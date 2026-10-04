"""Scan orchestration.

Coordinates discovery -> executable resolution -> parallel static analysis ->
per-service analysis -> scoring -> graph assembly. Returns a fully-populated set
of :class:`Target` objects plus a trust-boundary :class:`Graph`.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from analyzers.capabilities import analyze_capabilities
from analyzers.entitlements import analyze_entitlements
from analyzers.ipc import classify_ipc
from analyzers.leads import generate_leads
from analyzers.lpe import analyze_lpe
from analyzers.rce import analyze_rce
from analyzers.scoring import ScoringEngine
from analyzers.security_signals import detect_signals
from analyzers.sinks import classify_sinks
from collectors import discover_services, inspect_codesign, inspect_macho
from collectors.dataflow import inspect_dataflow
from models.executable import Executable
from models.finding import FactLevel, Finding, Target
from utils.commands import ResultCache
from utils.provenance import binary_identity

log = logging.getLogger(__name__)

SCOPE_ROOTS = {
    "all": None,  # None => default roots inside discover_services
    "daemons": ["/System/Library/LaunchDaemons", "/Library/LaunchDaemons"],
    "agents": [
        "/System/Library/LaunchAgents",
        "/Library/LaunchAgents",
        os.path.expanduser("~/Library/LaunchAgents"),
    ],
}


def _analyze_executable(path: str, cache: ResultCache) -> Executable:
    """Analyze a single executable (macho + codesign), memoized in *cache*."""
    exe = Executable(path=path)
    before = binary_identity(path)
    exe.macho = inspect_macho(path, cache)
    flow = inspect_dataflow(path, exe.macho)
    exe.macho.dataflow_facts = flow.facts
    exe.macho.dataflow_unknown_reasons = flow.unknown_reasons
    exe.macho.dataflow_functions_analyzed = flow.functions_analyzed
    exe.macho.dataflow_direct_calls = flow.direct_calls
    exe.macho.ipc_operations = flow.ipc_operations
    exe.macho.ipc_operation_unknown_reasons = flow.ipc_operation_unknown_reasons
    exe.macho.nsxpc_unconditional_accept_listeners = flow.unconditional_accept_listeners
    exe.codesign = inspect_codesign(path, cache)
    after = binary_identity(path)
    exe.identity = {
        "before_analysis": before, "after_analysis": after,
        "status": ("STABLE" if before.get("status") == "HASHED"
                   and before == after else "UNVERIFIED_OR_CHANGED"),
    }
    exe.analyzed = True
    return exe


def analyze_service(svc, exe: Executable) -> Target:
    """Run the full analysis pipeline for one service and return a Target."""
    engine = ScoringEngine()
    ipc_result = classify_ipc(svc, exe.macho)
    ent_result = analyze_entitlements(exe.codesign.entitlements if exe.codesign else {})
    sig_result = detect_signals(svc, exe.macho, exe.codesign)
    score_result = engine.score(svc, ipc_result, ent_result, sig_result)
    capability_findings, primitive_edges = analyze_capabilities(
        svc, exe.macho, sig_result, exe.codesign)
    lpe_findings = analyze_lpe(svc, exe.macho, capability_findings)
    rce_findings = analyze_rce(svc, exe.macho, validation=sig_result.validation)
    why, questions = generate_leads(svc, ipc_result, sig_result, score_result)

    # Load state is a parsed fact, not a heuristic: record it either way so a
    # reader never has to assume a listed job is live.
    state_finding = Finding(
        category="load_state",
        level=FactLevel.FACT,
        message="job is enabled" if svc.enabled else "job is DISABLED and would not be loaded by launchd",
        evidence=svc.enabled_derivation,
    )

    return Target(
        service=svc,
        executable=exe,
        score=score_result.score,
        reasons=score_result.reasons,
        findings=[state_finding] + ipc_result.findings + ent_result.findings + sig_result.findings,
        ipc_classification=ipc_result.classification,
        sensitive_sinks=classify_sinks(sig_result.assessments),
        sink_assessments=list(sig_result.assessments),
        validation=sig_result.validation,
        validation_assessment=sig_result.validation_assessment,
        entitlement_findings=ent_result.high_value,
        checked_entitlements=sig_result.checked_entitlements,
        why_interesting=why,
        research_questions=questions,
        research_leads=why + questions,
        capability_findings=capability_findings,
        lpe_findings=lpe_findings,
        rce_findings=rce_findings,
        primitive_edges=primitive_edges,
    )


def run_scan(
    scope: str = "all",
    workers: int = 8,
    verbose: bool = False,
    progress=None,
    target: str | None = None,
) -> List[Target]:
    """Run a full scan and return targets sorted by score desc."""
    cache = ResultCache()
    services = discover_services(SCOPE_ROOTS.get(scope, None))
    if target:
        needle = target.lower()
        services = [svc for svc in services if (
            needle in svc.label.lower()
            or needle in (svc.associated_executable or "").lower()
            or any(needle in name.lower() for name in svc.mach_services)
        )]
    log.info("discovered %d launchd jobs (scope=%s)", len(services), scope)

    # Unique executable paths.
    exec_paths: Dict[str, None] = {}
    for svc in services:
        p = svc.associated_executable
        if p and os.path.exists(p):
            exec_paths[p] = None
    log.info("resolved %d unique executables", len(exec_paths))

    # Parallel static analysis.
    executables: Dict[str, Executable] = {}
    if exec_paths:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_analyze_executable, p, cache): p for p in exec_paths}
            done = 0
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    executables[p] = fut.result()
                except Exception as exc:  # noqa: BLE001
                    log.warning("analysis failed for %s: %s", p, exc)
                    executables[p] = Executable(path=p, analyzed=False)
                done += 1
                if progress:
                    progress(done, len(exec_paths))

    # Per-service analysis + scoring.
    targets: List[Target] = []
    for svc in services:
        exe = executables.get(svc.associated_executable) or Executable(path=svc.associated_executable or "")
        targets.append(analyze_service(svc, exe))

    targets.sort(key=lambda t: t.score, reverse=True)

    return targets
