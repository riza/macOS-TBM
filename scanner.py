"""Scan orchestration.

Coordinates discovery -> executable resolution -> parallel static analysis ->
per-service analysis -> scoring -> graph assembly. Returns a fully-populated set
of :class:`Target` objects plus a trust-boundary :class:`Graph`.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from analyzers.entitlements import analyze_entitlements
from analyzers.ipc import classify_ipc
from analyzers.leads import generate_leads
from analyzers.scoring import ScoringEngine
from analyzers.security_signals import detect_signals
from analyzers.sinks import classify_sinks
from collectors import discover_services, inspect_codesign, inspect_macho
from models.executable import Executable
from models.finding import FactLevel, Finding, Target
from utils.commands import ResultCache

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
    exe.macho = inspect_macho(path, cache)
    exe.codesign = inspect_codesign(path, cache)
    exe.analyzed = True
    return exe


def analyze_service(svc, exe: Executable) -> Target:
    """Run the full analysis pipeline for one service and return a Target."""
    engine = ScoringEngine()
    ipc_result = classify_ipc(svc, exe.macho)
    ent_result = analyze_entitlements(exe.codesign.entitlements if exe.codesign else {})
    sig_result = detect_signals(svc, exe.macho, exe.codesign)
    score_result = engine.score(svc, ipc_result, ent_result, sig_result)
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
        why_interesting=why,
        research_questions=questions,
        research_leads=why + questions,
    )


def run_scan(
    scope: str = "all",
    workers: int = 8,
    verbose: bool = False,
    progress=None,
) -> List[Target]:
    """Run a full scan and return targets sorted by score desc."""
    cache = ResultCache()
    services = discover_services(SCOPE_ROOTS.get(scope, None))
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
