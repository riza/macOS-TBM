"""Bug-bounty scoring engine for macOS-TBM.

Scores every target in report.json along LPE / RCE / DOS / CRED dimensions
using the static evidence already collected by a scan.  Read-only — no new
analysis, no launchd mutations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BugBountyScore:
    label: str
    tbm_score: int
    run_as: str
    validation: str
    mach_count: int
    lpe: int = 0
    rce: int = 0
    dos: int = 0
    cred: int = 0
    sinks: List[str] = field(default_factory=list)
    held_ents: List[str] = field(default_factory=list)
    checked_ents: List[str] = field(default_factory=list)
    not_observed: List[str] = field(default_factory=list)
    research_priority: int = 0
    exploitability_evidence: int = 0
    candidate_capability: str = "UNKNOWN"
    maturity: str = "SINK_CANDIDATE"
    proven_primitive: Optional[str] = None
    primitive: str = "UNKNOWN"
    confidence: str = "SPECULATIVE"
    reachable_by: List[str] = field(default_factory=list)
    reason: List[str] = field(default_factory=list)
    framework: str = ""
    sink_category: str = ""
    dimensions: Dict[str, int] = field(default_factory=dict)
    identity_verification: str = "UNKNOWN"
    primitives: List[str] = field(default_factory=list)
    candidate_capabilities: List[str] = field(default_factory=list)
    confidence_levels: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    sink_categories: List[str] = field(default_factory=list)
    lpe_findings: List[Dict[str, Any]] = field(default_factory=list)
    rce_findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.lpe + self.rce + self.dos + self.cred

    def flags(self) -> str:
        f = []
        if self.lpe >= 45:
            f.append("\U0001f534LPE")  # 🔴
        elif self.lpe >= 25:
            f.append("\U0001f7e1LPE")  # 🟡
        if self.rce >= 30:
            f.append("\U0001f534RCE")
        elif self.rce >= 15:
            f.append("\U0001f7e1RCE")
        if self.dos >= 15:
            f.append("\U0001f7e1DOS")
        if self.cred >= 35:
            f.append("\U0001f534CRED")
        elif self.cred >= 20:
            f.append("\U0001f7e1CRED")
        return " ".join(f) if f else "-"


def _sink_map(target: dict) -> Dict[str, str]:
    """Build {label: confidence} from sink assessments."""
    return {s["label"]: s["confidence"] for s in target.get("sink_assessments", [])}


class _AdapterSvc:
    """Minimal LaunchService stand-in for replaying analyzers over a report."""

    def __init__(self, svc: dict):
        self.label = (svc or {}).get("label", "?")
        self.run_as = (svc or {}).get("run_as", "?")
        self.sockets = (svc or {}).get("sockets") or {}
        self.is_privileged = self.run_as in ("root", "system")


class _AdapterMacho:
    """Minimal MachOInfo stand-in carrying the serialized analysis inputs."""

    def __init__(self, macho: dict):
        macho = macho or {}
        self.path = macho.get("path", "")
        self.is_macho = bool(macho.get("is_macho"))
        self.imported_symbols = list(macho.get("imported_symbols") or [])
        self.linked_libs = list(macho.get("linked_libs") or [])
        self.objc_classes = list(macho.get("objc_classes") or [])
        self.dataflow_facts = list(macho.get("dataflow_facts") or [])


def _synthesize_rce(target: dict) -> None:
    """Replay the RCE correlation over a serialized target missing rce_findings."""
    if "rce_findings" in target:
        return
    svc = _AdapterSvc(target.get("service") or {})
    exe = target.get("executable") or {}
    macho = _AdapterMacho(exe.get("macho") or {})
    from analyzers.rce import analyze_rce
    target["rce_findings"] = [
        f.to_dict() for f in analyze_rce(svc, macho,
                                         validation=target.get("validation", "UNKNOWN"))]


def _prepare_target(target: dict) -> dict:
    """Backfill derived hunting layers for reports that predate them."""
    _synthesize_rce(target)
    return target


def score_target(target: dict) -> Optional[BugBountyScore]:
    """Score a single target. Returns None when every dimension is zero."""
    _prepare_target(target)
    svc = target.get("service", {})
    label = target.get("label", "?")
    tbm_score = target.get("score", 0)
    run_as = svc.get("run_as", "?")
    validation = target.get("validation", "?")
    mach_count = len(svc.get("mach_services", []))

    sinks = _sink_map(target)
    va = target.get("validation_assessment") or {}
    not_observed = [n["class"] for n in va.get("not_observed", [])]
    held_ents = list(target.get("entitlement_findings", []))
    checked_ents = list(target.get("checked_entitlements", []))
    has_system_keychain = "com.apple.private.system-keychain" in held_ents
    has_keychain_groups = "keychain-access-groups" in held_ents
    has_account = "ACCOUNT" in sinks
    has_credential_high = sinks.get("CREDENTIAL") == "HIGH"
    has_execution = "EXECUTION" in sinks
    has_network = "NETWORK" in sinks
    has_install = "INSTALL/UPDATE" in sinks
    is_root = run_as == "root"
    is_weak = validation in ("WEAK", "NONE_OBSERVED")
    sectask_missing = "sectask-entitlement" in not_observed
    audittoken_missing = "audit-token-extraction" in not_observed
    codesign_missing = "code-signing-requirement" in not_observed

    capabilities = target.get("capability_findings") or []
    best = max(capabilities, key=lambda f: f.get("research_priority_score", 0), default={})
    research_priority = int(best.get(
        "research_priority_score", target.get("research_priority_score", 0)) or 0)
    sink_detail = best.get("sink") or {}
    candidate_capability = best.get("candidate_capability", best.get("primitive", "UNKNOWN"))
    maturity = best.get("maturity_level", best.get("maturity", "SINK_CANDIDATE"))
    proven_primitive = best.get("proven_primitive")
    primitive = proven_primitive or candidate_capability
    exploitability_evidence = int(best.get(
        "exploitability_evidence_score", target.get("exploitability_evidence_score", 0)) or 0)
    cap_confidence = best.get("confidence", "SPECULATIVE")
    reachable_by = list(best.get("reachability") or [])
    framework = sink_detail.get("framework") or ""
    sink_category = sink_detail.get("category") or ""
    dimensions = dict((best.get("exploitability_evidence") or best.get("score") or {}))
    dimensions.pop("overall", None)
    identity_verification = best.get("identity_verification", validation)
    primitives = sorted({c.get("proven_primitive") for c in capabilities
                         if c.get("proven_primitive")})
    candidate_capabilities = sorted({c.get("candidate_capability", c.get("primitive", "UNKNOWN"))
                                     for c in capabilities})
    confidence_levels = sorted({c.get("confidence", "SPECULATIVE") for c in capabilities})
    reachable_by = sorted({r for c in capabilities for r in (c.get("reachability") or [])})
    frameworks = sorted({(c.get("sink") or {}).get("framework") for c in capabilities
                         if (c.get("sink") or {}).get("framework")})
    sink_categories = sorted({(c.get("sink") or {}).get("category") for c in capabilities
                              if (c.get("sink") or {}).get("category")})
    reason: List[str] = []
    if is_root:
        reason.append("root service")
    if "LOCAL_USER" in reachable_by:
        reason.append("local endpoint is statically present; successful connection is unverified")
    if candidate_capability != "UNKNOWN":
        reason.append(f"{candidate_capability} · {maturity} ({cap_confidence})")
    if best.get("attacker_control") == "UNKNOWN":
        reason.append("source-to-sink argument control remains unproven")
    if validation in ("WEAK", "NONE_OBSERVED"):
        reason.append(f"caller validation {validation.lower().replace('_', ' ')} statically")

    # ── LPE ──────────────────────────────────────────────────────────
    lpe_findings = list(target.get("lpe_findings") or [])
    if "lpe_findings" in target:
        lpe = max((int(finding.get("score", 0)) for finding in lpe_findings), default=0)
        if lpe_findings:
            best_lpe = max(lpe_findings, key=lambda finding: int(finding.get("score", 0)))
            reason.append(
                f"LPE filesystem correlation: {', '.join(best_lpe.get('lpe_classes') or [])} "
                f"({best_lpe.get('confidence', 'INSUFFICIENT_EVIDENCE')})")
    else:
        # Schema <=2.0 compatibility: retain the original broad LPE score for
        # reports that predate operation-level filesystem findings.
        lpe = 0
        if is_root and is_weak:
            lpe += 30
        if is_root and sectask_missing:
            lpe += 10
        if is_root and audittoken_missing:
            lpe += 10
        if is_root and codesign_missing:
            lpe += 10
        if has_credential_high and is_weak:
            lpe += 15
        if is_root and has_execution:
            lpe += 10
        if is_root and len(held_ents) > len(checked_ents) and is_weak:
            lpe += 5

    # Runtime probe evidence (optional_analysis.runtime_xpc) is the strongest
    # reachability signal we hold: an unprivileged local client that connects to
    # a privileged daemon without being rejected crosses a trust boundary.
    runtime_obs = []
    for obs in ((target.get("optional_analysis") or {}).get("runtime_xpc") or []):
        if isinstance(obs, dict):
            runtime_obs.append(obs)
    unprivileged_confirmed = any(o.get("connection") == "CONFIRMED" for o in runtime_obs)
    if is_root and unprivileged_confirmed:
        if is_weak:
            lpe = max(lpe, 45)
            reason.append(
                "runtime: unprivileged client CONFIRMED a connection to a root service with no "
                f"observed caller validation"
                f" ({sum(1 for o in runtime_obs if o.get('connection') == 'CONFIRMED')} of "
                f"{len(runtime_obs)} probed services)")
        else:
            lpe = max(lpe, 25)
            reason.append(
                "runtime: root service accepts unprivileged connections; caller validation is "
                "present statically so operation-level review is required")

    # ── RCE ──────────────────────────────────────────────────────────
    rce = 0
    rce_findings = list(target.get("rce_findings") or [])
    if rce_findings:
        rce = max((int(finding.get("score", 0)) for finding in rce_findings), default=0)
        best_rce = max(rce_findings, key=lambda finding: int(finding.get("score", 0)))
        reason.append(
            f"RCE correlation: {', '.join(best_rce.get('rce_classes') or [])} "
            f"({best_rce.get('confidence', 'INSUFFICIENT_EVIDENCE')})")
    else:
        # Schema <=2.0 compatibility for reports that predate rce_findings.
        if is_root and has_network and is_weak:
            rce += 20
        if mach_count > 0 and is_root and is_weak:
            rce += 10
        if has_install and is_root:
            rce += 5
        if mach_count >= 2 and is_weak:
            rce += 5

    # ── DOS ──────────────────────────────────────────────────────────
    dos = 0
    if tbm_score >= 90 and is_weak:
        dos += 15
    if mach_count >= 3:
        dos += 5
    if is_root:
        dos += 5

    # ── CRED ─────────────────────────────────────────────────────────
    cred = 0
    if has_credential_high:
        cred += 20
    if has_system_keychain:
        cred += 10
    if has_account:
        cred += 5
    if has_keychain_groups:
        cred += 5

    total = lpe + rce + dos + cred
    if total == 0 and research_priority == 0:
        return None

    return BugBountyScore(
        label=label,
        tbm_score=tbm_score,
        run_as=run_as,
        validation=validation,
        mach_count=mach_count,
        lpe=lpe,
        rce=rce,
        dos=dos,
        cred=cred,
        sinks=list(sinks.keys()),
        held_ents=held_ents,
        checked_ents=checked_ents,
        not_observed=not_observed,
        research_priority=research_priority,
        exploitability_evidence=exploitability_evidence,
        candidate_capability=candidate_capability,
        maturity=maturity,
        proven_primitive=proven_primitive,
        primitive=primitive,
        confidence=cap_confidence,
        reachable_by=reachable_by,
        reason=reason,
        framework=framework,
        sink_category=sink_category,
        dimensions=dimensions,
        identity_verification=identity_verification,
        primitives=primitives,
        candidate_capabilities=candidate_capabilities,
        confidence_levels=confidence_levels,
        frameworks=frameworks,
        sink_categories=sink_categories,
        lpe_findings=lpe_findings,
        rce_findings=rce_findings,
    )


def score_report(report: dict) -> List[BugBountyScore]:
    """Score every target in a loaded report; return scored list sorted by total."""
    results: List[BugBountyScore] = []
    for t in report.get("targets", []):
        s = score_target(t)
        if s is not None:
            results.append(s)
    results.sort(key=lambda r: (r.research_priority, r.total, r.tbm_score), reverse=True)
    return results


def format_text(results: List[BugBountyScore], top: int = 30) -> str:
    lines = [f"TOP RESEARCH TARGETS ({len(results)} with static research signal)\n"]
    lines.append(f"  {'RPS':>3} {'EPS':>3}  {'MATURITY':16} {'CAPABILITY':35} TARGET")
    lines.append("  " + "-" * 104)
    for r in results[:top]:
        lines.append(
            f"  {r.research_priority:>3} {r.exploitability_evidence:>3}  "
            f"{r.maturity:16} {r.candidate_capability[:35]:35} {r.label}"
        )
        if r.reason:
            lines.append("         Reason: " + "; ".join(r.reason))
    if len(results) > top:
        lines.append(f"  ... +{len(results) - top} more (raise --top)")
    return "\n".join(lines)


def format_lpe_text(results: List[BugBountyScore], top: int = 30) -> str:
    rows = []
    for result in results:
        for finding in result.lpe_findings:
            rows.append((int(finding.get("score", 0)), result, finding))
    rows.sort(key=lambda row: (row[0], row[1].research_priority), reverse=True)
    lines = [f"PRIVILEGED FILESYSTEM LPE CANDIDATES ({len(rows)} correlated findings)\n"]
    lines.append(f"  {'LPE':>3} {'CONFIDENCE':22} {'CLASS':31} TARGET / SINK")
    lines.append("  " + "-" * 112)
    for score, result, finding in rows[:top]:
        sink = finding.get("sink") or {}
        classes = ",".join(finding.get("lpe_classes") or [])
        lines.append(
            f"  {score:>3} {str(finding.get('confidence', '?'))[:22]:22} "
            f"{classes[:31]:31} {result.label} / {sink.get('api', '?')}"
        )
        lines.append(
            f"         caller {finding.get('caller_validation')} · resource "
            f"{finding.get('resource_validation')} · target {finding.get('target')}"
        )
    if len(rows) > top:
        lines.append(f"  ... +{len(rows) - top} more (raise --top)")
    if not rows:
        lines.append("  none — import-only filesystem APIs are intentionally excluded")
    return "\n".join(lines)


def format_rce_text(results: List[BugBountyScore], top: int = 30) -> str:
    rows = []
    for result in results:
        for finding in result.rce_findings:
            rows.append((int(finding.get("score", 0)), result, finding))
    rows.sort(key=lambda row: (row[0], row[1].research_priority), reverse=True)
    lines = [f"NETWORK INGRESS x PARSER RCE CANDIDATES ({len(rows)} correlated findings)\n"]
    lines.append(f"  {'RCE':>3} {'CONFIDENCE':22} {'INGRESS':14} {'CLASS':34} TARGET")
    lines.append("  " + "-" * 112)
    for score, result, finding in rows[:top]:
        classes = ",".join(finding.get("rce_classes") or [])
        lines.append(
            f"  {score:>3} {str(finding.get('confidence', '?'))[:22]:22} "
            f"{str(finding.get('ingress_kind', '?'))[:14]:14} "
            f"{classes[:34]:34} {result.label}"
        )
        apis = finding.get("parser_apis") or []
        lines.append(
            f"         parser: {', '.join(apis[:10]) if apis else '(none bound)'} · "
            f"runs as {finding.get('privilege')} · validation {finding.get('caller_validation')}"
        )
    if len(rows) > top:
        lines.append(f"  ... +{len(rows) - top} more (raise --top)")
    if not rows:
        lines.append("  none — no network ingress x parser surface correlated in this report")
    return "\n".join(lines)


def format_single(r: BugBountyScore) -> str:
    lines = [
        f"═══ {r.label} ═══",
        f"  TBM score: {r.tbm_score}   Validation: {r.validation}   Run as: {r.run_as}",
        f"  Mach services: {r.mach_count}",
        "",
        "  ── Bug Bounty Scores ──",
        f"  LPE : {r.lpe:>3}  (Local Privilege Escalation)",
        f"  RCE : {r.rce:>3}  (Remote Code Execution)",
        f"  DOS : {r.dos:>3}  (Denial of Service)",
        f"  CRED: {r.cred:>3}  (Credential Theft)",
        f"  TOTAL: {r.total}",
        f"  Research priority: {r.research_priority}/100",
        f"  Exploitability evidence: {r.exploitability_evidence}/100",
        f"  Candidate: {r.candidate_capability}   Maturity: {r.maturity}",
        f"  Proven primitive: {r.proven_primitive or '(not proven)'}   Confidence: {r.confidence}",
        f"  Reachability: {', '.join(r.reachable_by) or 'UNKNOWN'}",
        "",
        f"  Sinks: {', '.join(r.sinks) if r.sinks else '(none)'}",
        f"  Held entitlements ({len(r.held_ents)}):",
    ]
    for e in r.held_ents[:10]:
        lines.append(f"    - {e}")
    if len(r.held_ents) > 10:
        lines.append(f"    ... +{len(r.held_ents) - 10} more")
    lines.append(f"  Checked entitlements ({len(r.checked_ents)}):")
    for e in r.checked_ents[:5]:
        lines.append(f"    - {e}")
    if len(r.checked_ents) > 5:
        lines.append(f"    ... +{len(r.checked_ents) - 5} more")
    lines.append(f"  Not-observed validation ({len(r.not_observed)}):")
    for n in r.not_observed:
        lines.append(f"    - {n}")
    if r.reason:
        lines.append("  Research rationale:")
        for item in r.reason:
            lines.append(f"    - {item}")
    if r.lpe_findings:
        lines.append("  Privileged filesystem LPE findings:")
        for finding in sorted(r.lpe_findings, key=lambda item: item.get("score", 0),
                              reverse=True):
            sink = finding.get("sink") or {}
            lines += [
                f"    [{finding.get('severity')}] {', '.join(finding.get('lpe_classes') or [])}",
                f"      Score/confidence: {finding.get('score')}/100 · {finding.get('confidence')}",
                f"      Flow: {finding.get('input_origin')} -> root -> {sink.get('api')}",
                f"      Caller validation: {finding.get('caller_validation')}",
                f"      Operation authorization: {finding.get('operation_authorization')}",
                f"      Resource validation: {finding.get('resource_validation')}",
                f"      Target: {finding.get('target')} ({finding.get('target_category')})",
                "      Static candidate only; exploitation is not confirmed.",
            ]
    if r.rce_findings:
        lines.append("  Network ingress x parser RCE findings:")
        for finding in sorted(r.rce_findings, key=lambda item: item.get("score", 0),
                              reverse=True):
            apis = finding.get("parser_apis") or []
            lines += [
                f"    [{finding.get('severity')}] {', '.join(finding.get('rce_classes') or [])}",
                f"      Score/confidence: {finding.get('score')}/100 · {finding.get('confidence')}",
                f"      Ingress: {finding.get('ingress_kind')} · parser: {', '.join(apis[:10]) if apis else '(none)'}",
                f"      Runs as {finding.get('privilege')} · validation {finding.get('caller_validation')}",
                "      Static candidate only; reachability of the parser from the network is unverified.",
            ]
    return "\n".join(lines)
