"""Bug-bounty scoring engine for macOS-TBM.

Scores every target in report.json along LPE / RCE / DOS / CRED dimensions
using the static evidence already collected by a scan.  Read-only — no new
analysis, no launchd mutations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional


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


def score_target(target: dict) -> Optional[BugBountyScore]:
    """Score a single target. Returns None when every dimension is zero."""
    svc = target.get("service", {})
    label = target.get("label", "?")
    tbm_score = target.get("score", 0)
    run_as = svc.get("run_as", "?")
    validation = target.get("validation", "?")
    mach_count = len(svc.get("mach_services", []))

    sinks = _sink_map(target)
    va = target.get("validation_assessment", {})
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

    # ── LPE ──────────────────────────────────────────────────────────
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

    # ── RCE ──────────────────────────────────────────────────────────
    rce = 0
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
    if total == 0:
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
    )


def score_report(report: dict) -> List[BugBountyScore]:
    """Score every target in a loaded report; return scored list sorted by total."""
    results: List[BugBountyScore] = []
    for t in report.get("targets", []):
        s = score_target(t)
        if s is not None:
            results.append(s)
    results.sort(key=lambda r: (r.total, r.tbm_score), reverse=True)
    return results


def format_text(results: List[BugBountyScore], top: int = 30) -> str:
    lines = [f"{len(results)} target(s) with bug-bounty signal\n"]
    lines.append(
        f"  {'SCORE':>4} {'FLAGS':25} {'TBM':>3} {'V':5} {'AS':15} {'M':>2} "
        f"| LPE RCE DOS CRED | LABEL"
    )
    for r in results[:top]:
        lines.append(
            f"  {r.total:>4} {r.flags():25} {r.tbm_score:>3} {r.validation[:5]:5} "
            f"{r.run_as:15} {r.mach_count:>2} | {r.lpe:>3} {r.rce:>3} {r.dos:>3} "
            f"{r.cred:>3} | {r.label}"
        )
    if len(results) > top:
        lines.append(f"  ... +{len(results) - top} more (raise --top)")
    return "\n".join(lines)


def format_single(r: BugBountyScore) -> str:
    lines = [
        f"═══ {r.label} ═══",
        f"  TBM score: {r.tbm_score}   Validation: {r.validation}   Run as: {r.run_as}",
        f"  Mach services: {r.mach_count}",
        f"",
        f"  ── Bug Bounty Scores ──",
        f"  LPE : {r.lpe:>3}  (Local Privilege Escalation)",
        f"  RCE : {r.rce:>3}  (Remote Code Execution)",
        f"  DOS : {r.dos:>3}  (Denial of Service)",
        f"  CRED: {r.cred:>3}  (Credential Theft)",
        f"  TOTAL: {r.total}",
        f"",
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
    return "\n".join(lines)