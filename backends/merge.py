"""Merge optional backend evidence into the existing operation finding."""

from __future__ import annotations

from models.capability import MATURITY_ORDER

from .base import FindingUpdate


def _snapshot(finding) -> dict:
    return {
        "maturity": finding.maturity_level,
        "attacker_control": finding.attacker_control,
        "confidence": finding.confidence,
        "controlled_arguments": dict(finding.controlled_arguments),
        "validation_scope": finding.identity.scope,
        "authorization_scope": finding.authorization.scope,
    }


def merge_finding_update(finding, update: FindingUpdate, source: str) -> None:
    """Evidence-monotonic merge; never removes native or conflicting evidence."""
    if update.finding_id != finding.finding_id:
        raise ValueError("backend update belongs to a different finding")
    if not finding.before_optional_analysis:
        finding.before_optional_analysis = _snapshot(finding)
    if source not in finding.analysis_sources:
        finding.analysis_sources.append(source)
    finding.optional_evidence.extend(e.to_dict() for e in update.evidence)

    if update.call_path_confirmed and finding.maturity_level == "SINK_CANDIDATE":
        finding.maturity_level = "REACHABLE_SINK"
    for name, state in update.controlled_arguments.items():
        old = finding.controlled_arguments.get(name, "UNKNOWN")
        if old not in {"UNKNOWN", state}:
            finding.evidence_conflicts.append(
                f"{source} says {name}={state}; existing evidence says {old}")
        elif old == "UNKNOWN":
            finding.controlled_arguments[name] = state
    for name in update.constant_arguments:
        old = finding.controlled_arguments.get(name, "UNKNOWN")
        if old == "UNKNOWN":
            finding.controlled_arguments[name] = "CONSTANT"
        elif old != "CONSTANT":
            finding.evidence_conflicts.append(
                f"{source} says {name}=CONSTANT; existing evidence says {old}")

    controlled = any(v == "HIGH" for v in finding.controlled_arguments.values())
    if controlled and update.call_path_confirmed:
        if MATURITY_ORDER.index(finding.maturity_level) < MATURITY_ORDER.index("CONTROLLED_SINK"):
            finding.maturity_level = "CONTROLLED_SINK"
        finding.attacker_control = "HIGH"

    if update.validation_scope:
        finding.identity.scope = update.validation_scope
    if update.authorization_scope:
        finding.authorization.scope = update.authorization_scope
    finding.unknown_reasons = [
        reason for reason in finding.unknown_reasons
        if reason not in set(update.resolved_unknown_reasons)
    ]
    # Finding-wide confidence includes argument flow, guards and post-condition.
    # An additional observation or resolved call path cannot establish those.
    # Preserve confidence until a backend supplies a dedicated proof contract.
    score = finding.exploitability_score
    score.maturity_level = finding.maturity_level
    score.sink_reachability = {
        "SINK_CANDIDATE": 1, "REACHABLE_SINK": 5, "CONTROLLED_SINK": 7,
        "PRIMITIVE": 9, "IMPACT": 10,
    }[finding.maturity_level]
    score.primitive_maturity = {
        "SINK_CANDIDATE": 1, "REACHABLE_SINK": 4, "CONTROLLED_SINK": 7,
        "PRIMITIVE": 9, "IMPACT": 10,
    }[finding.maturity_level]
    score.attacker_control = {"UNKNOWN": 1, "LOW": 2, "PARTIAL": 5, "HIGH": 8}.get(
        finding.attacker_control, 1)
    score.analysis_confidence = {"SPECULATIVE": 1, "LOW": 2, "MEDIUM": 5,
                                 "HIGH": 8, "CONFIRMED": 10}[finding.confidence]
