"""Research-lead generation.

Produces human-readable *research leads* — questions and observations that
guide manual reverse engineering. These are explicitly NOT vulnerability
claims; they frame what a researcher should investigate next.
"""

from __future__ import annotations

from typing import List, Tuple


def _sink_note(sink: str) -> str:
    notes = {
        "account": "interacts with account/user/group management (OpenDirectory/DirectoryServices)",
        "credential": "handles credentials (Keychain/Security.framework/authentication tokens)",
        "privacy": "touches privacy-sensitive data (TCC/camera/mic/screen/location)",
        "filesystem": "performs privileged filesystem mutation",
        "execution": "spawns processes / installs helpers / talks to launchd",
        "install_update": "participates in install/software-update flows",
        "network": "has network-facing surface",
        "security_policy": "evaluates code signing / Gatekeeper / sandbox policy",
    }
    return notes.get(sink, sink)


def generate_leads(service, ipc_result, signals_result, score_result) -> Tuple[List[str], List[str]]:
    """Return (why_interesting, research_questions) for a target."""
    why: List[str] = []
    questions: List[str] = []

    if not getattr(service, "enabled", True):
        why.append(f"DISABLED: {getattr(service, 'enabled_derivation', 'not loadable as configured')}")
    if service.is_privileged:
        why.append("privileged system daemon")
    if service.mach_services:
        why.append(f"exposes {len(service.mach_services)} Mach service(s): {', '.join(service.mach_services[:3])}")
    if ipc_result.provider_signals:
        why.append("XPC/Mach provider indicators present")
    strength = getattr(signals_result, "validation", "NONE_OBSERVED")
    if strength == "NONE_OBSERVED":
        why.append("caller-validation indicators not observed statically")
    else:
        why.append(f"caller-validation evidence: {strength} (requires manual review)")
    for assessment in getattr(signals_result, "assessments", []):
        why.append(f"{_sink_note(assessment.sink)} [{assessment.confidence}]")

    # Always-frame questions as open research items.
    if service.mach_services or ipc_result.provider_signals:
        questions.extend([
            "How is caller identity established for incoming connections?",
            "Is authorization performed per connection or per operation?",
            "Are audit tokens propagated across IPC boundaries?",
        ])
    if signals_result.caller_validation:
        questions.append("Are entitlement checks operation-specific or coarse?")
    else:
        questions.append("Is caller validation performed via an API not visible to static analysis (helper, private framework, inline)?")
    questions.append("Does the daemon act as a deputy for another subsystem?")
    questions.append("Which parameters cross from a less-trusted client into privileged operations?")

    return why, questions
