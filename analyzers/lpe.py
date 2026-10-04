"""Optional LPE hunting layer for privileged filesystem trust boundaries.

This module correlates existing operation findings and bounded dataflow facts.
It deliberately emits nothing for an imported filesystem API alone.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional, Tuple

from models.lpe import LPEFinding
from utils.rules import lpe_rules

_PATH_FIELDS = {"path", "source_path", "destination_path", "resource_path"}
_WRITE_LIKE = {"rename", "chmod", "chown", "unlink", "mkdir", "copy", "link", "open"}


def _matches(api: str, pattern: str) -> bool:
    actual = api.lstrip("_")
    pattern = pattern.lstrip("_")
    return actual.startswith(pattern[:-1]) if pattern.endswith("*") else actual == pattern


def _operation_group(api: str, rules: Dict[str, Any]) -> str:
    for group, patterns in (rules.get("filesystem_sinks") or {}).items():
        if any(_matches(api, pattern) for pattern in patterns):
            return group
    return ""


def _flow_for_finding(macho, finding) -> Optional[Dict[str, Any]]:
    if not macho or not finding.sink_address:
        return None
    for flow in getattr(macho, "dataflow_facts", []) or []:
        if (flow.get("sink_api") == finding.sink_api
                and str(flow.get("sink_address", "")).lower()
                == str(finding.sink_address).lower()
                and (not finding.handler_function
                     or flow.get("function") == finding.handler_function)):
            return flow
    return None


def _path_control(finding) -> Tuple[bool, str]:
    controlled = getattr(finding, "controlled_arguments", {}) or {}
    states = [value for name, value in controlled.items()
              if name in _PATH_FIELDS or name.endswith("_path")]
    if "HIGH" in states:
        return True, "HIGH"
    if states:
        return False, states[0]
    return False, "NOT_APPLICABLE"


def _input_origin(finding) -> Tuple[str, str]:
    source = finding.sources[0] if finding.sources else None
    api = getattr(source, "api", "") if source else ""
    if api.startswith("xpc_") or "XPC" in finding.transport:
        return "xpc", getattr(source, "argument", "unknown") if source else "unknown"
    if api == "mach_msg" or "Mach" in finding.transport:
        return "mach", getattr(source, "argument", "unknown") if source else "unknown"
    return "ipc" if source else "unknown", getattr(source, "argument", "unknown") if source else "unknown"


def _literal_context(flow: Optional[Dict[str, Any]], macho, rules: Dict[str, Any]):
    """Return path context, separating flow-bound literals from binary-wide hints."""
    bound = [str(value) for value in ((flow or {}).get("path_literals") or [])]
    strings = [str(value) for value in (getattr(macho, "interesting_strings", []) or [])]
    candidates = bound or strings
    sensitive: List[Tuple[str, str]] = []
    for value in candidates:
        for target in rules.get("sensitive_targets", []):
            if any(pattern.lower() in value.lower() for pattern in target.get("patterns", [])):
                sensitive.append((value, target["category"]))
                break
    temporary = [value for value in candidates if any(
        pattern.lower() in value.lower() for pattern in rules.get("unsafe_temporary_paths", []))]
    return {
        "bound": bool(bound),
        "sensitive": sensitive,
        "temporary": temporary,
        "context_only": not bound and bool(sensitive or temporary),
    }


def _toctou(flow: Optional[Dict[str, Any]], macho, rules: Dict[str, Any]):
    if not flow or not macho:
        return None
    try:
        sink_address = int(str(flow.get("sink_address", "0")), 16)
    except ValueError:
        sink_address = 0
    for check in getattr(macho, "dataflow_facts", []) or []:
        if not any(_matches(check.get("sink_api", ""), pattern)
                   for pattern in rules.get("toctou_checks", [])):
            continue
        if (check.get("source_address") != flow.get("source_address")
                or check.get("source_function") != flow.get("source_function")):
            continue
        try:
            check_address = int(str(check.get("sink_address", "0")), 16)
        except ValueError:
            continue
        if check_address and sink_address and check_address < sink_address:
            return check
    return None


def _resource_validation(group: str, flow, macho, rules):
    check = _toctou(flow, macho, rules)
    if check:
        return ("POTENTIAL_TOCTOU", [
            f"{check.get('sink_api')}@{check.get('sink_address')} precedes a later path operation",
            "the same IPC source origin reaches both pathname resolutions",
        ], True)
    if group in {"chmod", "chown"} and flow and flow.get("sink_api", "").startswith("f"):
        return ("DESCRIPTOR_BASED_REFERENCE", [
            "descriptor-based sink observed; descriptor provenance still requires review"], False)
    imports = getattr(macho, "imported_symbols", []) if macho else []
    observed = sorted({name for name in imports if any(
        _matches(name, pattern) for pattern in rules.get("resource_validation", []))})
    if observed:
        return ("PRESENT_IN_BINARY", observed, False)
    return ("NONE_OBSERVED", [], False)


def _resource_scope(group: str, flow, macho, rules):
    """Classify resource checks without promoting metadata to a scope guard.

    ``lstat``/``fstat``/owner checks bind facts about an object; they do not
    constrain the target to an allowed root and so never prove resource
    authorization. A prefix/root check stays CONDITIONAL because its
    canonicalization and symlink behavior are not resolved statically.
    """
    checks = rules.get("resource_checks", {})
    imports = list(getattr(macho, "imported_symbols", []) or []) if macho else []
    observed: Dict[str, List[str]] = {}
    for category, patterns in checks.items():
        hits = sorted({name for name in imports
                       if any(_matches(name, pattern) for pattern in patterns)})
        if hits:
            observed[category] = hits
    sink = (flow or {}).get("sink_api", "")
    if group in {"chmod", "chown"} and sink.startswith("f"):
        observed.setdefault("DESCRIPTOR_BINDING", [sink])
    if "PATH_SCOPE_GUARD" in observed:
        return ("PATH_SCOPE_GUARD", observed["PATH_SCOPE_GUARD"], "CONDITIONAL",
                ["path canonicalization and symlink behavior are not resolved"])
    if "DESCRIPTOR_BINDING" in observed:
        return ("DESCRIPTOR_BINDING", observed["DESCRIPTOR_BINDING"], "UNKNOWN",
                ["descriptor binds the object but not the caller's authority over it"])
    if "METADATA_CHECK" in observed:
        return ("METADATA_CHECK", observed["METADATA_CHECK"], "UNKNOWN",
                ["metadata checks do not constrain the target to an allowed root"])
    return ("NONE_OBSERVED", [], "UNKNOWN", [])


def _severity(score: int, rules: Dict[str, Any]) -> str:
    thresholds = rules.get("thresholds", {})
    if score >= int(thresholds.get("high", 70)):
        return "HIGH"
    if score >= int(thresholds.get("medium", 45)):
        return "MEDIUM"
    return "LOW"


def _confidence(finding, user_controlled: bool, contextual: bool) -> str:
    if user_controlled and finding.maturity_level in {
            "CONTROLLED_SINK", "PRIMITIVE", "IMPACT"}:
        return "CONFIRMED_FLOW"
    if user_controlled and finding.maturity_level == "REACHABLE_SINK":
        return "STRONG_CANDIDATE"
    if contextual and finding.maturity_level == "REACHABLE_SINK":
        return "POSSIBLE"
    return "INSUFFICIENT_EVIDENCE"


def _caller_validation(finding) -> Tuple[str, str]:
    """Summarize operation invocation checks without crediting binary-wide presence."""
    if finding.authorization.scope == "AUTHORIZATION_GUARDS_SINK":
        return finding.authorization.strength, finding.authorization.scope
    if finding.identity.scope == "VALIDATION_GUARDS_SINK":
        return finding.identity.strength, finding.identity.scope
    if (finding.identity.strength == "NONE_OBSERVED"
            and finding.authorization.strength == "NONE_OBSERVED"):
        return "NONE_OBSERVED", "OPERATION_GUARD_NOT_OBSERVED"
    return "PRESENT_NOT_BOUND", (
        f"{finding.identity.scope};{finding.authorization.scope}")


def analyze_lpe(service, macho, capability_findings: Iterable[Any]) -> List[LPEFinding]:
    """Correlate privileged IPC input with filesystem operations.

    Import-only ``SINK_CANDIDATE`` records are intentionally excluded.
    """
    if not getattr(service, "is_privileged", False):
        return []
    rules = lpe_rules()
    weights = rules.get("weights", {})
    out: List[LPEFinding] = []
    for finding in capability_findings:
        if finding.sink_category != "filesystem":
            continue
        group = _operation_group(finding.sink_api, rules)
        if not group:
            continue
        flow = _flow_for_finding(macho, finding)
        reachable = finding.maturity_level != "SINK_CANDIDATE"
        deep_call_path = "RADARE2" in (finding.analysis_sources or [])
        if (not flow or not reachable
                or (flow.get("reachability_confirmed") is False
                    and not deep_call_path)):
            continue
        user_controlled, path_state = _path_control(finding)
        context = _literal_context(flow, macho, rules)
        resource_validation, resource_evidence, toctou = _resource_validation(
            group, flow, macho, rules)
        resource_scope, scope_evidence, scope_confidence, scope_notes = _resource_scope(
            group, flow, macho, rules)
        bound_sensitive = bool(context["bound"] and context["sensitive"])
        bound_temp = bool(context["bound"] and context["temporary"])
        contextual = bool(toctou or bound_sensitive or bound_temp)
        # A reachable call with no path influence or path/resource context is
        # not an LPE finding merely because it invokes a filesystem API.
        if not user_controlled and not contextual:
            continue

        classes: List[str] = []
        if user_controlled:
            classes.append("FS_USER_PATH_TO_ROOT_SINK")
        classes += {
            "rename": ["FS_PRIVILEGED_RENAME"],
            "chmod": ["FS_PRIVILEGED_CHMOD"],
            "chown": ["FS_PRIVILEGED_CHOWN"],
        }.get(group, [])
        if group == "open" and user_controlled and resource_validation == "NONE_OBSERVED":
            classes.append("FS_SYMLINK_FOLLOW")
        if toctou:
            classes.append("FS_TOCTOU")
        if bound_temp:
            classes.extend(["FS_UNSAFE_TEMP", "FS_WRITABLE_PARENT"])
        target = "potentially security-sensitive"
        target_category = "unresolved"
        if context["sensitive"]:
            target, target_category = context["sensitive"][0]
        elif context["temporary"]:
            target, target_category = context["temporary"][0], "unsafe_temporary"
        if bound_sensitive and group in _WRITE_LIKE:
            if target_category == "launch_daemon_plist" or target.lower().endswith(".plist"):
                classes.append("FS_PLIST_OVERWRITE")
            if target_category in {"privileged_helper", "privileged_executable", "root_script"}:
                classes.append("FS_EXECUTABLE_OVERWRITE")
        classes = list(dict.fromkeys(classes))
        if not classes:
            continue

        caller_validation, caller_validation_scope = _caller_validation(finding)
        signals = {
            "privileged_process": int(weights.get("privileged_process", 20)),
            "dangerous_filesystem_sink": int(weights.get("dangerous_filesystem_sink", 15)),
        }
        if user_controlled:
            signals["attacker_controlled_path"] = int(
                weights.get("attacker_controlled_path", 20))
        if caller_validation == "NONE_OBSERVED":
            signals["caller_validation_none_observed"] = int(
                weights.get("caller_validation_none_observed", 20))
        if resource_validation == "NONE_OBSERVED":
            signals["resource_validation_none_observed"] = int(
                weights.get("resource_validation_none_observed", 15))
        if bound_sensitive:
            signals["sensitive_target"] = int(weights.get("sensitive_target", 25))
        if toctou:
            signals["toctou_pattern"] = int(weights.get("toctou_pattern", 20))
        if bound_temp:
            signals["unsafe_temporary_path"] = int(
                weights.get("unsafe_temporary_path", 10))
        score = min(100, sum(signals.values()))
        confidence = _confidence(finding, user_controlled, contextual)
        origin, input_name = _input_origin(finding)
        evidence = [
            f"privileged service {service.label} runs as root/system",
            f"bounded IPC path reaches {finding.sink_api}@{finding.sink_address}",
            f"path control: {path_state}",
        ]
        if context["context_only"]:
            evidence.append(
                "sensitive/temporary path strings occur in the binary but are not bound to this sink")
        evidence.extend(resource_evidence)
        evidence.extend(scope_evidence)
        evidence.extend(scope_notes)
        research_questions: List[str] = []
        if resource_scope != "PATH_SCOPE_GUARD":
            research_questions.append(
                "resource authorization unresolved: is the target constrained to an allowed root?")
        if finding.authorization.scope != "AUTHORIZATION_GUARDS_SINK":
            research_questions.append(
                "operation authorization unresolved: does a per-operation check guard this sink?")
        missing = []
        if not user_controlled:
            missing.append("path argument control is not established")
        if not bound_sensitive:
            missing.append("security-sensitive target path is not bound to this operation")
        if finding.identity.scope != "VALIDATION_GUARDS_SINK":
            missing.append("caller validation is not proven to guard this filesystem operation")
        missing.append("caller authority over the selected resource is not proven; metadata and descriptor checks do not establish it")
        if finding.authorization.scope != "AUTHORIZATION_GUARDS_SINK":
            missing.append("operation authorization is not proven to guard this filesystem operation")
        digest = hashlib.sha1(
            f"{service.label}:{finding.finding_id}:{','.join(classes)}".encode("utf-8")
        ).hexdigest()[:10]
        out.append(LPEFinding(
            finding_id=f"lpe-{digest}", lpe_classes=classes,
            operation=group, sink_api=finding.sink_api,
            privilege="root", entry_point=finding.entry_point,
            input_origin=origin, input_name=input_name,
            user_controlled=user_controlled,
            caller_validation=caller_validation,
            caller_validation_scope=caller_validation_scope,
            operation_authorization=finding.authorization.strength,
            operation_authorization_scope=finding.authorization.scope,
            resource_validation=resource_validation,
            resource_validation_evidence=resource_evidence,
            target=target, target_category=target_category,
            target_sensitive=bound_sensitive,
            toctou_candidate=toctou, unsafe_temporary_path=bound_temp,
            confidence=confidence, score=score, severity=_severity(score, rules),
            evidence=evidence, missing_evidence=missing,
            sink_address=finding.sink_address, function=finding.handler_function,
            source_finding_id=finding.finding_id,
            analysis_sources=list(finding.analysis_sources), score_signals=signals,
            resource_authorization="UNKNOWN",
            descriptor_provenance=(flow or {}).get("descriptor_provenance", {}),
            resource_scope=resource_scope,
            resource_scope_confidence=scope_confidence,
            resource_scope_evidence=scope_evidence,
            research_questions=research_questions,
        ))
    out.sort(key=lambda finding: (finding.score, finding.confidence), reverse=True)
    return out


def refresh_lpe_findings(targets: Iterable[Any]) -> None:
    for target in targets:
        executable = getattr(target, "executable", None)
        macho = getattr(executable, "macho", None) if executable else None
        target.lpe_findings = analyze_lpe(
            target.service, macho, getattr(target, "capability_findings", []))
