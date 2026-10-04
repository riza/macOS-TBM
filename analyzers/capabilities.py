"""Operation-scoped capability maturity, controls and scoring.

Binary-wide observations create candidates. Only dataflow facts may advance a
finding to reachable/controlled maturity, and strong primitive names remain
unset unless every promotion requirement is explicitly proven.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Tuple

from models.capability import (
    AUTHORIZATION_GUARDS_SINK,
    AUTHORIZATION_NOT_OBSERVED,
    AUTHORIZATION_PER_MESSAGE,
    AUTHORIZATION_PRESENT_IN_BINARY,
    AUTHORIZATION_PROFILE_ALLOWLIST,
    MATURITY_ORDER,
    VALIDATION_GUARDS_SINK,
    VALIDATION_NOT_OBSERVED,
    VALIDATION_PRESENT_IN_BINARY,
    CapabilityEvidence,
    CapabilityFinding,
    DataSource,
    ExploitabilityEvidenceScore,
    PrimitiveEdge,
    SecurityControl,
)
from utils.rules import capability_rules, scoring_rules

from ._match import match_details, string_match_quality


def _hits(macho, patterns: List[str]) -> List[Tuple[str, str, str]]:
    if not macho:
        return []
    out: List[Tuple[str, str, str]] = []
    seen = set()
    for kind, values, anchored in (
        ("import", macho.imported_symbols, True),
        ("objc", macho.objc_classes, True),
        ("string", macho.interesting_strings, False),
    ):
        for pattern, value in match_details(values, patterns, anchored=anchored):
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            if kind == "string" and string_match_quality(pattern, value) != "identifier":
                kind = "token"
            out.append((kind, pattern, value))
    return out


def _sources(macho) -> List[DataSource]:
    rules = capability_rules().get("sources", {})
    return [
        DataSource(api=value, data_kind=rules[pattern], attacker_control="UNKNOWN",
                   confidence="LOW")
        for kind, pattern, value in _hits(macho, list(rules)) if kind == "import"
    ]


def _identity_strength(sig_result) -> Tuple[str, str, List[str]]:
    assessment = sig_result.validation_assessment
    classes = set(assessment.by_class)
    evidence = [e.describe() for e in assessment.evidence]
    matches = {e.match for e in assessment.evidence}
    method = ", ".join(sorted(classes)) or "NONE_OBSERVED"
    if matches & {"SecTaskCreateFromSelf", "SecCodeCopySelf"}:
        return method, "WEAK", evidence
    remote_identity = bool(matches & {
        "SecTaskCreateWithAuditToken", "SecCodeCopyGuestWithAttributes"})
    verifies_code = bool(matches & {
        "SecCodeCheckValidity", "SecStaticCodeCheckValidity"})
    if remote_identity and verifies_code and "audit-token-extraction" in classes:
        return method, "STRONG", evidence
    if ("SecTaskCreateWithAuditToken" in matches
            and "SecTaskCopyValueForEntitlement" in matches
            and "audit-token-extraction" in classes):
        return method, "STRONG", evidence
    if classes & {"entitlement-check", "per-message-entitlement",
                  "sectask-entitlement", "code-signing-requirement"}:
        return method, "CONDITIONAL", evidence
    if classes:
        return method, "WEAK", evidence
    return method, "NONE_OBSERVED", []


def _binary_identity(sig_result) -> SecurityControl:
    method, strength, evidence = _identity_strength(sig_result)
    return SecurityControl(
        method=method, strength=strength,
        scope=(VALIDATION_PRESENT_IN_BINARY if evidence else VALIDATION_NOT_OBSERVED),
        evidence=evidence,
    )


def _authorization_strength(api: str) -> str:
    if api == "AuthorizationCopyRights":
        return "STRONG"
    if api in {"sandbox_check", "sandbox_check_by_audit_token"}:
        return "CONDITIONAL"
    if api in {"SecTaskCopyValueForEntitlement", "xpc_connection_copy_entitlement_value"}:
        return "CONDITIONAL"
    return "WEAK"


def _binary_authorization(macho, sig_result=None) -> SecurityControl:
    patterns = capability_rules().get("authorization", [])
    evidence = [value for kind, _pattern, value in _hits(macho, patterns)
                if kind in ("import", "objc")]
    per_message = bool(
        sig_result
        and "per-message-entitlement" in sig_result.validation_assessment.by_class
    )
    if per_message:
        return SecurityControl(
            method="per-message entitlement (valueForEntitlement)",
            strength="CONDITIONAL", scope=AUTHORIZATION_PER_MESSAGE,
            evidence=["correlated NSXPCConnection valueForEntitlement: + boolValue pattern"],
            relationship_confidence="MEDIUM",
        )
    if not evidence:
        return SecurityControl(
            method="NONE_OBSERVED", strength="NONE_OBSERVED",
            scope=AUTHORIZATION_NOT_OBSERVED,
        )
    strongest = max((_authorization_strength(api) for api in evidence),
                    key=lambda value: {"WEAK": 1, "CONDITIONAL": 2, "STRONG": 3}[value])
    return SecurityControl(
        method=", ".join(evidence), strength=strongest,
        scope=AUTHORIZATION_PRESENT_IN_BINARY, evidence=evidence,
    )


def _scoped_control(binary: SecurityControl, flow: Optional[Dict], kind: str) -> SecurityControl:
    if not flow:
        return binary
    controls = flow.get(f"{kind}_controls") or []
    if not controls:
        return binary
    ranked = sorted(controls, key=lambda control: (
        control.get("scope", "").endswith("GUARDS_SINK"),
        bool(control.get("branch_address"))), reverse=True)
    best = ranked[0]
    strength = (binary.strength if kind == "validation"
                else _authorization_strength(best.get("api", "")))
    return SecurityControl(
        method=best.get("api", binary.method), strength=strength,
        scope=best.get("scope", binary.scope),
        evidence=[f"{best.get('api')} in {best.get('function')}"] + list(binary.evidence),
        function=best.get("function", ""),
        branch_address=best.get("branch_address", ""),
        relationship_confidence=("HIGH" if best.get("scope", "").endswith("GUARDS_SINK")
                                 else "MEDIUM"),
        guard_evidence=dict(best.get("guard_evidence", {})),
        unknown_reason=best.get("unknown_reason", ""),
    )


def _reachability(service) -> List[str]:
    if not getattr(service, "enabled", True):
        return ["UNKNOWN"]
    if service.mach_services or service.sockets:
        return ["LOCAL_USER", "UNSANDBOXED_PROCESS"]
    if getattr(service, "xpc_service", False):
        return ["SYSTEM_COMPONENT_ONLY", "UNKNOWN"]
    return ["UNKNOWN"]


_SANDBOX_PREDICATES = {"sandbox_check", "sandbox_check_by_audit_token"}


def _policy_paths(flow: Optional[Dict]) -> List[Dict]:
    """Model dispatcher predicates as ``predicate -> allowed op`` paths.

    A predicate is never promoted to an operation guard here; the failure and
    success successors are left empty until the control-flow pass proves them.
    """
    if not flow:
        return []
    declared = capability_rules().get("profile_predicates", {})
    sandbox_predicates = set(declared) or _SANDBOX_PREDICATES
    paths: List[Dict] = []
    for control in flow.get("authorization_controls", []):
        api = control.get("api", "")
        if api in sandbox_predicates:
            paths.append({
                "predicate": api,
                "allowed_operation": flow.get("sink_api", ""),
                "success_semantics": declared.get(api, {}).get(
                    "success_semantics", "UNKNOWN"),
                "scope": control.get("scope", ""),
                "reject_successor": "",
                "continue_successor": "",
                "relationship": "PREDICATE_OBSERVED",
                "evidence": [f"{api} in {control.get('function', '')}"],
            })
    return paths


def _caller_profiles(service, policy_paths: List[Dict]) -> List[Dict]:
    """Per-profile reachability and authorization, kept separate from identity."""
    reachability = _reachability(service)
    if "LOCAL_USER" in reachability:
        unsandboxed_entry, sandboxed_entry = "DECLARED", "CONDITIONAL"
    else:
        unsandboxed_entry, sandboxed_entry = "UNKNOWN", "UNKNOWN"
    unsandboxed = {
        "profile": "UNSANDBOXED", "entry_reachability": unsandboxed_entry,
        "mach_lookup": "NOT_REQUIRED", "authorization": "AUTHORIZATION_NOT_OBSERVED",
        "declared_client_capability": [],
        "basis": "Mach service exposed to local processes; no sandbox needed",
    }
    sandboxed = {
        "profile": "SANDBOXED", "entry_reachability": sandboxed_entry,
        "mach_lookup": "UNKNOWN", "authorization": "AUTHORIZATION_NOT_OBSERVED",
        "declared_client_capability": [],
        "basis": "sandbox mach-lookup capability is client-side and not observable server-side",
    }
    if policy_paths:
        sandboxed["authorization"] = AUTHORIZATION_PROFILE_ALLOWLIST
        sandboxed["basis"] += "; dispatcher exposes a caller-sandbox predicate"
    entitled = {
        "profile": "PRIVATE_ENTITLEMENT", "entry_reachability": "UNKNOWN",
        "mach_lookup": "UNKNOWN", "authorization": "AUTHORIZATION_NOT_OBSERVED",
        "declared_client_capability": [],
        "basis": "no client binary or launch metadata proving a private entitlement",
    }
    unknown = {
        "profile": "UNKNOWN", "entry_reachability": "UNKNOWN",
        "mach_lookup": "UNKNOWN", "authorization": "UNKNOWN",
        "declared_client_capability": [],
        "basis": "caller identity not recovered statically",
    }
    return [unsandboxed, sandboxed, entitled, unknown]


def _transport(service, macho) -> str:
    if service.mach_services:
        return "Mach/XPC"
    if service.sockets:
        return "launchd socket"
    if getattr(service, "xpc_service", False):
        return "bundled XPC"
    if _sources(macho):
        return "XPC (registration not resolved)"
    return "UNKNOWN"


def _entry(service) -> str:
    if service.mach_services:
        return ", ".join(service.mach_services[:3])
    if service.sockets:
        return "launchd socket: " + ", ".join(list(service.sockets)[:3])
    return "entry point not resolved statically"


def _matches_pattern(api: str, pattern: str) -> bool:
    api = api.lstrip("_")
    if pattern.endswith("*"):
        return api.startswith(pattern[:-1])
    if pattern.endswith(":"):
        # ObjC selector prefix.
        return api.startswith(pattern)
    return api == pattern


def _argument_map(operation: Dict, sink_api: str) -> Dict[int, str]:
    mappings = operation.get("arguments", {})
    for pattern, values in mappings.items():
        if _matches_pattern(sink_api, pattern):
            return {int(index): name for index, name in values.items()}
    return {}


def _control_fields(operation: Dict, sink_api: str, flow: Optional[Dict]) -> Dict[str, str]:
    mapping = _argument_map(operation, sink_api)
    fields = {name: "UNKNOWN" for name in mapping.values()}
    if not fields:
        for name in operation.get("required_control", []):
            fields[name] = "UNKNOWN"
        for name in operation.get("required_control_any", []):
            fields[name] = "UNKNOWN"
    if not flow:
        return fields or {"request_parameters": "UNKNOWN"}
    for index in flow.get("constant_argument_indexes", []):
        fields[mapping.get(int(index), f"argument_{index}")] = "CONSTANT"
    for index in flow.get("controlled_argument_indexes", []):
        fields[mapping.get(int(index), f"argument_{index}")] = "HIGH"
    descriptor_index = next((index for index, name in mapping.items()
                             if name == "file_descriptor"), None)
    if (descriptor_index is not None and fields.get("file_descriptor") == "HIGH"
            and flow.get("descriptor_provenance", {}).get(str(descriptor_index))):
        fields["resource_path"] = "HIGH"
    return fields or {"request_parameters": "UNKNOWN"}


def _required_control_satisfied(operation: Dict, controls: Dict[str, str]) -> Tuple[bool, bool]:
    required = operation.get("required_control", [])
    alternatives = operation.get("required_control_any", [])
    all_required = bool(required) and all(controls.get(name) == "HIGH" for name in required)
    any_required = bool(alternatives) and any(controls.get(name) == "HIGH" for name in alternatives)
    satisfied = all_required or any_required
    partial = any(value == "HIGH" for value in controls.values()) and not satisfied
    return satisfied, partial


def _maturity(operation: Dict, service, flow: Optional[Dict], controls: Dict[str, str]) -> Tuple[str, Optional[str]]:
    if not flow or flow.get("reachability_confirmed") is False:
        return "SINK_CANDIDATE", None
    satisfied, _partial = _required_control_satisfied(operation, controls)
    if not satisfied:
        return "REACHABLE_SINK", None
    maturity = "CONTROLLED_SINK"
    # NONE_OBSERVED is uncertainty, not proof of an authorization bypass. The
    # static pass promotes only when an upstream analyzer explicitly proves the
    # boundary and operation authority conditions.
    promotion = bool(
        flow.get("source_binding") == "PROVEN"
        and flow.get("authorization_bypass_proven") is True
        and service.is_privileged
    )
    primitive = operation.get("proven_primitive") if promotion else None
    if primitive:
        maturity = "PRIMITIVE"
    if primitive and flow.get("post_condition_proven") is True:
        maturity = "IMPACT"
    return maturity, primitive


def _attacker_control(operation: Dict, controls: Dict[str, str], flow: Optional[Dict]) -> str:
    if not flow:
        return "UNKNOWN"
    satisfied, partial = _required_control_satisfied(operation, controls)
    if satisfied:
        return "HIGH"
    if partial:
        return "PARTIAL"
    relevant = [
        name for name in (
            list(operation.get("required_control", []))
            + list(operation.get("required_control_any", []))
        ) if name in controls
    ]
    if relevant and all(controls.get(name) == "CONSTANT" for name in relevant):
        return "LOW"
    return "UNKNOWN"


def _research_priority(service, macho, operation: Dict, operation_count: int,
                       identity: SecurityControl, codesign=None,
                       authorization: Optional[SecurityControl] = None,
                       controls: Optional[Dict[str, str]] = None,
                       flow: Optional[Dict] = None) -> int:
    weights = scoring_rules().get("research_priority", {})
    score = 0
    score += 25 if service.is_privileged else 5
    score += 20 if (service.mach_services or service.sockets) else 5
    score += 5 if getattr(service, "enabled", True) else 0
    entitlements = getattr(codesign, "entitlements", {}) or {}
    score += min(10, len(entitlements))
    score += min(15, int(operation.get("research_value", 5)))
    score += min(10, operation_count // 2)
    score += 5 if _sources(macho) else 0
    score += 5 if identity.scope in {VALIDATION_NOT_OBSERVED, VALIDATION_PRESENT_IN_BINARY} else 0
    # The research-priority combination is deliberately separate from the
    # exploitability-evidence score: it routes attention, it does not prove a
    # bypass or a primitive.
    controls = controls or {}
    caller_influenced = bool(flow and (
        flow.get("controlled_argument_indexes") or flow.get("descriptor_provenance")))
    resource_controlled = any(
        controls.get(name) == "HIGH"
        for name in ("path", "file_descriptor", "resource_path", "destination_path"))
    if caller_influenced and resource_controlled:
        score += int(weights.get("controlled_resource_sink", 10))
    if authorization is not None and authorization.scope != AUTHORIZATION_GUARDS_SINK:
        score += int(weights.get("unresolved_operation_authorization", 8))
    if resource_controlled and operation.get("category") in {"filesystem", "credential"}:
        score += int(weights.get("write_or_ownership_sink", 5))
    return min(100, score)


def _risk_for_control(control: SecurityControl, guards_scope: str) -> int:
    if control.scope == guards_scope:
        return {"STRONG": 1, "CONDITIONAL": 3, "WEAK": 6,
                "NONE_OBSERVED": 5}.get(control.strength, 5)
    if control.scope.endswith("REACHABLE_FROM_HANDLER"):
        return 4
    # A binary-wide check is not credited as protection for this operation.
    return 5


def _exploitability_score(service, maturity: str, identity: SecurityControl,
                          authorization: SecurityControl, attacker_control: str,
                          confidence: str, reply_flow: List[str], requires_reply: bool,
                          chainable: bool) -> ExploitabilityEvidenceScore:
    maturity_axis = {
        "SINK_CANDIDATE": 1, "REACHABLE_SINK": 4, "CONTROLLED_SINK": 7,
        "PRIMITIVE": 9, "IMPACT": 10,
    }[maturity]
    return ExploitabilityEvidenceScore(
        entry_point_reachability=(5 if getattr(service, "enabled", True)
                                  and (service.mach_services or service.sockets) else 2),
        identity_weakness=_risk_for_control(identity, VALIDATION_GUARDS_SINK),
        authorization_weakness=_risk_for_control(authorization, AUTHORIZATION_GUARDS_SINK),
        attacker_control={"UNKNOWN": 1, "LOW": 2, "PARTIAL": 5, "HIGH": 8}.get(
            attacker_control, 1),
        sink_reachability={"SINK_CANDIDATE": 1, "REACHABLE_SINK": 5,
                           "CONTROLLED_SINK": 7, "PRIMITIVE": 9, "IMPACT": 10}[maturity],
        primitive_maturity=maturity_axis,
        post_condition={"SINK_CANDIDATE": 1, "REACHABLE_SINK": 2,
                        "CONTROLLED_SINK": 4, "PRIMITIVE": 7, "IMPACT": 10}[maturity],
        reply_dataflow=(8 if reply_flow else (0 if requires_reply else 5)),
        chainability=(5 if chainable and maturity in {"PRIMITIVE", "IMPACT"} else 1),
        analysis_confidence={"SPECULATIVE": 1, "LOW": 2, "MEDIUM": 5,
                             "HIGH": 8, "CONFIRMED": 10}[confidence],
        maturity_level=maturity,
    )


def _unknown_reasons(macho, flow: Optional[Dict], attacker_control: str,
                     sources: List[DataSource]) -> List[str]:
    reasons = set(flow.get("unknown_reasons", []) if flow else [])
    if flow and flow.get("reachability_confirmed") is False:
        reasons.add("UNKNOWN_NO_CALL_PATH")
    if not sources:
        reasons.add("UNKNOWN_NO_IPC_SOURCE")
    if not flow:
        reasons.add("UNKNOWN_NO_CALL_PATH")
        reasons.update((getattr(macho, "dataflow_unknown_reasons", {}) or {}).keys())
    elif attacker_control == "UNKNOWN" and not reasons:
        reasons.add("UNKNOWN_ALIAS")
    return sorted(reasons)


def _missing_and_steps(operation: Dict, maturity: str, controls: Dict[str, str],
                       identity: SecurityControl, authorization: SecurityControl,
                       flow: Optional[Dict], reply_flow: List[str]) -> Tuple[List[str], List[str]]:
    missing: List[str] = []
    steps: List[str] = []
    if not flow or flow.get("reachability_confirmed") is False:
        missing.append("No supported call path from an IPC source to this sink")
        steps.append("Resolve the handler and direct/indirect call path to the sink")
    unknown_args = [name for name, state in controls.items() if state == "UNKNOWN"]
    if unknown_args:
        missing.append("Sink argument control unresolved: " + ", ".join(unknown_args))
        steps.append("Determine the origin of sink argument(s): " + ", ".join(unknown_args))
    if identity.scope == VALIDATION_PRESENT_IN_BINARY:
        missing.append("Caller validation exists in the binary but is not proven to guard this sink")
        steps.append("Determine whether the validation result branch dominates the sink")
    elif identity.scope == VALIDATION_NOT_OBSERVED:
        missing.append("Operation-scoped caller identity verification not observed")
        steps.append("Recover caller identity checks on the operation path")
    if authorization.scope == AUTHORIZATION_PRESENT_IN_BINARY:
        missing.append("Authorization exists in the binary but is not proven to guard this operation")
        steps.append("Bind the authorization decision to this sink")
    elif authorization.scope == AUTHORIZATION_PER_MESSAGE:
        missing.append(
            "Per-message entitlement checks are present but this check is not yet bound to the sink")
        steps.append("Map the handler entitlement reject branch to this sink")
    elif authorization.scope == AUTHORIZATION_NOT_OBSERVED:
        missing.append("Operation authorization not observed on the recovered path")
        steps.append("Recover per-operation authorization checks and reject paths")
    if operation.get("requires_reply") and not reply_flow:
        missing.append("Sensitive result is not proven to reach an IPC/Mach reply")
        steps.append("Trace the operation result into a reply or completion handler")
    if operation.get("requires_private_exportable_key"):
        missing.append("Key class and exportability are not established")
        steps.append("Determine key origin, private/public class and Secure Enclave/exportability state")
    if maturity not in {"PRIMITIVE", "IMPACT"}:
        missing.append("Attacker-useful primitive is not proven")
    if maturity != "IMPACT":
        missing.append("Concrete post-condition is not proven")
        steps.append("Verify the operation's concrete post-condition")
    return list(dict.fromkeys(missing)), list(dict.fromkeys(steps))


_CONTROL_RANK = {"UNKNOWN": 0, "CONSTANT": 1, "LOW": 1, "PARTIAL": 2, "HIGH": 3}


def _merge_duplicate_findings(findings: List[CapabilityFinding]) -> List[CapabilityFinding]:
    """Collapse findings that share an id (same service + sink instance).

    Many dataflow facts can reach the same sink from different sources; they
    describe one operation instance and must not be reported as separate
    findings. The strongest evidence wins and the inputs are merged.
    """
    groups: Dict[str, List[CapabilityFinding]] = {}
    for finding in findings:
        groups.setdefault(finding.finding_id, []).append(finding)
    merged: List[CapabilityFinding] = []
    for group in groups.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        best = max(group, key=lambda f: (
            MATURITY_ORDER.index(f.maturity_level)
            if f.maturity_level in MATURITY_ORDER else 0,
            f.research_priority_score, f.exploitability_evidence_score))
        seen_sources = {(s.api, s.address, s.function, s.name) for s in best.sources}
        seen_evidence = {(e.kind, e.value, e.address) for e in best.evidence}
        reasons = set(best.unknown_reasons)
        controls = dict(best.controlled_arguments)
        profiles = {p.get("profile") for p in best.caller_profiles}
        paths = {(p.get("predicate"), p.get("allowed_operation"))
                 for p in best.policy_paths}
        for finding in group:
            for source in finding.sources:
                key = (source.api, source.address, source.function, source.name)
                if key not in seen_sources:
                    seen_sources.add(key)
                    best.sources.append(source)
            for evidence in finding.evidence:
                key = (evidence.kind, evidence.value, evidence.address)
                if key not in seen_evidence:
                    seen_evidence.add(key)
                    best.evidence.append(evidence)
            reasons.update(finding.unknown_reasons)
            for name, value in finding.controlled_arguments.items():
                if _CONTROL_RANK.get(value, 0) > _CONTROL_RANK.get(
                        controls.get(name, "UNKNOWN"), 0):
                    controls[name] = value
            for key, value in finding.descriptor_provenance.items():
                best.descriptor_provenance.setdefault(key, value)
            for profile in finding.caller_profiles:
                if profile.get("profile") not in profiles:
                    profiles.add(profile.get("profile"))
                    best.caller_profiles.append(profile)
            for path in finding.policy_paths:
                key = (path.get("predicate"), path.get("allowed_operation"))
                if key not in paths:
                    paths.add(key)
                    best.policy_paths.append(path)
        best.unknown_reasons = sorted(reasons)
        best.controlled_arguments = controls
        merged.append(best)
    return merged


def analyze_capabilities(service, macho, sig_result, codesign=None) -> Tuple[List[CapabilityFinding], List[PrimitiveEdge]]:
    rules = capability_rules()
    binary_sources = _sources(macho)
    binary_identity = _binary_identity(sig_result)
    binary_authorization = _binary_authorization(macho, sig_result)
    reachability = _reachability(service)
    operations_present = []
    for operation in rules.get("operations", []):
        hits = _hits(macho, operation.get("symbols", []))
        flows = [
            fact for fact in (getattr(macho, "dataflow_facts", []) if macho else [])
            if any(_matches_pattern(fact.get("sink_api", ""), pattern)
                   for pattern in operation.get("symbols", []))
        ]
        useful_hits = [hit for hit in hits if hit[0] in ("import", "objc")]
        useful_hits = useful_hits or [hit for hit in hits if hit[0] == "string"]
        if useful_hits or flows:
            operations_present.append((operation, useful_hits, flows))

    findings: List[CapabilityFinding] = []
    proven_primitives: List[str] = []
    for operation, hits, flows in operations_present:
        instances = flows or [None]
        for instance_index, flow in enumerate(instances, 1):
            sink_api = (flow.get("sink_api") if flow else hits[0][2])
            controls = _control_fields(operation, sink_api, flow)
            attacker_control = _attacker_control(operation, controls, flow)
            maturity, proven_primitive = _maturity(operation, service, flow, controls)
            if proven_primitive:
                proven_primitives.append(proven_primitive)
            identity = _scoped_control(binary_identity, flow, "validation")
            authorization = _scoped_control(binary_authorization, flow, "authorization")
            reply_flow = list(flow.get("reply_dataflow", [])) if flow else []
            confidence = (
                "LOW" if not flow else
                ("HIGH" if attacker_control == "HIGH" and not flow.get("unknown_reasons")
                 else "MEDIUM")
            )
            if maturity == "IMPACT" and flow and flow.get("runtime_confirmed"):
                confidence = "CONFIRMED"
            candidate = operation["candidate_capability"]
            chainable = operation.get("proven_primitive") in {
                chain["source"] for chain in rules.get("chains", [])}
            exploitability = _exploitability_score(
                service, maturity, identity, authorization, attacker_control,
                confidence, reply_flow, bool(operation.get("requires_reply")), chainable)
            research_priority = _research_priority(
                service, macho, operation, len(operations_present), binary_identity,
                codesign, authorization=authorization, controls=controls, flow=flow)
            sources = list(binary_sources)
            if flow and flow.get("source_api") != "unknown":
                sources = [DataSource(
                    api=flow.get("source_api", "unknown"), data_kind="IPC field",
                    attacker_control=("HIGH" if flow.get("controlled_argument_indexes") else "LOW"),
                    confidence=flow.get("confidence", "MEDIUM"),
                    address=flow.get("source_address", ""),
                    function=flow.get("source_function", ""),
                    name=flow.get("source_key"),
                    argument=flow.get("source_key") or "unknown",
                )]
            unknown = _unknown_reasons(macho, flow, attacker_control, sources)
            missing, steps = _missing_and_steps(
                operation, maturity, controls, identity, authorization, flow, reply_flow)
            policy_paths = _policy_paths(flow)
            caller_profiles = _caller_profiles(service, policy_paths)
            digest = hashlib.sha1(
                f"{service.label}:{sink_api}:{flow.get('sink_address', '') if flow else instance_index}"
                .encode("utf-8")).hexdigest()[:10]
            evidence = [CapabilityEvidence(
                kind=kind, value=value,
                meaning=("binary imports the sensitive operation" if kind == "import"
                         else "static reference to the operation"),
                relationship="PROVEN" if kind == "import" else "INFERRED",
            ) for kind, _pattern, value in hits[:8]]
            if flow:
                evidence.append(CapabilityEvidence(
                    kind="dataflow", value="; ".join(flow.get("propagation") or []),
                    meaning="bounded source/call-path/sink relationship",
                    address=flow.get("sink_address", ""),
                    relationship=("PROVEN" if flow.get("controlled_argument_indexes") else "INFERRED"),
                    function=flow.get("function", ""),
                ))
            entry_function = flow.get("entry_point_function", "") if flow else ""
            edge_states = [
                {"from": "entry_point", "to": "source",
                 "state": "INFERRED" if sources else "UNRESOLVED"},
                {"from": "source", "to": "sink",
                 "state": ("PROVEN" if maturity in {"CONTROLLED_SINK", "PRIMITIVE", "IMPACT"}
                           else "INFERRED" if maturity == "REACHABLE_SINK" else "UNRESOLVED")},
                {"from": "candidate", "to": "primitive",
                 "state": "PROVEN" if proven_primitive else "UNRESOLVED"},
            ]
            findings.append(CapabilityFinding(
                finding_id=f"cap-{digest}",
                entry_point=(f"{_entry(service)} :: {entry_function}" if entry_function
                             else _entry(service)),
                handler_function=entry_function,
                transport=_transport(service, macho),
                sources=sources,
                caller_identity=("local client; successful connection unverified"
                                 if "LOCAL_USER" in reachability else "UNKNOWN"),
                expected_caller_identity=(
                    "caller holding " + ", ".join(sig_result.checked_entitlements[:4])
                    if sig_result.checked_entitlements else "UNKNOWN (not recovered statically)"),
                identity=identity,
                authorization=authorization,
                sink_category=operation["category"],
                sink_api=sink_api,
                sink_operation=operation["operation"],
                candidate_capability=candidate,
                maturity_level=maturity,
                proven_primitive=proven_primitive,
                attacker_control=attacker_control,
                controlled_arguments=controls,
                reachability=reachability,
                post_condition=operation["post_condition"],
                post_condition_confidence={
                    "SINK_CANDIDATE": "SPECULATIVE", "REACHABLE_SINK": "LOW",
                    "CONTROLLED_SINK": "MEDIUM", "PRIMITIVE": "HIGH", "IMPACT": "CONFIRMED",
                }[maturity],
                potential_impact=operation["impact"],
                confidence=confidence,
                evidence=evidence,
                missing_evidence=missing,
                next_research_steps=steps,
                unknown_reasons=unknown,
                exploitability_score=exploitability,
                research_priority_score=research_priority,
                framework=operation.get("framework", ""),
                path_control=(controls.get("path", controls.get("destination_path", "not-applicable"))),
                dataflow=(list(flow.get("propagation") or []) if flow else
                          ([sources[0].api, "unresolved call path", sink_api]
                           if sources else ["source unresolved", sink_api])),
                reply_dataflow=reply_flow,
                edge_states=edge_states,
                sink_address=flow.get("sink_address", "") if flow else "",
                caller_profiles=caller_profiles,
                policy_paths=policy_paths,
                descriptor_provenance=(dict(flow.get("descriptor_provenance", {}))
                                       if flow else {}),
                call_path_state=(flow.get("reachability_state", "UNRESOLVED")
                                 if flow else "NOT_OBSERVED"),
                call_path=(list(flow.get("call_path", [])) if flow else []),
            ))

    edges: List[PrimitiveEdge] = []
    findings = _merge_duplicate_findings(findings)
    for chain in rules.get("chains", []):
        if chain["source"] not in proven_primitives:
            continue
        edges.append(PrimitiveEdge(
            source=chain["source"], target=chain["target"],
            required_precondition=chain["precondition"],
            evidence=[f"{chain['source']} primitive proven in {service.label}"],
            confidence="LOW", missing_proof=chain["missing"], edge_state="UNRESOLVED",
        ))
    return findings, edges
