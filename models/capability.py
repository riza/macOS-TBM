"""Operation-scoped capability maturity and evidence models.

The central invariant is that an imported sensitive API is a sink candidate,
not an attacker primitive. Findings advance through an explicit maturity model
only as call-path, argument-control, authorization, reply-flow and
post-condition evidence accumulates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CONFIDENCE_ORDER = ["SPECULATIVE", "LOW", "MEDIUM", "HIGH", "CONFIRMED"]
CONTROL_ORDER = ["UNKNOWN", "LOW", "PARTIAL", "HIGH"]
MATURITY_ORDER = [
    "SINK_CANDIDATE", "REACHABLE_SINK", "CONTROLLED_SINK", "PRIMITIVE", "IMPACT",
]

VALIDATION_PRESENT_IN_BINARY = "VALIDATION_PRESENT_IN_BINARY"
VALIDATION_REACHABLE_FROM_HANDLER = "VALIDATION_REACHABLE_FROM_HANDLER"
VALIDATION_GUARDS_SINK = "VALIDATION_GUARDS_SINK"
VALIDATION_NOT_OBSERVED = "VALIDATION_NOT_OBSERVED"

AUTHORIZATION_PRESENT_IN_BINARY = "AUTHORIZATION_PRESENT_IN_BINARY"
AUTHORIZATION_PER_MESSAGE = "AUTHORIZATION_PER_MESSAGE"
AUTHORIZATION_REACHABLE_FROM_HANDLER = "AUTHORIZATION_REACHABLE_FROM_HANDLER"
AUTHORIZATION_GUARDS_SINK = "AUTHORIZATION_GUARDS_SINK"
AUTHORIZATION_NOT_OBSERVED = "AUTHORIZATION_NOT_OBSERVED"
AUTHORIZATION_PROFILE_ALLOWLIST = "AUTHORIZATION_PROFILE_ALLOWLIST"

PROFILE_SANDBOXED = "SANDBOXED"
PROFILE_UNSANDBOXED = "UNSANDBOXED"
PROFILE_ENTITLED = "PRIVATE_ENTITLEMENT"
PROFILE_UNKNOWN = "UNKNOWN"

UNKNOWN_REASONS = {
    "UNKNOWN_INDIRECT_CALL", "UNKNOWN_OBJC_DISPATCH", "UNKNOWN_SWIFT_DISPATCH",
    "UNKNOWN_WRAPPER", "UNKNOWN_ALIAS", "UNKNOWN_RETURN_VALUE",
    "UNKNOWN_BLOCK_CALLBACK", "UNKNOWN_MACH_MESSAGE_LAYOUT",
    "UNKNOWN_NO_CALL_PATH", "UNKNOWN_NO_IPC_SOURCE",
    "UNKNOWN_ANALYSIS_BUDGET", "UNKNOWN_OTHER",
}


@dataclass
class CapabilityEvidence:
    kind: str
    value: str
    meaning: str
    address: str = ""
    relationship: str = "INFERRED"
    function: str = ""
    evidence_source: str = "NATIVE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "value": self.value, "meaning": self.meaning,
            "address": self.address or None, "relationship": self.relationship,
            "function": self.function or None,
            "evidence_source": self.evidence_source,
        }


@dataclass
class DataSource:
    api: str
    data_kind: str
    argument: str = "unknown"
    attacker_control: str = "UNKNOWN"
    confidence: str = "LOW"
    name: str = ""
    address: str = ""
    function: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "api": self.api, "type": self.data_kind, "data_kind": self.data_kind,
            "argument": self.argument, "name": self.name or None,
            "address": self.address or None, "function": self.function or None,
            "attacker_control": self.attacker_control, "confidence": self.confidence,
        }


@dataclass
class SecurityControl:
    """Identity verification or operation authorization, with scope."""

    method: str = "NONE_OBSERVED"
    strength: str = "NONE_OBSERVED"
    scope: str = VALIDATION_NOT_OBSERVED
    evidence: List[str] = field(default_factory=list)
    function: str = ""
    branch_address: str = ""
    relationship_confidence: str = "LOW"
    guard_evidence: Dict[str, Any] = field(default_factory=dict)
    unknown_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method, "strength": self.strength, "scope": self.scope,
            "evidence": list(self.evidence), "function": self.function or None,
            "branch_address": self.branch_address or None,
            "relationship_confidence": self.relationship_confidence,
            "guard_evidence": dict(self.guard_evidence),
            "unknown_reason": self.unknown_reason or None,
        }


@dataclass
class ExploitabilityEvidenceScore:
    """Attacker-evidence axes, all oriented as attacker advantage (0..10)."""

    entry_point_reachability: int = 0
    identity_weakness: int = 0
    authorization_weakness: int = 0
    attacker_control: int = 0
    sink_reachability: int = 0
    primitive_maturity: int = 0
    post_condition: int = 0
    reply_dataflow: int = 0
    chainability: int = 0
    analysis_confidence: int = 0
    maturity_level: str = "SINK_CANDIDATE"

    @property
    def overall(self) -> int:
        values = [
            self.entry_point_reachability, self.identity_weakness,
            self.authorization_weakness, self.attacker_control,
            self.sink_reachability, self.primitive_maturity,
            self.post_condition, self.reply_dataflow, self.chainability,
            self.analysis_confidence,
        ]
        raw = round(sum(values) / len(values) * 10)
        ceilings = {
            "SINK_CANDIDATE": 20, "REACHABLE_SINK": 40,
            "CONTROLLED_SINK": 65, "PRIMITIVE": 85, "IMPACT": 100,
        }
        return max(0, min(ceilings.get(self.maturity_level, 20), raw))

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "entry_point_reachability": self.entry_point_reachability,
            "identity_weakness": self.identity_weakness,
            "authorization_weakness": self.authorization_weakness,
            "attacker_control": self.attacker_control,
            "sink_reachability": self.sink_reachability,
            "primitive_maturity": self.primitive_maturity,
            "post_condition": self.post_condition,
            "reply_dataflow": self.reply_dataflow,
            "chainability": self.chainability,
            "analysis_confidence": self.analysis_confidence,
            "overall": self.overall,
        }
        data.update({
            "reachability": self.entry_point_reachability,
            "caller_validation": self.identity_weakness,
            "authorization": self.authorization_weakness,
            "sink_capability": self.primitive_maturity,
            "confidence": self.analysis_confidence,
        })
        return data


# Compatibility name used by the first capability schema.
ExploitabilityScore = ExploitabilityEvidenceScore


@dataclass
class CapabilityFinding:
    finding_id: str
    entry_point: str
    transport: str
    sources: List[DataSource]
    caller_identity: str
    expected_caller_identity: str
    identity: SecurityControl
    authorization: SecurityControl
    sink_category: str
    sink_api: str
    sink_operation: str
    candidate_capability: str
    maturity_level: str
    proven_primitive: Optional[str]
    attacker_control: str
    controlled_arguments: Dict[str, str]
    reachability: List[str]
    post_condition: str
    post_condition_confidence: str
    potential_impact: str
    confidence: str
    evidence: List[CapabilityEvidence]
    missing_evidence: List[str]
    next_research_steps: List[str]
    unknown_reasons: List[str]
    exploitability_score: ExploitabilityEvidenceScore
    research_priority_score: int
    framework: str = ""
    path_control: str = "unknown"
    dataflow: List[str] = field(default_factory=list)
    reply_dataflow: List[str] = field(default_factory=list)
    edge_states: List[Dict[str, str]] = field(default_factory=list)
    sink_address: str = ""
    handler_function: str = ""
    analysis_sources: List[str] = field(default_factory=lambda: ["NATIVE"])
    optional_evidence: List[Dict[str, Any]] = field(default_factory=list)
    dynamic_reachability: Dict[str, Any] = field(default_factory=dict)
    evidence_conflicts: List[str] = field(default_factory=list)
    before_optional_analysis: Dict[str, Any] = field(default_factory=dict)
    caller_profiles: List[Dict[str, Any]] = field(default_factory=list)
    policy_paths: List[Dict[str, Any]] = field(default_factory=list)
    descriptor_provenance: Dict[str, Any] = field(default_factory=dict)
    call_path_state: str = "UNRESOLVED"
    call_path: List[str] = field(default_factory=list)

    @property
    def primitive(self) -> str:
        """Deprecated compatibility alias: proven primitive or candidate name."""
        return self.proven_primitive or self.candidate_capability

    @property
    def score(self) -> ExploitabilityEvidenceScore:
        """Deprecated compatibility alias for ``exploitability_score``."""
        return self.exploitability_score

    @property
    def identity_verification(self) -> str:
        return self.identity.strength

    @property
    def identity_evidence(self) -> List[str]:
        return self.identity.evidence

    @property
    def authorization_decision(self) -> str:
        return self.authorization.strength

    @property
    def authorization_evidence(self) -> List[str]:
        return self.authorization.evidence

    @property
    def missing_proof(self) -> List[str]:
        return self.missing_evidence

    @property
    def exploitability_evidence_score(self) -> int:
        return self.exploitability_score.overall

    def to_dict(self) -> Dict[str, Any]:
        score = self.exploitability_score.to_dict()
        return {
            "finding_id": self.finding_id,
            "entry_point": self.entry_point,
            "handler_function": self.handler_function or None,
            "transport": self.transport,
            "sources": [s.to_dict() for s in self.sources],
            "caller_identity": self.caller_identity,
            "expected_caller_identity": self.expected_caller_identity,
            "identity_verification": self.identity_verification,
            "identity_evidence": list(self.identity_evidence),
            "identity_verification_detail": self.identity.to_dict(),
            "authorization_decision": self.authorization_decision,
            "authorization_evidence": list(self.authorization_evidence),
            "authorization": self.authorization.to_dict(),
            "sink": {
                "category": self.sink_category, "api": self.sink_api,
                "operation": self.sink_operation, "framework": self.framework or None,
                "address": self.sink_address or None,
                "controlled_arguments": dict(self.controlled_arguments),
            },
            "candidate_capability": self.candidate_capability,
            "maturity": self.maturity_level,
            "maturity_level": self.maturity_level,
            "proven_primitive": self.proven_primitive,
            "primitive": self.primitive,
            "primitive_deprecated": True,
            "attacker_control": self.attacker_control,
            "controlled_arguments": dict(self.controlled_arguments),
            "path_control": self.path_control,
            "reachability": list(self.reachability),
            "dataflow": list(self.dataflow),
            "reply_dataflow": list(self.reply_dataflow),
            "edge_states": list(self.edge_states),
            "post_condition": self.post_condition,
            "post_condition_confidence": self.post_condition_confidence,
            "potential_impact": self.potential_impact,
            "confidence": self.confidence,
            "evidence": [e.to_dict() for e in self.evidence],
            "missing_evidence": list(self.missing_evidence),
            "missing_proof": list(self.missing_evidence),
            "next_research_steps": list(self.next_research_steps),
            "unknown_reasons": list(self.unknown_reasons),
            "analysis_sources": list(self.analysis_sources),
            "optional_evidence": list(self.optional_evidence),
            "dynamic_reachability": dict(self.dynamic_reachability),
            "evidence_conflicts": list(self.evidence_conflicts),
            "before_optional_analysis": dict(self.before_optional_analysis),
            "caller_profiles": list(self.caller_profiles),
            "policy_paths": list(self.policy_paths),
            "descriptor_provenance": dict(self.descriptor_provenance),
            "call_path_state": self.call_path_state,
            "call_path": list(self.call_path),
            "security_control_strength": {
                "identity_verification": self.identity.strength,
                "authorization": self.authorization.strength,
            },
            "exploitability_contribution": {
                "identity_weakness": score["identity_weakness"],
                "authorization_weakness": score["authorization_weakness"],
            },
            "exploitability_evidence": score,
            "exploitability_evidence_score": self.exploitability_evidence_score,
            "score": score,
            "score_deprecated": True,
            "research_priority_score": self.research_priority_score,
            "mermaid": capability_mermaid(self),
        }


@dataclass
class PrimitiveEdge:
    source: str
    target: str
    required_precondition: str
    evidence: List[str]
    confidence: str = "SPECULATIVE"
    missing_proof: str = ""
    edge_state: str = "UNRESOLVED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source, "target": self.target,
            "required_precondition": self.required_precondition,
            "evidence": list(self.evidence), "confidence": self.confidence,
            "missing_proof": self.missing_proof, "edge_state": self.edge_state,
        }


def _node(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9 _./:-]", "", text)[:100]


def _edge(state: str, label: str) -> str:
    if state == "PROVEN":
        return f"-->|{label}: PROVEN|"
    if state == "INFERRED":
        return f"-->|{label}: INFERRED|"
    return f"-.->|{label}: UNRESOLVED|"


def capability_mermaid(finding: CapabilityFinding) -> str:
    """Render an evidence-state-aware operation graph."""
    source = finding.sources[0].api if finding.sources else "Input not resolved"
    path_state = {
        "SINK_CANDIDATE": "UNRESOLVED", "REACHABLE_SINK": "INFERRED",
        "CONTROLLED_SINK": "PROVEN", "PRIMITIVE": "PROVEN", "IMPACT": "PROVEN",
    }.get(finding.maturity_level, "UNRESOLVED")
    primitive = finding.proven_primitive or "primitive not proven"
    lines = [
        "flowchart TD",
        f'  A["{_node(finding.caller_identity)}"]',
        f'  B["Trust boundary: {_node(finding.entry_point)}"]',
        f'  C["Source: {_node(source)}"]',
        f'  D["Identity: {_node(finding.identity.scope)}"]',
        f'  E["Authorization: {_node(finding.authorization.scope)}"]',
        f'  F["Sink: {_node(finding.sink_api)}"]',
        f'  G["Candidate: {_node(finding.candidate_capability)}"]',
        f'  H["Primitive: {_node(primitive)}"]',
        f'  I["Post-condition: {_node(finding.post_condition)}"]',
        f"  A {_edge('INFERRED', 'TRUST BOUNDARY')} B",
        f"  B {_edge('INFERRED' if finding.sources else 'UNRESOLVED', 'ENTRY')} C",
        f"  C {_edge(path_state, 'DATAFLOW')} F",
        f"  D {_edge('PROVEN' if finding.identity.scope == VALIDATION_GUARDS_SINK else 'INFERRED', 'VALIDATION')} F",
        f"  E {_edge('PROVEN' if finding.authorization.scope == AUTHORIZATION_GUARDS_SINK else 'INFERRED', 'AUTHORIZATION')} F",
        f"  F {_edge('PROVEN', 'SINK')} G",
        f"  G {_edge('PROVEN' if finding.proven_primitive else 'UNRESOLVED', 'PROMOTION')} H",
        f"  H {_edge('PROVEN' if finding.maturity_level == 'IMPACT' else 'INFERRED', 'POST-CONDITION')} I",
        "  classDef attacker fill:#ffd6d6,stroke:#a00,color:#111",
        "  classDef boundary fill:#fff0b3,stroke:#a66b00,color:#111",
        "  classDef validation fill:#d9eaff,stroke:#165d9c,color:#111",
        "  classDef sink fill:#eadcff,stroke:#6332a8,color:#111",
        "  class A,C attacker",
        "  class B boundary",
        "  class D,E validation",
        "  class F,G,H,I sink",
    ]
    return "\n".join(lines)
