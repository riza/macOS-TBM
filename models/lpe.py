"""Conservative privileged-filesystem LPE research findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class LPEFinding:
    finding_id: str
    lpe_classes: List[str]
    operation: str
    sink_api: str
    privilege: str
    entry_point: str
    input_origin: str
    input_name: str
    user_controlled: bool
    caller_validation: str
    caller_validation_scope: str
    operation_authorization: str
    operation_authorization_scope: str
    resource_validation: str
    resource_validation_evidence: List[str]
    target: str
    target_category: str
    target_sensitive: bool
    toctou_candidate: bool
    unsafe_temporary_path: bool
    confidence: str
    score: int
    severity: str
    evidence: List[str]
    missing_evidence: List[str]
    sink_address: str = ""
    function: str = ""
    source_finding_id: str = ""
    analysis_sources: List[str] = field(default_factory=lambda: ["NATIVE"])
    score_signals: Dict[str, int] = field(default_factory=dict)
    resource_authorization: str = "UNKNOWN"
    descriptor_provenance: Dict[str, Any] = field(default_factory=dict)
    resource_scope: str = "UNKNOWN"
    resource_scope_confidence: str = "UNKNOWN"
    resource_scope_evidence: List[str] = field(default_factory=list)
    research_questions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "type": "filesystem_operation",
            "lpe_classes": list(self.lpe_classes),
            "operation": self.operation,
            "sink": {"api": self.sink_api, "address": self.sink_address or None,
                     "function": self.function or None},
            "privilege": self.privilege,
            "entry_point": self.entry_point,
            "input_origin": self.input_origin,
            "input_name": self.input_name,
            "user_controlled": self.user_controlled,
            "caller_validation": self.caller_validation,
            "caller_validation_scope": self.caller_validation_scope,
            "operation_authorization": self.operation_authorization,
            "operation_authorization_scope": self.operation_authorization_scope,
            "resource_validation": self.resource_validation,
            "resource_authorization": self.resource_authorization,
            "descriptor_provenance": dict(self.descriptor_provenance),
            "resource_scope": self.resource_scope,
            "resource_scope_confidence": self.resource_scope_confidence,
            "resource_scope_evidence": list(self.resource_scope_evidence),
            "research_questions": list(self.research_questions),
            "resource_validation_evidence": list(self.resource_validation_evidence),
            "target": self.target,
            "target_category": self.target_category,
            "target_sensitive": self.target_sensitive,
            "toctou_candidate": self.toctou_candidate,
            "unsafe_temporary_path": self.unsafe_temporary_path,
            "confidence": self.confidence,
            "score": self.score,
            "severity": self.severity,
            "evidence": list(self.evidence),
            "missing_evidence": list(self.missing_evidence),
            "source_finding_id": self.source_finding_id or None,
            "analysis_sources": list(self.analysis_sources),
            "score_signals": dict(self.score_signals),
            "exploitability_confirmed": False,
        }
