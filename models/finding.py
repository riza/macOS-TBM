"""Findings and scored-target models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .common import FactLevel


@dataclass
class Finding:
    """A single piece of evidence with an explicit confidence level."""

    category: str
    level: FactLevel
    message: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "level": self.level.value,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass
class ScoreReason:
    """A single weighted contribution to a target's priority score."""

    weight: int
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"weight": self.weight, "reason": self.reason}


@dataclass
class Target:
    """A scored research target: one service + its executable + analyses."""

    service: Any  # LaunchService
    executable: Any  # Executable
    score: int = 0
    reasons: List[ScoreReason] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    ipc_classification: str = "unknown"
    sensitive_sinks: List[str] = field(default_factory=list)
    sink_assessments: List[Any] = field(default_factory=list)  # SinkAssessment
    validation: str = "NONE_OBSERVED"
    validation_assessment: Any = None  # ValidationAssessment
    entitlement_findings: List[str] = field(default_factory=list)
    checked_entitlements: List[str] = field(default_factory=list)
    why_interesting: List[str] = field(default_factory=list)
    research_questions: List[str] = field(default_factory=list)
    research_leads: List[str] = field(default_factory=list)
    capability_findings: List[Any] = field(default_factory=list)
    lpe_findings: List[Any] = field(default_factory=list)
    rce_findings: List[Any] = field(default_factory=list)
    primitive_edges: List[Any] = field(default_factory=list)
    optional_analysis: Dict[str, Any] = field(default_factory=dict)

    @property
    def research_priority_score(self) -> int:
        """Binary-profile research value, independent of primitive evidence."""
        if not self.capability_findings:
            return max(0, min(100, self.score))
        return max(f.research_priority_score for f in self.capability_findings)

    @property
    def exploitability_evidence_score(self) -> int:
        """Best operation-level attacker-evidence score for this target."""
        if not self.capability_findings:
            return 0
        return max(f.exploitability_evidence_score for f in self.capability_findings)

    def _binary_profile(self) -> Dict[str, Any]:
        maturities: Dict[str, int] = {}
        candidates: Dict[str, int] = {}
        for finding in self.capability_findings:
            maturities[finding.maturity_level] = maturities.get(finding.maturity_level, 0) + 1
            candidates[finding.candidate_capability] = candidates.get(
                finding.candidate_capability, 0) + 1
        return {
            "service": self.service.label,
            "privileged": self.service.is_privileged,
            "mach_service_count": len(self.service.mach_services),
            "interesting_entitlement_count": len(self.entitlement_findings),
            "sink_count": len(self.sink_assessments),
            "operation_finding_count": len(self.capability_findings),
            "maturity_counts": maturities,
            "candidate_capabilities": candidates,
            "research_priority_score": self.research_priority_score,
            "exploitability_evidence_score": self.exploitability_evidence_score,
        }

    @property
    def priority(self) -> str:
        if self.score >= 80:
            return "HIGH"
        if self.score >= 50:
            return "MEDIUM"
        if self.score >= 25:
            return "LOW"
        return "INFO"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.service.label,
            "score": self.score,
            "priority": self.priority,
            "reasons": [r.to_dict() for r in self.reasons],
            "service": self.service.to_dict(),
            "executable": self.executable.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "ipc_classification": self.ipc_classification,
            "sensitive_sinks": list(self.sensitive_sinks),
            "sink_assessments": [a.to_dict() for a in self.sink_assessments],
            "validation": self.validation,
            "validation_assessment": (self.validation_assessment.to_dict()
                                      if self.validation_assessment else None),
            "entitlement_findings": list(self.entitlement_findings),
            "checked_entitlements": list(self.checked_entitlements),
            "why_interesting": list(self.why_interesting),
            "research_questions": list(self.research_questions),
            "research_leads": list(self.research_leads),
            "research_priority_score": self.research_priority_score,
            "exploitability_evidence_score": self.exploitability_evidence_score,
            "binary_profile": self._binary_profile(),
            "operation_findings": [f.to_dict() for f in self.capability_findings],
            "capability_findings": [f.to_dict() for f in self.capability_findings],
            "lpe_findings": [f.to_dict() for f in self.lpe_findings],
            "rce_findings": [f.to_dict() for f in self.rce_findings],
            "primitive_edges": [e.to_dict() for e in self.primitive_edges],
            "optional_analysis": dict(self.optional_analysis),
        }
