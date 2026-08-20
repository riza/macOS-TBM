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
        }
