"""Conservative network-ingress RCE research findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class RCEFinding:
    finding_id: str
    rce_classes: List[str]
    ingress_kind: str
    privilege: str
    parser_kinds_high: List[str]
    parser_kinds_medium: List[str]
    parser_apis: List[str]
    caller_validation: str
    confidence: str
    score: int
    severity: str
    evidence: List[str]
    missing_evidence: List[str]
    analysis_sources: List[str] = field(default_factory=lambda: ["NATIVE"])
    score_signals: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "type": "network_ingress_parser",
            "rce_classes": list(self.rce_classes),
            "ingress_kind": self.ingress_kind,
            "privilege": self.privilege,
            "parser_kinds_high": list(self.parser_kinds_high),
            "parser_kinds_medium": list(self.parser_kinds_medium),
            "parser_apis": list(self.parser_apis),
            "caller_validation": self.caller_validation,
            "confidence": self.confidence,
            "score": self.score,
            "severity": self.severity,
            "evidence": list(self.evidence),
            "missing_evidence": list(self.missing_evidence),
            "analysis_sources": list(self.analysis_sources),
            "score_signals": dict(self.score_signals),
            "exploitability_confirmed": False,
        }
