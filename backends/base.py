"""Backend-neutral evidence contracts used by optional analyzers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class BackendEvidence:
    evidence_source: str
    observation: str
    relationship: str = "INFERRED"
    address: str = ""
    function: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_source": self.evidence_source,
            "observation": self.observation,
            "relationship": self.relationship,
            "address": self.address or None,
            "function": self.function or None,
            "detail": dict(self.detail),
        }


@dataclass
class FindingUpdate:
    finding_id: str
    evidence: List[BackendEvidence] = field(default_factory=list)
    call_path_confirmed: bool = False
    controlled_arguments: Dict[str, str] = field(default_factory=dict)
    constant_arguments: List[str] = field(default_factory=list)
    validation_scope: str = ""
    authorization_scope: str = ""
    resolved_unknown_reasons: List[str] = field(default_factory=list)


@dataclass
class BackendStats:
    backend: str
    requested: bool = False
    available: bool = True
    analyzed: int = 0
    cache_hits: int = 0
    call_paths_resolved: int = 0
    arguments_resolved: int = 0
    unknown_resolved: int = 0
    validation_relationships_resolved: int = 0
    services_tested: int = 0
    connections_established: int = 0
    operations_safely_tested: int = 0
    operations_reached: int = 0
    rejected: int = 0
    unsafe_not_tested: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)
