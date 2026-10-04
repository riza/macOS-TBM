"""Launchd service model.

A :class:`LaunchService` captures the parsed, normalized contents of a single
launchd job (plist). The ``run_as`` field carries not just the classification
but an explicit ``derivation`` string explaining *how* the classification was
reached, so we never silently assume a LaunchDaemon runs as root.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .common import RunAs, ServiceScope, ServiceType


@dataclass
class LaunchService:
    label: str
    plist_path: str
    service_type: ServiceType = ServiceType.UNKNOWN
    scope: ServiceScope = ServiceScope.UNKNOWN

    program: Optional[str] = None
    program_arguments: List[str] = field(default_factory=list)
    user_name: Optional[str] = None
    group_name: Optional[str] = None
    mach_services: List[str] = field(default_factory=list)
    sockets: Dict[str, Any] = field(default_factory=dict)
    keep_alive: Any = None
    run_at_load: bool = False
    environment_variables: Dict[str, str] = field(default_factory=dict)
    associated_executable: Optional[str] = None
    xpc_service: bool = False

    # Run-as classification.
    run_as: RunAs = RunAs.UNKNOWN
    run_as_user: Optional[str] = None
    run_as_derivation: str = ""

    # Whether launchd would actually load the job (plist Disabled key combined
    # with the launchd override database, which takes precedence).
    enabled: bool = True
    enabled_derivation: str = ""

    # Raw plist preserved for inspection/transparency.
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_privileged(self) -> bool:
        """True if the service runs as root (system privilege)."""
        return self.run_as == RunAs.ROOT

    @property
    def exposes_ipc(self) -> bool:
        """True if the service registers Mach services or sockets."""
        return bool(self.mach_services) or bool(self.sockets)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "plist_path": self.plist_path,
            "service_type": self.service_type.value,
            "scope": self.scope.value,
            "program": self.program,
            "program_arguments": list(self.program_arguments),
            "user_name": self.user_name,
            "group_name": self.group_name,
            "mach_services": list(self.mach_services),
            "sockets": self.sockets,
            "keep_alive": self.keep_alive,
            "run_at_load": self.run_at_load,
            "environment_variables": dict(self.environment_variables),
            "associated_executable": self.associated_executable,
            "xpc_service": self.xpc_service,
            "run_as": self.run_as.value,
            "run_as_user": self.run_as_user,
            "run_as_derivation": self.run_as_derivation,
            "enabled": self.enabled,
            "enabled_derivation": self.enabled_derivation,
        }
