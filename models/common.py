"""Shared enums used across the data model."""

from __future__ import annotations

from enum import Enum


class FactLevel(str, Enum):
    """Confidence classification for a piece of evidence.

    * ``FACT``      — directly observed (e.g. a MachService key in a plist).
    * ``HEURISTIC`` — inferred by rule (e.g. "links OpenDirectory.framework").
    * ``UNKNOWN``   — could not be determined (e.g. unreadable binary).
    """

    FACT = "FACT"
    HEURISTIC = "HEURISTIC"
    UNKNOWN = "UNKNOWN"


class ServiceScope(str, Enum):
    """Where a launchd job lives and how it is loaded."""

    SYSTEM_DAEMON = "system-daemon"
    SYSTEM_AGENT = "system-agent"
    LOCAL_DAEMON = "local-daemon"
    LOCAL_AGENT = "local-agent"
    USER_AGENT = "user-agent"
    XPC_SERVICE = "xpc-service"
    UNKNOWN = "unknown"


class ServiceType(str, Enum):
    DAEMON = "daemon"
    AGENT = "agent"
    XPC_SERVICE = "xpc-service"
    UNKNOWN = "unknown"


class RunAs(str, Enum):
    ROOT = "root"
    SPECIFIC_USER = "specific-user"
    CURRENT_USER = "current-user"
    UNKNOWN = "unknown"
