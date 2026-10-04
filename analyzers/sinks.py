"""Sensitive sink taxonomy.

Maps the raw sensitive-signal categories (from ``rules/signals.json``) to the
human-facing sink taxonomy used in reports and scoring. Classifications are
heuristic: a static indicator of subsystem interaction does not prove a
component actually performs the sensitive operation.
"""

from __future__ import annotations

from typing import Dict, List

SINK_LABELS: Dict[str, str] = {
    "account": "ACCOUNT",
    "credential": "CREDENTIAL",
    "privacy": "PRIVACY",
    "filesystem": "FILESYSTEM",
    "execution": "EXECUTION",
    "install_update": "INSTALL/UPDATE",
    "network": "NETWORK",
    "security_policy": "SECURITY POLICY",
}

SINK_DESCRIPTIONS: Dict[str, str] = {
    "account": "account creation, users/groups, OpenDirectory, DirectoryServices",
    "credential": "Keychain, Security.framework, authentication tokens",
    "privacy": "TCC, camera, microphone, screen capture, contacts/photos/location",
    "filesystem": "privileged file modification, permissions, ownership, xattrs, quarantine",
    "execution": "process spawning, installers, helpers, launchd interaction",
    "install_update": "Installer, softwareupdated, package management",
    "network": "sockets, listeners, network configuration",
    "security_policy": "code signing, Gatekeeper, sandbox, policy evaluation",
}


def classify_sinks(sensitive) -> List[str]:
    """Return the ordered list of human-facing sink labels present.

    Accepts either the legacy ``{sink: [needles]}`` mapping or a list of
    :class:`~models.evidence.SinkAssessment`.
    """
    if isinstance(sensitive, dict):
        present = {k for k, v in sensitive.items() if v}
    else:
        present = {a.sink for a in sensitive}
    return [SINK_LABELS[key] for key in SINK_LABELS if key in present]
