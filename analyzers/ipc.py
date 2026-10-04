"""IPC participation classification (static, heuristic).

Classifies a binary as a Mach/XPC *provider*, *client*, *both*, or *unknown*
based on the presence of IPC-related symbols and strings. This is a heuristic:
static indicators can be hidden behind helper functions or dynamic dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from models.finding import FactLevel, Finding
from utils.rules import signals_rules

from ._match import match_all, symbol_pool


@dataclass
class IPCResult:
    classification: str = "unknown-ipc-participant"
    provider_signals: List[str] = field(default_factory=list)
    client_signals: List[str] = field(default_factory=list)
    generic_signals: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


def _evidence(macho):
    """Return the (symbols, strings) evidence pools used for IPC detection."""
    if macho is None:
        return [], []
    return symbol_pool(macho), list(macho.interesting_strings)


def classify_ipc(service, macho) -> IPCResult:
    """Classify IPC role for a launchd service + its Mach-O metadata."""
    rules = signals_rules()
    provider_cfg = rules.get("ipc_provider", {})
    client_cfg = rules.get("ipc_client", {})
    generic_cfg = rules.get("ipc_generic", {})

    syms, strings = _evidence(macho)
    hits = lambda cfg: [n for n, _ in match_all(  # noqa: E731
        syms, strings, list(cfg.get("symbols", [])) + list(cfg.get("strings", [])))]
    provider = hits(provider_cfg)
    client = hits(client_cfg)
    generic = hits(generic_cfg)

    result = IPCResult(
        provider_signals=provider,
        client_signals=client,
        generic_signals=generic,
    )

    exposes = bool(service.mach_services) if service else False
    exposes = exposes or bool(service and service.sockets)

    is_provider = bool(provider) or exposes
    is_client = bool(client)

    if is_provider and is_client:
        result.classification = "xpc-mach-provider-and-client"
    elif is_provider:
        result.classification = "mach-service-provider" if not provider else "xpc-service-provider"
    elif is_client:
        result.classification = "xpc-mach-client"
    elif generic:
        result.classification = "unknown-ipc-participant"
        result.findings.append(
            Finding(
                category="ipc",
                level=FactLevel.HEURISTIC,
                message="generic Mach/IPC primitives observed; role unclear",
                evidence=", ".join(generic[:10]),
            )
        )
    else:
        result.classification = "unknown-ipc-participant"

    if exposes:
        result.findings.append(
            Finding(
                category="ipc",
                level=FactLevel.FACT,
                message=f"launchd job registers Mach service(s): {', '.join(service.mach_services) if service else ''}",
                evidence="launchd MachServices key",
            )
        )
    if provider:
        result.findings.append(
            Finding(
                category="ipc",
                level=FactLevel.HEURISTIC,
                message="XPC/Mach service provider indicators present",
                evidence=", ".join(provider[:10]),
            )
        )
    if client:
        result.findings.append(
            Finding(
                category="ipc",
                level=FactLevel.HEURISTIC,
                message="XPC/Mach client indicators present",
                evidence=", ".join(client[:10]),
            )
        )
    return result
