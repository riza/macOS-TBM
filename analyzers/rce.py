"""Optional RCE hunting layer: network ingress x untrusted-data parser correlation.

A remote code-execution surface needs untrusted bytes to reach a complex
parser inside a privileged process.  This layer correlates launchd network
sockets / listener APIs with historically bug-rich parser APIs in the same
binary, and records the evidence trail so a researcher can pick the juiciest
network-facing root daemons instead of grepping imports by hand.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional, Tuple

from models.rce import RCEFinding
from utils.rules import rce_rules


def _matches(actual: str, pattern: str) -> bool:
    actual = actual.lstrip("_")
    pattern = pattern.lstrip("_")
    if pattern.endswith("*"):
        return actual.startswith(pattern[:-1])
    if pattern.endswith("*"):
        pass
    return actual == pattern


def _first_match(names: Iterable[str], patterns: Iterable[str]) -> Optional[str]:
    for name in names:
        for pattern in patterns:
            if _matches(name, pattern):
                return name
    return None


def _group_matches(names: List[str], group: Dict[str, List[str]],
                   ) -> Dict[str, List[str]]:
    hits: Dict[str, List[str]] = {}
    for kind, patterns in group.items():
        if kind.startswith("_"):
            continue
        found = sorted({name for name in names
                        for pattern in patterns if _matches(name, pattern)})
        if found:
            hits[kind] = found
    return hits


def _ingress(service, macho, rules: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Return (kind, evidence) for how remote data may enter the process."""
    socket_keys = (rules.get("network_ingress") or {}).get(
        "launchd_socket_network_keys", [])
    sockets = getattr(service, "sockets", None) or {}
    for sock in sockets.values():
        if not isinstance(sock, dict):
            continue
        for key in socket_keys:
            if key in sock:
                detail = f"launchd socket {key}={sock[key]}"
                return "listener", [detail]
    imports = list(getattr(macho, "imported_symbols", []) or [])
    libs = [str(lib).lower() for lib in (getattr(macho, "linked_libs", []) or [])]
    net_lib_hit = next((f for f in (
        (rules.get("network_ingress") or {}).get("listener_frameworks", [])
        + (rules.get("network_ingress") or {}).get("client_frameworks", [])
        or []) if any(f.lower() in lib for lib in libs)), "")
    listener_apis = (rules.get("network_ingress") or {}).get("listener_apis", [])
    sock_api = _first_match(imports, {"bind", "listen", "accept", "accept4"})
    # Generic bind/listen/accept also serve local unix/XPC sockets; only treat
    # them as network listeners when a networking framework is also linked.
    nw_api = _first_match(imports, [a for a in listener_apis
                                    if a not in {"bind", "listen", "accept", "accept4"}])
    if nw_api or (sock_api and net_lib_hit):
        return "listener_api", [f"listener import {nw_api or sock_api}"
                                + (" + network framework" if net_lib_hit else "")]
    client_apis = (rules.get("network_ingress") or {}).get("client_apis", [])
    hit = _first_match(imports, client_apis)
    if hit:
        return "client", [f"client import {hit}"]
    if net_lib_hit:
        # A networking framework is linked but no listener/client symbol is
        # visible; classify conservatively as an outbound client.
        return "client", [f"linked {net_lib_hit}"]
    return "", []


def analyze_rce(service, macho, validation: str = "UNKNOWN") -> List[RCEFinding]:
    """Correlate network ingress with untrusted-data parser surface."""
    if not macho or not getattr(macho, "is_macho", False):
        return []
    rules = rce_rules()
    weights = rules.get("weights", {})
    ingress_kind, ingress_evidence = _ingress(service, macho, rules)
    if not ingress_kind:
        return []
    imports = list(getattr(macho, "imported_symbols", []) or [])
    parsers = rules.get("parsers") or {}
    high = _group_matches(imports, parsers.get("high") or {})
    medium = _group_matches(imports, parsers.get("medium") or {})

    privileged = bool(getattr(service, "is_privileged", False))
    signals: Dict[str, int] = {}
    if ingress_kind == "listener":
        signals["network_listener"] = int(weights.get("network_listener", 25))
    elif ingress_kind == "listener_api":
        signals["network_listener_api"] = int(weights.get("network_listener_api", 15))
    else:
        signals["network_client"] = int(weights.get("network_client", 10))
    if high:
        signals["high_complexity_parser"] = int(weights.get("high_complexity_parser", 20))
    elif medium:
        signals["medium_complexity_parser"] = int(weights.get("medium_complexity_parser", 8))
    if privileged:
        signals["privileged_process"] = int(weights.get("privileged_process", 15))
    if privileged and ingress_kind in {"listener", "listener_api"} and high:
        signals["root_listener_high_parser"] = int(
            weights.get("root_listener_high_parser", 15))
    if validation == "NONE_OBSERVED" and ingress_kind in {"client", "listener_api"}:
        signals["caller_validation_none_observed"] = int(
            weights.get("caller_validation_none_observed", 10))
    score = min(100, sum(signals.values()))

    classes: List[str] = []
    if ingress_kind in {"listener", "listener_api"}:
        classes.append("NETWORK_LISTENER")
    else:
        classes.append("NETWORK_CLIENT")
    for kind in sorted(high):
        classes.append(f"PARSER_{kind.upper()}")
    for kind in sorted(medium):
        classes.append(f"PARSER_{kind.upper()}")
    if ingress_kind in {"listener", "listener_api"} and high:
        classes.append("BINARY_WIDE_PARSER_SURFACE")
    if privileged and ingress_kind in {"listener", "listener_api"} and high:
        classes.append("RCE_ROOT_LISTENER_PARSER")

    if score < int((rules.get("thresholds") or {}).get("medium", 40)):
        return []

    # Listener + parser + privilege is a binary-wide correlation, not proof that
    # ingress bytes reach the parser, so the top tier stays POSSIBLE until a
    # dataflow links a network source to a parser sink.
    if high and ingress_kind in {"listener", "listener_api"}:
        confidence = "POSSIBLE"
    else:
        confidence = "INSUFFICIENT_EVIDENCE"

    parser_apis = sorted({api for apis in high.values() for api in apis}
                         | {api for apis in medium.values() for api in apis})
    evidence = [
        f"{service.label} exposes a network {ingress_kind.replace('_', ' ')}",
        *ingress_evidence,
        f"parser surface: {', '.join(parser_apis[:12])}" if parser_apis else "no parser import observed",
        f"runs as {'root/system' if privileged else getattr(service, 'run_as', '?')}",
    ]
    missing: List[str] = []
    if not high:
        missing.append("no high-complexity parser import observed in this binary")
    if ingress_kind in {"listener", "listener_api"} and high:
        missing.append("ingress bytes are not proven to reach the parser; this is a "
                       "binary-wide listener + parser correlation")
    if ingress_kind == "client":
        missing.append("daemon connects outbound; whether remote data reaches the parser is unverified")
    if not privileged:
        missing.append("daemon is not privileged; RCE impact is limited to the daemon's own rights")
    digest = hashlib.sha1(
        f"{service.label}:{','.join(classes)}".encode("utf-8")).hexdigest()[:10]
    return [RCEFinding(
        finding_id=f"rce-{digest}", rce_classes=classes,
        ingress_kind=ingress_kind, privilege=(
            "root" if privileged else str(getattr(service, "run_as", "?"))),
        parser_kinds_high=sorted(high), parser_kinds_medium=sorted(medium),
        parser_apis=parser_apis, caller_validation=validation,
        confidence=confidence, score=score,
        severity=("HIGH" if score >= int((rules.get("thresholds") or {}).get("high", 65))
                  else "MEDIUM" if score >= int((rules.get("thresholds") or {}).get("medium", 40))
                  else "LOW"),
        evidence=evidence, missing_evidence=missing,
    )]


def refresh_rce_findings(targets: Iterable[Any]) -> None:
    """Recompute RCE findings (e.g. after optional analysis updated validation)."""
    for target in targets:
        executable = getattr(target, "executable", None)
        macho = getattr(executable, "macho", None) if executable else None
        target.rce_findings = analyze_rce(
            target.service, macho, validation=getattr(target, "validation", "UNKNOWN"))
