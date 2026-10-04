"""Selection and correlation for optional deep/runtime backends."""

from __future__ import annotations

from typing import Any, Callable, List

from utils.commands import ResultCache

from .base import BackendStats
from .radare2 import run_radare2
from .runtime_xpc import MacOSXPCProbe, RuntimeProbeUnavailable


def run_optional_backends(
    targets: List[Any], *, deep_analysis: str | None = None,
    deep_min_score: int = 70, deep_max_findings: int = 200,
    deep_workers: int = 3, deep_binary_timeout: float = 300.0,
    runtime_probe: bool = False, runtime_timeout: float = 1.0,
    runtime_max_services: int = 50, probe_send_empty: bool = False,
    cache: ResultCache | None = None, runtime_backend=None,
    deep_progress: Callable[[dict], None] | None = None,
) -> dict:
    result = {
        "analysis_sources": {"NATIVE": True, "RADARE2": False, "RUNTIME_XPC": False},
        "radare2": BackendStats("RADARE2").to_dict(),
        "runtime_xpc": BackendStats("RUNTIME_XPC").to_dict(),
    }
    if deep_analysis == "radare2":
        stats = run_radare2(
            targets, deep_min_score, deep_max_findings, cache,
            progress=deep_progress,
            workers=deep_workers, binary_timeout=deep_binary_timeout,
        )
        result["radare2"] = stats.to_dict()
        result["analysis_sources"]["RADARE2"] = stats.available and stats.analyzed > 0

    if runtime_probe:
        stats = BackendStats("RUNTIME_XPC", requested=True)
        try:
            backend = runtime_backend or MacOSXPCProbe()
        except RuntimeProbeUnavailable as exc:
            stats.available = False
            stats.errors.append(str(exc))
            result["runtime_xpc"] = stats.to_dict()
            from analyzers.lpe import refresh_lpe_findings
            refresh_lpe_findings(targets)
            return result
        tested = 0
        seen = set()
        for target in targets:
            observations = []
            for name in target.service.mach_services:
                if name in seen or tested >= runtime_max_services:
                    continue
                seen.add(name)
                tested += 1
                try:
                    observation = backend.probe(
                        name, timeout=runtime_timeout, send_empty=probe_send_empty)
                    data = observation.to_dict() if hasattr(observation, "to_dict") else dict(observation)
                    observations.append(data)
                    stats.services_tested += 1
                    stats.connections_established += int(data.get("connection") == "CONFIRMED")
                    stats.operations_safely_tested += int(probe_send_empty)
                    stats.operations_reached += int(data.get("operation_reachability") == "CONFIRMED")
                    stats.rejected += int("REJECTED" in data.get("status", ""))
                    stats.unsafe_not_tested += int(not probe_send_empty)
                except Exception as exc:  # noqa: BLE001
                    stats.errors.append(f"{name}: {exc}")
            if observations:
                target.optional_analysis.setdefault("runtime_xpc", []).extend(observations)
                for finding in target.capability_findings:
                    if "RUNTIME_XPC" not in finding.analysis_sources:
                        finding.analysis_sources.append("RUNTIME_XPC")
                    finding.dynamic_reachability = {
                        "mach_reachability": (
                            "CONFIRMED" if any(o.get("connection") == "CONFIRMED"
                                               for o in observations) else "NOT_CONFIRMED"),
                        "operation_reachability": "NOT_PROVEN",
                        "authorization_bypass": "NOT_PROVEN",
                        "observations": observations,
                    }
                    finding.optional_evidence.extend({
                        "evidence_source": "RUNTIME_XPC",
                        "observation": f"{o.get('mach_service')}: {o.get('status')}",
                        "relationship": "PROVEN" if o.get("connection") == "CONFIRMED" else "UNRESOLVED",
                        "detail": o,
                    } for o in observations)
        result["runtime_xpc"] = stats.to_dict()
        result["analysis_sources"]["RUNTIME_XPC"] = stats.services_tested > 0
    # Optional Radare2 evidence may promote a capability after the native pass;
    # rebuild the derived LPE/RCE layers so they reflect the final evidence state.
    from analyzers.lpe import refresh_lpe_findings
    from analyzers.rce import refresh_rce_findings
    refresh_lpe_findings(targets)
    refresh_rce_findings(targets)
    return result
