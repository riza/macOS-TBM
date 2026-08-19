"""JSON report assembly and writing."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from graph.model import Graph
from utils.jsonio import dumps as _json_dumps


def _summary(targets: List[Any]) -> Dict[str, Any]:
    total = len(targets)
    privileged = sum(1 for t in targets if t.service.is_privileged)
    mach_xpc = sum(1 for t in targets if t.service.mach_services or t.service.sockets)
    interesting_ent = set()
    for t in targets:
        interesting_ent.update(t.entitlement_findings)
    high = sum(1 for t in targets if t.priority == "HIGH")
    return {
        "total_services": total,
        "privileged_services": privileged,
        "mach_xpc_services": mach_xpc,
        "interesting_entitlement_count": len(interesting_ent),
        "high_priority_targets": high,
    }


def build_report(targets: List[Any], graph: Graph | None = None, meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Assemble the full report dict (targets + summary + optional graph)."""
    report: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "macOS-TBM (Trust Boundary Mapper)",
        "meta": meta or {},
        "summary": _summary(targets),
        "targets": [t.to_dict() for t in targets],
    }
    if graph is not None:
        report["graph"] = graph.to_dict()
    return report


def write_json_report(path: str, report: Dict[str, Any]) -> None:
    """Write the report to *path* as JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_json_dumps(report))
