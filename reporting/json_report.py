"""JSON report assembly and writing."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from graph.model import Graph
from utils.jsonio import dumps as _json_dumps
from utils.provenance import research_provenance


def _summary(targets: List[Any]) -> Dict[str, Any]:
    total = len(targets)
    privileged = sum(1 for t in targets if t.service.is_privileged)
    mach_xpc = sum(1 for t in targets if t.service.mach_services or t.service.sockets)
    interesting_ent = set()
    for t in targets:
        interesting_ent.update(t.entitlement_findings)
    high = sum(1 for t in targets if t.priority == "HIGH")
    capability_count = sum(len(getattr(t, "capability_findings", [])) for t in targets)
    research_high = sum(1 for t in targets if getattr(t, "research_priority_score", 0) >= 80)
    capabilities = [finding for target in targets
                    for finding in getattr(target, "capability_findings", [])]
    lpe_findings = [finding for target in targets
                    for finding in getattr(target, "lpe_findings", [])]
    rce_findings = [finding for target in targets
                    for finding in getattr(target, "rce_findings", [])]

    def counts(attribute: str) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for finding in capabilities:
            value = str(getattr(finding, attribute, "UNKNOWN"))
            out[value] = out.get(value, 0) + 1
        return dict(sorted(out.items()))

    unknown_causes: Dict[str, int] = {}
    validation_scope: Dict[str, int] = {}
    for finding in capabilities:
        for reason in getattr(finding, "unknown_reasons", []):
            unknown_causes[reason] = unknown_causes.get(reason, 0) + 1
        scope = getattr(getattr(finding, "identity", None), "scope", "VALIDATION_NOT_OBSERVED")
        validation_scope[scope] = validation_scope.get(scope, 0) + 1
    avg_research = (sum(t.research_priority_score for t in targets) / total) if total else 0
    avg_exploitability = (sum(f.exploitability_evidence_score for f in capabilities)
                          / len(capabilities)) if capabilities else 0
    lpe_classes: Dict[str, int] = {}
    lpe_confidence: Dict[str, int] = {}
    for finding in lpe_findings:
        lpe_confidence[finding.confidence] = lpe_confidence.get(finding.confidence, 0) + 1
        for name in finding.lpe_classes:
            lpe_classes[name] = lpe_classes.get(name, 0) + 1
    rce_classes: Dict[str, int] = {}
    rce_confidence: Dict[str, int] = {}
    for finding in rce_findings:
        rce_confidence[finding.confidence] = rce_confidence.get(finding.confidence, 0) + 1
        for name in finding.rce_classes:
            rce_classes[name] = rce_classes.get(name, 0) + 1
    operation_authorization_scope: Dict[str, int] = {}
    for finding in capabilities:
        scope = getattr(getattr(finding, "authorization", None), "scope", "UNKNOWN")
        operation_authorization_scope[scope] = (
            operation_authorization_scope.get(scope, 0) + 1)
    resource_scope: Dict[str, int] = {}
    for finding in lpe_findings:
        value = str(getattr(finding, "resource_scope", "UNKNOWN"))
        resource_scope[value] = resource_scope.get(value, 0) + 1
    xpc_operations = 0
    for target in targets:
        macho = getattr(getattr(target, "executable", None), "macho", None)
        xpc_operations += len(getattr(macho, "ipc_operations", []) or [])
    return {
        "total_services": total,
        "privileged_services": privileged,
        "mach_xpc_services": mach_xpc,
        "interesting_entitlement_count": len(interesting_ent),
        "high_priority_targets": high,
        "capability_findings": capability_count,
        "research_priority_80_plus": research_high,
        "maturity": counts("maturity_level"),
        "attacker_control": counts("attacker_control"),
        "capability_confidence": counts("confidence"),
        "validation_scope": dict(sorted(validation_scope.items())),
        "unknown_attacker_control_causes": dict(sorted(unknown_causes.items())),
        "average_research_priority": round(avg_research, 2),
        "average_exploitability_evidence": round(avg_exploitability, 2),
        "lpe_findings": len(lpe_findings),
        "lpe_classes": dict(sorted(lpe_classes.items())),
        "lpe_confidence": dict(sorted(lpe_confidence.items())),
        "operation_authorization_scope": dict(sorted(operation_authorization_scope.items())),
        "resource_scope": dict(sorted(resource_scope.items())),
        "xpc_operations": xpc_operations,
        "rce_findings": len(rce_findings),
        "rce_classes": dict(sorted(rce_classes.items())),
        "rce_confidence": dict(sorted(rce_confidence.items())),
    }


def build_report(targets: List[Any], graph: Graph | None = None, meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Assemble the full report dict (targets + summary + optional graph)."""
    report: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "macOS-TBM (Trust Boundary Mapper)",
        "schema_version": "2.2",
        "provenance": research_provenance(include_radare2=bool(
            (((meta or {}).get("optional_analysis") or {}).get("radare2") or {}).get("requested"))),
        "schema_compatibility": {
            "deprecated_fields": {
                "capability_findings[].primitive": "use candidate_capability and proven_primitive",
                "capability_findings[].score": "use exploitability_evidence",
                "capability_findings[].missing_proof": "use missing_evidence"
            },
            "operation_findings_alias": "capability_findings",
            "lpe_findings": "additive optional privileged-filesystem analysis layer",
            "rce_findings": "additive optional network-ingress x parser analysis layer",
            "ipc_operations": "additive XPC request/dispatch relationship evidence",
            "caller_profiles": "additive per-profile reachability and authorization",
            "policy_paths": "additive dispatcher predicate -> operation paths",
            "descriptor_provenance": "additive path -> descriptor provenance",
            "resource_scope": "additive resource-check classification (not a scope guard)",
            "guard_evidence": "additive control-flow dominance/successor evidence"
        },
        "meta": meta or {},
        "summary": _summary(targets),
        "targets": [t.to_dict() for t in targets],
    }
    optional = (meta or {}).get("optional_analysis")
    if optional:
        report["summary"]["optional_analysis"] = optional
    if graph is not None:
        report["graph"] = graph.to_dict()
    return report


def write_json_report(path: str, report: Dict[str, Any]) -> None:
    """Write the report to *path* as JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_json_dumps(report))
