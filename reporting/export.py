"""Per-entity export of a report to CSV and Markdown.

``report.json`` is one nested document; research is usually done one entity at a
time — "every Mach service and who owns it", "every private entitlement and who
holds it", "every piece of evidence behind a FILESYSTEM label". This module
flattens the report into one table per entity so those questions become a
``grep``, a spreadsheet sort, or a note in a research journal.

Nothing here re-scans: it reads a report produced by ``tbm scan``, so exporting
is instant and repeatable.
"""

from __future__ import annotations

import csv
import io
import os
import re
from typing import Any, Dict, Iterable, List, Sequence, Tuple

# One entity per table: (filename stem, column headers, row builder).
Row = Sequence[Any]
Table = Tuple[str, List[str], List[Row]]

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _svc(target: Dict[str, Any]) -> Dict[str, Any]:
    return target.get("service") or {}


def _exe(target: Dict[str, Any]) -> Dict[str, Any]:
    return target.get("executable") or {}


def _cs(target: Dict[str, Any]) -> Dict[str, Any]:
    return _exe(target).get("codesign") or {}


def _macho(target: Dict[str, Any]) -> Dict[str, Any]:
    return _exe(target).get("macho") or {}


# --------------------------------------------------------------------------
# tables
# --------------------------------------------------------------------------

def _services(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for t in targets:
        s = _svc(t)
        rows.append([
            t["label"], t["score"], t["priority"],
            "enabled" if s.get("enabled", True) else "disabled",
            s.get("service_type"), s.get("scope"),
            s.get("run_as_user") or s.get("run_as"),
            s.get("associated_executable") or "",
            len(s.get("mach_services") or []),
            t.get("ipc_classification"), t.get("validation"),
            len((_cs(t).get("entitlements") or {})),
            " ".join(t.get("sensitive_sinks") or []),
            s.get("plist_path"), s.get("run_at_load"),
            s.get("enabled_derivation", ""),
        ])
    return ("services", [
        "label", "score", "priority", "state", "type", "scope", "run_as", "binary",
        "mach_services", "ipc", "validation", "entitlements", "sinks", "plist",
        "run_at_load", "state_reason",
    ], rows)


def _executables(targets: List[Dict[str, Any]]) -> Table:
    by_path: Dict[str, Dict[str, Any]] = {}
    for t in targets:
        path = (_exe(t).get("path") or _svc(t).get("associated_executable") or "")
        if not path:
            continue
        entry = by_path.setdefault(path, {"labels": [], "target": t})
        entry["labels"].append(t["label"])
        # Keep the highest-scoring target as the representative row.
        if t["score"] > entry["target"]["score"]:
            entry["target"] = t
    rows = []
    for path, entry in sorted(by_path.items()):
        t = entry["target"]
        cs, mo = _cs(t), _macho(t)
        rows.append([
            path,
            "yes" if cs.get("is_signed") else ("no" if cs.get("is_signed") is False else "unknown"),
            cs.get("signer_identifier") or "", cs.get("team_identifier") or "",
            "" if cs.get("platform_binary") is None else ("yes" if cs.get("platform_binary") else "no"),
            " ".join(mo.get("architectures") or []),
            len(cs.get("entitlements") or {}),
            mo.get("imported_symbols_count", ""), mo.get("linked_libs_count", ""),
            mo.get("objc_classes_count", ""),
            len(entry["labels"]), " ".join(sorted(entry["labels"])),
        ])
    return ("executables", [
        "path", "signed", "identifier", "team", "platform_binary", "architectures",
        "entitlements", "imported_symbols", "linked_libs", "objc_classes",
        "used_by_count", "used_by",
    ], rows)


def _mach_services(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for t in targets:
        s = _svc(t)
        for name in s.get("mach_services") or []:
            rows.append([
                name, t["label"], s.get("run_as_user") or s.get("run_as"),
                "enabled" if s.get("enabled", True) else "disabled",
                t["score"], t.get("validation"), s.get("associated_executable") or "",
            ])
    rows.sort(key=lambda r: (-r[4], r[0]))
    return ("mach_services",
            ["mach_service", "provided_by", "run_as", "state", "score", "validation", "binary"],
            rows)


def _entitlements(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for t in targets:
        high = set(t.get("entitlement_findings") or [])
        for key, value in sorted((_cs(t).get("entitlements") or {}).items()):
            rows.append([
                key, t["label"], "yes" if key in high else "no",
                _svc(t).get("run_as_user") or _svc(t).get("run_as"),
                t["score"], _stringify(value),
            ])
    rows.sort(key=lambda r: (r[0], -r[4]))
    return ("entitlements", ["entitlement", "held_by", "high_value", "run_as", "score", "value"], rows)


def _entitlement_summary(targets: List[Dict[str, Any]]) -> Table:
    holders: Dict[str, List[str]] = {}
    high: set = set()
    for t in targets:
        high |= set(t.get("entitlement_findings") or [])
        for key in (_cs(t).get("entitlements") or {}):
            holders.setdefault(key, []).append(t["label"])
    rows = [[key, len(labels), "yes" if key in high else "no", " ".join(sorted(labels)[:20])]
            for key, labels in holders.items()]
    rows.sort(key=lambda r: (-r[1], r[0]))
    return ("entitlement_summary", ["entitlement", "holders", "high_value", "held_by"], rows)


def _frameworks(targets: List[Dict[str, Any]]) -> Table:
    users: Dict[str, set] = {}
    weak: Dict[str, set] = {}
    for t in targets:
        mo = _macho(t)
        weak_set = set(mo.get("weak_linked_libs") or [])
        for lib in mo.get("linked_libs") or []:
            users.setdefault(lib, set()).add(t["label"])
            if lib in weak_set:
                weak.setdefault(lib, set()).add(t["label"])
    rows = []
    for lib, labels in users.items():
        rows.append([
            lib, len(labels),
            "yes" if "/PrivateFrameworks/" in lib else "no",
            len(weak.get(lib, ())), " ".join(sorted(labels)[:20]),
        ])
    rows.sort(key=lambda r: (-r[1], r[0]))
    return ("frameworks", ["library", "linked_by", "private", "weak_links", "linked_by_labels"], rows)


def _sinks(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for t in targets:
        for a in t.get("sink_assessments") or []:
            rows.append([
                t["label"], a["label"], a["confidence"], a["score"],
                " ".join(a.get("aspects") or []),
                len(a.get("evidence") or []),
                t["score"], t.get("validation"),
                _svc(t).get("run_as_user") or _svc(t).get("run_as"),
            ])
    rows.sort(key=lambda r: (r[1], -r[3]))
    return ("sinks", ["service", "sink", "confidence", "evidence_score", "aspects",
                      "evidence_count", "service_score", "validation", "run_as"], rows)


def _evidence(targets: List[Dict[str, Any]]) -> Table:
    """Every observation behind every sink label — the grep target."""
    rows = []
    for t in targets:
        for a in t.get("sink_assessments") or []:
            for e in a.get("evidence") or []:
                rows.append([
                    t["label"], a["label"], a["confidence"],
                    e.get("kind"), e.get("aspect") or "", e.get("weight"),
                    e.get("needle"), e.get("match"),
                ])
    return ("sink_evidence",
            ["service", "sink", "sink_confidence", "kind", "aspect", "weight", "needle", "match"],
            rows)


def _validation(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for t in targets:
        va = t.get("validation_assessment") or {}
        for e in va.get("evidence") or []:
            rows.append([t["label"], t.get("validation"), va.get("score", 0),
                         "observed", e.get("aspect") or "other", e.get("weight"),
                         e.get("match"), ""])
        for m in va.get("not_observed") or []:
            rows.append([t["label"], t.get("validation"), va.get("score", 0),
                         "not_observed", m.get("class"), m.get("weight"),
                         "", m.get("looked_for", "")])
    return ("caller_validation",
            ["service", "confidence", "score", "state", "class", "weight", "match", "looked_for"],
            rows)


def _findings(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for t in targets:
        for f in t.get("findings") or []:
            rows.append([t["label"], f.get("category"), f.get("level"),
                         f.get("message"), f.get("evidence", "")])
    return ("findings", ["service", "category", "level", "message", "evidence"], rows)


def _score_reasons(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for t in targets:
        for r in t.get("reasons") or []:
            rows.append([t["label"], t["score"], r.get("weight"), r.get("reason")])
    return ("score_reasons", ["service", "total_score", "weight", "reason"], rows)


def _capabilities(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for t in targets:
        for c in t.get("capability_findings") or []:
            sink = c.get("sink") or {}
            score = c.get("exploitability_evidence") or c.get("score") or {}
            identity = c.get("identity_verification_detail") or {}
            authorization = c.get("authorization") or {}
            rows.append([
                t["label"], c.get("finding_id"), c.get("research_priority_score"),
                c.get("exploitability_evidence_score"), c.get("candidate_capability"),
                c.get("maturity_level") or c.get("maturity"), c.get("proven_primitive"),
                c.get("primitive"), c.get("confidence"),
                " ".join(c.get("reachability") or []), c.get("entry_point"),
                c.get("handler_function"), c.get("transport"),
                c.get("expected_caller_identity"), identity.get("method"),
                identity.get("strength") or c.get("identity_verification"),
                identity.get("scope"), authorization.get("method"),
                authorization.get("strength") or c.get("authorization_decision"),
                authorization.get("scope"), c.get("attacker_control"),
                _stringify(c.get("controlled_arguments") or {}),
                sink.get("category"), sink.get("api"), sink.get("address"), sink.get("operation"),
                sink.get("framework"), c.get("path_control"),
                " -> ".join(c.get("dataflow") or []),
                " -> ".join(c.get("reply_dataflow") or []), c.get("post_condition"),
                c.get("post_condition_confidence"), c.get("potential_impact"),
                "; ".join(c.get("missing_evidence") or c.get("missing_proof") or []),
                "; ".join(c.get("next_research_steps") or []),
                "; ".join(c.get("unknown_reasons") or []),
                ", ".join(c.get("analysis_sources") or ["NATIVE"]),
                _stringify(c.get("dynamic_reachability") or {}),
                _stringify(c.get("optional_evidence") or []),
                score.get("entry_point_reachability"), score.get("identity_weakness"),
                score.get("authorization_weakness"), score.get("attacker_control"),
                score.get("sink_reachability"), score.get("primitive_maturity"),
                score.get("post_condition"), score.get("reply_dataflow"),
                score.get("chainability"), score.get("analysis_confidence"),
            ])
    rows.sort(key=lambda r: (-(r[2] or 0), r[0]))
    return ("capability_findings", [
        "service", "finding_id", "research_priority_score", "exploitability_evidence_score",
        "candidate_capability", "maturity", "proven_primitive", "primitive_deprecated",
        "confidence", "reachable_by", "entry_point", "handler_function", "transport",
        "expected_caller_identity", "identity_method", "identity_strength", "validation_scope",
        "authorization_method", "authorization_strength", "authorization_scope",
        "attacker_control", "controlled_arguments", "sink_category", "sink_api",
        "sink_address", "sink_operation", "framework", "path_control", "dataflow",
        "reply_dataflow", "post_condition", "post_condition_confidence", "potential_impact",
        "missing_evidence", "next_research_steps", "unknown_reasons",
        "analysis_sources", "dynamic_reachability", "optional_evidence",
        "dim_entry_point_reachability", "dim_identity_weakness",
        "dim_authorization_weakness", "dim_attacker_control", "dim_sink_reachability",
        "dim_primitive_maturity", "dim_post_condition", "dim_reply_dataflow",
        "dim_chainability", "dim_analysis_confidence",
    ], rows)


def _primitive_edges(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for t in targets:
        for edge in t.get("primitive_edges") or []:
            rows.append([
                t["label"], edge.get("source"), edge.get("target"),
                edge.get("required_precondition"), edge.get("confidence"),
                edge.get("edge_state"), "; ".join(edge.get("evidence") or []),
                edge.get("missing_proof"),
            ])
    return ("primitive_edges", [
        "service", "source", "target", "required_precondition", "confidence",
        "edge_state", "evidence", "missing_proof",
    ], rows)


def _lpe_findings(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for target in targets:
        for finding in target.get("lpe_findings") or []:
            sink = finding.get("sink") or {}
            rows.append([
                target["label"], finding.get("finding_id"), finding.get("score"),
                finding.get("severity"), finding.get("confidence"),
                ", ".join(finding.get("lpe_classes") or []), finding.get("operation"),
                sink.get("api"), sink.get("address"), sink.get("function"),
                finding.get("privilege"), finding.get("entry_point"),
                finding.get("input_origin"), finding.get("input_name"),
                finding.get("user_controlled"), finding.get("caller_validation"),
                finding.get("caller_validation_scope"), finding.get("operation_authorization"),
                finding.get("operation_authorization_scope"), finding.get("resource_validation"),
                finding.get("target"), finding.get("target_category"),
                finding.get("target_sensitive"), finding.get("toctou_candidate"),
                finding.get("unsafe_temporary_path"),
                "; ".join(finding.get("evidence") or []),
                "; ".join(finding.get("missing_evidence") or []),
                _stringify(finding.get("score_signals") or {}),
            ])
    rows.sort(key=lambda row: (-(row[2] or 0), row[0]))
    return ("lpe_findings", [
        "service", "finding_id", "score", "severity", "confidence", "lpe_classes",
        "operation", "sink_api", "sink_address", "function", "privilege", "entry_point",
        "input_origin", "input_name", "user_controlled", "caller_validation",
        "caller_validation_scope", "operation_authorization", "operation_authorization_scope",
        "resource_validation", "target", "target_category",
        "target_sensitive", "toctou_candidate", "unsafe_temporary_path", "evidence",
        "missing_evidence", "score_signals",
    ], rows)


def _rce_findings(targets: List[Dict[str, Any]]) -> Table:
    rows = []
    for target in targets:
        for finding in target.get("rce_findings") or []:
            rows.append([
                target["label"], finding.get("finding_id"), finding.get("score"),
                finding.get("severity"), finding.get("confidence"),
                ", ".join(finding.get("rce_classes") or []), finding.get("ingress_kind"),
                finding.get("privilege"), finding.get("caller_validation"),
                ", ".join(finding.get("parser_apis") or []),
                "; ".join(finding.get("evidence") or []),
                "; ".join(finding.get("missing_evidence") or []),
            ])
    rows.sort(key=lambda row: (-(row[2] or 0), row[0]))
    return ("rce_findings", [
        "service", "finding_id", "score", "severity", "confidence", "rce_classes",
        "ingress_kind", "privilege", "caller_validation", "parser_apis", "evidence",
        "missing_evidence",
    ], rows)


def _boundary_crossings(report: Dict[str, Any]) -> Table:
    """Every place a less-privileged client names a root daemon's Mach service."""
    from graph.query import TrustGraph

    rows = []
    for c in TrustGraph(report.get("graph") or {}).boundary_crossings():
        rows.append([c["mach_service"], c["provider"], c["provider_score"],
                     c["provider_validation"], c["client_service"] or c["client"],
                     c["client_run_as"], c["evidence"], c["edge_state"],
                     c["runtime_demonstrated"]])
    return ("boundary_crossings",
            ["mach_service", "provider", "provider_score", "provider_validation",
             "client", "client_run_as", "evidence", "edge_state",
             "runtime_demonstrated"], rows)


def _graph_nodes(report: Dict[str, Any]) -> Table:
    rows = []
    for n in (report.get("graph") or {}).get("nodes") or []:
        data = n.get("data") or {}
        rows.append([n.get("id"), n.get("type"), n.get("label"),
                     " ".join(f"{k}={_stringify(v)}" for k, v in sorted(data.items()))])
    return ("graph_nodes", ["id", "type", "label", "data"], rows)


def _graph_edges(report: Dict[str, Any]) -> Table:
    rows = [[e.get("source"), e.get("type"), e.get("target"), e.get("label", "")]
            for e in (report.get("graph") or {}).get("edges") or []]
    return ("graph_edges", ["source", "type", "target", "label"], rows)


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return " ".join(_stringify(v) for v in value)
    if isinstance(value, dict):
        return " ".join(f"{k}={_stringify(v)}" for k, v in sorted(value.items()))
    return "" if value is None else str(value)


def build_tables(report: Dict[str, Any]) -> List[Table]:
    """Flatten *report* into one table per entity."""
    targets = report.get("targets") or []
    tables = [
        _services(targets),
        _executables(targets),
        _mach_services(targets),
        _entitlements(targets),
        _entitlement_summary(targets),
        _frameworks(targets),
        _sinks(targets),
        _evidence(targets),
        _validation(targets),
        _findings(targets),
        _score_reasons(targets),
        _capabilities(targets),
        _lpe_findings(targets),
        _rce_findings(targets),
        _primitive_edges(targets),
    ]
    if report.get("graph"):
        tables += [_boundary_crossings(report), _graph_nodes(report), _graph_edges(report)]
    return tables


# --------------------------------------------------------------------------
# writers
# --------------------------------------------------------------------------

def _write_csv(path: str, headers: List[str], rows: Iterable[Row]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(["" if c is None else c for c in row])


def _md_cell(value: Any) -> str:
    text = _stringify(value).replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= 300 else text[:297] + "..."


def _write_md_table(path: str, title: str, headers: List[str], rows: Iterable[Row],
                    limit: int = 0) -> None:
    rows = list(rows)
    shown = rows[:limit] if limit else rows
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"# {title}\n\n{len(rows)} rows")
        if limit and len(rows) > limit:
            fh.write(f" (showing the first {limit}; the CSV has all of them)")
        fh.write("\n\n")
        fh.write("| " + " | ".join(headers) + " |\n")
        fh.write("|" + "|".join("---" for _ in headers) + "|\n")
        for row in shown:
            fh.write("| " + " | ".join(_md_cell(c) for c in row) + " |\n")


def _safe_name(label: str) -> str:
    return _UNSAFE.sub("_", label).strip("_") or "unnamed"


def _target_markdown(target: Dict[str, Any]) -> str:
    """A per-service dossier, written to be pasted into research notes."""
    s, cs, mo = _svc(target), _cs(target), _macho(target)
    out = io.StringIO()
    w = out.write
    state = "enabled" if s.get("enabled", True) else "**disabled**"
    w(f"# {target['label']}\n\n")
    w(f"`{target['priority']}` · score **{target['score']}** · {state} · "
      f"caller validation **{target.get('validation', 'NONE_OBSERVED')}**\n\n")

    w("## launchd\n\n")
    for key, value in [
        ("plist", f"`{s.get('plist_path')}`"),
        ("binary", f"`{s.get('associated_executable') or ''}`"),
        ("type / scope", f"{s.get('service_type')} / {s.get('scope')}"),
        ("run as", f"{s.get('run_as_user') or s.get('run_as')} — {s.get('run_as_derivation', '')}"),
        ("load state", f"{'enabled' if s.get('enabled', True) else 'disabled'} — {s.get('enabled_derivation', '')}"),
        ("mach services", ", ".join(f"`{m}`" for m in s.get("mach_services") or []) or "—"),
        ("ipc", target.get("ipc_classification")),
    ]:
        w(f"- **{key}**: {value}\n")

    w("\n## code signing\n\n")
    for key, value in [
        ("signed", "yes" if cs.get("is_signed") else ("no" if cs.get("is_signed") is False else "unknown")),
        ("identifier", f"`{cs.get('signer_identifier') or '—'}`"),
        ("team", cs.get("team_identifier") or "—"),
        ("platform binary", "unknown" if cs.get("platform_binary") is None else ("yes" if cs.get("platform_binary") else "no")),
        ("authority", " ← ".join(cs.get("authority") or []) or "—"),
        ("architectures", ", ".join(mo.get("architectures") or []) or "—"),
    ]:
        w(f"- **{key}**: {value}\n")

    assessments = target.get("sink_assessments") or []
    if assessments:
        w("\n## sensitive subsystems\n")
        for a in assessments:
            aspects = f" — aspects: {', '.join(a.get('aspects') or [])}" if a.get("aspects") else ""
            w(f"\n### {a['label']} · {a['confidence']} ({a['score']}){aspects}\n\n")
            for e in a.get("evidence") or []:
                weight = f"+{e['weight']}" if e.get("weight") else "not counted"
                aspect = f" _{e['aspect']}_" if e.get("aspect") else ""
                w(f"- `{e.get('match')}` — {e.get('kind')}{aspect} ({weight})\n")

    va = target.get("validation_assessment") or {}
    w(f"\n## caller validation — {target.get('validation', 'NONE_OBSERVED')}"
      f" (score {va.get('score', 0)})\n\n")
    for e in va.get("evidence") or []:
        w(f"- ✓ **{e.get('aspect') or 'other'}** (+{e.get('weight')}) — `{e.get('match')}`\n")
    for m in va.get("not_observed") or []:
        w(f"- ? {m.get('class')} (+{m.get('weight')}) — {m.get('description')}\n")
    w("\n> Static evidence only. \"Not observed\" is a statement about the scanner,"
      " not about the service.\n")

    capabilities = target.get("capability_findings") or []
    if capabilities:
        w(f"\n## capability paths ({len(capabilities)}) — research priority "
          f"{target.get('research_priority_score', 0)}/100\n")
        for c in capabilities:
            sink = c.get("sink") or {}
            w(f"\n### {c.get('primitive')} · {c.get('confidence')} · "
              f"{c.get('research_priority_score', 0)}/100\n\n")
            w(f"- **entry / transport**: {c.get('entry_point')} / {c.get('transport')}\n")
            w(f"- **dataflow**: `{' → '.join(c.get('dataflow') or [])}`\n")
            w(f"- **expected caller**: {c.get('expected_caller_identity')}\n")
            w(f"- **identity verification**: {c.get('identity_verification')}\n")
            w(f"- **authorization**: {c.get('authorization_decision')}\n")
            w(f"- **sink**: `{sink.get('api')}` — {sink.get('operation')}\n")
            w(f"- **attacker control**: {c.get('attacker_control')} — "
              f"`{_stringify(c.get('controlled_arguments') or {})}`\n")
            w(f"- **reachability**: {', '.join(c.get('reachability') or ['UNKNOWN'])}\n")
            w(f"- **call path**: {c.get('call_path_state', 'UNRESOLVED')} — "
              f"`{' -> '.join(c.get('call_path') or [])}`\n")
            for profile in c.get("caller_profiles") or []:
                w(f"- **caller profile**: {profile.get('profile')} — "
                  f"reach={profile.get('entry_reachability')}, "
                  f"mach_lookup={profile.get('mach_lookup')}, "
                  f"authorization={profile.get('authorization')}\n")
            for path in c.get("policy_paths") or []:
                w(f"- **policy path**: {path.get('predicate')} → "
                  f"{path.get('allowed_operation')} [{path.get('relationship')}]\n")
            guard = (c.get("authorization") or {}).get("guard_evidence") or {}
            if guard:
                w(f"- **guard evidence**: `{_stringify(guard)}`\n")
            unknown_reason = (c.get("authorization") or {}).get("unknown_reason")
            if unknown_reason:
                w(f"- **guard unknown**: {unknown_reason}\n")
            if c.get("descriptor_provenance"):
                w(f"- **descriptor provenance**: `{_stringify(c['descriptor_provenance'])}`\n")
            w(f"- **post-condition**: {c.get('post_condition')}\n")
            w(f"- **potential impact**: {c.get('potential_impact')}\n")
            for item in c.get("missing_proof") or []:
                w(f"- ? {item}\n")

    ipc_operations = (_macho(target) or {}).get("ipc_operations") or []
    if ipc_operations:
        w(f"\n## XPC operations ({len(ipc_operations)})\n")
        for operation in ipc_operations:
            w(f"\n### {operation.get('operation') or 'unresolved'} · "
              f"{operation.get('relationship', 'UNRESOLVED')}\n\n")
            w(f"- **request key**: {operation.get('request_key') or 'unknown'}\n")
            w(f"- **handler**: {operation.get('handler') or 'unresolved'}\n")
            w(f"- **input keys**: {', '.join(operation.get('input_keys') or []) or 'none'}\n")
            w(f"- **dispatcher**: {operation.get('dispatcher') or 'unknown'}\n")

    lpe_findings = target.get("lpe_findings") or []
    if lpe_findings:
        w(f"\n## LPE hunting — privileged filesystem ({len(lpe_findings)})\n")
        for finding in lpe_findings:
            sink = finding.get("sink") or {}
            w(f"\n### {', '.join(finding.get('lpe_classes') or [])} · "
              f"{finding.get('severity')} · {finding.get('confidence')}\n\n")
            w(f"- **score**: {finding.get('score', 0)}/100\n")
            w(f"- **flow**: {finding.get('input_origin')} → privileged service → "
              f"`{sink.get('api')}`\n")
            w(f"- **caller validation**: {finding.get('caller_validation')} "
              f"({finding.get('caller_validation_scope')})\n")
            w(f"- **operation authorization**: {finding.get('operation_authorization')} "
              f"({finding.get('operation_authorization_scope')})\n")
            w(f"- **resource validation**: {finding.get('resource_validation')}\n")
            w(f"- **resource scope**: {finding.get('resource_scope', 'UNKNOWN')} "
              f"({finding.get('resource_scope_confidence', 'UNKNOWN')})\n")
            w(f"- **resource authorization**: "
              f"{finding.get('resource_authorization', 'UNKNOWN')}\n")
            if finding.get("descriptor_provenance"):
                w(f"- **descriptor provenance**: "
                  f"`{_stringify(finding['descriptor_provenance'])}`\n")
            w(f"- **target**: {finding.get('target')} "
              f"({finding.get('target_category')})\n")
            w(f"- **TOCTOU candidate**: {finding.get('toctou_candidate')}\n")
            for item in finding.get("research_questions") or []:
                w(f"- [ ] {item}\n")
            for item in finding.get("missing_evidence") or []:
                w(f"- ? {item}\n")

    rce_findings = target.get("rce_findings") or []
    if rce_findings:
        w(f"\n## RCE hunting — network ingress x parser ({len(rce_findings)})\n")
        for finding in rce_findings:
            w(f"\n### {', '.join(finding.get('rce_classes') or [])} · "
              f"{finding.get('severity')} · {finding.get('confidence')}\n\n")
            w(f"- **score**: {finding.get('score', 0)}/100\n")
            w(f"- **ingress**: {finding.get('ingress_kind')} · runs as "
              f"{finding.get('privilege')}\n")
            w(f"- **parser**: `{', '.join(finding.get('parser_apis') or [])}`\n")
            w(f"- **caller validation**: {finding.get('caller_validation')}\n")
            for item in finding.get("missing_evidence") or []:
                w(f"- ? {item}\n")

    ents = cs.get("entitlements") or {}
    if ents:
        high = set(target.get("entitlement_findings") or [])
        w(f"\n## entitlements ({len(ents)})\n\n")
        for key in sorted(ents, key=lambda k: (k not in high, k)):
            mark = "**private**  " if key in high else ""
            w(f"- {mark}`{key}` = `{_stringify(ents[key])}`\n")

    w("\n## score\n\n")
    for r in target.get("reasons") or []:
        w(f"- `{r.get('weight'):+d}` {r.get('reason')}\n")

    if target.get("why_interesting"):
        w("\n## why interesting\n\n")
        for line in target["why_interesting"]:
            w(f"- {line}\n")
    if target.get("research_questions"):
        w("\n## research questions\n\n")
        for line in target["research_questions"]:
            w(f"- [ ] {line}\n")

    findings = target.get("findings") or []
    if findings:
        w(f"\n## findings ({len(findings)})\n\n")
        for f in findings:
            evidence = f" — {f['evidence']}" if f.get("evidence") else ""
            w(f"- `{f.get('level')}` [{f.get('category')}] {f.get('message')}{evidence}\n")

    return out.getvalue()


def export_report(report: Dict[str, Any], outdir: str, formats: Sequence[str] = ("csv", "md"),
                  dossiers: bool = True, md_limit: int = 500) -> List[str]:
    """Write one file per entity under *outdir*; return the paths written."""
    os.makedirs(outdir, exist_ok=True)
    written: List[str] = []
    tables = build_tables(report)

    for name, headers, rows in tables:
        if "csv" in formats:
            path = os.path.join(outdir, f"{name}.csv")
            _write_csv(path, headers, rows)
            written.append(path)
        if "md" in formats:
            path = os.path.join(outdir, f"{name}.md")
            _write_md_table(path, name.replace("_", " "), headers, rows, limit=md_limit)
            written.append(path)

    if "md" in formats and dossiers:
        target_dir = os.path.join(outdir, "services")
        os.makedirs(target_dir, exist_ok=True)
        index: List[str] = []
        for target in report.get("targets") or []:
            name = _safe_name(target["label"])
            path = os.path.join(target_dir, f"{name}.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(_target_markdown(target))
            written.append(path)
            index.append(f"- [{target['label']}](services/{name}.md) — "
                         f"`{target['priority']}` score {target['score']}, "
                         f"validation {target.get('validation', 'NONE_OBSERVED')}")
        index_path = os.path.join(outdir, "index.md")
        summary = report.get("summary") or {}
        with open(index_path, "w", encoding="utf-8") as fh:
            fh.write("# macOS-TBM export\n\n")
            fh.write(f"Generated {report.get('generated_at', '')} by {report.get('tool', '')}.\n\n")
            fh.write("| metric | value |\n|---|---|\n")
            for key, value in summary.items():
                fh.write(f"| {key.replace('_', ' ')} | {value} |\n")
            fh.write("\n## entity tables\n\n")
            for name, _, rows in tables:
                fh.write(f"- [{name.replace('_', ' ')}]({name}.md) — {len(rows)} rows "
                         f"([csv]({name}.csv))\n")
            fh.write("\n## services\n\n")
            fh.write("\n".join(index) + "\n")
        written.append(index_path)

    return written
