#!/usr/bin/env python3
"""macOS-TBM (Trust Boundary Mapper) — attack-surface research tool.

Usage:
    python3 tbm.py scan [--output ./results] [--json] [--html] [--graph] [--verbose]
    python3 tbm.py tui [--report ./results/report.json]
    python3 tbm.py inspect /usr/libexec/exampled
    python3 tbm.py service com.apple.example

The default pipeline is read-only and static. Optional deep/runtime backends
run only when explicitly requested. The tool does NOT prove exploitability;
absence of a static signal is never a claim of a vulnerability.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

import deputy_all
from app_info import version_string
from backends.orchestrator import run_optional_backends
from backends.runtime_xpc import MacOSXPCProbe, RuntimeProbeUnavailable
from collectors import discover_services, inspect_codesign, inspect_macho
from collectors.dataflow import inspect_dataflow
from entowners import entowners_contains, entowners_exact
from graph.exporters import export_dot, export_json, export_mermaid
from graph.model import build_graph
from graph.query import (
    TrustGraph,
    paths_to_text,
    to_dot,
    to_mermaid,
    to_text,
)
from hunt import format_single, format_text, score_report
from models.executable import Executable
from reporting.export import export_report
from reporting.html_report import write_html_report
from reporting.json_report import build_report, write_json_report
from scanner import analyze_service, run_scan
from ui import (
    LIST_LIMIT,
    Radare2Progress,
    ScanProgress,
    configure_logging,
    print_banner,
    render_scan_cli,
    render_scan_result,
    render_tui,
    run_tui_app,
)
from utils.commands import ResultCache
from utils.jsonio import dumps as json_dumps
from xref import format_xref, xref_string


def _write_output(output: str, destination: Optional[str]) -> None:
    """Write command output to stdout or a file, without polluting pipelines."""
    if destination is None:
        print(output)
        return
    os.makedirs(os.path.dirname(os.path.abspath(destination)), exist_ok=True)
    with open(destination, "w", encoding="utf-8") as fh:
        fh.write(output + "\n")
    print(f"  {destination}")


def _setup_logging(verbose: bool) -> None:
    configure_logging(verbose, interactive=sys.stderr.isatty())


def _apply_filters(targets: List, args: argparse.Namespace) -> List:
    out = targets
    if getattr(args, "min_score", None) is not None:
        out = [t for t in out if (t.research_priority_score or t.score) >= args.min_score]
    if getattr(args, "privileged_only", False):
        out = [t for t in out if t.service.is_privileged]
    if getattr(args, "mach_only", False):
        out = [t for t in out if t.service.mach_services or t.service.sockets]
    if getattr(args, "entitlement", None):
        pat = args.entitlement.lower()
        out = [
            t
            for t in out
            if any(pat in k.lower() for k in (t.executable.codesign.entitlements if t.executable.codesign else {}))
            or any(pat in e.lower() for e in t.entitlement_findings)
        ]
    if getattr(args, "primitive", None):
        wanted = {p.upper() for p in args.primitive}
        out = [t for t in out if any(
            wanted.intersection({f.primitive.upper(), f.candidate_capability.upper(),
                                 (f.proven_primitive or "").upper()})
            for f in t.capability_findings)]
    if getattr(args, "maturity", None):
        wanted = {m.upper() for m in args.maturity}
        out = [t for t in out if any(
            f.maturity_level.upper() in wanted for f in t.capability_findings)]
    if getattr(args, "min_exploitability", None) is not None:
        out = [t for t in out if t.exploitability_evidence_score >= args.min_exploitability]
    if getattr(args, "proven_only", False):
        out = [t for t in out if any(f.proven_primitive for f in t.capability_findings)]
    if getattr(args, "confidence", None):
        wanted = {c.upper() for c in args.confidence}
        out = [t for t in out if any(
            f.confidence.upper() in wanted for f in t.capability_findings)]
    if getattr(args, "reachable_by", None):
        wanted = {r.upper() for r in args.reachable_by}
        out = [t for t in out if any(
            wanted.intersection({r.upper() for r in f.reachability})
            for f in t.capability_findings)]
    if getattr(args, "sink", None):
        wanted = args.sink.lower()
        out = [t for t in out if (
            any(wanted in a.sink.lower() or wanted in a.label.lower()
                for a in t.sink_assessments)
            or any(wanted in f.sink_category.lower() or wanted in f.sink_api.lower()
                   for f in t.capability_findings)
        )]
    if getattr(args, "framework", None):
        wanted = args.framework.lower()
        out = [t for t in out if (
            any(wanted in lib.lower() for lib in
                (t.executable.macho.linked_libs if t.executable.macho else []))
            or any(wanted in f.framework.lower() for f in t.capability_findings)
        )]
    if getattr(args, "validation", None):
        wanted = {v.upper() for v in args.validation}
        out = [t for t in out if (t.validation.upper() in wanted or any(
            f.identity_verification.upper() in wanted for f in t.capability_findings))]
    if getattr(args, "limit", None) is not None:
        out = out[: args.limit]
    return out


# A scan without -out still saves its work; only an explicit --json pipe does not.
DEFAULT_OUTDIR = "./results"
# Width of the saved text report: wide enough for paths, narrow enough to read.
RAW_WIDTH = 120


def _cmd_scan(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)
    stdout_output = args.output is None and args.json
    outdir = args.output or DEFAULT_OUTDIR

    def progress(done: int, total: int) -> None:
        if not args.verbose and total and not stdout_output and sys.stdout.isatty():
            print(f"\r  analyzing executables: {done}/{total}", end="", flush=True)

    progress_enabled = not stdout_output and sys.stderr.isatty()
    with ScanProgress("rich", enabled=progress_enabled, stream=sys.stderr) as scan_progress:
        progress_callback = scan_progress.update
        if not scan_progress.enabled:
            progress_callback = progress
        targets = run_scan(
            scope=args.scope, workers=args.workers, verbose=args.verbose,
            progress=progress_callback, target=args.target,
        )
    if not stdout_output:
        print()

    targets = _apply_filters(targets, args)
    with Radare2Progress(
        enabled=bool(args.deep_analysis) and not stdout_output and sys.stderr.isatty(),
        stream=sys.stderr,
    ) as deep_progress:
        optional_analysis = run_optional_backends(
            targets,
            deep_analysis=args.deep_analysis,
            deep_min_score=args.deep_min_score,
            deep_max_findings=args.deep_max_findings,
            deep_workers=args.deep_workers,
            deep_binary_timeout=args.deep_binary_timeout,
            runtime_probe=args.runtime_probe,
            runtime_timeout=args.runtime_timeout,
            runtime_max_services=args.runtime_max_services,
            probe_send_empty=args.probe_send_empty,
            deep_progress=deep_progress.update,
        )
    graph = build_graph(targets)
    filter_meta = {
        "scope": args.scope,
        "min_score": args.min_score,
        "privileged_only": args.privileged_only,
        "mach_only": args.mach_only,
        "entitlement": args.entitlement,
        "primitive": args.primitive,
        "maturity": args.maturity,
        "min_exploitability": args.min_exploitability,
        "proven_only": args.proven_only,
        "confidence": args.confidence,
        "reachable_by": args.reachable_by,
        "sink": args.sink,
        "framework": args.framework,
        "validation": args.validation,
        "limit": args.limit,
        "deep_analysis": args.deep_analysis,
        "runtime_probe": args.runtime_probe,
    }
    report = build_report(targets, graph, meta={
        "scope": args.scope, "filters": filter_meta,
        "optional_analysis": optional_analysis,
        "scan_options": {key: value for key, value in vars(args).items()
                         if key != "func"},
    })

    s = report["summary"]
    if stdout_output:
        _write_output(json_dumps(report), args.output)
        render_scan_result(s, output_dir=outdir, stream=sys.stderr)
        return 0

    os.makedirs(outdir, exist_ok=True)
    want_json = args.json or not (args.html or args.graph)
    want_html = args.html or not (args.json or args.graph)
    want_graph = args.graph or not (args.json or args.html)

    artifacts = []
    if want_json:
        write_json_report(os.path.join(outdir, "report.json"), report)
        artifacts.append("report.json")
    if want_html:
        # write_html_report slims the payload itself and uses the graph for counts
        write_html_report(os.path.join(outdir, "report.html"), report)
        artifacts.append("report.html")
    if want_graph:
        with open(os.path.join(outdir, "graph.json"), "w", encoding="utf-8") as fh:
            fh.write(export_json(graph))
        with open(os.path.join(outdir, "graph.dot"), "w", encoding="utf-8") as fh:
            fh.write(export_dot(graph))
        with open(os.path.join(outdir, "graph.mmd"), "w", encoding="utf-8") as fh:
            fh.write(export_mermaid(graph))
        artifacts.append("graph.json / graph.dot / graph.mmd")

    # The terminal view is saved verbatim, so the dossiers are kept without
    # flooding stdout; --detail prints them here as well.
    with open(os.path.join(outdir, "scan.txt"), "w", encoding="utf-8") as fh:
        render_scan_cli(report, limit=args.limit or 15, detail=True,
                        detail_limit=args.detail_limit, list_limit=args.list_limit,
                        width=RAW_WIDTH, stream=fh)
    artifacts.append("scan.txt")

    render_scan_cli(report, limit=args.limit or 15, detail=args.detail,
                    detail_limit=args.detail_limit, list_limit=args.list_limit)
    render_scan_result(s, output_dir=outdir, artifacts=artifacts)
    if not args.detail:
        print(f"  full per-target dossiers: {os.path.join(outdir, 'scan.txt')}"
              f"   (--detail prints them here too)")
    return 0


def _print_target(t) -> None:
    svc = t.service
    exe = t.executable
    cs = exe.codesign
    print(f"\n=== {svc.label}  (score {t.score}, {t.priority}) ===")
    print(f"  plist:    {svc.plist_path}")
    print(f"  binary:   {svc.associated_executable or '-'}")
    print(f"  run as:   {svc.run_as.value} — {svc.run_as_derivation}")
    print(f"  mach:     {', '.join(svc.mach_services) or '-'}")
    print(f"  ipc:      {t.ipc_classification}")
    if cs:
        print(f"  signed:   {cs.is_signed}  id={cs.signer_identifier}  team={cs.team_identifier}")
        print(f"  entitlements: {', '.join(cs.entitlements) or '-'}")
    if t.sink_assessments:
        print("  sinks:")
        for a in t.sink_assessments:
            bar = "\u2588" * max(1, min(10, a.score // 2))
            aspects = f"  [{', '.join(a.aspects)}]" if a.aspects else ""
            print(f"    {a.label:16} {a.confidence:6} {bar} ({a.score}){aspects}")
            # Group the evidence by aspect so the facets stay readable.
            groups: dict = {}
            for ev in a.evidence:
                groups.setdefault(ev.aspect, []).append(ev)
            for aspect, evs in sorted(groups.items(), key=lambda kv: -max(e.weight for e in kv[1])):
                shown = [e for e in evs if e.weight][:6]
                skipped = len(evs) - len(shown)
                head = f"{aspect}: " if aspect else ""
                if shown:
                    print(f"        \u21b3 {head}{', '.join(e.match for e in shown)}"
                          + (f" (+{skipped} not counted)" if skipped else ""))
                elif not aspect:
                    print(f"        \u21b3 {', '.join(e.describe() for e in evs[:3])}")
    else:
        print("  sinks:    -")
    va = t.validation_assessment
    print(f"  caller validation: {t.validation}" + (f"  (score {va.score})" if va else ""))
    if va:
        for name, evs in sorted(va.by_class.items(), key=lambda kv: -max(e.weight for e in kv[1])):
            w = max(e.weight for e in evs)
            print(f"        \u2713 {name:26} +{w}  {', '.join(e.match for e in evs[:3])}")
        for miss in va.missing[:4]:
            print(f"        ? {miss['class']:26} +{miss['weight']}  not observed")
    print("  reasons:")
    for r in t.reasons:
        print(f"    {r.weight:+d}  {r.reason}")
    print("  why interesting:")
    for w in t.why_interesting:
        print(f"    - {w}")
    print("  research questions:")
    for q in t.research_questions:
        print(f"    ? {q}")


def _cmd_inspect(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)
    path = os.path.abspath(args.path)
    if not os.path.exists(path):
        print(f"error: {path} does not exist", file=sys.stderr)
        return 1

    cache = ResultCache()
    exe = Executable(path=path)
    exe.macho = inspect_macho(path, cache)
    flow = inspect_dataflow(path, exe.macho)
    exe.macho.dataflow_facts = flow.facts
    exe.macho.dataflow_unknown_reasons = flow.unknown_reasons
    exe.macho.dataflow_functions_analyzed = flow.functions_analyzed
    exe.macho.dataflow_direct_calls = flow.direct_calls
    exe.codesign = inspect_codesign(path, cache)

    print(f"=== inspect {path} ===")
    mo = exe.macho
    cs = exe.codesign
    if mo:
        print(f"  Mach-O: {mo.is_macho}  fat: {mo.is_fat}  archs: {', '.join(mo.architectures) or '-'}")
        print(f"  linked libs ({len(mo.linked_libs)}):")
        for lib in mo.linked_libs[:30]:
            print(f"    {lib}")
        print(f"  imported symbols: {len(mo.imported_symbols)}  exported: {len(mo.exported_symbols)}")
        print(f"  objc classes: {len(mo.objc_classes)}  rpaths: {len(mo.rpaths)}")
        if mo.interesting_strings:
            print(f"  interesting strings ({len(mo.interesting_strings)}):")
            for s in mo.interesting_strings[:30]:
                print(f"    {s}")
        if mo.dataflow_facts:
            print(f"  direct IPC source-to-sink flows ({len(mo.dataflow_facts)}):")
            for fact in mo.dataflow_facts[:20]:
                args_text = ",".join(str(i) for i in fact.get("controlled_argument_indexes", []))
                print(f"    {fact.get('function')}  {fact.get('source_api')}@"
                      f"{fact.get('source_address')} -> {fact.get('sink_api')}@"
                      f"{fact.get('sink_address')}  args={args_text}")
        if mo.dataflow_unknown_reasons:
            causes = ", ".join(f"{key}={value}" for key, value in
                               sorted(mo.dataflow_unknown_reasons.items()))
            print(f"  unresolved dataflow causes: {causes}")
    if cs:
        print(f"  signed: {cs.is_signed}  id={cs.signer_identifier}  team={cs.team_identifier}")
        print(f"  platform binary: {cs.platform_binary}")
        print(f"  flags: {', '.join(cs.flags) or '-'}")
        print(f"  authority: {' <- '.join(cs.authority) or '-'}")
        if cs.entitlements:
            print(f"  entitlements ({len(cs.entitlements)}):")
            for k, v in cs.entitlements.items():
                print(f"    {k} = {v}")
        else:
            print("  entitlements: none")
    return 0


def _cmd_probe(args: argparse.Namespace) -> int:
    """Explicit active reachability check for one Mach service."""
    _setup_logging(args.verbose)
    try:
        backend = MacOSXPCProbe()
        observation = backend.probe(
            args.mach_service, timeout=args.timeout, send_empty=args.send_empty)
    except RuntimeProbeUnavailable as exc:
        print(f"runtime probe unavailable: {exc}", file=sys.stderr)
        return 2
    payload = observation.to_dict()
    if args.format == "json":
        _write_output(json_dumps(payload), args.output)
    else:
        lines = [
            f"Mach service: {payload['mach_service']}",
            f"Status: {payload['status']}",
            f"Mach reachability: {payload['connection']}",
            f"Request: {payload['request']}",
            f"Operation reachability: {payload['operation_reachability']}",
            f"Authorization bypass: {payload['authorization_bypass']}",
            f"Reply: {payload['reply']}",
        ]
        if payload.get("error"):
            lines.append(f"Error: {payload['error']}")
        _write_output("\n".join(lines), args.output)
    return 0


def _load_graph(path: str) -> Optional[TrustGraph]:
    if not os.path.exists(path):
        print(f"no report at {path} — run 'tbm scan' first, or pass --report", file=sys.stderr)
        return None
    with open(path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    graph = report.get("graph")
    if not graph:
        print(f"{path} carries no graph (was it written with --json only?)", file=sys.stderr)
        return None
    return TrustGraph(graph)


def _cmd_graph(args: argparse.Namespace) -> int:
    """Query the trust-boundary graph instead of reading all 8,000 nodes."""
    _setup_logging(args.verbose)
    tg = _load_graph(args.report)
    if tg is None:
        return 2

    output = ""
    if args.boundaries:
        rows = tg.boundary_crossings(min_score=args.min_score,
                                     enabled_only=not args.include_disabled,
                                     validation=args.validation or None)
        if args.format == "json":
            output = json.dumps(rows, indent=2)
        else:
            lines = [f"{len(rows)} boundary crossing(s): a non-root client naming a "
                     f"root daemon's Mach service\n"]
            lines.append(f"  {'MACH SERVICE':52} {'PROVIDER':30} {'SCORE':>5} {'VALIDATION':12} CLIENT")
            for r in rows[: args.limit]:
                lines.append(f"  {r['mach_service'][:52]:52} {r['provider'][:30]:30} "
                             f"{r['provider_score']:>5} {r['provider_validation']:12} "
                             f"{r['client_service'] or r['client']} [{r['evidence']}]")
            if len(rows) > args.limit:
                lines.append(f"  ... +{len(rows) - args.limit} more (raise --limit)")
            output = "\n".join(lines)

    elif args.path:
        source, target = args.path
        src_ids, dst_ids = tg.resolve(source), tg.resolve(target)
        if not src_ids or not dst_ids:
            print(f"could not resolve {'source' if not src_ids else 'target'}", file=sys.stderr)
            return 1
        paths = tg.shortest_paths(src_ids[0], dst_ids[0], max_paths=args.max_paths,
                                  max_depth=args.depth or 6)
        if args.format == "json":
            output = json.dumps([[{"node": n, "edge": e} for n, e in p] for p in paths], indent=2)
        else:
            output = (f"{tg.node(src_ids[0]).get('label')}  ->  "
                      f"{tg.node(dst_ids[0]).get('label')}\n\n" + paths_to_text(tg, paths))

    elif args.deputy:
        gate = list(args.deputy_entitlement) if args.deputy_entitlement else None
        rows = tg.deputies(args.deputy, gate_entitlements=gate)
        if args.format == "json":
            output = json.dumps(rows, indent=2)
        else:
            target = args.deputy
            header = (f"{len(rows)} deputy candidate(s) for {target}: clients that look up "
                      f"its Mach service and hold a gate entitlement (checked server-side, "
                      f"falling back to <label>.*)\n")
            lines = [header]
            lines.append(f"  {'CLIENT':48} {'RUN_AS':12} {'PRIV':>5} {'VALIDATION':12} GATE ENTITLEMENTS")
            for r in rows[: args.limit]:
                lines.append(f"  {r['client'][:48]:48} {r['client_run_as']:12} "
                             f"{'yes' if r['client_privileged'] else 'no':>5} "
                             f"{r['client_validation']:12} {', '.join(r['gate_entitlements'])}")
            if not rows:
                lines.append("  (no deputies found — pass --deputy-entitlement to gate on an "
                             "explicit entitlement)")
            if len(rows) > args.limit:
                lines.append(f"  ... +{len(rows) - args.limit} more (raise --limit)")
            output = "\n".join(lines)

    elif args.node:
        ids = tg.resolve(args.node)
        if not ids:
            print(f"no node matches {args.node!r}", file=sys.stderr)
            return 1
        if len(ids) > 1 and args.format == "text":
            print(f"{len(ids)} nodes match {args.node!r}; showing {ids[0]}")
            for other in ids[1:6]:
                print(f"    also: {other}")
            print()
        sub = tg.neighbourhood(ids[0], depth=args.depth or 1,
                               edge_types=args.edge or None, limit=args.limit)
        output = {"dot": lambda: to_dot(sub, tg.node(ids[0]).get("label", "graph")),
                  "mermaid": lambda: to_mermaid(sub),
                  "json": lambda: json.dumps(sub.to_dict(), indent=2),
                  "text": lambda: to_text(tg, sub)}[args.format]()
    else:
        print("pick one of --node, --path, --boundaries or --deputy", file=sys.stderr)
        return 2

    _write_output(output, args.output)
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    """Flatten an existing report into one file per entity."""
    _setup_logging(args.verbose)
    if not os.path.exists(args.report):
        print(f"no report at {args.report} — run 'tbm scan' first, or pass --report", file=sys.stderr)
        return 2
    with open(args.report, "r", encoding="utf-8") as fh:
        report = json.load(fh)

    formats = ["csv", "md"] if args.format == "both" else [args.format]
    written = export_report(report, args.output, formats=formats,
                            dossiers=not args.no_dossiers, md_limit=args.md_limit)

    tables = sum(1 for p in written if os.path.dirname(p) == os.path.abspath(args.output)
                 or os.path.dirname(p) == args.output)
    dossiers = len(written) - tables
    print(f"\n  {len(written)} files -> {args.output}")
    for path in sorted(p for p in written if p.endswith((".csv", ".md"))
                       and os.sep + "services" + os.sep not in p)[:40]:
        print(f"    {os.path.basename(path)}")
    if dossiers:
        print(f"    services/  ({dossiers} per-service dossiers)")
    return 0


def _cmd_xref(args: argparse.Namespace) -> int:
    """Find code references to a string in a Mach-O binary (RE helper).

    Read-only: parses the Mach-O and streams the disassembly; no launchd
    contact. arm64/arm64e cross-references (adrp+add literal pools).
    """
    _setup_logging(args.verbose)
    path = os.path.abspath(args.binary)
    if not os.path.exists(path):
        print(f"error: {path} does not exist", file=sys.stderr)
        return 1
    try:
        results = xref_string(
            path,
            args.string,
            arch=args.arch,
            context=args.context,
            max_refs=args.max_refs,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        payload = [
            {
                "string_vaddr": hex(r.string_vaddr),
                "ref_vaddr": hex(r.ref_vaddr),
                "function": hex(r.function) if r.function else None,
                "context": r.context,
            }
            for r in results
        ]
        output = json_dumps(payload)
    else:
        output = format_xref(results)
    _write_output(output, args.output)
    return 0


def _cmd_entowners(args: argparse.Namespace) -> int:
    """List which scanned targets hold a given entitlement.

    Read-only over report.json; no new analysis, no launchd mutations.
    """
    _setup_logging(args.verbose)
    if not os.path.exists(args.report):
        print(f"no report at {args.report} — run 'tbm scan' first, or pass --report",
              file=sys.stderr)
        return 2
    with open(args.report, "r", encoding="utf-8") as fh:
        report = json.load(fh)

    if args.contains:
        rows = entowners_contains(report, args.entitlement)
    else:
        rows = entowners_exact(report, args.entitlement)

    if args.format == "json":
        output = json_dumps(rows)
    elif not rows:
        output = f"no target holds an entitlement matching '{args.entitlement}'"
    else:
        output = "\n".join(
            f'{r["score"]:>3} {str(r["run_as"]):15s} {r["validation"]:14s} '
            f'{r["label"]}  [{", ".join(r["matching"])}]'
            for r in rows
        )
    _write_output(output, args.output)
    return 0


def _cmd_deputy_all(args: argparse.Namespace) -> int:
    """Map deputy chains across every daemon in an existing report.

    Read-only over report.json; no new analysis, no launchd mutations.
    """
    _setup_logging(args.verbose)
    tg = _load_graph(args.report)
    if tg is None:
        return 2
    by_root = deputy_all.build(
        tg,
        gate=args.gate_entitlement,
        max_depth=args.max_depth,
        min_score=args.min_score,
        root_only=args.root_only,
    )
    counts = deputy_all.counts(by_root)
    if args.output:
        deputy_all.write_outputs(by_root, args.output)
        _write_output(
            f"deputy-all: {counts['roots']} roots, {counts['chains']} chains, "
            f"{counts['unprivileged_leaves']} end at an unprivileged client -> "
            f"{args.output}.md/.csv/.json",
            None,
        )
    else:
        _write_output(deputy_all.render_text(by_root, args.limit), None)
    return 0


def _cmd_hunt(args: argparse.Namespace) -> int:
    """Score targets in an existing report for bug-bounty signals (LPE/RCE/DOS/CRED).

    Read-only — no new analysis, no launchd mutations.
    """
    _setup_logging(args.verbose)
    if not os.path.exists(args.report):
        print(f"no report at {args.report} — run 'tbm scan' first, or pass --report",
              file=sys.stderr)
        return 2
    with open(args.report, "r", encoding="utf-8") as fh:
        report = json.load(fh)

    results = score_report(report)

    # --label: single-target brief
    if args.label:
        needle = args.label.lower()
        matches = [r for r in results if needle in r.label.lower()]
        if not matches:
            print(f"no target matching '{args.label}'", file=sys.stderr)
            return 1
        _write_output("\n\n".join(format_single(m) for m in matches), args.output)
        return 0

    # --class: sort by a single dimension
    if getattr(args, "class_filter", None):
        cls = args.class_filter
        if cls == "all":
            pass  # keep total sort
        else:
            results.sort(key=lambda r: getattr(r, cls, 0), reverse=True)

    if getattr(args, "primitive", None):
        wanted = args.primitive.upper()
        results = [r for r in results if wanted in {
            p.upper() for p in r.primitives + r.candidate_capabilities}]
    if getattr(args, "maturity", None):
        results = [r for r in results if r.maturity == args.maturity]
    if getattr(args, "min_exploitability", None) is not None:
        results = [r for r in results
                   if r.exploitability_evidence >= args.min_exploitability]
    if getattr(args, "proven_only", False):
        results = [r for r in results if r.proven_primitive]
    if getattr(args, "confidence", None):
        if getattr(args, "class_filter", None) == "lpe":
            results = [r for r in results if any(
                finding.get("confidence") == args.confidence for finding in r.lpe_findings)]
        else:
            results = [r for r in results if args.confidence in r.confidence_levels]
    if getattr(args, "reachable_by", None):
        results = [r for r in results if args.reachable_by in r.reachable_by]
    if getattr(args, "sink", None):
        wanted = args.sink.lower()
        results = [r for r in results if any(wanted in s.lower() for s in r.sink_categories)
                   or any(wanted in s.lower() for s in r.sinks)]
    if getattr(args, "framework", None):
        wanted = args.framework.lower()
        results = [r for r in results if any(wanted in f.lower() for f in r.frameworks)]
    if getattr(args, "validation", None):
        results = [r for r in results if r.validation == args.validation
                   or r.identity_verification == args.validation]

    top = getattr(args, "top", 30)
    if getattr(args, "min_score", None) is not None:
        results = [r for r in results if r.research_priority >= args.min_score]
    if getattr(args, "min_tbm_score", None) is not None:
        results = [r for r in results if r.tbm_score >= args.min_tbm_score]

    if args.format == "json":
        from utils.jsonio import dumps as json_dumps
        payload = [
            {
                "label": r.label,
                "tbm_score": r.tbm_score,
                "run_as": r.run_as,
                "validation": r.validation,
                "mach_count": r.mach_count,
                "lpe": r.lpe,
                "rce": r.rce,
                "dos": r.dos,
                "cred": r.cred,
                "total": r.total,
                "flags": r.flags(),
                "sinks": r.sinks,
                "held_ents": r.held_ents,
                "checked_ents": r.checked_ents,
                "not_observed": r.not_observed,
                "research_priority_score": r.research_priority,
                "exploitability_evidence_score": r.exploitability_evidence,
                "candidate_capability": r.candidate_capability,
                "maturity": r.maturity,
                "proven_primitive": r.proven_primitive,
                "primitive": r.primitive,
                "confidence": r.confidence,
                "reachable_by": r.reachable_by,
                "reason": r.reason,
                "framework": r.framework,
                "sink_category": r.sink_category,
                "dimensions": r.dimensions,
                "identity_verification": r.identity_verification,
                "primitives": r.primitives,
                "candidate_capabilities": r.candidate_capabilities,
                "confidence_levels": r.confidence_levels,
                "frameworks": r.frameworks,
                "sink_categories": r.sink_categories,
                "lpe_findings": r.lpe_findings,
                "rce_findings": r.rce_findings,
            }
            for r in results[:top]
        ]
        _write_output(json_dumps(payload), args.output)
        return 0

    # text output
    parts = []
    if getattr(args, "class_filter", None):
        parts.append(f"  class filter: --class {args.class_filter}")
    if getattr(args, "class_filter", None) == "lpe":
        from hunt import format_lpe_text
        parts.append(format_lpe_text(results, top=top))
    elif getattr(args, "class_filter", None) == "rce":
        from hunt import format_rce_text
        parts.append(format_rce_text(results, top=top))
    else:
        parts.append(format_text(results, top=top))
    _write_output("\n".join(parts), args.output)
    return 0


def _cmd_tui(args: argparse.Namespace) -> int:
    """Review an existing JSON report in the terminal, dossiers included."""
    _setup_logging(args.verbose)
    if not os.path.exists(args.report):
        print(f"no report at {args.report} — run 'tbm scan' first, or pass --report",
              file=sys.stderr)
        return 2
    with open(args.report, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    if sys.stdin.isatty() and sys.stdout.isatty() and run_tui_app(
            report, list_limit=args.list_limit):
        return 0
    render_tui(report, limit=args.limit, min_score=args.min_score,
               priority=args.priority, validation=args.validation,
               sink=args.sink, search=args.search,
               detail=args.detail, list_limit=args.list_limit)
    return 0


def _cmd_protocol(args: argparse.Namespace) -> int:
    """Extract NSXPC-exported protocols from a Mach-O binary (or a service)."""
    _setup_logging(args.verbose)
    from collectors.nsxpc import extract_protocols

    path, mach_services = _resolve_binary_or_service(args.target)
    if not path:
        print(f"could not resolve '{args.target}' to a binary", file=sys.stderr)
        return 1

    result = extract_protocols(path)
    result["mach_service"] = mach_services[0] if mach_services else None

    if args.format == "json":
        output = json.dumps(result, indent=2)
    else:
        lines = [f"{path}"]
        mach = result["mach_service"]
        if mach:
            lines.append(f"  mach service: {mach}")
        for proto in result["protocols"]:
            lines.append(f"\nprotocol {proto['name']}  ({len(proto['methods'])} methods)")
            for m in proto["methods"]:
                lines.append(f"  {m['signature']}")
        if not result["protocols"]:
            lines.append("\n(no NSXPC-exported protocols found)")
        output = "\n".join(lines)

    _write_output(output, args.output)
    return 0


def _resolve_binary_or_service(target: str):
    """Return ``(binary_path, [mach_services])`` for a path or a service label."""
    path = os.path.abspath(target)
    if os.path.exists(path):
        return path, []
    label = target.lower()
    matches = [s for s in discover_services() if label in s.label.lower()]
    if matches:
        svc = matches[0]
        return svc.associated_executable, svc.mach_services
    return None, []


def _cmd_service(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)
    label = args.label.lower()
    services = discover_services()
    matches = [s for s in services if label in s.label.lower()]
    if not matches:
        print(f"no service matching '{args.label}'", file=sys.stderr)
        return 1

    cache = ResultCache()
    for svc in matches:
        exe = Executable(path=svc.associated_executable or "")
        if exe.path and os.path.exists(exe.path):
            exe.macho = inspect_macho(exe.path, cache)
            flow = inspect_dataflow(exe.path, exe.macho)
            exe.macho.dataflow_facts = flow.facts
            exe.macho.dataflow_unknown_reasons = flow.unknown_reasons
            exe.macho.dataflow_functions_analyzed = flow.functions_analyzed
            exe.macho.dataflow_direct_calls = flow.direct_calls
            exe.codesign = inspect_codesign(exe.path, cache)
        target = analyze_service(svc, exe)
        _print_target(target)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tbm",
        description="macOS-TBM — trust-boundary and attack-surface research tool",
    )
    p.add_argument("--version", action="version", version=version_string())
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan launchd services and map trust boundaries")
    s.add_argument("target", nargs="?",
                   help="optional service label, Mach service or executable substring")
    s.add_argument("-out", "--output", default=None,
                   help=f"output directory (default: {DEFAULT_OUTDIR})")
    s.add_argument("--json", action="store_true", help="emit report.json only")
    s.add_argument("--html", action="store_true", help="emit report.html only")
    s.add_argument("--graph", action="store_true", help="emit graph.json/.dot/.mmd only")
    s.add_argument("--scope", choices=["all", "daemons", "agents"], default="all")
    s.add_argument("--workers", type=int, default=8, help="parallel analysis workers")
    s.add_argument("--deep-analysis", choices=["radare2"], default=None,
                   help="experimental static callsite/xref enrichment")
    s.add_argument("--deep-min-score", type=int, default=70)
    s.add_argument("--deep-max-findings", type=int, default=200)
    s.add_argument("--deep-workers", type=int, default=3,
                   help="parallel Radare2 binary workers (default: 3)")
    s.add_argument("--deep-binary-timeout", type=float, default=300.0,
                   help="maximum Radare2 aaa time per binary in seconds (default: 300)")
    s.add_argument("--runtime-probe", action="store_true",
                   help="actively validate Mach reachability (connect-only by default)")
    s.add_argument("--runtime-timeout", type=float, default=1.0)
    s.add_argument("--runtime-max-services", type=int, default=50)
    s.add_argument("--probe-send-empty", action="store_true",
                   help="with --runtime-probe, explicitly send an empty XPC dictionary")
    s.add_argument("--min-score", type=int, default=None,
                   help="minimum research-priority score (legacy score if no capability exists)")
    s.add_argument("--privileged-only", action="store_true", help="only root/system services")
    s.add_argument("--mach-only", action="store_true", help="only Mach/XPC-exposing services")
    s.add_argument("--entitlement", default=None, help="filter by entitlement substring")
    s.add_argument("--primitive", action="append", metavar="PRIMITIVE",
                   help="filter by candidate capability or proven primitive (repeatable)")
    s.add_argument("--maturity", action="append",
                   choices=["SINK_CANDIDATE", "REACHABLE_SINK", "CONTROLLED_SINK",
                            "PRIMITIVE", "IMPACT"],
                   help="filter by operation maturity (repeatable)")
    s.add_argument("--min-exploitability", type=int, default=None,
                   help="minimum exploitability-evidence score")
    s.add_argument("--proven-only", action="store_true",
                   help="only targets with a proven primitive")
    s.add_argument("--confidence", action="append",
                   choices=["CONFIRMED", "HIGH", "MEDIUM", "LOW", "SPECULATIVE"],
                   help="filter by capability confidence (repeatable)")
    s.add_argument("--reachable-by", action="append",
                   choices=["LOCAL_USER", "SANDBOXED_PROCESS", "UNSANDBOXED_PROCESS",
                            "ENTITLED_PROCESS", "ROOT_ONLY", "SYSTEM_COMPONENT_ONLY", "UNKNOWN"],
                   help="filter by statically inferred reachability (repeatable)")
    s.add_argument("--sink", help="filter by sink category or API substring")
    s.add_argument("--framework", help="filter by sensitive framework substring")
    s.add_argument("--validation", action="append",
                   choices=["NONE_OBSERVED", "WEAK", "CONDITIONAL", "MEDIUM", "STRONG", "UNKNOWN"],
                   help="filter by caller identity-verification grade (repeatable)")
    s.add_argument("--limit", type=int, default=None, help="cap number of reported targets")
    s.add_argument("--detail", action="store_true",
                   help="also print the per-target dossiers, which are always saved"
                        " to scan.txt")
    s.add_argument("--detail-limit", type=int, default=None,
                   help="max per-target dossiers to write (default: every reported target)")
    s.add_argument("--list-limit", type=int, default=LIST_LIMIT,
                   help="max items per long list inside a dossier (0 = no cap)")
    s.add_argument("-v", "--verbose", action="store_true", help="include detailed diagnostics")
    s.set_defaults(func=_cmd_scan)

    i = sub.add_parser("inspect", help="analyze a single Mach-O binary")
    i.add_argument("path")
    i.add_argument("--verbose", action="store_true")
    i.set_defaults(func=_cmd_inspect)

    pb = sub.add_parser("probe", help="actively validate one Mach service")
    pb.add_argument("mach_service")
    pb.add_argument("--timeout", type=float, default=1.0)
    pb.add_argument("--send-empty", action="store_true",
                    help="explicitly send one empty XPC dictionary")
    pb.add_argument("--format", choices=["text", "json"], default="text")
    pb.add_argument("-out", "--output")
    pb.add_argument("--verbose", action="store_true")
    pb.set_defaults(func=_cmd_probe)

    sv = sub.add_parser("service", help="analyze launchd service(s) by label substring")
    sv.add_argument("label")
    sv.add_argument("--verbose", action="store_true")
    sv.set_defaults(func=_cmd_service)

    pr = sub.add_parser(
        "protocol",
        help="extract NSXPC-exported protocols from a binary or service")
    pr.add_argument("target", help="binary path or launchd service label")
    pr.add_argument("--format", choices=["text", "json"], default="text")
    pr.add_argument("-out", "--output", help="write to a file (default: stdout)")
    pr.add_argument("--verbose", action="store_true")
    pr.set_defaults(func=_cmd_protocol)

    e = sub.add_parser("export", help="export an existing report as per-entity CSV / Markdown")
    e.add_argument("--report", default="./results/report.json", help="report.json to read")
    e.add_argument("--output", default="./results/export", help="output directory")
    e.add_argument("--format", choices=["csv", "md", "both"], default="both")
    e.add_argument("--no-dossiers", action="store_true",
                   help="skip the per-service Markdown dossiers")
    e.add_argument("--md-limit", type=int, default=500,
                   help="max rows per Markdown table (0 = all); CSV always has every row")
    e.add_argument("--verbose", action="store_true")
    e.set_defaults(func=_cmd_export)

    tu = sub.add_parser("tui", help="review a report in the terminal, with full dossiers")
    tu.add_argument("--report", default="./results/report.json", help="report.json to read")
    tu.add_argument("--limit", type=int, default=25,
                    help="top targets to show in the non-interactive view"
                         " (the dashboard scrolls through all of them)")
    tu.add_argument("--min-score", type=int, default=0, help="only targets scoring at least N")
    tu.add_argument("--priority", choices=["HIGH", "MEDIUM", "LOW", "INFO"],
                    help="filter by priority")
    tu.add_argument("--validation", choices=["NONE_OBSERVED", "WEAK", "MEDIUM", "STRONG"],
                    help="filter by caller-validation grade")
    tu.add_argument("--sink", help="filter by sensitive sink name")
    tu.add_argument("--search", help="filter by service-label substring")
    tu.add_argument("--detail", action="store_true",
                    help="print the full dossier for each shown target (non-interactive view)")
    tu.add_argument("--list-limit", type=int, default=LIST_LIMIT,
                    help="max items per long list inside a dossier (0 = no cap)")
    tu.add_argument("-v", "--verbose", action="store_true", help="include detailed diagnostics")
    tu.set_defaults(func=_cmd_tui)

    g = sub.add_parser("graph", help="query the trust-boundary graph")
    g.add_argument("--report", default="./results/report.json", help="report.json to read")
    g.add_argument("--node", help="show what surrounds a service / binary / Mach service")
    g.add_argument("--path", nargs=2, metavar=("FROM", "TO"),
                   help="shortest routes between two entities")
    g.add_argument("--boundaries", action="store_true",
                   help="every non-root client naming a root daemon's Mach service")
    g.add_argument("--deputy", metavar="DAEMON",
                   help="deputy candidates for a daemon: clients that look up its "
                        "Mach service and hold a <label>.* entitlement")
    g.add_argument("--deputy-entitlement", action="append", metavar="ENT",
                   help="--deputy: gate on this entitlement key instead of the "
                        "<label>.* heuristic (repeatable)")
    g.add_argument("--depth", type=int, default=0, help="hops (default 1 for --node, 6 for --path)")
    g.add_argument("--edge", action="append",
                   help="restrict to an edge type (repeatable): PROVIDES, LOOKS_UP, LINKS_TO, ...")
    g.add_argument("--min-score", type=int, default=0, help="--boundaries: minimum provider score")
    g.add_argument("--validation", action="append",
                   choices=["NONE_OBSERVED", "WEAK", "MEDIUM", "STRONG"],
                   help="--boundaries: only providers with this validation grade (repeatable)")
    g.add_argument("--include-disabled", action="store_true",
                   help="--boundaries: include providers launchd would not load")
    g.add_argument("--max-paths", type=int, default=5)
    g.add_argument("--limit", type=int, default=60, help="max nodes / rows")
    g.add_argument("--format", choices=["text", "dot", "mermaid", "json"], default="text")
    g.add_argument("-out", "--output", help="write to a file (default: stdout)")
    g.add_argument("--verbose", action="store_true")
    g.set_defaults(func=_cmd_graph)

    h = sub.add_parser(
        "hunt",
        help="rank unexplored components by capability and exploitability evidence")
    h.add_argument("--report", default="./results/report.json", help="report.json to read")
    h.add_argument("--label", metavar="DAEMON",
                   help="single-target detailed brief (substring match)")
    h.add_argument("--class", dest="class_filter",
                   choices=["lpe", "rce", "dos", "cred", "all"],
                   help="sort by a single bug-bounty dimension")
    h.add_argument("--top", type=int, default=30, help="top N targets (default 30)")
    h.add_argument("--min-score", type=int, default=None,
                   help="minimum research-priority score")
    h.add_argument("--min-tbm-score", type=int, default=None,
                   help="minimum original TBM score")
    h.add_argument("--primitive", help="filter by candidate capability or proven primitive")
    h.add_argument("--maturity",
                   choices=["SINK_CANDIDATE", "REACHABLE_SINK", "CONTROLLED_SINK",
                            "PRIMITIVE", "IMPACT"])
    h.add_argument("--min-exploitability", type=int, default=None,
                   help="minimum exploitability-evidence score")
    h.add_argument("--proven-only", action="store_true",
                   help="only findings promoted to a proven primitive")
    h.add_argument("--confidence",
                   choices=["CONFIRMED", "HIGH", "MEDIUM", "LOW", "SPECULATIVE",
                            "CONFIRMED_FLOW", "STRONG_CANDIDATE", "POSSIBLE",
                            "INSUFFICIENT_EVIDENCE"])
    h.add_argument("--reachable-by",
                   choices=["LOCAL_USER", "SANDBOXED_PROCESS", "UNSANDBOXED_PROCESS",
                            "ENTITLED_PROCESS", "ROOT_ONLY", "SYSTEM_COMPONENT_ONLY", "UNKNOWN"])
    h.add_argument("--sink", help="filter by sink category")
    h.add_argument("--framework", help="filter by sensitive framework")
    h.add_argument("--validation",
                   choices=["NONE_OBSERVED", "WEAK", "CONDITIONAL", "MEDIUM", "STRONG", "UNKNOWN"])
    h.add_argument("--format", choices=["text", "json"], default="text")
    h.add_argument("-out", "--output", help="write to a file (default: stdout)")
    h.add_argument("--verbose", action="store_true")
    h.set_defaults(func=_cmd_hunt)

    x = sub.add_parser(
        "xref",
        help="find code references to a string in a Mach-O binary (RE helper)")
    x.add_argument("binary", help="Mach-O path (fat OK, use --arch to pick a slice)")
    x.add_argument("string", help="C string (or substring) to cross-reference")
    x.add_argument("--arch", default=None,
                   help="slice of a fat binary (arm64e, arm64, x86_64)")
    x.add_argument("--context", type=int, default=16,
                   help="disassembly lines around each reference (default 16)")
    x.add_argument("--max-refs", type=int, default=20,
                   help="stop after this many references (default 20)")
    x.add_argument("--format", choices=["text", "json"], default="text")
    x.add_argument("-out", "--output", help="write to a file (default: stdout)")
    x.add_argument("--verbose", action="store_true")
    x.set_defaults(func=_cmd_xref)

    e = sub.add_parser(
        "entowners",
        help="list which scanned targets hold a given entitlement")
    e.add_argument("entitlement",
                   help="entitlement key (exact by default, substring with --contains)")
    e.add_argument("--contains", action="store_true",
                   help="treat ENTITLEMENT as a substring match")
    e.add_argument("--report", default="./results/report.json", help="report.json to read")
    e.add_argument("--format", choices=["text", "json"], default="text")
    e.add_argument("-out", "--output", help="write to a file (default: stdout)")
    e.add_argument("--verbose", action="store_true")
    e.set_defaults(func=_cmd_entowners)

    d = sub.add_parser(
        "deputy-all",
        help="map deputy chains (clients that hold a daemon's gate entitlement) across all daemons")
    d.add_argument("--report", default="./results/report.json", help="report.json to read")
    d.add_argument("--gate-entitlement", action="append", default=None, metavar="ENT",
                   help="gate on this key for ALL daemons (overrides the per-daemon heuristic)")
    d.add_argument("--max-depth", type=int, default=4,
                   help="max deputy-chain depth (default 4)")
    d.add_argument("--min-score", type=int, default=0,
                   help="only expand daemons with score >= N")
    d.add_argument("--root-only", action="store_true",
                   help="only report chains rooted at privileged (root) daemons")
    d.add_argument("--limit", type=int, default=60,
                   help="max roots printed in text mode (default 60)")
    d.add_argument("-out", "--output", metavar="PREFIX",
                   help="write <PREFIX>.md/.csv/.json instead of printing text")
    d.add_argument("--verbose", action="store_true")
    d.set_defaults(func=_cmd_deputy_all)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    output_destination = getattr(args, "output", None)
    machine_output = False
    if args.command == "scan":
        machine_output = output_destination is None and getattr(args, "json", False)
    if args.command in {"graph", "protocol", "hunt", "xref", "entowners", "deputy-all", "probe"}:
        machine_output = output_destination is None
    print_banner(args.command, stream=sys.stderr if machine_output else sys.stdout)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
