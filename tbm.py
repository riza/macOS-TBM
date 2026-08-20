#!/usr/bin/env python3
"""macOS-TBM (Trust Boundary Mapper) — read-only attack-surface research tool.

Usage:
    python3 tbm.py scan [--output ./results] [--json] [--html] [--graph] [--verbose]
    python3 tbm.py tui [--report ./results/report.json]
    python3 tbm.py inspect /usr/libexec/exampled
    python3 tbm.py service com.apple.example

Static/read-only analysis only. The tool maps attack surface; it does NOT
determine exploitability. Absence of a static security signal is never a claim
of a vulnerability.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import List, Optional

from collectors import discover_services, inspect_codesign, inspect_macho
from app_info import version_string
from hunt import format_single, format_text, score_report
from graph.exporters import export_dot, export_json, export_mermaid
from graph.query import (
    TrustGraph,
    paths_to_text,
    to_dot,
    to_mermaid,
    to_text,
)
from graph.model import build_graph
from models.executable import Executable
from reporting.export import export_report
from reporting.html_report import write_html_report
from reporting.json_report import build_report, write_json_report
from scanner import analyze_service, run_scan
from ui import (LIST_LIMIT, ScanProgress, configure_logging, print_banner,
                render_scan_cli, render_scan_result, render_tui, run_tui_app)
from utils.commands import ResultCache, run
from utils.jsonio import dumps as json_dumps


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
        out = [t for t in out if t.score >= args.min_score]
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
            progress=progress_callback,
        )
    if not stdout_output:
        print()

    targets = _apply_filters(targets, args)
    graph = build_graph(targets)
    filter_meta = {
        "scope": args.scope,
        "min_score": args.min_score,
        "privileged_only": args.privileged_only,
        "mach_only": args.mach_only,
        "entitlement": args.entitlement,
        "limit": args.limit,
    }
    report = build_report(targets, graph, meta={"scope": args.scope, "filters": filter_meta})

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
    exe.codesign = inspect_codesign(path, cache)

    print(f"=== inspect {path} ===")
    mo = exe.macho
    cs = exe.codesign
    if mo:
        print(f"  Mach-O: {mo.is_macho}  fat: {mo.is_fat}  archs: {', '.join(mo.architectures) or '-'}")
        print(f"  linked libs ({len(mo.linked_libs)}):")
        for l in mo.linked_libs[:30]:
            print(f"    {l}")
        print(f"  imported symbols: {len(mo.imported_symbols)}  exported: {len(mo.exported_symbols)}")
        print(f"  objc classes: {len(mo.objc_classes)}  rpaths: {len(mo.rpaths)}")
        if mo.interesting_strings:
            print(f"  interesting strings ({len(mo.interesting_strings)}):")
            for s in mo.interesting_strings[:30]:
                print(f"    {s}")
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


def _cmd_probe(args: argparse.Namespace) -> int:
    """ACTIVE probe: connect to exposed Mach services as an unprivileged client.

    This is the one non-read-only subcommand. Everything else inspects; this
    connects and sends real (empty / one-key) XPC messages to classify which
    root services an unprivileged process can actually reach.
    """
    _setup_logging(args.verbose)
    if not os.path.exists(args.report):
        print(f"no report at {args.report} — run 'tbm scan' first, or pass --report", file=sys.stderr)
        return 2
    with open(args.report, "r", encoding="utf-8") as fh:
        report = json.load(fh)

    from probes import format_json, format_text, run_probe, services_from_report
    from probes.xpc import CtypesXPCBackend, XPCUnavailable, launchctl_liveness

    services = services_from_report(report, only=args.service or None)
    if not services:
        where = f" matching {args.service}" if args.service else ""
        print(f"no root/system Mach services{where} in {args.report}", file=sys.stderr)
        return 1

    try:
        backend = CtypesXPCBackend()
    except XPCUnavailable as exc:
        print(f"XPC is unavailable here ({exc}); probe needs macOS.", file=sys.stderr)
        return 3

    liveness = launchctl_liveness(run)
    rows = run_probe(services, backend, timeout=args.timeout, limit=args.limit,
                     liveness=liveness)

    output = format_json(rows) if args.format == "json" else format_text(rows)
    _write_output(output, args.output)

    # ctypes + libdispatch can crash during interpreter teardown (a trailing
    # event delivered to a torn-down callback). The work is done and flushed, so
    # exit hard to guarantee a clean status instead of a teardown-time SIGSEGV.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


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
        for m in matches:
            print(format_single(m))
        return 0

    # --class: sort by a single dimension
    if getattr(args, "class_filter", None):
        cls = args.class_filter
        if cls == "all":
            pass  # keep total sort
        else:
            results.sort(key=lambda r: getattr(r, cls, 0), reverse=True)

    top = getattr(args, "top", 30)
    if getattr(args, "min_score", None) is not None:
        results = [r for r in results if r.total >= args.min_score]
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
            }
            for r in results[:top]
        ]
        print(json_dumps(payload))
        return 0

    # text output
    clsinfo = f"  class filter: --class {args.class_filter}" if getattr(args, "class_filter", None) else ""
    print(f"{clsinfo}")
    print(format_text(results, top=top))
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


def _cmd_clientgen(args: argparse.Namespace) -> int:
    """Emit a compilable Objective-C NSXPC client from an extracted protocol."""
    _setup_logging(args.verbose)
    from collectors.clientgen import generate_main_m

    if not os.path.exists(args.protocol):
        print(f"no protocol file at {args.protocol} — run 'tbm protocol' first", file=sys.stderr)
        return 2
    with open(args.protocol, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    mach_service = args.mach_service or data.get("mach_service")
    if not mach_service:
        print("no Mach service name: pass --mach-service or extract via a service label",
              file=sys.stderr)
        return 2

    protocols = data.get("protocols") or []
    if args.protocol_name:
        protocols = [p for p in protocols if p.get("name") == args.protocol_name]
        if not protocols:
            print(f"no protocol named {args.protocol_name!r}", file=sys.stderr)
            return 1
    if not protocols:
        print("the protocol file carries no protocols", file=sys.stderr)
        return 1

    try:
        source = generate_main_m(protocols[0], mach_service, args.selector)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _write_output(source.rstrip("\n"), args.output)
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
            exe.codesign = inspect_codesign(exe.path, cache)
        target = analyze_service(svc, exe)
        _print_target(target)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tbm",
        description="macOS-TBM — static, read-only trust-boundary and attack-surface mapper",
    )
    p.add_argument("--version", action="version", version=version_string())
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan launchd services and map trust boundaries")
    s.add_argument("-out", "--output", default=None,
                   help=f"output directory (default: {DEFAULT_OUTDIR})")
    s.add_argument("--json", action="store_true", help="emit report.json only")
    s.add_argument("--html", action="store_true", help="emit report.html only")
    s.add_argument("--graph", action="store_true", help="emit graph.json/.dot/.mmd only")
    s.add_argument("--scope", choices=["all", "daemons", "agents"], default="all")
    s.add_argument("--workers", type=int, default=8, help="parallel analysis workers")
    s.add_argument("--min-score", type=int, default=None, help="only targets with score >= N")
    s.add_argument("--privileged-only", action="store_true", help="only root/system services")
    s.add_argument("--mach-only", action="store_true", help="only Mach/XPC-exposing services")
    s.add_argument("--entitlement", default=None, help="filter by entitlement substring")
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

    cg = sub.add_parser(
        "clientgen",
        help="generate a compilable Objective-C NSXPC client from an extracted protocol")
    cg.add_argument("protocol", help="protocol JSON written by 'tbm protocol --format json'")
    cg.add_argument("--mach-service", help="Mach service name (overrides the extracted one)")
    cg.add_argument("--protocol-name", help="which protocol to generate (default first)")
    cg.add_argument("--selector", help="method to call (default: first method)")
    cg.add_argument("-out", "--output", default=None,
                    help="write main.m here (default: stdout)")
    cg.add_argument("--verbose", action="store_true")
    cg.set_defaults(func=_cmd_clientgen)

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

    pr = sub.add_parser(
        "probe",
        help="ACTIVE: connect to exposed Mach services as an unprivileged client")
    pr.add_argument("--report", default="./results/report.json", help="report.json to read")
    pr.add_argument("--service", action="append", metavar="LABEL",
                    help="probe only providers whose label contains LABEL (repeatable)")
    pr.add_argument("--limit", type=int, default=None, help="cap number of services probed")
    pr.add_argument("--timeout", type=float, default=3.0,
                    help="seconds to wait per sub-probe (default 3)")
    pr.add_argument("--format", choices=["text", "json"], default="text")
    pr.add_argument("-out", "--output", help="write to a file (default: stdout)")
    pr.add_argument("--verbose", action="store_true")
    pr.set_defaults(func=_cmd_probe)

    h = sub.add_parser(
        "hunt",
        help="score targets in a report for bug-bounty signals (LPE/RCE/DOS/CRED)")
    h.add_argument("--report", default="./results/report.json", help="report.json to read")
    h.add_argument("--label", metavar="DAEMON",
                   help="single-target detailed brief (substring match)")
    h.add_argument("--class", dest="class_filter",
                   choices=["lpe", "rce", "dos", "cred", "all"],
                   help="sort by a single bug-bounty dimension")
    h.add_argument("--top", type=int, default=30, help="top N targets (default 30)")
    h.add_argument("--min-score", type=int, default=None,
                   help="minimum total bug-bounty score")
    h.add_argument("--min-tbm-score", type=int, default=None,
                   help="minimum original TBM score")
    h.add_argument("--format", choices=["text", "json"], default="text")
    h.add_argument("-out", "--output", help="write to a file (default: stdout)")
    h.add_argument("--verbose", action="store_true")
    h.set_defaults(func=_cmd_hunt)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    output_destination = getattr(args, "output", None)
    machine_output = False
    if args.command == "scan":
        machine_output = output_destination is None and getattr(args, "json", False)
    if args.command in {"graph", "probe", "protocol", "clientgen", "hunt"}:
        machine_output = output_destination is None
    print_banner(args.command, stream=sys.stderr if machine_output else sys.stdout)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
