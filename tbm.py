#!/usr/bin/env python3
"""macOS-TBM (Trust Boundary Mapper) — read-only attack-surface research tool.

Usage:
    python3 tbm.py scan [--output ./results] [--json] [--html] [--graph] [--verbose]
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
from graph.exporters import export_dot, export_json, export_mermaid
from graph.model import build_graph
from models.executable import Executable
from reporting.export import export_report
from reporting.html_report import write_html_report
from reporting.json_report import build_report, write_json_report
from scanner import analyze_service, run_scan
from utils.commands import ResultCache


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


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


def _cmd_scan(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)
    outdir = args.output or "./results"

    def progress(done: int, total: int) -> None:
        if not args.verbose and total and sys.stdout.isatty():
            print(f"\r  analyzing executables: {done}/{total}", end="", flush=True)

    targets = run_scan(scope=args.scope, workers=args.workers, verbose=args.verbose, progress=progress)
    if progress:
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

    os.makedirs(outdir, exist_ok=True)

    want_json = args.json or not (args.html or args.graph)
    want_html = args.html or not (args.json or args.graph)
    want_graph = args.graph or not (args.json or args.html)

    if want_json:
        write_json_report(os.path.join(outdir, "report.json"), report)
        print(f"  report.json -> {outdir}")
    if want_html:
        # write_html_report slims the payload itself and uses the graph for counts
        write_html_report(os.path.join(outdir, "report.html"), report)
        print(f"  report.html -> {outdir}")
    if want_graph:
        with open(os.path.join(outdir, "graph.json"), "w", encoding="utf-8") as fh:
            fh.write(export_json(graph))
        with open(os.path.join(outdir, "graph.dot"), "w", encoding="utf-8") as fh:
            fh.write(export_dot(graph))
        with open(os.path.join(outdir, "graph.mmd"), "w", encoding="utf-8") as fh:
            fh.write(export_mermaid(graph))
        print(f"  graph.json / graph.dot / graph.mmd -> {outdir}")

    s = report["summary"]
    print(
        f"\nDone. {s['total_services']} services, {s['privileged_services']} privileged, "
        f"{s['mach_xpc_services']} Mach/XPC, {s['high_priority_targets']} high-priority."
    )
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
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan launchd services and map trust boundaries")
    s.add_argument("--output", default="./results", help="output directory (default ./results)")
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
    s.add_argument("--verbose", action="store_true")
    s.set_defaults(func=_cmd_scan)

    i = sub.add_parser("inspect", help="analyze a single Mach-O binary")
    i.add_argument("path")
    i.add_argument("--verbose", action="store_true")
    i.set_defaults(func=_cmd_inspect)

    sv = sub.add_parser("service", help="analyze launchd service(s) by label substring")
    sv.add_argument("label")
    sv.add_argument("--verbose", action="store_true")
    sv.set_defaults(func=_cmd_service)

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

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
