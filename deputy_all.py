#!/usr/bin/env python3
"""Extract the full deputy-chain map for every LaunchService in report.json.

A *deputy* is a client that looks up a daemon's Mach service and holds an
entitlement the daemon is expected to gate on. This walks every LaunchService,
runs ``TrustGraph.deputies()`` for it, then recursively expands any deputy that
is itself a daemon (privileged or not), producing chains of the form:

    <privileged daemon>  ->  <deputy daemon>  ->  ...  ->  <leaf client>

Chains that end at an *unprivileged* client are the ones an attacker can
actually ride (non-root -> deputy -> root sink).

Read-only: it loads an existing report and writes nothing back to the system.
"""

import argparse
import json
import os
import sys
from collections import defaultdict

from graph.query import TrustGraph

DEFAULT_REPORT = os.path.join("results", "report.json")


def load_graph(path: str) -> TrustGraph:
    with open(path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    graph = report.get("graph")
    if not graph:
        raise SystemExit(f"{path} carries no graph (run 'tbm scan' first)")
    return TrustGraph(graph)


def service_label(tg: TrustGraph, node_id: str) -> str:
    return tg.node(node_id).get("label", node_id)


def service_data(tg: TrustGraph, node_id: str) -> dict:
    return tg.node(node_id).get("data") or {}


def service_of_executable(tg: TrustGraph, exe_id: str):
    """The LaunchService that launches this executable (via LAUNCHED_BY)."""
    for other, _edge, _out in tg.neighbours(exe_id, {"LAUNCHED_BY"}):
        if tg.node(other).get("type") == "LaunchService":
            return other
    return None


def expand(tg: TrustGraph, svc_id: str, gate: list | None, chain: list,
           depth: int, max_depth: int, seen: set, out):
    """Recursively follow deputies; out collects chains starting at chain."""
    rows = tg.deputies(service_label(tg, svc_id), gate_entitlements=gate)
    for r in rows:
        client_id = None
        for cand in tg.resolve(r["client"]):
            if tg.nodes[cand].get("label") == r["client"]:
                client_id = cand
                break
        step = {
            "client": r["client"],
            "client_id": client_id,
            "client_service": r["client_service"],
            "client_run_as": r["client_run_as"],
            "client_privileged": r["client_privileged"],
            "client_validation": r["client_validation"],
            "gate_entitlements": r["gate_entitlements"],
            "lookup_evidence": r["lookup_evidence"],
        }
        key = tuple(x["client"] for x in chain) + (r["client"],)
        if key in seen:
            continue
        seen.add(key)
        new_chain = chain + [step]
        if r["client_privileged"] and depth < max_depth and client_id:
            dep_svc = service_of_executable(tg, client_id)
            if dep_svc:
                expand(tg, dep_svc, gate, new_chain, depth + 1, max_depth, seen, out)
        out.append(new_chain)


def build(tg: TrustGraph, gate: list | None = None, max_depth: int = 4,
          min_score: int = 0, root_only: bool = False) -> dict:
    """Walk every LaunchService and return chains indexed by root label."""
    chains = []
    seen: set = set()
    for nid, node in tg.nodes.items():
        if node.get("type") != "LaunchService":
            continue
        data = service_data(tg, nid)
        if min_score and data.get("score", 0) < min_score:
            continue
        if root_only and not data.get("privileged"):
            continue
        root_step = {
            "client": service_label(tg, nid),
            "client_id": nid,
            "client_service": data.get("service", ""),
            "client_run_as": data.get("run_as_user", "?"),
            "client_privileged": bool(data.get("privileged")),
            "client_validation": data.get("validation", "NONE_OBSERVED"),
            "gate_entitlements": [],
            "lookup_evidence": "root",
        }
        expand(tg, nid, gate, [root_step], 0, max_depth, seen, chains)

    by_root = defaultdict(list)
    for c in chains:
        if c:
            by_root[c[0]["client"]].append(c)
    return dict(by_root)


def counts(by_root: dict) -> dict:
    return {
        "roots": len(by_root),
        "chains": sum(len(v) for v in by_root.values()),
        "unprivileged_leaves": sum(1 for cs in by_root.values() for c in cs
                                   if not c[-1]["client_privileged"]),
    }


def render_text(by_root: dict, limit: int = 60) -> str:
    """A terminal rendering of the chain map, capped at ``limit`` roots."""
    c = counts(by_root)
    lines = [f"Deputy chains — {c['roots']} roots, {c['chains']} chains, "
             f"{c['unprivileged_leaves']} end at an unprivileged client"]
    if not by_root:
        lines.append("no deputy chains found")
        return "\n".join(lines)
    lines.append("")
    lines.append("Chain = daemon -> client holding the gate entitlement; expanded while "
                 "the deputy is itself a daemon. [UNPRIV] marks a non-root leaf.")
    lines.append("")
    shown = sorted(by_root)[:limit]
    for root in shown:
        chains_for_root = sorted(by_root[root],
                                 key=lambda ch: (ch[-1]["client_privileged"], ch[-1]["client"]))
        lines.append(root)
        for ch in chains_for_root:
            leaf = ch[-1]
            marker = "priv" if leaf["client_privileged"] else "UNPRIV"
            lines.append(f"  [{marker}] {' > '.join(x['client'] for x in ch)}")
        lines.append("")
    if len(by_root) > len(shown):
        lines.append(f"... {len(by_root) - len(shown)} more root(s) withheld (raise --limit)")
    return "\n".join(lines).rstrip()


def write_outputs(by_root: dict, out_prefix: str) -> dict:
    """Write ``<out_prefix>.json/.csv/.md``; return the counts written."""
    parent = os.path.dirname(os.path.abspath(out_prefix))
    os.makedirs(parent, exist_ok=True)

    with open(out_prefix + ".json", "w", encoding="utf-8") as fh:
        json.dump(by_root, fh, indent=1)

    with open(out_prefix + ".csv", "w", encoding="utf-8") as fh:
        fh.write("root,path,leaf_privileged,leaf_run_as,leaf_validation,"
                 "gate_entitlements,lookup_evidence\n")
        for root, cs in by_root.items():
            for c in cs:
                leaf = c[-1]
                fh.write(f"{root},{' > '.join(x['client'] for x in c)},"
                         f"{'yes' if leaf['client_privileged'] else 'no'},"
                         f"{leaf['client_run_as']},{leaf['client_validation']},"
                         f"{'|'.join(leaf['gate_entitlements'])},{leaf['lookup_evidence']}\n")

    with open(out_prefix + ".md", "w", encoding="utf-8") as fh:
        fh.write(f"# Deputy chains (all daemons) — {len(by_root)} roots, "
                 f"{sum(len(v) for v in by_root.values())} chains\n\n")
        fh.write("Chain = daemon -> client-with-gate-entitlement; expanded while the "
                 "deputy is itself a daemon.\n\n")
        for root in sorted(by_root):
            chains_for_root = sorted(by_root[root],
                                     key=lambda ch: (ch[-1]["client_privileged"], ch[-1]["client"]))
            fh.write(f"## {root}\n")
            for c in chains_for_root:
                leaf = c[-1]
                marker = "**UNPRIV**" if not leaf["client_privileged"] else "priv"
                fh.write(f"- {marker} {' > '.join(x['client'] for x in c)}\n")
                fh.write(f"    leaf: {leaf['client_run_as']} "
                         f"validation={leaf['client_validation']} "
                         f"gate={','.join(leaf['gate_entitlements'])} "
                         f"lookup={leaf['lookup_evidence']}\n")
            fh.write("\n")

    return counts(by_root)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", default=DEFAULT_REPORT, help="report.json to read")
    ap.add_argument("--out", default=None, metavar="PREFIX",
                    help="write <PREFIX>.md/.csv/.json instead of printing text")
    ap.add_argument("--gate-entitlement", action="append", default=None,
                    metavar="ENT", help="gate on this key for ALL daemons (overrides heuristic)")
    ap.add_argument("--max-depth", type=int, default=4,
                    help="max deputy-chain depth (default 4)")
    ap.add_argument("--min-score", type=int, default=0,
                    help="only expand daemons with score >= N")
    ap.add_argument("--root-only", action="store_true",
                    help="only report chains rooted at privileged (root) daemons")
    ap.add_argument("--limit", type=int, default=60,
                    help="max roots printed in text mode (default 60)")
    args = ap.parse_args()

    tg = load_graph(args.report)
    by_root = build(tg, args.gate_entitlement, args.max_depth, args.min_score, args.root_only)
    c = counts(by_root)
    if args.out:
        write_outputs(by_root, args.out)
        print(f"deputy-all: {c['roots']} roots, {c['chains']} chains, "
              f"{c['unprivileged_leaves']} end at an unprivileged client -> "
              f"{args.out}.md/.csv/.json")
    else:
        print(render_text(by_root, args.limit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
