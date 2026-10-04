"""Querying the trust-boundary graph.

A whole-system graph is 8,000 nodes and tens of thousands of edges; nobody reads
that. Research asks narrow questions, and this module answers them against a
graph loaded from ``report.json``:

* **neighbourhood** — what surrounds one service, binary or Mach service,
* **paths** — how a client reaches a privileged provider,
* **boundaries** — every place a less-privileged client can look up a Mach
  service provided by a root daemon.

Traversal is undirected on purpose. ``PROVIDES`` points from the daemon to the
service and ``LOOKS_UP`` from the client at it, so the client→daemon route only
exists if the two are walked in opposite directions.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


@dataclass
class Subgraph:
    """A slice of the graph, with the node and edge objects it contains."""

    nodes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    root: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"root": self.root, "nodes": list(self.nodes.values()), "edges": self.edges}


class TrustGraph:
    """An indexed view over the ``graph`` section of a report."""

    def __init__(self, graph: Dict[str, Any]) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {n["id"]: n for n in graph.get("nodes") or []}
        self.edges: List[Dict[str, Any]] = list(graph.get("edges") or [])
        self._adj: Dict[str, List[Tuple[str, Dict[str, Any], bool]]] = {}
        for edge in self.edges:
            src, dst = edge.get("source"), edge.get("target")
            self._adj.setdefault(src, []).append((dst, edge, True))
            self._adj.setdefault(dst, []).append((src, edge, False))

    # -- lookup ------------------------------------------------------------
    def resolve(self, term: str, node_type: Optional[str] = None) -> List[str]:
        """Find node ids by exact id, exact label, then substring."""
        if term in self.nodes:
            return [term]
        candidates = [n for n in self.nodes.values()
                      if node_type is None or n.get("type") == node_type]
        exact = [n["id"] for n in candidates if n.get("label") == term]
        if exact:
            return exact
        lowered = term.lower()
        return sorted(n["id"] for n in candidates
                      if lowered in str(n.get("label", "")).lower() or lowered in n["id"].lower())

    def node(self, node_id: str) -> Dict[str, Any]:
        return self.nodes.get(node_id, {"id": node_id, "type": "?", "label": node_id, "data": {}})

    def neighbours(self, node_id: str, edge_types: Optional[Sequence[str]] = None):
        for other, edge, outgoing in self._adj.get(node_id, ()):
            if edge_types and edge.get("type") not in edge_types:
                continue
            yield other, edge, outgoing

    # -- queries -----------------------------------------------------------
    def neighbourhood(self, node_id: str, depth: int = 1,
                      edge_types: Optional[Sequence[str]] = None,
                      node_types: Optional[Sequence[str]] = None,
                      limit: int = 400) -> Subgraph:
        """Everything within *depth* hops of *node_id*."""
        sub = Subgraph(root=node_id)
        sub.nodes[node_id] = self.node(node_id)
        frontier = deque([(node_id, 0)])
        seen: Set[str] = {node_id}
        seen_edges: Set[int] = set()
        while frontier:
            current, dist = frontier.popleft()
            if dist >= depth:
                continue
            for other, edge, _ in self.neighbours(current, edge_types):
                if node_types and self.node(other).get("type") not in node_types:
                    continue
                if id(edge) not in seen_edges:
                    seen_edges.add(id(edge))
                    sub.edges.append(edge)
                if other not in seen:
                    seen.add(other)
                    sub.nodes[other] = self.node(other)
                    if len(sub.nodes) >= limit:
                        return sub
                    frontier.append((other, dist + 1))
        return sub

    def shortest_paths(self, source: str, target: str, max_paths: int = 5,
                       max_depth: int = 6) -> List[List[Tuple[str, Optional[Dict[str, Any]]]]]:
        """Up to *max_paths* shortest undirected routes from *source* to *target*.

        Each path is a list of ``(node_id, edge used to get here)`` pairs.
        """
        if source == target:
            return [[(source, None)]]
        queue: deque = deque([[(source, None)]])
        found: List[List[Tuple[str, Optional[Dict[str, Any]]]]] = []
        best_len: Optional[int] = None
        visited_at: Dict[str, int] = {source: 0}
        while queue:
            path = queue.popleft()
            current = path[-1][0]
            if best_len is not None and len(path) > best_len:
                break
            for other, edge, _ in self.neighbours(current):
                if any(other == step[0] for step in path):
                    continue
                depth = len(path)
                if other == target:
                    found.append(path + [(other, edge)])
                    best_len = len(path) + 1
                    if len(found) >= max_paths:
                        return found
                    continue
                if depth >= max_depth:
                    continue
                # Allow revisits at the same BFS depth so parallel routes survive.
                if visited_at.get(other, depth) < depth:
                    continue
                visited_at.setdefault(other, depth)
                queue.append(path + [(other, edge)])
        return found

    def boundary_crossings(self, min_score: int = 0, enabled_only: bool = True,
                           validation: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        """Every Mach service of a root daemon that a non-root client can look up.

        This is the shape the whole tool is pointed at: something less trusted
        naming an endpoint that something more trusted answers on.
        """
        # Which service provides which Mach endpoint.
        provider: Dict[str, str] = {}
        for edge in self.edges:
            if edge.get("type") == "PROVIDES":
                provider[edge["target"]] = edge["source"]

        crossings: List[Dict[str, Any]] = []
        for edge in self.edges:
            if edge.get("type") != "LOOKS_UP":
                continue
            mach_id = edge["target"]
            provider_id = provider.get(mach_id)
            if not provider_id:
                continue
            prov = self.node(provider_id)
            client = self.node(edge["source"])
            pdata, cdata = prov.get("data") or {}, client.get("data") or {}
            if not pdata.get("privileged"):
                continue
            if cdata.get("privileged"):
                continue  # root talking to root is not a boundary crossing
            if enabled_only and pdata.get("enabled") is False:
                continue
            if pdata.get("score", 0) < min_score:
                continue
            if validation and pdata.get("validation", "NONE_OBSERVED") not in validation:
                continue
            crossings.append({
                "mach_service": self.node(mach_id).get("label"),
                "provider": prov.get("label"),
                "provider_score": pdata.get("score", 0),
                "provider_validation": pdata.get("validation", "NONE_OBSERVED"),
                "client": client.get("label"),
                "client_service": cdata.get("service", ""),
                "client_run_as": cdata.get("run_as_user", "?"),
                "evidence": (edge.get("data") or {}).get("evidence", "?"),
                "edge_state": (edge.get("data") or {}).get(
                    "edge_state", "DECLARED_NOT_DEMONSTRATED"),
                "runtime_demonstrated": bool(
                    (edge.get("data") or {}).get("runtime_demonstrated", False)),
            })
        crossings.sort(key=lambda c: (-c["provider_score"], c["mach_service"], c["client"]))
        return crossings

    def deputies(self, target: str, gate_entitlements: Optional[Sequence[str]] = None
                 ) -> List[Dict[str, Any]]:
        """Deputy candidates for a target daemon.

        A *deputy* is a client that looks up the target's Mach service **and**
        holds an entitlement the target is expected to gate on. The default gate
        set is the target's own ``checked_entitlements`` (the keys it appears to
        check server-side on its clients, via ``CHECKED_ENTITLEMENT`` edges);
        when none were observed it falls back to every entitlement namespaced
        under the target's label (``<label>.*``) — the ``com.apple.<name>.spi``
        pattern Apple uses for server-side client checks. An explicit
        ``gate_entitlements`` list overrides both.

        This is identification, not exploitation: a deputy on the list still has
        to be reachable from a less-trusted client and to forward attacker input.

        Scope note: clients are drawn from ``LOOKS_UP`` edges, which only exist
        where a Mach-lookup exception names the service. Platform binaries that
        reach the service through a client framework *without* an explicit
        exception will not appear here (see ``LINKS_TO`` for the framework view).
        """
        ids = self.resolve(target, "LaunchService")
        if not ids:
            ids = self._provider_of(target)
        if not ids:
            return []
        svc_id = ids[0]
        svc = self.node(svc_id)
        label = svc.get("label") or svc_id

        mach_ids = {other for other, _e, _o in self.neighbours(svc_id, {"PROVIDES"})}

        if gate_entitlements is None:
            # Prefer the REAL gate: the entitlements the daemon checks on its
            # clients (CHECKED_ENTITLEMENT edges). Fall back to the <label>.*
            # heuristic only when nothing was observed.
            checked = self._checked_entitlements(svc_id)
            if checked:
                gate = checked
            else:
                prefix = label + "."
                gate = {n.get("label") for n in self.nodes.values()
                        if n.get("type") == "Entitlement"
                        and str(n.get("label", "")).startswith(prefix)}
        else:
            gate = set(gate_entitlements)

        # Evidence per (client -> mach) lookup edge, gathered once.
        lookup_evidence: Dict[Tuple[str, str], str] = {}
        clients: Set[str] = set()
        for edge in self.edges:
            if edge.get("type") == "LOOKS_UP" and edge.get("target") in mach_ids:
                clients.add(edge["source"])
                lookup_evidence[(edge["source"], edge["target"])] = \
                    (edge.get("data") or {}).get("evidence", "?")

        rows: List[Dict[str, Any]] = []
        for cli in sorted(clients):
            held = {edge.get("target", "")[len("ent:"):]
                    for _o, edge, _out in self.neighbours(cli, {"HAS_ENTITLEMENT"})}
            matched = sorted(held & gate)
            if not matched:
                continue
            cnode = self.node(cli)
            cdata = cnode.get("data") or {}
            evidence = next(iter(lookup_evidence.get((cli, m)) for m in mach_ids
                                 if (cli, m) in lookup_evidence), "?")
            rows.append({
                "client": cnode.get("label", cli),
                "client_service": cdata.get("service", ""),
                "client_run_as": cdata.get("run_as_user", "?"),
                "client_privileged": bool(cdata.get("privileged")),
                "client_validation": cdata.get("validation", "NONE_OBSERVED"),
                "gate_entitlements": matched,
                "lookup_evidence": evidence,
            })
        rows.sort(key=lambda r: (r["client_privileged"], r["client"]))
        return rows

    def _checked_entitlements(self, svc_id: str) -> Set[str]:
        """Entitlement keys a service checks on its clients (CHECKED_ENTITLEMENT)."""
        return {
            self.node(edge["target"]).get("label", "")
            for edge in self.edges
            if edge.get("type") == "CHECKED_ENTITLEMENT" and edge.get("source") == svc_id
        }

    def _provider_of(self, target: str) -> List[str]:
        """Resolve a Mach-service name (or node id) to its provider service."""
        mach_id = target if target.startswith("mach:") else f"mach:{target}"
        prov = [e.get("source") for e in self.edges
                if e.get("type") == "PROVIDES" and e.get("target") == mach_id]
        if not prov:
            mach = self.node(mach_id)
            label = mach.get("label")
            prov = [e.get("source") for e in self.edges
                    if e.get("type") == "PROVIDES"
                    and self.node(e.get("target")).get("label") == label]
        return prov[:1]


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

_SHAPES = {
    "LaunchService": ("box", "#ffb020"),
    "Executable": ("box3d", "#4fd6e0"),
    "MachService": ("ellipse", "#a98bff"),
    "Framework": ("note", "#8b98aa"),
    "PrivateFramework": ("note", "#ff6b5e"),
    "Dylib": ("note", "#8b98aa"),
    "Entitlement": ("hexagon", "#8fd14f"),
    "SecuritySubsystem": ("diamond", "#ff6b5e"),
}


def to_dot(sub: Subgraph, title: str = "trust boundary") -> str:
    out = [f'digraph "{title}" {{', '  rankdir=LR;', '  bgcolor="#0b0e13";',
           '  node [style=filled fillcolor="#161b22" fontcolor="#dfe6ef" '
           'color="#2b3441" fontname="Helvetica" fontsize=10];',
           '  edge [color="#5b6879" fontcolor="#8b98aa" fontname="Helvetica" fontsize=8];']
    for node in sub.nodes.values():
        shape, color = _SHAPES.get(node.get("type", ""), ("box", "#8b98aa"))
        penwidth = 2.5 if node["id"] == sub.root else 1.0
        label = str(node.get("label", node["id"])).replace('"', r"\"")
        out.append(f'  "{node["id"]}" [label="{label}" shape={shape} '
                   f'color="{color}" penwidth={penwidth}];')
    for edge in sub.edges:
        label = edge.get("type", "")
        evidence = (edge.get("data") or {}).get("evidence")
        if evidence:
            label += f" ({evidence})"
        out.append(f'  "{edge["source"]}" -> "{edge["target"]}" [label="{label}"];')
    out.append("}")
    return "\n".join(out)


def to_mermaid(sub: Subgraph) -> str:
    ids: Dict[str, str] = {}
    out = ["graph LR"]
    for i, node in enumerate(sub.nodes.values()):
        key = f"n{i}"
        ids[node["id"]] = key
        label = str(node.get("label", node["id"])).replace('"', "'")
        shape = ("([%s])" if node.get("type") == "MachService" else
                 "[%s]" if node.get("type") in ("LaunchService", "Executable") else "{{%s}}")
        out.append(f'  {key}{shape % label}')
    for edge in sub.edges:
        src, dst = ids.get(edge["source"]), ids.get(edge["target"])
        if not src or not dst:
            continue
        out.append(f'  {src} -->|{edge.get("type", "")}| {dst}')
    return "\n".join(out)


def to_text(graph: TrustGraph, sub: Subgraph) -> str:
    """A grouped, readable listing of a neighbourhood."""
    root = sub.root
    lines = []
    if root:
        node = graph.node(root)
        data = node.get("data") or {}
        detail = " ".join(f"{k}={v}" for k, v in data.items() if k in
                          ("run_as_user", "privileged", "enabled", "score", "validation"))
        lines.append(f"{node.get('type')}  {node.get('label')}")
        if detail:
            lines.append(f"  {detail}")
        lines.append("")
    groups: Dict[str, List[str]] = {}
    for edge in sub.edges:
        outgoing = edge["source"] == root
        other = edge["target"] if outgoing else edge["source"]
        arrow = "->" if outgoing else "<-"
        evidence = (edge.get("data") or {}).get("evidence")
        suffix = f"  ({evidence})" if evidence else ""
        node = graph.node(other)
        key = f"{arrow} {edge.get('type')}"
        groups.setdefault(key, []).append(f"{node.get('label')}{suffix}")
    for key in sorted(groups):
        items = sorted(set(groups[key]))
        lines.append(f"  {key}  ({len(items)})")
        for item in items[:40]:
            lines.append(f"      {item}")
        if len(items) > 40:
            lines.append(f"      ... +{len(items) - 40} more")
        lines.append("")
    return "\n".join(lines)


def paths_to_text(graph: TrustGraph, paths: Iterable[List[Tuple[str, Optional[Dict[str, Any]]]]]) -> str:
    lines = []
    for i, path in enumerate(paths, 1):
        lines.append(f"path {i}  ({len(path) - 1} hops)")
        previous: Optional[str] = None
        for node_id, edge in path:
            node = graph.node(node_id)
            if edge is None:
                lines.append(f"    {node.get('label')}   [{node.get('type')}]")
                previous = node_id
                continue
            # The arrow describes how the edge was walked from the previous hop,
            # so a client reaching a provider reads "-> LOOKS_UP" then
            # "<- PROVIDES".
            direction = "->" if edge["source"] == previous else "<-"
            previous = node_id
            evidence = (edge.get("data") or {}).get("evidence")
            suffix = f" ({evidence})" if evidence else ""
            lines.append(f"      {direction} {edge.get('type')}{suffix}")
            lines.append(f"    {node.get('label')}   [{node.get('type')}]")
        lines.append("")
    return "\n".join(lines) if lines else "no path found"
