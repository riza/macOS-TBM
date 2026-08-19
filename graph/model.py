"""Trust-boundary graph: nodes, edges, and the builder that assembles it.

The graph encodes relationships such as:

    Launch Service --PROVIDES--> Mach Service
    Executable    --LAUNCHED_BY--> Launch Service
    Executable    --LOOKS_UP--> Mach Service      (a client edge; see below)
    Executable    --LINKS_TO--> Framework
    Executable    --HAS_ENTITLEMENT--> Entitlement
    Executable    --ACCESSES_SUBSYSTEM--> Security Subsystem

``LOOKS_UP`` is the edge that makes the graph a *trust-boundary* graph: it points
from a would-be client at a service another job provides, and it is only drawn
where there is evidence for it:

* ``evidence=entitlement`` — the binary carries
  ``com.apple.security.exception.mach-lookup.global-name`` (or ``.local-name``)
  naming that service. Apple declared the relationship; it is authoritative.
* ``evidence=string`` — the service name appears verbatim in the binary, which
  is what a ``bootstrap_look_up`` / ``xpc_connection_create_mach_service`` call
  site looks like from the outside.

An earlier version drew ``CONNECTS_TO`` from every framework a job links to every
Mach service that *the same job* provides. That produced 59,671 edges of the form
"CloudTelemetry.framework connects to com.apple.security.syspolicy" purely
because syspolicyd links CloudTelemetry — a self-loop dressed up as a client
relationship. Those edges are gone.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from analyzers.sinks import SINK_LABELS


@dataclass
class Node:
    id: str
    node_type: str
    label: str
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "type": self.node_type, "label": self.label, "data": self.data}


@dataclass
class Edge:
    source: str
    target: str
    edge_type: str
    label: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.edge_type,
            "label": self.label,
            "data": self.data,
        }


class Graph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []

    def add_node(self, node: Node) -> None:
        self.nodes.setdefault(node.id, node)

    def __init_index(self) -> None:
        self._seen = {(e.source, e.target, e.edge_type) for e in self.edges}

    def add_edge(self, edge: Edge) -> None:
        # Indexed rather than scanned: the linear membership test made graph
        # assembly quadratic in the number of edges.
        if not hasattr(self, "_seen"):
            self.__init_index()
        key = (edge.source, edge.target, edge.edge_type)
        if key not in self._seen:
            self._seen.add(key)
            self.edges.append(edge)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }


def _framework_name(lib: str) -> Optional[str]:
    """Extract a framework/private-framework name from a linked library path."""
    if ".framework/" in lib:
        return lib.split(".framework/")[0].split("/")[-1] + ".framework"
    if lib.endswith(".framework"):
        return os.path.basename(lib)
    # dylibs -> use basename
    base = os.path.basename(lib)
    return base if base else None


def _framework_type(lib: str) -> str:
    if ".framework" in lib:
        return "PrivateFramework" if "PrivateFrameworks" in lib else "Framework"
    return "Dylib"


# Entitlements whose *values* name the Mach services a process may look up.
_MACH_LOOKUP_ENTITLEMENTS = (
    "com.apple.security.exception.mach-lookup.global-name",
    "com.apple.security.exception.mach-lookup.local-name",
)


def _declared_lookups(codesign) -> List[str]:
    """Mach service names a binary is entitled to look up."""
    names: List[str] = []
    if not codesign:
        return names
    for key in _MACH_LOOKUP_ENTITLEMENTS:
        value = (codesign.entitlements or {}).get(key)
        if isinstance(value, list):
            names += [str(v) for v in value]
        elif isinstance(value, str):
            names.append(value)
    return names


def build_graph(targets: List[Any]) -> Graph:
    """Assemble the trust-boundary graph from a list of analyzed targets."""
    g = Graph()

    # Every Mach service name in the system, so a client edge can only point at
    # a service that actually exists.
    known_mach = {name for t in targets for name in (t.service.mach_services or [])}

    for t in targets:
        svc = t.service
        exe = t.executable
        exe_path = svc.associated_executable

        # Service node.
        svc_id = f"service:{svc.label}"
        run_as = svc.run_as.value if hasattr(svc.run_as, "value") else str(svc.run_as)
        enabled = getattr(svc, "enabled", True)
        g.add_node(Node(svc_id, "LaunchService", svc.label, {
            "run_as": run_as,
            "run_as_user": svc.run_as_user or run_as,
            "privileged": svc.is_privileged,
            "enabled": enabled,
            "scope": svc.scope.value if hasattr(svc.scope, "value") else str(svc.scope),
            "score": t.score,
            "validation": getattr(t, "validation", "NONE_OBSERVED"),
        }))

        # Executable node. It carries the privilege it runs with, so a query can
        # ask which side of a trust boundary a node sits on.
        exe_id = None
        if exe_path:
            exe_id = f"exec:{exe_path}"
            g.add_node(Node(exe_id, "Executable", exe_path, {
                "run_as_user": svc.run_as_user or run_as,
                "privileged": svc.is_privileged,
                "service": svc.label,
            }))
            g.add_edge(Edge(exe_id, svc_id, "LAUNCHED_BY", "launched by"))

        # Mach services.
        for name in svc.mach_services:
            mach_id = f"mach:{name}"
            g.add_node(Node(mach_id, "MachService", name))
            g.add_edge(Edge(svc_id, mach_id, "PROVIDES", "provides"))

        # Linked frameworks.
        macho = exe.macho if exe else None
        libs = macho.linked_libs if macho else []
        for lib in libs:
            fw_name = _framework_name(lib)
            if not fw_name:
                continue
            fw_id = f"fw:{fw_name}"
            g.add_node(Node(fw_id, _framework_type(lib), fw_name))
            if exe_id:
                g.add_edge(Edge(exe_id, fw_id, "LINKS_TO", "links to"))

        # Client edges, drawn only where there is evidence and never to a service
        # the job provides itself.
        if exe_id:
            own = set(svc.mach_services or [])
            declared = set(_declared_lookups(exe.codesign if exe else None))
            named = {s for s in (macho.interesting_strings if macho else []) if s in known_mach}
            for name in sorted(declared | named):
                if name in own or name not in known_mach:
                    continue
                evidence = "entitlement" if name in declared else "string"
                g.add_edge(Edge(exe_id, f"mach:{name}", "LOOKS_UP",
                                f"looks up ({evidence})", {"evidence": evidence}))

        # Entitlements.
        if exe and exe.codesign:
            for ent_key in exe.codesign.entitlements:
                ent_id = f"ent:{ent_key}"
                g.add_node(Node(ent_id, "Entitlement", ent_key))
                if exe_id:
                    g.add_edge(Edge(exe_id, ent_id, "HAS_ENTITLEMENT", "has entitlement"))

        # Sensitive subsystems.
        for sink in t.sensitive_sinks:
            subsys_id = f"subsystem:{sink}"
            g.add_node(Node(subsys_id, "SecuritySubsystem", sink))
            if exe_id:
                g.add_edge(Edge(exe_id, subsys_id, "ACCESSES_SUBSYSTEM", "accesses"))

    return g
