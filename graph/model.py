"""Trust-boundary graph: nodes, edges, and the builder that assembles it.

The graph encodes relationships such as:

    Launch Service --PROVIDES--> Mach Service
    Executable    --LINKS_TO--> Framework
    Framework     --CONNECTS_TO--> Mach Service
    Executable    --HAS_ENTITLEMENT--> Entitlement
    Executable    --ACCESSES_SUBSYSTEM--> Security Subsystem
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.edge_type,
            "label": self.label,
        }


class Graph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []

    def add_node(self, node: Node) -> None:
        self.nodes.setdefault(node.id, node)

    def add_edge(self, edge: Edge) -> None:
        key = (edge.source, edge.target, edge.edge_type)
        if not any((e.source, e.target, e.edge_type) == key for e in self.edges):
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


def build_graph(targets: List[Any]) -> Graph:
    """Assemble the trust-boundary graph from a list of analyzed targets."""
    g = Graph()

    for t in targets:
        svc = t.service
        exe = t.executable
        exe_path = svc.associated_executable

        # Service node.
        svc_id = f"service:{svc.label}"
        run_as = svc.run_as.value if hasattr(svc.run_as, "value") else str(svc.run_as)
        g.add_node(Node(svc_id, "LaunchService", svc.label, {"run_as": run_as, "privileged": svc.is_privileged}))

        # Executable node.
        exe_id = None
        if exe_path:
            exe_id = f"exec:{exe_path}"
            g.add_node(Node(exe_id, "Executable", exe_path))
            g.add_edge(Edge(exe_id, svc_id, "LAUNCHED_BY", "launched by"))

        # Mach services.
        for name in svc.mach_services:
            mach_id = f"mach:{name}"
            g.add_node(Node(mach_id, "MachService", name))
            g.add_edge(Edge(svc_id, mach_id, "PROVIDES", "provides"))

        # Linked frameworks + CONNECTS_TO mach services.
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
            # Correlation: framework -> mach service (client relationship).
            for name in svc.mach_services:
                g.add_edge(Edge(fw_id, f"mach:{name}", "CONNECTS_TO", "connects to"))

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
