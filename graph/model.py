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

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


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
                                f"declared lookup ({evidence})", {
                                    "evidence": evidence,
                                    "edge_state": "DECLARED_NOT_DEMONSTRATED",
                                    "declared": True,
                                    "runtime_demonstrated": False,
                                    "evidence_state": "DECLARED",
                                }))

        # Entitlements.
        if exe and exe.codesign:
            for ent_key in exe.codesign.entitlements:
                ent_id = f"ent:{ent_key}"
                g.add_node(Node(ent_id, "Entitlement", ent_key))
                if exe_id:
                    g.add_edge(Edge(exe_id, ent_id, "HAS_ENTITLEMENT", "has entitlement"))

        # Server-side entitlement checks: the daemon gates its clients on these
        # keys. Distinct from HAS_ENTITLEMENT — a checked key is one the daemon
        # queries on *others*, and it usually does not hold it itself.
        for key in getattr(t, "checked_entitlements", None) or []:
            ent_id = f"ent:{key}"
            g.add_node(Node(ent_id, "Entitlement", key))
            g.add_edge(Edge(svc_id, ent_id, "CHECKED_ENTITLEMENT",
                            "checks client entitlement", {"evidence": "server-side-check"}))

        # Sensitive subsystems.
        for sink in t.sensitive_sinks:
            subsys_id = f"subsystem:{sink}"
            g.add_node(Node(subsys_id, "SecuritySubsystem", sink))
            if exe_id:
                g.add_edge(Edge(exe_id, subsys_id, "ACCESSES_SUBSYSTEM", "accesses"))

        # Operation findings are distinct from the binary profile. Their edge
        # metadata carries proof state so unresolved paths never render like a
        # complete attack chain.
        for finding in getattr(t, "capability_findings", []) or []:
            op_id = f"operation:{finding.finding_id}"
            g.add_node(Node(op_id, "OperationFinding", finding.finding_id, {
                "candidate_capability": finding.candidate_capability,
                "maturity": finding.maturity_level,
                "proven_primitive": finding.proven_primitive,
                "research_priority_score": finding.research_priority_score,
                "exploitability_evidence_score": finding.exploitability_evidence_score,
                "confidence": finding.confidence,
            }))
            g.add_edge(Edge(svc_id, op_id, "HAS_OPERATION_FINDING", "operation finding", {
                "evidence_state": "INFERRED",
            }))
            source_id = f"source:{finding.finding_id}"
            source_label = finding.sources[0].api if finding.sources else "unresolved input source"
            g.add_node(Node(source_id, "OperationSource", source_label))
            g.add_edge(Edge(op_id, source_id, "HAS_INPUT_SOURCE", "input source", {
                "evidence_state": "INFERRED" if finding.sources else "UNRESOLVED",
            }))
            sink_id = f"opsink:{finding.finding_id}"
            g.add_node(Node(sink_id, "OperationSink", finding.sink_api, {
                "address": finding.sink_address,
                "controlled_arguments": finding.controlled_arguments,
            }))
            flow_state = next((edge["state"] for edge in finding.edge_states
                               if edge.get("from") == "source" and edge.get("to") == "sink"),
                              "UNRESOLVED")
            g.add_edge(Edge(source_id, sink_id, "OPERATION_DATAFLOW", "source to sink", {
                "evidence_state": flow_state,
            }))
            candidate_id = f"candidate:{finding.finding_id}"
            g.add_node(Node(candidate_id, "CandidateCapability", finding.candidate_capability))
            g.add_edge(Edge(sink_id, candidate_id, "INDICATES_CANDIDATE", "sink candidate", {
                "evidence_state": "PROVEN",
            }))
            post_id = f"post:{finding.finding_id}"
            g.add_node(Node(post_id, "PostCondition", finding.post_condition, {
                "confidence": finding.post_condition_confidence,
            }))
            g.add_edge(Edge(candidate_id, post_id, "MAY_CAUSE", "potential post-condition", {
                "evidence_state": ("PROVEN" if finding.maturity_level == "IMPACT" else "INFERRED"),
            }))
            if finding.proven_primitive:
                primitive_id = f"primitive:{finding.finding_id}"
                g.add_node(Node(primitive_id, "ProvenPrimitive", finding.proven_primitive))
                g.add_edge(Edge(candidate_id, primitive_id, "PROMOTED_TO_PRIMITIVE",
                                "promotion", {"evidence_state": "PROVEN"}))

            # Caller profiles and dispatcher predicates are separate evidence
            # axes from identity and authorization. Only profiles with recovered
            # reachability become edges; unresolved ones stay off the graph.
            for profile in getattr(finding, "caller_profiles", []) or []:
                if profile.get("entry_reachability") == "UNKNOWN":
                    continue
                profile_id = f"profile:{finding.finding_id}:{profile.get('profile')}"
                g.add_node(Node(profile_id, "CallerProfile", profile.get("profile", "UNKNOWN"), {
                    "entry_reachability": profile.get("entry_reachability"),
                    "mach_lookup": profile.get("mach_lookup"),
                    "authorization": profile.get("authorization"),
                    "declared_client_capability": list(
                        profile.get("declared_client_capability", [])),
                }))
                g.add_edge(Edge(profile_id, op_id, "MAY_INVOKE_OPERATION",
                                "caller profile to operation", {
                                    "evidence_state": "INFERRED",
                                    "authorization": profile.get("authorization"),
                                }))
            for path in getattr(finding, "policy_paths", []) or []:
                predicate_id = f"policy:{finding.finding_id}:{path.get('predicate')}"
                g.add_node(Node(predicate_id, "PolicyPredicate",
                                path.get("predicate", "UNKNOWN"), {
                                    "allowed_operation": path.get("allowed_operation"),
                                    "success_semantics": path.get("success_semantics"),
                                }))
                g.add_edge(Edge(op_id, predicate_id, "GATED_BY_PREDICATE",
                                "operation policy predicate", {
                                    "evidence_state": path.get("relationship", "UNRESOLVED"),
                                }))

        # Optional LPE hunting layer. Filesystem nodes describe the resource
        # side of the trust boundary separately from caller authorization.
        for finding in getattr(t, "lpe_findings", []) or []:
            lpe_id = f"lpe:{finding.finding_id}"
            g.add_node(Node(lpe_id, "LPEFinding", finding.finding_id, {
                "classes": list(finding.lpe_classes),
                "confidence": finding.confidence,
                "score": finding.score,
                "caller_validation": finding.caller_validation,
                "resource_validation": finding.resource_validation,
                "exploitability_confirmed": False,
            }))
            g.add_edge(Edge(svc_id, lpe_id, "HAS_LPE_FINDING", "LPE research candidate", {
                "evidence_state": "INFERRED",
            }))
            actor_id = "actor:local-user"
            g.add_node(Node(actor_id, "TrustBoundaryActor", "unprivileged local user", {
                "privileged": False,
            }))
            input_state = ("PROVEN" if finding.confidence == "CONFIRMED_FLOW"
                           else "INFERRED")
            g.add_edge(Edge(actor_id, lpe_id, "SUPPLIES_IPC_INPUT",
                            f"{finding.input_origin} argument: {finding.input_name}", {
                                "evidence_state": input_state,
                                "finding_id": finding.finding_id,
                            }))
            g.add_edge(Edge(lpe_id, svc_id, "CROSSES_TO_PRIVILEGED_SERVICE",
                            "privileged trust-boundary crossing", {
                                "evidence_state": input_state,
                            }))
            resource_key = finding.target if finding.target_sensitive else (
                finding.target_category or "unresolved")
            resource_digest = hashlib.sha1(resource_key.encode("utf-8")).hexdigest()[:12]
            fs_id = f"filesystem:{resource_digest}"
            g.add_node(Node(fs_id, "FilesystemResource", finding.target, {
                "category": finding.target_category,
                "sensitive": finding.target_sensitive,
                "resource_validation": finding.resource_validation,
            }))
            g.add_edge(Edge(svc_id, fs_id, "PERFORMS_FILESYSTEM_OPERATION",
                            finding.sink_api, {
                                "finding_id": finding.finding_id,
                                "sink_address": finding.sink_address,
                                "user_controlled": finding.user_controlled,
                                "evidence_state": input_state,
                            }))
            g.add_edge(Edge(lpe_id, fs_id, "TARGETS_FILESYSTEM_RESOURCE",
                            finding.operation, {
                                "evidence_state": ("PROVEN" if finding.target_sensitive
                                                   else "UNRESOLVED"),
                            }))

    return g
