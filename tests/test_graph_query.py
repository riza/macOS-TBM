"""Tests for trust-boundary graph edges and queries."""

from __future__ import annotations

import unittest

import _paths  # noqa: F401

from graph.query import TrustGraph, to_dot, to_mermaid


def _graph():
    """A daemon, its Mach service, a user agent that looks it up, and a bystander."""
    return {
        "nodes": [
            {"id": "service:root.daemon", "type": "LaunchService", "label": "root.daemon",
             "data": {"privileged": True, "enabled": True, "score": 100,
                      "validation": "NONE_OBSERVED", "run_as_user": "root"}},
            {"id": "exec:/usr/libexec/rootd", "type": "Executable", "label": "/usr/libexec/rootd",
             "data": {"privileged": True, "service": "root.daemon", "run_as_user": "root"}},
            {"id": "mach:com.example.root", "type": "MachService", "label": "com.example.root"},
            {"id": "service:user.agent", "type": "LaunchService", "label": "user.agent",
             "data": {"privileged": False, "enabled": True, "score": 40,
                      "validation": "STRONG", "run_as_user": "current-user"}},
            {"id": "exec:/usr/libexec/agent", "type": "Executable", "label": "/usr/libexec/agent",
             "data": {"privileged": False, "service": "user.agent", "run_as_user": "current-user"}},
            {"id": "service:other.daemon", "type": "LaunchService", "label": "other.daemon",
             "data": {"privileged": True, "enabled": True, "score": 90, "validation": "STRONG"}},
            {"id": "exec:/usr/libexec/otherd", "type": "Executable", "label": "/usr/libexec/otherd",
             "data": {"privileged": True, "service": "other.daemon"}},
        ],
        "edges": [
            {"source": "exec:/usr/libexec/rootd", "target": "service:root.daemon",
             "type": "LAUNCHED_BY", "label": "launched by", "data": {}},
            {"source": "service:root.daemon", "target": "mach:com.example.root",
             "type": "PROVIDES", "label": "provides", "data": {}},
            {"source": "exec:/usr/libexec/agent", "target": "service:user.agent",
             "type": "LAUNCHED_BY", "label": "launched by", "data": {}},
            {"source": "exec:/usr/libexec/agent", "target": "mach:com.example.root",
             "type": "LOOKS_UP", "label": "looks up", "data": {"evidence": "entitlement"}},
            {"source": "exec:/usr/libexec/otherd", "target": "service:other.daemon",
             "type": "LAUNCHED_BY", "label": "launched by", "data": {}},
            {"source": "exec:/usr/libexec/otherd", "target": "mach:com.example.root",
             "type": "LOOKS_UP", "label": "looks up", "data": {"evidence": "string"}},
        ],
    }


class TestResolve(unittest.TestCase):
    def setUp(self):
        self.g = TrustGraph(_graph())

    def test_exact_label_wins_over_substring(self):
        self.assertEqual(self.g.resolve("root.daemon"), ["service:root.daemon"])

    def test_substring_finds_candidates(self):
        self.assertIn("mach:com.example.root", self.g.resolve("com.example"))

    def test_unknown_term_resolves_to_nothing(self):
        self.assertEqual(self.g.resolve("no.such.thing"), [])


class TestNeighbourhood(unittest.TestCase):
    def setUp(self):
        self.g = TrustGraph(_graph())

    def test_one_hop_reaches_direct_neighbours_only(self):
        sub = self.g.neighbourhood("service:root.daemon", depth=1)
        self.assertEqual(set(sub.nodes) - {"service:root.daemon"},
                         {"exec:/usr/libexec/rootd", "mach:com.example.root"})

    def test_two_hops_reach_the_clients(self):
        sub = self.g.neighbourhood("service:root.daemon", depth=2)
        self.assertIn("exec:/usr/libexec/agent", sub.nodes)

    def test_edge_type_filter(self):
        sub = self.g.neighbourhood("service:root.daemon", depth=1, edge_types=["PROVIDES"])
        self.assertEqual(set(sub.nodes),
                         {"service:root.daemon", "mach:com.example.root"})

    def test_limit_caps_the_slice(self):
        sub = self.g.neighbourhood("service:root.daemon", depth=3, limit=2)
        self.assertLessEqual(len(sub.nodes), 2)


class TestPaths(unittest.TestCase):
    def setUp(self):
        self.g = TrustGraph(_graph())

    def test_client_reaches_provider_across_edge_directions(self):
        """PROVIDES and LOOKS_UP point at the service from opposite sides."""
        paths = self.g.shortest_paths("service:user.agent", "service:root.daemon")
        self.assertTrue(paths)
        hops = [node for node, _ in paths[0]]
        self.assertEqual(hops[0], "service:user.agent")
        self.assertEqual(hops[-1], "service:root.daemon")
        self.assertIn("mach:com.example.root", hops)

    def test_no_path_between_unconnected_nodes(self):
        g = TrustGraph({"nodes": [{"id": "a", "type": "X", "label": "a", "data": {}},
                                  {"id": "b", "type": "X", "label": "b", "data": {}}],
                        "edges": []})
        self.assertEqual(g.shortest_paths("a", "b"), [])

    def test_source_equals_target(self):
        self.assertEqual(len(self.g.shortest_paths("service:user.agent", "service:user.agent")), 1)


class TestBoundaries(unittest.TestCase):
    def setUp(self):
        self.g = TrustGraph(_graph())

    def test_only_unprivileged_clients_count_as_a_crossing(self):
        rows = self.g.boundary_crossings()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["client_service"], "user.agent")
        self.assertEqual(rows[0]["provider"], "root.daemon")
        self.assertEqual(rows[0]["evidence"], "entitlement")

    def test_min_score_filters_providers(self):
        self.assertEqual(self.g.boundary_crossings(min_score=101), [])

    def test_validation_filter(self):
        self.assertTrue(self.g.boundary_crossings(validation=["NONE_OBSERVED"]))
        self.assertEqual(self.g.boundary_crossings(validation=["STRONG"]), [])

    def test_disabled_providers_are_excluded_by_default(self):
        data = _graph()
        for node in data["nodes"]:
            if node["id"] == "service:root.daemon":
                node["data"]["enabled"] = False
        g = TrustGraph(data)
        self.assertEqual(g.boundary_crossings(), [])
        self.assertTrue(g.boundary_crossings(enabled_only=False))


def _deputy_graph():
    """A root daemon, a privileged deputy, and a bystander client.

    The deputy looks the daemon's Mach service up *and* holds a
    ``<label>.*`` entitlement (the ``com.apple.<name>.spi`` pattern Apple uses
    for server-side client gating). The bystander looks the service up but holds
    no gate entitlement.
    """
    return {
        "nodes": [
            {"id": "service:com.example.rootd", "type": "LaunchService",
             "label": "com.example.rootd",
             "data": {"privileged": True, "enabled": True, "score": 100,
                      "validation": "NONE_OBSERVED", "run_as_user": "root"}},
            {"id": "exec:/usr/libexec/rootd", "type": "Executable",
             "label": "/usr/libexec/rootd",
             "data": {"privileged": True, "service": "com.example.rootd",
                      "run_as_user": "root"}},
            {"id": "mach:com.example.rootd", "type": "MachService",
             "label": "com.example.rootd"},
            {"id": "exec:/usr/libexec/setupagent", "type": "Executable",
             "label": "/usr/libexec/setupagent",
             "data": {"privileged": False, "service": "com.example.setupagent",
                      "run_as_user": "current-user", "validation": "STRONG"}},
            {"id": "exec:/usr/libexec/bystander", "type": "Executable",
             "label": "/usr/libexec/bystander",
             "data": {"privileged": False, "service": "com.example.other",
                      "run_as_user": "current-user"}},
            {"id": "ent:com.example.rootd.spi", "type": "Entitlement",
             "label": "com.example.rootd.spi"},
            {"id": "ent:com.example.rootd.bridge", "type": "Entitlement",
             "label": "com.example.rootd.bridge"},
        ],
        "edges": [
            {"source": "exec:/usr/libexec/rootd", "target": "service:com.example.rootd",
             "type": "LAUNCHED_BY", "label": "launched by", "data": {}},
            {"source": "service:com.example.rootd", "target": "mach:com.example.rootd",
             "type": "PROVIDES", "label": "provides", "data": {}},
            {"source": "exec:/usr/libexec/setupagent", "target": "mach:com.example.rootd",
             "type": "LOOKS_UP", "label": "looks up", "data": {"evidence": "entitlement"}},
            {"source": "exec:/usr/libexec/setupagent", "target": "ent:com.example.rootd.spi",
             "type": "HAS_ENTITLEMENT", "label": "has entitlement", "data": {}},
            {"source": "exec:/usr/libexec/bystander", "target": "mach:com.example.rootd",
             "type": "LOOKS_UP", "label": "looks up", "data": {"evidence": "string"}},
            {"source": "exec:/usr/libexec/rootd", "target": "ent:com.example.rootd.bridge",
             "type": "HAS_ENTITLEMENT", "label": "has entitlement", "data": {}},
        ],
    }


class TestDeputies(unittest.TestCase):
    def setUp(self):
        self.g = TrustGraph(_deputy_graph())

    def test_default_gate_is_label_namespaced(self):
        rows = self.g.deputies("com.example.rootd")
        clients = [r["client"] for r in rows]
        self.assertEqual(clients, ["/usr/libexec/setupagent"])
        self.assertEqual(rows[0]["gate_entitlements"], ["com.example.rootd.spi"])

    def test_bystander_without_gate_entitlement_is_excluded(self):
        rows = self.g.deputies("com.example.rootd")
        self.assertNotIn("/usr/libexec/bystander", [r["client"] for r in rows])

    def test_explicit_gate_entitlements_override_the_heuristic(self):
        rows = self.g.deputies("com.example.rootd", gate_entitlements=["com.example.rootd.bridge"])
        self.assertEqual(rows, [])  # no *client* holds bridge

    def test_unprivileged_clients_are_reported(self):
        rows = self.g.deputies("com.example.rootd")
        self.assertTrue(rows)
        self.assertFalse(rows[0]["client_privileged"])
        self.assertEqual(rows[0]["client_validation"], "STRONG")

    def test_unknown_target_returns_empty(self):
        self.assertEqual(self.g.deputies("no.such.daemon"), [])


def _checked_deputy_graph():
    """A daemon that checks a client entitlement NOT under its own label.

    The daemon's ``checked_entitlements`` is ``com.example.gate.checked`` (via a
    CHECKED_ENTITLEMENT edge); a client holds it and looks the service up. The
    ``<label>.*`` heuristic would NOT match that key, so this pins that
    ``deputies()`` prefers the checked set over the namespace fallback.
    """
    return {
        "nodes": [
            {"id": "service:com.example.rootd", "type": "LaunchService",
             "label": "com.example.rootd",
             "data": {"privileged": True, "enabled": True, "score": 100,
                      "validation": "NONE_OBSERVED", "run_as_user": "root"}},
            {"id": "exec:/usr/libexec/rootd", "type": "Executable",
             "label": "/usr/libexec/rootd",
             "data": {"privileged": True, "service": "com.example.rootd"}},
            {"id": "mach:com.example.rootd", "type": "MachService",
             "label": "com.example.rootd"},
            {"id": "exec:/usr/libexec/checkedclient", "type": "Executable",
             "label": "/usr/libexec/checkedclient",
             "data": {"privileged": False, "service": "com.example.checkedclient",
                      "run_as_user": "current-user"}},
            {"id": "ent:com.example.gate.checked", "type": "Entitlement",
             "label": "com.example.gate.checked"},
        ],
        "edges": [
            {"source": "exec:/usr/libexec/rootd", "target": "service:com.example.rootd",
             "type": "LAUNCHED_BY", "label": "launched by", "data": {}},
            {"source": "service:com.example.rootd", "target": "mach:com.example.rootd",
             "type": "PROVIDES", "label": "provides", "data": {}},
            {"source": "service:com.example.rootd", "target": "ent:com.example.gate.checked",
             "type": "CHECKED_ENTITLEMENT", "label": "checks client entitlement",
             "data": {"evidence": "server-side-check"}},
            {"source": "exec:/usr/libexec/checkedclient", "target": "mach:com.example.rootd",
             "type": "LOOKS_UP", "label": "looks up", "data": {"evidence": "entitlement"}},
            {"source": "exec:/usr/libexec/checkedclient", "target": "ent:com.example.gate.checked",
             "type": "HAS_ENTITLEMENT", "label": "has entitlement", "data": {}},
        ],
    }


class TestDeputiesPreferCheckedEntitlements(unittest.TestCase):
    def setUp(self):
        self.g = TrustGraph(_checked_deputy_graph())

    def test_checked_entitlements_override_the_label_heuristic(self):
        rows = self.g.deputies("com.example.rootd")
        clients = [r["client"] for r in rows]
        self.assertEqual(clients, ["/usr/libexec/checkedclient"])
        self.assertEqual(rows[0]["gate_entitlements"], ["com.example.gate.checked"])

    def test_no_checked_entitlements_falls_back_to_heuristic(self):
        # Without the CHECKED_ENTITLEMENT edge, the checked key would not match
        # the <label>.* heuristic and no deputy would be reported.
        data = _checked_deputy_graph()
        data["edges"] = [e for e in data["edges"] if e["type"] != "CHECKED_ENTITLEMENT"]
        self.assertEqual(TrustGraph(data).deputies("com.example.rootd"), [])

    def test_explicit_gate_still_overrides_checked(self):
        rows = self.g.deputies("com.example.rootd",
                               gate_entitlements=["com.example.nonexistent"])
        self.assertEqual(rows, [])



class TestRendering(unittest.TestCase):
    def test_dot_and_mermaid_contain_every_node(self):
        g = TrustGraph(_graph())
        sub = g.neighbourhood("service:root.daemon", depth=2)
        dot, mermaid = to_dot(sub), to_mermaid(sub)
        self.assertTrue(dot.startswith("digraph"))
        self.assertTrue(mermaid.startswith("graph LR"))
        for node in sub.nodes.values():
            self.assertIn(node["label"], dot)


class TestClientEdges(unittest.TestCase):
    """The builder must not invent client relationships."""

    def test_declared_lookups_read_the_entitlement_values(self):
        from graph.model import _declared_lookups
        from types import SimpleNamespace
        cs = SimpleNamespace(entitlements={
            "com.apple.security.exception.mach-lookup.global-name": ["com.example.a", "com.example.b"],
        })
        self.assertEqual(_declared_lookups(cs), ["com.example.a", "com.example.b"])

    def test_no_lookup_edge_to_a_service_the_job_provides_itself(self):
        from graph.model import build_graph
        from types import SimpleNamespace
        svc = SimpleNamespace(
            label="self.looper", plist_path="/x.plist", mach_services=["com.example.self"],
            associated_executable="/usr/libexec/selfd", run_as="root", run_as_user="root",
            is_privileged=True, enabled=True, scope="system-daemon", sockets={},
        )
        exe = SimpleNamespace(
            codesign=SimpleNamespace(entitlements={
                "com.apple.security.exception.mach-lookup.global-name": ["com.example.self"]}),
            macho=SimpleNamespace(linked_libs=[], interesting_strings=["com.example.self"]),
        )
        target = SimpleNamespace(service=svc, executable=exe, score=10,
                                 sensitive_sinks=[], validation="NONE_OBSERVED")
        g = build_graph([target])
        self.assertEqual([e for e in g.edges if e.edge_type == "LOOKS_UP"], [])


if __name__ == "__main__":
    unittest.main()
