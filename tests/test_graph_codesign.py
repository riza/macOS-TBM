"""Tests for graph building and exporters, and codesign XML extraction."""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace

import _paths  # noqa: F401

from collectors.codesign import _extract_entitlements
from graph.exporters import export_dot, export_json, export_mermaid
from graph.model import Graph, build_graph


def _target(label="t", mach_services=(), libs=(), entitlements=(), sinks=(), privileged=False,
            strings=(), executable="/usr/libexec/x"):
    svc = SimpleNamespace(
        label=label, associated_executable=executable,
        mach_services=list(mach_services), run_as="root" if privileged else "user",
        run_as_user="root" if privileged else "current-user",
        is_privileged=privileged, sockets={}, enabled=True, scope="system-daemon",
    )
    macho = SimpleNamespace(linked_libs=list(libs), interesting_strings=list(strings))
    codesign = SimpleNamespace(entitlements={e: True for e in entitlements})
    exe = SimpleNamespace(macho=macho, codesign=codesign)
    return SimpleNamespace(service=svc, executable=exe, sensitive_sinks=list(sinks),
                           score=10, validation="NONE_OBSERVED")


class TestGraph(unittest.TestCase):
    def test_build_graph_nodes_and_edges(self):
        t = _target(
            mach_services=["com.apple.demo"],
            libs=["/System/Library/Frameworks/Security.framework/Versions/A/Security"],
            entitlements=["com.apple.private.foo"],
            sinks=["CREDENTIAL"],
        )
        g = build_graph([t])
        types = {n.node_type for n in g.nodes.values()}
        self.assertIn("MachService", types)
        self.assertIn("Framework", types)
        self.assertIn("Entitlement", types)
        edge_types = {e.edge_type for e in g.edges}
        self.assertIn("PROVIDES", edge_types)
        self.assertIn("LINKS_TO", edge_types)
        self.assertIn("HAS_ENTITLEMENT", edge_types)
        # A framework a job links is not a client of the service that job
        # provides; that edge used to be invented for every pair.
        self.assertNotIn("CONNECTS_TO", edge_types)

    def test_a_client_naming_a_service_gets_a_lookup_edge(self):
        provider = _target(label="provider", mach_services=["com.example.svc"], privileged=True)
        client = _target(label="client", executable="/usr/libexec/client",
                         strings=["com.example.svc"])
        g = build_graph([provider, client])
        lookups = [e for e in g.edges if e.edge_type == "LOOKS_UP"]
        self.assertEqual(len(lookups), 1)
        self.assertEqual(lookups[0].source, "exec:/usr/libexec/client")
        self.assertEqual(lookups[0].target, "mach:com.example.svc")
        self.assertEqual(lookups[0].data["evidence"], "string")

    def test_no_lookup_edge_to_an_unknown_service_name(self):
        client = _target(label="client", strings=["com.example.does-not-exist"])
        g = build_graph([client])
        self.assertEqual([e for e in g.edges if e.edge_type == "LOOKS_UP"], [])

    def test_export_json_roundtrip(self):
        g = build_graph([_target(mach_services=["com.x"])])
        data = json.loads(export_json(g))
        self.assertIn("nodes", data)
        self.assertIn("edges", data)

    def test_export_dot(self):
        g = build_graph([_target(mach_services=["com.x"])])
        dot = export_dot(g)
        self.assertTrue(dot.startswith("digraph"))
        self.assertIn("->", dot)

    def test_export_mermaid(self):
        g = build_graph([_target(mach_services=["com.x"])])
        mmd = export_mermaid(g)
        self.assertTrue(mmd.startswith("graph LR"))


class TestCodesignExtract(unittest.TestCase):
    def test_extract_with_prefix_garbage(self):
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
            '<plist version="1.0"><dict><key>com.apple.private.foo</key><true/></dict></plist>'
        )
        text = "Executable=/x\nwarning: deprecated\n" + xml
        self.assertEqual(_extract_entitlements(text), {"com.apple.private.foo": True})

    def test_extract_none_when_empty(self):
        self.assertIsNone(_extract_entitlements(""))


if __name__ == "__main__":
    unittest.main()
