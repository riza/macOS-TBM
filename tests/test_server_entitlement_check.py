"""Tests for the server-side entitlement-check signal.

The crux is the held-vs-checked distinction: a daemon *holds* entitlements
(``codesign.entitlements``) and *checks* a possibly-different set on its
clients. ``detect_checked_entitlements`` separates the two, the graph emits a
``CHECKED_ENTITLEMENT`` edge for the checked set, and ``deputies()`` prefers
that set over the ``<label>.*`` heuristic.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

import _paths  # noqa: F401

from analyzers.security_signals import detect_checked_entitlements


def _macho(imports=(), objc=(), strings=(), listeners=()):
    return SimpleNamespace(
        imported_symbols=list(imports),
        objc_classes=list(objc),
        interesting_strings=list(strings),
        linked_libs=[],
        weak_linked_libs=[],
        nsxpc_unconditional_accept_listeners=list(listeners),
    )


def _codesign(entitlements=None):
    return SimpleNamespace(entitlements=dict(entitlements or {}))


class TestHeldVsChecked(unittest.TestCase):
    def test_checked_keys_exclude_held_entitlements(self):
        macho = _macho(
            imports=["SecTaskCopyValueForEntitlement"],
            strings=["com.apple.mobileactivationd.spi", "com.apple.held.key"],
        )
        codesign = _codesign({"com.apple.held.key": True})
        keys, evidence = detect_checked_entitlements(macho, codesign)
        self.assertEqual(keys, ["com.apple.mobileactivationd.spi"])
        self.assertTrue(evidence)  # the SecTask checker marker was seen

    def test_no_checker_marker_yields_no_keys(self):
        # A com.apple.* string without a checker API is a name, not a check.
        macho = _macho(strings=["com.apple.some.spi"])
        keys, evidence = detect_checked_entitlements(macho, _codesign())
        self.assertEqual(keys, [])
        self.assertEqual(evidence, [])

    def test_lone_string_checker_marker_does_not_count(self):
        macho = _macho(strings=["valueForEntitlement:", "com.apple.x.spi"])
        keys, evidence = detect_checked_entitlements(macho, _codesign())
        self.assertEqual(keys, [])
        self.assertEqual(evidence, [])

    def test_correlated_nsxpc_per_message_checker_counts(self):
        macho = _macho(
            objc=["NSXPCConnection"],
            strings=["valueForEntitlement:", "boolValue", "com.apple.x.spi"],
            listeners=["-[RDXPCListener listener:shouldAcceptNewConnection:]"],
        )
        keys, evidence = detect_checked_entitlements(macho, _codesign())
        self.assertEqual(keys, ["com.apple.x.spi"])
        self.assertTrue(any(e.kind == "correlated-static" for e in evidence))

    def test_key_held_but_not_referenced_elsewhere_is_not_checked(self):
        macho = _macho(imports=["xpc_connection_copy_entitlement_value"],
                       strings=["com.apple.held.key"])
        codesign = _codesign({"com.apple.held.key": True})
        keys, _ = detect_checked_entitlements(macho, codesign)
        self.assertEqual(keys, [])

    def test_deduplicated_and_sorted(self):
        macho = _macho(imports=["SecTaskCopyValueForEntitlement"],
                       strings=["com.apple.foo.z", "com.apple.foo.a", "com.apple.foo.z"])
        keys, _ = detect_checked_entitlements(macho, _codesign())
        self.assertEqual(keys, ["com.apple.foo.a", "com.apple.foo.z"])

    def test_non_entitlement_shaped_keys_are_dropped(self):
        # Error domains, Mach-service names and short identifiers are not
        # entitlement keys and must not be reported as checked entitlements.
        macho = _macho(imports=["SecTaskCopyValueForEntitlement"],
                       strings=["com.apple.MobileActivation.ErrorDomain",
                                "com.apple.fairplay",
                                "com.apple.real.check"])
        keys, _ = detect_checked_entitlements(macho, _codesign())
        self.assertEqual(keys, ["com.apple.real.check"])


class TestCheckedEntitlementEdge(unittest.TestCase):
    def test_build_graph_emits_checked_entitlement_edge(self):
        from graph.model import build_graph

        svc = SimpleNamespace(
            label="com.example.rootd", plist_path="/x.plist",
            mach_services=["com.example.rootd"], associated_executable="/usr/libexec/rootd",
            run_as="root", run_as_user="root", is_privileged=True, enabled=True,
            scope="system-daemon", sockets={},
        )
        exe = SimpleNamespace(
            codesign=SimpleNamespace(entitlements={"com.apple.private.own": True}),
            macho=SimpleNamespace(linked_libs=[], interesting_strings=[]),
        )
        target = SimpleNamespace(service=svc, executable=exe, score=10,
                                 sensitive_sinks=[], validation="NONE_OBSERVED",
                                 checked_entitlements=["com.example.client.spi"])
        g = build_graph([target])

        checked = [e for e in g.edges if e.edge_type == "CHECKED_ENTITLEMENT"]
        self.assertEqual(len(checked), 1)
        self.assertEqual(checked[0].source, "service:com.example.rootd")
        self.assertEqual(checked[0].target, "ent:com.example.client.spi")

        # The checked key is a distinct node from the held one.
        node_ids = {n.id for n in g.nodes.values()}
        self.assertIn("ent:com.example.client.spi", node_ids)
        self.assertIn("ent:com.apple.private.own", node_ids)


if __name__ == "__main__":
    unittest.main()
