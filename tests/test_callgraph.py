"""Regression tests for the direct call graph and reachability states."""

from __future__ import annotations

import unittest

import _paths  # noqa: F401

from collectors.callgraph import CallGraph
from collectors.dataflow import parse_disassembly


class TestCallGraph(unittest.TestCase):
    def test_reachable_follows_direct_edges(self):
        graph = CallGraph()
        graph.add_edge("entry", "a")
        graph.add_edge("a", "b")
        graph.add_edge("orphan", "z")
        self.assertEqual(graph.reachable({"entry"}), {"entry", "a", "b"})

    def test_absent_edges_are_not_negative_evidence(self):
        graph = CallGraph()
        self.assertEqual(graph.reachable({"entry"}), {"entry"})
        self.assertEqual(graph.incoming("a"), set())

    def test_shortest_paths_are_bounded_and_rooted(self):
        graph = CallGraph()
        graph.add_edge("entry", "a")
        graph.add_edge("a", "sink")
        paths = graph.shortest_paths("sink", {"entry"}, max_depth=8)
        self.assertEqual(paths[0], ["entry", "a", "sink"])

    def test_indirect_marker_is_separate_from_direct_edges(self):
        graph = CallGraph()
        graph.mark_indirect("dispatcher")
        self.assertTrue(graph.has_indirect("dispatcher"))
        self.assertFalse(graph.has_indirect("other"))


INDIRECT_HANDLER = """
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x19, x0
0000000100001008 mov x0, x19
000000010000100c bl 0x100008100 ; symbol stub for: _unlink
0000000100001010 ret
"""

DIRECT_HANDLER = """
caller:
0000000100001000 bl 0x100002000 <_handle>
0000000100001004 ret
handle:
0000000100002000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100002004 mov x19, x0
0000000100002008 mov x0, x19
000000010000200c bl 0x100008100 ; symbol stub for: _unlink
0000000100002010 ret
"""


def _fact(text, starts):
    facts = parse_disassembly(
        text, ["xpc_dictionary_get_string"], ["unlink"],
        executable_ranges=[(0x100001000, 0x100003000)],
        function_starts={"arm64": starts},
    )
    return facts[0]


class TestFactReachabilityState(unittest.TestCase):
    def test_block_handler_is_confirmed_indirect_not_unresolved(self):
        fact = _fact(INDIRECT_HANDLER, [0x100001000])
        self.assertEqual(fact["reachability_state"], "CONFIRMED_INDIRECT")
        self.assertTrue(fact["reachability_confirmed"])
        self.assertNotIn("UNKNOWN_NO_CALL_PATH", fact["unknown_reasons"])

    def test_directly_called_handler_is_confirmed_direct(self):
        fact = _fact(DIRECT_HANDLER, [0x100001000, 0x100002000])
        self.assertEqual(fact["reachability_state"], "CONFIRMED_DIRECT")
        self.assertEqual(fact["reachability_evidence"], "CALL_REFERENCE")


if __name__ == "__main__":
    unittest.main()
