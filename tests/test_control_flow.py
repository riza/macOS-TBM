"""Regression tests for fail-closed operation-guard control-flow proof."""

from __future__ import annotations

import unittest

import _paths  # noqa: F401

from collectors.dataflow import parse_disassembly

POSITIVE = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x19, x0
0000000100001008 bl 0x100008010 ; symbol stub for: _SecCodeCheckValidity
000000010000100c cbnz x0, 0x100001030
0000000100001010 mov x0, x19
0000000100001014 bl 0x100008100 ; symbol stub for: _unlink
0000000100001030 ret
"""

NEGATIVE = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x19, x0
0000000100001008 bl 0x100008010 ; symbol stub for: _SecCodeCheckValidity
000000010000100c cbz x0, 0x100001030
0000000100001010 mov x0, x19
0000000100001014 bl 0x100008100 ; symbol stub for: _unlink
0000000100001030 ret
"""

ALTERNATE_PATH = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x19, x0
0000000100001008 cbnz x19, 0x100001014
000000010000100c bl 0x100008010 ; symbol stub for: _SecCodeCheckValidity
0000000100001010 cbnz x0, 0x100001024
0000000100001014 mov x0, x19
0000000100001018 bl 0x100008100 ; symbol stub for: _unlink
000000010000101c ret
0000000100001024 ret
"""

UNRELATED_BRANCH = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x19, x0
0000000100001008 bl 0x100008010 ; symbol stub for: _SecCodeCheckValidity
000000010000100c mov x20, #0x1
0000000100001010 cbz x20, 0x100001030
0000000100001014 mov x0, x19
0000000100001018 bl 0x100008100 ; symbol stub for: _unlink
0000000100001030 ret
"""

UNKNOWN_SEMANTICS = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x19, x0
0000000100001008 bl 0x100008010 ; symbol stub for: _sandbox_check_by_audit_token
000000010000100c cbnz x0, 0x100001030
0000000100001010 mov x0, x19
0000000100001014 bl 0x100008100 ; symbol stub for: _unlink
0000000100001030 ret
"""

INDIRECT = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x19, x0
0000000100001008 bl 0x100008010 ; symbol stub for: _SecCodeCheckValidity
000000010000100c cbnz x0, 0x100001020
0000000100001010 mov x0, x19
0000000100001014 bl 0x100008100 ; symbol stub for: _unlink
0000000100001018 br x8
0000000100001020 ret
"""

OBJECT_BOOLEAN = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x19, x0
0000000100001008 bl 0x100008010 ; symbol stub for: _SecTaskCopyValueForEntitlement
000000010000100c mov x20, x0
0000000100001010 adrp x1, 0x1000
0000000100001014 add x1, x1, #0x10 ; literal pool for: "boolValue"
0000000100001018 mov x0, x20
000000010000101c bl 0x100008020 ; symbol stub for: _objc_msgSend
0000000100001020 cbz w0, 0x100001038
0000000100001024 mov x0, x19
0000000100001028 bl 0x100008100 ; symbol stub for: _unlink
0000000100001038 ret
"""


def _fact(text):
    facts = parse_disassembly(text, ["xpc_dictionary_get_string"], ["unlink"])
    return facts[0]


def _validation_scope(fact):
    return fact["validation_controls"][0]["scope"]


class TestOperationGuard(unittest.TestCase):
    def test_failure_branch_skipping_sink_proves_guard(self):
        self.assertEqual(_validation_scope(_fact(POSITIVE)),
                         "VALIDATION_GUARDS_SINK")

    def test_success_branch_skipping_sink_is_not_a_guard(self):
        self.assertNotEqual(_validation_scope(_fact(NEGATIVE)),
                            "VALIDATION_GUARDS_SINK")

    def test_alternate_path_to_sink_breaks_dominance(self):
        fact = _fact(ALTERNATE_PATH)
        self.assertNotEqual(_validation_scope(fact), "VALIDATION_GUARDS_SINK")

    def test_branch_on_unrelated_register_is_not_a_guard(self):
        fact = _fact(UNRELATED_BRANCH)
        self.assertNotEqual(_validation_scope(fact), "VALIDATION_GUARDS_SINK")

    def test_unknown_success_semantics_is_not_a_guard(self):
        fact = _fact(UNKNOWN_SEMANTICS)
        self.assertTrue(fact["authorization_controls"])
        self.assertNotEqual(fact["authorization_controls"][0]["scope"],
                            "AUTHORIZATION_GUARDS_SINK")

    def test_indirect_jump_yields_unknown_control_flow(self):
        fact = _fact(INDIRECT)
        self.assertIn("UNKNOWN_CONTROL_FLOW", fact["unknown_reasons"])
        self.assertNotEqual(_validation_scope(fact), "VALIDATION_GUARDS_SINK")

    def test_entitlement_object_boolean_is_a_guard(self):
        self.assertEqual(_validation_scope(_fact(OBJECT_BOOLEAN)),
                         "VALIDATION_GUARDS_SINK")


if __name__ == "__main__":
    unittest.main()
