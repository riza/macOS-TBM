"""Regression tests for bounded XPC request/dispatch extraction."""

from __future__ import annotations

import unittest

import _paths  # noqa: F401

from collectors.dataflow import parse_disassembly
from collectors.xpc_dispatch import analyze_xpc_dispatch
from models.executable import MachOInfo


def _op(analysis, operation):
    return next(o for o in analysis.operations if o.get("operation") == operation)


class TestDispatchSurface(unittest.TestCase):
    def test_dispatch_operations_surface_on_the_dataflow_analysis(self):
        from collectors.dataflow import analyze_disassembly
        text = """
dispatch:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "request"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 adrp x1, 0x1000
0000000100001014 add x1, x1, #0x20 ; literal pool for: "RepairPermissionsForCloudItems"
0000000100001018 mov x0, x19
000000010000101c bl 0x100008100 ; symbol stub for: _strcmp
0000000100001020 cbz w0, 0x100001040
0000000100001024 b 0x100001060
repair_handler:
0000000100001040 ret
"""
        analysis = analyze_disassembly(
            text, ["xpc_dictionary_get_string"], ["unlink"])
        self.assertTrue(analysis.ipc_operations)
        self.assertEqual(analysis.ipc_operations[0]["operation"],
                         "RepairPermissionsForCloudItems")

    def test_macho_model_round_trips_ipc_operations(self):
        info = MachOInfo(path="/fixture", is_macho=True)
        info.ipc_operations = [{"request_key": "request", "operation": "Op",
                                "handler": "h", "input_keys": [],
                                "dispatcher": "d", "relationship": "PROVEN",
                                "evidence": []}]
        info.ipc_operation_unknown_reasons = {"UNKNOWN_INDIRECT_HANDLER": 1}
        data = info.to_dict()
        self.assertEqual(data["ipc_operations"][0]["operation"], "Op")
        self.assertEqual(data["ipc_operation_unknown_reasons"],
                         {"UNKNOWN_INDIRECT_HANDLER": 1})

    def test_audit_token_is_not_an_attacker_payload_source(self):
        text = """
handle_request:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "auditToken"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_audit_token
000000010000100c mov x0, x0
0000000100001010 bl 0x100008100 ; symbol stub for: _unlink
0000000100001014 ret
"""
        facts = parse_disassembly(
            text, ["xpc_dictionary_get_audit_token", "xpc_dictionary_get_string"],
            ["unlink"])
        self.assertFalse(any(f["source_api"] == "xpc_dictionary_get_audit_token"
                             for f in facts))
        self.assertFalse(any(0 in f["controlled_argument_indexes"] for f in facts))




class TestXpcKeyBinding(unittest.TestCase):
    def test_key_literal_binds_to_the_correct_source(self):
        text = """
handle_request:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "request"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 adrp x1, 0x1000
0000000100001014 add x1, x1, #0x20 ; literal pool for: "Paths"
0000000100001018 bl 0x100008010 ; symbol stub for: _xpc_dictionary_get_data
000000010000101c mov x0, x19
0000000100001020 bl 0x100008100 ; symbol stub for: _unlink
0000000100001024 ret
"""
        facts = parse_disassembly(
            text, ["xpc_dictionary_get_string", "xpc_dictionary_get_data"],
            ["unlink"])
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["source_api"], "xpc_dictionary_get_string")
        self.assertEqual(facts[0]["source_key"], "request")


class TestRequestDispatch(unittest.TestCase):
    def test_request_comparison_chain_extracts_operation_handler_and_inputs(self):
        text = """
dispatch:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "request"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 adrp x1, 0x1000
0000000100001014 add x1, x1, #0x20 ; literal pool for: "RepairPermissionsForCloudItems"
0000000100001018 mov x0, x19
000000010000101c bl 0x100008100 ; symbol stub for: _strcmp
0000000100001020 cbz w0, 0x100001040
0000000100001024 b 0x100001060
repair_handler:
0000000100001040 adrp x1, 0x1000
0000000100001044 add x1, x1, #0x30 ; literal pool for: "Paths"
0000000100001048 bl 0x100008200 ; symbol stub for: _xpc_dictionary_get_data
000000010000104c ret
"""
        analysis = analyze_xpc_dispatch(text)
        repair = _op(analysis, "RepairPermissionsForCloudItems")
        self.assertEqual(repair["request_key"], "request")
        self.assertEqual(repair["handler"], "repair_handler")
        self.assertEqual(repair["dispatcher"], "dispatch")
        self.assertEqual(repair["relationship"], "PROVEN")
        self.assertEqual(repair["input_keys"], ["Paths"])
        self.assertTrue(any(e["kind"] == "string-xref" for e in repair["evidence"]))

    def test_comparison_chain_yields_one_operation_per_request_value(self):
        text = """
dispatch:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "request"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 adrp x1, 0x1000
0000000100001014 add x1, x1, #0x20 ; literal pool for: "OperationOne"
0000000100001018 mov x0, x19
000000010000101c bl 0x100008100 ; symbol stub for: _strcmp
0000000100001020 cbz w0, 0x100001060
0000000100001024 adrp x1, 0x1000
0000000100001028 add x1, x1, #0x40 ; literal pool for: "OperationTwo"
000000010000102c mov x0, x19
0000000100001030 bl 0x100008100 ; symbol stub for: _strcmp
0000000100001034 cbz w0, 0x100001080
0000000100001038 ret
one_handler:
0000000100001060 ret
two_handler:
0000000100001080 ret
"""
        analysis = analyze_xpc_dispatch(text)
        self.assertEqual(sorted(o["operation"] for o in analysis.operations),
                         ["OperationOne", "OperationTwo"])
        self.assertEqual(_op(analysis, "OperationOne")["handler"], "one_handler")
        self.assertEqual(_op(analysis, "OperationTwo")["handler"], "two_handler")

    def test_unresolved_indirect_dispatcher_is_not_a_handler_claim(self):
        text = """
dispatch:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "request"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c br x8
"""
        analysis = analyze_xpc_dispatch(text)
        self.assertIn("UNKNOWN_INDIRECT_HANDLER", analysis.unknown_reasons)
        entry = analysis.operations[0]
        self.assertEqual(entry["request_key"], "request")
        self.assertIsNone(entry["operation"])
        self.assertIsNone(entry["handler"])
        self.assertEqual(entry["relationship"], "UNKNOWN_INDIRECT_HANDLER")

    def test_intra_function_handler_block_is_resolved(self):
        text = """
dispatch:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "request"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 adrp x1, 0x1000
0000000100001014 add x1, x1, #0x20 ; literal pool for: "RepairPermissionsForCloudItems"
0000000100001018 mov x0, x19
000000010000101c bl 0x100008100 ; symbol stub for: _strcmp
0000000100001020 cbz w0, 0x100001038
0000000100001024 ret
0000000100001038 mov x0, x19
000000010000103c bl 0x100008200 ; symbol stub for: _unlink
0000000100001040 ret
"""
        analysis = analyze_xpc_dispatch(
            text, function_starts={"arm64": [0x100001000]})
        repair = _op(analysis, "RepairPermissionsForCloudItems")
        self.assertEqual(repair["relationship"], "PROVEN")
        self.assertEqual(repair["handler"], "dispatch+0x38")

    def test_integer_request_switch_is_extracted(self):
        text = """
dispatch:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "requestedOperation"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_int64
000000010000100c mov x19, x0
0000000100001010 cmp w19, #0x3
0000000100001014 b.eq 0x100001030
0000000100001018 cmp w19, #0x7
000000010000101c b.eq 0x100001040
0000000100001020 ret
0000000100001030 ret
0000000100001040 ret
"""
        analysis = analyze_xpc_dispatch(
            text, function_starts={"arm64": [0x100001000]})
        self.assertEqual(sorted(o["operation"] for o in analysis.operations),
                         ["#3", "#7"])
        first = _op(analysis, "#3")
        self.assertEqual(first["request_key"], "requestedOperation")
        self.assertEqual(first["handler"], "dispatch+0x30")
        self.assertEqual(first["relationship"], "PROVEN")

    def test_comparison_wrapper_dispatch_is_extracted(self):
        text = """
dispatch:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "request"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 add x0, sp, #0x8
0000000100001014 adrp x1, 0x1000
0000000100001018 add x1, x1, #0x20 ; literal pool for: "SetChildPermissions"
000000010000101c bl 0x100002000 <_string_equal>
0000000100001020 tbnz w0, #0x0, 0x100001040
0000000100001024 ret
0000000100001040 ret
string_equal:
0000000100002000 bl 0x100008100 ; symbol stub for: _CFEqual
0000000100002004 ret
"""
        analysis = analyze_xpc_dispatch(
            text, function_starts={"arm64": [0x100001000, 0x100002000]})
        operation = _op(analysis, "SetChildPermissions")
        self.assertEqual(operation["request_key"], "request")
        self.assertEqual(operation["relationship"], "PROVEN")
        self.assertEqual(operation["handler"], "dispatch+0x40")

    def test_block_handler_input_keys_come_from_the_owning_function(self):
        text = """
dispatch:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "request"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 adrp x1, 0x1000
0000000100001014 add x1, x1, #0x20 ; literal pool for: "RepairPermissionsForCloudItems"
0000000100001018 mov x0, x19
000000010000101c bl 0x100008100 ; symbol stub for: _strcmp
0000000100001020 cbz w0, 0x100001040
0000000100001024 ret
0000000100001040 adrp x1, 0x1000
0000000100001044 add x1, x1, #0x30 ; literal pool for: "Paths"
0000000100001048 bl 0x100008200 ; symbol stub for: _xpc_dictionary_get_data
000000010000104c ret
"""
        analysis = analyze_xpc_dispatch(
            text, function_starts={"arm64": [0x100001000]})
        operation = _op(analysis, "RepairPermissionsForCloudItems")
        self.assertEqual(operation["handler"], "dispatch+0x40")
        self.assertIn("Paths", operation["input_keys"])

    def test_operations_sharing_one_successor_are_not_proven_handlers(self):
        text = """
dispatch:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "request"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 adrp x1, 0x1000
0000000100001014 add x1, x1, #0x20 ; literal pool for: "OperationOne"
0000000100001018 mov x0, x19
000000010000101c bl 0x100008100 ; symbol stub for: _strcmp
0000000100001020 cbz w0, 0x100001040
0000000100001024 adrp x1, 0x1000
0000000100001028 add x1, x1, #0x40 ; literal pool for: "OperationTwo"
000000010000102c mov x0, x19
0000000100001030 bl 0x100008100 ; symbol stub for: _strcmp
0000000100001034 cbz w0, 0x100001040
0000000100001038 ret
0000000100001040 ret
"""
        analysis = analyze_xpc_dispatch(
            text, function_starts={"arm64": [0x100001000]})
        self.assertEqual(sorted(o["operation"] for o in analysis.operations),
                         ["OperationOne", "OperationTwo"])
        for operation in analysis.operations:
            self.assertEqual(operation["relationship"], "SHARED_SUCCESSOR")
            self.assertEqual(operation["handler"], "dispatch+0x40")

    def test_single_comparison_on_a_non_dispatch_key_is_filtered(self):
        text = """
handle:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "value"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 adrp x1, 0x1000
0000000100001014 add x1, x1, #0x20 ; literal pool for: "uninitialized"
0000000100001018 mov x0, x19
000000010000101c bl 0x100008100 ; symbol stub for: _strcmp
0000000100001020 cbz w0, 0x100001030
0000000100001024 ret
0000000100001030 ret
"""
        analysis = analyze_xpc_dispatch(text)
        self.assertEqual(analysis.operations, [])

    def test_a_chain_on_a_non_dispatch_key_is_kept(self):
        text = """
handle:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "value"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 adrp x1, 0x1000
0000000100001014 add x1, x1, #0x20 ; literal pool for: "state-one"
0000000100001018 mov x0, x19
000000010000101c bl 0x100008100 ; symbol stub for: _strcmp
0000000100001020 cbz w0, 0x100001030
0000000100001024 adrp x1, 0x1000
0000000100001028 add x1, x1, #0x40 ; literal pool for: "state-two"
000000010000102c mov x0, x19
0000000100001030 bl 0x100008100 ; symbol stub for: _strcmp
0000000100001034 ret
"""
        analysis = analyze_xpc_dispatch(text)
        self.assertEqual(sorted(o["operation"] for o in analysis.operations),
                         ["state-one", "state-two"])


