"""Regression tests for path -> descriptor provenance and resource authority."""

from __future__ import annotations

import unittest

import _paths  # noqa: F401

from analyzers.capabilities import analyze_capabilities
from analyzers.lpe import analyze_lpe
from analyzers.security_signals import detect_signals
from collectors.dataflow import parse_disassembly
from models.common import RunAs, ServiceScope, ServiceType
from models.executable import CodeSigningInfo, MachOInfo
from models.service import LaunchService

OPEN_THEN_FCHOWN = """
handle_request:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "path"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 mov x0, x19
0000000100001014 bl 0x100008010 ; symbol stub for: _open
0000000100001018 mov x20, x0
000000010000101c mov x0, x20
0000000100001020 mov x1, #0x0
0000000100001024 mov x2, #0x0
0000000100001028 bl 0x100008100 ; symbol stub for: _fchown
000000010000102c ret
"""

DESCRIPTOR_VIA_WRAPPER = """
handle_request:
0000000100001000 bl 0x100002000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 bl 0x100002100 <_open_from_message>
0000000100001008 mov x19, x0
000000010000100c mov x0, x19
0000000100001010 mov x1, #0x0
0000000100001014 mov x2, #0x0
0000000100001018 bl 0x100008100 ; symbol stub for: _fchown
000000010000101c ret
open_from_message:
0000000100002000 adrp x1, 0x1000
0000000100002004 add x1, x1, #0x20 ; literal pool for: "path"
0000000100002008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000200c bl 0x100008010 ; symbol stub for: _open
0000000100002010 ret
"""

OVERWRITTEN_DESCRIPTOR = """
handle_request:
0000000100001000 bl 0x100002000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 bl 0x100008010 ; symbol stub for: _open
0000000100001008 mov x19, x0
000000010000100c bl 0x100008010 ; symbol stub for: _open
0000000100001010 mov x19, x0
0000000100001014 mov x0, x19
0000000100001018 mov x1, #0x0
000000010000101c mov x2, #0x0
0000000100001020 bl 0x100008100 ; symbol stub for: _fchown
0000000100001024 ret
"""


def _fchown_fact(text):
    facts = parse_disassembly(text, ["xpc_dictionary_get_string"], ["open", "fchown"])
    return next(f for f in facts if f["sink_api"] == "fchown")


class TestDescriptorProvenance(unittest.TestCase):
    def test_open_path_then_fchown_binds_only_the_descriptor(self):
        fact = _fchown_fact(OPEN_THEN_FCHOWN)
        self.assertEqual(fact["controlled_argument_indexes"], [0])
        self.assertIn("0", fact["descriptor_provenance"])
        resource = fact["descriptor_provenance"]["0"][0]
        self.assertEqual(resource["api"], "open")
        self.assertEqual(resource["path_argument"], 0)
        self.assertTrue(any(origin.startswith("SOURCE|")
                            for origin in resource["origins"]))

    def test_descriptor_provenance_survives_a_helper_return(self):
        fact = _fchown_fact(DESCRIPTOR_VIA_WRAPPER)
        self.assertEqual(fact["controlled_argument_indexes"], [0])
        self.assertIn("0", fact["descriptor_provenance"])
        self.assertEqual(fact["descriptor_provenance"]["0"][0]["api"], "open")

    def test_overwritten_register_does_not_carry_stale_provenance(self):
        fact = _fchown_fact(OVERWRITTEN_DESCRIPTOR)
        resources = fact["descriptor_provenance"].get("0", [])
        self.assertTrue(resources)
        self.assertTrue(all(entry.get("address") == "000000010000100c"
                            for entry in resources))
        self.assertFalse(any(entry.get("address") == "0000000100001004"
                             for entry in resources))

    def test_controlled_descriptor_is_a_controlled_sink_not_arbitrary_chown(self):
        fact = _fchown_fact(OPEN_THEN_FCHOWN)
        svc = LaunchService(
            label="com.example.dsh", plist_path="/System/Library/LaunchDaemons/x.plist",
            service_type=ServiceType.DAEMON, scope=ServiceScope.SYSTEM_DAEMON,
            mach_services=["com.example.dsh"], run_as=RunAs.ROOT,
            run_as_user="root", enabled=True,
        )
        macho = MachOInfo(
            path="/fixture", is_macho=True,
            imported_symbols=["xpc_dictionary_get_string", "open", "fchown"],
            dataflow_facts=[fact],
        )
        codesign = CodeSigningInfo(path="/fixture", is_signed=True)
        signals = detect_signals(svc, macho, codesign)
        findings, _ = analyze_capabilities(svc, macho, signals, codesign)
        finding = next(f for f in findings
                       if f.candidate_capability == "CHOWN_SINK_CANDIDATE")
        self.assertEqual(finding.maturity_level, "CONTROLLED_SINK")
        self.assertIsNone(finding.proven_primitive)
        self.assertEqual(finding.controlled_arguments["file_descriptor"], "HIGH")
        self.assertEqual(finding.controlled_arguments.get("resource_path"), "HIGH")

        lpe = analyze_lpe(svc, macho, findings)
        chown = [entry for entry in lpe if entry.operation == "chown"]
        self.assertTrue(chown)
        self.assertEqual(chown[0].resource_authorization, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
