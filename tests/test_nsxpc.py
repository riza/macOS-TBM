"""Tests for passive NSXPC protocol extraction."""

from __future__ import annotations

import unittest

import _paths  # noqa: F401

from collectors.nsxpc import (
    decode_type,
    method_signature,
    parse_methname,
    parse_method_types,
    parse_otool_ov,
    parse_selrefs,
    resolve_names,
)

# A trimmed excerpt of the real `otool -ov` output for
# /usr/libexec/mobileactivationd (absolute-pointer layout, resolved names).
OTOOL_OV_FIXTURE = """\
Contents of (__DATA_CONST,__objc_classlist) section
0000000100098218 0x10009da40 _OBJC_CLASS_$_MobileActivationMacOSDaemon
           isa        0x10009da68 _OBJC_METACLASS_$_MobileActivationMacOSDaemon
           name       0x10008657e MobileActivationMacOSDaemon
        baseProtocols  0x10009c898 __OBJC_CLASS_PROTOCOLS_$_MobileActivationMacOSDaemon
            count    2
            list[0]  0x10009dc70 __OBJC_PROTOCOL_$_NSXPCListenerDelegate
            list[1]  0x10009dc10 __OBJC_PROTOCOL_$_MobileActivationMacOSProtocol
                name      0x100086557 MobileActivationMacOSProtocol
                protocols 0x10009c7d8 __OBJC_$_PROTOCOL_REFS_MobileActivationMacOSProtocol
                    count    1
                    list[0]  0x10009dbb0 __OBJC_PROTOCOL_$_NSObject
                instanceMethods 0x10008bf00 __OBJC_$_PROTOCOL_INSTANCE_METHODS_MobileActivationMacOSProtocol
                    entsize 24
                    count   5
                    name    0x10005de9f copyAutomaticTimeEnabledWithCompletion:
                    types   0x10006b119 v24@0:8@?16
                    imp     0x100000000 __mh_execute_header
                    name    0x10005e000 copyRTCResetCountWithCompletionBlock:
                    types   0x10006b119 v24@0:8@?16
                    imp     0x100000000 __mh_execute_header
                    name    0x10005dfb6 copyMonotonicClockWithCompletionBlock:
                    types   0x10006b119 v24@0:8@?16
                    imp     0x100000000 __mh_execute_header
                    name    0x10005e07f createActivationInfo:withCompletionBlock:
                    types   0x10006b12c v32@0:8@16@?24
                    imp     0x100000000 __mh_execute_header
                    name    0x10005e550 handleActivationInfo:options:withCompletionBlock:
                    types   0x10006b13f v40@0:8@16@24@?32
                    imp     0x100000000 __mh_execute_header
                classMethods 0x100000000 __mh_execute_header
"""

# The same protocol in the modern relative-pointer (arm64e) layout, where otool
# resolves `types` but leaves `name` as an offset + selref address.
OTOOL_OV_RELATIVE_FIXTURE = """\
    baseProtocols  0x10009c898 __OBJC_CLASS_PROTOCOLS_$_MobileActivationMacOSDaemon
        count    2
        list[0]  0x10009dc70 __OBJC_PROTOCOL_$_NSXPCListenerDelegate
        list[1]  0x10009dc10 __OBJC_PROTOCOL_$_MobileActivationMacOSProtocol
    instanceMethods 0x100067d68 __OBJC_$_PROTOCOL_INSTANCE_METHODS_MobileActivationMacOSProtocol
        entsize 12 (relative)
        count   2
        name    0x35990 (0x10009d700)
        types   0x1ea11 (0x100086785) v24@0:8@?16
        imp     0x0
        name    0x3598c (0x10009d708)
        types   0x1ea05 (0x100086785) v24@0:8@?16
        imp     0x0
    classMethods 0x100000000 __mh_execute_header
"""


class TestTypeDecoding(unittest.TestCase):
    def test_decode_primitives(self):
        self.assertEqual(decode_type("v"), "void")
        self.assertEqual(decode_type("@"), "id")
        self.assertEqual(decode_type("@?"), "id")
        self.assertEqual(decode_type("B"), "BOOL")
        self.assertEqual(decode_type("q"), "long long")
        self.assertEqual(decode_type("^v"), "void *")

    def test_parse_method_types(self):
        ret, args = parse_method_types("v40@0:8@16@24@?32")
        self.assertEqual(ret, "v")
        self.assertEqual(args, ["@", "@", "@?"])

    def test_parse_method_types_with_struct(self):
        ret, args = parse_method_types("v24@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16")
        self.assertEqual(ret, "v")
        self.assertEqual(args, ["{CGRect={CGPoint=dd}{CGSize=dd}}"])

    def test_signature(self):
        sig = method_signature("handleActivationInfo:options:withCompletionBlock:",
                               "v40@0:8@16@24@?32")
        self.assertEqual(
            sig,
            "- (void)handleActivationInfo:(id)arg0 options:(id)arg1 withCompletionBlock:(id)block")

    def test_signature_falls_back_when_labels_missing(self):
        self.assertEqual(method_signature("m:", "v24@0:8@16"), "- (void)m:(id)arg0")


class TestParseOtoolOv(unittest.TestCase):
    def test_extracts_exported_protocol_and_methods(self):
        protocols = parse_otool_ov(OTOOL_OV_FIXTURE)
        self.assertEqual([p.name for p in protocols], ["MobileActivationMacOSProtocol"])
        proto = protocols[0]
        self.assertEqual(len(proto.methods), 5)
        self.assertEqual(proto.methods[0].name, "copyAutomaticTimeEnabledWithCompletion:")
        self.assertEqual(
            proto.methods[4].signature,
            "- (void)handleActivationInfo:(id)arg0 options:(id)arg1 withCompletionBlock:(id)block")

    def test_non_listener_protocols_are_not_exported(self):
        # A protocol referenced by a class that does NOT conform to
        # NSXPCListenerDelegate must not be reported.
        text = """\
        baseProtocols 0x1 __OBJC_CLASS_PROTOCOLS_$_SomeOtherClass
            count    1
            list[0]  0x2 __OBJC_PROTOCOL_$_SomeOtherProtocol
"""
        self.assertEqual(parse_otool_ov(text), [])

    def test_relative_names_are_left_unresolved(self):
        protocols = parse_otool_ov(OTOOL_OV_RELATIVE_FIXTURE)
        self.assertEqual(len(protocols), 1)
        self.assertTrue(all(m.name is None for m in protocols[0].methods))
        self.assertEqual(protocols[0].methods[0].selref, 0x10009D700)


class TestSelectorResolution(unittest.TestCase):
    def test_resolve_names_via_selref_chain(self):
        protocols = parse_otool_ov(OTOOL_OV_RELATIVE_FIXTURE)
        methname = {
            0x10007809D: "copyAutomaticTimeEnabledWithCompletion:",
            0x100078210: "copyRTCResetCountWithCompletionBlock:",
        }
        # chained pointers: low 32 bits = offset from image base 0x100000000
        selrefs = {0x10009D700: 0x10007809D, 0x10009D708: 0x100078210}
        resolve_names(protocols, methname, selrefs)
        names = [m.name for m in protocols[0].methods]
        self.assertEqual(names, ["copyAutomaticTimeEnabledWithCompletion:",
                                 "copyRTCResetCountWithCompletionBlock:"])

    def test_parse_selrefs_applies_image_base(self):
        text = (
            "Contents of (__DATA,__objc_selrefs) section\n"
            "000000010009d700  0007809d 00080000 00078210 00080000 \n"
        )
        selrefs = parse_selrefs(text, image_base=0x100000000)
        self.assertEqual(selrefs[0x10009D700], 0x10007809D)
        self.assertEqual(selrefs[0x10009D708], 0x100078210)

    def test_parse_methname(self):
        text = (
            "Contents of (__TEXT,__objc_methname) section\n"
            "000000010007809d  copyAutomaticTimeEnabledWithCompletion:\n"
            "0000000100078210  copyRTCResetCountWithCompletionBlock:\n"
        )
        m = parse_methname(text)
        self.assertEqual(m[0x10007809D], "copyAutomaticTimeEnabledWithCompletion:")


if __name__ == "__main__":
    unittest.main()
