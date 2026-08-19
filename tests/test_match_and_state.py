"""Regression tests for the false positives found by auditing a real scan.

Each test pins one over-broad match or mis-parsed plist that made the report
claim surface a machine does not actually have.
"""

from __future__ import annotations

import os
import plistlib
import tempfile
import unittest

import _paths  # noqa: F401

from analyzers._match import lib_has, match_all, matched_needles, library_names
from collectors.launchd import _parse_plist, derive_enabled, resolve_conditional
from models.common import ServiceType


class TestSymbolMatching(unittest.TestCase):
    """Symbols match whole names; strings match on token boundaries."""

    def test_connect_does_not_match_xpc_connection(self):
        syms = ["xpc_connection_send_message", "dispatch_mach_connect", "xpc_connection_create"]
        self.assertEqual(matched_needles(syms, ["connect"], anchored=True), [])

    def test_connect_matches_the_connect_syscall(self):
        self.assertEqual(matched_needles(["connect", "socket"], ["connect"], anchored=True), ["connect"])

    def test_system_does_not_match_cfstringgetsystemencoding(self):
        syms = ["CFStringGetSystemEncoding", "IORegisterForSystemPower"]
        self.assertEqual(matched_needles(syms, ["system"], anchored=True), [])

    def test_star_needle_still_matches_prefix(self):
        syms = ["posix_spawnattr_setflags", "SecItemCopyMatching"]
        self.assertEqual(
            matched_needles(syms, ["posix_spawn*", "SecItem*"], anchored=True),
            ["posix_spawn*", "SecItem*"],
        )

    def test_strings_match_inside_an_entry(self):
        strings = ["com.apple.MobileSoftwareUpdate.UpdateBrainService"]
        self.assertEqual(matched_needles(strings, ["MobileSoftwareUpdate"]), ["MobileSoftwareUpdate"])

    def test_match_all_finds_a_symbol_listed_under_strings(self):
        # xpc_connection_get_audit_token is an imported symbol; a rule listing it
        # in either section must still detect it.
        pairs = match_all(["xpc_connection_get_audit_token"], [], ["xpc_connection_get_audit_token"])
        self.assertEqual([n for n, _ in pairs], ["xpc_connection_get_audit_token"])


class TestLibraryMatching(unittest.TestCase):
    def test_security_does_not_match_endpoint_security(self):
        libs = ["/usr/lib/libEndpointSecurity.dylib"]
        self.assertEqual(lib_has(libs, ["Security"]), [])

    def test_security_does_not_match_security_foundation(self):
        libs = ["/System/Library/Frameworks/SecurityFoundation.framework/Versions/A/SecurityFoundation"]
        self.assertEqual(lib_has(libs, ["Security"]), [])

    def test_security_framework_matches(self):
        libs = ["/System/Library/Frameworks/Security.framework/Versions/A/Security"]
        self.assertEqual(lib_has(libs, ["Security"]), ["Security"])

    def test_library_names_strips_lib_prefix_and_version(self):
        names = library_names(["/usr/lib/libarchive.2.dylib"])
        self.assertIn("archive", names)
        self.assertIn("libarchive", names)


class TestConditionalPlistValues(unittest.TestCase):
    """Feature-flag conditionals must resolve, never stringify into garbage."""

    def test_resolves_if_feature_flag_enabled(self):
        value, note = resolve_conditional(
            {"#IfFeatureFlagEnabled": "Spotlight/RoleUserIndexDaemon", "#Then": "_mds_stores"}
        )
        self.assertEqual(value, "_mds_stores")
        self.assertIn("Spotlight/RoleUserIndexDaemon", note)

    def test_plain_value_passes_through(self):
        self.assertEqual(resolve_conditional("_locationd"), ("_locationd", None))

    def test_conditional_username_becomes_the_real_user(self):
        data = {
            "Label": "com.example.conditional",
            "ProgramArguments": ["/usr/bin/true"],
            "UserName": {"#IfFeatureFlagEnabled": "Some/Flag", "#Then": "_someuser"},
        }
        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as fh:
            plistlib.dump(data, fh)
            path = fh.name
        try:
            svc = _parse_plist(path)
            self.assertEqual(svc.user_name, "_someuser")
            self.assertEqual(svc.run_as_user, "_someuser")
            self.assertIn("conditional on", svc.run_as_derivation)
        finally:
            os.unlink(path)


class TestNonJobPlists(unittest.TestCase):
    def test_config_payload_without_label_or_program_is_skipped(self):
        # com.apple.jetsamproperties.Mac.plist shape: config data in LaunchDaemons.
        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as fh:
            plistlib.dump({"Version4": {"Angel": {}}}, fh)
            path = fh.name
        try:
            self.assertIsNone(_parse_plist(path))
        finally:
            os.unlink(path)

    def test_empty_plist_is_skipped(self):
        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as fh:
            plistlib.dump({}, fh)
            path = fh.name
        try:
            self.assertIsNone(_parse_plist(path))
        finally:
            os.unlink(path)

    def test_label_fallback_drops_the_plist_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as fh:
            plistlib.dump({"ProgramArguments": ["/usr/bin/true"]}, fh)
            path = fh.name
        try:
            svc = _parse_plist(path)
            self.assertFalse(svc.label.endswith(".plist"))
        finally:
            os.unlink(path)


class TestDisabledState(unittest.TestCase):
    """A job launchd will not load is not live attack surface."""

    def test_plist_disabled_is_reported_disabled(self):
        enabled, why = derive_enabled("com.example.nonexistent.job", ServiceType.DAEMON, True)
        self.assertFalse(enabled)
        self.assertIn("Disabled=true", why)

    def test_no_disabled_key_is_enabled(self):
        enabled, why = derive_enabled("com.example.nonexistent.job", ServiceType.DAEMON, None)
        self.assertTrue(enabled)

    def test_conditional_disabled_key_resolves(self):
        enabled, _ = derive_enabled(
            "com.example.nonexistent.job",
            ServiceType.DAEMON,
            {"#IfFeatureFlagEnabled": "Some/Flag", "#Then": True},
        )
        self.assertFalse(enabled)


if __name__ == "__main__":
    unittest.main()


class TestEvidenceWeighting(unittest.TestCase):
    """A sink label is only as strong as the kind of evidence behind it."""

    def _sink(self, *evidence):
        from models.evidence import SinkAssessment
        return SinkAssessment(sink="x", label="X", evidence=list(evidence))

    def test_library_link_alone_is_low(self):
        from models.evidence import Evidence, LIBRARY
        a = self._sink(Evidence(LIBRARY, "SecurityFoundation", "SecurityFoundation"))
        self.assertEqual(a.confidence, "LOW")
        self.assertTrue(a.counts)

    def test_weak_link_and_loose_token_do_not_count(self):
        from models.evidence import Evidence, TOKEN, WEAK_LIBRARY
        a = self._sink(
            Evidence(WEAK_LIBRARY, "Network", "Network"),
            Evidence(TOKEN, "mount", "Failed to apply quarantine info to mount point"),
        )
        self.assertEqual(a.score, 0)
        self.assertFalse(a.counts)

    def test_entitlement_plus_import_is_high(self):
        from models.evidence import Evidence, ENTITLEMENT, IMPORT
        a = self._sink(
            Evidence(ENTITLEMENT, "com.apple.rootless.", "com.apple.rootless.volume.Preboot"),
            Evidence(IMPORT, "chmod", "chmod"),
        )
        self.assertEqual(a.confidence, "HIGH")

    def test_entitlement_alone_is_medium(self):
        from models.evidence import Evidence, ENTITLEMENT
        a = self._sink(Evidence(ENTITLEMENT, "com.apple.private.tcc.", "com.apple.private.tcc.allow"))
        self.assertEqual(a.confidence, "MEDIUM")

    def test_per_kind_cap_stops_one_class_dominating(self):
        from models.evidence import Evidence, IMPORT
        many = [Evidence(IMPORT, f"Sec{i}", f"Sec{i}") for i in range(10)]
        self.assertEqual(self._sink(*many).score, 16)  # 2 x 8, not 10 x 8


class TestStringMatchQuality(unittest.TestCase):
    def test_word_in_a_log_message_is_a_loose_token(self):
        from analyzers._match import string_match_quality
        self.assertEqual(
            string_match_quality("mount", "%.*s: Failed to apply quarantine info to mount point"),
            "token")

    def test_component_of_an_unrelated_path_is_a_loose_token(self):
        from analyzers._match import string_match_quality
        self.assertEqual(
            string_match_quality("system", "/System/Library/Sandbox/Profiles/system.sb"), "token")

    def test_bundle_identifier_component_is_evidence(self):
        from analyzers._match import string_match_quality
        self.assertEqual(
            string_match_quality("MobileSoftwareUpdate",
                                 "com.apple.MobileSoftwareUpdate.UpdateBrainService"), "identifier")


class TestValidationAxis(unittest.TestCase):
    def test_audit_token_and_entitlement_check_are_strong(self):
        from models.evidence import Evidence, IMPORT, validation_strength
        self.assertEqual(validation_strength([
            Evidence(IMPORT, "xpc_connection_get_audit_token", "xpc_connection_get_audit_token",
                     "audit-token-extraction", 5),
            Evidence(IMPORT, "SecTaskCopyValueForEntitlement", "SecTaskCopyValueForEntitlement",
                     "sectask-entitlement", 8),
        ]), "STRONG")

    def test_a_single_weak_class_is_weak(self):
        from models.evidence import Evidence, IMPORT, validation_strength
        self.assertEqual(validation_strength(
            [Evidence(IMPORT, "sandbox_check", "sandbox_check", "sandbox-check", 4)]), "WEAK")

    def test_nothing_observed(self):
        from models.evidence import validation_strength
        self.assertEqual(validation_strength([]), "NONE_OBSERVED")

    def test_validation_is_not_part_of_the_score(self):
        import json
        from utils.rules import scoring_rules
        ids = {r["id"] for r in scoring_rules()["rules"]}
        self.assertNotIn("caller_validation", ids)


class TestAspectWeighting(unittest.TestCase):
    """A primitive counts for the weaker of how well we saw it and what it means."""

    def test_path_resolution_import_is_capped(self):
        from models.evidence import Evidence, IMPORT
        ev = Evidence(IMPORT, "stat", "stat", "metadata", 2)
        self.assertEqual(ev.weight, 2)

    def test_mount_import_keeps_full_weight(self):
        from models.evidence import Evidence, IMPORT
        self.assertEqual(Evidence(IMPORT, "mount", "mount", "mount", 8).weight, 8)

    def test_a_loose_token_stays_worthless_whatever_it_means(self):
        from models.evidence import Evidence, TOKEN
        ev = Evidence(TOKEN, "mount", "Failed to apply quarantine info to mount point", "mount", 8)
        self.assertEqual(ev.weight, 0)

    def test_read_only_primitives_alone_do_not_reach_high(self):
        from models.evidence import Evidence, IMPORT, SinkAssessment
        a = SinkAssessment("filesystem", "FILESYSTEM", [
            Evidence(IMPORT, "stat", "stat", "metadata", 2),
            Evidence(IMPORT, "open", "open", "path-resolution", 2),
            Evidence(IMPORT, "fcntl", "fcntl", "path-resolution", 2),
        ])
        self.assertEqual(a.confidence, "LOW")

    def test_aspects_are_listed_strongest_first(self):
        from models.evidence import Evidence, IMPORT, SinkAssessment
        a = SinkAssessment("filesystem", "FILESYSTEM", [
            Evidence(IMPORT, "stat", "stat", "metadata", 2),
            Evidence(IMPORT, "unmount", "unmount", "mount", 8),
        ])
        self.assertEqual(a.aspects, ["mount", "metadata"])


class TestValidationAssessment(unittest.TestCase):
    """Validation is graded from weighted classes, like a sink."""

    def _ev(self, cls, weight, name):
        from models.evidence import Evidence, IMPORT
        return Evidence(IMPORT, name, name, cls, weight)

    def test_sandbox_check_alone_is_weak(self):
        from models.evidence import ValidationAssessment
        a = ValidationAssessment([self._ev("sandbox-check", 4, "sandbox_check")])
        self.assertEqual(a.confidence, "WEAK")
        self.assertEqual(a.score, 4)

    def test_audit_token_plus_sectask_is_strong(self):
        from models.evidence import ValidationAssessment
        a = ValidationAssessment([
            self._ev("audit-token-extraction", 5, "xpc_connection_get_audit_token"),
            self._ev("sectask-entitlement", 8, "SecTaskCopyValueForEntitlement"),
        ])
        self.assertEqual(a.confidence, "STRONG")

    def test_a_class_counts_once_however_many_symbols(self):
        from models.evidence import ValidationAssessment
        a = ValidationAssessment([
            self._ev("caller-identity", 3, "audit_token_to_euid"),
            self._ev("caller-identity", 3, "audit_token_to_pid"),
            self._ev("caller-identity", 3, "audit_token_to_ruid"),
        ])
        self.assertEqual(a.score, 3)

    def test_nothing_observed(self):
        from models.evidence import ValidationAssessment
        self.assertEqual(ValidationAssessment().confidence, "NONE_OBSERVED")

    def test_every_grade_carries_its_evidence(self):
        """No confidence label may exist without the evidence that produced it."""
        from models.evidence import ValidationAssessment
        a = ValidationAssessment([self._ev("entitlement-check", 5, "xpc_connection_copy_entitlement_value")])
        self.assertNotEqual(a.confidence, "NONE_OBSERVED")
        self.assertTrue(a.to_dict()["evidence_text"])
