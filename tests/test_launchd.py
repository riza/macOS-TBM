"""Tests for plist loading and launchd run-as derivation."""

from __future__ import annotations

import os
import plistlib
import tempfile
import unittest

import _paths  # noqa: F401

from collectors.launchd import _parse_plist, derive_run_as
from models.common import RunAs, ServiceScope, ServiceType
from utils.plist import load_plist


class TestPlist(unittest.TestCase):
    def test_load_binary_plist(self):
        data = {"Label": "com.example.test", "Program": "/usr/bin/true"}
        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as fh:
            plistlib.dump(data, fh, fmt=plistlib.FMT_BINARY)
            path = fh.name
        try:
            self.assertEqual(load_plist(path), data)
        finally:
            os.unlink(path)

    def test_load_missing_returns_none(self):
        self.assertIsNone(load_plist("/nonexistent/never.plist"))


class TestDeriveRunAs(unittest.TestCase):
    def test_daemon_defaults_root(self):
        run_as, user, _ = derive_run_as(ServiceScope.SYSTEM_DAEMON, ServiceType.DAEMON, None)
        self.assertEqual(run_as, RunAs.ROOT)
        self.assertEqual(user, "root")

    def test_daemon_with_username(self):
        run_as, user, deriv = derive_run_as(ServiceScope.SYSTEM_DAEMON, ServiceType.DAEMON, "_windowserver")
        self.assertEqual(run_as, RunAs.SPECIFIC_USER)
        self.assertEqual(user, "_windowserver")
        self.assertIn("_windowserver", deriv)

    def test_agent_defaults_current_user(self):
        run_as, user, _ = derive_run_as(ServiceScope.USER_AGENT, ServiceType.AGENT, None)
        self.assertEqual(run_as, RunAs.CURRENT_USER)
        self.assertIsNone(user)

    def test_unknown_scope(self):
        run_as, _, _ = derive_run_as(ServiceScope.UNKNOWN, ServiceType.UNKNOWN, None)
        self.assertEqual(run_as, RunAs.UNKNOWN)


class TestParsePlist(unittest.TestCase):
    def _write(self, data: dict) -> str:
        fh = tempfile.NamedTemporaryFile(suffix=".plist", delete=False)
        plistlib.dump(data, fh, fmt=plistlib.FMT_XML)
        fh.close()
        return fh.name

    def test_parse_basic(self):
        path = self._write(
            {
                "Label": "com.example.d",
                "Program": "/usr/libexec/exampled",
                "MachServices": {"com.example.mach": True, "com.example.mach2": False},
            }
        )
        try:
            svc = _parse_plist(path)
            self.assertEqual(svc.label, "com.example.d")
            self.assertEqual(svc.associated_executable, "/usr/libexec/exampled")
            self.assertEqual(sorted(svc.mach_services), ["com.example.mach", "com.example.mach2"])
            self.assertTrue(svc.exposes_ipc)
        finally:
            os.unlink(path)

    def test_program_arguments_fallback(self):
        path = self._write(
            {"Label": "x", "ProgramArguments": ["/usr/libexec/foo", "--bar"]}
        )
        try:
            svc = _parse_plist(path)
            self.assertEqual(svc.associated_executable, "/usr/libexec/foo")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
