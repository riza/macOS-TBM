"""Compile safe Mach-O fixtures and statically inspect them; never execute them."""

from __future__ import annotations

import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: F401
from test_capabilities import _service

from scanner import _analyze_executable, analyze_service
from utils.commands import ResultCache

SOURCE = Path(__file__).parent / "fixtures" / "research" / "native_calls.c"


def evaluate_native():
    if platform.system() != "Darwin" or not shutil.which("clang"):
        return {"status": "NOT_RUN", "reason": "macOS and clang required", "cases": []}
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        for arch in ("arm64", "x86_64"):
            for case, name in ((1, "controlled_path"), (2, "constant_path"), (3, "wrapper_path")):
                binary = Path(directory) / f"{arch}-{name}"
                command = ["clang", "-arch", arch, "-O0", "-fno-inline",
                           f"-DTBM_CASE={case}", str(SOURCE), "-o", str(binary)]
                subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
                executable = _analyze_executable(str(binary), ResultCache())
                target = analyze_service(_service(), executable)
                candidates = [f for f in target.capability_findings if f.sink_api == "open"]
                # The x86 wrapper return is an explicit unsupported case today.
                expected = ("SINK_CANDIDATE" if arch == "x86_64" and case == 3 else
                            "REACHABLE_SINK" if case == 2 else "CONTROLLED_SINK")
                observed = sorted({f.maturity_level for f in candidates})
                passed = (expected in observed and all(f.proven_primitive is None for f in candidates)
                          and executable.identity["status"] == "STABLE")
                rows.append({"arch": arch, "name": name, "expected": expected,
                             "observed": observed, "passed": passed,
                             "binary_sha256": executable.identity["after_analysis"]["sha256"],
                             "unknown_reasons": sorted({r for f in candidates for r in f.unknown_reasons})})
    return {"status": "COMPLETE", "cases": rows,
            "limitations": ["O0 fixtures only; launchd identity is simulated",
                            "No runtime operation, authorization or post-condition tested",
                            "x86_64 wrapper return remains unresolved"]}


@unittest.skipUnless(platform.system() == "Darwin" and shutil.which("clang"), "macOS/clang required")
class TestNativeBinaryCorpus(unittest.TestCase):
    def test_compiled_arm64_and_x86_fixtures(self):
        result = evaluate_native()
        for row in result["cases"]:
            with self.subTest(arch=row["arch"], case=row["name"]):
                self.assertTrue(row["passed"], row)
