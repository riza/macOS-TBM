"""Evaluate portable evidence contracts, without scanning or probing a host."""

from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT))

from test_native_binary_corpus import evaluate_native  # noqa: E402
from test_research_corpus import evaluate  # noqa: E402

from utils.provenance import research_provenance  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="save evaluation JSON")
    args = parser.parse_args()
    rows = evaluate()
    binary_results = evaluate_native()
    # Native guards/arguments/dispatch have a separate contract corpus.
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for module in ("test_capabilities", "test_control_flow", "test_xpc_dispatch",
                   "test_descriptor_provenance", "test_callgraph", "test_research_corpus"):
        suite.addTests(loader.loadTestsFromName(module))
    native = unittest.TextTestRunner(stream=sys.stderr).run(suite)
    result = {
        "evaluation_kind": "AUTHORED_CONTRACT_FIXTURES",
        "limitations": ["Not a real-daemon precision/recall benchmark",
                        "r2 responses are authored, not captured from installed radare2",
                        "Compiled native fixtures use simulated launchd metadata and O0 only"],
        "provenance": research_provenance(),
        "native_binaries": binary_results,
        "r2_cases": rows, "contract_tests_run": native.testsRun,
        "contract_tests_passed": native.wasSuccessful(),
    }
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
    else:
        print(output, end="")
    return int(not (all(row["passed"] for row in rows)
                    and all(row["passed"] for row in binary_results["cases"])
                    and native.wasSuccessful()))


if __name__ == "__main__":
    raise SystemExit(main())
