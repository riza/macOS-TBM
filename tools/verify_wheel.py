"""Install a built wheel outside the checkout and verify its stdlib-only CLI."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import venv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--schema", type=Path, help="also validate report with jsonschema (optional dependency)")
    args = parser.parse_args()
    wheel = args.wheel.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="tbm-wheel-") as directory:
        root = Path(directory)
        venv.EnvBuilder(with_pip=True).create(root / "venv")
        binaries = root / "venv" / ("Scripts" if os.name == "nt" else "bin")
        python = binaries / ("python.exe" if os.name == "nt" else "python")
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("TBM_BUILD", None)

        def run(command):
            return subprocess.run(command, cwd=root, env=env, check=True,
                                  capture_output=True, text=True, timeout=60)

        run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)])
        for arguments in (["--version"], ["--help"], ["scan", "--help"], ["graph", "--help"]):
            run([str(binaries / "tbm"), *arguments])
        code = '''
from pathlib import Path
import tbm
import json
from models.common import ServiceScope, ServiceType
from models.service import LaunchService
from models.executable import Executable
from scanner import analyze_service
from utils.rules import capability_rules, entitlements_rules, signals_rules, scoring_rules, lpe_rules, rce_rules
from reporting.json_report import build_report
from reporting.html_report import write_html_report
assert "site-packages" in str(Path(tbm.__file__).resolve())
for loader in (capability_rules, entitlements_rules, signals_rules, scoring_rules, lpe_rules, rce_rules):
    assert loader(), loader.__name__
service = LaunchService(label="com.example.fixture", plist_path="fixture.plist",
                        service_type=ServiceType.DAEMON, scope=ServiceScope.LOCAL_DAEMON)
fixture = analyze_service(service, Executable(path="fixture"))
report = build_report([fixture], meta={"scan_options": {"deep_analysis": None, "runtime_probe": False}})
assert report["schema_version"] == "2.2"
assert len(report["provenance"]["rules_sha256"]) == 6
assert len(report["targets"]) == 1
Path("report.json").write_text(json.dumps(report))
write_html_report("report.html", report)
assert Path("report.html").stat().st_size > 10000
print("Installed wheel: CLI, six rule sets, schema 2.2 and HTML assembly passed")
'''
        print(run([str(python), "-c", code]).stdout, end="")
        if args.schema:
            from jsonschema import Draft202012Validator
            schema = json.loads(args.schema.read_text())
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(json.loads((root / "report.json").read_text()))
            print("Report envelope validated against JSON schema")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
