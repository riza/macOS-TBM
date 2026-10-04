"""Read-only provenance; failures remain explicit rather than invented identity."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from app_info import VERSION, build_id
from utils.commands import run, which
from utils.rules import _RULES_DIR, load_json


def binary_identity(path: str) -> dict:
    try:
        with open(path, "rb") as stream:
            before = os.fstat(stream.fileno())
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
            after = os.fstat(stream.fileno())
        def stamp(stat):
            return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
        if stamp(before) != stamp(after):
            return {"status": "CHANGED_DURING_HASH", "sha256": None}
        return {"status": "HASHED", "sha256": digest.hexdigest(),
                "size": after.st_size, "mtime_ns": after.st_mtime_ns}
    except OSError as exc:
        return {"status": "UNAVAILABLE", "sha256": None, "error": str(exc)}


def research_provenance(include_radare2: bool = False) -> dict:
    rules = {}
    for path in sorted(Path(_RULES_DIR).glob("*.json")):
        # Hash the same parsed/cached content consumed by the analyzers.
        encoded = json.dumps(load_json(path.name), sort_keys=True,
                             separators=(",", ":")).encode()
        rules[path.name] = hashlib.sha256(encoded).hexdigest()
    build = None
    if platform.system() == "Darwin":
        try:
            proc = subprocess.run(["/usr/bin/sw_vers", "-buildVersion"],
                                  capture_output=True, text=True, timeout=2, check=False)
            build = proc.stdout.strip() if proc.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        binding = version("r2pipe")
    except PackageNotFoundError:
        binding = None
    radare_version = None
    if include_radare2:
        executable = which("r2") or which("radare2")
        if executable:
            result = run([executable, "-v"], timeout=2)
            if result.ok and result.stdout.strip():
                radare_version = result.stdout.strip().splitlines()[0]
    source_root = Path(__file__).resolve().parents[1]
    files = [source_root / name for name in
             ("app_info.py", "deputy_all.py", "entowners.py", "hunt.py", "scanner.py",
              "tbm.py", "ui.py", "xref.py")]
    for package in ("analyzers", "backends", "collectors", "graph", "models", "reporting", "utils"):
        files.extend((source_root / package).rglob("*.py"))
    code_hash = hashlib.sha256()
    for path in sorted(files):
        code_hash.update(str(path.relative_to(source_root)).encode() + b"\0")
        code_hash.update(path.read_bytes())
        code_hash.update(b"\0")
    return {"tool_version": VERSION, "code_sha256": code_hash.hexdigest(), "source_build": build_id(),
            "host": {"system": platform.system(), "release": platform.release(),
                     "macos_version": platform.mac_ver()[0] or None,
                     "macos_build": build, "machine": platform.machine()},
            "python_version": platform.python_version(), "r2pipe_version": binding,
            "radare2_version": radare_version,
            "rules_sha256": rules, "rules_hash_encoding": "canonical-json-sort-keys"}
