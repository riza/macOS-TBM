"""Code-signing collection via ``codesign`` (read-only).

Extracts signer identifier, team identifier, flags, authority chain, designated
requirement, platform-binary heuristic, and entitlements. All failures are
captured in ``errors`` and never raised.
"""

from __future__ import annotations

import logging
import os
import re
from typing import List, Optional

from models.executable import CodeSigningInfo
from utils import plist as plist_util
from utils.commands import ResultCache, run

log = logging.getLogger(__name__)

_FLAGS_RE = re.compile(r"flags=0x[0-9a-fA-F]+\(([^)]*)\)")
_IDENT_RE = re.compile(r"^Identifier=(.+)$", re.MULTILINE)
_TEAM_RE = re.compile(r"^TeamIdentifier=(.+)$", re.MULTILINE)
_DR_RE = re.compile(r"^Designated Requirement=(\S.*)$", re.MULTILINE)
_AUTH_RE = re.compile(r"^Authority=(.+)$", re.MULTILINE)
_PLATFORM_RE = re.compile(r"^Platform=(.+)$", re.MULTILINE)


def _parse_flags(text: str) -> List[str]:
    m = _FLAGS_RE.search(text)
    if not m:
        return []
    return [f.strip() for f in m.group(1).split(",") if f.strip()]


def _extract_entitlements(text: str):
    """Parse entitlements XML from ``codesign`` output.

    ``codesign -d --entitlements :-`` may prefix the XML with an ``Executable=``
    line and a deprecation warning. We locate the first ``<?xml``/``<plist``
    marker and parse only the plist document (up to ``</plist>``), dropping any
    trailing tool output that would otherwise break the parser.
    """
    if not text:
        return None
    for marker in ("<?xml", "<plist", "<dict"):
        idx = text.find(marker)
        if idx == -1:
            continue
        end = text.find("</plist>", idx)
        chunk = text[idx:end + len("</plist>")] if end != -1 else text[idx:]
        parsed = plist_util.load_plist_bytes(chunk.encode("utf-8"))
        if parsed is not None:
            return parsed
    return None


def _cache_key(path: str) -> str:
    try:
        st = os.stat(path)
        return f"codesign:{path}:{st.st_size}:{int(st.st_mtime)}"
    except OSError:
        return f"codesign:{path}:missing"


def inspect_codesign(path: str, cache: Optional[ResultCache] = None) -> CodeSigningInfo:
    """Run ``codesign`` against *path* and return normalized metadata."""
    key = _cache_key(path)
    if cache is not None and key in cache:
        return cache.get(key)

    info = CodeSigningInfo(path=path)

    # Detailed info (identifiers, flags, authority, DR) arrives on stderr.
    res = run(["codesign", "-dvvv", "--verbose=4", "--", path], timeout=30.0)
    text = res.stdout + "\n" + res.stderr

    if res.not_found:
        info.errors.append("codesign not available")
        _store(cache, key, info)
        return info
    if res.timed_out:
        info.errors.append("codesign timed out")
        _store(cache, key, info)
        return info

    if res.returncode != 0 and "not signed" in text.lower():
        info.is_signed = False
        _store(cache, key, info)
        return info

    info.is_signed = res.returncode == 0

    m = _IDENT_RE.search(text)
    if m:
        info.signer_identifier = m.group(1).strip()
    m = _TEAM_RE.search(text)
    if m:
        team = m.group(1).strip()
        info.team_identifier = None if team in ("not set", "none", "") else team
    m = _DR_RE.search(text)
    if m:
        info.designated_requirement = m.group(1).strip()
    info.flags = _parse_flags(text)
    info.authority = _AUTH_RE.findall(text)

    # Platform binary heuristic: Apple root in the chain, or an Apple bundle id.
    if info.signer_identifier and info.signer_identifier.startswith("com.apple."):
        info.platform_binary = True
    elif any("Apple Root CA" in a or "Apple Code Signing" in a for a in info.authority):
        info.platform_binary = True
    else:
        info.platform_binary = False  # we could not confirm platform status -> treat as non-platform heuristic

    # Entitlements (XML or binary plist; prefer stdout, fall back to stderr).
    ent_res = run(["codesign", "-d", "--entitlements", ":-", "--", path], timeout=30.0)
    if ent_res.ok:
        parsed = _extract_entitlements(ent_res.stdout) or _extract_entitlements(ent_res.stderr)
        if isinstance(parsed, dict):
            info.entitlements = parsed
        elif ent_res.stdout.strip():
            info.errors.append("entitlements present but unparseable")
    elif ent_res.returncode != 0:
        # No entitlements is normal; record only if it actually errored.
        info.errors.append(f"entitlements query failed (rc={ent_res.returncode})")

    _store(cache, key, info)
    return info


def _store(cache: Optional[ResultCache], key: str, info: CodeSigningInfo) -> CodeSigningInfo:
    if cache is not None:
        cache.put(key, info)
    return info
