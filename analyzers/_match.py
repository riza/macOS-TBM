"""Shared matching helpers for the analyzers.

Signal detection runs needles from ``rules/*.json`` against three evidence
pools:

* imported symbols (from ``nm -u``) and Objective-C class names (from ``nm``),
* interesting strings (filtered ``strings`` output),
* linked library / framework names (from ``otool -L``).

Matching is **name-aware**, not naive substring matching, and the rule differs
per pool:

* symbols, ObjC classes and library names are matched against the *whole* name.
  ``connect`` is the function ``connect``; it is not ``dispatch_mach_connect``
  and not ``xpc_connection_send_message``. ``Security`` is not
  ``libEndpointSecurity.dylib``.
* strings are free text, so a needle may match anywhere inside an entry as long
  as it sits on identifier-token boundaries.

A needle ending in ``*`` becomes a prefix match in both modes, so
``posix_spawn*`` still picks up ``posix_spawnattr_setflags`` and ``SecItem*``
picks up ``SecItemCopyMatching``.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable, List, Tuple

# A needle may only start where a previous identifier token ended.
_PREFIX_GUARD = r"(?<![A-Za-z0-9])"
# An exact needle may not be followed by more of the same identifier token.
_SUFFIX_GUARD = r"(?![A-Za-z0-9])"


@lru_cache(maxsize=8192)
def _pattern(needle: str, anchored: bool) -> "re.Pattern[str]":
    """Compile *needle* into a match pattern for one pool kind.

    ``anchored`` matches the whole name (symbols, ObjC classes, library names);
    otherwise the needle may appear anywhere inside an entry, on token
    boundaries (free-text strings). A trailing ``*`` is a prefix match in both
    modes.
    """
    prefix_match = needle.endswith("*")
    body = re.escape(needle[:-1] if prefix_match else needle)
    if anchored:
        return re.compile("^" + body + ("" if prefix_match else "$"))
    suffix = "" if prefix_match else _SUFFIX_GUARD
    return re.compile(_PREFIX_GUARD + body + suffix)


def _hits(haystack: Iterable[str], needle: str, anchored: bool) -> List[str]:
    pat = _pattern(needle, anchored)
    return [h for h in haystack if pat.search(h)]


def matched_needles(haystack: Iterable[str], needles: Iterable[str], anchored: bool = False) -> List[str]:
    """Return the *needles* that match at least one *haystack* entry."""
    hs = list(haystack)
    found: List[str] = []
    for needle in needles:
        if not needle:
            continue
        pat = _pattern(needle, anchored)
        if any(pat.search(h) for h in hs):
            found.append(needle)
    return found


def match_details(haystack: Iterable[str], needles: Iterable[str], anchored: bool = False) -> List[Tuple[str, str]]:
    """Return ``(needle, first matching entry)`` pairs.

    Findings quote the matching entry so a reader can tell a real hit from an
    accidental one without re-running the tool.
    """
    hs = list(haystack)
    out: List[Tuple[str, str]] = []
    for needle in needles:
        if not needle:
            continue
        hit = _hits(hs, needle, anchored)
        if hit:
            out.append((needle, hit[0]))
    return out


def match_all(symbols: Iterable[str], strings: Iterable[str], needles: Iterable[str]) -> List[Tuple[str, str]]:
    """Match *needles* against both pools, each with its own matching rule.

    A needle is evidence wherever it turns up: as an imported symbol, an ObjC
    class, or quoted in the binary's strings. Deduplicated by needle, symbol
    hits first because they are the stronger signal.
    """
    needles = list(needles)
    out = match_details(symbols, needles, anchored=True)
    seen = {n for n, _ in out}
    out += [(n, h) for n, h in match_details(strings, needles) if n not in seen]
    return out


def string_match_quality(needle: str, entry: str) -> str:
    """Classify how meaningful a hit in the free-text string pool is.

    ``"identifier"`` — the entry *is* the thing (``NSTask``,
    ``com.apple.MobileSoftwareUpdate.UpdateBrainService``,
    ``https://albert.apple.com/deviceservices/deviceActivation``): the needle is
    the whole entry, a dotted/slashed component of it, or its prefix.

    ``"token"`` — the needle is a word inside a sentence or an unrelated path
    (``mount`` in ``"Failed to apply quarantine info to mount point"``, ``system``
    in ``/System/Library/Sandbox/Profiles/system.sb``). Audited scans showed this
    class is noise, so callers weight it at zero.
    """
    core = needle[:-1] if needle.endswith("*") else needle
    if any(ch.isspace() for ch in entry):
        return "token"
    if entry == core:
        return "identifier"
    if entry.startswith("/"):
        # A filesystem path: matching one of its components says nothing about
        # the API. /System/Library/Sandbox/Profiles/system.sb is not system().
        return "token"
    if entry.startswith(core):
        return "identifier"
    # A component of a dotted identifier, a bundle id or a URL path.
    for part in re.split(r"[./:]+", entry):
        if part == core or part.startswith(core):
            return "identifier"
    return "token"


def library_names(libs: Iterable[str]) -> List[str]:
    """Reduce ``otool -L`` paths to the names a rule can match against.

    ``/System/Library/Frameworks/Security.framework/Versions/A/Security`` ->
    ``Security``; ``/usr/lib/libEndpointSecurity.dylib`` -> ``EndpointSecurity``
    (plus ``libEndpointSecurity``). Matching names rather than whole paths keeps
    ``/System/Library/...`` directory components out of the evidence pool.
    """
    names: List[str] = []
    seen = set()

    def add(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            names.append(name)

    for path in libs:
        base = path.rsplit("/", 1)[-1]
        for part in path.split("/"):
            if part.endswith(".framework"):
                add(part[: -len(".framework")])
        stem = base
        for suffix in (".dylib", ".so", ".a"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        # Trim the version suffix of names such as ``libarchive.2``.
        stem = re.sub(r"\.\d+$", "", stem)
        add(stem)
        if stem.startswith("lib") and len(stem) > 3:
            add(stem[3:])
    return names


def lib_has(libs: Iterable[str], needles: Iterable[str]) -> List[str]:
    """Return the library/framework needles present in *libs*."""
    return matched_needles(library_names(libs), needles, anchored=True)


def symbol_pool(macho) -> List[str]:
    """Build the symbol evidence pool from a :class:`MachOInfo` (or ``None``)."""
    if macho is None:
        return []
    return list(macho.imported_symbols) + list(macho.objc_classes)


def evidence_pool(macho) -> List[str]:
    """Symbols, ObjC classes and interesting strings in one pool."""
    if macho is None:
        return []
    return symbol_pool(macho) + list(macho.interesting_strings)
