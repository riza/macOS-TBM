"""Find which scanned targets hold a given entitlement.

Works on an existing ``report.json``. A target "holds" an entitlement when it
appears in the target's ``entitlement_findings`` list or in its
``codesign.entitlements`` map. Read-only.
"""

from typing import List, Tuple


def _entitlement_keys(t: dict) -> List[Tuple[str, str]]:
    """(entitlement, evidence) pairs held by a target."""
    keys = []
    for f in t.get("entitlement_findings", []):
        name = f.get("entitlement") if isinstance(f, dict) else str(f)
        if name:
            keys.append((name, "findings"))
    cs = (t.get("executable") or {}).get("codesign") or t.get("codesign") or {}
    ents = cs.get("entitlements") or {}
    for k in ents:
        keys.append((k, "codesign"))
    return keys


def _row(t: dict, matching: List[str]) -> dict:
    svc = t.get("service", {})
    return {
        "label": t.get("label", "?"),
        "run_as": svc.get("run_as", "?"),
        "privileged": svc.get("privileged"),
        "score": t.get("score", 0),
        "validation": t.get("validation", "?"),
        "matching": matching,
        "mach_services": svc.get("mach_services", []),
    }


def _sort(rows: List[dict]) -> List[dict]:
    rows.sort(key=lambda r: (str(r["run_as"]) != "root", -int(r["score"] or 0)))
    return rows


def entowners_exact(report: dict, entitlement: str) -> List[dict]:
    """Targets holding exactly ``entitlement``."""
    rows = []
    for t in report.get("targets", []):
        for name, _how in _entitlement_keys(t):
            if name == entitlement:
                rows.append(_row(t, [name]))
                break
    return _sort(rows)


def entowners_contains(report: dict, needle: str) -> List[dict]:
    """Targets holding any entitlement whose key contains ``needle``."""
    rows = []
    for t in report.get("targets", []):
        matching = sorted({name for name, _h in _entitlement_keys(t) if needle in name})
        if matching:
            rows.append(_row(t, matching))
    return _sort(rows)
