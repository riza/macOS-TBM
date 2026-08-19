"""Loading of the configurable rule files (entitlements / signals / scoring)."""

from __future__ import annotations

import json
import os
from typing import Any, Optional

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")

_cache: dict[str, Any] = {}


def _path(name: str) -> str:
    return os.path.join(_RULES_DIR, name)


def load_json(name: str) -> Any:
    """Load ``rules/<name>`` with caching."""
    if name not in _cache:
        with open(_path(name), "r", encoding="utf-8") as fh:
            _cache[name] = json.load(fh)
    return _cache[name]


def entitlements_rules() -> dict:
    return load_json("entitlements.json")


def signals_rules() -> dict:
    return load_json("signals.json")


def scoring_rules() -> dict:
    return load_json("scoring.json")


def resolve_pattern(category: str) -> Optional[dict]:
    """Return the rule dict that maps *category* (unused; kept for API symmetry)."""
    return None
