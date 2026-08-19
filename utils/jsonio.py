"""JSON serialization helpers that tolerate plist-derived non-primitive values.

Entitlement and launchd-plist values can contain ``bytes`` (plist ``<data>``)
or ``datetime`` objects (plist ``<date>``). Plain ``json.dumps`` raises on these;
this module provides a ``default`` hook and ``dumps`` wrapper so a single odd
value can never abort report generation.
"""

from __future__ import annotations

import base64
import datetime
import json
from typing import Any


def json_default(obj: Any) -> Any:
    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(bytes(obj)).decode("ascii")
    if isinstance(obj, (datetime.datetime, datetime.date, datetime.time)):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    # Last resort: stringify anything else unknown.
    try:
        return str(obj)
    except Exception:
        return repr(obj)


def dumps(obj: Any, indent: int = 2) -> str:
    return json.dumps(obj, indent=indent, default=json_default)
