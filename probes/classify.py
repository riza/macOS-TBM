"""Reachability classification and output — the backend-independent half.

The XPC C calls live in :mod:`probes.xpc`. Everything here is pure: given the
raw outcomes of the sub-probes it decides one bucket, and it formats rows. That
split is what lets the tests exercise the classification and the table without
touching a live system or root.

Per service we run up to three sub-probes as an unprivileged client:

* **connect-only** — create the mach-service connection, resume, send nothing,
  hold it open for ``timeout``. Outcome is ``invalid`` (bootstrap lookup or
  connect error) or ``alive`` (accepted, stayed up).
* **empty** — send an empty dictionary. Outcome is ``invalid`` /
  ``interrupted`` (peer accepted then dropped us) / ``reply`` / ``silent``.
* **malformed** — send a one-key dictionary. Same outcome set.

plus a best-effort liveness check on the provider process.

The buckets, and why each matters for LPE triage:

``spawn``                 the peer answered or the daemon is up and tolerated us
``connect-alive``         connection accepted, held open, never dropped us
``empty-interrupted``     empty message → "Connection interrupted" (reachable, rejects us early)
``malformed-interrupted`` one-key message → "Connection interrupted"
``timeout``               a send drew neither reply nor error and nothing spawned
``unreachable``           bootstrap lookup / connect failed ("Connection invalid")

``connect-alive`` and ``empty-interrupted`` are the "actually reachable" set: an
unprivileged client got far enough to talk to a privileged peer.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Sequence

BUCKETS = [
    "spawn",
    "connect-alive",
    "empty-interrupted",
    "malformed-interrupted",
    "timeout",
    "unreachable",
]

# The set we care about most: an unprivileged client reached a privileged peer.
REACHABLE_BUCKETS = ("connect-alive", "empty-interrupted")


def classify(connect: str, empty: str, malformed: str, spawned: bool = False) -> str:
    """Reduce the sub-probe outcomes to exactly one bucket.

    ``connect`` in {``invalid``, ``alive``}; ``empty`` and ``malformed`` in
    {``invalid``, ``interrupted``, ``reply``, ``silent``}. ``spawned`` is whether
    the provider process was seen running after probing.

    Interrupts rank above ``spawn`` on purpose: "reachable but the peer dropped
    us" is a sharper triage signal than "the daemon is up", and an always-on
    daemon is up regardless of us.

    ``timeout`` is the fallback for a degenerate case — a connection that never
    resolved to ``invalid`` or ``alive`` within the window — so in a live run the
    common outcomes are the other five.
    """
    if connect == "invalid":
        return "unreachable"
    if empty == "interrupted":
        return "empty-interrupted"
    if malformed == "interrupted":
        return "malformed-interrupted"
    if empty == "reply" or malformed == "reply":
        return "spawn"
    if spawned:
        return "spawn"
    if connect == "alive":
        return "connect-alive"
    return "timeout"


def services_from_report(report: Dict[str, Any],
                         only: Optional[Sequence[str]] = None) -> List[Dict[str, str]]:
    """Extract the root/system Mach services worth probing from a report.

    A service qualifies when it runs as root and registers at least one Mach
    service. *only*, if given, keeps just the providers whose label contains one
    of the substrings (mirroring ``tbm service``).
    """
    wanted = [s.lower() for s in only] if only else None
    out: List[Dict[str, str]] = []
    seen = set()
    for target in report.get("targets") or []:
        svc = target.get("service") or {}
        run_as = svc.get("run_as_user") or svc.get("run_as") or "?"
        if run_as != "root":
            continue
        label = svc.get("label", target.get("label", ""))
        if wanted and not any(w in label.lower() for w in wanted):
            continue
        for name in svc.get("mach_services") or []:
            if name in seen:
                continue
            seen.add(name)
            out.append({"mach_service": name, "provider_label": label, "run_as": run_as})
    return out


def probe_service(backend: Any, mach_service: str, provider_label: str, run_as: str,
                  timeout: float = 3.0, liveness: Optional[Callable[[str], bool]] = None) -> Dict[str, Any]:
    """Probe one Mach service and return a result row.

    *backend* exposes ``connect_probe(name, timeout)`` and
    ``send_probe(name, payload, timeout)`` (see :mod:`probes.xpc`). *liveness*,
    if given, maps a provider label to whether its process is running.
    """
    connect = backend.connect_probe(mach_service, timeout)
    empty = malformed = "skipped"
    error_message = ""

    if connect == "invalid":
        # No point sending into a name that does not resolve.
        empty = malformed = "invalid"
        error_message = backend.last_error or "Connection invalid"
    else:
        empty = backend.send_probe(mach_service, None, timeout)
        error_message = backend.last_error or error_message
        if empty not in ("interrupted", "reply"):
            malformed = backend.send_probe(mach_service, {"tbm_probe": 1}, timeout)
            error_message = backend.last_error or error_message

    spawned = bool(liveness(provider_label)) if liveness else False
    classification = classify(connect, empty, malformed, spawned)

    return {
        "mach_service": mach_service,
        "provider_label": provider_label,
        "run_as": run_as,
        "classification": classification,
        "error_message": error_message if classification != "unreachable" or error_message
        else "Connection invalid",
        "detail": {"connect": connect, "empty": empty, "malformed": malformed, "spawned": spawned},
    }


def run_probe(services: Sequence[Dict[str, str]], backend: Any, timeout: float = 3.0,
              limit: Optional[int] = None, liveness: Optional[Callable[[str], bool]] = None,
              progress: Optional[Callable[[int, int], None]] = None) -> List[Dict[str, Any]]:
    """Probe every ``(mach_service, provider_label, run_as)`` in *services*."""
    selected = list(services)[: limit] if limit else list(services)
    rows: List[Dict[str, Any]] = []
    for i, svc in enumerate(selected, 1):
        rows.append(probe_service(
            backend, svc["mach_service"], svc.get("provider_label", ""),
            svc.get("run_as", "?"), timeout=timeout, liveness=liveness))
        if progress:
            progress(i, len(selected))
    return rows


def summarize(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Counts per bucket plus the reachable shortlist."""
    counts = {b: 0 for b in BUCKETS}
    for row in rows:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
    shortlist = [
        {"mach_service": r["mach_service"], "provider_label": r["provider_label"],
         "classification": r["classification"]}
        for r in rows if r["classification"] in REACHABLE_BUCKETS
    ]
    return {"total": len(rows), "counts": counts, "reachable": shortlist}


def format_json(rows: Sequence[Dict[str, Any]]) -> str:
    columns = ["mach_service", "provider_label", "run_as", "classification", "error_message"]
    payload = {
        "probed": len(rows),
        "results": [{k: r[k] for k in columns} for r in rows],
        "summary": summarize(rows),
    }
    return json.dumps(payload, indent=2)


def format_text(rows: Sequence[Dict[str, Any]]) -> str:
    if not rows:
        return "no root/system Mach services to probe."
    lines = [
        f"Probed {len(rows)} Mach service(s) as an unprivileged client "
        f"(ACTIVE — this command sends real XPC messages).\n",
        f"  {'MACH SERVICE':52} {'PROVIDER':26} {'RUN AS':8} {'CLASSIFICATION':22} ERROR",
    ]
    order = {b: i for i, b in enumerate(BUCKETS)}
    for r in sorted(rows, key=lambda x: (order.get(x["classification"], 99), x["mach_service"])):
        lines.append(
            f"  {r['mach_service'][:52]:52} {r['provider_label'][:26]:26} "
            f"{r['run_as'][:8]:8} {r['classification']:22} {r['error_message']}")

    summary = summarize(rows)
    lines.append("\nclassification summary:")
    for bucket in BUCKETS:
        count = summary["counts"].get(bucket, 0)
        if count:
            lines.append(f"  {bucket:22} {count}")

    reachable = summary["reachable"]
    lines.append(f"\nactually reachable ({len(reachable)}): "
                 f"connect-alive + empty-interrupted — an unprivileged client reached a privileged peer")
    if reachable:
        for item in reachable:
            lines.append(f"  {item['classification']:22} {item['mach_service']}  "
                         f"({item['provider_label']})")
    else:
        lines.append("  (none)")
    return "\n".join(lines)
