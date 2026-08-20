"""Active probing of exposed Mach services.

Everything else in macOS-TBM is read-only static analysis. This package is the
one exception: it *connects* to Mach services as an unprivileged client to see
which ones an unprivileged process can actually reach. It is opt-in, lives
behind the separate ``tbm probe`` subcommand, and never runs during a scan.
"""

from .classify import (
    BUCKETS,
    REACHABLE_BUCKETS,
    classify,
    format_json,
    format_text,
    probe_service,
    run_probe,
    services_from_report,
    summarize,
)

__all__ = [
    "BUCKETS",
    "REACHABLE_BUCKETS",
    "classify",
    "format_json",
    "format_text",
    "probe_service",
    "run_probe",
    "services_from_report",
    "summarize",
]
