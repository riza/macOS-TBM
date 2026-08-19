"""launchd job discovery and plist parsing.

Enumerates the standard launchd job directories and parses each plist into a
:class:`LaunchService`. Binary plists are handled via :mod:`plistlib` (and
``plutil`` fallback). Run-as classification is derived explicitly and recorded
in ``run_as_derivation`` so the reasoning is always visible.
"""

from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from models.common import RunAs, ServiceScope, ServiceType
from models.service import LaunchService
from utils import plist as plist_util
from utils.commands import run

log = logging.getLogger(__name__)

# (directory, ServiceScope, ServiceType, default_run_as)
LAUNCHD_ROOTS: List[Tuple[str, ServiceScope, ServiceType]] = [
    ("/System/Library/LaunchDaemons", ServiceScope.SYSTEM_DAEMON, ServiceType.DAEMON),
    ("/Library/LaunchDaemons", ServiceScope.LOCAL_DAEMON, ServiceType.DAEMON),
    ("/System/Library/LaunchAgents", ServiceScope.SYSTEM_AGENT, ServiceType.AGENT),
    ("/Library/LaunchAgents", ServiceScope.LOCAL_AGENT, ServiceType.AGENT),
    (os.path.expanduser("~/Library/LaunchAgents"), ServiceScope.USER_AGENT, ServiceType.AGENT),
]


def _is_daemon(service_type: ServiceType) -> bool:
    return service_type == ServiceType.DAEMON


def resolve_conditional(value: Any) -> Tuple[Any, Optional[str]]:
    """Resolve a launchd conditional value to ``(value, note)``.

    Newer system plists express keys as feature-flag conditionals, e.g.
    ``UserName = {"#IfFeatureFlagEnabled": "Spotlight/RoleUserIndexDaemon",
    "#Then": "_mds_stores"}``. Stringifying that dict produced nonsense identities
    such as ``[object Object]``, so the ``#Then``/``#Else`` branch is taken and
    the condition is recorded instead.
    """
    if not isinstance(value, dict):
        return value, None
    cond = next((k for k in value if isinstance(k, str) and k.startswith("#If")), None)
    if cond is None:
        return None, None
    branch = value.get("#Then", value.get("#Else"))
    resolved, _ = resolve_conditional(branch)
    return resolved, f"conditional on {cond}={value.get(cond)!r}"


def _str_or_none(value: Any) -> Optional[str]:
    return str(value) if isinstance(value, (str, int)) else None


@lru_cache(maxsize=4)
def _launchd_overrides(domain: str) -> Dict[str, bool]:
    """Read launchd's disable overrides for *domain* (``system`` / ``user/501``).

    The override database wins over the plist ``Disabled`` key, in both
    directions: ``launchctl disable`` turns off a plist-enabled job, and
    ``launchctl enable`` turns on a plist-disabled one (that is how Remote Login
    enables ``com.openssh.sshd``).
    """
    res = run(["launchctl", "print-disabled", domain], timeout=15.0)
    if not res.ok:
        log.debug("launchctl print-disabled %s failed", domain)
        return {}
    return {
        m.group(1): m.group(2) == "disabled"
        for m in re.finditer(r'"([^"]+)"\s*=>\s*(disabled|enabled)', res.stdout)
    }


def overrides_for(service_type: ServiceType) -> Dict[str, bool]:
    """Override table for the domain a job of *service_type* lives in."""
    if service_type == ServiceType.DAEMON:
        return _launchd_overrides("system")
    return _launchd_overrides(f"user/{os.getuid()}")


def derive_enabled(label: str, service_type: ServiceType, plist_disabled: Any) -> Tuple[bool, str]:
    """Decide whether a job is actually loadable, and explain why."""
    override = overrides_for(service_type).get(label)
    if override is not None:
        return (not override), (
            f"launchd override database marks it {'disabled' if override else 'enabled'}"
        )
    disabled, note = resolve_conditional(plist_disabled)
    if disabled is True:
        return False, "plist sets Disabled=true and no launchd override re-enables it" + (
            f" ({note})" if note else ""
        )
    return True, "no Disabled key and no launchd override"


def derive_run_as(scope: ServiceScope, service_type: ServiceType, user_name: Optional[str]) -> Tuple[RunAs, Optional[str], str]:
    """Classify run-as identity and record the reasoning.

    LaunchDaemons run as root by default *unless* a ``UserName`` is specified.
    LaunchAgents run as the user that loaded them (typically the current user)
    unless a ``UserName`` is specified. If a ``UserName`` is present, the job
    runs as that specific user. We never infer root without explaining why.
    """
    if user_name:
        return (
            RunAs.SPECIFIC_USER,
            user_name,
            f"plist specifies UserName={user_name!r}",
        )
    if service_type == ServiceType.DAEMON:
        return (
            RunAs.ROOT,
            "root",
            "LaunchDaemon with no UserName; launchd runs daemons as root by default",
        )
    if service_type == ServiceType.AGENT:
        return (
            RunAs.CURRENT_USER,
            None,
            "LaunchAgent with no UserName; runs as the user that loaded it (current user)",
        )
    return RunAs.UNKNOWN, None, "could not derive run-as identity"


def _extract_mach_services(data: dict) -> List[str]:
    """Collect Mach service names from a plist ``MachServices`` dict."""
    services: List[str] = []
    raw = data.get("MachServices")
    if isinstance(raw, dict):
        for name, value in raw.items():
            # Names are keys; value True/False/dict indicates registration.
            services.append(name)
    return services


def _resolve_executable(data: dict, program_arguments: List[str]) -> Optional[str]:
    """Return the primary executable path for a job, or ``None`` if unknown."""
    prog = data.get("Program")
    if prog:
        return prog
    if program_arguments:
        return program_arguments[0]
    return None


def _parse_plist(path: str) -> Optional[LaunchService]:
    data = plist_util.load_plist(path)
    if not isinstance(data, dict):
        log.debug("skipping non-dict plist: %s", path)
        return None

    # Determine scope/type from directory.
    dirname = os.path.dirname(path)
    scope = ServiceScope.UNKNOWN
    service_type = ServiceType.UNKNOWN
    for root, sc, st in LAUNCHD_ROOTS:
        if dirname == root:
            scope = sc
            service_type = st
            break

    program_arguments = list(data.get("ProgramArguments", []) or [])
    label_key = data.get("Label")
    if not label_key and not data.get("Program") and not program_arguments:
        # Not a launchd job: config payloads such as
        # com.apple.jetsamproperties.Mac.plist and leftover empty plists live in
        # these directories but declare no label and no program.
        log.debug("skipping non-job plist (no Label, no Program): %s", path)
        return None
    label = label_key or os.path.basename(path)[: -len(".plist")]

    user_name, user_note = resolve_conditional(data.get("UserName"))
    group_name, _ = resolve_conditional(data.get("GroupName"))
    user_name = _str_or_none(user_name)
    group_name = _str_or_none(group_name)
    run_as, run_as_user, derivation = derive_run_as(scope, service_type, user_name)
    if user_note:
        derivation = f"{derivation}; {user_note}"

    enabled, enabled_derivation = derive_enabled(str(label), service_type, data.get("Disabled"))

    xpc_service = data.get("ServiceType", "") == "XPC" or data.get("_ServiceType") == "XPC"

    svc = LaunchService(
        label=str(label),
        plist_path=path,
        service_type=service_type,
        scope=scope,
        program=data.get("Program"),
        program_arguments=[str(a) for a in program_arguments],
        user_name=str(user_name) if user_name is not None else None,
        group_name=str(group_name) if group_name is not None else None,
        mach_services=_extract_mach_services(data),
        sockets=data.get("Sockets", {}) if isinstance(data.get("Sockets"), dict) else {},
        keep_alive=data.get("KeepAlive"),
        run_at_load=bool(data.get("RunAtLoad", False)),
        environment_variables=dict(data.get("EnvironmentVariables", {}) or {}),
        associated_executable=_resolve_executable(data, program_arguments),
        xpc_service=xpc_service,
        run_as=run_as,
        run_as_user=run_as_user,
        run_as_derivation=derivation,
        enabled=enabled,
        enabled_derivation=enabled_derivation,
        raw=data,
    )
    return svc


def discover_services(roots: Optional[List[str]] = None) -> List[LaunchService]:
    """Discover launchd jobs under *roots* (defaults to the standard locations).

    A malformed or unreadable plist is skipped, never fatal.
    """
    if roots is None:
        roots = [r for r, _, _ in LAUNCHD_ROOTS]
    services: List[LaunchService] = []
    for root in roots:
        if not os.path.isdir(root):
            log.debug("launchd root missing: %s", root)
            continue
        try:
            entries = sorted(os.listdir(root))
        except OSError as exc:
            log.warning("cannot list %s: %s", root, exc)
            continue
        for entry in entries:
            if not entry.endswith(".plist"):
                continue
            path = os.path.join(root, entry)
            try:
                svc = _parse_plist(path)
            except Exception as exc:  # noqa: BLE001 - per-file isolation
                log.warning("failed to parse %s: %s", path, exc)
                continue
            if svc is not None:
                services.append(svc)
    return services
