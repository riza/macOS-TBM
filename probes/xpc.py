"""The live XPC backend, via ctypes against libxpc — no compile step.

Design choice (a) from the task: Python cannot call the XPC C API directly, so
we bind it with ctypes. libxpc has no on-disk ``.dylib`` on modern macOS (it
lives in the dyld shared cache), but its symbols are re-exported through the
already-loaded ``libSystem``, so ``ctypes.CDLL(None)`` resolves every one we
need. That avoids the fallback (a bundled C helper compiled to a temp dir): no
toolchain, no temp files, still stdlib-only.

The one awkward part is ``xpc_connection_set_event_handler``, which takes an
Objective-C *block*, not a C function pointer. We hand-build a global block
literal whose ``invoke`` slot is a ctypes callback — the documented, stable
block ABI.

This module is import-safe on any platform: if the symbols are missing it raises
``XPCUnavailable`` only when you actually try to probe, so the rest of the tool
(and the test suite, which mocks this backend) never depends on a live system.
"""

from __future__ import annotations

import ctypes
import threading
from typing import Any, Dict, Optional

VP = ctypes.c_void_p


class XPCUnavailable(RuntimeError):
    """Raised when the XPC C API cannot be reached (e.g. not on macOS)."""


class _Descriptor(ctypes.Structure):
    _fields_ = [("reserved", ctypes.c_ulong), ("size", ctypes.c_ulong)]


class _Block(ctypes.Structure):
    # The stable Objective-C block layout for a global, non-capturing block.
    _fields_ = [
        ("isa", VP),
        ("flags", ctypes.c_int),
        ("reserved", ctypes.c_int),
        ("invoke", VP),
        ("descriptor", ctypes.POINTER(_Descriptor)),
    ]


_INVOKE = ctypes.CFUNCTYPE(None, VP, VP)   # void (^)(void *block, xpc_object_t event)


def _bind():
    lib = ctypes.CDLL(None, use_errno=True)
    if not hasattr(lib, "xpc_connection_create_mach_service"):
        raise XPCUnavailable("libxpc symbols are not available in this process")

    sigs = {
        "xpc_connection_create_mach_service": (VP, [ctypes.c_char_p, VP, ctypes.c_uint64]),
        "xpc_connection_set_event_handler": (None, [VP, VP]),
        "xpc_connection_resume": (None, [VP]),
        "xpc_connection_cancel": (None, [VP]),
        "xpc_connection_send_message": (None, [VP, VP]),
        "xpc_release": (None, [VP]),
        "xpc_get_type": (VP, [VP]),
        "xpc_dictionary_create": (VP, [VP, VP, ctypes.c_size_t]),
        "xpc_dictionary_set_int64": (None, [VP, ctypes.c_char_p, ctypes.c_int64]),
        "xpc_dictionary_get_string": (ctypes.c_char_p, [VP, ctypes.c_char_p]),
        "dispatch_queue_create": (VP, [ctypes.c_char_p, VP]),
    }
    for name, (res, args) in sigs.items():
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = res, args
    return lib


class CtypesXPCBackend:
    """Probe Mach services with real XPC connections as an unprivileged client."""

    # xpc_connection_create_mach_service is called with flags 0: a plain client
    # connection, with none of the daemon/privileged listener flags. Running the
    # command as an unprivileged user is what makes the probe unprivileged; we do
    # not (and must not) request any elevation.
    _CLIENT_FLAGS = 0

    def __init__(self) -> None:
        self._lib = _bind()
        self._type_error = ctypes.cast(getattr(self._lib, "_xpc_type_error"), VP).value
        self._isa = ctypes.cast(getattr(self._lib, "_NSConcreteGlobalBlock"), VP)
        self.last_error: str = ""
        # Keep every block/queue alive for the process: dispatch may deliver a
        # trailing event after cancel, and a freed callback would crash.
        self._keepalive: list = []

    # -- block plumbing ----------------------------------------------------
    def _make_block(self, pyfn):
        cb = _INVOKE(pyfn)
        desc = _Descriptor(0, ctypes.sizeof(_Block))
        blk = _Block(self._isa, 1 << 28, 0, ctypes.cast(cb, VP), ctypes.pointer(desc))
        self._keepalive.extend((cb, desc, blk))
        return blk

    def _one(self, name: str, payload: Optional[Dict[str, int]], timeout: float, send: bool) -> str:
        lib = self._lib
        events: list = []
        signalled = threading.Event()

        def handler(_block, obj):
            is_error = lib.xpc_get_type(obj) == self._type_error
            message = None
            if is_error:
                raw = lib.xpc_dictionary_get_string(obj, b"XPCErrorDescription")
                message = raw.decode("utf-8", "replace") if raw else "error"
            events.append((is_error, message))
            signalled.set()

        block = self._make_block(handler)
        queue = lib.dispatch_queue_create(b"com.macostbm.probe", None)
        conn = lib.xpc_connection_create_mach_service(name.encode(), queue, self._CLIENT_FLAGS)
        if not conn:
            self.last_error = "could not create mach-service connection"
            return "invalid"

        lib.xpc_connection_set_event_handler(conn, ctypes.byref(block))
        lib.xpc_connection_resume(conn)
        if send:
            msg = lib.xpc_dictionary_create(None, None, 0)
            if payload:
                for key, value in payload.items():
                    lib.xpc_dictionary_set_int64(msg, key.encode(), int(value))
            lib.xpc_connection_send_message(conn, msg)

        got = signalled.wait(timeout)
        lib.xpc_connection_cancel(conn)

        if not got:
            self.last_error = ""
            return "alive" if not send else "silent"

        is_error, message = events[0]
        if not is_error:
            self.last_error = ""
            return "reply"
        self.last_error = message or "error"
        low = (message or "").lower()
        if "interrupt" in low:
            return "interrupted"
        if "invalid" in low:
            return "invalid"
        return "invalid"

    # -- backend interface used by probes.classify -------------------------
    def connect_probe(self, name: str, timeout: float) -> str:
        """Connect, resume, send nothing, hold open: ``invalid`` or ``alive``."""
        outcome = self._one(name, None, timeout, send=False)
        return "invalid" if outcome == "invalid" else "alive"

    def send_probe(self, name: str, payload: Optional[Dict[str, int]], timeout: float) -> str:
        """Send a dict and wait: ``invalid`` / ``interrupted`` / ``reply`` / ``silent``."""
        return self._one(name, payload, timeout, send=True)


def launchctl_liveness(run_fn: Any) -> Any:
    """Return a ``label -> bool`` liveness check backed by ``launchctl print``.

    Best-effort and read-only: a running provider has a ``pid = N`` line. Any
    failure (not root for that domain, no such service) reads as "not running".
    """
    def alive(label: str) -> bool:
        if not label:
            return False
        res = run_fn(["launchctl", "print", f"system/{label}"], timeout=5.0)
        if not getattr(res, "ok", False):
            return False
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("pid ="):
                return True
        return False
    return alive
