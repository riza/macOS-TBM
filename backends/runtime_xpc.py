"""Explicitly opt-in, conservative macOS XPC/Mach reachability backend.

Default probing creates/resumes/cancels a client connection and sends no
message. An empty dictionary is sent only when ``send_empty`` is explicitly
enabled. No arbitrary fields, fuzzing, destructive operation or elevation is
implemented here.
"""

from __future__ import annotations

import ctypes
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List

VP = ctypes.c_void_p


class RuntimeProbeUnavailable(RuntimeError):
    pass


class _Descriptor(ctypes.Structure):
    _fields_ = [("reserved", ctypes.c_ulong), ("size", ctypes.c_ulong)]


class _Block(ctypes.Structure):
    _fields_ = [("isa", VP), ("flags", ctypes.c_int), ("reserved", ctypes.c_int),
                ("invoke", VP), ("descriptor", ctypes.POINTER(_Descriptor))]


_INVOKE = ctypes.CFUNCTYPE(None, VP, VP)


def _bind():
    lib = ctypes.CDLL(None, use_errno=True)
    if not hasattr(lib, "xpc_connection_create_mach_service"):
        raise RuntimeProbeUnavailable("libxpc is unavailable")
    signatures = {
        "xpc_connection_create_mach_service": (VP, [ctypes.c_char_p, VP, ctypes.c_uint64]),
        "xpc_connection_set_event_handler": (None, [VP, VP]),
        "xpc_connection_resume": (None, [VP]),
        "xpc_connection_cancel": (None, [VP]),
        "xpc_connection_send_message": (None, [VP, VP]),
        "xpc_get_type": (VP, [VP]),
        "xpc_dictionary_create": (VP, [VP, VP, ctypes.c_size_t]),
        "xpc_dictionary_get_string": (ctypes.c_char_p, [VP, ctypes.c_char_p]),
        "xpc_release": (None, [VP]),
        "dispatch_queue_create": (VP, [ctypes.c_char_p, VP]),
    }
    for name, (restype, argtypes) in signatures.items():
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = restype, argtypes
    return lib


@dataclass
class RuntimeObservation:
    mach_service: str
    status: str
    connection: str = "UNKNOWN"
    request: str = "NOT_TESTED"
    operation_reachability: str = "NOT_PROVEN"
    authorization_bypass: str = "NOT_PROVEN"
    reply: str = "NOT_TESTED"
    error: str = ""
    evidence_source: str = "RUNTIME_XPC"
    events: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


class MacOSXPCProbe:
    name = "RUNTIME_XPC"

    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise RuntimeProbeUnavailable("runtime XPC probing requires macOS")
        self.lib = _bind()
        self.type_error = ctypes.cast(self.lib._xpc_type_error, VP).value
        self.isa = ctypes.cast(self.lib._NSConcreteGlobalBlock, VP)
        self.keepalive: List[Any] = []

    @staticmethod
    def available() -> bool:
        return sys.platform == "darwin"

    def probe(self, name: str, timeout: float = 1.0,
              send_empty: bool = False) -> RuntimeObservation:
        lib, events, signal = self.lib, [], threading.Event()

        def handler(_block, obj):
            is_error = lib.xpc_get_type(obj) == self.type_error
            description = ""
            if is_error:
                raw = lib.xpc_dictionary_get_string(obj, b"XPCErrorDescription")
                description = raw.decode("utf-8", "replace") if raw else "XPC error"
            events.append((is_error, description))
            signal.set()

        callback = _INVOKE(handler)
        descriptor = _Descriptor(0, ctypes.sizeof(_Block))
        block = _Block(self.isa, 1 << 28, 0, ctypes.cast(callback, VP),
                       ctypes.pointer(descriptor))
        self.keepalive.extend((callback, descriptor, block))
        queue = lib.dispatch_queue_create(b"com.macostbm.runtime-probe", None)
        connection = lib.xpc_connection_create_mach_service(name.encode(), queue, 0)
        if not connection:
            return RuntimeObservation(name, "SERVICE_UNAVAILABLE", connection="REJECTED")
        lib.xpc_connection_set_event_handler(connection, ctypes.byref(block))
        lib.xpc_connection_resume(connection)
        if send_empty:
            message = lib.xpc_dictionary_create(None, None, 0)
            lib.xpc_connection_send_message(connection, message)
            lib.xpc_release(message)
        got_event = signal.wait(timeout)
        lib.xpc_connection_cancel(connection)

        if got_event and events[0][0]:
            error = events[0][1]
            low = error.lower()
            status = "CONNECTION_REJECTED" if "invalid" in low else "XPC_ERROR"
            return RuntimeObservation(
                name, status, connection="REJECTED",
                request="REQUEST_SENT" if send_empty else "NOT_TESTED",
                reply="REQUEST_REJECTED" if send_empty else "NOT_TESTED",
                error=error, events=[status],
            )
        if got_event:
            return RuntimeObservation(
                name, "REPLY_RECEIVED", connection="CONFIRMED",
                request="REQUEST_SENT" if send_empty else "NOT_TESTED",
                operation_reachability="UNKNOWN",
                reply="REPLY_RECEIVED", events=["CONNECTION_ESTABLISHED", "REPLY_RECEIVED"],
            )
        return RuntimeObservation(
            name, "CONNECTION_ESTABLISHED", connection="CONFIRMED",
            request="REQUEST_SENT" if send_empty else "NOT_TESTED",
            operation_reachability="UNKNOWN" if send_empty else "NOT_PROVEN",
            reply="NO_REPLY" if send_empty else "NOT_TESTED",
            events=["SERVICE_FOUND", "CONNECTION_ESTABLISHED"]
                    + (["REQUEST_SENT"] if send_empty else []),
        )
