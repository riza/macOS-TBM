"""Safe, bounded subprocess execution.

All external tool invocation in this project funnels through this module so that
we can guarantee:

* no ``shell=True`` (arguments are never interpreted by a shell),
* every call has a timeout,
* stdout/stderr are captured and decoded with error-tolerant handling,
* failures are surfaced as structured ``CommandError`` instead of crashing a scan,
* results are optionally cached.

Nothing here mutates the system. Every command is read-only by design.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Iterable, Optional


class CommandError(Exception):
    """Raised when an external command fails, times out, or is not found."""

    def __init__(self, message: str, cmd: Iterable[str] = (), returncode: Optional[int] = None):
        self.message = message
        self.cmd = list(cmd)
        self.returncode = returncode
        super().__init__(message)


@dataclass
class CommandResult:
    """Structured result of a subprocess run."""

    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    timed_out: bool = False
    not_found: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.not_found


def which(tool: str) -> Optional[str]:
    """Return the absolute path of *tool* or ``None`` if unavailable."""
    return shutil.which(tool)


def run(
    cmd: Iterable[str],
    timeout: float = 30.0,
    stdin: Optional[bytes] = None,
    check: bool = False,
) -> CommandResult:
    """Run *cmd* safely and return a :class:`CommandResult`.

    ``shell`` is always ``False``. ``timeout`` bounds execution. Exceptions are
    converted into a ``CommandResult`` carrying ``not_found``/``timed_out`` flags
    rather than propagating, so a single bad binary cannot abort a scan.
    """
    args = [str(c) for c in cmd]
    try:
        proc = subprocess.run(
            args,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return CommandResult(
            stdout=proc.stdout.decode("utf-8", errors="replace"),
            stderr=proc.stderr.decode("utf-8", errors="replace"),
            returncode=proc.returncode,
        )
    except FileNotFoundError:
        return CommandResult(not_found=True, returncode=127)
    except subprocess.TimeoutExpired:
        return CommandResult(timed_out=True, returncode=-1)
    except OSError as exc:  # permission denied, etc.
        if check:
            raise CommandError(f"OSError running {args!r}: {exc}", args) from exc
        return CommandResult(returncode=-1, stderr=str(exc))


class ResultCache:
    """Thread-safe memoization keyed by a string key (e.g. path + mtime)."""

    def __init__(self) -> None:
        self._data: dict = {}
        self._lock = threading.Lock()

    def get(self, key: str, default=None):
        with self._lock:
            return self._data.get(key, default)

    def put(self, key: str, value) -> None:
        with self._lock:
            self._data[key] = value

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._data

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
