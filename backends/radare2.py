"""Optional r2pipe backend for bounded callsite/xref confirmation."""

from __future__ import annotations

import importlib.util
import json
import os
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List

from utils.commands import ResultCache, which
from utils.provenance import binary_identity

from .base import BackendEvidence, BackendStats, FindingUpdate


class Radare2Unavailable(RuntimeError):
    pass


class Radare2AnalysisTimeout(RuntimeError):
    pass


class Radare2Backend:
    name = "RADARE2"

    def __init__(self, cache: ResultCache | None = None,
                 analysis_timeout: float = 300.0) -> None:
        self.cache = cache if cache is not None else ResultCache()
        self.analysis_timeout = max(1.0, float(analysis_timeout))
        self._sessions: Dict[str, Any] = {}
        self._text_ranges: Dict[str, List[tuple[int, int]]] = {}
        self._call_graphs: Dict[str, Dict[str, set[str]]] = {}

    @staticmethod
    def available() -> bool:
        return bool((which("r2") or which("radare2")) and importlib.util.find_spec("r2pipe"))

    @staticmethod
    def unavailable_reason() -> str:
        """Distinguish a missing radare2 binary from a missing Python binding."""
        has_r2 = bool(which("r2") or which("radare2"))
        has_r2pipe = importlib.util.find_spec("r2pipe") is not None
        if has_r2 and has_r2pipe:
            return "radare2 and r2pipe are available"
        if has_r2 and not has_r2pipe:
            return ("radare2 is installed but the Python r2pipe package is missing "
                    "(pip install r2pipe)")
        if has_r2pipe and not has_r2:
            return "the r2pipe package is installed but the radare2 binary is missing"
        return "radare2 and the Python r2pipe package are both missing"

    def _open(self, path: str):
        if not self.available():
            raise Radare2Unavailable("radare2 and Python package r2pipe are required")
        import r2pipe  # type: ignore[import-not-found]
        return r2pipe.open(path, flags=["-2"])

    def _session(self, path: str):
        if path not in self._sessions:
            session = self._open(path)
            session.cmd("e anal.in=bin.sections.x")
            session.cmd(f"e anal.timeout={int(self.analysis_timeout)}")
            started = time.monotonic()
            session.cmd("aaa")
            elapsed = time.monotonic() - started
            if elapsed >= self.analysis_timeout * 0.98:
                try:
                    session.quit()
                finally:
                    raise Radare2AnalysisTimeout(
                        f"aaa exceeded the {self.analysis_timeout:g}s per-binary timeout")
            self._sessions[path] = session
            self._text_ranges[path] = self._executable_text_ranges(session)
        return self._sessions[path]

    @staticmethod
    def _executable_text_ranges(r2) -> List[tuple[int, int]]:
        ranges = []
        for section in r2.cmdj("iSj") or []:
            name = str(section.get("name", ""))
            perm = str(section.get("perm", ""))
            if not (name.endswith(".__text") or name == "__text") or "x" not in perm:
                continue
            start = int(section.get("vaddr", section.get("paddr", 0)) or 0)
            size = int(section.get("vsize", section.get("size", 0)) or 0)
            if start and size:
                ranges.append((start, start + size))
        return ranges

    def _in_text(self, path: str, address: int) -> bool:
        return bool(address) and any(
            start <= address < end for start, end in self._text_ranges.get(path, []))

    def close(self) -> None:
        for session in self._sessions.values():
            try:
                session.quit()
            except Exception:  # noqa: BLE001
                pass
        self._sessions.clear()
        self._text_ranges.clear()
        self._call_graphs.clear()

    def close_path(self, path: str) -> None:
        """Close one binary session as soon as all of its findings are done."""
        session = self._sessions.pop(path, None)
        self._text_ranges.pop(path, None)
        self._call_graphs.pop(path, None)
        if session is not None:
            try:
                session.quit()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _xref_commands(api: str) -> List[str]:
        clean = api.lstrip("_").replace(":", "_")
        return [f"axtj @ sym.imp.{clean}", f"axtj @ reloc.{clean}", f"axtj @ sym.{clean}"]

    def _xrefs(self, r2, api: str, path: str) -> List[Dict]:
        for command in self._xref_commands(api):
            value = r2.cmdj(command) or []
            if isinstance(value, list) and value:
                filtered = [xref for xref in value if self._in_text(
                    path, int(xref.get("from", xref.get("addr", 0)) or 0))
                    and str(xref.get("type", "")).upper() == "CALL"]
                if filtered:
                    return filtered
        return []

    def _function_has_reference(self, r2, path: str, names: set[str]) -> bool:
        functions = {str(f.get("name", "")): int(f.get("addr", f.get("offset", 0)) or 0)
                     for f in (r2.cmdj("aflj") or [])}
        for name in names:
            offset = functions.get(name, 0)
            if not offset:
                continue
            refs = r2.cmdj(f"axtj @ {offset}") or []
            if any(self._in_text(path, int(ref.get("from", 0) or 0))
                   and str(ref.get("type", "")).upper() == "CALL" for ref in refs):
                return True
        return False

    def _call_graph(self, r2, path: str) -> Dict[str, set[str]]:
        """Build the intra-binary call graph once per binary.

        radare2 >= 6 no longer emits ``callrefs`` inside ``aflj``/``afij``;
        caller->callee edges are recovered from ``axtj @@f`` (all function
        xrefs in a single r2 command), cached by binary path.
        """
        cached = self._call_graphs.get(path)
        if cached is not None:
            return cached
        graph: Dict[str, set[str]] = {}
        for line in (r2.cmd("axtj @@f") or "").splitlines():
            line = line.strip()
            if not line.startswith("["):
                continue
            try:
                refs = json.loads(line)
            except ValueError:
                continue
            for ref in refs:
                if (str(ref.get("type", "")).upper() != "CALL"
                        or not self._in_text(path, int(ref.get("from", 0) or 0))):
                    continue
                caller = ref.get("fcn_name")
                callee = ref.get("refname")
                if caller and callee and caller != callee:
                    graph.setdefault(caller, set()).add(callee)
        self._call_graphs[path] = graph
        return graph

    def _bounded_path(self, r2, path: str, source_names: set[str],
                      sink_names: set[str]) -> List[str]:
        if source_names & sink_names:
            return [sorted(source_names & sink_names)[0]]
        graph = self._call_graph(r2, path)
        queue = [(name, [name]) for name in sorted(source_names)]
        seen = set(source_names)
        while queue:
            name, path_trace = queue.pop(0)
            if len(path_trace) > 6:
                continue
            for target in sorted(graph.get(name, set())):
                if target in sink_names:
                    return path_trace + [target]
                if target not in seen:
                    seen.add(target)
                    queue.append((target, path_trace + [target]))
        return []

    def analyze(self, path: str, finding: Any) -> tuple[FindingUpdate, bool]:
        stat = os.stat(path)
        key = ("r2-v3-call-only", path, stat.st_mtime_ns, stat.st_size, finding.finding_id,
               finding.sink_api, finding.sink_address, finding.handler_function,
               tuple(source.api for source in finding.sources), tuple(finding.unknown_reasons))
        cached = self.cache.get(str(key))
        if cached is not None:
            return cached, True

        update = FindingUpdate(finding_id=finding.finding_id)
        r2 = self._session(path)
        try:
            xrefs = self._xrefs(r2, finding.sink_api, path)
            if finding.sink_address:
                try:
                    address = int(str(finding.sink_address), 16)
                except ValueError:
                    address = 0
                # A containing function alone does not establish this sink call.
                xrefs = [xref for xref in xrefs
                         if int(xref.get("from", xref.get("addr", 0)) or 0) == address]
            if xrefs:
                source_xrefs = []
                for source in finding.sources:
                    source_xrefs.extend(self._xrefs(r2, source.api, path))
                source_names = {x.get("fcn_name", "") for x in source_xrefs if x.get("fcn_name")}
                proven_callsites = 0
                for xref in xrefs:
                    address = xref.get("from") or xref.get("addr") or 0
                    function = xref.get("fcn_name") or ""
                    sink_names = {function} if function else set()
                    call_path = (self._bounded_path(r2, path, source_names, sink_names)
                                 if source_names and sink_names else [])
                    if len(call_path) == 1:
                        # Co-location is insufficient; require source-before-sink.
                        call_path = call_path if any(
                            x.get("fcn_name") == function
                            and int(x.get("from", 0) or 0) < int(address)
                            for x in source_xrefs) else []
                    referenced = self._function_has_reference(r2, path, sink_names)
                    callsite_confirmed = bool(
                        referenced and call_path)
                    proven_callsites += int(callsite_confirmed)
                    update.evidence.append(BackendEvidence(
                        evidence_source=self.name,
                        observation=(
                            f"[R2] referenced source-to-{finding.sink_api} callsite confirmed"
                            if callsite_confirmed else
                            f"[R2] {finding.sink_api} callsite observed; caller/thunk/source path unresolved"
                        ),
                        relationship="PROVEN" if callsite_confirmed else "UNRESOLVED",
                        address=(hex(address) if isinstance(address, int) else str(address)),
                        function=function,
                        detail={
                            "xref_count": len(xrefs), "call_path": call_path,
                            "proof_scope": "STATIC_CALL_PATH",
                            "argument_flow": "NOT_PROVEN",
                            "ipc_entry_reachability": "NOT_PROVEN",
                            "operation_authorization": "NOT_PROVEN",
                            "post_condition": "NOT_PROVEN",
                            "executable_section": "__TEXT.__text",
                            "caller_or_thunk_reference": referenced,
                            "callsite_reachable": callsite_confirmed,
                            "callsite_maturity": (
                                "REACHABLE_SINK" if callsite_confirmed
                                else "SINK_CANDIDATE"),
                        },
                    ))
                update.call_path_confirmed = proven_callsites > 0
                if update.call_path_confirmed:
                    update.resolved_unknown_reasons = [
                        reason for reason in finding.unknown_reasons
                        if reason == "UNKNOWN_NO_CALL_PATH"
                    ]
        finally:
            pass
        self.cache.put(str(key), update)
        return update, False


def run_radare2(
    targets: List[Any], min_score: int = 70, max_findings: int = 200,
    cache: ResultCache | None = None,
    progress: Callable[[dict], None] | None = None,
    workers: int = 3, binary_timeout: float = 300.0,
) -> BackendStats:
    stats = BackendStats(backend="RADARE2", requested=True)
    if not Radare2Backend.available():
        stats.available = False
        stats.errors.append(f"{Radare2Backend.unavailable_reason()}; native results preserved")
        return stats
    candidates = []
    for target in targets:
        for finding in target.capability_findings:
            # Include HIGH attacker-control findings that are still unproven
            # candidates: they carry the strongest signal and deep analysis
            # can still confirm (and promote) their callsite reachability.
            if (finding.research_priority_score >= min_score
                    and finding.attacker_control in {"UNKNOWN", "PARTIAL", "HIGH"}
                    and finding.maturity_level in {"SINK_CANDIDATE", "REACHABLE_SINK"}):
                candidates.append((target, finding))
    candidates.sort(key=lambda item: item[1].research_priority_score, reverse=True)
    selected = candidates[:max_findings]
    by_path: OrderedDict[str, list[tuple[Any, Any]]] = OrderedDict()
    for target, finding in selected:
        by_path.setdefault(target.executable.path, []).append((target, finding))
    total_findings = len(selected)
    total_binaries = len(by_path)
    done_findings = 0
    done_binaries = 0

    active_paths: set[str] = set()

    def report(path: str, stage: str) -> None:
        if progress:
            progress({
                "backend": "RADARE2", "stage": stage, "path": path,
                "active_paths": sorted(active_paths),
                "workers": max(1, workers),
                "findings_done": done_findings, "findings_total": total_findings,
                "findings_remaining": max(0, total_findings - done_findings),
                "binaries_done": done_binaries, "binaries_total": total_binaries,
                "binaries_remaining": max(0, total_binaries - done_binaries),
            })

    def analyze_binary(path: str, path_findings: list[tuple[Any, Any]]):
        backend = Radare2Backend(cache, analysis_timeout=binary_timeout)
        results = []
        errors = []
        before = binary_identity(path)
        try:
            native_identity = getattr(path_findings[0][0].executable, "identity", {})
            native_hash = (native_identity.get("after_analysis") or {}).get("sha256")
            if (before.get("status") != "HASHED"
                    or (native_hash and native_hash != before.get("sha256"))):
                return [], [f"{path}: binary identity unavailable or changed since native analysis"]
            for target, finding in path_findings:
                try:
                    update, cached = backend.analyze(path, finding)
                    results.append((target, finding, update, cached))
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{path}: {exc}")
                    if isinstance(exc, Radare2AnalysisTimeout):
                        break
        finally:
            backend.close_path(path)
            backend.close()
        if binary_identity(path) != before:
            return [], errors + [f"{path}: binary changed during radare2 analysis; updates discarded"]
        return results, errors

    if not selected:
        report("", "complete")
        return stats

    worker_count = min(max(1, int(workers)), total_binaries)
    ordered_paths = list(by_path)
    active_paths.update(ordered_paths[:worker_count])
    report(ordered_paths[0], "analyzing")
    next_active = worker_count
    with ThreadPoolExecutor(max_workers=worker_count,
                            thread_name_prefix="tbm-radare2") as pool:
        futures = {
            pool.submit(analyze_binary, path, path_findings): (path, path_findings)
            for path, path_findings in by_path.items()
        }
        for future in as_completed(futures):
            path, path_findings = futures[future]
            try:
                results, errors = future.result()
            except Exception as exc:  # noqa: BLE001
                results, errors = [], [f"{path}: {exc}"]
            stats.errors.extend(errors)
            for _target, finding, update, cached in results:
                stats.analyzed += 1
                stats.cache_hits += int(cached)
                stats.call_paths_resolved += int(update.call_path_confirmed)
                stats.unknown_resolved += len(update.resolved_unknown_reasons)
                from .merge import merge_finding_update
                merge_finding_update(finding, update, "RADARE2")
            done_findings += len(path_findings)
            done_binaries += 1
            active_paths.discard(path)
            if next_active < len(ordered_paths):
                active_paths.add(ordered_paths[next_active])
                next_active += 1
            report(path, "complete" if done_binaries == total_binaries else "binary_complete")
    return stats
