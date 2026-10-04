"""Bounded direct call graph and reachability states (read-only).

The graph is built from recovered direct call edges only. An absent edge is
uncertainty, never proof that execution is impossible: functions that are only
entered through an indirect or block dispatch stay ``CONFIRMED_INDIRECT`` and
everything without evidence stays ``UNRESOLVED``.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Set

CONFIRMED_DIRECT = "CONFIRMED_DIRECT"
CONFIRMED_INDIRECT = "CONFIRMED_INDIRECT"
UNRESOLVED = "UNRESOLVED"
NOT_OBSERVED = "NOT_OBSERVED"

_REACHABLE_STATES = {CONFIRMED_DIRECT, CONFIRMED_INDIRECT}


@dataclass
class CallGraph:
    """Direct caller -> callee edges plus functions with an unresolved transfer."""

    edges: Dict[str, Set[str]] = field(default_factory=dict)
    indirect: Set[str] = field(default_factory=set)

    def add_edge(self, caller: str, callee: str) -> None:
        self.edges.setdefault(caller, set()).add(callee)

    def mark_indirect(self, function: str) -> None:
        self.indirect.add(function)

    def has_indirect(self, function: str) -> bool:
        return function in self.indirect

    def incoming(self, callee: str) -> Set[str]:
        return {caller for caller, callees in self.edges.items() if callee in callees}

    def reachable(self, roots: Iterable[str], limit: int = 100_000) -> Set[str]:
        seen: Set[str] = set()
        queue = deque(roots)
        visits = 0
        while queue:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            visits += 1
            if visits > limit:
                break
            queue.extend(self.edges.get(node, ()))
        return seen

    def shortest_paths(self, target: str, roots: Iterable[str], max_depth: int = 8,
                       max_paths: int = 8) -> List[List[str]]:
        results: List[List[str]] = []
        for root in roots:
            queue = deque([[root]])
            while queue:
                path = queue.popleft()
                if len(path) - 1 > max_depth:
                    continue
                node = path[-1]
                if node == target:
                    results.append(path)
                    if len(results) >= max_paths:
                        return results
                    continue
                for nxt in self.edges.get(node, ()):
                    if nxt not in path:
                        queue.append(path + [nxt])
        return results


def is_reachable(state: str) -> bool:
    return state in _REACHABLE_STATES
