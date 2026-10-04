"""Small fail-closed CFG checks for operation guards in native disassembly.

An API name or a forward jump alone never proves authorization. The control
must dominate every supported path to the sink, the branch must consume the
control's return value, the declared success semantics must be known, the
failure successor must not reach the sink and the success successor must.
Unresolved indirect transfers and analysis budgets leave the relationship
unresolved with a named ``UNKNOWN_*`` reason instead of a guard claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Set

_MAX_INSTRUCTIONS = 4096
_ZERO_BRANCHES = {"cbz", "b.eq", "je", "jz"}
_NONZERO_BRANCHES = {"cbnz", "b.ne", "jne", "jnz"}
_SUPPORTED_BRANCHES = _ZERO_BRANCHES | _NONZERO_BRANCHES
_BOOLEAN_EXTRACTION = re.compile(r"(?i)boolvalue|xpc_bool_get_value|cfboolean")


@dataclass
class GuardEvaluation:
    proven: bool = False
    reason: str = ""
    semantics: str = ""
    success_address: Optional[int] = None
    failure_address: Optional[int] = None
    dominance: bool = False
    used_result: bool = False
    branch_op: str = ""

    def evidence(self) -> Dict:
        return {
            "dominance": self.dominance,
            "used_result": self.used_result,
            "semantics": self.semantics,
            "branch_op": self.branch_op,
            "success_address": self.success_address,
            "failure_address": self.failure_address,
        }


def _build_edges(instructions):
    positions = {ins.address_int: i for i, ins in enumerate(instructions)}
    count = len(instructions)
    edges: Dict[int, Set[int]] = {}
    unresolved = False
    for i, ins in enumerate(instructions):
        op = ins.mnemonic
        fallthrough = {i + 1} if i + 1 < count else set()
        conditional = (op.startswith("b.") or op in {"cbz", "cbnz", "tbz", "tbnz"}
                       or (op.startswith("j") and op not in {"jmp", "jmpq"}))
        if conditional or op in {"b", "jmp", "jmpq"}:
            target = re.search(r"(?:0x)?([0-9a-fA-F]{6,16})",
                               ins.operands.split(";", 1)[0])
            if not target or int(target.group(1), 16) not in positions:
                unresolved = True
                edges[i] = fallthrough
            else:
                edges[i] = {positions[int(target.group(1), 16)]}
                if conditional:
                    edges[i] |= fallthrough
        elif op in {"br", "braa", "brab"}:
            unresolved = True
            edges[i] = set()
        elif op.startswith("ret"):
            edges[i] = set()
        else:
            edges[i] = fallthrough
    return edges, unresolved, positions


def _reaches(edges, start: int, target: int, blocked: Set[int] = frozenset()) -> bool:
    todo, seen = [start], set()
    while todo:
        current = todo.pop()
        if current == target:
            return True
        if current in seen or current in blocked:
            continue
        seen.add(current)
        todo.extend(edges.get(current, ()))
    return False


def _zero_comparison(instructions, branch_index: int) -> bool:
    previous = instructions[branch_index - 1]
    operands = previous.operands.split(";", 1)[0].strip()
    if previous.mnemonic.startswith(("cmp", "cmn")):
        return bool(re.search(r"(?:#|\$)(?:0x)?0(?:\s|,|$)", operands))
    if previous.mnemonic.startswith(("test", "tst")):
        return len(set(part.strip() for part in operands.split(","))) == 1
    return False


def evaluate_guard(instructions, control, branch, event,
                   success_semantics: Dict[str, str]) -> GuardEvaluation:
    """Return whether *control* provably guards *event* through *branch*."""
    result = GuardEvaluation()
    semantics = success_semantics.get(control.get("api", ""))
    if semantics not in {"zero", "object_then_boolean"}:
        result.reason = "UNKNOWN_CONTROL_FLOW"
        return result
    result.semantics = semantics
    if branch.get("control_address") != control.get("address"):
        result.reason = "UNKNOWN_CONTROL_FLOW"
        return result
    if not branch.get("uses_control_result"):
        return result
    result.used_result = True
    if not instructions or len(instructions) > _MAX_INSTRUCTIONS:
        result.reason = "UNKNOWN_ANALYSIS_BUDGET"
        return result
    edges, unresolved, positions = _build_edges(instructions)
    if unresolved:
        result.reason = "UNKNOWN_CONTROL_FLOW"
        return result
    ci, bi, si = int(control["index"]), int(branch["index"]), int(event["index"])
    if not (ci < bi < si):
        return result
    if not _reaches(edges, 0, si) or _reaches(edges, 0, si, frozenset({ci})):
        return result
    if _reaches(edges, 0, si, frozenset({bi})):
        return result
    result.dominance = True
    op = branch["mnemonic"]
    if op not in _SUPPORTED_BRANCHES:
        return result
    if op not in {"cbz", "cbnz"} and not _zero_comparison(instructions, bi):
        return result
    if semantics == "object_then_boolean":
        window = instructions[ci:bi]
        if not any(_BOOLEAN_EXTRACTION.search(ins.operands) for ins in window):
            return result
    target = positions.get(int(branch["target"]))
    if target is None:
        result.reason = "UNKNOWN_CONTROL_FLOW"
        return result
    fallthrough = bi + 1 if bi + 1 < len(instructions) else None
    taken_is_zero = op in _ZERO_BRANCHES
    success_is_zero = semantics == "zero"
    taken_is_success = taken_is_zero == success_is_zero
    success = target if taken_is_success else fallthrough
    failure = fallthrough if taken_is_success else target
    if success is None or failure is None:
        result.reason = "UNKNOWN_CONTROL_FLOW"
        return result
    result.branch_op = op
    result.success_address = instructions[success].address_int
    result.failure_address = instructions[failure].address_int
    if _reaches(edges, success, si) and not _reaches(edges, failure, si):
        result.proven = True
    return result


def guard_proven(instructions, control, branch, event, success_rules) -> bool:
    """Compatibility wrapper returning only the boolean proof."""
    return evaluate_guard(instructions, control, branch, event, success_rules).proven
