"""Bounded static extraction of XPC request dispatch (read-only).

The pass answers one narrow question: given a disassembly, which XPC dictionary
keys are read, which request values are compared, and which handler (if any) a
request value selects. It never asserts a handler it cannot resolve: an
unresolvable indirect transfer becomes ``UNKNOWN_INDIRECT_HANDLER`` and a
comparison without a resolvable successor stays ``INFERRED``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from collectors.dataflow import (
    _call_target,
    _called_api,
    _parse_functions,
    _registers,
    _string_literals,
)
from utils.rules import capability_rules

_XPC_GET = (
    "xpc_dictionary_get_string", "xpc_dictionary_get_data",
    "xpc_dictionary_get_uint64", "xpc_dictionary_get_int64",
    "xpc_dictionary_get_bool", "xpc_dictionary_get_value",
    "xpc_dictionary_get_double", "xpc_dictionary_get_array",
    "xpc_dictionary_get_dictionary", "xpc_dictionary_get_date",
    "xpc_dictionary_get_uuid",
)
_COMPARE = ("strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp", "bcmp",
            "CFEqual", "CFStringCompare")
_INT_GET = {"xpc_dictionary_get_int64", "xpc_dictionary_get_uint64"}
_CALL_OPS = ("bl", "blr", "call", "callq")
_INDIRECT_BRANCH = ("br", "braa", "brab", "jmp", "jmpq")
_EQUAL_TARGET_OPS = {"cbz", "b.eq", "beq", "je", "jz"}


@dataclass
class XpcDispatchAnalysis:
    operations: List[Dict] = field(default_factory=list)
    unknown_reasons: Dict[str, int] = field(default_factory=dict)


def _arch_regs(arch: str):
    if arch == "x86_64":
        return "rax", ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    return "x0", [f"x{i}" for i in range(8)]


def _is_conditional(op: str) -> bool:
    return (op.startswith("b.") or op in {"cbz", "cbnz", "tbz", "tbnz"}
            or (op.startswith("j") and op not in {"jmp", "jmpq"}))


def _dest_sources(arch: str, operands: str):
    regs = _registers(operands)
    if not regs:
        return None, []
    if arch == "x86_64":
        return regs[-1], regs[:-1]
    return regs[0], regs[1:]


def _branch_target(operand: str) -> int:
    match = re.search(r"(?:0x)?([0-9a-fA-F]{6,16})", operand.split(";", 1)[0])
    return int(match.group(1), 16) if match else 0


def _instruction_owner(functions) -> Dict[Tuple[str, int], str]:
    """Map ``(arch, instruction address)`` to the function that owns it."""
    owners: Dict[Tuple[str, int], str] = {}
    for func in functions.values():
        for insn in func.instructions:
            owners[(func.arch, insn.address_int)] = func.name
    return owners


def _resolve_handler(address: int, arch: str, address_index, functions,
                     owners) -> Optional[str]:
    """Resolve a branch target to a function or an intra-function block."""
    key = address_index.get((arch, address))
    if key:
        return functions[key].name
    owner = owners.get((arch, address))
    if owner:
        func_key = next((k for k, f in functions.items()
                         if f.name == owner and f.arch == arch), None)
        if func_key is not None:
            offset = address - functions[func_key].start
            return f"{owner}+0x{offset:x}"
    return None


def _function_input_keys(func) -> List[str]:
    """Dictionary keys read by this function, in first-seen order."""
    _, argregs = _arch_regs(func.arch)
    strings: Dict[str, Set[str]] = {}
    keys: List[str] = []
    for insn in func.instructions:
        op, text = insn.mnemonic, insn.operands
        if op in _CALL_OPS:
            if _called_api(text, _XPC_GET):
                candidates = sorted(strings.get(argregs[1], set()))
                if candidates and candidates[0] not in keys:
                    keys.append(candidates[0])
            for reg in argregs:
                strings.pop(reg, None)
            continue
        dest, sources = _dest_sources(func.arch, text)
        literals = set(_string_literals(text))
        for reg in sources:
            literals |= strings.get(reg, set())
        if dest:
            if literals:
                strings[dest] = literals
            else:
                strings.pop(dest, None)
    return keys


def _analyze_dispatch(func, functions, address_index, input_keys_by_name, owners,
                      name_index, comparators):
    arch = func.arch
    retreg, argregs = _arch_regs(arch)
    marks: Dict[str, str] = {}
    strings: Dict[str, Set[str]] = {}
    int_marks: Dict[str, str] = {}
    last_request_key: Optional[str] = None
    pending: Optional[Dict] = None
    saw_get = False
    operations: List[Dict] = []
    unknown: Dict[str, int] = {}

    def emit(operation, handler, request_key, relationship, evidence):
        # A block handler is named "<function>+0x<offset>"; the input keys are
        # read from the owning function, not the block label.
        owner = handler.split("+0x", 1)[0] if handler else None
        operations.append({
            "request_key": request_key,
            "operation": operation,
            "handler": handler,
            "input_keys": list(input_keys_by_name.get(owner, [])) if owner else [],
            "dispatcher": func.name,
            "relationship": relationship,
            "evidence": evidence,
        })

    for index, insn in enumerate(func.instructions):
        op, text = insn.mnemonic, insn.operands
        if op in _CALL_OPS:
            api_get = _called_api(text, _XPC_GET)
            if api_get:
                candidates = sorted(strings.get(argregs[1], set()))
                key = candidates[0] if candidates else None
                if key:
                    last_request_key = key
                    saw_get = True
                    marks[retreg] = key
                    if api_get in _INT_GET:
                        int_marks[retreg] = key
                    else:
                        int_marks.pop(retreg, None)
                else:
                    marks.pop(retreg, None)
                    int_marks.pop(retreg, None)
                for reg in argregs:
                    strings.pop(reg, None)
                continue
            if _called_api(text, _COMPARE):
                compared: Set[str] = set()
                for reg in argregs[:2]:
                    compared |= strings.get(reg, set())
                request_key = marks.get(argregs[0]) or marks.get(argregs[1])
                if compared and request_key:
                    pending = {
                        "operation": sorted(compared)[0],
                        "request_key": request_key,
                        "result_reg": retreg,
                        "index": index,
                        "evidence": [{"address": insn.address, "kind": "string-xref"}],
                    }
                marks.pop(retreg, None)
                int_marks.pop(retreg, None)
                continue
            local_target = _call_target(
                text, arch, functions, name_index, address_index)
            if local_target and local_target in comparators:
                literal = None
                for reg in argregs[:3]:
                    values = sorted(strings.get(reg, set()))
                    if values:
                        literal = values[0]
                        break
                request_key = marks.get(argregs[0]) or last_request_key
                if literal and request_key:
                    pending = {
                        "operation": literal,
                        "request_key": request_key,
                        "result_reg": retreg,
                        "index": index,
                        "evidence": [{"address": insn.address,
                                      "kind": "comparison-wrapper"}],
                    }
            marks.pop(retreg, None)
            int_marks.pop(retreg, None)
            for reg in argregs:
                strings.pop(reg, None)
            continue
        if _is_conditional(op):
            uses_result = False
            if pending is not None and index - int(pending.get("index", index)) <= 2:
                if pending.get("flags"):
                    uses_result = True
                elif pending.get("result_reg") in set(_registers(text)):
                    uses_result = True
            if uses_result:
                target = _branch_target(text)
                fallthrough = (func.instructions[index + 1].address_int
                               if index + 1 < len(func.instructions) else 0)
                if op in _EQUAL_TARGET_OPS:
                    equal_address = target
                elif op in {"tbnz", "tbz"} and re.search(r"#0x0(?:\b|,)", text):
                    equal_address = target if op == "tbnz" else fallthrough
                elif op in {"cbnz", "b.ne", "bne", "jne", "jnz"}:
                    equal_address = fallthrough
                else:
                    equal_address = 0
                handler = _resolve_handler(equal_address, arch, address_index, functions, owners)
                evidence = list(pending["evidence"])
                if handler:
                    evidence.append({"address": insn.address, "kind": "table-entry"})
                emit(pending["operation"], handler, pending["request_key"],
                     "PROVEN" if handler else "INFERRED", evidence)
                pending = None
            continue
        if op in _INDIRECT_BRANCH:
            if pending is None and (saw_get or last_request_key):
                unknown["UNKNOWN_INDIRECT_HANDLER"] = (
                    unknown.get("UNKNOWN_INDIRECT_HANDLER", 0) + 1)
                emit(None, None, last_request_key, "UNKNOWN_INDIRECT_HANDLER",
                     [{"address": insn.address, "kind": "call"}])
            continue
        if op in {"cmp", "cmn", "subs", "sub"} and int_marks:
            regs = _registers(text)
            immediate = re.search(r"#(0x[0-9a-fA-F]+|\d+)", text)
            if regs and regs[0] in int_marks and immediate:
                raw = immediate.group(1)
                value = int(raw, 16) if raw.startswith("0x") else int(raw)
                pending = {
                    "operation": f"#{value}",
                    "request_key": int_marks[regs[0]],
                    "result_reg": None,
                    "flags": True,
                    "index": index,
                    "evidence": [{"address": insn.address, "kind": "int-compare"}],
                }
            continue
        dest, sources = _dest_sources(arch, text)
        literals = set(_string_literals(text))
        inherited_strings: Set[str] = set()
        inherited_int: Optional[str] = None
        for reg in sources:
            literals |= strings.get(reg, set())
            if reg in marks:
                inherited_strings.add(marks[reg])
            if reg in int_marks:
                inherited_int = int_marks[reg]
        if dest:
            if literals:
                strings[dest] = literals
            else:
                strings.pop(dest, None)
            if inherited_strings:
                marks[dest] = sorted(inherited_strings)[0]
            else:
                marks.pop(dest, None)
            if inherited_int is not None:
                int_marks[dest] = inherited_int
            else:
                int_marks.pop(dest, None)

    if pending is not None:
        emit(pending["operation"], None, pending["request_key"], "INFERRED",
             list(pending["evidence"]))
    return operations, unknown


def analyze_xpc_dispatch(text: str, executable_ranges=None,
                         function_starts=None) -> XpcDispatchAnalysis:
    functions = _parse_functions(text, executable_ranges, function_starts)
    address_index = {(func.arch, func.start): key for key, func in functions.items()}
    input_keys_by_name = {func.name: _function_input_keys(func)
                          for func in functions.values()}
    owners = _instruction_owner(functions)
    name_index = {(func.arch, func.name): key for key, func in functions.items()}
    comparators = {key for key, func in functions.items()
                   if any(_called_api(insn.operands, _COMPARE)
                          for insn in func.instructions
                          if insn.mnemonic in _CALL_OPS)}
    operations: List[Dict] = []
    unknown: Dict[str, int] = {}
    for func in functions.values():
        found, reasons = _analyze_dispatch(func, functions, address_index,
                                           input_keys_by_name, owners, name_index,
                                           comparators)
        operations.extend(found)
        for reason, count in reasons.items():
            unknown[reason] = unknown.get(reason, 0) + count

    from collections import Counter
    rules = capability_rules()
    dispatch_keys = [token.lower() for token in rules.get("dispatch_keys", [])]
    min_chain = int(rules.get("dispatch_min_chain", 2))

    def is_dispatch_key(key) -> bool:
        if not key:
            return False
        lowered = str(key).lower()
        return any(token in lowered for token in dispatch_keys)
    chain_sizes = Counter(entry["dispatcher"] for entry in operations
                          if entry.get("operation"))
    # A branch target shared by two or more distinct operations is a common
    # policy successor (the allowlist's continue target), not a per-operation
    # handler; do not label it PROVEN.
    handler_ops: Dict[Tuple[str, str], Set[str]] = {}
    for entry in operations:
        if entry.get("operation") and entry.get("handler"):
            handler_ops.setdefault((entry["dispatcher"], entry["handler"]), set()).add(
                entry["operation"])
    for entry in operations:
        if (entry.get("operation") and entry.get("handler")
                and entry.get("relationship") == "PROVEN"
                and len(handler_ops.get((entry["dispatcher"], entry["handler"]), set())) >= 2):
            entry["relationship"] = "SHARED_SUCCESSOR"
    unique: List[Dict] = []
    seen = set()
    for entry in operations:
        if entry.get("operation") is None:
            if entry["relationship"] != "UNKNOWN_INDIRECT_HANDLER" \
                    and not is_dispatch_key(entry.get("request_key")):
                continue
        elif (not is_dispatch_key(entry.get("request_key"))
              and chain_sizes[entry["dispatcher"]] < min_chain):
            # A lone comparison on a key that is not a known dispatch key is
            # more likely a data-field check than a request selector.
            continue
        key = (entry["dispatcher"], entry["operation"], entry["handler"],
               entry["request_key"], entry["relationship"])
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return XpcDispatchAnalysis(operations=unique, unknown_reasons=unknown)
