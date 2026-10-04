"""Bounded interprocedural taint extraction from ``otool -tvV`` output.

The pass is deliberately evidence-oriented rather than a general decompiler.
It tracks source returns through registers, stack slots, direct helper calls and
simple wrapper returns; records sink calls even when their arguments remain
uncontrolled; separates validation/authorization location from gate evidence;
and follows sensitive results into common reply APIs. Dynamic dispatch and
unsupported aliases are retained as explicit UNKNOWN causes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from utils.commands import run
from utils.rules import capability_rules, lpe_rules

_INSN = re.compile(r"^\s*([0-9a-fA-F]{6,16})\s+([A-Za-z.][A-Za-z0-9.]*)\s*(.*?)\s*$")
_LABEL = re.compile(r"^\s*(?:[0-9a-fA-F]+\s+)?(?:<)?(.+?)(?:>)?:\s*$")
_ARCH_HEADER = re.compile(r"\(architecture\s+(arm64e?|x86_64)\):")
_REG = re.compile(r"(?<![\w#])%?(?:x(?:[0-9]|[12][0-9]|30)|w(?:[0-9]|[12][0-9]|30)|rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r1[0-5])\b")
_STACK = re.compile(r"\[(?:sp|fp|x29)(?:,\s*#?(-?0x[0-9a-fA-F]+|-?\d+))?\]|(-?0x[0-9a-fA-F]+|-?\d+)\(%(?:rsp|rbp)\)")
_HEX = re.compile(r"(?:0x)?([0-9a-fA-F]{6,16})")
_PATH_LITERAL = re.compile(
    r"(?i)(?:literal pool for:|cfstring=|@)?\s*[\"']?"
    r"((?:/(?:[A-Za-z0-9._+@%-]+/?)+"
    r"|Library/Caches[^\"'\s,;)]*|NSTemporaryDirectory))")
_STRING_LITERAL = re.compile(
    r'(?i)(?:literal pool for:|cfstring\s+ref:?|cfstring=)\s*@?"([^"\n]+)"')


@dataclass
class DataflowAnalysis:
    facts: List[Dict] = field(default_factory=list)
    unknown_reasons: Dict[str, int] = field(default_factory=dict)
    functions_analyzed: int = 0
    direct_calls: int = 0
    unconditional_accept_listeners: List[str] = field(default_factory=list)
    ipc_surface: List[Dict] = field(default_factory=list)
    ipc_operations: List[Dict] = field(default_factory=list)
    ipc_operation_unknown_reasons: Dict[str, int] = field(default_factory=dict)


@dataclass
class _Instruction:
    address: str
    mnemonic: str
    operands: str
    arch: str
    index: int

    @property
    def address_int(self) -> int:
        try:
            return int(self.address, 16)
        except ValueError:
            return 0


@dataclass
class _Function:
    name: str
    arch: str
    instructions: List[_Instruction] = field(default_factory=list)

    @property
    def start(self) -> int:
        return self.instructions[0].address_int if self.instructions else 0


@dataclass
class _Summary:
    name: str
    arch: str
    events: List[Dict] = field(default_factory=list)
    return_origins: Set[str] = field(default_factory=set)
    unknown_reasons: Set[str] = field(default_factory=set)
    instructions: List[_Instruction] = field(default_factory=list)


def _expand_patterns() -> Tuple[List[str], List[str], List[str], List[str], List[str]]:
    rules = capability_rules()
    sources = list(rules.get("sources", {}))
    sinks = [p for operation in rules.get("operations", [])
             for p in operation.get("symbols", [])]
    lpe = lpe_rules()
    sinks += [pattern for patterns in (lpe.get("filesystem_sinks") or {}).values()
              for pattern in patterns]
    sinks += list(lpe.get("toctou_checks", []))
    replies = list(rules.get("replies", []))
    validation = list(rules.get("identity_validation", []))
    authorization = list(rules.get("authorization", []))
    return tuple(list(dict.fromkeys(x)) for x in (
        sources, sinks, replies, validation, authorization))  # type: ignore[return-value]


def _matches(actual: str, pattern: str) -> bool:
    actual = actual.lstrip("_")
    pattern = pattern.lstrip("_")
    if pattern.endswith("*"):
        return actual.startswith(pattern[:-1])
    if pattern.endswith(":"):
        # ObjC selector: a prefix pattern matches any selector that starts with it.
        return actual.startswith(pattern)
    return actual == pattern


def _called_api(operand: str, patterns: Iterable[str]) -> Optional[str]:
    names = re.findall(r"[_A-Za-z][A-Za-z0-9_$:.]*", operand)
    names = [n.split("@", 1)[0].lstrip("_") for n in names]
    for pattern in sorted(patterns, key=lambda p: len(p.rstrip("*")), reverse=True):
        for name in names:
            if _matches(name, pattern):
                return name
    return None


def _registers(operand: str) -> List[str]:
    out = []
    for match in _REG.findall(operand.lower()):
        reg = match.lstrip("%")
        if reg.startswith("w") and reg[1:].isdigit():
            reg = "x" + reg[1:]
        if reg not in out:
            out.append(reg)
    return out


def _stack_slot(operand: str) -> Optional[str]:
    match = _STACK.search(operand.lower())
    if not match:
        return None
    offset = match.group(1) or match.group(2) or "0"
    base = "sp" if ("sp" in match.group(0) or "rsp" in match.group(0)) else "fp"
    return f"{base}:{offset}"


def _split_operands(text: str) -> List[str]:
    parts, current, depth = [], [], 0
    for char in text.split(";", 1)[0]:
        if char in "[(":
            depth += 1
        elif char in ")]":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return parts


def _path_literals(text: str) -> Set[str]:
    return {match.group(1) for match in _PATH_LITERAL.finditer(text)}


def _string_literals(text: str) -> Set[str]:
    return {match.group(1) for match in _STRING_LITERAL.finditer(text)}


def _normal_name(name: str) -> str:
    return name.strip().strip("<>").lstrip("_")


def _in_executable_range(address: int, ranges: Optional[List[Tuple[int, int]]]) -> bool:
    return not ranges or any(start <= address < end for start, end in ranges)


def _parse_functions(
    text: str, executable_ranges: Optional[List[Tuple[int, int]]] = None,
    function_starts: Optional[Dict[str, Iterable[int]]] = None,
) -> Dict[str, _Function]:
    functions: Dict[str, _Function] = {}
    starts_by_arch = {arch: set(values)
                      for arch, values in (function_starts or {}).items()}
    arch = "arm64"
    current: Optional[_Function] = None
    serial = 0
    for raw in text.splitlines():
        header = _ARCH_HEADER.search(raw)
        if header:
            arch = "x86_64" if header.group(1) == "x86_64" else "arm64"
            current = None
            continue
        label = _LABEL.match(raw)
        if label and not _INSN.match(raw):
            name = _normal_name(label.group(1))
            key = f"{arch}:{name}"
            current = functions.setdefault(key, _Function(name=name, arch=arch))
            continue
        match = _INSN.match(raw)
        if not match:
            continue
        address, mnemonic, operands = match.groups()
        address_int = int(address, 16)
        if not _in_executable_range(address_int, executable_ranges):
            continue
        op = mnemonic.lower()
        inferred_arch = arch
        # Look only at the operand text, never the comment: a format-string
        # literal such as "%{public}@" is not an x86 register and must not
        # fragment an arm64 function into spurious x86_64 pieces.
        operand_code = operands.split(";", 1)[0]
        if op in ("bl", "blr") or "[" in operand_code:
            inferred_arch = "arm64"
        elif "%" in operand_code or op.startswith("call"):
            inferred_arch = "x86_64"
        is_start = address_int in starts_by_arch.get(inferred_arch, set())
        split = (current is None or current.arch != inferred_arch
                 or (is_start and current.instructions and current.start != address_int))
        if split:
            name = (f"sub_{address_int:x}" if is_start
                    else f"unknown_{inferred_arch}_{address}")
            key = f"{inferred_arch}:{name}"
            current = functions.setdefault(
                key, _Function(name=name, arch=inferred_arch))
        current.instructions.append(_Instruction(
            address=address, mnemonic=op, operands=operands,
            arch=inferred_arch, index=serial,
        ))
        serial += 1
    return functions


def _unconditional_accept_listeners(functions: Dict[str, _Function]) -> List[str]:
    """Recognize tiny NSXPC listener methods that unconditionally return true."""
    out: List[str] = []
    for function in functions.values():
        if "shouldacceptnewconnection" not in function.name.lower():
            continue
        instructions = function.instructions
        if not instructions or not any(insn.mnemonic in {"ret", "retq"}
                                       for insn in instructions):
            continue
        if any(_is_conditional_branch(insn.mnemonic) for insn in instructions):
            continue
        returns_true = any(
            insn.mnemonic.startswith("mov")
            and re.search(r"(?:w0|x0|%eax|%rax)", insn.operands, re.IGNORECASE)
            and re.search(r"(?:#|\$)(?:0x)?1\b", insn.operands, re.IGNORECASE)
            for insn in instructions
        )
        if returns_true:
            out.append(function.name)
    return sorted(set(out))


def _call_target(operand: str, arch: str, functions: Dict[str, _Function],
                 name_index: Optional[Dict[Tuple[str, str], str]] = None,
                 address_index: Optional[Dict[Tuple[str, int], str]] = None) -> Optional[str]:
    names = [_normal_name(n) for n in re.findall(r"[_A-Za-z][A-Za-z0-9_$:.]*", operand)]
    if name_index is None:
        name_index = {(f.arch, f.name): key for key, f in functions.items()}
    for name in reversed(names):
        target = name_index.get((arch, name))
        if target:
            return target
    match = _HEX.search(operand)
    if match:
        address = int(match.group(1), 16)
        if address_index is None:
            address_index = {(f.arch, f.start): key for key, f in functions.items()}
        return address_index.get((arch, address))
    return None


def _resolve_origins(origins: Iterable[str], arg_map: Dict[int, Set[str]]) -> Set[str]:
    resolved: Set[str] = set()
    for origin in origins:
        if origin.startswith("RESOURCE|"):
            resource = json.loads(origin.split("|", 1)[1])
            resource["origins"] = sorted(_resolve_origins(resource["origins"], arg_map))
            resolved.add("RESOURCE|" + json.dumps(resource, sort_keys=True))
        elif origin.startswith("ARG:"):
            try:
                resolved.update(arg_map.get(int(origin.split(":", 1)[1]), set()))
            except ValueError:
                continue
        else:
            resolved.add(origin)
    return resolved


def _input_origins(origins: Iterable[str]) -> Set[str]:
    """Unwrap descriptor provenance without confusing a descriptor with a path."""
    result = set()
    for origin in origins:
        if origin.startswith("RESOURCE|"):
            result.update(_input_origins(json.loads(origin.split("|", 1)[1])["origins"]))
        else:
            result.add(origin)
    return result


def _map_return(origins: Iterable[str], args: List[Set[str]]) -> Set[str]:
    return _resolve_origins(origins, {i: value for i, value in enumerate(args)})


def _branch_target(operand: str) -> int:
    match = _HEX.search(operand)
    return int(match.group(1), 16) if match else 0


def _is_conditional_branch(op: str) -> bool:
    return (op.startswith("b.") or op in {"cbz", "cbnz", "tbz", "tbnz"}
            or (op.startswith("j") and op not in {"jmp", "jmpq"}))


def _analyze_function(func: _Function, functions: Dict[str, _Function],
                      return_summaries: Dict[str, Set[str]], patterns,
                      name_index: Dict[Tuple[str, str], str],
                      address_index: Dict[Tuple[str, int], str],
                      selector_refs: Optional[Dict[str, Dict[int, str]]] = None) -> _Summary:
    sources, sinks, replies, validation, authorization = patterns
    rules = capability_rules()
    transforms = list(rules.get("transforms", []))
    arch = func.arch
    retreg = "rax" if arch == "x86_64" else "x0"
    argregs = (["rdi", "rsi", "rdx", "rcx", "r8", "r9"] if arch == "x86_64"
               else [f"x{i}" for i in range(8)])
    taint: Dict[str, Set[str]] = {reg: {f"ARG:{i}"} for i, reg in enumerate(argregs)}
    memory: Dict[str, Set[str]] = {}
    literals: Dict[str, Set[str]] = {}
    literal_memory: Dict[str, Set[str]] = {}
    string_consts: Dict[str, Set[str]] = {}
    pages: Dict[str, int] = {}
    selectors: Dict[str, str] = {}
    constants: Set[str] = set()
    constant_memory: Set[str] = set()
    summary = _Summary(name=func.name, arch=arch, instructions=func.instructions)
    last_control: Optional[Dict] = None

    for local_index, insn in enumerate(func.instructions):
        op, operand_text = insn.mnemonic, insn.operands
        operands = _split_operands(operand_text)
        if op in ("bl", "blr", "call", "callq"):
            args = [set(taint.get(reg, set())) for reg in argregs]
            literal_args = [set(literals.get(reg, set())) for reg in argregs]
            constant_args = [index for index, reg in enumerate(argregs) if reg in constants]
            source_api = _called_api(operand_text, sources)
            if source_api in rules.get("trusted_metadata_sources", []):
                source_api = None
            sink_api = _called_api(operand_text, sinks)
            if sink_api is None and "objc_msgsend" in operand_text.lower():
                selector = selectors.get(argregs[1]) if len(argregs) > 1 else None
                if selector and any(_matches(selector, pattern) for pattern in sinks):
                    sink_api = selector
            reply_api = _called_api(operand_text, replies)
            validation_api = _called_api(operand_text, validation)
            authorization_api = _called_api(operand_text, authorization)
            local_target = _call_target(
                operand_text, arch, functions, name_index, address_index)
            event_base = {"index": local_index, "address": insn.address,
                          "function": func.name}

            if sink_api:
                summary.events.append({**event_base, "kind": "sink", "api": sink_api,
                                       "arg_origins": args,
                                       "argument_literals": literal_args,
                                       "constant_argument_indexes": constant_args})
                taint[retreg] = {f"RESULT|{sink_api}|{insn.address}|{func.name}"}
                resource_rule = rules.get("descriptor_returns", {}).get(sink_api)
                if resource_rule:
                    path_index = int(resource_rule["path_argument"])
                    taint[retreg].add("RESOURCE|" + json.dumps({
                        "api": sink_api, "address": insn.address,
                        "function": func.name,
                        "origins": sorted(args[path_index]),
                        "path_literals": sorted(literal_args[path_index]),
                        "path_argument": path_index,
                    }, sort_keys=True))
                literals.pop(retreg, None)
                constants.discard(retreg)
            elif source_api:
                key_candidates = sorted(string_consts.get(argregs[1], set()))
                key = key_candidates[0] if key_candidates else ""
                origin = f"SOURCE|{source_api}|{insn.address}|{func.name}|{key}"
                summary.events.append({**event_base, "kind": "source", "api": source_api,
                                       "origin": origin, "key": key or None})
                taint[retreg] = {origin}
                literals.pop(retreg, None)
                constants.discard(retreg)
                if source_api == "mach_msg":
                    summary.unknown_reasons.add("UNKNOWN_MACH_MESSAGE_LAYOUT")
            elif reply_api:
                summary.events.append({**event_base, "kind": "reply", "api": reply_api,
                                       "arg_origins": args})
                taint.pop(retreg, None)
                literals.pop(retreg, None)
                constants.discard(retreg)
            elif validation_api or authorization_api:
                kind = "validation" if validation_api else "authorization"
                api = validation_api or authorization_api or "unknown"
                event = {**event_base, "kind": kind, "api": api}
                summary.events.append(event)
                last_control = event
                taint[retreg] = {f"CONTROL|{kind}|{api}|{insn.address}"}
                literals.pop(retreg, None)
                constants.discard(retreg)
            elif local_target:
                summary.events.append({**event_base, "kind": "call", "target": local_target,
                                       "arg_origins": args,
                                       "argument_literals": literal_args,
                                       "constant_argument_indexes": constant_args})
                mapped = _map_return(return_summaries.get(local_target, set()), args)
                if mapped:
                    taint[retreg] = mapped
                    literals.pop(retreg, None)
                    constants.discard(retreg)
                    # Direct helpers that return IPC-derived values are source
                    # wrappers. Reify the recovered source at the callsite so
                    # the caller's later operations remain traversable.
                    for origin in sorted(_input_origins(mapped)):
                        if origin.startswith("SOURCE|"):
                            api, _address, _function, _key = _source_parts(origin)
                            summary.events.append({
                                **event_base, "kind": "source", "api": api,
                                "origin": origin, "key": _key or None,
                                "via_wrapper": local_target,
                            })
                else:
                    taint.pop(retreg, None)
                    literals.pop(retreg, None)
                    constants.discard(retreg)
                    if any(args):
                        summary.unknown_reasons.add("UNKNOWN_RETURN_VALUE")
            else:
                called = _called_api(operand_text, transforms)
                symbol_text = operand_text.lower()
                combined = set().union(*args) if args else set()
                combined_literals = set().union(*literal_args) if literal_args else set()
                if called:
                    taint[retreg] = combined
                    if combined_literals:
                        literals[retreg] = combined_literals
                    else:
                        literals.pop(retreg, None)
                    constants.discard(retreg)
                elif "objc_msgsend" in symbol_text:
                    if combined:
                        taint[retreg] = combined
                    constants.discard(retreg)
                    if combined_literals:
                        literals[retreg] = combined_literals
                    else:
                        literals.pop(retreg, None)
                    summary.unknown_reasons.add("UNKNOWN_OBJC_DISPATCH")
                elif "swift" in symbol_text:
                    if combined:
                        taint[retreg] = combined
                    constants.discard(retreg)
                    summary.unknown_reasons.add("UNKNOWN_SWIFT_DISPATCH")
                else:
                    if op == "blr" or "*%" in operand_text:
                        summary.unknown_reasons.add("UNKNOWN_INDIRECT_CALL")
                    elif combined:
                        summary.unknown_reasons.add("UNKNOWN_WRAPPER")
                    taint.pop(retreg, None)
                    literals.pop(retreg, None)
                    constants.discard(retreg)
            continue

        if _is_conditional_branch(op):
            if last_control and local_index - int(last_control["index"]) <= 8:
                branch_regs = set(_registers(operand_text))
                control_origin = f"CONTROL|{last_control['kind']}|{last_control['api']}|{last_control['address']}"
                uses_control_result = any(control_origin in taint.get(reg, set())
                                          for reg in branch_regs)
                if not uses_control_result and local_index:
                    previous = func.instructions[local_index - 1]
                    if previous.mnemonic.startswith(("cmp", "test", "tst")):
                        uses_control_result = any(
                            control_origin in taint.get(reg, set())
                            for reg in _registers(previous.operands))
                summary.events.append({
                    "kind": "branch", "control_kind": last_control["kind"],
                    "control_api": last_control["api"], "index": local_index,
                    "address": insn.address, "target": _branch_target(operand_text),
                    "function": func.name,
                    "uses_control_result": uses_control_result,
                    "control_address": last_control["address"],
                    "mnemonic": op,
                })
            continue

        regs = _registers(operand_text)
        if op.startswith(("str", "stur")) or (arch == "x86_64" and op.startswith("mov")
                                               and operands and "(" in operands[-1]):
            slot = _stack_slot(operand_text)
            source_reg = regs[0] if regs else None
            if slot and source_reg and source_reg in taint:
                memory[slot] = set(taint[source_reg])
            elif slot:
                memory.pop(slot, None)
            if slot and source_reg and source_reg in literals:
                literal_memory[slot] = set(literals[source_reg])
            elif slot:
                literal_memory.pop(slot, None)
            if slot and source_reg in constants:
                constant_memory.add(slot)
            elif slot:
                constant_memory.discard(slot)
            continue
        if op == "adrp":
            adrp_regs = _registers(operand_text)
            page = re.search(r";\s*0x([0-9a-fA-F]+)", operand_text)
            if adrp_regs:
                dest = adrp_regs[0]
                taint.pop(dest, None)
                constants.add(dest)
                if page:
                    pages[dest] = int(page.group(1), 16)
            continue
        if (op.startswith(("ldr", "ldur")) and "[" in operand_text and selector_refs):
            ldr_regs = _registers(operand_text)
            offset = re.search(r"#(0x[0-9a-fA-F]+|\d+)", operand_text)
            if len(ldr_regs) >= 2 and offset and ldr_regs[1] in pages:
                target = pages[ldr_regs[1]] + int(offset.group(1), 0)
                selector = selector_refs.get(arch, {}).get(target)
                if selector:
                    selectors[ldr_regs[0]] = selector
        if op.startswith(("ldr", "ldur")) or (arch == "x86_64" and op.startswith("mov")
                                               and operands and "(" in operands[0]):
            slot = _stack_slot(operand_text)
            dest = (regs[-1] if regs else None) if arch == "x86_64" else (
                regs[0] if regs else None)
            if dest and slot in memory:
                taint[dest] = set(memory[slot])
            elif dest:
                taint.pop(dest, None)
            if dest and slot in literal_memory:
                literals[dest] = set(literal_memory[slot])
            elif dest:
                literals.pop(dest, None)
            if dest and slot in constant_memory:
                constants.add(dest)
            elif dest:
                constants.discard(dest)
            continue
        if op.startswith(("mov", "orr", "add", "sub", "adr", "lea")) and regs:
            if arch == "x86_64":
                source_regs, dest = regs[:-1], regs[-1]
            else:
                dest, source_regs = regs[0], regs[1:]
            inherited = set().union(*(taint.get(reg, set()) for reg in source_regs))
            inherited_literals = set().union(*(literals.get(reg, set()) for reg in source_regs))
            inherited_literals.update(_path_literals(operand_text))
            inherited_strings = set().union(*(string_consts.get(reg, set()) for reg in source_regs))
            inherited_strings.update(_string_literals(operand_text))
            if inherited:
                taint[dest] = inherited
                constants.discard(dest)
            else:
                taint.pop(dest, None)
                # Immediate/symbol/address material with no tainted source is a
                # statically fixed value for argument-level reporting.
                if "#" in operand_text or "$" in operand_text or op.startswith(("adr", "lea")):
                    constants.add(dest)
                else:
                    constants.discard(dest)
            if inherited_literals:
                literals[dest] = inherited_literals
            else:
                literals.pop(dest, None)
            if inherited_strings:
                string_consts[dest] = inherited_strings
            else:
                string_consts.pop(dest, None)
        if op in ("ret", "retq"):
            summary.return_origins.update(taint.get(retreg, set()))

    summary.return_origins.update(taint.get(retreg, set()))
    summary.events.sort(key=lambda event: int(event.get("index", 0)))
    return summary


def _success_semantics() -> Dict[str, str]:
    rules = capability_rules()
    merged = dict(rules.get("guard_success", {}))
    merged.update(rules.get("guard_success_semantics", {}))
    return merged


def _controls_for(summary: _Summary, event: Dict, carried: List[Dict]) -> List[Dict]:
    from collectors.control_flow import evaluate_guard
    semantics = _success_semantics()
    controls = list(carried)
    event_index = int(event.get("index", 0))
    for control in summary.events:
        if control.get("kind") not in {"validation", "authorization"}:
            continue
        if int(control["index"]) >= event_index:
            continue
        scope = ("VALIDATION_REACHABLE_FROM_HANDLER" if control["kind"] == "validation"
                 else "AUTHORIZATION_REACHABLE_FROM_HANDLER")
        branch_address = ""
        unknown_reason = ""
        guard_evidence: Dict = {}
        for branch in summary.events:
            if (branch.get("kind") == "branch"
                    and branch.get("control_kind") == control["kind"]
                    and branch.get("uses_control_result") is True
                    and int(control["index"]) < int(branch["index"]) < event_index):
                evaluation = evaluate_guard(
                    summary.instructions, control, branch, event, semantics)
                if evaluation.proven:
                    scope = ("VALIDATION_GUARDS_SINK" if control["kind"] == "validation"
                             else "AUTHORIZATION_GUARDS_SINK")
                    branch_address = branch["address"]
                    guard_evidence = evaluation.evidence()
                    break
                if evaluation.reason and not unknown_reason:
                    unknown_reason = evaluation.reason
        controls.append({
            "kind": control["kind"], "api": control["api"], "scope": scope,
            "function": summary.name, "branch_address": branch_address,
            "unknown_reason": unknown_reason, "guard_evidence": guard_evidence,
        })
    return controls


def _source_parts(origin: str) -> Tuple[str, str, str, str]:
    parts = origin.split("|", 4)
    if len(parts) >= 4:
        return (parts[1], parts[2], parts[3], parts[4] if len(parts) > 4 else "")
    return ("unknown", "", "", "")


def _result_parts(origin: str) -> Tuple[str, str, str]:
    parts = origin.split("|", 3)
    return (parts[1], parts[2], parts[3]) if len(parts) == 4 else ("unknown", "", "")


def analyze_disassembly(
    text: str, source_patterns: Optional[List[str]] = None,
    sink_patterns: Optional[List[str]] = None,
    executable_ranges: Optional[List[Tuple[int, int]]] = None,
    function_starts: Optional[Dict[str, Iterable[int]]] = None,
    selector_refs: Optional[Dict[str, Dict[int, str]]] = None,
) -> DataflowAnalysis:
    """Return facts plus aggregate UNKNOWN instrumentation for one disassembly."""
    defaults = _expand_patterns()
    patterns = (
        source_patterns or defaults[0], sink_patterns or defaults[1],
        defaults[2], defaults[3], defaults[4],
    )
    functions = _parse_functions(text, executable_ranges, function_starts)
    unconditional_accept = _unconditional_accept_listeners(functions)
    name_index = {(func.arch, func.name): key for key, func in functions.items()}
    address_index = {(func.arch, func.start): key for key, func in functions.items()}
    return_summaries: Dict[str, Set[str]] = {key: set() for key in functions}
    summaries: Dict[str, _Summary] = {}
    for _ in range(8):
        summaries = {
            key: _analyze_function(
                func, functions, return_summaries, patterns, name_index,
                address_index, selector_refs)
            for key, func in functions.items()
        }
        updated = {key: set(summary.return_origins) for key, summary in summaries.items()}
        if updated == return_summaries:
            break
        return_summaries = updated

    # A source and sink coexisting in an unreferenced helper does not make the
    # sink reachable. Direct callers are the native pass's strongest bounded
    # reference evidence; optional Radare2 analysis adds thunk/ICOD/data refs.
    referenced_functions = {
        event["target"]
        for summary in summaries.values()
        for event in summary.events
        if event.get("kind") == "call" and event.get("target") in summaries
    }

    from collectors.callgraph import (
        CONFIRMED_DIRECT,
        CONFIRMED_INDIRECT,
        UNRESOLVED,
        CallGraph,
        is_reachable,
    )
    call_graph = CallGraph()
    for func_key, summary in summaries.items():
        for event in summary.events:
            if event.get("kind") == "call" and event.get("target") in summaries:
                call_graph.add_edge(func_key, event["target"])
        if summary.unknown_reasons & {"UNKNOWN_INDIRECT_CALL", "UNKNOWN_BLOCK_CALLBACK"}:
            call_graph.mark_indirect(func_key)
    source_functions = {
        func_key for func_key, summary in summaries.items()
        if any(event.get("kind") == "source" for event in summary.events)
    }
    name_to_key = {summary.name: func_key for func_key, summary in summaries.items()}

    def handler_entry_state(handler_name: str) -> str:
        """Whether the trust-boundary handler is entered directly or indirectly."""
        handler_key = name_to_key.get(handler_name)
        if handler_key not in source_functions:
            return UNRESOLVED
        if call_graph.incoming(handler_key):
            return CONFIRMED_DIRECT
        return CONFIRMED_INDIRECT

    reply_results: Dict[Tuple[str, str, str], List[Dict]] = {}
    for summary in summaries.values():
        for event in summary.events:
            if event.get("kind") != "reply":
                continue
            for origins in event.get("arg_origins", []):
                for origin in origins:
                    if origin.startswith("RESULT|"):
                        reply_results.setdefault(_result_parts(origin), []).append(event)

    facts: List[Dict] = []
    unknown_counts: Dict[str, int] = {}
    traversal_visits = 0
    traversal_budget = 500_000
    fact_budget = 20_000
    source_budget = 5_000

    def walk(key: str, minimum_index: int, arg_map: Dict[int, Set[str]],
             constant_map: Set[int], literal_map: Dict[int, Set[str]],
             call_path: List[str], carried_controls: List[Dict], seen: Set[str], depth: int,
             root_source: str) -> None:
        nonlocal traversal_visits
        traversal_visits += 1
        if traversal_visits > traversal_budget or len(facts) >= fact_budget:
            unknown_counts["UNKNOWN_ANALYSIS_BUDGET"] = 1
            return
        if depth > 6 or key in seen or key not in summaries:
            return
        summary = summaries[key]
        resolved_unknown = sorted(summary.unknown_reasons)
        for reason in resolved_unknown:
            unknown_counts[reason] = unknown_counts.get(reason, 0) + 1
        for event in summary.events:
            if int(event.get("index", 0)) <= minimum_index:
                continue
            kind = event.get("kind")
            if kind == "sink":
                resolved_args = [
                    _resolve_origins(origins, arg_map)
                    for origins in event.get("arg_origins", [])
                ]
                resolved_literals = []
                for sink_index, origins in enumerate(event.get("arg_origins", [])):
                    values = set((event.get("argument_literals") or [])[sink_index]
                                 if sink_index < len(event.get("argument_literals") or []) else [])
                    for origin in origins:
                        if origin.startswith("ARG:"):
                            try:
                                values.update(literal_map.get(int(origin.split(":", 1)[1]), set()))
                            except ValueError:
                                pass
                    resolved_literals.append(values)
                controlled = [
                    index for index, origins in enumerate(resolved_args)
                    if any(origin.startswith("SOURCE|") for origin in _input_origins(origins))
                ]
                constant_indexes = set(event.get("constant_argument_indexes", []))
                for sink_index, origins in enumerate(event.get("arg_origins", [])):
                    if any(
                        origin.startswith("ARG:")
                        and int(origin.split(":", 1)[1]) in constant_map
                        for origin in origins
                    ):
                        constant_indexes.add(sink_index)
                source_origins = [
                    origin for origins in resolved_args for origin in _input_origins(origins)
                    if origin.startswith("SOURCE|")
                ]
                if not source_origins:
                    # A call path from the source-containing handler still
                    # establishes reachability even when all sink args are constants.
                    source_origins = [root_source]
                controls = _controls_for(summary, event, carried_controls)
                control_unknown = {control["unknown_reason"] for control in controls
                                   if control.get("unknown_reason")}
                sink_key = (event["api"], event["address"], summary.name)
                replies_for_sink = reply_results.get(sink_key, [])
                source_api, source_address, source_function, source_key = (
                    _source_parts(source_origins[0]) if source_origins
                    else ("unknown", "", call_path[0] if call_path else summary.name, ""))
                if not source_key:
                    source_key = next(
                        (_source_parts(origin)[3] for origin in source_origins
                         if _source_parts(origin)[3]), "")
                propagation = [f"{source_api}@{source_address}"]
                propagation += [f"call {name}" for name in call_path[1:]]
                propagation.append(f"{event['api']}@{event['address']}")
                handler_name = call_path[0] if call_path else summary.name
                handler_entry = handler_entry_state(handler_name)
                reachability_state = (handler_entry if handler_entry in
                                      {CONFIRMED_DIRECT, CONFIRMED_INDIRECT}
                                      else UNRESOLVED)
                reachability_confirmed = is_reachable(reachability_state)
                facts.append({
                    "source_api": source_api,
                    "source_address": source_address,
                    "source_function": source_function,
                    "source_key": source_key or None,
                    "source_binding": "INFERRED",
                    "sink_api": event["api"],
                    "sink_address": event["address"],
                    "function": summary.name,
                    "entry_point_function": handler_name,
                    "call_path": list(call_path),
                    "reachability_state": reachability_state,
                    "handler_entry": handler_entry,
                    "reachability_confirmed": reachability_confirmed,
                    "reachability_evidence": (
                        "CALL_REFERENCE" if len(call_path) > 1 or key in referenced_functions
                        else "ENTRY_HANDLER" if reachability_confirmed else "NO_CALLER_REFERENCE"
                    ),
                    "controlled_argument_indexes": controlled,
                    "descriptor_provenance": {
                        str(index): [json.loads(origin.split("|", 1)[1])
                                     for origin in sorted(origins)
                                     if origin.startswith("RESOURCE|")]
                        for index, origins in enumerate(resolved_args)
                        if any(origin.startswith("RESOURCE|") for origin in origins)
                    },
                    "constant_argument_indexes": sorted(constant_indexes),
                    "path_literals": sorted(set().union(*resolved_literals)
                                            if resolved_literals else set()),
                    "propagation": propagation,
                    "reply_dataflow": [
                        f"{event['api']}@{event['address']} -> {reply['api']}@{reply['address']}"
                        for reply in replies_for_sink
                    ],
                    "validation_controls": [c for c in controls if c["kind"] == "validation"],
                    "authorization_controls": [c for c in controls if c["kind"] == "authorization"],
                    "unknown_reasons": sorted(set(resolved_unknown) | control_unknown | (
                        set() if reachability_confirmed else {"UNKNOWN_NO_CALL_PATH"})),
                    "confidence": ("HIGH" if controlled and len(call_path) == 1
                                   else "MEDIUM"),
                })
            elif kind == "call":
                resolved = [
                    _resolve_origins(origins, arg_map)
                    for origins in event.get("arg_origins", [])
                ]
                next_map = {i: origins for i, origins in enumerate(resolved) if origins}
                next_constants = set(event.get("constant_argument_indexes", []))
                next_literals: Dict[int, Set[str]] = {}
                event_literals = event.get("argument_literals") or []
                for callee_index, origins in enumerate(event.get("arg_origins", [])):
                    values = set(event_literals[callee_index]
                                 if callee_index < len(event_literals) else [])
                    for origin in origins:
                        if origin.startswith("ARG:"):
                            try:
                                values.update(literal_map.get(int(origin.split(":", 1)[1]), set()))
                            except ValueError:
                                pass
                    if values:
                        next_literals[callee_index] = values
                for callee_index, origins in enumerate(event.get("arg_origins", [])):
                    if any(
                        origin.startswith("ARG:")
                        and int(origin.split(":", 1)[1]) in constant_map
                        for origin in origins
                    ):
                        next_constants.add(callee_index)
                controls = _controls_for(summary, event, carried_controls)
                walk(event["target"], -1, next_map, next_constants, next_literals,
                     call_path + [summaries[event["target"]].name],
                     controls, seen | {key}, depth + 1, root_source)

    source_count = 0
    for key, summary in summaries.items():
        for source in [e for e in summary.events if e.get("kind") == "source"]:
            source_count += 1
            if source_count > source_budget:
                unknown_counts["UNKNOWN_ANALYSIS_BUDGET"] = 1
                break
            walk(key, int(source["index"]), {}, set(), {}, [summary.name], [], set(), 0,
                 source["origin"])

    unique: List[Dict] = []
    seen_facts = set()
    for fact in facts:
        key = (fact["entry_point_function"], fact["source_address"], fact["sink_address"],
               tuple(fact["controlled_argument_indexes"]), tuple(fact["call_path"]))
        if key not in seen_facts:
            seen_facts.add(key)
            unique.append(fact)
    direct_calls = sum(1 for s in summaries.values() for e in s.events if e.get("kind") == "call")
    from collectors.xpc_dispatch import analyze_xpc_dispatch
    dispatch = analyze_xpc_dispatch(text, executable_ranges, function_starts)
    return DataflowAnalysis(
        facts=unique, unknown_reasons=unknown_counts,
        functions_analyzed=len(functions), direct_calls=direct_calls,
        unconditional_accept_listeners=unconditional_accept,
        ipc_operations=dispatch.operations,
        ipc_operation_unknown_reasons=dispatch.unknown_reasons,
    )


def parse_disassembly(
    text: str, source_patterns: Optional[List[str]] = None,
    sink_patterns: Optional[List[str]] = None,
    executable_ranges: Optional[List[Tuple[int, int]]] = None,
    function_starts: Optional[Dict[str, Iterable[int]]] = None,
    selector_refs: Optional[Dict[str, Dict[int, str]]] = None,
) -> List[Dict]:
    """Compatibility wrapper returning only dataflow facts."""
    return analyze_disassembly(
        text, source_patterns, sink_patterns, executable_ranges,
        function_starts, selector_refs).facts


def parse_executable_text_ranges(load_commands: str) -> List[Tuple[int, int]]:
    """Extract executable ``__TEXT,__text`` VM ranges from ``otool -l``."""
    ranges: List[Tuple[int, int]] = []
    section: Dict[str, str] = {}
    in_section = False
    for raw in load_commands.splitlines() + ["Section"]:
        line = raw.strip()
        if line == "Section":
            if (section.get("sectname") == "__text"
                    and section.get("segname") == "__TEXT"):
                try:
                    start = int(section["addr"], 0)
                    size = int(section["size"], 0)
                except (KeyError, ValueError):
                    pass
                else:
                    if size:
                        ranges.append((start, start + size))
            section = {}
            in_section = True
            continue
        if in_section:
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0] in {"sectname", "segname", "addr", "size"}:
                section[parts[0]] = parts[1]
    return ranges


def inspect_dataflow(path: str, macho) -> DataflowAnalysis:
    """Run the bounded pass only when source and sink imports both exist."""
    if not macho or not getattr(macho, "is_macho", False):
        return DataflowAnalysis()
    sources, sinks, _replies, _validation, _authorization = _expand_patterns()
    imports = list(getattr(macho, "imported_symbols", []) or [])
    has_source = any(any(_matches(name, pattern) for pattern in sources)
                     for name in imports)
    if not has_source:
        return DataflowAnalysis(unknown_reasons={"UNKNOWN_NO_IPC_SOURCE": 1})
    starts = getattr(macho, "function_starts", None) or None
    selectors = getattr(macho, "objc_selector_refs", None) or None
    if not any(any(_matches(name, pattern) for pattern in sinks) for name in imports):
        # No known sink: still extract the request/dispatch surface, which does
        # not depend on a sink import.
        result = run(["otool", "-tvV", path], timeout=90.0)
        if not result.ok:
            return DataflowAnalysis(unknown_reasons={"UNKNOWN_OTHER": 1})
        ranges = list(getattr(macho, "text_ranges", []) or [])
        from collectors.xpc_dispatch import analyze_xpc_dispatch
        dispatch = analyze_xpc_dispatch(result.stdout, ranges or None, starts)
        return DataflowAnalysis(
            ipc_operations=dispatch.operations,
            ipc_operation_unknown_reasons=dispatch.unknown_reasons,
        )
    result = run(["otool", "-tvV", path], timeout=90.0)
    if not result.ok:
        return DataflowAnalysis(unknown_reasons={"UNKNOWN_OTHER": 1})
    ranges = list(getattr(macho, "text_ranges", []) or [])
    if not ranges:
        sections = run(["otool", "-l", path], timeout=40.0)
        ranges = parse_executable_text_ranges(sections.stdout) if sections.ok else []
    if not ranges:
        return DataflowAnalysis(unknown_reasons={"UNKNOWN_OTHER": 1})
    return analyze_disassembly(result.stdout, sources, sinks, ranges, starts,
                               selectors)
