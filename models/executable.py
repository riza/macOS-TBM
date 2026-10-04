"""Executable (Mach-O) and code-signing data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class MachOInfo:
    """Static metadata extracted from a Mach-O binary (read-only analysis)."""

    path: str
    is_macho: bool = False
    is_fat: bool = False
    architectures: List[str] = field(default_factory=list)
    linked_libs: List[str] = field(default_factory=list)
    weak_linked_libs: List[str] = field(default_factory=list)
    imported_symbols: List[str] = field(default_factory=list)
    exported_symbols: List[str] = field(default_factory=list)
    objc_classes: List[str] = field(default_factory=list)
    rpaths: List[str] = field(default_factory=list)
    interesting_strings: List[str] = field(default_factory=list)
    function_starts: Dict[str, List[int]] = field(default_factory=dict)
    objc_selector_refs: Dict[str, Dict[int, str]] = field(default_factory=dict)
    text_ranges: List[Tuple[int, int]] = field(default_factory=list)
    dataflow_facts: List[Dict[str, Any]] = field(default_factory=list)
    dataflow_unknown_reasons: Dict[str, int] = field(default_factory=dict)
    dataflow_functions_analyzed: int = 0
    dataflow_direct_calls: int = 0
    ipc_operations: List[Dict[str, Any]] = field(default_factory=list)
    ipc_operation_unknown_reasons: Dict[str, int] = field(default_factory=dict)
    nsxpc_unconditional_accept_listeners: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self, max_items: int = 250) -> Dict[str, Any]:
        def lim(xs: List[str]) -> List[str]:
            return list(xs[:max_items])

        return {
            "path": self.path,
            "is_macho": self.is_macho,
            "is_fat": self.is_fat,
            "architectures": list(self.architectures),
            "linked_libs": lim(self.linked_libs),
            "linked_libs_count": len(self.linked_libs),
            "weak_linked_libs": list(self.weak_linked_libs),
            "imported_symbols": lim(self.imported_symbols),
            "imported_symbols_count": len(self.imported_symbols),
            "exported_symbols": lim(self.exported_symbols),
            "exported_symbols_count": len(self.exported_symbols),
            "objc_classes": lim(self.objc_classes),
            "objc_classes_count": len(self.objc_classes),
            "rpaths": list(self.rpaths),
            "interesting_strings": lim(self.interesting_strings),
            "interesting_strings_count": len(self.interesting_strings),
            "function_starts": {arch: len(values)
                                for arch, values in self.function_starts.items()},
            "objc_selector_refs": {arch: len(values)
                                   for arch, values in self.objc_selector_refs.items()},
            "text_ranges": [[start, end] for start, end in self.text_ranges],
            "dataflow_facts": list(self.dataflow_facts[:max_items]),
            "dataflow_facts_count": len(self.dataflow_facts),
            "dataflow_unknown_reasons": dict(self.dataflow_unknown_reasons),
            "dataflow_functions_analyzed": self.dataflow_functions_analyzed,
            "dataflow_direct_calls": self.dataflow_direct_calls,
            "ipc_operations": list(self.ipc_operations[:max_items]),
            "ipc_operations_count": len(self.ipc_operations),
            "ipc_operation_unknown_reasons": dict(self.ipc_operation_unknown_reasons),
            "nsxpc_unconditional_accept_listeners": list(
                self.nsxpc_unconditional_accept_listeners),
            "errors": list(self.errors),
        }


@dataclass
class CodeSigningInfo:
    """Code-signing metadata plus parsed entitlements."""

    path: str
    is_signed: bool = False
    signer_identifier: Optional[str] = None
    team_identifier: Optional[str] = None
    designated_requirement: Optional[str] = None
    flags: List[str] = field(default_factory=list)
    authority: List[str] = field(default_factory=list)
    platform_binary: Optional[bool] = None  # None == UNKNOWN
    entitlements: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "is_signed": self.is_signed,
            "signer_identifier": self.signer_identifier,
            "team_identifier": self.team_identifier,
            "designated_requirement": self.designated_requirement,
            "flags": list(self.flags),
            "authority": list(self.authority),
            "platform_binary": self.platform_binary,
            "entitlements": dict(self.entitlements),
            "errors": list(self.errors),
        }


@dataclass
class Executable:
    """A unique executable discovered during the scan."""

    path: str
    macho: Optional[MachOInfo] = None
    codesign: Optional[CodeSigningInfo] = None
    analyzed: bool = False
    identity: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "analyzed": self.analyzed,
            "identity": dict(self.identity),
            "macho": self.macho.to_dict() if self.macho else None,
            "codesign": self.codesign.to_dict() if self.codesign else None,
        }
