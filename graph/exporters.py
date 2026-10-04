"""Graph exporters: JSON, Graphviz DOT, and Mermaid."""

from __future__ import annotations

from utils.jsonio import dumps as _json_dumps

from .model import Graph


def _sanitize_dot(value: str) -> str:
    return value.replace('"', '\\"')


def _sanitize_id(value: str) -> str:
    # DOT/Mermaid ids must be alphanumeric/underscore-safe.
    return "".join(ch if ch.isalnum() else "_" for ch in value)


def export_json(graph: Graph) -> str:
    """Serialize the graph to a JSON string."""
    return _json_dumps(graph.to_dict())


def export_dot(graph: Graph) -> str:
    """Render the graph as Graphviz DOT."""
    lines = ["digraph trust_boundaries {", '  rankdir=LR;', '  node [shape=box, style=rounded];']
    node_attrs = {
        "LaunchService": "fillcolor=\"#ffe0e0\", style=\"filled,rounded\"",
        "Executable": "fillcolor=\"#e0f0ff\", style=\"filled,rounded\"",
        "MachService": "fillcolor=\"#fff3cd\", style=\"filled,rounded\"",
        "Framework": "fillcolor=\"#e0ffe0\", style=\"filled,rounded\"",
        "PrivateFramework": "fillcolor=\"#e0ffe0\", style=\"filled,dashed,rounded\"",
        "Dylib": "fillcolor=\"#eef7ee\", style=\"filled,rounded\"",
        "Entitlement": "fillcolor=\"#f0e0ff\", style=\"filled,rounded\"",
        "SecuritySubsystem": "fillcolor=\"#ffcccc\", style=\"filled,rounded\"",
        "OperationFinding": "fillcolor=\"#fff3cd\", style=\"filled,rounded\"",
        "OperationSource": "fillcolor=\"#ffd6d6\", style=\"filled,rounded\"",
        "OperationSink": "fillcolor=\"#eadcff\", style=\"filled,rounded\"",
        "CandidateCapability": "fillcolor=\"#f7e8ff\", style=\"filled,dashed,rounded\"",
        "ProvenPrimitive": "fillcolor=\"#ffcccc\", style=\"filled,bold,rounded\"",
        "PostCondition": "fillcolor=\"#e8e8e8\", style=\"filled,rounded\"",
    }
    for n in graph.nodes.values():
        attrs = node_attrs.get(n.node_type, "")
        lines.append(f'  "{_sanitize_dot(n.id)}" [label="{_sanitize_dot(n.label)}", {attrs}];')
    for e in graph.edges:
        state = e.data.get("evidence_state", "INFERRED")
        style = ("solid" if state == "PROVEN" else
                 "dashed" if state in {"INFERRED", "DECLARED"} else "dotted")
        lines.append(
            f'  "{_sanitize_dot(e.source)}" -> "{_sanitize_dot(e.target)}" '
            f'[label="{_sanitize_dot(e.edge_type)} [{state}]", style="{style}"];'
        )
    lines.append("}")
    return "\n".join(lines)


def export_mermaid(graph: Graph) -> str:
    """Render the graph as Mermaid ``graph LR``."""
    lines = ["graph LR"]
    for e in graph.edges:
        state = e.data.get("evidence_state", "INFERRED")
        label = f"{_sanitize_dot(e.edge_type)} [{state}]"
        arrow = f" -->|{label}| " if state == "PROVEN" else f" -.->|{label}| "
        lines.append(
            f'  {_sanitize_id(e.source)}["{_sanitize_dot(e.source.split(":", 1)[-1])}"]'
            f'{arrow}'
            f'{_sanitize_id(e.target)}["{_sanitize_dot(e.target.split(":", 1)[-1])}"]'
        )
    return "\n".join(lines)
