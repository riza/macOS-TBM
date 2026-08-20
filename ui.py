"""Optional terminal UI helpers.

The scanner remains usable with Python's standard library alone. Rich and tqdm
are detected at runtime and enhance interactive terminals when installed; pipes
and non-interactive environments stay plain and machine-readable.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app_info import VERSION, build_id


def rich_available() -> bool:
    try:
        import rich  # noqa: F401
    except ImportError:
        return False
    return True


# One logo for the CLI banner and the dashboard header.
LOGO = r"""  __  __
 / /_/ /  __ _
/ __/ _ \/  ' \
\__/_.__/_/_/_/"""


def print_banner(command: str, *, stream=None) -> None:
    """Print the human-facing identity banner to the selected terminal stream."""
    stream = stream or sys.stderr
    art = LOGO
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
        console = Console(file=stream)
        body = Text.assemble(
            (art + "\n", "bold cyan"),
            (f"macOS-TBM  v{VERSION}  •  build {build_id()}  •  {command}", "dim"),
        )
        console.print(Panel(body, border_style="cyan", expand=False))
        return
    except ImportError:
        pass
    print(art, file=stream)
    print(f"macOS-TBM  v{VERSION}  |  build {build_id()}  |  {command}", file=stream)


def configure_logging(verbose: bool, *, interactive: bool = True) -> None:
    """Configure concise logs, using Rich only for an interactive terminal."""
    if interactive:
        try:
            from rich.logging import RichHandler
        except ImportError:
            RichHandler = None
        if RichHandler is not None:
            logging.basicConfig(
                level=logging.DEBUG if verbose else logging.INFO,
                format="%(message)s",
                datefmt="[%X]",
                handlers=[RichHandler(rich_tracebacks=True, markup=False, show_path=False)],
            )
            return
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


class ScanProgress:
    """Progress callback adapter for Rich, tqdm, or a quiet fallback."""

    def __init__(self, mode: str = "auto", *, enabled: bool = True, stream=None):
        self.mode = mode
        self.enabled = enabled and mode != "none"
        self.stream = stream or sys.stderr
        self._progress = None
        self._task = None
        self._bar = None
        self._last = 0

    def __enter__(self):
        if not self.enabled:
            return self
        mode = self.mode
        if mode in ("auto", "rich"):
            try:
                from rich.console import Console
                from rich.progress import (
                    BarColumn,
                    Progress,
                    SpinnerColumn,
                    TaskProgressColumn,
                    TextColumn,
                    TimeRemainingColumn,
                )
                self._progress = Progress(
                    SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                    BarColumn(), TaskProgressColumn(), TimeRemainingColumn(),
                    transient=True, console=Console(file=self.stream),
                )
                self._progress.start()
                return self
            except ImportError:
                if mode == "rich":
                    mode = "auto"
        if mode in ("auto", "tqdm"):
            try:
                from tqdm import tqdm
                self._bar = tqdm(total=0, unit="exe", desc="analyzing", file=self.stream,
                                 dynamic_ncols=True)
                return self
            except ImportError:
                self.enabled = False
        return self

    def update(self, done: int, total: int) -> None:
        if not self.enabled:
            return
        if self._progress is not None:
            if self._task is None:
                self._task = self._progress.add_task("analyzing executables", total=total)
            self._progress.update(self._task, completed=done, total=total)
        elif self._bar is not None:
            if self._bar.total != total:
                self._bar.total = total
                self._bar.refresh()
            self._bar.update(max(0, done - self._last))
        self._last = done

    def __exit__(self, exc_type, exc, tb):
        if self._progress is not None:
            self._progress.stop()
        if self._bar is not None:
            self._bar.close()



# ---------------------------------------------------------------------------
# per-target dossier
#
# The HTML drawer is the reference view: the terminal shows the same sections,
# in the same order, from the same report fields. Long Mach-O lists are capped
# so a full-system scan stays scrollable; the cap is reported, never silent.
# ---------------------------------------------------------------------------

LIST_LIMIT = 40

# One tag column width for every section, so the dossier reads as one table.
TAG_WIDTH = 18

# One palette for every view. Validation follows the dossier's convention:
# green where evidence was observed, yellow where it was not.
PRIORITY_STYLES = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "INFO": "cyan"}
VALIDATION_STYLES = {"STRONG": "green", "MEDIUM": "cyan", "WEAK": "yellow",
                     "NONE_OBSERVED": "dim yellow"}

_DOSSIER_SECTIONS = (
    "launchd metadata", "code signing", "why it is interesting", "score contributors",
    "sensitive subsystems", "caller validation", "entitlements", "checked entitlements",
    "findings", "manual research questions", "binary detail",
)


def _text(value: Any) -> str:
    """Render a report value for a terminal cell without inventing content."""
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(v) for v in value) or "-"
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _capped(items: Iterable[Any], limit: int) -> Tuple[List[Any], int]:
    """Return *limit* items plus the number withheld (0 disables the cap)."""
    items = list(items or [])
    if limit and len(items) > limit:
        return items[:limit], len(items) - limit
    return items, 0


def _entitlement_order(entitlements: Dict[str, Any], private: Sequence[str]) -> List[str]:
    high = set(private or [])
    return sorted(entitlements, key=lambda k: (k not in high, k))


def _validation_rows(assessment: Dict[str, Any]) -> Tuple[List[Tuple[str, int, str]],
                                                          List[Dict[str, Any]]]:
    """Group observed validation evidence by class; keep 'not observed' intact."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for ev in assessment.get("evidence") or []:
        groups.setdefault(ev.get("aspect") or "other", []).append(ev)
    seen = [(name, max(e.get("weight", 0) for e in evs),
             ", ".join(e.get("match", "") for e in evs))
            for name, evs in groups.items()]
    seen.sort(key=lambda row: -row[1])
    return seen, list(assessment.get("not_observed") or [])


def dossier_renderables(target: Dict[str, Any], *, list_limit: int = LIST_LIMIT) -> List[Any]:
    """Build the Rich renderables for one target, mirroring the HTML dossier.

    Every section is the same two-column grid: a fixed-width tag on the left and
    a folding body on the right, so field names, evidence kinds, weights and
    bullets all line up down the whole dossier instead of per-section.
    """
    from rich.console import Group
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    service = target.get("service") or {}
    executable = target.get("executable") or {}
    codesign = executable.get("codesign") or {}
    macho = executable.get("macho") or {}
    entitlements = codesign.get("entitlements") or {}
    private = set(target.get("entitlement_findings") or [])
    priority = target.get("priority", "-")
    colour = PRIORITY_STYLES.get(priority, "cyan")
    out: List[Any] = []

    def cell(value: Any, style: str = "") -> Any:
        return value if isinstance(value, Text) else Text(_text(value), style=style)

    def rows(pairs: Sequence[Tuple[Any, Any]]) -> Table:
        table = Table.grid(padding=(0, 2))
        table.add_column(width=TAG_WIDTH, justify="right", no_wrap=True, style="cyan")
        table.add_column(overflow="fold", ratio=1)
        for tag, body in pairs:
            table.add_row(cell(tag), cell(body))
        return table

    def section(title: str) -> None:
        out.append(Rule(Text(title, style="bold white"), align="left", style="grey35"))

    def bullets(items: Sequence[Any], marker: str = "-", style: str = "dim") -> Table:
        shown, hidden = _capped(items, list_limit)
        pairs = [(Text(marker, style=style), _text(item)) for item in shown]
        if hidden:
            pairs.append((Text(""), Text(f"... {hidden:,} more", style="dim")))
        if not pairs:
            pairs = [(Text(""), Text("none", style="dim"))]
        return rows(pairs)

    title = Text()
    title.append(target.get("label", "-"), style=f"bold {colour}")
    title.append(f"  {priority}", style=colour)
    title.append(f"  score {target.get('score', 0)}", style="bold white")
    title.append(f"  {_text(service.get('service_type'))}/{_text(service.get('scope'))}"
                 f"  {_text(target.get('ipc_classification'))}", style="dim")
    if service.get("enabled") is False:
        title.append("  disabled", style="bold yellow")
    out.append(Rule(title, style=colour))

    section("launchd metadata")
    out.append(rows([
        ("plist", service.get("plist_path")),
        ("binary", service.get("associated_executable")),
        ("program", service.get("program") or service.get("program_arguments")),
        ("run as", f"{_text(service.get('run_as_user') or service.get('run_as'))}"
                   f"  ({_text(service.get('run_as_derivation'))})"),
        ("user / group", f"{_text(service.get('user_name'))} / {_text(service.get('group_name'))}"),
        ("load state", f"{'enabled' if service.get('enabled', True) else 'disabled'}"
                       f"  ({_text(service.get('enabled_derivation'))})"),
        ("mach services", service.get("mach_services")),
        ("sockets", service.get("sockets") or None),
        ("keep alive", service.get("keep_alive")),
        ("run at load", service.get("run_at_load")),
        ("environment", service.get("environment_variables") or None),
        ("xpc service", service.get("xpc_service")),
    ]))

    section("code signing")
    signed = codesign.get("is_signed")
    out.append(rows([
        ("signed", "unknown" if signed is None else ("yes" if signed else "no")),
        ("identifier", codesign.get("signer_identifier")),
        ("team", codesign.get("team_identifier")),
        ("platform binary", "unknown" if codesign.get("platform_binary") is None
         else ("yes" if codesign.get("platform_binary") else "no")),
        ("flags", codesign.get("flags")),
        ("authority", " <- ".join(codesign.get("authority") or []) or None),
        ("requirement", codesign.get("designated_requirement")),
        ("architectures", macho.get("architectures")),
    ]))

    section("why it is interesting")
    out.append(bullets(target.get("why_interesting") or target.get("research_leads") or []))

    section("score contributors")
    reasons = target.get("reasons") or []
    if reasons:
        widest = max(1, max(abs(r.get("weight", 0)) for r in reasons))
        pairs = []
        for reason in reasons:
            weight = reason.get("weight", 0)
            filled = max(1, round(10 * abs(weight) / widest))
            # Pad with dots rather than spaces: trailing spaces would be trimmed
            # and the bars would no longer share a left edge.
            bar = "#" * filled + "." * (10 - filled)
            tag = Text(f"{weight:+d} {bar}", style="green" if weight >= 0 else "red")
            pairs.append((tag, reason.get("reason")))
        out.append(rows(pairs))
    else:
        out.append(rows([("", Text("no contributors", style="dim"))]))

    section("sensitive subsystems - evidence")
    assessments = target.get("sink_assessments") or []
    if assessments:
        pairs = []
        for assessment in assessments:
            head = Text(f"{assessment.get('confidence', '-')}", style="yellow")
            head.append(f"  {'=' * max(1, min(20, int(assessment.get('score', 0) // 2)))}"
                        f" {assessment.get('score', 0)}", style="dim")
            if assessment.get("aspects"):
                head.append(f"  [{', '.join(assessment['aspects'])}]", style="cyan")
            pairs.append((Text(_text(assessment.get("label")), style="bold magenta"), head))
            evidence, hidden = _capped(assessment.get("evidence"), list_limit)
            for ev in evidence:
                weight = ev.get("weight") or 0
                body = Text(_text(ev.get("match")))
                body.append(f"  {'+' + str(weight) if weight else 'not counted'}", style="dim")
                if ev.get("aspect"):
                    body.append(f"  {ev['aspect']}", style="cyan")
                pairs.append((Text(_text(ev.get("kind")), style="dim"), body))
            if hidden:
                pairs.append((Text(""), Text(f"... {hidden:,} more", style="dim")))
        out.append(rows(pairs))
    else:
        out.append(rows([("", Text("no sink indicators", style="dim"))]))

    validation = target.get("validation", "NONE_OBSERVED")
    assessment = target.get("validation_assessment") or {}
    section(f"caller validation - {validation} (score {assessment.get('score', 0)})")
    seen, missing = _validation_rows(assessment)
    pairs = []
    for name, weight, matches in seen:
        body = Text(name, style="green")
        body.append(f"  {matches}", style="")
        pairs.append((Text(f"ok +{weight}", style="green"), body))
    for miss in missing:
        body = Text(_text(miss.get("class")), style="yellow")
        body.append(f"  {_text(miss.get('description'))}", style="dim")
        if miss.get("looked_for"):
            body.append(f"  (looked for: {_text(miss.get('looked_for'))})", style="dim")
        pairs.append((Text(f"? +{miss.get('weight', 0)}", style="yellow"), body))
    if not pairs:
        pairs = [("", Text("no validation evidence", style="dim"))]
    pairs.append((Text(""), Text('Static evidence only. "Not observed" is a statement about'
                                 " this scanner, not about the service.", style="dim")))
    out.append(rows(pairs))

    section(f"entitlements ({len(entitlements)})")
    keys, hidden = _capped(_entitlement_order(entitlements, private), list_limit)
    pairs = []
    for key in keys:
        body = Text(key)
        body.append(f" = {_text(entitlements[key])}", style="cyan")
        pairs.append((Text("private", style="bold red") if key in private else Text(""), body))
    if hidden:
        pairs.append((Text(""), Text(f"... {hidden:,} more", style="dim")))
    out.append(rows(pairs or [("", Text("none", style="dim"))]))

    checked = target.get("checked_entitlements") or []
    if checked:
        section(f"checked entitlements ({len(checked)})")
        out.append(rows([("", Text("strings the binary appears to check on callers;"
                                   " not grants it holds", style="dim"))]))
        out.append(bullets(checked))

    findings = target.get("findings") or []
    section(f"findings ({len(findings)})")
    shown, hidden = _capped(findings, list_limit)
    pairs = []
    for finding in shown:
        level = finding.get("level", "?")
        style = {"FACT": "green", "HEURISTIC": "yellow"}.get(level, "dim")
        body = Text(_text(finding.get("message")))
        body.append(f"  [{_text(finding.get('category'))}]", style="dim")
        if finding.get("evidence"):
            body.append(f"\n{_text(finding.get('evidence'))}", style="dim")
        pairs.append((Text(level, style=style), body))
    if hidden:
        pairs.append((Text(""), Text(f"... {hidden:,} more", style="dim")))
    out.append(rows(pairs or [("", Text("none", style="dim"))]))

    section("manual research questions")
    out.append(bullets(target.get("research_questions") or [], marker="?", style="cyan"))

    section("binary detail")
    out.append(rows([
        ("path", executable.get("path")),
        ("mach-o / fat", f"{_text(macho.get('is_macho'))} / {_text(macho.get('is_fat'))}"),
        ("imported symbols", macho.get("imported_symbols_count",
                                       len(macho.get("imported_symbols") or []) or None)),
        ("exported symbols", macho.get("exported_symbols_count",
                                       len(macho.get("exported_symbols") or []) or None)),
        ("rpaths", macho.get("rpaths") or None),
        ("weak linked libs", len(macho.get("weak_linked_libs") or []) or None),
        ("errors", macho.get("errors") or None),
    ]))
    for title_text, values in (("linked libraries", macho.get("linked_libs") or []),
                               ("interesting strings", macho.get("interesting_strings") or []),
                               ("ObjC classes", macho.get("objc_classes") or [])):
        out.append(rows([(Text(title_text, style="bold cyan"), Text(f"{len(values):,}", style="dim"))]))
        out.append(bullets(values))
    return [Group(*out)]


def _dossier_lines(target: Dict[str, Any], *, list_limit: int = LIST_LIMIT) -> List[str]:
    """Plain-text dossier for when Rich is missing: same sections, same columns."""
    service = target.get("service") or {}
    executable = target.get("executable") or {}
    codesign = executable.get("codesign") or {}
    macho = executable.get("macho") or {}
    entitlements = codesign.get("entitlements") or {}
    private = set(target.get("entitlement_findings") or [])
    lines: List[str] = []

    def row(tag: Any, body: Any) -> None:
        lines.append(f"{_text(tag) if tag not in ('', None) else '':>{TAG_WIDTH}}  {_text(body)}")

    def section(title: str) -> None:
        lines.append(f"{title} " + "-" * max(0, 78 - len(title)))

    def items(values: Sequence[Any], marker: str = "-") -> None:
        shown, hidden = _capped(values, list_limit)
        for value in shown:
            row(marker, value)
        if hidden:
            row("", f"... {hidden:,} more")
        if not shown:
            row("", "none")

    lines.append(f"=== {target.get('label', '-')}  {target.get('priority', '-')}  "
                 f"score {target.get('score', 0)}  "
                 f"{_text(target.get('ipc_classification'))} ===")
    section("launchd metadata")
    for tag, value in (("plist", service.get("plist_path")),
                       ("binary", service.get("associated_executable")),
                       ("program", service.get("program") or service.get("program_arguments")),
                       ("run as", f"{_text(service.get('run_as_user') or service.get('run_as'))}"
                                  f"  ({_text(service.get('run_as_derivation'))})"),
                       ("user / group", f"{_text(service.get('user_name'))} /"
                                        f" {_text(service.get('group_name'))}"),
                       ("load state", f"{'enabled' if service.get('enabled', True) else 'disabled'}"
                                      f"  ({_text(service.get('enabled_derivation'))})"),
                       ("mach services", service.get("mach_services")),
                       ("sockets", service.get("sockets") or None),
                       ("keep alive", service.get("keep_alive")),
                       ("run at load", service.get("run_at_load")),
                       ("xpc service", service.get("xpc_service"))):
        row(tag, value)
    section("code signing")
    signed = codesign.get("is_signed")
    for tag, value in (("signed", "unknown" if signed is None else signed),
                       ("identifier", codesign.get("signer_identifier")),
                       ("team", codesign.get("team_identifier")),
                       ("platform binary", "unknown" if codesign.get("platform_binary") is None
                        else codesign.get("platform_binary")),
                       ("flags", codesign.get("flags")),
                       ("authority", " <- ".join(codesign.get("authority") or []) or None),
                       ("architectures", macho.get("architectures"))):
        row(tag, value)
    section("why it is interesting")
    items(target.get("why_interesting") or target.get("research_leads") or [])
    section("score contributors")
    for reason in target.get("reasons") or []:
        row(f"{reason.get('weight', 0):+d}", reason.get("reason"))
    section("sensitive subsystems - evidence")
    for assessment in target.get("sink_assessments") or []:
        row(assessment.get("label"), f"{assessment.get('confidence', '-')}"
                                     f"  {assessment.get('score', 0)}")
        evidence, hidden = _capped(assessment.get("evidence"), list_limit)
        for ev in evidence:
            weight = ev.get("weight") or 0
            row(ev.get("kind"), f"{_text(ev.get('match'))}"
                                f"  {('+' + str(weight)) if weight else 'not counted'}")
        if hidden:
            row("", f"... {hidden:,} more")
    assessment = target.get("validation_assessment") or {}
    section(f"caller validation - {target.get('validation', 'NONE_OBSERVED')}"
            f" (score {assessment.get('score', 0)})")
    seen, missing = _validation_rows(assessment)
    for name, weight, matches in seen:
        row(f"ok +{weight}", f"{name}  {matches}")
    for miss in missing:
        row(f"? +{miss.get('weight', 0)}",
            f"{_text(miss.get('class'))}  {_text(miss.get('description'))}")
    row("", 'Static evidence only. "Not observed" is a statement about this scanner,'
            " not about the service.")
    section(f"entitlements ({len(entitlements)})")
    keys, hidden = _capped(_entitlement_order(entitlements, private), list_limit)
    for key in keys:
        row("private" if key in private else "", f"{key} = {_text(entitlements[key])}")
    if hidden:
        row("", f"... {hidden:,} more")
    if not keys:
        row("", "none")
    checked = target.get("checked_entitlements") or []
    if checked:
        section(f"checked entitlements ({len(checked)})")
        items(checked)
    findings = target.get("findings") or []
    section(f"findings ({len(findings)})")
    shown, hidden = _capped(findings, list_limit)
    for finding in shown:
        row(finding.get("level"), f"{_text(finding.get('message'))}"
                                  f"  [{_text(finding.get('category'))}]")
        if finding.get("evidence"):
            row("", _text(finding.get("evidence")))
    if hidden:
        row("", f"... {hidden:,} more")
    if not shown:
        row("", "none")
    section("manual research questions")
    items(target.get("research_questions") or [], marker="?")
    section("binary detail")
    row("path", executable.get("path"))
    row("imported symbols", macho.get("imported_symbols_count",
                                      len(macho.get("imported_symbols") or []) or None))
    row("exported symbols", macho.get("exported_symbols_count",
                                      len(macho.get("exported_symbols") or []) or None))
    for title, values in (("linked libraries", macho.get("linked_libs") or []),
                          ("interesting strings", macho.get("interesting_strings") or []),
                          ("ObjC classes", macho.get("objc_classes") or [])):
        row(title, f"{len(values):,}")
        items(values)
    return lines


def render_dossiers(targets: Sequence[Dict[str, Any]], *, list_limit: int = LIST_LIMIT,
                    width: Optional[int] = None, stream=None) -> None:
    """Print the full dossier for every target, Rich when it is installed."""
    stream = stream or sys.stdout
    try:
        from rich.console import Console
        console = Console(file=stream, width=width)
        for target in targets:
            for renderable in dossier_renderables(target, list_limit=list_limit):
                console.print(renderable)
            console.print()
        return
    except ImportError:
        pass
    for target in targets:
        for line in _dossier_lines(target, list_limit=list_limit):
            print(line, file=stream)
        print(file=stream)


def render_tui(report: Dict[str, Any], *, limit: int = 25, min_score: int = 0,
               priority: Optional[str] = None, validation: Optional[str] = None,
               sink: Optional[str] = None, search: Optional[str] = None,
               detail: bool = False, list_limit: int = LIST_LIMIT,
               stream=None) -> None:
    """Render a terminal dashboard with the same review axes as the HTML report."""
    stream = stream or sys.stdout
    summary = report.get("summary", {})
    targets = report.get("targets", [])
    needle = search.lower() if search else None
    targets = [t for t in targets
               if t.get("score", 0) >= min_score
               and (not priority or t.get("priority") == priority)
               and (not validation or t.get("validation") == validation)
               and (not sink or sink.upper() in (t.get("sensitive_sinks") or []))
               and (not needle or needle in str(t.get("label", "")).lower())]
    rows = targets[:limit]
    try:
        from collections import Counter
        from rich.console import Console
        from rich.columns import Columns
        from rich.panel import Panel
        from rich.table import Table
        console = Console(file=stream)
        metrics = Table.grid(expand=True, padding=(0, 2))
        metrics.add_column(justify="right", style="cyan")
        metrics.add_column(justify="left", style="bold white")
        metrics.add_column(justify="right", style="cyan")
        metrics.add_column(justify="left", style="bold white")
        metrics.add_row("SERVICES", f"{summary.get('total_services', 0):,}",
                        "PRIVILEGED", f"{summary.get('privileged_services', 0):,}")
        metrics.add_row("MACH/XPC", f"{summary.get('mach_xpc_services', 0):,}",
                        "HIGH PRIORITY", f"{summary.get('high_priority_targets', 0):,}")
        metrics.add_row("ENTITLEMENTS", f"{summary.get('interesting_entitlement_count', 0):,}",
                        "SHOWING", f"{len(rows):,}/{len(targets):,}")
        console.print(Panel(metrics, title="macOS-TBM  •  report overview", border_style="cyan"))

        priority = Counter(t.get("priority", "UNKNOWN") for t in targets)
        validation = Counter(t.get("validation", "UNKNOWN") for t in targets)
        sinks = Counter(sink for t in targets for sink in (t.get("sensitive_sinks") or []))

        def distribution(title, counts, color):
            table = Table(title=title, box=None, padding=(0, 1), expand=True)
            table.add_column("CATEGORY", style=color)
            table.add_column("COUNT", justify="right")
            for name, count in counts.most_common(6):
                table.add_row(name, f"{count:,}")
            return Panel(table, border_style="dim")

        console.print(Columns([
            distribution("Priority", priority, "yellow"),
            distribution("Caller validation", validation, "green"),
            distribution("Sensitive sinks", sinks, "magenta"),
        ], equal=True, expand=True))

        table = Table(title=f"Top targets by score  ({len(rows)} of {len(targets)})",
                      expand=True, row_styles=["", "dim"])
        for col in ("SCORE", "PRIORITY", "VALIDATION", "SERVICE", "SINKS", "IPC"):
            table.add_column(col, overflow="ellipsis")
        for target in rows:
            table.add_row(
                str(target.get("score", 0)), target.get("priority", "-"),
                target.get("validation", "-"), target.get("label", "-"),
                ", ".join(target.get("sensitive_sinks") or []) or "-",
                target.get("ipc_classification", "-"),
            )
        console.print(table)
        if detail and rows:
            from rich.rule import Rule
            console.print(Rule(f"[bold cyan]Dossiers ({len(rows):,})[/bold cyan]"))
            render_dossiers(rows, list_limit=list_limit, stream=stream)
        return
    except ImportError:
        pass

    print("macOS-TBM", file=stream)
    print(
        f"services={summary.get('total_services', 0)} "
        f"privileged={summary.get('privileged_services', 0)} "
        f"mach_xpc={summary.get('mach_xpc_services', 0)} "
        f"high_priority={summary.get('high_priority_targets', 0)}",
        file=stream,
    )
    for target in rows:
        print(
            f"{target.get('score', 0):>3} {target.get('priority', '-'):8} "
            f"{target.get('validation', '-'):14} {target.get('label', '-')}",
            file=stream,
        )
    if detail and rows:
        render_dossiers(rows, list_limit=list_limit, stream=stream)


def build_dashboard(report: Dict[str, Any], *, list_limit: int = LIST_LIMIT):
    """Build the Textual dashboard app, or return None when Textual is missing."""
    try:
        from rich.align import Align
        from rich.console import Group
        from rich.text import Text
        from textual.app import App, ComposeResult
        from textual.containers import Horizontal, VerticalScroll
        from textual.widgets import DataTable, Footer, Input, Static
    except ImportError:
        return None

    class Dashboard(App):
        TITLE = "macOS-TBM"
        CSS = """
        Screen { background: #0b0e13; color: #dce4ef; }
        #banner { height: 8; border-bottom: solid #263246; }
        #search { margin: 0 1; border: round #263246; }
        #body { height: 1fr; }
        #targets { width: 65; padding: 0 1 0 3; overflow-x: hidden;
                   border-right: solid #263246; }
        #detail { width: 1fr; padding: 0 3 0 2; }
        #dossier { width: 1fr; }
        Footer { background: #111827; }
        /* The table borrows the dossier's palette: cyan chrome, a cyan cursor. */
        #targets > .datatable--header { background: #0b0e13; color: #36c5f0;
                                        text-style: bold; }
        #targets > .datatable--cursor { background: #1c3d52; color: #dce4ef; }
        #targets > .datatable--hover { background: #141a24; }
        """
        BINDINGS = [
            ("q", "quit", "Quit"), ("/", "focus_search", "Search"),
            ("p", "cycle_priority", "Priority"), ("v", "cycle_validation", "Validation"),
            ("r", "reset_filters", "Reset"), ("f", "toggle_full", "Full width"),
            ("j", "cursor_down", "Down"), ("k", "cursor_up", "Up"),
            ("tab", "focus_detail", "Scroll"),
        ]

        def __init__(self, data, item_limit):
            super().__init__()
            self.data = data
            self.item_limit = item_limit
            self.priority = None
            self.validation = None
            self.full = False
            self.filtered = []
            self.shown = []

        def compose(self) -> ComposeResult:
            yield Static(id="banner")
            yield Input(placeholder="search service label…   (press /)", id="search")
            with Horizontal(id="body"):
                yield DataTable(id="targets", cursor_type="row")
                with VerticalScroll(id="detail"):
                    yield Static("Select a target to inspect its dossier", id="dossier")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#targets", DataTable)
            table.zebra_stripes = True
            table.add_column("SCORE", width=5)
            table.add_column("PRIO", width=6)
            table.add_column("VALIDATION", width=13)
            table.add_column("SERVICE", width=26)
            self.refresh_view()
            table.focus()

        def current_targets(self):
            needle = self.query_one("#search", Input).value.lower()
            targets = self.data.get("targets", [])
            return [t for t in targets
                    if (not needle or needle in str(t.get("label", "")).lower())
                    and (not self.priority or t.get("priority") == self.priority)
                    and (not self.validation or t.get("validation") == self.validation)]

        def refresh_view(self) -> None:
            self.filtered = self.current_targets()
            self.shown = self.filtered
            table = self.query_one("#targets", DataTable)
            table.clear()
            for index, target in enumerate(self.shown):
                priority = target.get("priority", "-")
                validation = target.get("validation", "-")
                enabled = (target.get("service") or {}).get("enabled", True)
                table.add_row(
                    Text(str(target.get("score", 0)), justify="right", style="bold white"),
                    Text(priority, style=PRIORITY_STYLES.get(priority, "cyan")),
                    Text(validation, style=VALIDATION_STYLES.get(validation, "dim")),
                    Text(target.get("label", "-"), overflow="ellipsis",
                         style="" if enabled else "dim"),
                    key=str(index),
                )
            self.query_one("#banner", Static).update(self.banner())
            self.show_detail(0)

        def banner(self):
            """Logo, identity and counters, centred as one block above the panes."""
            summary = self.data.get("summary", {})
            counters = Text(justify="center")
            for name, value in (("SERVICES", summary.get("total_services", 0)),
                                ("PRIVILEGED", summary.get("privileged_services", 0)),
                                ("MACH/XPC", summary.get("mach_xpc_services", 0)),
                                ("HIGH", summary.get("high_priority_targets", 0)),
                                ("ENTITLEMENTS",
                                 summary.get("interesting_entitlement_count", 0))):
                counters.append(f"  {name} ", style="cyan")
                counters.append(f"{value:,}", style="bold white")
            state = Text(
                f"showing {len(self.shown):,} of {len(self.data.get('targets', [])):,}"
                f"   priority {self.priority or 'all'}"
                f"   validation {self.validation or 'all'}",
                style="dim", justify="center")
            return Group(
                Align.center(Text(LOGO, style="bold cyan")),
                Text(f"macOS-TBM  v{VERSION}  ·  build {build_id()}",
                     style="dim", justify="center"),
                counters, state,
            )

        def show_detail(self, index: int) -> None:
            """Render the full dossier for the row at *index* of the shown rows."""
            panel = self.query_one("#dossier", Static)
            if not (0 <= index < len(self.shown)):
                panel.update(Text("No target matches these filters", style="dim"))
                return
            panel.update(Group(*dossier_renderables(self.shown[index],
                                                    list_limit=self.item_limit)))
            self.query_one("#detail", VerticalScroll).scroll_home(animate=False)

        def _row_index(self, event) -> int:
            try:
                return int(str(event.row_key.value))
            except (AttributeError, TypeError, ValueError):
                return event.cursor_row

        def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
            self.show_detail(self._row_index(event))

        def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
            self.show_detail(self._row_index(event))

        def on_input_changed(self, event: Input.Changed) -> None:
            if event.input.id == "search":
                self.refresh_view()

        def action_focus_search(self) -> None:
            self.query_one("#search", Input).focus()

        def action_focus_detail(self) -> None:
            self.query_one("#detail", VerticalScroll).focus()

        def action_cursor_down(self) -> None:
            self.query_one("#targets", DataTable).action_cursor_down()

        def action_cursor_up(self) -> None:
            self.query_one("#targets", DataTable).action_cursor_up()

        def action_toggle_full(self) -> None:
            """Give the dossier the whole body width; the table stays one keypress away."""
            self.full = not self.full
            self.query_one("#targets", DataTable).display = not self.full

        def action_cycle_priority(self) -> None:
            values = [None, "HIGH", "MEDIUM", "LOW", "INFO"]
            self.priority = values[(values.index(self.priority) + 1) % len(values)]
            self.refresh_view()

        def action_cycle_validation(self) -> None:
            values = [None, "NONE_OBSERVED", "WEAK", "MEDIUM", "STRONG"]
            self.validation = values[(values.index(self.validation) + 1) % len(values)]
            self.refresh_view()

        def action_reset_filters(self) -> None:
            self.priority = self.validation = None
            self.query_one("#search", Input).value = ""
            self.refresh_view()

    return Dashboard(report, list_limit)


def run_tui_app(report: Dict[str, Any], *, list_limit: int = LIST_LIMIT) -> bool:
    """Run the keyboard-driven Textual dashboard; return False if unavailable.

    The dashboard scrolls, so it always lists every target that passes the
    filters; ``--limit`` caps the non-interactive views, which do not.
    """
    app = build_dashboard(report, list_limit=list_limit)
    if app is None:
        return False
    app.run()
    return True


def render_scan_result(summary: Dict[str, Any], *, output_dir: str,
                       artifacts=None, stream=None) -> None:
    """Render scan artifacts and the final summary for a human terminal."""
    stream = stream or sys.stdout
    artifacts = list(artifacts or [])
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        console = Console(file=stream)
        metrics = Table.grid(padding=(0, 2))
        metrics.add_column(style="cyan", justify="right")
        metrics.add_column(style="white")
        metrics.add_row("SERVICES", f"{summary.get('total_services', 0):,}")
        metrics.add_row("PRIVILEGED", f"{summary.get('privileged_services', 0):,}")
        metrics.add_row("MACH/XPC", f"{summary.get('mach_xpc_services', 0):,}")
        metrics.add_row("HIGH PRIORITY", f"{summary.get('high_priority_targets', 0):,}")
        console.print(Panel(metrics, title="Scan complete", border_style="green", expand=False))
        if artifacts:
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column(style="green", width=2)
            table.add_column(style="bold")
            table.add_column(style="dim")
            for artifact in artifacts:
                table.add_row("✓", artifact, f"→ {output_dir}")
            console.print(table)
        return
    except ImportError:
        pass

    if artifacts:
        for artifact in artifacts:
            print(f"  {artifact} -> {output_dir}", file=stream)
    print(
        f"\nScan complete. {summary.get('total_services', 0)} services, "
        f"{summary.get('privileged_services', 0)} privileged, "
        f"{summary.get('mach_xpc_services', 0)} Mach/XPC, "
        f"{summary.get('high_priority_targets', 0)} high-priority.",
        file=stream,
    )


def render_scan_cli(report: Dict[str, Any], *, limit: int = 15, detail: bool = True,
                    detail_limit: Optional[int] = None, list_limit: int = LIST_LIMIT,
                    width: Optional[int] = None, stream=None) -> None:
    """Render the scan: a linpeas-style summary followed by full target dossiers."""
    stream = stream or sys.stdout
    summary = report.get("summary", {})
    targets = report.get("targets", [])
    dossiers = targets[:detail_limit] if detail_limit else targets
    try:
        from collections import Counter
        from rich.console import Console, Group
        from rich.rule import Rule
        from rich.table import Table
        from rich.text import Text
        console = Console(file=stream, width=width)
        console.print(Rule("[bold cyan][+] macOS-TBM scan summary[/bold cyan]"))
        console.print(
            f"[cyan]Services[/cyan] {summary.get('total_services', 0):,}  "
            f"[cyan]Privileged[/cyan] {summary.get('privileged_services', 0):,}  "
            f"[cyan]Mach/XPC[/cyan] {summary.get('mach_xpc_services', 0):,}  "
            f"[yellow]High priority[/yellow] {summary.get('high_priority_targets', 0):,}  "
            f"[cyan]Entitlements[/cyan] {summary.get('interesting_entitlement_count', 0):,}"
        )

        high = [t for t in targets if t.get("priority") == "HIGH"][:limit]
        console.print(Rule("[bold red][!] High-priority review queue[/bold red]"))
        if high:
            table = Table(show_header=True, header_style="bold", expand=True)
            for col in ("SCORE", "SERVICE", "VALIDATION", "IPC", "SINKS"):
                table.add_column(col, overflow="ellipsis")
            for target in high:
                table.add_row(
                    str(target.get("score", 0)), target.get("label", "-"),
                    target.get("validation", "-"), target.get("ipc_classification", "-"),
                    ", ".join(target.get("sensitive_sinks") or []) or "-",
                )
            console.print(table)
        else:
            console.print("[green]  no HIGH priority targets in this scope[/green]")

        none_count = sum(1 for t in targets if t.get("validation") == "NONE_OBSERVED")
        console.print(Rule("[bold yellow][!] Caller-validation signals[/bold yellow]"))
        if none_count:
            console.print(
                f"[yellow]  {none_count:,} target(s) have no caller-validation signal observed statically.[/yellow]"
            )
        else:
            console.print("[green]  validation signals observed for every target[/green]")

        sinks = Counter(sink for t in targets for sink in (t.get("sensitive_sinks") or []))
        console.print(Rule("[bold magenta][+] Sensitive subsystems[/bold magenta]"))
        console.print("  " + "  ".join(f"{name}={count:,}" for name, count in sinks.most_common(8))
                     if sinks else "[dim]  none observed[/dim]")

        console.print(Rule("[bold blue][i] Suggested next steps[/bold blue]"))
        console.print(Group(
            Text("  tbm tui --report ./results/report.json    # keyboard review\n"),
            Text("  tbm graph --report ./results/report.json --boundaries --format json\n"),
            Text("  tbm protocol <service-or-binary> --format json"),
        ))
        if detail and dossiers:
            console.print(Rule(f"[bold cyan][+] Target dossiers "
                               f"({len(dossiers):,} of {len(targets):,})[/bold cyan]"))
            render_dossiers(dossiers, list_limit=list_limit, width=width, stream=stream)
        return
    except ImportError:
        pass

    print("[+] macOS-TBM scan summary", file=stream)
    print(
        f"Services={summary.get('total_services', 0)}  "
        f"Privileged={summary.get('privileged_services', 0)}  "
        f"Mach/XPC={summary.get('mach_xpc_services', 0)}  "
        f"High priority={summary.get('high_priority_targets', 0)}",
        file=stream,
    )
    print("[!] High-priority review queue", file=stream)
    for target in [t for t in targets if t.get("priority") == "HIGH"][:limit]:
        print(f"  {target.get('score', 0):>3} {target.get('label', '-')}", file=stream)
    if detail and dossiers:
        print(f"[+] Target dossiers ({len(dossiers)} of {len(targets)})", file=stream)
        render_dossiers(dossiers, list_limit=list_limit, stream=stream)
