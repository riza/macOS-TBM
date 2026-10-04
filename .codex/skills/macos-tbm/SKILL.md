---
name: macos-tbm
description: Use this repository's macOS Trust Boundary Mapper to scan launchd services and Mach/XPC attack surfaces, inspect binaries and code-signing metadata, query trust-boundary graphs, export reports, triage bug-bounty signals, and interpret findings conservatively. Trigger for requests about running, extending, testing, or explaining this project's CLI, rules, reports, or analyzers.
---

# macOS-TBM project skill

The default pipeline is a read-only static research tool. Optional Radare2 deep
analysis and conservative XPC/Mach reachability validation run only when the
user explicitly requests them. Neither establishes exploitability.

## Safety and evidence rules

- Work from the repository root and prefer `tbm.py` plus checked-in tests.
- Never load, unload, enable, disable, bootstrap, bootout, or otherwise mutate
  launchd jobs.
- Runtime probing must be explicit, bounded, non-destructive and reported as
  active. Connect-only is the default; sending even an empty XPC dictionary
  requires its separate flag. Never fuzz, invoke destructive operations,
  elevate, persist, alter credentials/settings, or produce exploit/PoC code.
- Never turn `not observed` into `absent`, `safe`, or proof of exploitability.
  Preserve `NONE_OBSERVED`, `WEAK`, `MEDIUM`, and `STRONG` exactly.
- Distinguish linked frameworks from imported APIs, declared lookups from
  successful connections, and client-held entitlements from server checks.
- Treat an imported sensitive API as a `SINK_CANDIDATE`, never as an attacker
  primitive. Preserve the maturity sequence `SINK_CANDIDATE` →
  `REACHABLE_SINK` → `CONTROLLED_SINK` → `PRIMITIVE` → `IMPACT`; use strong
  primitive names only when the corresponding proof gate is satisfied.
- Keep caller identity verification separate from per-operation authorization.
  Binary-wide presence is not a sink guard, and `NONE_OBSERVED` is not proof of
  an authorization bypass.
- Keep research priority separate from exploitability evidence. Report named
  `UNKNOWN_*` causes, missing evidence, and next research steps rather than
  silently filling unsupported relationships.

## Standard workflow

1. Check `python3 tbm.py --help` and the relevant subcommand help.
2. Start with a scoped passive scan: `python3 tbm.py scan --scope daemons`. It
   prints a summary and saves the artifacts to `./results`, including
   `scan.txt`, the full terminal report with one dossier per target.
3. Use `--json` for a machine-readable stdout stream (the only mode that writes
   nothing), `-out DIR` for another directory, or `--detail` to print the
   dossiers in the terminal as well.
4. Narrow review with `graph --boundaries`, `--node`, `--path`, or `--deputy`.
5. Use `protocol` for passive NSXPC extraction.
6. Report target identity, interface, concrete evidence, caller-validation
   evidence, operation maturity, both scores, limitations, and open
   manual-review questions.

For human terminal review, use `tui --report ./results/report.json`; it renders
a keyboard-driven Textual dashboard whose detail pane holds the same dossier as
the HTML report. The table lists every target that passes the filters and
scrolls; `--limit` applies to the non-interactive views only. Use `/`, `p`, `v`, `r`, arrows/`j`/`k`, `tab` (scroll the
dossier), `f` (full width), and `q` for navigation. Without Textual or a TTY it
falls back to the Rich dashboard; narrow that view with `--min-score`,
`--priority`, `--validation`, `--sink`, or `--search`, and add `--detail` to
print each shown dossier.

`scan` without `-out` writes to `./results` and prints only the summary plus the
list of files written; the dossiers go to `scan.txt`. Keep it that way: nothing
the report contains may be dropped on the way to disk, so `scan.txt` is the
whole terminal report, not an excerpt. `--detail` echoes it to stdout,
`--detail-limit` caps how many dossiers are written, and `--list-limit` caps
long Mach-O lists inside one (0 = no cap). A capped list must always state how
many entries were withheld.

## Output and scripting

`graph`, `protocol`, `hunt`, `xref`, and `entowners`
stream to stdout by default. Pass `-out <file>` only when persistence is needed:

```bash
python3 tbm.py graph --boundaries --format json | jq 'length'
python3 tbm.py protocol com.apple.example --format json
python3 tbm.py hunt --class lpe --top 20
python3 tbm.py hunt --label com.apple.example
python3 tbm.py entowners com.apple.private.tcc --contains
python3 tbm.py xref /usr/libexec/exampled com.apple.example --arch arm64e
```

`hunt` adds bug-bounty dimensions (LPE/RCE/DOS/CRED) on top of the TBM score,
`entowners` lists which scanned targets hold an entitlement, and `xref` finds
code references to a string in a Mach-O (RE helper). All three are read-only and
operate on an existing `./results/report.json` or a binary path.

For `scan`, the default is a compact terminal summary plus artifacts in
`./results`. Use JSON for a pipe, or `-out` for another directory:

```bash
python3 tbm.py scan --json | jq '.summary'
python3 tbm.py scan --scope daemons -out ./results
```

Keep machine-readable stdout clean. New commands should send progress and
status messages to stderr when stdout is being piped.

Rich is the default interactive progress backend and tqdm is the fallback when
Rich is unavailable. Both are optional dependencies in `requirements.txt`; keep
every UI enhancement optional and retain a deterministic stdlib fallback.

## Rules and implementation changes

Read the relevant declarative rule before changing detection behavior:

- `rules/signals.json`: symbol, library, string, and subsystem signals.
- `rules/entitlements.json`: entitlement categories and sensitivity.
- `rules/scoring.json`: explainable score weights and caps.
- `rules/capabilities.json`: IPC sources, reply APIs, operation argument
  semantics, candidate names, proof-gated primitive names, chain rules,
  `dispatch_keys`/`dispatch_min_chain`, `guard_success_semantics`,
  `profile_predicates`, and descriptor producer/consumer semantics.
- `rules/lpe.json`: filesystem sinks, `resource_checks` classification, and
  research weights.

Mach-O headers and load commands (`LC_FUNCTION_STARTS`, `LC_MAIN`, dylibs,
rpaths, sections, `__objc_selrefs`) are parsed natively in
`collectors/macho.py`; `otool` is only needed for disassembly. Function
boundaries come from `LC_FUNCTION_STARTS`, and the direct call graph,
reachability states, XPC request/dispatch extraction, and operation-guard proof
live in `collectors/callgraph.py`, `collectors/xpc_dispatch.py`, and
`collectors/control_flow.py`. Findings expose `ipc_operations`,
`caller_profiles`, `policy_paths`, `descriptor_provenance`, `call_path_state`,
and `resource_scope`; preserve their `UNKNOWN_*`/`UNRESOLVED` values.

Prefer declarative rule changes over analyzer code when possible. Every new
signal, score change, graph edge, output format, or safety invariant needs a
focused regression test under `tests/`. Run:

```bash
python3 -m unittest discover -s tests -v
```

If macOS-only tools (`codesign`, `otool`, `nm`, `strings`, `launchctl`, or XPC)
are unavailable, state that limitation and use fixtures/unit tests instead of
inventing evidence.
