# Changelog

## Research beta evidence hardening (unreleased)

- Restrict experimental r2 enrichment to executable CALL xrefs and exact sink
  addresses; remove handler-name and containing-function proof shortcuts.
- Preserve wrapper/return-value unknowns, finding confidence and unknown
  attacker control; record conflicts and reject updates for another finding.
- Add schema 2.2 provenance, Python-code/rule hashes, complete scan options and
  before/after native binary identity; discard r2 updates on identity changes.
- Expose backend evidence and conflicts in HTML and terminal dossiers.
- Add 13 authored r2 cases, compiled arm64/x86_64 native fixtures, an evaluation
  artifact and isolated wheel verification in CI; document x86 wrapper limits.


All notable changes to macOS-TBM are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Installable package and `tbm` command.** A `pyproject.toml` declares the
  project (`pip install .`, `pipx install .`) and installs a `tbm` console
  script equivalent to `python3 tbm.py`. Optional extras: `[ui]` (Rich + tqdm +
  Textual) and `[deep]` (r2pipe). The bundled `rules/*.json` are shipped as
  package data, so a wheel install resolves them the same way a checkout does.
  Running from the checkout with no install still works unchanged.

- **Lint, type, and coverage tooling.** `ruff` (imports, errors, bugbear) runs
  green and gates CI; `mypy` is configured and runs advisory while its findings
  are driven down; `coverage` reports branch coverage from the unit suite. A
  `dev` extra installs all three. Existing findings were fixed rather than
  suppressed: undefined `List` annotations in `reporting/html_report.py`,
  unused and unsorted imports, ambiguous loop names, lambda assignments, and
  unused loop variables.

- **`tbm deputy-all`.** The standalone `deputy_all.py` chain map is now a CLI
  subcommand. It walks every daemon in a report, lists the clients that hold its
  gate entitlement, expands chains while the deputy is itself a daemon, and marks
  the chains that end at an unprivileged client. Prints text by default; `-out
  PREFIX` writes `<PREFIX>.md/.csv/.json`. Covered by tests.

- **Native Mach-O parsing.** Mach-O headers and load commands are now read in
  Python instead of shelling out to `lipo`/`otool -l`: architectures (including
  the `arm64e` subtype), linked and weakly-linked dylibs, rpaths, `LC_MAIN`
  entry, `__TEXT,__text` ranges, and `__objc_selrefs`/`__objc_methname`. `otool`
  remains only for disassembly. Verified against `lipo` on 60 system binaries
  (no mismatch).

- **Authoritative function boundaries.** `LC_FUNCTION_STARTS` is decoded
  (fat-slice-aware ULEB128, range-validated, fail-closed) and drives function
  discovery, replacing the label heuristic that collapsed a stripped image into
  one function. On `DesktopServicesHelper` this turns 0 resolved direct calls
  into 8460 and 285 heuristic functions into 1915 real ones. A `%` inside an
  operand comment no longer fragments arm64 functions into x86_64 pieces.

- **Direct call graph and reachability states.** A new `collectors/callgraph.py`
  builds direct caller→callee edges and classifies each recovered path as
  `CONFIRMED_DIRECT`, `CONFIRMED_INDIRECT`, `UNRESOLVED`, or `NOT_OBSERVED`. An
  absent edge is uncertainty, never proof of unreachability. Call paths are
  surfaced per finding (`call_path_state`, `call_path`).

- **XPC request/dispatch extraction.** New `collectors/xpc_dispatch.py` reports
  `ipc_operations`: request key, operation value, dispatcher, resolved handler
  (function or basic block), handler input keys, and evidence. It recognizes
  string comparisons, local comparison wrappers that call `CFEqual`, integer
  `cmp #imm`/`b.eq` switches, and Objective-C selector dispatch resolved from
  `__objc_selrefs`. Relationships stay `PROVEN`/`INFERRED`/`UNRESOLVED`/
  `UNKNOWN_INDIRECT_HANDLER`; only `dispatch_keys` or a chain of at least
  `dispatch_min_chain` values enter the dispatch surface.

- **Objective-C selector sinks.** `removeItemAtPath:error:`,
  `setAttributes:ofItemAtPath:error:`, `createDirectoryAtPath:…`, and similar
  selectors are now matched (selector-aware prefix rules) with their method
  argument indices, so ObjC filesystem operations can reach the same maturity
  model as their C counterparts.

- **Native Mach-O reader tests.** `tests/test_macho_reader.py` covers thin, fat,
  and malformed images with synthetic fixtures.

- **Optional privileged-filesystem LPE hunting.** Scan reports now include
  conservative `lpe_findings` that correlate IPC-derived paths with root
  filesystem operations, separate caller and resource validation, recognize
  TOCTOU/unsafe-temp/sensitive-target context, and add filesystem nodes to the
  trust-boundary graph. `tbm hunt --class lpe` ranks these findings without
  treating imported APIs or `NONE_OBSERVED` as proof of exploitability.

- **Optional analysis backends.** `--deep-analysis radare2` uses lazy-loaded
  `r2pipe` for bounded xref/callsite confirmation on prioritized unresolved
  findings. `--runtime-probe` performs explicit connect-only XPC/Mach
  reachability validation; `--probe-send-empty` / `tbm probe --send-empty`
  separately authorize one empty dictionary. Both contribute evidence to the
  existing operation finding, preserve conflicts, and never turn connection
  success into authorization bypass or a proven primitive.

- **Explicit operation maturity.** Sensitive API references now begin as
  `SINK_CANDIDATE` and advance only through recovered evidence:
  `REACHABLE_SINK`, `CONTROLLED_SINK`, `PRIMITIVE`, then `IMPACT`. Reports use
  conservative candidate names until the corresponding primitive is proven;
  an import of `ftruncate` is no longer labelled arbitrary file write, and an
  import of `SecKeyCreateSignature` is no longer labelled a signing oracle.
- **Bounded interprocedural dataflow.** The read-only arm64/x86 `otool` pass now
  follows registers, stack slots, direct helper calls, simple wrapper returns,
  per-argument constants, and sensitive result flow into XPC/Mach replies.
  Validation and authorization are independent, operation-scoped controls with
  `PRESENT_IN_BINARY`, `REACHABLE_FROM_HANDLER`, and `GUARDS_SINK` states.
  Unsupported ObjC/Swift dispatch, indirect calls, aliases, wrappers, return
  values, callbacks, and Mach layouts remain explicit `UNKNOWN_*` causes.
- **Separate research priority and exploitability evidence.** Research priority
  ranks high-value binaries for manual review. A distinct ten-axis evidence
  score measures attacker-oriented proof and is hard-capped by maturity, so a
  root service can remain high priority without looking proven exploitable.
  `scan` and `hunt` gained maturity, minimum-evidence and proven-only filters;
  JSON schema 2.0 retains deprecated compatibility fields explicitly.
- **Evidence-complete reporting.** JSON, HTML, terminal dossiers, CSV/Markdown,
  DOT and Mermaid now carry candidate/proven names, maturity, handler and sink
  addresses, reply flow, control scope, edge proof state, missing evidence,
  next research steps, and aggregated unknown causes.

- **Full dossiers in the terminal.** `tbm scan` (without `-out`) and the `tui`
  detail pane now render the same sections as the HTML dossier from the same
  report fields: launchd metadata, code signing, why it is interesting, score
  contributors, sensitive-subsystem evidence, the caller-validation table
  (observed classes and the ones not observed, with what was looked for), every
  entitlement with private ones first, checked entitlements, findings with
  evidence, research questions, and binary detail. `--detail` prints them,
  `--detail-limit` caps the number of dossiers, and
  `--list-limit` caps long Mach-O lists inside one (`0` = no cap; the number
  withheld is always printed). The Textual dashboard gained a scrollable dossier
  pane (`tab`), a full-width toggle (`f`), and live updates as the row cursor
  moves; the non-interactive Rich view gained `tui --detail`.

### Changed

- **README split into a landing page and `docs/` guides.** The README keeps the
  pitch, badges, quick start, feature list, requirements and license; the deep
  material moved to `docs/`: getting started, usage, architecture, trust model
  and scoring, querying and protocol analysis, evidence and limitations,
  per-entity export, extending the rule sets, safety, and development. The
  capability contract and XPC dispatch sections moved with them, and the README
  now links a documentation index.

- **`scan` saves instead of flooding the terminal.** Without `-out` it now
  writes to `./results` — `report.json`, `report.html`, the graph exports and
  `scan.txt`, which holds the complete terminal report including every
  per-target dossier — and prints the summary plus the list of files written.
  `--detail` prints the dossiers in the terminal as well. `--json` remains the
  one mode that writes nothing and streams the report to stdout, and
  `--html` / `--graph` no longer require `-out`.
- **One palette across every view.** The dashboard table now uses the dossier's
  colours — priority red / yellow / green, and caller validation green where
  evidence was observed, yellow where it was not, so `NONE_OBSERVED` no longer
  reads as reassuring — with zebra rows, a cyan header and a cyan cursor. Rich
  output also keeps colour when it writes to a terminal; files and pipes stay
  plain, so `scan.txt` and piped output are unchanged.
- **One aligned column layout for the dossier.** Every section is now the same
  two-column grid — an 18-wide tag column and a folding body — so field names,
  evidence kinds, weights, bullets and entitlement markers line up down the
  whole dossier instead of shifting per section. Score bars are dot-padded to a
  fixed width so they share both edges.
- **A simpler dashboard.** The Textual header and the duplicated key-hint strip
  are gone; the `tbm` logo, version, counters and active filters sit centred at
  the top, search spans the width, and the target table keeps four fixed-width
  columns (score, priority, validation, service) with the rest of the width
  going to the dossier. The table starts on the same column as the search box
  and runs the full height of the screen: it now lists every target that passes
  the filters and scrolls, so `tui --limit` caps only the non-interactive view.

- **`tbm protocol`** — passively extracts the NSXPC protocol a daemon exports
  (`otool -ov` + `nm`, with ObjC type-encoding decode and, for modern arm64e
  relative method lists, selref→selector resolution).
- **Server-side entitlement check signal** — the `com.apple.*` keys a binary
  *checks* on its clients (held vs checked are different sets), stored as
  `checked_entitlements` in `report.json`, emitted as `CHECKED_ENTITLEMENT`
  graph edges, and used by `tbm graph --deputy` as the default gate (falling
  back to the `<label>.*` heuristic).

- **An interactive graph explorer in the HTML report.** The trust core (3,597
  nodes, 7,137 edges) is index-encoded into ~290 KB and rendered on a canvas
  with three modes: a layered boundary-crossing ladder (client → Mach service →
  root provider), a force-directed neighbourhood around one entity, and the top
  targets by score. Pan, zoom, drag, expand on double-click, filter by edge
  type, and jump to a dossier from any node. Opens with the Graph button, `g`,
  or from a dossier.
- **`tbm graph`** queries the trust-boundary graph instead of dumping it:
  `--node` for a neighbourhood, `--path A B` for the routes between two
  entities, `--boundaries` for every non-root client naming a root daemon's
  Mach service (filterable by provider score and validation grade), in text,
  DOT, Mermaid or JSON.
- The dashboard shows the same relationship per target: which clients name this
  service, by what evidence, and whether they cross a privilege boundary.
- `boundary_crossings.csv` joins the export.
- **`tbm export`** flattens a report into one CSV and Markdown table per entity
  (services, executables, Mach services, entitlements, frameworks, sinks, sink
  evidence, caller validation, findings, score reasons, graph nodes and edges),
  plus a per-service Markdown dossier and an index. Reads `report.json`, so it
  is instant and needs no re-scan.
- **Caller validation is graded like a sink**, with weighted classes of identity
  primitive (`sectask-entitlement` 8, `code-signing-requirement` 8,
  `authorization-services` 6, `audit-token-extraction` 5, `entitlement-check` 5,
  `sandbox-check` 4, `caller-identity` 3, `code-signing-status` 3), each counted
  once, plus the classes that were looked for and not found. Reported in the CLI,
  in the dashboard as a ✓/? checklist, and in the CSV as `validation_score`,
  `validation_classes` and `validation_evidence`. Regrading moved 280 STRONG →
  134 STRONG / 151 MEDIUM / 57 WEAK: two `audit_token_to_*` calls used to count
  as two independent primitives; they are one class.
- **Sink evidence gained aspects.** Filesystem primitives are grouped into
  `mount`, `mutation`, `xattr`, `quarantine`, `path-resolution` and `metadata`,
  and a match counts for the lesser of its evidence kind and its aspect weight.
  The full path-resolution surface (`open`, `openat`, `realpath`, `access`,
  `fcntl`, `stat`, `lstat`, `fstatat`, xattr and mount/unmount/DiskArbitration
  calls) is now collected and displayed without letting ubiquitous read
  primitives manufacture confidence. 40 jobs touch `mount`; 580 carry a
  FILESYSTEM label, of which 290 are HIGH and 240 LOW.
- **Evidence-weighted sink assessment.** Every sink label now carries the
  observations behind it, weighted by kind (import 8, entitlement 6, ObjC class
  5, identifier string 3, library link 1, weak link and loose token 0), capped
  at two per kind, yielding a HIGH / MEDIUM / LOW confidence. Shown in the CLI
  as a bar with the evidence beneath it, in the dashboard as a per-sink panel,
  and in the CSV as `sink_confidence` and `sink_evidence` columns.
- Entitlements are sink evidence for the first time. Auditing showed 60% of the
  cases where an entitlement directly implies a sink (`com.apple.rootless.*` →
  FILESYSTEM, `com.apple.security.network.client` → NETWORK) carried no such label.

### Removed

- Removed live Mach/XPC probing, Objective-C service-client generation, their
  tests, and the exploit workflow. macOS-TBM is now exclusively a read-only
  static-analysis and reporting tool.
- Sinks supported only by zero-weight evidence are reported as near-miss
  findings instead of labels — `tccd` no longer claims NETWORK on the strength
  of `-[TCCDSQLDatabase _doEval:bind:step:lock:line:]`.
- Weak-linked frameworks are recorded separately and weigh nothing.
- ObjC network classes (`NSURLSession`, `NSURLCredential`) are matched;
  `mobileactivationd`'s NETWORK label previously rested on a weak-linked
  framework while its NSURLSession references went unseen.

- Load-state detection: every job now reports `enabled` with the reasoning,
  combining the plist `Disabled` key with launchd's override database (the
  override wins in both directions). Disabled jobs score −30 and are badged in
  the dashboard, with an "enabled only" filter.
- Findings quote the evidence that matched (`connect <- dispatch_mach_connect`),
  so an over-broad rule is visible in the report instead of hiding behind a label.
- HTML dashboard: six interactive SVG charts (score distribution, priority mix,
  sensitive subsystems, findings by category, IPC role, top targets), a filter
  bar with priority chips and toggles, a per-target dossier drawer, and CSV
  export of the current filter.
- Regression tests for every false-positive class fixed below
  (`tests/test_match_and_state.py`).

### Changed

- **Caller validation is no longer part of the score.** It was a −5×n reduction,
  which meant a service the scanner could not read outranked one it could. It is
  now its own axis: `NONE_OBSERVED` / `WEAK` / `MEDIUM` / `STRONG`.
- Sink rule weights scale with evidence confidence (HIGH ×1.0, MEDIUM ×0.6,
  LOW ×0.3).

- **Signal matching is name-aware.** Needles match whole symbol, ObjC class and
  library names; strings match on identifier-token boundaries; a trailing `*` is
  a prefix match. Rule files were rewritten for the new semantics.
- Caller-validation needles are matched against every evidence pool, and the set
  gained the primitives that were missing (`xpc_connection_get_audit_token`,
  `xpc_connection_copy_entitlement_value`, `SecTaskCopySigningIdentifier`,
  `sandbox_check`, `csops`). Bare `NSXPC*` usage no longer counts as validation.
- The HTML report embeds a slimmed payload (no graph, no raw symbol tables,
  capped list fields), cutting the file from ~20 MB to ~12 MB on a stock system.
- Renamed to **macOS-TBM**; the CLI entry point is now `tbm.py`.

### Fixed

- Cached direct-call name/address indexes remove an accidental
  O(calls × functions) cost in the interprocedural pass; `mDNSResponder`
  inspection on the reference machine fell from roughly 105 seconds to 9.2
  seconds. Deterministic source/traversal/fact budgets now surface
  `UNKNOWN_ANALYSIS_BUDGET` instead of hanging or silently truncating.
- Removed over-broad `GSS*`, `credential*`, `Kerberos*`, and `mbr_*` operation
  patterns that promoted logging and membership-query APIs into credential or
  group-mutation candidates.

- **The graph's client edges were fiction.** `CONNECTS_TO` was drawn from every
  framework a job linked to every Mach service *the same job* provided — 59,671
  edges of the form "CloudTelemetry.framework connects to
  com.apple.security.syspolicy" because syspolicyd links CloudTelemetry. It is
  replaced by `LOOKS_UP`, drawn only from a mach-lookup entitlement value or from
  the service name appearing verbatim in the client binary, never to a service
  the job provides itself. 38,669 edges now, 2,050 of them evidence-backed
  client edges (1,602 entitlement, 448 string).
- Graph assembly deduplicated edges with a linear scan, which made it quadratic:
  a full scan took 6m35s and now takes 1m06s.

- `connect` matching `xpc_connection_send_message` flagged 310 targets as
  network-facing without a single socket symbol; `system`/`fork`/`proc_`
  substring hits produced 359 bogus EXECUTION labels; the library needle
  `Security` matched `libEndpointSecurity.dylib`.
- Disabled jobs (`com.apple.screensharing`, `com.apple.smbd`, `com.openssh.sshd`,
  …) were ranked as live attack surface — 43 jobs on a stock system.
- Feature-flag conditional `UserName`/`GroupName` values were stringified into
  garbage (`[object Object]`); they now resolve to the real identity.
- Config payloads without a label or program (`com.apple.jetsamproperties.Mac.plist`,
  empty leftover plists) were counted as services.
- `logd` and `watchdogd` were reported as having no caller validation while
  importing audit-token and entitlement-check primitives.
- The dashboard's min-score filter defaulted to `0` and so silently hid the
  targets that score below zero once the disabled penalty applies; the score
  histogram now covers negative buckets.

Sink label counts on a stock system after these fixes: NETWORK 484 → 185,
EXECUTION 483 → 196, CREDENTIAL 369 → 207, ACCOUNT 247 → 109, HIGH-priority
targets 276 → 161.

### Fixed

- **Findings are no longer duplicated.** Multiple dataflow facts reaching the
  same sink instance produced findings with the same id, appended repeatedly
  (`com.apple.NetworkSharing` reported 1681 rows for 13 sinks). Findings are now
  merged per sink instance: the strongest evidence wins and inputs, evidence,
  unknown causes, controlled arguments, profiles and policy paths are unioned.
  On a full scan this takes ~6926 rows to ~1787 real operation instances.

- **XPC shared successor is not a handler.** When several operations branch to
  the same target, that target is the allowlist's common continue block, not a
  per-operation handler; it is now reported as `SHARED_SUCCESSOR` instead of
  `PROVEN`. Handler input keys are read from the owning function, so
  `input_keys` is populated for block handlers too.

- **RCE correlation no longer overclaims.** A listener + parser + root
  co-occurrence is a binary-wide research candidate, not proof that ingress
  bytes reach the parser: the top tier is `POSSIBLE` (not `STRONG_CANDIDATE`),
  the class is `BINARY_WIDE_PARSER_SURFACE`, and `missing_evidence` always
  states that the ingress→parser path is unproven.

- **Clearer optional-backend diagnostics.** When radare2 is installed but the
  Python `r2pipe` binding is missing in the running interpreter, the report now
  says so (and points at `pip install r2pipe`) instead of a generic
  "radare2/r2pipe unavailable". Run deep analysis with `.venv-deep/bin/python`.

- **Wider dataflow budget.** The bounded traversal/fact/source budgets were
  raised (100k→500k visits), removing `UNKNOWN_ANALYSIS_BUDGET` on large
  daemons; `DesktopServicesHelper` recovered 90→135 facts.

## [0.1.0]

- Initial release: launchd discovery, Mach/XPC classification, code signing and
  entitlement analysis, Mach-O static analysis, sensitive-sink classification,
  trust-boundary graph, explainable scoring, JSON/HTML/graph reports.
