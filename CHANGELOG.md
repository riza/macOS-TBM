# Changelog

All notable changes to macOS-TBM are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

- **`tbm probe`** — the one *active* (non-read-only) command: it connects to
  every root Mach service in a report as an unprivileged client and classifies
  reachability (`spawn`, `connect-alive`, `empty-interrupted`,
  `malformed-interrupted`, `timeout`, `unreachable`), shortlisting the
  actually-reachable set. Talks to XPC via `ctypes` against the `libxpc`
  symbols re-exported through `libSystem` — no compile step, still stdlib-only.
- **`tbm protocol` / `tbm clientgen`** — extract the NSXPC protocol a daemon
  exports (`otool -ov` + `nm`, with ObjC type-encoding decode and, for modern
  arm64e relative method lists, selref→selector resolution) and generate a
  compilable Objective-C `main.m` test client.
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

## [0.1.0]

- Initial release: launchd discovery, Mach/XPC classification, code signing and
  entitlement analysis, Mach-O static analysis, sensitive-sink classification,
  trust-boundary graph, explainable scoring, JSON/HTML/graph reports.
