# Changelog

All notable changes to macOS-TBM are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
