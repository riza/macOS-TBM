<div align="center">
<pre>
  __  __       
 / /_/ /  __ _ 
/ __/ _ \/  ' \
\__/_.__/_/_/_/
</pre>
</div>

<h1 align="center">macOS-TBM</h1>

<p align="center">
  <strong>macOS Trust Boundary Mapper</strong><br>
  Static, read-only attack-surface mapping for every launchd service on a Mac.
</p>

<p align="center">
  <a href="#quick-start"><img alt="platform" src="https://img.shields.io/badge/platform-macOS-000000?style=flat-square&logo=apple"></a>
  <a href="#requirements"><img alt="python" src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white"></a>
  <a href="#requirements"><img alt="dependencies" src="https://img.shields.io/badge/dependencies-stdlib%20%2B%20optional%20UI-2ea043?style=flat-square"></a>
  <a href=".github/workflows/ci.yml"><img alt="tests" src="https://img.shields.io/badge/tests-unittest-8957e5?style=flat-square"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"></a>
</p>

---

macOS-TBM enumerates every launchd job on the system, correlates its plist,
code signature, entitlements and Mach-O structure, and produces an explainable,
prioritized list of components worth reading by hand — plus a self-contained
HTML dashboard and a trust-boundary graph.

> [!IMPORTANT]
> The tool maps **attack surface**. It does **not** determine exploitability.
> Absence of a static security signal is **never** a claim of a vulnerability.
> Run it only on systems you are authorised to analyse.

```console
$ python3 tbm.py scan
2026-08-19 10:33:04 INFO scanner: discovered 901 launchd jobs (scope=all)
2026-08-19 10:33:04 INFO scanner: resolved 829 unique executables

────────────────────── [+] macOS-TBM scan summary ──────────────────────
Services 901  Privileged 348  Mach/XPC 759  High priority 220  Entitlements 1,545
──────────────────── [!] High-priority review queue ────────────────────
  SCORE  SERVICE                        VALIDATION  IPC
    122  com.apple.security.syspolicy   STRONG      xpc-mach-provider-and-client
    120  com.apple.ManagedClient.enroll STRONG      xpc-mach-provider-and-client
...
╭─ Scan complete ───╮
│      SERVICES 901 │
│    PRIVILEGED 348 │
│      MACH/XPC 759 │
│ HIGH PRIORITY 220 │
╰───────────────────╯
  ✓ report.json                         → ./results
  ✓ report.html                         → ./results
  ✓ graph.json / graph.dot / graph.mmd  → ./results
  ✓ scan.txt                            → ./results
  full per-target dossiers: ./results/scan.txt   (--detail prints them here too)
```

---

## Quick start

```bash
git clone https://github.com/riza/macOS-TBM.git
cd macOS-TBM

# Map the whole system (a few minutes: it runs nm/otool/codesign per binary)
python3 tbm.py scan

# Show version and source build identifier
python3 tbm.py --version

# Read the result: in a browser, in the terminal, or as plain text
open results/report.html
python3 tbm.py tui
less -R results/scan.txt
```

No install step is required: the scanner works with the standard library only.
For a richer interactive terminal experience, optionally install
`requirements.txt` (Rich + tqdm); non-interactive output keeps its plain
fallback and remains safe to pipe.

---

## What it does

For every launchd job on the system it collects and correlates:

1. **Target discovery** — LaunchDaemons/LaunchAgents (system, local, user),
   their programs, Mach services, sockets, and run-as identity (with the
   derivation explained, never assumed).
2. **Mach/XPC attack-surface mapping** — static detection of `xpc_*`,
   `NSXPC*`, `bootstrap_*`, `mach_msg`, `mach_port_*`, and `audit_token_*`
   APIs, classified as *provider / client / both / unknown*.
3. **Code signing** — identifier, team ID, flags, authority chain, designated
   requirement, and a platform-binary heuristic (via `codesign`).
4. **Entitlement analysis** — rule-driven categorization (`com.apple.private.*`,
   TCC, keychain groups, system extensions, EndpointSecurity, DriverKit,
   Mach lookup, sandbox, …) with a sensitivity score.
5. **Mach-O static analysis** — architectures (fat/universal), linked
   dylibs/frameworks, imported/exported symbols, Objective-C classes, rpaths,
   and filtered interesting strings (via `lipo`/`otool`/`nm`/`strings`).
6. **Security signals** — static indicators of caller validation
   (`SecTask*`, `SecCode*`, `AuthorizationCopyRights`, `audit_token_*`, `NSXPC*`)
   and sensitive-subsystem interaction (OpenDirectory, Security, TCC,
   installer/update, networking, filesystem mutation, process execution).
7. **Sensitive sink classification** — ACCOUNT / CREDENTIAL / PRIVACY /
   FILESYSTEM / EXECUTION / INSTALL-UPDATE / NETWORK / SECURITY-POLICY.
8. **Trust-boundary graph** — services, executables, Mach services, frameworks,
   entitlements, and subsystems connected by PROVIDES / LAUNCHED_BY /
   LINKS_TO / CONNECTS_TO / HAS_ENTITLEMENT / ACCESSES_SUBSYSTEM edges.
9. **Research priority scoring** — explainable, configurable weights.
10. **Load state** — whether launchd would actually load the job, combining the
    plist `Disabled` key with launchd's override database. Disabled jobs stay in
    the report (an administrator can turn them on) but are scored down and badged.
11. **Research leads** — "why interesting" + open manual-review questions.

### Terminal review

Install the optional UI helpers — Rich, tqdm and Textual — and the terminal
views light up:

```bash
python3 -m pip install -r requirements.txt
python3 tbm.py scan --scope daemons
python3 tbm.py tui --report ./results/report.json
```

Scan progress uses Rich by default, falls back to tqdm when Rich is missing, and
disables animation when stdout/stderr are redirected. Colour follows the stream:
a terminal gets the palette, a file or a pipe stays plain, so `scan.txt` and
piped output are unchanged.

**`tbm tui`** opens a keyboard-driven Textual dashboard: the logo, counters and
active filters centred at the top, the target table on the left — every target
that passes the filters, scrolled — and the dossier of the highlighted row on
the right. Table and dossier share one palette: priority is red / yellow /
green, and caller validation follows the dossier's convention of green where
evidence was observed and yellow where it was not, so `NONE_OBSERVED` never
reads as reassuring.

| Key | Action |
|-----|--------|
| `↑` `↓` / `j` `k` | move the row cursor; the dossier follows |
| `/` | focus search (filter by service label) |
| `p` / `v` | cycle the priority / caller-validation filter |
| `r` | reset all filters |
| `tab` | focus the dossier pane and scroll it |
| `f` | give the dossier the full width |
| `q` | quit |

Without Textual or a TTY, `tui` falls back to the Rich dashboard: summary
panel, priority / validation / sink distributions and the top targets, narrowed
with `--min-score`, `--priority`, `--validation`, `--sink` and `--search`. Add
`--detail` to print the full dossier of every shown target, and `--limit` to cap
how many are shown — the interactive dashboard scrolls, so `--limit` applies to
this view only.

The dossier is the terminal edition of the HTML drawer and carries the same
sections from the same report fields, all in one aligned two-column layout:

- **launchd metadata** — plist, program, run-as with its derivation, load state
  with its derivation, Mach services, sockets, keep-alive, run-at-load,
- **code signing** — signed, identifier, team, platform binary, flags, the full
  authority chain, architectures,
- **why it is interesting** and the **score contributors**, each with its weight
  and a bar,
- **sensitive subsystems** — every piece of evidence with its kind, match,
  aspect and weight, including the ones that were not counted,
- **caller validation** — the observed classes with their matches *and* the ones
  not observed, with the weight and exactly what was looked for,
- **every entitlement**, private ones first, plus the entitlements the binary
  appears to check on its callers,
- **findings** with their evidence, the open **research questions**, and the
  **binary detail** (linked libraries, interesting strings, ObjC classes,
  symbol counts).

Long Mach-O lists are capped by `--list-limit` (`0` removes the cap) and the
number withheld is always printed.

Interactive commands show a `macOS-TBM` banner with the version, command, and
short git build identifier. For JSON/stdout pipelines, the banner is sent to
stderr so the data stream stays valid.

### The dashboard

`results/report.html` is a single self-contained file — no network access, no
CDN, no tracking. It carries its own data and renders:

- score distribution, priority mix, sensitive subsystems, findings by evidence
  level, IPC role and top targets — **every chart element is a filter**,
- a sortable register of all targets with a per-row sink matrix,
- a per-target dossier: launchd metadata, signature, entitlements (private ones
  first), score contributors, every finding with its evidence, and the open
  research questions,
- CSV export of whatever the current filter shows.

---

## Requirements

- macOS (uses `codesign`, `lipo`, `otool`, `nm`, `strings`, `plutil`).
- Python 3.10+ (standard library required; Rich and tqdm are optional UI packages).

The scanner is **read-only**: it never modifies launchd configuration, never
loads/unloads services, never sends XPC messages, and never mutates the files it
inspects.

---

## Usage

```bash
# Full scan (all launchd roots): summary in the terminal, artifacts in ./results
python3 tbm.py scan

# Print the per-target dossiers in the terminal as well (always in scan.txt)
python3 tbm.py scan --detail
python3 tbm.py scan --detail --detail-limit 20 --list-limit 10

# Scoped scan with another output directory and filters
python3 tbm.py scan --scope daemons -out ./results \
    --min-score 70 --privileged-only --mach-only

# Only JSON / only HTML / only graph artifacts
python3 tbm.py scan --html
python3 tbm.py scan --graph

# Stream a machine-readable report and write nothing
python3 tbm.py scan --json | jq '.summary'

# Review a finished report in the terminal
python3 tbm.py tui
python3 tbm.py tui --priority HIGH --validation NONE_OBSERVED --detail

# Export the last report as one file per entity (CSV + Markdown)
python3 tbm.py export

# Query the trust-boundary graph
python3 tbm.py graph --boundaries --validation NONE_OBSERVED --min-score 90
python3 tbm.py graph --node com.apple.diskimagesiod.spb --depth 2
python3 tbm.py graph --path com.apple.someagent com.apple.somedaemon
python3 tbm.py graph --deputy com.apple.mobileactivationd
python3 tbm.py graph --deputy com.apple.mobileactivationd --deputy-entitlement com.apple.mobileactivationd.spi
# Graph queries print to stdout by default
python3 tbm.py graph --boundaries --format json | jq 'length'

# ACTIVE: probe which exposed Mach services an unprivileged client can reach
python3 tbm.py probe --service com.apple.mobileactivationd
python3 tbm.py probe --limit 40 --timeout 2 --format json

# Filter by entitlement substring
python3 tbm.py scan --entitlement com.apple.private.tcc

# Inspect a single binary
python3 tbm.py inspect /usr/libexec/exampled

# Analyze a specific launchd service by label substring
python3 tbm.py service com.apple.example

# Extract the NSXPC protocol a daemon exports, and generate a test client
python3 tbm.py protocol /usr/libexec/mobileactivationd
python3 tbm.py protocol com.apple.mobileactivationd --format json --output proto.json
python3 tbm.py clientgen proto.json --mach-service com.apple.mobileactivationd -o main.m
clang -fobjc-arc -framework Foundation main.m -o client

# More parallelism / verbosity
python3 tbm.py scan --workers 16 --verbose
```

`scan` saves its work and keeps the terminal short. Without `-out` it writes to
`./results`: `report.json`, `report.html`, the graph exports, and `scan.txt` —
the complete terminal report, summary plus the full dossier of every reported
target. stdout gets the evidence-oriented, linpeas-style summary and a list of
what was written. Use `--detail` to print the dossiers in the terminal as well,
`--detail-limit N` to cap how many are written, `--list-limit N` to cap long
lists inside one, `-out DIR` for another directory, or `--json` to stream the
report to stdout instead (the one mode that writes nothing). `graph`, `probe`, `protocol`, and `clientgen` print to stdout by
default; pass `-out <file>` when a file is needed.

Outputs (under `--output`, default `./results`):

| File         | Description                                   |
|--------------|-----------------------------------------------|
| `report.json`| Full machine-readable report (summary + targets) |
| `report.html`| Self-contained dashboard (charts, filters, per-target dossier) |
| `scan.txt`   | The full terminal report: summary plus one dossier per target |
| `export/`    | One CSV + Markdown table per entity, plus a dossier per service |
| `graph.json` | Trust-boundary graph as JSON                    |
| `graph.dot`  | Graphviz DOT                                   |
| `graph.mmd`  | Mermaid `graph LR`                             |

Open `report.html` in a browser for the interactive dashboard. It needs no network
access and carries its own data: score histogram, priority mix, sensitive-subsystem
and findings breakdowns (every chart element is a filter), a sortable target register
with a sink matrix per row, a slide-in dossier per target, and CSV export of the
current filter. Press `/` to focus search, `Esc` to close the dossier.

The dashboard embeds a slimmed copy of the report — the graph and the raw symbol
tables are dropped, long lists are capped — so it stays a fraction of the size of
`report.json` while showing everything it renders.

---

## Architecture

```
macos-tbm/
├── tbm.py                  # CLI entry point (scan / inspect / service)
├── scanner.py              # orchestration: discovery -> analysis -> scoring
├── collectors/             # FACT collection (read-only external tools)
│   ├── launchd.py          #   plist discovery + parse + run-as derivation
│   ├── filesystem.py       #   XPC bundle / binary roots (future use)
│   ├── codesign.py         #   codesign metadata + entitlements
│   └── macho.py            #   lipo/otool/nm/strings static analysis
├── analyzers/              # HEURISTIC analysis
│   ├── ipc.py              #   provider/client classification
│   ├── entitlements.py     #   categorization + sensitivity
│   ├── security_signals.py #   caller-validation + sensitive APIs
│   ├── sinks.py            #   sensitive sink taxonomy
│   ├── scoring.py          #   explainable priority scoring
│   └── leads.py            #   research-lead generation
├── graph/
│   ├── model.py            #   Node/Edge + build_graph()
│   └── exporters.py        #   JSON / DOT / Mermaid
├── reporting/
│   ├── json_report.py      #   report assembly + report.json
│   └── html_report.py      #   self-contained dashboard
├── models/                 # dataclasses (LaunchService, Executable, Target, …)
├── rules/                  # configurable rules (see below)
│   ├── entitlements.json
│   ├── signals.json
│   └── scoring.json
├── utils/
│   ├── commands.py         # safe subprocess (no shell, timeouts, caching)
│   ├── plist.py            # plist loading (binary + fallback)
│   └── rules.py            # rule-file loader
├── tests/                  # unittest suite
└── .github/                # CI, issue and pull-request templates
```

**Data model** — every piece of evidence carries an explicit confidence level:

- `FACT` — directly observed (e.g. a `MachServices` key in a plist).
- `HEURISTIC` — inferred by rule (e.g. "links Security.framework").
- `UNKNOWN` — could not be determined.

---

## Querying the graph

The whole graph is 8,000 nodes; research asks narrow questions. `tbm graph`
answers them against the last report:

```bash
# Where can a non-root client reach a root daemon that shows no caller checks?
python3 tbm.py graph --boundaries --validation NONE_OBSERVED --validation WEAK --min-score 90

# What surrounds one entity (service, binary or Mach service)?
python3 tbm.py graph --node com.apple.diskimagesiod.spb --depth 2

# How does this agent reach that daemon?
python3 tbm.py graph --path com.apple.ManagedClientAgent.agent com.apple.ManagedClient

# Feed a slice to Graphviz
python3 tbm.py graph --node com.apple.mobileactivationd --depth 2 --format dot --output n.dot
dot -Tsvg n.dot -o n.svg
```

`--boundaries` is the query the tool exists for — every place something less
trusted names an endpoint something more trusted answers on:

```
MACH SERVICE                                  PROVIDER              SCORE VALIDATION    CLIENT
com.apple.icloud.searchpartyd.beaconmanager   ...searchpartyd         113 NONE_OBSERVED com.apple.assistant_service [entitlement]
com.apple.mobileactivationd                   ...mobileactivationd    111 NONE_OBSERVED com.apple.BTServer.cloudpairing [entitlement]
```

The dashboard shows the same relationship per target: who names this service,
by what evidence, and whether that client crosses a privilege boundary.

### The explorer

`report.html` carries an interactive view of the trust core — services,
binaries, Mach services and subsystems, 3,597 nodes and 7,137 edges,
index-encoded into ~290 KB. Open it with the **Graph** button, `g`, or the
**Graph ↗** button in any dossier; entitlement and framework nodes stay out (they
are 4,500 nodes and 31,000 edges that answer a different question).

Three modes:

- **boundary crossings** — a ladder: clients on the left, the Mach services they
  name in the middle, the root daemons that answer on the right. Highest-scoring
  providers first.
- **focus: one entity** — a force-directed neighbourhood around one node, depth
  1–3. Drag nodes, double-click to expand, click for details.
- **top targets by score** — the highest-scoring enabled services with their
  endpoints and clients.

Pan by dragging, zoom with the wheel, filter by edge type, and click any node for
its score, privilege, load state, validation grade and edge counts — with
*Focus here*, *Expand* and *Open dossier* from there. A dashed edge is
string evidence, a solid one an entitlement; a hollow node is a disabled job.

---

## Probing reachability — the one active command

> [!WARNING]
> `tbm probe` is the **only** command that is not read-only. Every other command
> inspects; `probe` *connects* to exposed Mach services and sends real (empty and
> one-key) XPC messages, as an unprivileged client, to classify which root
> services an unprivileged process can actually reach. It runs as your normal
> user — never `sudo` — and it is opt-in: a scan never probes.

Static analysis tells you a root daemon *exposes* a Mach service; it cannot tell
you whether an unprivileged process can *reach* it. Confirming that is the #1
manual step in LPE triage — normally a hand-written C probe per service. `probe`
does it for every root service in a report at once:

```bash
python3 tbm.py probe                                   # every root Mach service in report.json
python3 tbm.py probe --service com.apple.mobileactivationd
python3 tbm.py probe --limit 40 --timeout 2 --format json --output probe.json
```

Each service is classified into exactly one bucket:

| Bucket | Meaning |
|--------|---------|
| `spawn` | the peer replied, or the daemon is up and tolerated our messages |
| `connect-alive` | connection accepted and held open, never dropped us |
| `empty-interrupted` | an empty message drew "Connection interrupted" (reachable, rejected early) |
| `malformed-interrupted` | a one-key message drew "Connection interrupted" |
| `timeout` | a send drew neither reply nor error and nothing spawned |
| `unreachable` | bootstrap lookup / connect failed ("Connection invalid") |

`connect-alive` and `empty-interrupted` are the **actually reachable** set: an
unprivileged client got far enough to talk to a privileged peer, which is where
manual review should start. The summary lists that shortlist.

```
  MACH SERVICE                          PROVIDER              RUN AS  CLASSIFICATION     ERROR
  com.apple.mobileactivationd           com.apple.mobileacti… root    empty-interrupted  Connection interrupted
```

**How it talks to XPC.** Python cannot call the XPC C API directly. macOS-TBM
binds `libxpc` with **ctypes** — no compile step, no bundled helper, still
stdlib-only. `libxpc` has no on-disk `.dylib` on modern macOS, but its symbols
are re-exported through the already-loaded `libSystem`, so `ctypes.CDLL(None)`
resolves them; the one block argument (`xpc_connection_set_event_handler`) is a
hand-built global block literal. See [probes/xpc.py](probes/xpc.py). Not on
macOS, or the symbols are missing? `probe` exits with a clear message and the
rest of the tool is unaffected.

---

## NSXPC protocol extraction and client generation

For NSXPC daemons, reconstructing the exported Objective-C protocol by hand is
slow. `tbm protocol` extracts it automatically and `tbm clientgen` turns it into
a compilable test client:

```bash
python3 tbm.py protocol /usr/libexec/mobileactivationd
python3 tbm.py protocol com.apple.mobileactivationd --format json --output proto.json
python3 tbm.py clientgen proto.json --mach-service com.apple.mobileactivationd \
    --selector handleActivationInfo:options:withCompletionBlock: --output main.m
clang -fobjc-arc -framework Foundation main.m -o client
```

`tbm protocol <binary-or-service>` runs `otool -ov` (arm64e slice, falling back
to the whole file) and `nm`, finds protocols exported via `NSXPCListenerDelegate`,
parses each `instanceMethods` table, and decodes the ObjC type encodings into
readable signatures — `v40@0:8@16@24@?32` becomes
`- (void)handleActivationInfo:(id)arg0 options:(id)arg1 withCompletionBlock:(id)block`.

On modern arm64e binaries `otool` prints the resolved *types* but leaves the
selector *names* as relative offsets; the extractor resolves the two-level
indirection (method-list name → `__objc_selrefs` → `__objc_methname`) itself.
Block arguments are rendered as `id` — the skeleton cannot know a block's
signature, and neither can a static extractor.

`tbm clientgen` emits a self-contained `main.m`: it declares the `@protocol`,
builds an `NSXPCConnection` to the Mach service, sets `remoteObjectInterface`,
and calls one selector (first method, or `--selector`) with `NSNull` / empty
arguments and a logging completion block. Both commands stay stdlib-only and
read-only; only the *generated client* is active when you choose to run it.

---

## Server-side entitlement checks

The `<label>.*` entitlement heuristic is a guess about what a daemon gates its
clients on. The **server-side entitlement check** signal reports the real
answer: the `com.apple.*` keys a binary *checks* on its clients.

A binary that calls `valueForEntitlement:` / `xpc_connection_copy_entitlement_value` /
`SecTaskCopyValueForEntitlement` / `remoteProcessHasBooleanEntitlement:` (or
carries strings like `"missing entitlement"` / `"not entitled"`) is checking its
clients. The `com.apple.*` keys in its string table that are **not** among its
own held entitlements are the candidate checked keys — the held set (what Apple
granted *it*) and the checked set (what it queries on *others*) are different,
and this is the crux. The result is stored per target as `checked_entitlements`
in `report.json`, emitted as `CHECKED_ENTITLEMENT` edges in the graph, and is
what `tbm graph --deputy <daemon>` gates on by default — falling back to the
`<label>.*` heuristic only when nothing was observed.

---

## Trust-boundary model

Nodes:

- **LaunchService** — a launchd job (`Label`, scope, run-as).
- **Executable** — a Mach-O binary referenced by a job.
- **MachService** — a name registered under a plist `MachServices` key.
- **Framework / PrivateFramework** — a linked library.
- **Entitlement** — an entitlement key.
- **SecuritySubsystem** — a sensitive sink category.

Edges:

| Edge                | Direction                    | Meaning                          |
|---------------------|------------------------------|----------------------------------|
| `PROVIDES`          | LaunchService → MachService  | job registers the Mach service   |
| `LAUNCHED_BY`       | Executable → LaunchService   | executable is launched by job    |
| `LINKS_TO`          | Executable → Framework       | binary links the library         |
| `LOOKS_UP`          | Executable → MachService     | client names the service (see below) |
| `HAS_ENTITLEMENT`   | Executable → Entitlement     | binary carries the entitlement   |
| `CHECKED_ENTITLEMENT`| LaunchService → Entitlement | daemon checks the entitlement on its clients (server-side) |
| `ACCESSES_SUBSYSTEM`| Executable → Subsystem       | binary touches a sensitive sink  |

`LOOKS_UP` is the edge that makes this a *trust-boundary* graph, and it is only
drawn where there is evidence:

- **`evidence=entitlement`** — the client carries
  `com.apple.security.exception.mach-lookup.global-name` naming that service.
  Apple declared the relationship; it is authoritative.
- **`evidence=string`** — the service name appears verbatim in the client binary,
  which is what a `bootstrap_look_up` call site looks like from the outside.

Never to a service the job provides itself, and never to a name no job provides.

```
Client ──LOOKS_UP──▶ XPC/Mach service ◀──PROVIDES── Daemon ──ACCESSES──▶ Subsystem
```

> An earlier version drew `CONNECTS_TO` from every framework a job linked to
> every Mach service *the same job* provided — 59,671 edges asserting things like
> "CloudTelemetry.framework connects to com.apple.security.syspolicy" purely
> because syspolicyd links CloudTelemetry. Those edges were fiction and are gone;
> the graph is now 38,669 edges, of which 2,050 are evidence-backed client edges.

---

## Scoring methodology

Scores are sums of configurable weights (defaults shown):

| Rule                    | Weight | Trigger                                        |
|-------------------------|--------|------------------------------------------------|
| privileged_service      | +20    | runs as root / system                          |
| exposes_ipc             | +20    | Mach service / socket exposed                  |
| private_entitlement     | +15    | private / high-value entitlements              |
| auth_security_api       | +15    | credential / Security.framework APIs           |
| account_credential      | +15    | account / credential subsystem                 |
| filesystem_mutation     | +10    | fs mutation indicators                         |
| installer_update        | +10    | installer / software-update                    |
| network                 | +10    | network-facing surface                         |
| tcc_privacy             | +15    | TCC / privacy interaction                      |
| disabled_service        | −30    | launchd would not load the job as configured   |

Sink rule weights are multiplied by the **confidence** of the evidence behind
them: `HIGH ×1.0`, `MEDIUM ×0.6`, `LOW ×0.3`. A NETWORK label resting on one
framework link contributes 3 points; one backed by an entitlement and two
imports contributes 10.

**Caller validation is not scored.** It is reported on its own axis because "the
scanner saw no validation" and "the service does not validate" are different
statements, and letting the first one raise a target's rank quietly conflated
them. It is graded the same way as a sink — weighted classes of identity
primitive, each with what it proves, plus the classes that were looked for and
not found:

| Validation class | Weight | What it proves |
|------------------|--------|----------------|
| `sectask-entitlement` | 8 | builds a SecTask from the caller and queries its entitlements |
| `code-signing-requirement` | 8 | evaluates a code-signing requirement against the caller |
| `authorization-services` | 6 | asks Authorization Services to authorize the right |
| `audit-token-extraction` | 5 | obtains the caller's audit token from the connection |
| `entitlement-check` | 5 | checks an entitlement on the connection |
| `sandbox-check` | 4 | asks the sandbox whether the caller may do this |
| `caller-identity` | 3 | reads the caller's uid/gid/pid |
| `code-signing-status` | 3 | reads the caller's code-signing status flags |

Each class counts once however many of its symbols appear. **≥12 STRONG**,
**≥5 MEDIUM**, **>0 WEAK**, else `NONE_OBSERVED` — so the canonical correct
pattern (read the caller's audit token *and* check something about it) is the
cheapest route to STRONG, while a lone `sandbox_check` grades WEAK.

```
CALLER VALIDATION                                    WEAK   ████ 4
  ✓ sandbox-check              +4  sandbox_check
  ? audit-token-extraction     +5  obtains the caller's audit token from the connection
  ? sectask-entitlement        +8  builds a SecTask from the caller and queries its entitlements
  ? code-signing-requirement   +8  evaluates a code-signing requirement against the caller
```

**Important.** Caller-validation indicators *reduce* triage priority only. They
must **never** be read as a safety or vulnerability conclusion. A negative
signal ("not observed statically") is reported verbatim as such — never as
"authorization is missing".

Priorities: `HIGH ≥ 80`, `MEDIUM ≥ 50`, `LOW ≥ 25`, else `INFO`.

---

## Per-entity export

`report.json` is one nested document, but research is done one entity at a time.
`tbm export` flattens the last report — no re-scan, it reads `report.json`:

```bash
python3 tbm.py export                       # CSV + Markdown into ./results/export
python3 tbm.py export --format csv          # tables only
python3 tbm.py export --no-dossiers         # skip the per-service Markdown files
```

| File | One row per |
|------|-------------|
| `services.csv` | launchd job — score, state, run-as, sinks, validation |
| `executables.csv` | unique binary — signature, architectures, which jobs use it |
| `mach_services.csv` | Mach service name, and who provides it |
| `entitlements.csv` | (entitlement, holder) pair |
| `entitlement_summary.csv` | entitlement — how many jobs hold it |
| `frameworks.csv` | linked library — how many jobs link it, weak links |
| `sinks.csv` | (service, sink) — confidence, evidence score, aspects |
| `sink_evidence.csv` | **every observation behind every label** — kind, aspect, weight, matched symbol |
| `boundary_crossings.csv` | a non-root client naming a root daemon's Mach service |
| `caller_validation.csv` | (service, validation class) — observed and *not* observed |
| `findings.csv` | finding, with its FACT / HEURISTIC / UNKNOWN level |
| `score_reasons.csv` | scoring contribution |
| `graph_nodes.csv` / `graph_edges.csv` | trust-boundary graph |

`sink_evidence.csv` is the one to grep — every claim the tool makes, with what
produced it:

```bash
# every job that calls a mount primitive, and which one
awk -F, '$5=="mount" && $6>0' results/export/sink_evidence.csv
```

Markdown mirrors every table, and `services/<label>.md` is a per-service dossier
with the launchd metadata, signature, evidence per sink, the caller-validation
checklist, entitlements, score breakdown and the research questions as
checkboxes — made to be dropped into a research journal. `index.md` links it all.

---

## Evidence and confidence

Every sink label carries the evidence that produced it, weighted by *kind*:

| Evidence kind | Weight | What it means |
|---------------|--------|---------------|
| `import`      | 8      | the binary calls this API (`unlink`, `SecItemAdd`) |
| `entitlement` | 6      | a capability Apple granted it (`com.apple.rootless.volume.Preboot`) |
| `objc`        | 5      | a referenced Objective-C class (`NSURLSession`) |
| `string`      | 3      | an identifier it knows (`com.apple.MobileSoftwareUpdate.UpdateBrainService`) |
| `library`     | 1      | a linked framework — almost nothing on its own |
| `weak-library`| 0      | a weak link that may never resolve at runtime |
| `token`       | 0      | a word inside a sentence or path — not evidence |

A rule may also group its primitives into **aspects**, which cap what a match is
worth by what it *means*. `mount` and `unlink` are worth their full import
weight; `stat`, `open` and `fcntl` sit under `path-resolution` / `metadata` at
weight 2, because nearly every binary calls them. The evidence still lists them
— you can see the whole path-resolution surface of a daemon — without letting
them manufacture confidence:

```
FILESYSTEM  HIGH  █████████ (18)  [mount, mutation, quarantine, path-resolution, metadata]
    ↳ mount: unmount, DADiskMountWithArguments, DADiskUnmount
    ↳ mutation: fchmodat, ftruncate, mkdir, mkdirat, futimes
    ↳ quarantine: qtn_file_alloc
    ↳ path-resolution: open, access, faccessat, fcntl, fdopendir, NSFileManager
    ↳ metadata: stat, fstat, fstatat, fstatfs, ffsctl
```

At most two items of one kind count, so forty keychain imports do not outweigh
an entitlement plus two calls. The total sets the confidence: **≥10 HIGH**,
**≥5 MEDIUM**, else **LOW**. A sink supported only by zero-weight evidence is
not labelled at all — it is reported as a near-miss finding, which is how
`tccd` stopped being "network-facing" on the strength of
`-[TCCDSQLDatabase _doEval:bind:step:lock:line:]`.

```console
$ python3 tbm.py service com.apple.mobileactivationd
  sinks:
    CREDENTIAL       HIGH   ██████████ (28)
        ↳ entitlement: com.apple.private.system-keychain
        ↳ import: SecItemAdd
        ↳ import: SecItemCopyMatching
    NETWORK          HIGH   ████████ (17)
        ↳ entitlement: com.apple.security.network.client
        ↳ weak-library: Network
        ↳ objc: NSURLSession
    INSTALL/UPDATE   MEDIUM ████ (9)
        ↳ entitlement: com.apple.private.IASInstallerAuthAgent
        ↳ string: com.apple.MobileSoftwareUpdate.UpdateBrainService
  validation: NONE_OBSERVED
```

---

## Limitations & false-positive risks

- **Static only.** Symbols, strings, and linked libraries are *indicators*, not
  proof of behavior. A daemon may link Security.framework without ever checking
  a caller.
- **Signal absence ≠ missing authorization.** Caller validation may be performed
  via private frameworks, helpers, inline code, dynamic dispatch, or entirely
  different APIs that static analysis cannot see.
- **Matching is name-aware, but still an indicator.** Needles match whole symbol
  and library names (`connect` is the `connect` syscall, not
  `xpc_connection_send_message`; `Security` is not `libEndpointSecurity.dylib`),
  and every finding quotes the entry that matched — but linking a framework is
  still not the same as using it against a caller.
- **Entitlement sensitivity is a heuristic.** A `com.apple.private.*` key does not
  by itself imply a privilege boundary worth exploiting.
- **Run-as derivation is principled but not omniscient.** LaunchDaemons default to
  root only in the absence of `UserName`; some jobs are further constrained by
  sandbox profiles that we do not parse.
- **Sink classification is inference.** "Interacts with account management" means
  "static indicators present", not "performs account mutation" — read the
  evidence list and its confidence, not the label alone.
- **An entitlement is capability, not usage.** It weighs less than an import for
  exactly that reason: holding `com.apple.private.tcc.allow` means a service
  *may* read TCC-protected data, not that it does.
- **Load state is point-in-time.** `enabled` combines the plist `Disabled` key with
  launchd's override database (the override wins, which is how Remote Login
  enables `com.openssh.sshd`). A disabled job is kept in the report, scored −30
  and badged, because an administrator can turn it on at any time.
- **A plist is not always a job.** Config payloads that live in the launchd
  directories (e.g. `com.apple.jetsamproperties.Mac.plist`) declare no label and
  no program; they are skipped rather than counted as services.

Every finding in the report carries its `FACT` / `HEURISTIC` / `UNKNOWN` level.

---

## Extending the rule sets

Rules are JSON under `rules/` and load at runtime — no code changes needed for
most additions.

### Add / tune an entitlement category (`rules/entitlements.json`)

```json
{
  "categories": {
    "my_category": { "description": "...", "sensitivity": 12 }
  },
  "rules": [
    { "category": "my_category", "match": "com.example.private.", "type": "prefix" }
  ]
}
```

`type` is one of `prefix`, `contains`, `exact`. More specific (longer) matches
win automatically.

### Add a security signal (`rules/signals.json`)

Needles are matched per evidence pool. Against **symbols, ObjC classes and
library names** a needle must match the *whole* name; against **strings** it may
match inside an entry on identifier-token boundaries. A trailing `*` is a prefix
match in both modes (`posix_spawn*` matches `posix_spawnattr_setflags`). Library
needles see framework/dylib names, not paths — so `Security` matches
`Security.framework` and not `libEndpointSecurity.dylib`:

```json
{
  "sensitive": {
    "my_subsystem": {
      "description": "...",
      "libs": ["MyFramework"],
      "symbols": ["MyAPICall"],
      "strings": ["com.example.mydaemon"]
    }
  }
}
```

Caller-validation signals live under `"caller_validation"`; IPC provider/client
signals under `"ipc_provider"` / `"ipc_client"` / `"ipc_generic"`.

### Tune scoring weights (`rules/scoring.json`)

Edit the `weight` of any rule id. `caller_validation_cap` bounds the number of
negative caller-validation contributions.

---

## Example workflow

```bash
# 1. Map the whole system.
python3 tbm.py scan --output ./results

# 2. Open the dashboard and sort by score; note HIGH targets.
open ./results/report.html

# 3. Drill into a specific service.
python3 tbm.py service com.apple.example

# 4. Inspect the binary and its entitlements directly.
python3 tbm.py inspect /usr/libexec/exampled

# 5. Export the graph for visualization (Graphviz / Mermaid).
dot -Tsvg ./results/graph.dot -o graph.svg
```

---

## Safety

- All external commands run via `subprocess` with `shell=False`, timeouts, and
  captured errors; a single malformed plist or binary cannot abort a scan.
- Binary/plist results are cached by path + mtime + size; identical executables
  referenced by many services are analyzed once.
- Analysis is parallelized through a bounded `ThreadPoolExecutor`.
- No tool here connects to, fuzzes, mutates, or invokes private services.

---

## Running tests

```bash
python3 -m unittest discover -s tests -t tests -v
```

CI runs the suite on macOS across Python 3.10 / 3.12 / 3.13, plus an end-to-end
smoke scan of the runner's own LaunchDaemons — see
[.github/workflows/ci.yml](.github/workflows/ci.yml).

---

## Contributing

False-positive reports are the most valuable contribution this project can get:
open one with the command output that contradicts the report and it becomes a
rule fix plus a regression test. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
two hard rules (stay read-only, never claim a vulnerability) and for how the
rule matcher works before you tune `rules/*.json`.

- [Report a false positive](../../issues/new?template=false_positive.md)
- [Report a bug](../../issues/new?template=bug_report.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Release notes: [CHANGELOG.md](CHANGELOG.md)

---

## Prior art and thanks

Built on the shoulders of the macOS research community — the people who
documented XPC internals, launchd behaviour, entitlement semantics and the
`audit_token` validation pitfalls that this tool looks for. macOS-TBM does not
discover anything Apple's own tooling (`codesign`, `otool`, `nm`, `launchctl`)
cannot show you; it correlates all of it at once and explains the ranking.

---

## License

[MIT](LICENSE) © macOS-TBM contributors
