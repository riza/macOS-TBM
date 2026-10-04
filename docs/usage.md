# Usage

```bash
# Full scan (all launchd roots): summary in the terminal, artifacts in ./results
python3 tbm.py scan

# Print the per-target dossiers in the terminal as well (always in scan.txt)
python3 tbm.py scan --detail
python3 tbm.py scan --detail --detail-limit 20 --list-limit 10

# Scoped scan with another output directory and filters
python3 tbm.py scan --scope daemons -out ./results \
    --min-score 70 --privileged-only --mach-only

# Capability-focused filters (candidate names are safe before proof)
python3 tbm.py scan --primitive SIGNATURE_OPERATION_CANDIDATE \
    --maturity CONTROLLED_SINK --confidence MEDIUM
python3 tbm.py scan --proven-only --min-exploitability 50
python3 tbm.py scan --reachable-by LOCAL_USER --min-score 80
python3 tbm.py scan --validation NONE_OBSERVED --sink filesystem
python3 tbm.py scan --framework AuthenticationServices

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

# Map deputy chains across every daemon (add -out PREFIX to write .md/.csv/.json)
python3 tbm.py deputy-all --min-score 90 --root-only --limit 20
python3 tbm.py deputy-all -out results/deputy-all

# Filter by entitlement substring
python3 tbm.py scan --entitlement com.apple.private.tcc

# Inspect a single binary
python3 tbm.py inspect /usr/libexec/exampled

# Analyze a specific launchd service by label substring
python3 tbm.py service com.apple.example

# Statically extract the NSXPC protocol a daemon exports
python3 tbm.py protocol /usr/libexec/mobileactivationd
python3 tbm.py protocol com.apple.mobileactivationd --format json --output proto.json

# Rank unexplored targets by research priority; inspect evidence separately
python3 tbm.py hunt
python3 tbm.py hunt --class lpe --top 20
python3 tbm.py hunt --primitive SIGNATURE_OPERATION_CANDIDATE \
    --maturity CONTROLLED_SINK --reachable-by LOCAL_USER
python3 tbm.py hunt --proven-only --min-exploitability 50
python3 tbm.py hunt --min-score 80 --min-tbm-score 80 --format json
python3 tbm.py hunt --label com.apple.example          # single-target brief

# Which scanned targets hold a given entitlement (report.json query)
python3 tbm.py entowners com.apple.private.tcc
python3 tbm.py entowners com.apple.private --contains

# Find code references to a string inside a Mach-O (RE helper)
python3 tbm.py xref /usr/libexec/exampled com.apple.example
python3 tbm.py xref /usr/libexec/exampled com.apple --arch arm64e --context 32 --format json

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
report to stdout instead (the one mode that writes nothing). `graph` and
`protocol` print to stdout by default; pass `-out <file>` when a file is needed. `hunt`, `xref`, and
`entowners` also print to stdout by default and accept `-out <file>` (see their
`--help`). `hunt` reads `./results/report.json` by default (`--report`), as do
`graph` and `entowners`. `xref` takes a Mach-O path and a string; it handles fat
binaries via `--arch` and supports `arm64`/`arm64e` `adrp`/`add` literal-pool
cross-references. `hunt` scores every target with bug-bounty dimensions
(LPE/RCE/DOS/CRED) on top of the original TBM score and prints an ordered,
linpeas-style table; `--label` prints one target's full brief.

`hunt --class lpe` uses the optional privileged-filesystem correlation layer.
It requires a privileged service plus a bounded IPC-to-filesystem path and
path/resource context; an imported `open`, `rename`, `chmod`, or similar API is
not enough. Caller validation and resource validation are reported separately.
The configurable rules and weights live in `rules/lpe.json`. Confidence values
(`CONFIRMED_FLOW`, `STRONG_CANDIDATE`, `POSSIBLE`, and
`INSUFFICIENT_EVIDENCE`) describe static correlation strength, not confirmed
exploitation. Explicit Radare2 mode can strengthen reachability evidence; the
native bounded-dataflow pass remains sufficient to create a finding.

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

## Terminal review

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

## The dashboard

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

[← Back to the docs index](index.md)
