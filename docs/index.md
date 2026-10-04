# macOS-TBM documentation

`README.md` stays the pitch and the fastest path to a first scan; these pages
are the chapters behind it.

| Guide | What it covers |
|-------|----------------|
| [Getting started](getting-started.md) | Install (`pipx` / `pip`), requirements, the first scan, and an end-to-end example workflow. |
| [Usage](usage.md) | Every `tbm` subcommand and filter, what `scan` writes, the interactive terminal review, and the HTML dashboard. |
| [Architecture](architecture.md) | The collection → analysis → scoring pipeline, the capability evidence contract, XPC request/dispatch extraction, and the repository layout. |
| [Trust model and scoring](trust-model.md) | Graph nodes and edges, the `LOOKS_UP` boundary edge, scoring weights, and caller-validation grades. |
| [Querying and protocol analysis](querying.md) | `tbm graph` queries, the dashboard explorer, NSXPC protocol extraction, and server-side entitlement checks. |
| [Evidence, confidence, and limitations](evidence.md) | Evidence kinds and weights, confidence thresholds, and the false-positive risks to keep in mind. |
| [Per-entity export](exporting.md) | Flattening `report.json` into one CSV and Markdown file per entity. |
| [Extending the rule sets](extending.md) | Adding or tuning `rules/*.json` without touching Python. |
| [Safety](safety.md) | The read-only guarantees and the bounded, explicit runtime probe. |
| [Research beta validation](research-release.md) | Evidence contract, compiled fixtures, reproducibility and release gates. |
| [Development](development.md) | Running tests and coverage, CI, and how to contribute. |

Project files: [README](../README.md) · [SECURITY](../SECURITY.md) ·
[CONTRIBUTING](../CONTRIBUTING.md) · [CHANGELOG](../CHANGELOG.md) ·
[LICENSE](../LICENSE).
