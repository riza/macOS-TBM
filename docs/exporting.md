# Per-entity export

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

[← Back to the docs index](index.md)
