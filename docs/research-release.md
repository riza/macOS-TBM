# Research beta: evidence contract and release validation

macOS-TBM correlates launchd, code-signing and Mach/XPC evidence to shorten
manual research. Research priority is a review queue, not a vulnerability verdict.
The release is a research beta; supported analysis boundaries are part of the result.

## What optional r2 analysis establishes

Radare2 is **experimental static callsite/xref enrichment**. It requires explicit
`--deep-analysis radare2`. It considers `CALL` references in executable `__text`,
requires an observed source-to-sink function path and a caller reference, and
preserves an existing finding's exact sink address. A handler name, data pointer,
indirect/code reference, or containing function does not establish that path.
Within one function, source-before-sink address order is required. This is still
structural evidence: branch feasibility, actual listener entry, argument flow,
operation authorization and post-condition remain separate questions. A known
function call path is not proof that a particular IPC request can traverse it.

Only `UNKNOWN_NO_CALL_PATH` may be removed by this backend. Wrapper return and
return-value uncertainty remain. Finding-wide confidence and unknown attacker
control are preserved; a path alone cannot answer either question. Native
argument evidence can still combine with an additional path to support a
controlled sink, without establishing a primitive or impact. Conflicts remain
visible. Binary identity changes cause r2 updates to be discarded.

`--deep-binary-timeout` configures r2's internal analysis timeout and an elapsed
check around `aaa`; it is **not a hard process deadline** for every r2 command.
Unresolved indirect/tail calls are intentional false-negative boundaries.

## Reproduction data

JSON schema 2.2 adds `provenance`, `meta.scan_options` and `executable.identity`.
Existing finding fields remain compatible; older reports do not gain provenance
retroactively. [The envelope schema](report-schema.json) documents the additive
fields and deliberately leaves evolving finding payloads extensible.

Reports record tool/source identifiers, a hash of the project Python code, host
OS/build/machine, Python/r2pipe versions, the r2 version when that backend is requested, and canonical hashes of the parsed rules
actually consumed by the analyzers. `meta.scan_options` records all parsed scan
options, including target filters, caps and optional-backend timeout settings.
A missing `radare2_version` means it was not requested or version discovery failed.

Each native executable gets hashes and file stamps before and after analysis.
`STABLE` means those snapshots agree; it does not exclude an intervening change
that was restored. Unreadable/changed inputs remain explicit. This identifies
research inputs, not a perfectly reproducible system snapshot. Architecture
selection, parser errors and analyzed-function counts remain in the Mach-O data.
Use JSON for full evidence; HTML and terminal views summarize long binary lists.
Backend relationships, addresses, paths, proof scope and conflicts are visible
in both terminal dossiers and the HTML capability pane.

## Evaluation

```bash
python3 tools/evaluate_research.py --output research-evaluation.json
python3 -m unittest discover -s tests -v
```

[The checked-in evaluation](research-evaluation.json) contains:

- 13 authored r2 response cases. They test our interpretation of r2 output;
  they do not test the accuracy or compatibility of an installed r2 version.
- Six compiled native Mach-O cases: three C cases for arm64 and x86_64. The
  fixture is compiled at O0, statically inspected, and never executed. launchd
  metadata is simulated, and no IPC connection is attempted.
- Native argument, guard, dispatch, descriptor and callgraph contract tests.

| Native C case | arm64 | x86_64 | What it establishes |
|---|---|---|---|
| Request-derived path → read-only open | CONTROLLED_SINK | CONTROLLED_SINK | Argument provenance in this fixture |
| Request getter plus constant `/dev/null` path | REACHABLE_SINK | REACHABLE_SINK | Getter presence does not make the constant path controlled |
| Getter returned through a wrapper → open | CONTROLLED_SINK | SINK_CANDIDATE | x86_64 wrapper-return recovery remains unresolved |

The results are evidence-contract checks, **not real-daemon precision/recall**.
Do not use the old `full-v3` resolved-path count as an accuracy benchmark: its
r2 interpretation predates these stricter rules. Reports must be regenerated
when the rules or proof contract change.

## Three research examples

1. **Surface and flow:** inspect `corpus_controlled_path` in
   [native_calls.c](../tests/fixtures/research/native_calls.c). Native analysis
   links the getter result to open's path argument. Next research questions for
   a real daemon would be listener reachability, caller authority, resource
   restrictions and the observed result. This fixture proves none of those.
2. **A tempting lead eliminated:** `corpus_constant_path` imports the same getter
   and sink but opens a constant path. The constant-path contract prevents it
   from becoming arbitrary path access. Binary-wide API co-occurrence alone
   would have produced a misleading lead.
3. **A boundary kept visible:** the x86_64 wrapper fixture remains a candidate.
   Manual review would inspect the wrapper return and the argument passed into
   open. The missing flow is a scanner limitation, not proof of unreachability.

Additional guard examples live in `tests/test_control_flow.py` and
`tests/test_capabilities.py`: validation elsewhere in a binary is not a guard,
and strong identity does not establish operation authorization.

## Local release gates

```bash
python3 -m pip install build
python3 -m build
python3 tools/verify_wheel.py dist/*.whl
# Optional formal schema validation in the development environment:
python3 -m pip install jsonschema
python3 tools/verify_wheel.py dist/*.whl --schema docs/report-schema.json
```

The wheel verifier creates a temporary environment outside the checkout,
installs without dependencies, checks CLI entry points and all six rule sets,
and assembles JSON/HTML without running a host scan. The sdist includes docs,
fixture sources and evaluation tools. CI repeats package and evaluation checks.

Before publishing a release, inspect CI results on supported Python versions,
review the evaluation artifact and label the release research beta. Native
fixtures cover arm64/x86_64 at O0; they do not certify every macOS release,
arm64e dispatch, optimized binaries or third-party daemon. Real-daemon ground
truth and an installed-r2 compatibility matrix remain separate future work.

## Local validation record

On 2026-10-04, the local run passed 299 unit tests, all 13 authored r2 cases,
all six compiled native cases, and 71 selected evidence-contract tests. Ruff
and whitespace checks passed. A wheel installed outside the checkout passed
CLI/rule loading, JSON/HTML assembly and formal schema validation. This is a
local result; the added CI matrix still needs to run on the release commit.
