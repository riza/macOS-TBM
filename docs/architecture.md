# Architecture

## Capability evidence contract

| Maturity | What static evidence establishes |
|----------|----------------------------------|
| `SINK_CANDIDATE` | A sensitive API is referenced; no handler-to-sink path is established. |
| `REACHABLE_SINK` | A supported IPC-source handler reaches the sink; required argument control is not established. |
| `CONTROLLED_SINK` | The required sink argument(s) are traced from the request, with constants reported separately. |
| `PRIMITIVE` | The attacker-useful primitive and authorization condition are explicitly proven. |
| `IMPACT` | The concrete post-condition is proven in addition to the primitive. |

Strong names such as `SIGNING_ORACLE`, `PRIVATE_KEY_EXPORT`, and
`ARBITRARY_FILE_WRITE` appear in `proven_primitive` only at the corresponding
proof level. Before that, reports use names such as
`SIGNATURE_OPERATION_CANDIDATE` or `FILE_WRITE_SINK_CANDIDATE`.

Identity verification and operation authorization are separate controls. Each
is scoped as merely present in the binary, reachable from the recovered
handler, or proven to guard the specific sink. `NONE_OBSERVED` remains an
unknown, never evidence of a bypass. Every unresolved relationship carries a
named cause, missing evidence, and a concrete next research step.

One finding is reported per operation instance (service + sink): several
dataflow facts reaching the same sink are merged, the strongest evidence wins,
and their inputs, evidence, unknown causes, and controlled arguments are
unioned, so a sink reached from many sources is one finding, not many.

## XPC request/dispatch extraction

When a service selects work by a request value, the report carries
`ipc_operations`: the dictionary key that holds the request, the operation
value it is compared against, the dispatcher, the resolved handler, the input
keys the handler reads, and the evidence for each. Handlers resolve at function
or basic-block granularity (`sub_10002f9e4+0x2e4`). Three dispatch shapes are
recognized:

- a string request compared with `strcmp`/`memcmp`, or through a local
  comparison wrapper that calls `CFEqual`;
- an integer request read with `xpc_dictionary_get_int64`/`get_uint64` and
  compared with `cmp #imm` / `b.eq`;
- an Objective-C selector dispatch, resolved from `__objc_selrefs`.

Relationships are `PROVEN`, `INFERRED`, `UNRESOLVED`, or
`UNKNOWN_INDIRECT_HANDLER`; a handler is never invented from an import. When
several operations branch to the same target, that target is the allowlist's
common continue block, so it is reported as `SHARED_SUCCESSOR` rather than a
per-operation handler. `input_keys` lists the XPC keys the handler's owning
function reads. Only keys listed in `rules/capabilities.json` (`dispatch_keys`)
or a comparison chain of at least `dispatch_min_chain` values are reported,
which keeps data field comparisons out of the dispatch surface.

## Repository layout

```
macos-tbm/
├── tbm.py                  # CLI entry point and read-only subcommands
├── scanner.py              # orchestration: discovery -> analysis -> scoring
├── collectors/             # FACT collection (read-only external tools)
│   ├── launchd.py          #   plist discovery + parse + run-as derivation
│   ├── filesystem.py       #   XPC bundle / binary roots (future use)
│   ├── codesign.py         #   codesign metadata + entitlements
│   ├── macho.py            #   native Mach-O parse + nm/strings/otool disasm
│   ├── dataflow.py         #   bounded interprocedural taint + reply flow
│   ├── callgraph.py        #   direct call graph + reachability states
│   ├── xpc_dispatch.py     #   XPC request/dispatch extraction
│   ├── control_flow.py     #   fail-closed operation-guard proof
│   └── nsxpc.py            #   passive NSXPC protocol extraction
├── analyzers/              # HEURISTIC analysis
│   ├── ipc.py              #   provider/client classification
│   ├── entitlements.py     #   categorization + sensitivity
│   ├── security_signals.py #   caller-validation + sensitive APIs
│   ├── sinks.py            #   sensitive sink taxonomy
│   ├── capabilities.py     #   operation maturity + independent scores
│   ├── scoring.py          #   explainable priority scoring
│   └── leads.py            #   research-lead generation
├── graph/
│   ├── model.py            #   Node/Edge + build_graph()
│   └── exporters.py        #   JSON / DOT / Mermaid
├── reporting/
│   ├── json_report.py      #   report assembly + report.json
│   └── html_report.py      #   self-contained dashboard
├── models/                 # services, binaries, findings and capability paths
├── rules/                  # configurable rules (see below)
│   ├── capabilities.json   # sources, argument semantics, sinks and proof gates
│   ├── entitlements.json
│   ├── signals.json
│   └── scoring.json
├── utils/
│   ├── commands.py         # safe subprocess (no shell, timeouts, caching)
│   ├── plist.py            # plist loading (binary + fallback)
│   └── rules.py            # rule-file loader
├── tests/                  # unittest suite
├── docs/                   # user and developer guides
├── pyproject.toml          # packaging + ruff/mypy/coverage config
└── .github/                # CI, issue and pull-request templates
```

**Data model** — every piece of evidence carries an explicit confidence level:

- `FACT` — directly observed (e.g. a `MachServices` key in a plist).
- `HEURISTIC` — inferred by rule (e.g. "links Security.framework").
- `UNKNOWN` — could not be determined.

---

[← Back to the docs index](index.md)
