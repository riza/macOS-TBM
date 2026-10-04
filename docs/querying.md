# Querying and protocol analysis

## Querying the graph

The full graph can contain thousands of nodes; research asks narrow questions. `tbm graph`
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

`report.html` carries an interactive, compact view of the trust core — services,
binaries, Mach services and subsystems. Open it with the **Graph** button, `g`, or the
**Graph ↗** button in any dossier; entitlement and framework nodes stay out (they
answer a different question and would make the interactive view unnecessarily dense).

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

## Deputy chains

`tbm graph --deputy <daemon>` answers the question for one provider. `tbm
deputy-all` runs it across every daemon in the report and expands each chain
while the deputy is itself a daemon:

```bash
python3 tbm.py deputy-all --min-score 90 --root-only --limit 20
python3 tbm.py deputy-all -out results/deputy-all   # writes .md/.csv/.json
```

A *deputy* is a client that looks up a daemon's Mach service **and** holds an
entitlement the daemon is expected to gate on. Chains ending at an unprivileged
client (`UNPRIV` in the text view) are the ones an attacker could ride:
non-root → deputy → root sink. The gate is the same server-side
`CHECKED_ENTITLEMENT` evidence as `graph --deputy`, falling back to the
`<label>.*` heuristic only when nothing was observed.

## NSXPC protocol extraction

For NSXPC daemons, reconstructing the exported Objective-C protocol by hand is
slow. `tbm protocol` extracts it statically:

```bash
python3 tbm.py protocol /usr/libexec/mobileactivationd
python3 tbm.py protocol com.apple.mobileactivationd --format json --output proto.json
```

`tbm protocol <binary-or-service>` runs `otool -ov` (arm64e slice, falling back
to the whole file) and `nm`, finds protocols exported via `NSXPCListenerDelegate`,
parses each `instanceMethods` table, and decodes the ObjC type encodings into
readable signatures — `v40@0:8@16@24@?32` becomes
`- (void)handleActivationInfo:(id)arg0 options:(id)arg1 withCompletionBlock:(id)block`.

On modern arm64e binaries `otool` prints the resolved *types* but leaves the
selector *names* as relative offsets; the extractor resolves the two-level
indirection (method-list name → `__objc_selrefs` → `__objc_methname`) itself.
Block arguments are rendered as `id` because a static extractor cannot recover
the block's signature reliably. Extraction never opens an XPC connection.

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

[← Back to the docs index](index.md)
