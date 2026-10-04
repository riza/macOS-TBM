# Trust model and scoring

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

[← Back to the docs index](index.md)
