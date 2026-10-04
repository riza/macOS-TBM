# Evidence, confidence, and limitations

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

[← Back to the docs index](index.md)

## Optional backend proof boundaries

Radare2 is experimental static callsite/xref enrichment. A structural call path
does not establish request reachability, argument flow, authorization or impact.
See [research beta validation](research-release.md) for the exact promotion
contract, architecture limitations, provenance and evaluation results.
