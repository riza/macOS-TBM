# Extending the rule sets

Rules are JSON under `rules/` and load at runtime — no code changes needed for
most additions.

## Add / tune an entitlement category (`rules/entitlements.json`)

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

## Add a security signal (`rules/signals.json`)

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

## Tune scoring weights (`rules/scoring.json`)

Edit the `weight` of any rule id. `caller_validation_cap` bounds the number of
negative caller-validation contributions.

## Tune capability analysis (`rules/capabilities.json`)

This file maps IPC input APIs to source kinds, sensitive APIs to sink categories
and operation primitives, and possible multi-step chains. A chain entry remains
explicitly speculative unless the bounded dataflow pass observes argument
propagation; adding co-occurring API names alone must never claim proven flow.

---

[← Back to the docs index](index.md)
