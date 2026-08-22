# com.apple.icloud.searchpartyd — exploit brief

Status: static gate map complete · runtime NOT authorized
Raw dumps: `lpe-work/re/searchpartyd-fmca-*` · truth: `lpe-work/STATE.md`

## What it is
Root XPC daemon behind Find My ("searchpartyd"). Implements beacon scanning,
pairing, observation store, finder-state, accessory discovery, advertisement
cache, and APS. It is a high-value root target because of the private
entitlements it holds (system keychain, CKKS, CloudKit masquerade, TCC,
location, NVRAM, MobileGestalt, AuthKit) and the broad Mach surface (12
services). A compromise of this daemon is a root + credential + privacy
extraction, not just code execution.

Static validation is `NONE_OBSERVED` (0 checked entitlements) — treat that as a
hypothesis, not a fact.

## Attack surface
- 12 Mach services (list in STATE.md). Every service has an XPC listener with
  an accept closure; the FMCA closure at `0x100630a20` is one accept path that
  gates via `NSXPCConnection.hasEntitlement<Entitlement>`.
- Entitlement gates: enum-typed Swift entitlements (`FindMyBase.Entitlement`
  protocol, `searchpartyd.XPCEntitlementEnforced`). The entitlement STRINGS are
  the real keys; the enum tags (5/6/7/8) select which one per connection class.
- Entry options:
  1. Ad-hoc signed client carrying a gate entitlement string
     (`com.apple.icloud.searchpartyd.access` / `.beaconmanager` /
     `.advertisementcache` / `.ownersession` / ...) → connect to a service.
  2. FMCA bypass: if global `0x101513960` + the first-check-true path lets a
     connection through without the second entitlement, an unentitled (or
     singly-entitled) client may pass.
  3. Confused deputy: `com.apple.icloud.searchpartyuseragent` (current-user,
     holds many searchpartyd keys) is the natural bridge from user context.

## Gate keys and holders (static)
See STATE.md. Short version: bluetoothd and findmydeviced are the privileged
external holders; locationd holds advertisementcache keys as specific-user;
the PerfPower family holds beaconmanager without validation.

## Extraction if compromised
- Keychain CRUD / signing under system keychain entitlement.
- CloudKit/CKKS identity: masquerade as the account, move/read iCloud data.
- TCC privacy DB + location authorization grants.
- NVRAM + MobileGestalt protected keys (device identity).
- Find My payloads: beacon keys, observation store, secure locations, finder
  state, advertisement cache — owner/sharee relationships and location history.
- Root context push/network via APS/IDS.

## Next step (needs authorization)
Runtime pass with frida on `searchpartyd`:
1. Resolve `hasEntitlement` (FindMyBase, from shared cache) and hook it; log
   the enum string per call.
2. Hook the selector at `0x10150d5f8` (bitmask) and the closure `0x100630a20`
   to map bit 9/11/13 → service → entitlement string.
3. Set a hardware watchpoint on `0x101513960` to find the writer and initial
   value; confirm the FMCA fallback condition.
4. Build ad-hoc client with each candidate entitlement string and record which
   service accepts unprivileged clients.
