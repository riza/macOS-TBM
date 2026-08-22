# STATE — single source of truth

Target: `com.apple.icloud.searchpartyd` · binary `/usr/libexec/searchpartyd` ·
arm64e thin: `lpe-work/re/searchpartyd-thin` (copy from `/tmp/spd-arm64e`)
Report: `results/report.json` · commit: `69c7dd5`

## Scores
- TBM score: 113 · validation: `NONE_OBSERVED` · run-as: root
- hunt: TOTAL 175 · LPE 80 · RCE 35 · DOS 25 · CRED 35
- Sinks: CREDENTIAL, PRIVACY, NETWORK, ACCOUNT, FILESYSTEM

## 12 Mach services
- com.apple.searchparty.BeaconScanningSession
- com.apple.icloud.searchpartyd.pairingmanager
- com.apple.searchparty.managedperipheral
- com.apple.icloud.searchpartyd.beaconmanager
- com.apple.searchparty.ObservationStoreService
- com.apple.icloud.searchpartyd.finderstatemanager
- com.apple.searchparty.BeaconKeyService
- com.apple.icloud.searchpartyd.accessorydiscoverymanager
- com.apple.icloud.searchpartyd.scheduler
- com.apple.icloud.searchpartyd.advertisementcache
- com.apple.icloud.searchpartyd.aps
- com.apple.icloud.searchpartyd.beaconmanager.agentdaemoninternal

## FMCA gate closure (`hasEntitlement` bypass path)
- string: `Temporarily allowing FMCA client without explicit entitlement.`
- string vaddr: `0x1012d0a70`
- ref: `0x100630cb4` · function (closure): `0x100630a20` (`pacibsp` at start)
- closure raw dump: `lpe-work/re/searchpartyd-fmca-closure-dis.txt`
- xref dump: `lpe-work/re/searchpartyd-fmca-xref.txt`

### Logic (static)
- x21 = `NSXPCConnection`; x23 = connection attrs; selector at `0x10150d5f8`
  returns a bitmask; bits 9 / 11 / 13 select a check branch.
- Every branch builds an `Entitlement` enum case on the stack
  (`sturb w8, [x29,#-N]`, w8 = 5/6/7/8) and calls the generic
  `NSXPCConnection.hasEntitlement<A: FindMyBase.Entitlement>`.
- hasEntitlement symbol:
  `_$sSo15NSXPCConnectionC10FindMyBaseE14hasEntitlementySbxAC0F0RzlF`
  → `(extension in FindMyBase):__C.NSXPCConnection.hasEntitlement<A where A: FindMyBase.Entitlement>(A) -> Bool`
- calls pass protocol descriptor `0x1014c6d70` + witness table (lazy global
  `0x101530d0`; conformance descriptor `0x10127c7f4` → Entitlement protocol).
- FMCA path (`0x100630c44`): first check true AND second check false →
  read global `0x101513960`; if `!= -1` → log FMCA string, fall through to
  accept; if `== -1` → `swift_once` init at `0x100630e80` then log.
- accept: `0x100630d84` → callback `0x1001a2724` (closure `0x100106ed8`).
- reject: Swift error code `0xc` (12) at `0x100630d0c`.

### Open (static) — resolved at runtime
- Enum case tag (w8) ↔ entitlement string mapping. Type pointer is a
  PAC-authenticated `__auth_ptr` (conformance 0x10127c7f4 → 0x10148b660),
  not statically resolvable.
- Initial value and writer of `0x101513960` (feature flag / FMCA allow list).
- Which Mach service owns this closure.
- FindMyBase framework binary is NOT on disk (dyld shared cache) —
  `hasEntitlement` implementation must be read at runtime.

## Entitlement type names in binary (strings)
BeaconSharingEntitlement · AdvertisementCacheEntitlement ·
OwnerSessionEntitlement · SchedulerEntitlement ·
LightweightBeaconManagerEntitlement · ManagedCBPeripheralManagerEntitlement ·
SecureLocationsEntitlement · BeaconManagerEntitlement ·
AccessoryDiscoveryEntitlement · LocalFindableConnectionMaterialEntitlement ·
BTFindingEntitlement · FinderStateEntitlement · Entitlement
Protocol: `searchpartyd.XPCEntitlementEnforced`

## Gate-key holders (`tbm entowners --contains searchpartyd`, 16 targets)
- `com.apple.bluetoothd` (root, STRONG): access, beaconmanager, ownersession,
  advertisementcache access/write, finderstatemanager.access
- `com.apple.icloud.findmydeviced` (root, MEDIUM): beaconmanager, ownersession,
  pairingmanager, securelocations, securelocations.access
- `com.apple.icloud.searchpartyd` (root, NONE): access, advertisementcache
  read/write/access, scheduler.access
- PerfPowerServices / PerfPowerServicesExtended / perfpowermetricd /
  powerlogHelperd (root, NONE): beaconmanager
- `com.apple.locationd` (specific-user, STRONG): advertisementcache access

## held private entitlements (30, highlights)
system-keychain · private.ckks · cloudkit.masquerade ·
accounts.allaccounts · tcc.allow · locationd.authorizeapplications ·
iokit.system-nvram-allow · MobileGestalt.AllowedProtectedKeys ·
authkit.client.private · applecredentialmanager.allow

## Companion
- `com.apple.icloud.searchpartyuseragent`: current-user, TBM 93, NONE_OBSERVED,
  12 Mach services — user-side bridge / confused-deputy candidate.

## tbm tooling (this session, uncommitted)
- `xref.py`: absolute line idx, window eviction, context slicing, `pacibsp`
  function start, out-of-range guard, and `p.terminate()` before `p.wait()` to
  avoid pipe deadlock when max-refs breaks early.
- `tbm.py`: `xref`/`entowners`/`hunt` honor `-out/--output`; hunt `--label` -out.
- tests: `tests/test_xref.py`, `tests/test_entowners.py`,
  `tests/test_cli_output.py` — 173 pass.

## Blocker
- Confirm FMCA global (`0x101513960`) semantics and enum↔string mapping at
  runtime before building the bypass client. Active phase needs authorization.
