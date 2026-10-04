# Security policy

## What this tool is

macOS-TBM is a security-research tool. It reads launchd plists, code-signing
metadata and Mach-O structure, and it writes a report. The default pipeline is
static and never modifies the system. Optional runtime probing is explicit,
bounded and conservative: connect-only by default, with a separate flag for one
empty XPC dictionary. It never fuzzes arbitrary fields, invokes known
destructive operations, elevates, persists, changes settings/credentials, or
includes exploit implementations. Reachability is never reported as an
authorization bypass.

## Reporting a vulnerability *in macOS-TBM*

If you find a way to make this tool damage, mutate or exfiltrate from the system
it runs on — command injection through a crafted plist, a path handling bug, an
unsafe subprocess invocation — please report it privately through GitHub's
"Report a vulnerability" flow (Security → Advisories) rather than in a public
issue. Include the crafted input and the observed effect.

Expect an acknowledgement within a week.

## Reporting a vulnerability *found using* macOS-TBM

Findings about macOS itself belong to Apple, not to this repository. Use
<https://security.apple.com/> and follow their disclosure process. Please do not
open issues here containing unreported vulnerability details about Apple
components.

## Scope notes

- A report from this tool is a *research lead*, not a vulnerability. High scores
  mean "worth reading the binary", nothing more.
- Findings marked `HEURISTIC` are inferred from symbols and strings and can be
  wrong in both directions.
- Run scans on systems you are authorised to analyse.
