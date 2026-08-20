---
name: research
description: Dissect one macOS launchd daemon end to end with this repository's macOS-TBM. Given a service label or binary path, resolve it, pull its full dossier, enumerate its exposed Mach/XPC surface and NSXPC protocol, map who reaches it and which entitlements it holds versus checks, read its caller-validation evidence, and write a structured research brief. Trigger for "@research <daemon>", "take <daemon> apart", "what is <daemon>, where is it called from", or any single-target deep dive on a macOS system service.
---

# Daemon research — take one service apart with macOS-TBM

Goal: turn a daemon name into an evidence-backed brief — what it is, what it
exposes, who can reach it, what it is trusted to do, and how it decides whom to
trust — using only this repository's read-only tooling. This is reconnaissance
for manual review, not an exploitability claim.

Work from the repository root. Everything below is `python3 tbm.py ...`.

## Safety and evidence rules (inherit from the project skill)

Read [../macos-tbm/SKILL.md](../macos-tbm/SKILL.md) first; its rules bind here.
The ones that matter most for a deep dive:

- Read-only by default. Never load/unload/enable/disable/bootstrap a job.
- `probe` is the one active command: it opens XPC connections and sends test
  messages. Run it **only** when the user explicitly asks for active probing and
  confirms authorized use, and label its results as runtime evidence.
- Preserve `NONE_OBSERVED` / `WEAK` / `MEDIUM` / `STRONG` exactly. "Not observed"
  is a statement about this scanner, never proof the check is absent.
- Distinguish held entitlements from checked entitlements, linked frameworks
  from imported APIs, a declared Mach lookup from a live connection, and a
  provider's validation grade from the client's.
- Do not produce exploits, caller-validation bypasses, persistence, or
  credential access. Keep the brief defensive and review-oriented.

## Inputs

The user gives a **target**: a service label (`com.apple.mobileactivationd`), a
substring, or a binary path (`/usr/libexec/mobileactivationd`). If it is a
substring that matches several services, list the matches and ask which one, or
research each briefly and say so.

## Prerequisite: a report to query

Graph questions ("who reaches it", "is it a deputy") need a full
`report.json`, because the graph is built across every service.

1. If `./results/report.json` exists and is recent enough for the user, use it.
2. Otherwise run a scan first: `python3 tbm.py scan --scope daemons` (writes
   `./results`, including the graph). Use `--scope all` if the target is an agent.
3. For a binary with no launchd job, or a quick look with no graph, `tbm service`
   / `tbm inspect` alone still give the dossier.

## Workflow

Run these, then write the brief. Prefer `--format json` and pipe through `jq`
when you only need a field; fall back to the text view for reading.

1. **Identity & dossier** — what it is, how it runs, how it is signed.
   ```bash
   python3 tbm.py service <label>            # full dossier for the matching job(s)
   # or, from a saved report, the same target:
   jq '.targets[] | select(.label=="<label>")' results/report.json
   ```
   Capture: plist path, program, run-as + derivation, load state + derivation,
   score and priority, code signing (identifier, team, platform binary,
   authority), architectures.

2. **Exposed surface** — what a client can talk to.
   - Mach services and sockets from the dossier (`service.mach_services`).
   - The NSXPC protocol it exports, if any:
     ```bash
     python3 tbm.py protocol <label-or-binary> --format json
     ```
     Record the protocol name(s), each method, and its argument types. This is
     the interface an attacker-controlled client would call. Only run
     `clientgen` if the user explicitly wants a review client.

3. **Reach — who can call it, and where it sits.**
   ```bash
   python3 tbm.py graph --node <label> --depth 2          # its neighbourhood
   python3 tbm.py graph --boundaries --format json \
     | jq '.[] | select(.provider=="<label>")'            # non-root clients naming it
   python3 tbm.py graph --deputy <label>                  # confused-deputy candidates
   python3 tbm.py graph --path <some-client> <label>      # a concrete route in
   ```
   Capture: which Mach services it PROVIDES, who LOOKS_UP each (with the run-as
   user and privilege of the caller), whether any **non-root** client can reach
   a **root** provider, and any deputy that holds a `<label>.*`-style entitlement.

4. **Trust — what it is trusted with, and whom it trusts.**
   - **Holds**: `entitlement_findings` (the private/high-value grants) and the
     full `codesign.entitlements` map.
   - **Checks on callers**: `checked_entitlements` — the entitlement strings the
     binary appears to test on its clients. Held ≠ checked; say which is which.
   - **Sensitive sinks**: `sink_assessments` — the subsystems it touches
     (CREDENTIAL, EXECUTION, FILESYSTEM, PRIVACY, ...) with the concrete
     symbol/string/entitlement evidence and weights.

5. **Caller validation — how it decides whom to trust.**
   From `validation` + `validation_assessment`: the grade, the observed classes
   (audit-token extraction, entitlement check, code-signing requirement, ...)
   with their matches, **and** the classes not observed, with what was looked
   for. Report the grade verbatim and treat gaps as review questions, not holes.

6. **(Opt-in) runtime reachability.** Only if the user authorizes active
   probing:
   ```bash
   python3 tbm.py probe --service <label> --format json
   ```
   Classifies whether an unprivileged client can spawn/connect to the service.
   Label it runtime evidence, separate from the static findings.

## Output — the research brief

Write a compact, evidence-first brief with these sections. Every claim points at
its evidence (a symbol, string, entitlement, plist key, or graph edge); no claim
of exploitability.

- **Target** — label, binary, run-as, load state, score/priority, one-line "what
  it is".
- **Surface** — Mach services / sockets, and the NSXPC protocol (methods +
  argument types) if extracted.
- **Reach** — who provides/looks-up what; whether a non-root client reaches a
  root provider; deputy candidates. Note the concrete client → Mach service →
  provider chain.
- **Trust** — entitlements held (private ones first) vs. entitlements it checks
  on callers; sensitive sinks with evidence.
- **Caller validation** — the grade verbatim, observed classes, and the
  not-observed classes as open questions.
- **(If probed) Runtime** — reachability classification, labelled as active.
- **Open manual-review questions** — the `research_questions` from the dossier
  plus anything the reach/validation gaps raise (e.g. "is authorization
  per-connection or per-operation?", "which client parameters cross into the
  privileged operation?").
- **Limitations** — what is static-only, what "not observed" means here, and any
  binary the scanner could not read.

## Handy one-liners

```bash
# The whole dossier for one target, from a saved report
jq '.targets[] | select(.label=="com.apple.mobileactivationd")' results/report.json

# Everything that looks up this daemon's Mach services, with the caller's privilege
python3 tbm.py graph --node com.apple.mobileactivationd --depth 1 --format json

# Private grants held vs. entitlements checked on callers
jq '.targets[] | select(.label=="<label>")
    | {holds: .entitlement_findings, checks: .checked_entitlements}' results/report.json

# Caller-validation grade and the classes not observed
jq '.targets[] | select(.label=="<label>")
    | {grade: .validation, missing: [.validation_assessment.not_observed[].class]}' results/report.json
```
