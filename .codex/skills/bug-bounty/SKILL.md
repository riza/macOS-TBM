---
name: bug-bounty
description: macOS launchd service bug bounty triage — score and rank daemons for LPE, RCE, DOS, and credential theft potential using static analysis data. Produce attack-surface-focused research briefs. Trigger: "/bug-bounty", "bug bounty hunt", "find LPE/RCE", "@bug-bounty <daemon>"
---

# Bug Bounty Research — LPE/RCE/DOS hunting in macOS launchd services

This skill uses macOS-TBM's static analysis output. **Fully read-only** — never
mutates launchd jobs.

## Prerequisite

An up-to-date `./results/report.json` is required. If missing, scan first:

```bash
python3 tbm.py scan --scope all   # may take 5-15 min
```

## Commands

### `tbm hunt` — bug bounty scoring engine

Scores and ranks every target through LPE/RCE/DOS/CRED lenses.
Operates on `report.json` only — no new scan.

```bash
python3 tbm.py hunt                          # all targets, ranked by total score
python3 tbm.py hunt --top 20                 # top 20
python3 tbm.py hunt --class lpe              # rank by LPE score only
python3 tbm.py hunt --class rce              # RCE potential
python3 tbm.py hunt --class cred             # credential theft potential
python3 tbm.py hunt --min-score 80           # filter by minimum total score
python3 tbm.py hunt --label com.apple.teslad # single-target detailed brief
python3 tbm.py hunt --format json            # JSON output
```

### Other useful commands

```bash
# Non-root client → root provider boundary crossings
python3 tbm.py graph --boundaries --format json | jq '.[] | select(.provider_run_as == "root")'

# Deputy analysis: clients that can wield a daemon's privileges
python3 tbm.py graph --deputy <label>

# Extract XPC protocol
python3 tbm.py protocol <label> --format json

# Full dossier for a single target
python3 tbm.py service <label>
```

## Scoring Rules

`tbm hunt` scores each target on these signals:

### LPE (Local Privilege Escalation)

| Signal | Score |
|--------|-------|
| root + WEAK/NONE_OBSERVED validation | +30 |
| root + sectask-entitlement not-observed | +10 |
| root + audit-token-extraction not-observed | +10 |
| root + code-signing-requirement not-observed | +10 |
| CREDENTIAL sink HIGH + weak validation | +15 |
| root + EXECUTION sink | +10 |
| root + held_ents > checked_ents + weak validation | +5 |

### RCE (Remote Code Execution)

| Signal | Score |
|--------|-------|
| root + NETWORK sink + weak validation | +20 |
| root + mach_count > 0 + weak validation | +10 |
| INSTALL/UPDATE sink + root | +5 |
| mach_count ≥ 2 + weak validation | +5 |

### DOS (Denial of Service)

| Signal | Score |
|--------|-------|
| score ≥ 90 + weak validation | +15 |
| mach_count ≥ 3 | +5 |
| root | +5 |

### CRED (Credential Theft)

| Signal | Score |
|--------|-------|
| CREDENTIAL sink HIGH | +20 |
| `com.apple.private.system-keychain` held | +10 |
| ACCOUNT sink | +5 |
| `keychain-access-groups` held | +5 |

### Score Thresholds

| Class | Low | Medium | High |
|-------|-----|--------|------|
| LPE | 10-20 | 25-40 | 45+ |
| RCE | 5-10 | 15-25 | 30+ |
| DOS | 5-10 | 15+ | — |
| CRED | 10-15 | 20-30 | 35+ |

## Vulnerability Class Indicators

When manually reviewing a target, look for these patterns:

- **LPE**: root daemon + WEAK/NONE_OBSERVED validation + non-root client access + audit-token not-observed
- **RCE**: NETWORK sink + XPC deserialization + APS push-triggered + INSTALL/UPDATE sink
- **DOS**: critical system service + multiple Mach services + weak validation
- **CRED**: CREDENTIAL sink HIGH + system-keychain + ACCOUNT sink + keychain-access-groups

## Work Modes

### Mode 1: Hunt (broad sweep)

When the user says `/bug-bounty`: run `tbm hunt --top 30`, then produce short
briefs for the top 5-10 targets covering:

- Label, score, run-as, validation, vulnerability class flags
- Why it's interesting (which class drives the high score)
- Mach services, critical held entitlements
- Most promising attack vector

### Mode 2: Single-target deep dive (`@bug-bounty <daemon>`)

1. `tbm hunt --label <daemon>` — score card
2. `tbm service <label>` — full dossier
3. `tbm graph --node <label> --depth 2 --format json` — reach graph
4. `tbm graph --deputy <label>` — deputy analysis
5. `tbm protocol <label> --format json` — XPC protocol

Brief sections:

- **Score Card** — LPE/RCE/DOS/CRED scores
- **Attack Surface** — Mach services, NSXPC methods
- **Trust Boundary Crossing** — non-root → root transitions
- **Validation Gaps** — not-observed classes and their meaning
- **Held vs Checked** — entitlements held vs checked on callers
- **Potential Attack Vectors** — concrete scenarios through LPE/RCE/DOS/CRED lenses
- **Manual Review Roadmap** — which binary/framework and methods deserve closer static review
- **Limitations** — static analysis only, no runtime probing

## Safety Rules

- Stay read-only. Never load/unload/enable/disable/bootstrap launchd jobs.
- Do not connect to live services, generate clients, fuzz targets, or produce
  exploit/PoC code.
- `NONE_OBSERVED` ≠ "absent". Not seen in static analysis does not mean not present at runtime.
- Do not produce exploit code. Keep briefs defensive and review-oriented.
