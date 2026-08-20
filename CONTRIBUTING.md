# Contributing to macOS-TBM

Thanks for helping map the surface. This project has one hard rule and a few
soft ones.

## The hard rule: read-only, always

macOS-TBM never modifies the system it inspects. A contribution may **not**:

- load, unload, enable, disable, `kickstart` or `bootout` a launchd job,
- send an XPC or Mach message to a live service,
- write to, patch or re-sign any inspected file,
- fuzz, probe or exploit anything.

Every external command goes through `utils.commands.run`: `shell=False`, a
timeout, captured errors. If you need a new command, add it there and make sure
a failure degrades the scan instead of aborting it.

## The language rule: never claim a vulnerability

The tool maps attack surface. It does not determine exploitability. Findings
carry a level and must read accordingly:

| Level | Meaning | Example wording |
|-------|---------|-----------------|
| `FACT` | Parsed directly from metadata | "launchd job registers Mach service X" |
| `HEURISTIC` | Inferred from symbols/strings/libraries | "interacts with 'credential' subsystem (static indicators)" |
| `UNKNOWN` | Looked for, not found | "caller-validation signal not observed statically" |

"Not observed statically" is never "authorization is missing". A pull request
that turns an indicator into a verdict will be asked to reword it.

## Reporting a false positive

False positives are the most valuable bug report this project can get, and there
is an issue template for them. A good report contains the label, what the report
claimed, and the command output that contradicts it:

```bash
python3 tbm.py service com.apple.example
nm -arch all -u /usr/libexec/exampled | grep -E "your|symbols"
otool -L /usr/libexec/exampled
launchctl print system/com.apple.example
```

## Tuning rules

Most precision work needs no Python. `rules/*.json` is loaded at runtime — see
the "Extending the rule sets" section of the README for the matching semantics.

Two lessons already paid for, please keep them:

- **Match names, not substrings.** A needle must survive `_match.py`'s pool
  rules. `connect` is the `connect` syscall — writing it so that it also matches
  `xpc_connection_send_message` once mislabelled 310 targets as network-facing.
- **A framework link is weak evidence.** `Security` in `libs` once produced 348
  "handles credentials" claims. Prefer a symbol needle (`SecItemCopyMatching`)
  over a library needle when both would work.

When you change a rule, re-run a full scan and report the before/after counts
per sink in the pull request. A rule that changes nothing, or that changes
thousands of rows, both deserve a second look.

## Tests

```bash
python3 -m unittest discover -s tests -t tests -v
```

New heuristics need a test. Regression tests for fixed false positives live in
`tests/test_match_and_state.py` — add to it rather than starting a new file for
the same class of bug.

## Style

- Keep the scanner usable with the standard library alone. Rich, tqdm and
  Textual are optional terminal UI enhancements listed in `requirements.txt`;
  every command must retain a plain fallback when they are unavailable.
- Type hints on public functions, docstrings that say *why*, not *what*.
- Match the surrounding code: it is plain, boring Python on purpose.

## Commits and pull requests

Describe what the change does to the *output*, not just the code. For rule and
scoring changes, include the scan deltas. Small, reviewable pull requests get
merged; large ones get questions.
