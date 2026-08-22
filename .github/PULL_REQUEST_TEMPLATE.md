## What this changes

<!-- Describe the effect on the *output*, not only the code. -->

## Scan deltas (required for rule/scoring changes)

<!-- Re-run a full scan before and after, and paste the counts.

| sink | before | after |
|------|--------|-------|
-->

## Checklist

- [ ] Analysis read-only by default; any active behavior lives in an opt-in command (`probe`-style) that requires user authorization and never runs in a scan
- [ ] No vulnerability claims; findings keep their FACT / HEURISTIC / UNKNOWN level
- [ ] Standard library only
- [ ] `python3 -m unittest discover -s tests -t tests` passes
- [ ] New heuristic or fixed false positive has a test
