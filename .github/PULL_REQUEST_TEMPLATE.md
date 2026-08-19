## What this changes

<!-- Describe the effect on the *output*, not only the code. -->

## Scan deltas (required for rule/scoring changes)

<!-- Re-run a full scan before and after, and paste the counts.

| sink | before | after |
|------|--------|-------|
-->

## Checklist

- [ ] Read-only: no launchd mutation, no XPC/Mach messages, no file writes to inspected paths
- [ ] No vulnerability claims; findings keep their FACT / HEURISTIC / UNKNOWN level
- [ ] Standard library only
- [ ] `python3 -m unittest discover -s tests -t tests` passes
- [ ] New heuristic or fixed false positive has a test
