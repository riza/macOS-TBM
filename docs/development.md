# Development

## Running tests

```bash
python3 -m unittest discover -s tests -t tests -v
```

CI runs the suite on macOS across Python 3.10 / 3.12 / 3.13, plus an end-to-end
smoke scan of the runner's own LaunchDaemons — see
[.github/workflows/ci.yml](../.github/workflows/ci.yml).

## Contributing

False-positive reports are the most valuable contribution this project can get:
open one with the command output that contradicts the report and it becomes a
rule fix plus a regression test. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the
two hard rules (keep default analysis static and active analysis safe; never
claim a vulnerability) and for
how the rule matcher works before you tune `rules/*.json`.

- [Report a false positive](../../../issues/new?template=false_positive.md)
- [Report a bug](../../../issues/new?template=bug_report.md)
- Security policy: [SECURITY.md](../SECURITY.md)
- Release notes: [CHANGELOG.md](../CHANGELOG.md)

---

[← Back to the docs index](index.md)
