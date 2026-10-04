# Safety

- All external commands run via `subprocess` with `shell=False`, timeouts, and
  captured errors; a single malformed plist or binary cannot abort a scan.
- Binary/plist results are cached by path + mtime + size; identical executables
  referenced by many services are analyzed once.
- Analysis is parallelized through a bounded `ThreadPoolExecutor`.
- Static commands never connect to private services. The explicit runtime probe
  is bounded and non-destructive: connect-only by default, with at most one
  empty XPC dictionary behind a separate flag. It never fuzzes or invokes a
  known service operation.

---

[← Back to the docs index](index.md)
