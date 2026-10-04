# Getting started

```bash
git clone https://github.com/riza/macOS-TBM.git
cd macOS-TBM

# Map the whole system (deep dataflow can take 20+ minutes on a stock corpus)
python3 tbm.py scan

# Optional deep static analysis (requires radare2 + r2pipe)
python3 -m venv .venv-deep
.venv-deep/bin/python -m pip install -r requirements-deep.txt
.venv-deep/bin/python tbm.py scan com.apple.example --deep-analysis radare2

# Full deep scan: three binaries in parallel, five-minute cap per binary
.venv-deep/bin/python tbm.py scan --deep-analysis radare2 \
  --deep-workers 3 --deep-binary-timeout 300

# Active but connect-only Mach reachability validation
python3 tbm.py scan com.apple.example --runtime-probe

# Explicitly send one empty dictionary as well
python3 tbm.py probe com.apple.example.service --send-empty

# Show version and source build identifier
python3 tbm.py --version

# Read the result: in a browser, in the terminal, or as plain text
open results/report.html
python3 tbm.py tui
less -R results/scan.txt

# Optional: install the `tbm` command (pipx keeps it isolated)
pipx install .
# or, into the current environment
python3 -m pip install .
python3 -m pip install '.[ui]'     # Rich + tqdm + Textual
python3 -m pip install '.[deep]'   # r2pipe, for --deep-analysis radare2

tbm scan
tbm --version
```

No install step is required: `python3 tbm.py` runs from the checkout with the
standard library only. Installing the project adds a `tbm` console command
equivalent to `python3 tbm.py`. For a richer interactive terminal experience,
install the optional `ui` extra (Rich + tqdm + Textual); non-interactive output
keeps its plain fallback and remains safe to pipe.

## Requirements

- macOS (uses `codesign`, `nm`, `strings`, `plutil`, and `otool` for
  disassembly; Mach-O headers and sections are parsed natively).
- Python 3.10+ (standard library required; Rich and tqdm are optional UI packages).

The default analysis is **read-only and static**: it never modifies launchd
configuration, loads/unloads services, or mutates inspected files. The optional
runtime backend is active only behind explicit flags, is connect-only by
default, and can send at most one empty XPC dictionary when separately enabled.
The repository contains no runtime hook, generated operation client, fuzzing
harness, or exploit implementation.

## Example workflow

```bash
# 1. Map the whole system.
python3 tbm.py scan --output ./results

# 2. Open the dashboard and sort by score; note HIGH targets.
open ./results/report.html

# 3. Drill into a specific service.
python3 tbm.py service com.apple.example

# 4. Inspect the binary and its entitlements directly.
python3 tbm.py inspect /usr/libexec/exampled

# 5. Export the graph for visualization (Graphviz / Mermaid).
dot -Tsvg ./results/graph.dot -o graph.svg
```

---

[← Back to the docs index](index.md)
