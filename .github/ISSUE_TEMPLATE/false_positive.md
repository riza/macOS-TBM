---
name: False positive
about: The report claims surface the machine does not actually have
title: "[FP] <label>: <what was claimed>"
labels: false-positive
---

**Service label**

<!-- e.g. com.apple.watchdogd -->

**What the report claimed**

<!-- e.g. sink NETWORK; or "caller-validation not observed"; or run_as root -->

**What the machine says**

<!-- Paste the command output that contradicts it. Useful ones:
python3 tbm.py service <label>
nm -arch all -u <binary> | grep -E '<symbols>'
otool -L <binary>
launchctl print system/<label>
plutil -p /System/Library/LaunchDaemons/<label>.plist
-->

```
<output>
```

**Which needle or rule produced it**

<!-- The finding evidence quotes the match, e.g. "connect <- dispatch_mach_connect".
     Paste that line if you have it. -->

**Environment**

- macOS version:
- Hardware (Apple silicon / Intel):
