# macOS-TBM agent guidance

For tasks in this repository, read [.codex/skills/macos-tbm/SKILL.md](.codex/skills/macos-tbm/SKILL.md) and follow its safety, evidence, CLI, and testing rules. Static analysis is read-only by design; active phases (`probe`, runtime hooks, PoC clients) are opt-in and require explicit user authorization per phase.

To take a single daemon apart end to end — what it is, what it exposes, who reaches it, and how it validates callers — use [.codex/skills/research/SKILL.md](.codex/skills/research/SKILL.md) (`@research <daemon>`). To move from a research brief to a working PoC, use [.codex/skills/exploit/SKILL.md](.codex/skills/exploit/SKILL.md) (`@exploit <daemon>`).
