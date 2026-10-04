# macOS-TBM agent guidance

For tasks in this repository, read [.codex/skills/macos-tbm/SKILL.md](.codex/skills/macos-tbm/SKILL.md) and follow its safety, evidence, CLI, and testing rules. The default pipeline is static. Radare2 deep analysis and conservative XPC/Mach reachability probing are optional and must run only when explicitly requested; never add fuzzing, destructive operations, persistence, or exploit/PoC behavior.

To take a single daemon apart end to end — what it is, what it exposes, who appears to reach it statically, and how it validates callers — use [.codex/skills/research/SKILL.md](.codex/skills/research/SKILL.md) (`@research <daemon>`).

Active analysis requires explicit user authorization and must preserve operation authorization and post-condition as separate, unproven questions.
