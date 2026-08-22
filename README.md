# agent-guard

**A destructive-action reliability layer for AI agents.**

Agents increasingly run shell commands autonomously. When the command is
`rm -rf`, a wrong variable or one misjudged context switch is all it takes
to lose a repository - or worse. agent-guard makes destruction *reversible
by default* and *audited always*, across any harness that can run Python.

> Agent 可以自主提出删除,也可以执行低风险、可恢复的删除,
> 但不应默认拥有不可逆的数据销毁权。

## The four pillars

| Pillar | Guarantee |
|---|---|
| **Scope** | Workspace boundary, `.git`, and outside paths are never deletable |
| **Recoverability** | Deletions relocate to `.agent-trash/` with a manifest; git overwrites snapshot first |
| **Authorization** | One-way mode downgrade on veto; only humans restore power |
| **Auditability** | Every verdict, compensation, and restore lands in JSONL |

Guiding rule: **uncertainty increases restriction.** Unresolvable targets
are blocked, never guessed.

## Quickstart

Zero dependencies beyond Python 3.8+ and git.

```bash
# delete something - it is quarantined, not destroyed:
python3 skills/delete-guard/scripts/safe_delete.py build/ --reason "stale"

# inspect and undo:
python3 skills/delete-guard/scripts/status.py
python3 skills/delete-guard/scripts/restore.py list
python3 skills/delete-guard/scripts/restore.py <txid>
```

Harness adapter (intercept before executing any shell command):

```bash
python3 skills/delete-guard/scripts/check.py --enforce -- "$COMMAND"
case $? in 0) run "$COMMAND" ;; 2) refuse ;; esac
```

One call classifies by effect, applies compensation first (relocate /
git stash / clean-enumeration), and returns PROCEED or BLOCKED with stable
machine-readable codes. See `docs/architecture.md`.

## What gets protected

```text
rm -rf build/            → RELOCATE  (tree quarantined, command proceeds)
rm -rf .                 → BLOCK     (workspace root)
rm -rf $DIR/             → BLOCK     (unresolvable target)
rm *.log                 → BLOCK     (opaque glob; safe_delete expands it)
git clean -fd            → COMPENSATE (enumerate via -n, relocate, proceed)
git reset --hard         → COMPENSATE (stash snapshot first)
git push --force         → BLOCK     (V1: remote history is out of bounds)
node_modules/ (ignored)  → ALLOW     (provably regenerable)
```

## Repository layout

```
agent-guard/
├── skills/delete-guard/   # agent-facing skill: SKILL.md + CLI scripts
├── core/                  # classifier · policy · recovery · audit
├── tests/                 # unittest suite (35 tests)
└── docs/                  # architecture.md · threat-model.md
```

Skills guide agent behavior; constraints live in Core. Future
`git-guard`, `database-guard`, `cloud-guard` skills plug into the same core
without restructuring.

## Status

V1 prototype, validated against real agent workflows on Linux/macOS.
Windows dialects, retention/GC policy, and remote-ref protection are next;
see `docs/architecture.md#roadmap`.

## License

MIT - see `LICENSE`.
