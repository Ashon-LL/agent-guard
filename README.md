[![CI](https://github.com/mokuyoaxis/agent-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/mokuyoaxis/agent-guard/actions/workflows/ci.yml)

# agent-guard

**Make destructive agent actions reversible by default.**
**[简体中文](README.zh-CN.md)**

Agents increasingly run shell commands autonomously. When the command is
`rm -rf`, a wrong variable or one misjudged context switch is all it takes
to lose a repository — or worse. agent-guard makes destruction *reversible
by default* and *audited always*, across any harness that can run Python.

> **Agent Guard is not an approval system. It is an automatic recovery
> system with human escalation.** The agent works uninterrupted while
> operations stay reversible; only when the guard cannot safely automate —
> but user intent may be legitimate — does a decision escalate to a human.
>
> It is reliability infrastructure, **not a security sandbox**: it defends
> against mistakes, not against a malicious agent with equal OS privileges.

## The four pillars

| Pillar | Guarantee |
|---|---|
| **Scope** | Workspace boundary, `.git`, and outside paths are never deletable |
| **Recoverability** | Deletions relocate to `.agent-trash/` with a manifest; git overwrites snapshot first |
| **Authorization** | Session-scoped capability; a veto downgrades one-way, only humans restore |
| **Auditability** | Every verdict, compensation, and restore lands in append-only JSONL |

A rule runs through all four: **uncertainty increases restriction.**

## How it decides

The stable interface is not allow/block — it is a Decision Protocol:

```
Effect → Classifier → Policy → Decision   ∈ { ALLOW, RELOCATE, SNAPSHOT,
                                            ASK, BLOCK }
                                + ReasonCode   (stable, machine-readable)
                                + Explanation  (human-facing)
                                + RecoveryPlan (txids, strategy)
```

| Tier | Decisions | What the agent experiences |
|---|---|---|
| **SAFE** | `ALLOW` · `RELOCATE` · `SNAPSHOT` | Runs silently; compensation applied first; restorable via txid |
| **AMBIGUOUS** | `ASK` | Single-execution authorization (`ASK_ONCE`) — e.g. compound shapes the guard cannot safely automate |
| **FORBIDDEN** | `BLOCK` | Refused with reason and remediation; never askable |

True effect-uncertainty (`$VAR` targets, `bash -c`, `find -delete`,
stdin-fed lists) stays on the BLOCK path: allowing it would forfeit the
core guarantee. Adapters map decisions onto their harness natively — DSH
`PreToolDecision`, Claude Code PreToolUse `ask`, or a deny carrying the
explanation where no ask exists.

## Quickstart

Zero third-party dependencies. Requirements: Python 3.9+, POSIX shell,
git.

```bash
# delete something - it is quarantined, not destroyed:
python3 skills/delete-guard/scripts/safe_delete.py build/ --reason "stale"

# inspect and undo:
python3 skills/delete-guard/scripts/status.py
python3 skills/delete-guard/scripts/restore.py list
python3 skills/delete-guard/scripts/restore.py <txid>

# quarantine maintenance (dry plan by default):
python3 skills/delete-guard/scripts/gc.py
```

Harness adapter - intercept before executing any shell command:

```bash
python3 skills/delete-guard/scripts/check.py --enforce -- "$COMMAND"
case $? in 0) run "$COMMAND" ;; 2) refuse ;; 3) ask-the-human ;; esac
```

## What gets protected

```text
rm -rf build/            → RELOCATE  (tree quarantined, command proceeds)
rm -rf .                 → BLOCK     (workspace root)
rm -rf $DIR/             → BLOCK     (unresolvable target: fail closed)
rm *.log                 → BLOCK     (opaque glob; safe_delete expands it)
cd X && rm -rf build     → ASK_ONCE  (COMPOUND_CWD_DELETE)
touch f && rm f          → ASK_ONCE  (COMPOUND_CREATE_DELETE)
git clean -fd            → RELOCATE  (enumerate via -n, relocate, proceed)
git reset --hard         → SNAPSHOT  (stash first, apply to recover)
git push --force         → BLOCK     (remote history is never automated)
node_modules/ (ignored)  → ALLOW     (provably regenerable)
quarantine full          → BLOCK     (never fall back to permanent delete)
```

## Adapters

| Harness | Status | Mechanism |
|---|---|---|
| **DSH** (DeepSeek Harness) | **published plugin** | `dsh plugin --profile <p> add github:mokuyoaxis/agent-guard` — waterfall interception + tools + prompt section |
| **Claude Code** | ready (`adapters/claude/`) | PreToolUse hook → `permissionDecision` allow/ask/deny |
| OpenCode / MCP | planned | once conformance has proven out twice |

Cross-harness guarantee, enforced by `tests/test_conformance.py`:
identical command + cwd + workspace state must produce identical core
decision + reason code through any adapter.

## Repository layout

```
agent-guard/
├── skills/delete-guard/   # agent-facing skill: SKILL.md + CLI scripts
├── core/                  # classifier · policy · recovery · audit
├── adapters/claude/       # Claude Code PreToolUse hook adapter
├── tests/                 # unittest suites incl. cross-harness conformance
└── docs/                  # architecture · threat-model · friction log
```

Skills guide agent behavior; constraints live in Core. Future
`git-guard`, `database-guard`, `cloud-guard` skills plug into the same
compensation engine without restructuring.

## Documentation

| Read | For |
|---|---|
| [docs/architecture.md](docs/architecture.md) | pillars ↔ components, data flow, design decisions |
| [docs/threat-model.md](docs/threat-model.md) | honest limits: what this is and is not |
| [docs/friction.md](docs/friction.md) | what real agents taught us (F1–F8) |
| [skills/delete-guard/references/policy.md](skills/delete-guard/references/policy.md) | full rule table and decision codes |

## Status & roadmap

V1 hardening complete; `v0.1.0` release gate: CI (this repository),
retention policy documented, Claude adapter conformance green.
Next: second live adapter verification, retention automation,
Windows dialects (demand-driven), then `database-guard` /
`cloud-guard` on the same compensation engine.

## License

MIT — see [LICENSE](LICENSE).
