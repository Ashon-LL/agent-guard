# agent-guard architecture

## Positioning

agent-guard is **Agent Reliability Infrastructure**: it lowers the
probability that an autonomous agent causes irreversible loss through a
misjudged deletion, a mis-expanded command, or mistaken context - and it
leaves a recovery path and an evidence trail when anything destructive does
happen. It is explicitly *not* a sandbox or security boundary (see
`threat-model.md`).

## The four pillars and where they live

| Pillar | Question it answers | Component |
|---|---|---|
| Scope | Where may the agent act? | `core/classifier.py` (boundary facts) + `core/policy.py` (rules 3-6) |
| Recoverability | If wrong, how do we come back? | `core/recovery.py` (relocate / snapshot / restore) |
| Authorization | Who decides what? | `core/policy.py` (mode state machine) |
| Auditability | What actually happened? | `core/audit.py` + `.agent-trash/*.jsonl` |

A fifth, cross-cutting rule governs all four:

> **Uncertainty increases restriction** (fail closed).

Anything the classifier cannot resolve statically - shell variables, command
substitution, unbalanced quotes, indirect shells, stdin-fed target lists -
becomes a BLOCK verdict, never a guess.

## Data flow

```
shell command (from any harness)
        │
        ▼
[harness adapter]  ── fast prefilter: destructive keywords present? ──no──▶ run unchanged
        │ yes
        ▼
scripts/check.py --enforce -- <command>
        │
        ▼
classifier.classify_command ──▶ [OpSpec...]      facts, not decisions
        │
        ▼
policy.decide_ops ──▶ [Verdict...]               ALLOW / RELOCATE / COMPENSATE / BLOCK
        │                     │
        │              any BLOCK? ──▶ refuse, audit, exit 2
        ▼ no
recovery.RecoveryEngine                Compensation Strategy
        │                              ├─ relocate   (fs targets → .agent-trash/<txid>/)
        │                              ├─ snapshot   (git stash create+store, tree untouched)
        │                              └─ clean-enum (git clean -n → relocate matches)
        ▼
audit.append (JSONL, one line per decision)
        │
        ▼
PROCEED with txids ──▶ original command runs
```

Explicit-path tools skip the shell parsing front half:
`safe_delete.py PATH... → classify_paths → decide_path_batch → relocate`.

## The Decision Protocol

The stable cross-harness interface is not allow/block:

```
Effect -> Classifier -> Policy -> Decision  ∈ {ALLOW, RELOCATE, SNAPSHOT,
                                                ASK, BLOCK}
                                 + ReasonCode   (stable, machine-readable)
                                 + Explanation  (human-facing)
                                 + RecoveryPlan (payload: txids, strategy)
```

Adapters map decisions to native mechanisms - DSH `PreToolDecision`,
Claude Code PreToolUse `ask`, or, on harnesses without ask support, a deny
that carries the explanation (never a silent allow). Harness capability
thus never pollutes policy.

Architecture invariant (B1): **the guard analyzes the shell command's
direct effect; it does not infer the internal behavior of arbitrary
programs.** `npm run build && rm -rf dist` is invisible to creation
analysis by design - chasing program-internal effects would degrade the
classifier into a poor shell program analyzer.

Interaction tiers: SAFE (auto-execute, silent) / AMBIGUOUS (ASK_ONCE) /
FORBIDDEN (BLOCK, never askable).

## Key design decisions

1. **Effect-oriented, not dialect-oriented.** The classifier recognizes a
   concrete vocabulary (rm family, find -delete, git clean/reset/restore/
   checkout/push) but classifies by resulting effect on data. Adapters never
   re-implement rules; they call `check.py`, so there is exactly one rule
   engine across every harness.
2. **Enumerate-then-act.** Opaque target sets (globs) are refused at the
   shell layer; the explicit tool expands globs itself first. Opacity is
   converted into explicitness instead of being banned outright.
3. **Two compensation strategies, one interface.** Filesystem deletions
   *relocate* (the file still exists elsewhere); content-overwriting git ops
   *snapshot* (`stash create` without touching the tree). Both produce a
   txid recorded in manifest + audit. Future compensations (database
   backup/PITR, cloud snapshot) plug into the same slot.
4. **Restore is non-destructive.** It refuses to overwrite existing origin
   paths; `--force` is an explicit human decision. A recovery tool that can
   clobber would be a second destruction vector.
5. **Lexical boundaries.** Workspace containment is decided on normalized
   paths; deleting a symlink removes the link, never the target, so symlink
   targets outside the workspace neither leak nor block.
6. **Self-exclusion.** Targets inside `.agent-trash/` are exempted from
   quarantine - housekeeping cannot recurse into itself forever.

## Harness adapter model

Any agent harness integrates through three optional points, in increasing
order of value:

1. **Interception hook** (recommended): before executing a shell command,
   run `check.py --enforce -- <command>`; proceed on exit 0, refuse on
   exit 2. This is the DSH plugin's `tools/pre-execute` listener today.
2. **Agent-facing tools**: expose `safe_delete` / `restore` / `status` as
   model tools so the supported path is also the easiest path.
3. **Prompt section**: inject a short instruction pointing the model at the
   skill and the "prefer safe_delete" rule. Interception without prompting
   causes friction; prompting without interception is advisory only.

## Roadmap

- V1 (this repo): delete-guard skill, fs + git compensations, Linux/macOS.
- V1.x: retention/GC policy for `.agent-trash`; Windows cmd/PowerShell
  dialect support behind the same effect classifier.
- V2: `git-guard` skill (remote ref protection with lease semantics);
  adapter hardening (host-side mode storage, tamper-evident audit).
- V3+: `database-guard` (compensations = transaction / backup /
  point-in-time recovery), `cloud-guard` (snapshot / state capture). The
  Guard answers "may this happen"; the Compensation Engine answers "how do
  we come back" - both extend without restructuring the repository.
