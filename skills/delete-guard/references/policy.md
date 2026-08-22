# delete-guard policy reference (V1)

Platforms: Linux/macOS shells + git. Windows (cmd/PowerShell) is out of V1.

## Rule table (first match wins)

| # | Condition | Verdict code | Effect |
|---|---|---|---|
| 1 | dry run / no targets | `ALLOW_NOOP` | proceed unchanged |
| 2 | unresolvable targets: shell vars, command substitution, unbalanced quotes, `bash -c` with destructive smell, `find -delete`, `find -exec rm`, stdin-fed (`xargs`) | `BLOCK_UNDETERMINABLE` | refuse |
| 2a | SHAPE F1: destructive op preceded by `cd` in the same command line | `BLOCK_UNDETERMINABLE` | refuse; split into separate commands (compensation would run against the wrong workdir) |
| 2b | SHAPE F2: file-creation op (`touch/mkdir/cp/mv/install/ln/tee`, `>`/`>>`) precedes a target-dependent destructive op in the same line | `BLOCK_UNDETERMINABLE` | refuse; split (targets created later are invisible to pre-execution compensation; `reset --hard`/force-push exempt - position-independent) |
| 3 | any target inside quarantine (`.agent-trash/`) | `ALLOW_TRASH_GC` | direct delete permitted (housekeeping) |
| 4 | target outside workspace | `BLOCK_OUT_OF_WORKSPACE` | refuse |
| 5 | target is workspace root or `.git` (any depth) | `BLOCK_PROTECTED_PATH` | refuse |
| 6 | any glob target | `BLOCK_WILDCARD` | refuse; use safe_delete which enumerates |
| 7 | RESTRICTED mode, git/remote destructive op | `BLOCK_RESTRICTED_MODE` | refuse |
| 8 | RESTRICTED mode, fs delete | narrow files only -> `RELOCATE_NARROW`, else `BLOCK_RESTRICTED_MODE` | refuse or quarantine |
| 9 | force/mirror/ref-deletion push | `BLOCK_FORCE_PUSH` | refuse |
| 10 | `git clean` dry run | `ALLOW_NOOP` | proceed |
| 11 | `git clean -f...` | `COMPENSATE_CLEAN_ENUMERATE` | enumerate via `clean -n`, relocate matches, proceed |
| 12 | `git reset --hard`, `git restore <path>`, `git checkout -- <path>` | `COMPENSATE_SNAPSHOT` | `git stash create`+`store` first, proceed |
| 13 | all targets git-ignored AND match artifact patterns | `ALLOW_REGENERABLE` | direct delete |
| 14 | rooted recursive delete | `RELOCATE_TREE` | quarantine whole tree, proceed |
| 15 | named files/dirs | `RELOCATE_PATHS` | quarantine, proceed |

Precedence inside rule groups: `outside-workspace` > `workspace-root` >
`git-metadata`. RESTRICTED narrows before NORMAL relaxes.

## Verdict actions

- `ALLOW` - run unchanged.
- `RELOCATE` - move targets to quarantine, then run (the run itself then
  finds nothing - effect preserved, loss reversed).
- `COMPENSATE` - apply git compensation (snapshot / enumeration), then run.
- `BLOCK` - refuse; nothing is executed.

## Modes

```
NORMAL ──(human veto / high-risk event)──> RESTRICTED
RESTRICTED ──(interactive human terminal ONLY)──> NORMAL
```

State: `.agent-trash/state.json`. Non-interactive promotion raises
`AuthorizationRequired`. Harness adapters SHOULD keep the authoritative mode
in host memory instead (agent shells cannot touch it) and treat the file as
a portable fallback.

## Configuration (environment)

| Variable | Meaning |
|---|---|
| `AGENT_GUARD_WORKSPACE` | override workspace boundary discovery |
| `AGENT_GUARD_TRASH` | override quarantine location |
| `AGENT_GUARD_SESSION` | session identity recorded in audit/manifest |
| `AGENT_GUARD_ARTIFACTS` | `os.pathsep`-joined extra artifact patterns |
| `AGENT_GUARD_ALLOW_REGENERABLE` | `0` disables direct deletion of artifacts |

Default artifact patterns: `node_modules dist build out target __pycache__
.cache coverage .next .nuxt .venv venv .pytest_cache .mypy_cache .tox
.turbo .parcel-cache *.pyc *.pyo *.egg-info`

## Files

```
.agent-trash/
├── state.json        # authorization mode (portable fallback)
├── manifest.jsonl    # tx-start / relocate / snapshot / restore records
└── audit.jsonl       # every decision: allow, block, compensate
```

Excluded from git via `.git/info/exclude` (the user's `.gitignore` is never
modified). Retention/GC is intentionally manual in V1; `restore.py list` and
`status.py` expose what exists.

## Known limitations (V1)

- Command-level interception covers the recognized vocabulary; arbitrary
  scripts that delete internally are invisible to `check.py` (see
  `docs/threat-model.md`).
- `git stash create` captures tracked modifications; untracked files are not
  affected by `reset --hard`, so they need no snapshot.
- Windows cmd/PowerShell, databases, cloud resources: future skills
  (`git-guard`, `database-guard`, `cloud-guard`) on the same core.
