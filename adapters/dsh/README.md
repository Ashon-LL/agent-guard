# agent-guard adapter for DeepSeek Harness

Official DSH integration, shipped as a first-class `dsh-plugin` bundle.
The decision rules are NOT implemented here - this adapter translates the
Decision Protocol onto DSH's native mechanisms and delegates every verdict
to the shared Python core (`skills/delete-guard/scripts/check.py`) that
ships inside this very package.

## Install

```bash
dsh plugin --profile <your-profile> add github:mokuyoaxis/agent-guard
```

## What gets registered

| Contribution | Mechanism | Behavior |
|---|---|---|
| Interception | `tools/pre-execute` waterfall | destructive-looking bash runs through `check.py --enforce` first; ALLOW proceeds (compensation applied), ASK escalates once to the human, BLOCK denies with explanation and remediation |
| `agent_guard_safe_delete` | model tool | recoverable delete with explicit glob expansion and manifest |
| `agent_guard_restore` | model tool | list / restore quarantine transactions |
| `agent_guard_status` | model tool | mode, usage, retention view, recent decisions |
| Prompt section | system prompt (order 105) | deletion discipline for the model |

## Configuration (cordis.patch.yml row)

| Key | Default | Meaning |
|---|---|---|
| `repoRoot` | `""` (this package) | absolute path to a live agent-guard checkout for development |
| `defaultCwd` | executor default | working directory for guard invocations |
| `promptSection` | `true` | register the deletion-discipline section |
| `sectionOrder` | `105` | system-prompt section order |

## Notes

- The caller's sandbox policy is inherited per-invocation (`exec.agent.session`), so guard subprocesses never gain privileges the calling agent lacks.
- Guard failures fail closed (deny), never open.
- The Python core requires `python3` and `git` on PATH.
