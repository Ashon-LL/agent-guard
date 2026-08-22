# agent-guard threat model

## Honest positioning

agent-guard assumes the agent runs with the **same OS privileges as the
guard**. Under that assumption a *determined* adversary can always find a
bypass. Therefore:

- agent-guard is **reliability infrastructure**, not a security boundary.
  It defends against *mistakes*: misjudged context, mis-expanded commands,
  wrong working directory, hallucinated paths - which is what essentially
  all real-world "agent deleted my data" incidents are.
- You may claim: default-recoverable deletions, full decision audit, graded
  authorization, reduced blast radius of common accidents.
- You must NOT claim: sandboxing, containment of malicious agents,
  prevention of determined bypass.

## Assets

1. User data inside the workspace (tracked, untracked, ignored).
2. Everything outside the workspace boundary.
3. Git history (local refs, remote refs).

## Vectors and mitigations

| # | Vector | Mitigation | Residual risk |
|---|---|---|---|
| 1 | Agent deletes via unrecognized channel: its own script calling `unlink()`, `python -c`, `node -e` | Out of scope for command classification; prompt layer forbids circumvention; audit records what was seen | Real. Upgrade path: kernel-side enforcement (fanotify/eBPF/sandbox) or intercepting the FS service rather than the shell |
| 2 | Agent tampers with `.agent-trash/state.json` to self-promote mode | Portable file is advisory by design; harness adapters SHOULD hold the authoritative mode in host memory the agent's shell cannot reach | Accepted for pure-CLI usage; documented |
| 3 | Agent allocates a PTY to pass the `isatty()` human check | Documented heuristic; adapters enforce promotion out-of-band (human-only UI/command) | Heuristic, not cryptographic |
| 4 | Agent edits/removes `manifest.jsonl` to hide provenance | Append-only by convention; audit log is separate; adapters may ship both off-box | Tamper-evident only if exported |
| 5 | Symlink confusion (delete link vs target, trailing slash dereference) | Lexical boundary analysis; link relocation preserves the link; realpath recorded | Low |
| 6 | TOCTOU between classification and execution | Window is milliseconds inside one process; adapters that need more should classify-and-execute atomically | Small, acknowledged |
| 7 | Destructive restore | Restore refuses overwrites without explicit human `--force`; all restores audited | Low |
| 8 | Quarantine bloat turns `.agent-trash` into a liability (exfil via packaging, disk exhaustion) | Excluded via `.git/info/exclude`; `status.py` exposes size; GC is manual in V1 | Retention policy planned (V1.x) |

## What would upgrade this to a security boundary

Real containment requires enforcement below the agent's privilege level:
seccomp/Landlock/AppArmor profiles, containers/VMs, or a filesystem service
the agent can only reach through mediation. In such a world agent-guard's
rule engine remains useful as the *policy authoring* layer - the four
pillars and compensation model do not change; the enforcement point moves
into the kernel.
