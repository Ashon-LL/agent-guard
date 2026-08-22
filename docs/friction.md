# Friction log — real-agent validation (DSH adapter, first live session)

The adapter plugin (`tools/pre-execute` interception + three model tools +
prompt section) was pointed at a live coding agent performing real
destructive operations. Findings, in the order they hurt.

## F1 · Compound `cd X && rm y` resolves targets against the wrong base

The interceptor classifies against the tool call's declared workdir. A
command like `cd subdir && rm -rf build` runs `rm` inside `subdir`, but the
guard resolved `build` against the parent — wrong tree entirely.

**Implemented (fail-closed):** classifier shape rule F1 marks such ops
undeterminable → BLOCK_UNDETERMINABLE ("split the command"). Prompt guidance
additionally asks for explicit workdirs / standalone commands.

## F2 · Create-then-delete in one line is a timing blind spot

Observed live: `touch junk_a.tmp junk_b.tmp && mkdir -p empty_dir && git clean -fd`.
Pre-execution interception enumerates *before* the command runs — the junk
files did not exist yet, so compensation could not cover them and git truly
deleted them.

The same event proved the value: an untracked but valuable `keep.txt` lying
in the repo WAS enumerated and relocated before `git clean -fd` could
silently destroy it, then restored via `restore.py <txid>`. The guard saved
exactly the class of file it exists for.

**Implemented (fail-closed):** classifier shape rule F2 flags creation-before-
destruction lines → BLOCK_UNDETERMINABLE. Position-independent compensations
(`reset --hard` whole-tree stash; force-push, blocked anyway) are exempt by
design. Prompt guidance additionally asks for standalone deletion commands.

## F3 · Unmatched globs produced a self-contradicting BLOCK

`safe_delete '*.log'` with no *.log files answered BLOCK_WILDCARD — while its
own docs say safe_delete expands globs itself. **Fixed:** unmatched patterns
are now reported as `no_match` / ALLOW_NOOP instead of reaching the classifier
as opaque wildcards.

## F4 · Harness integration notes (DSH)

For future adapter authors embedding `check.py` in another harness:

1. Always call `shell.run(shell.resolve(request))` — raw specs crash host
   integration.
2. `ShellRunResult.stdout/stderr` are `CollectedOutput` objects; payload is
   `.text`.
3. Resolve the caller's sandbox policy from `exec.agent.session` and pass it
   in the request; otherwise you get the deployment default
   (workspace-write), which fails on hosts without a sandbox backend even
   when the calling session runs unconfined.
4. Dynamic tool registration must go through `harness.defineTool`;
   parameters are property maps (`required` is a per-property annotation);
   object output schemas must declare `additionalProperties`.
5. Per-destructive-command overhead is one python3 startup (~0.3 s); the
   keyword prefilter keeps non-destructive traffic at regex cost only.

## F5 · Heredoc bodies were scanned as command syntax (fixed live)

While writing THIS very file through a shell heredoc, the guard denied the
write twice: the documentation text quotes destructive commands, and the
classifier treated quoted examples as part of the command line. A file-WRITE
was blocked over its textual content. Even deploying the fix required a
maintenance window, because the old classifier denied the patch command too —
the chicken-and-egg is inherent to self-hosting guards.

**Fixed in V1:** `classifier.strip_heredocs()` removes heredoc payloads before
parsing; a regression test pins the behavior
(`test_heredoc_body_is_payload_not_syntax`). Redirection-into-file is write
territory, not delete territory.

## Verdict accuracy observed

| Command | Verdict | Correct? |
|---|---|---|
| `rm -rf build` (rooted dir) | RELOCATE_TREE → PROCEED | ✓ |
| `rm -rf .` | BLOCK_PROTECTED_PATH | ✓ |
| `rm -rf $UNSET/` | BLOCK_UNDETERMINABLE | ✓ |
| `git clean -fd`, pre-existing untracked present | COMPENSATE_CLEAN_ENUMERATE; valuable file relocated | ✓ |
| `git clean -fd`, junk created by same line | proceeded unprotected | ✗ → F2 |
| `safe_delete` mixed glob + file | relocate file, report no-match | ✓ after F3 fix |
| heredoc write quoting destructive text | false BLOCK → fixed by strip_heredocs | ✓ after F5 |
