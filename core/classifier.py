"""Effect-oriented classifier for potentially destructive operations.

The classifier turns raw input (a shell command string, or an explicit list
of paths handed to the safe_delete tool) into structured *facts*:

  OpSpec    - one destructive operation found in a command line
  PathSpec  - one deletion target with resolved boundary facts

It deliberately does NOT decide what to do - that is policy.py's job.
Design rules:

* Classify by effect, not dialect. V1 recognises a concrete vocabulary
  (rm/rmdir/unlink/shred, find -delete, git clean/reset/restore/checkout/
  push) because that vocabulary covers the overwhelming majority of real
  agent accidents on Linux/macOS.
* Fail closed. Unbalanced quotes, shell variables, command substitution,
  unknown flags, stdin-fed target lists, indirect shells (bash -c) - all
  become `undeterminable` facts. The policy layer restricts those.
* Lexical boundary analysis. Workspace containment is decided on the
  lexically normalized path (so deleting a symlink that points outside is
  deleting the *link*, not the target, and stays inside the boundary);
  symlink facts are still recorded for audit and for restore.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------- vocabulary

FS_DELETE_CMDS = {"rm", "rmdir", "unlink", "shred"}
SHELL_PREFIXES = {"sudo", "env", "nice", "nohup", "command", "time", "stdbuf", "xargs"}
INTERPRETER_CMDS = {"sh", "bash", "zsh", "ksh", "eval", "source", "."}
SEPARATORS = {";", "&", "&&", "|", "||"}
GLOB_CHARS = ("*", "?", "[")
INDETERMINACY_CHARS = ("$", "`")

# Rough prefilter for "does this opaque string smell destructive at all".
# Only used for indirect execution (bash -c '...'), where the guard cannot
# parse structure and therefore only needs a yes/no smell test.
DESTRUCTIVE_SMELL_RE = re.compile(
    r"(?:^|[\s;&|(=/])(rm|rmdir|unlink|shred)\b|find\s+\S.*-delete|"
    r"git\s+clean\b|git\s+reset\b|mkfs\b",
    re.IGNORECASE,
)

# --------------------------------------------------------------------- types

KIND_OTHER = "other"                    # not destructive (or not recognized)
KIND_FS_DELETE = "fs-delete"            # rm family
KIND_GIT_CLEAN = "git-clean"            # git clean -f...
KIND_GIT_RESET_HARD = "git-reset-hard"  # git reset --hard
KIND_GIT_DISCARD = "git-discard"        # git restore <path> / git checkout -- <path>
KIND_GIT_PUSH_FORCE = "git-push-force"  # force / mirror / ref-deletion push
KIND_UNKNOWN = "unknown"                # destructive smell, no parseable shape

# Whole-command-line shape facts (docs/friction.md F1/F2).
CREATION_CMDS = {"touch", "mkdir", "cp", "mv", "install", "ln", "tee"}
REDIRECT_CREATE_TOKENS = {">", ">>"}
# Kinds whose compensation depends on enumerating concrete targets; a target
# created earlier in the same line is invisible to pre-execution compensation.
TARGET_DEPENDENT_KINDS = {KIND_FS_DELETE, KIND_GIT_CLEAN, KIND_GIT_DISCARD}


@dataclass
class OpSpec:
    """One potentially destructive operation extracted from a command line."""

    op: str                      # program name, e.g. 'rm', 'git'
    kind: str                    # KIND_* constant
    sub: Optional[str] = None    # git subcommand when op == 'git'
    targets: List[str] = field(default_factory=list)   # raw target tokens
    recursive: bool = False
    force: bool = False
    dry_run: bool = False
    extra_flags: List[str] = field(default_factory=list)  # scope letters for git clean
    segment_index: int = 0          # position of this op within the command line
    wildcard: bool = False       # any target contains glob syntax
    undeterminable: bool = False # scope/targets cannot be resolved statically
    notes: List[str] = field(default_factory=list)

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)


@dataclass
class PathSpec:
    """One explicit deletion target with resolved boundary facts."""

    raw: str
    resolved: Optional[str] = None      # lexically normalized absolute path
    wildcard: bool = False
    indeterminable: bool = False        # contains $, `, ( in direct API
    exists: bool = False
    is_symlink: bool = False
    is_dir: bool = False
    is_file: bool = False
    link_target: Optional[str] = None   # realpath when is_symlink
    inside_workspace: bool = False
    inside_trash: bool = False
    protected: Optional[str] = None     # None | workspace-root | outside-workspace | git-metadata
    error: Optional[str] = None

# ------------------------------------------------------------- path analysis


def _has_glob(text: str) -> bool:
    return any(c in text for c in GLOB_CHARS)


def _has_indeterminacy(text: str) -> bool:
    return any(c in text for c in INDETERMINACY_CHARS) or "(" in text


def inside_path(path: str, root: str) -> bool:
    """True when path is root or lies under root (lexical, both absolute)."""
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # pragma: no cover - mixed abs/rel or exotic roots
        return False


def discover_workspace(start_dir: str) -> str:
    """Nearest ancestor (or start itself) containing .git; else start_dir.

    AGENT_GUARD_WORKSPACE overrides discovery entirely - harness adapters
    that already know the workspace should set it.
    """
    env = os.environ.get("AGENT_GUARD_WORKSPACE")
    if env:
        return os.path.normpath(os.path.abspath(env))
    cur = os.path.normpath(os.path.abspath(start_dir))
    while True:
        marker = os.path.join(cur, ".git")
        if os.path.exists(marker):  # dir (normal repo) or file (worktree)
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return os.path.normpath(os.path.abspath(start_dir))
        cur = parent


def classify_paths(
    raw_paths: List[str],
    base_dir: str,
    workspace: str,
    trash_root: Optional[str] = None,
) -> List[PathSpec]:
    """Resolve explicit deletion targets into boundary facts (safe_delete path).

    Boundary checks are lexical: `..` escapes are caught, and a symlink is
    judged by the location of the link itself, never by its target - deleting
    a link does not touch what it points to.
    """
    workspace = os.path.normpath(os.path.abspath(workspace))
    specs: List[PathSpec] = []
    for raw in raw_paths:
        spec = PathSpec(raw=raw)
        text = raw.strip()
        if not text:
            spec.error = "empty path"
            specs.append(spec)
            continue
        spec.wildcard = _has_glob(text)
        if _has_indeterminacy(text):
            spec.indeterminable = True
            spec.error = "variables/substitution are not allowed in the direct path API"
            specs.append(spec)
            continue
        expanded = os.path.expanduser(text)
        absolute = (
            os.path.normpath(os.path.abspath(expanded))
            if os.path.isabs(expanded)
            else os.path.normpath(os.path.abspath(os.path.join(base_dir, expanded)))
        )
        spec.resolved = absolute
        spec.exists = os.path.lexists(absolute)
        spec.is_symlink = os.path.islink(absolute)
        if spec.is_symlink:
            spec.link_target = os.path.realpath(absolute)
        elif os.path.isdir(absolute):
            spec.is_dir = True
        elif os.path.isfile(absolute):
            spec.is_file = True
        spec.inside_workspace = inside_path(absolute, workspace)
        if trash_root:
            spec.inside_trash = inside_path(absolute, os.path.normpath(trash_root))
        if absolute == workspace:
            spec.protected = "workspace-root"
        elif not spec.inside_workspace:
            spec.protected = "outside-workspace"
        else:
            rel = os.path.relpath(absolute, workspace)
            if any(part == ".git" for part in rel.split(os.sep)):
                spec.protected = "git-metadata"
        specs.append(spec)
    return specs

# ----------------------------------------------------------- shell parsing


def _split_segments(tokens: List[str]) -> List[List[str]]:
    segments: List[List[str]] = [[]]
    for tok in tokens:
        if tok in SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(tok)
    out: List[List[str]] = []
    for seg in segments:
        # Subshell/grouping parens attach to adjacent words under shlex
        # ((rm -rf x) tokenizes as ['(rm', '-rf', 'x)']); strip them from
        # segment edges so the dispatcher sees the real command head.
        while seg and seg[0][:1] in ("(", "{"):
            seg[0] = seg[0][1:]
            if not seg[0]:
                seg.pop(0)
        while seg and seg[-1][-1:] in (")", "}"):
            seg[-1] = seg[-1][:-1]
            if not seg[-1]:
                seg.pop()
        if seg:
            out.append(seg)
    return out


def _basename(path: str) -> str:
    return os.path.basename(path)


def _scan_targets(spec: OpSpec) -> None:
    for target in spec.targets:
        if _has_glob(target):
            spec.wildcard = True
        if _has_indeterminacy(target):
            spec.undeterminable = True
            spec.note(f"target '{target}' contains variable/substitution")


def _parse_fs_delete(head: str, segment: List[str], from_xargs: bool) -> OpSpec:
    spec = OpSpec(op=head, kind=KIND_FS_DELETE)
    after_dd = False
    for tok in segment[1:]:
        if not after_dd and tok == "--":
            after_dd = True
            continue
        if not after_dd and tok.startswith("-") and len(tok) > 1:
            if tok.startswith("--"):
                name = tok[2:]
                if name == "recursive":
                    spec.recursive = True
                elif name == "force":
                    spec.force = True
                elif name in ("interactive", "verbose", "one-file-system",
                              "preserve-root", "prompt"):
                    pass  # semantics-neutral for classification
                elif name == "no-preserve-root":
                    spec.note("no-preserve-root requested")
                else:
                    spec.undeterminable = True
                    spec.note(f"unknown flag --{name}")
            else:
                for ch in tok[1:]:
                    if ch in "rR":
                        spec.recursive = True
                    elif ch == "f":
                        spec.force = True
                    elif ch in "vidI":
                        pass
                    else:
                        spec.undeterminable = True
                        spec.note(f"unknown flag -{ch}")
            continue
        spec.targets.append(tok)
    if from_xargs:
        spec.undeterminable = True
        spec.note("target list arrives via stdin (xargs)")
    _scan_targets(spec)
    return spec


def _parse_find(segment: List[str]) -> OpSpec:
    rest = segment[1:]
    spec = OpSpec(op="find", kind=KIND_OTHER, targets=rest[:1])
    for i, tok in enumerate(rest):
        if tok == "-delete":
            spec.kind = KIND_FS_DELETE
            spec.recursive = True
            spec.undeterminable = True
            spec.note("find -delete: matched set depends on predicates")
            break
        if tok in ("-exec", "-execdir"):
            nxt = rest[i + 1] if i + 1 < len(rest) else ""
            if _basename(nxt) in {"rm", "sh", "bash", "xargs"}:
                spec.kind = KIND_FS_DELETE
                spec.recursive = True
                spec.undeterminable = True
                spec.note("find -exec rm: matched set depends on predicates")
                break
    return spec


def _parse_git(segment: List[str]) -> OpSpec:
    tokens = segment[1:]
    sub = tokens[0] if tokens else ""
    rest = tokens[1:]
    spec = OpSpec(op="git", kind=KIND_OTHER, sub=sub)

    if sub == "clean":
        spec.kind = KIND_GIT_CLEAN
        dry = False
        force = False
        after_dd = False
        idx = 0
        while idx < len(rest):
            tok = rest[idx]
            idx += 1
            if not after_dd and tok == "--":
                after_dd = True
                continue
            if not after_dd and tok.startswith("--"):
                name = tok[2:].split("=")[0]
                if name == "force":
                    force = True
                elif name == "dry-run":
                    dry = True
                elif name == "directory":
                    spec.extra_flags.append("-d")
                elif name == "ignored":
                    spec.extra_flags.append("-x")
                elif name == "quiet":
                    pass
                elif name == "exclude":
                    idx += 1  # --exclude <pattern> consumes an argument
                else:
                    spec.undeterminable = True
                    spec.note(f"unknown git clean flag --{name}")
                continue
            if not after_dd and tok.startswith("-") and len(tok) > 1:
                for ch in tok[1:]:
                    if ch == "n":
                        dry = True
                    elif ch == "f":
                        force = True
                    elif ch == "d":
                        spec.extra_flags.append("-d")
                    elif ch == "x":
                        spec.extra_flags.append("-x")
                    elif ch == "X":
                        spec.extra_flags.append("-X")
                    elif ch in ("i", "q", "e"):
                        pass
                    else:
                        spec.undeterminable = True
                        spec.note(f"unknown git clean flag -{ch}")
                continue
            spec.targets.append(tok)
        spec.dry_run = dry
        spec.force = force and not dry
        if not spec.targets and not spec.force and not dry:
            spec.dry_run = True  # git clean without -f is a dry run anyway
        _scan_targets(spec)
        return spec

    if sub == "reset":
        if "--hard" in rest:
            spec.kind = KIND_GIT_RESET_HARD
            spec.force = True
            spec.targets = [
                t for t in rest if t != "--hard" and not t.startswith("-")
            ]
            if not spec.targets:
                spec.note("whole-tree reset (no path limit)")
        return spec

    if sub == "restore":
        staged_only = ("--staged" in rest or "-S" in rest) and (
            "--worktree" not in rest and "-W" not in rest
        )
        if staged_only:
            spec.note("staged-only restore does not touch working tree files")
            return spec  # kind stays OTHER
        if "-p" in rest or "--patch" in rest:
            spec.kind = KIND_GIT_DISCARD
            spec.undeterminable = True
            spec.note("interactive patch selection")
            return spec
        spec.kind = KIND_GIT_DISCARD
        spec.targets = [t for t in rest if not t.startswith("-") or t == "--"]
        spec.targets = [t for t in spec.targets if t != "--"]
        _scan_targets(spec)
        return spec

    if sub == "checkout":
        if "--" in rest:
            spec.kind = KIND_GIT_DISCARD
            spec.targets = rest[rest.index("--") + 1:]
            _scan_targets(spec)
        elif "-p" in rest or "--patch" in rest:
            spec.kind = KIND_GIT_DISCARD
            spec.undeterminable = True
            spec.note("interactive patch selection")
        return spec

    if sub == "push":
        destructive: List[str] = []
        for tok in rest:
            if not tok.startswith("-"):
                if tok.startswith(":"):
                    destructive.append(f"ref-deletion {tok}")
                elif tok.startswith("+"):
                    destructive.append(f"force-refspec {tok}")
            elif tok in ("--force", "-f", "--mirror", "--delete", "-d"):
                destructive.append(tok)
            elif tok.startswith("--force-with-lease"):
                destructive.append("--force-with-lease")
        if destructive:
            spec.kind = KIND_GIT_PUSH_FORCE
            spec.force = True
            spec.note("remote mutation: " + ", ".join(destructive[:4]))
        return spec

    return spec  # other git subcommands are out of V1 scope


HEREDOC_OP_RE = re.compile(r"<<-?\s*([\"']?)([A-Za-z_][A-Za-z0-9_-]*)\1")


def strip_heredocs(cmd: str) -> str:
    """Remove heredoc bodies before classification (F5).

    A redirection like cat-over-heredoc writes a FILE; its body is payload
    text, not executable syntax. Scanning it produced false positives on
    documentation and scripts containing destructive-looking strings.
    The operator token itself is kept so upstream structure is preserved.
    """
    out = cmd
    while True:
        m = HEREDOC_OP_RE.search(out)
        if not m:
            return out
        tag = m.group(2)
        start = m.end()
        nl = out.find("\n", start)
        if nl == -1:
            return out[:start]
        terminator = re.compile(r"^\s*" + re.escape(tag) + r"\s*$",
                                re.MULTILINE)
        end_m = terminator.search(out, nl + 1)
        if not end_m:
            return out[:nl + 1]
        out = out[:start] + " " + out[nl + 1 + end_m.end():]


def _has_create_redirect(segment: List[str]) -> bool:
    return any(tok in REDIRECT_CREATE_TOKENS for tok in segment)


def _apply_shape_rules(specs: List[OpSpec], cd_positions: List[int],
                       creation_positions: List[int]) -> None:
    """Whole-command-line restrictions (docs/friction.md F1/F2).

    F1: a destructive op preceded by cd resolves against the wrong working
        directory - compensation would enumerate/snapshot the wrong tree.
        Applies to every destructive kind.
    F2: a target created earlier in the same line does not exist yet at
        interception time, so target-dependent compensation cannot cover it.
        Position-independent compensations (reset --hard whole-tree stash,
        force-push which is blocked anyway) are exempt.
    Both surface through the existing fail-closed path: undeterminable ->
    BLOCK_UNDETERMINABLE with the reason attached.
    """
    for spec in specs:
        if spec.kind in (KIND_OTHER, KIND_UNKNOWN):
            continue
        idx = spec.segment_index
        if any(pos < idx for pos in cd_positions):
            spec.undeterminable = True
            spec.note(
                "F1: destructive operation follows 'cd' within the same "
                "command line; targets cannot be resolved against the "
                "declared working directory - split into separate commands")
        if spec.kind in TARGET_DEPENDENT_KINDS and any(
                pos < idx for pos in creation_positions):
            spec.undeterminable = True
            spec.note(
                "F2: this command line creates files before destroying "
                "them; pre-execution compensation cannot see targets that "
                "do not exist yet - split into separate commands")


def classify_command(cmd: str) -> Tuple[List[OpSpec], Optional[str]]:
    """Parse one shell command line into destructive OpSpecs.

    Heredoc bodies are stripped before parsing (they are written payload,
    not commands - see docs/friction.md F5).

    Returns (specs, parse_error). Segments that are not destructive are
    returned as kind=OTHER and ignored by policy. A parse_error (unbalanced
    quoting) yields one undeterminable UNKNOWN spec - fail closed.
    """
    try:
        tokens = shlex.split(strip_heredocs(cmd), posix=True)
    except ValueError as exc:
        fallback = OpSpec(op="<unparseable>", kind=KIND_UNKNOWN, undeterminable=True)
        fallback.note(f"shell parse error: {exc}")
        return [fallback], str(exc)
    if not tokens:
        return [], None

    specs: List[OpSpec] = []
    cd_positions: List[int] = []
    creation_positions: List[int] = []

    def emit(spec: OpSpec, index: int) -> None:
        spec.segment_index = index
        specs.append(spec)

    for index, segment in enumerate(_split_segments(tokens)):
        seg = segment
        from_xargs = False
        while seg and _basename(seg[0]) in SHELL_PREFIXES:
            if _basename(seg[0]) == "xargs":
                from_xargs = True
            seg = seg[1:]
        if not seg:
            continue
        head = _basename(seg[0])

        if head == "cd":
            cd_positions.append(index)
        elif head in CREATION_CMDS or _has_create_redirect(seg):
            creation_positions.append(index)

        if head in INTERPRETER_CMDS:
            inner = " ".join(seg[1:])
            if DESTRUCTIVE_SMELL_RE.search(inner):
                spec = OpSpec(op=head, kind=KIND_UNKNOWN, undeterminable=True,
                              targets=[inner[:200]])
                spec.note("indirect shell execution with destructive smell")
                emit(spec, index)
            continue

        if head in FS_DELETE_CMDS:
            emit(_parse_fs_delete(head, seg, from_xargs), index)
        elif head == "find":
            emit(_parse_find(seg), index)
        elif head == "git":
            emit(_parse_git(seg), index)
        # anything else: kind OTHER, intentionally ignored by policy

    _apply_shape_rules(specs, cd_positions, creation_positions)
    return [s for s in specs if s.kind != KIND_OTHER], None
