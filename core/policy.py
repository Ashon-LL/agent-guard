"""Scope + Authorization pillars: turn classified facts into verdicts.

policy.py is pure decision logic - no filesystem mutation, no side effects.
Given OpSpecs/PathSpecs and a PolicyContext it returns Verdicts:

  ALLOW       proceed unchanged            (noop / provably regenerable / trash GC)
  RELOCATE    compensate first, then act   (move targets into quarantine)
  COMPENSATE  compensate first, then act   (git snapshot / clean enumeration)
  BLOCK       refuse                       (protected, out of bounds, uncertain)

Authorization model (session-scope V1):

  NORMAL ──user veto / high-risk event──> RESTRICTED
  RESTRICTED ──human explicit action only──> NORMAL

The agent can *request* promotion but never perform it: promotion requires
an interactive TTY. Harness adapters should keep the authoritative mode in
host memory where the agent's shell cannot reach it; the on-disk state file
is the portable fallback and is advisory by construction (see
docs/threat-model.md).

Guiding rule throughout: uncertainty increases restriction.
"""
from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import STATE_NAME, TRASH_DIRNAME
from .classifier import (
    KIND_FS_DELETE,
    KIND_GIT_CLEAN,
    KIND_GIT_DISCARD,
    KIND_GIT_PUSH_FORCE,
    KIND_GIT_RESET_HARD,
    KIND_UNKNOWN,
    PathSpec,
    OpSpec,
    classify_paths,
)

# ------------------------------------------------------------------ verdicts

ACTION_ALLOW = "ALLOW"
ACTION_RELOCATE = "RELOCATE"
ACTION_COMPENSATE = "COMPENSATE"
ACTION_BLOCK = "BLOCK"

# Stable machine-readable codes (adapters must not invent their own).
CODE_ALLOW_NOOP = "ALLOW_NOOP"
CODE_ALLOW_REGENERABLE = "ALLOW_REGENERABLE"
CODE_ALLOW_TRASH_GC = "ALLOW_TRASH_GC"
CODE_RELOCATE_PATHS = "RELOCATE_PATHS"
CODE_RELOCATE_TREE = "RELOCATE_TREE"
CODE_RELOCATE_NARROW = "RELOCATE_NARROW"
CODE_COMPENSATE_CLEAN_ENUMERATE = "COMPENSATE_CLEAN_ENUMERATE"
CODE_COMPENSATE_SNAPSHOT = "COMPENSATE_SNAPSHOT"
CODE_BLOCK_UNDETERMINABLE = "BLOCK_UNDETERMINABLE"
CODE_BLOCK_OUT_OF_WORKSPACE = "BLOCK_OUT_OF_WORKSPACE"
CODE_BLOCK_PROTECTED_PATH = "BLOCK_PROTECTED_PATH"
CODE_BLOCK_WILDCARD = "BLOCK_WILDCARD"
CODE_BLOCK_RESTRICTED_MODE = "BLOCK_RESTRICTED_MODE"
CODE_BLOCK_FORCE_PUSH = "BLOCK_FORCE_PUSH"


@dataclass
class Verdict:
    action: str                      # ACTION_* constant
    code: str                        # CODE_* constant
    reasons: List[str] = field(default_factory=list)
    payload: Dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.action == ACTION_BLOCK


# --------------------------------------------------------------------- modes

MODE_NORMAL = "NORMAL"
MODE_RESTRICTED = "RESTRICTED"


class AuthorizationRequired(RuntimeError):
    """Raised when a mode change requires a human and none is present."""


def state_path(trash_root: str) -> str:
    return os.path.join(trash_root, STATE_NAME)


def load_mode(trash_root: str) -> Dict[str, Any]:
    """Read authorization state; corrupt/missing state falls back to NORMAL."""
    path = state_path(trash_root)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        mode = data.get("mode")
        if mode in (MODE_NORMAL, MODE_RESTRICTED):
            return {
                "mode": mode,
                "since": data.get("since"),
                "set_by": data.get("set_by"),
                "degraded": False,
            }
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    return {"mode": MODE_NORMAL, "since": None, "set_by": None, "degraded": False}


def _save_mode(trash_root: str, mode: str, actor: str) -> Dict[str, Any]:
    os.makedirs(trash_root, exist_ok=True)
    state = {"mode": mode, "since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "set_by": actor}
    tmp = state_path(trash_root) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, state_path(trash_root))
    return state


def request_mode(trash_root: str, new_mode: str, actor: str = "unknown") -> Dict[str, Any]:
    """Change authorization mode, enforcing the one-way downgrade rule.

    Downgrade (NORMAL -> RESTRICTED) is always allowed - restriction is safe.
    Promotion (RESTRICTED -> NORMAL) demands an interactive human terminal;
    agents running non-interactively can never satisfy it. This is defense in
    depth for the portable CLI; harness adapters enforce the same rule with
    host-side state that agent shells cannot touch at all.
    """
    current = load_mode(trash_root)
    if new_mode == current["mode"]:
        return current
    if new_mode == MODE_RESTRICTED:
        return _save_mode(trash_root, MODE_RESTRICTED, actor)
    if new_mode == MODE_NORMAL:
        if not sys.stdin.isatty():
            raise AuthorizationRequired(
                "RESTRICTED -> NORMAL requires an interactive human terminal; "
                "the agent cannot promote itself."
            )
        return _save_mode(trash_root, MODE_NORMAL, actor)
    raise ValueError(f"unknown mode: {new_mode}")

# -------------------------------------------------------------------- config

DEFAULT_ARTIFACT_PATTERNS = [
    "node_modules", "dist", "build", "out", "target", "__pycache__",
    ".cache", "coverage", ".next", ".nuxt", ".venv", "venv",
    ".pytest_cache", ".mypy_cache", ".tox", ".turbo", ".parcel-cache",
    "*.pyc", "*.pyo", "*.egg-info",
]


@dataclass
class GuardConfig:
    artifact_patterns: List[str] = field(
        default_factory=lambda: list(DEFAULT_ARTIFACT_PATTERNS))
    allow_regenerable: bool = True

    @classmethod
    def from_env(cls) -> "GuardConfig":
        cfg = cls()
        extra = os.environ.get("AGENT_GUARD_ARTIFACTS")
        if extra:
            cfg.artifact_patterns.extend(
                p for p in extra.split(os.pathsep) if p)
        if os.environ.get("AGENT_GUARD_ALLOW_REGENERABLE", "").strip() in (
                "0", "false", "no"):
            cfg.allow_regenerable = False
        return cfg


@dataclass
class PolicyContext:
    workspace: str                    # absolute workspace root (boundary)
    trash_root: str                   # absolute quarantine root
    base_dir: str                     # cwd the command runs in
    mode: str = MODE_NORMAL
    config: GuardConfig = field(default_factory=GuardConfig.from_env)

# ------------------------------------------------------------- regenerability


def _matches_artifact(rel: str, patterns: List[str]) -> bool:
    parts = rel.split(os.sep)
    for pat in patterns:
        if any(fnmatch.fnmatch(part, pat) for part in parts):
            return True
        if fnmatch.fnmatch(rel, pat):
            return True
    return False


def is_git_ignored(workspace: str, path: str) -> bool:
    """True when git itself ignores path (exit 0 from check-ignore -q).

    Outside a git work tree git returns 128/129 - treated as NOT ignored
    (uncertainty increases restriction).
    """
    try:
        proc = subprocess.run(
            ["git", "-C", workspace, "check-ignore", "-q", "--", path],
            capture_output=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def regenerable(specs: List[PathSpec], ctx: PolicyContext) -> bool:
    """Provably regenerable = git-ignored AND matches artifact patterns."""
    if not ctx.config.allow_regenerable:
        return False
    for spec in specs:
        if not spec.resolved or not spec.exists:
            return False
        rel = os.path.relpath(spec.resolved, ctx.workspace)
        if not _matches_artifact(rel, ctx.config.artifact_patterns):
            return False
        if not is_git_ignored(ctx.workspace, spec.resolved):
            return False
    return True

# ------------------------------------------------------------------ decisions


def _block_undeterminable(spec: OpSpec) -> Verdict:
    return Verdict(
        action=ACTION_BLOCK,
        code=CODE_BLOCK_UNDETERMINABLE,
        reasons=["scope or targets cannot be resolved statically"] + spec.notes,
    )


def decide_path_batch(specs: List[PathSpec], ctx: PolicyContext,
                      recursive: bool) -> Verdict:
    """One batch of concrete deletion targets through the rule table."""
    reasons: List[str] = []

    errored = [s for s in specs if s.error or s.indeterminable]
    if errored:
        reasons.extend(s.error or "indeterminable target" for s in errored)
        return Verdict(ACTION_BLOCK, CODE_BLOCK_UNDETERMINABLE, reasons)

    if specs and all(s.inside_trash for s in specs):
        return Verdict(ACTION_ALLOW, CODE_ALLOW_TRASH_GC,
                       ["targets live inside the quarantine; GC is permitted"])

    protected_outside = [s for s in specs if s.protected == "outside-workspace"]
    if protected_outside:
        return Verdict(ACTION_BLOCK, CODE_BLOCK_OUT_OF_WORKSPACE,
                       [f"outside workspace boundary: {s.raw}" for s in protected_outside[:5]])

    protected_other = [s for s in specs
                       if s.protected in ("workspace-root", "git-metadata")]
    if protected_other:
        return Verdict(ACTION_BLOCK, CODE_BLOCK_PROTECTED_PATH,
                       [f"protected: {s.protected} ({s.raw})" for s in protected_other[:5]])

    wild = [s for s in specs if s.wildcard]
    if wild:
        return Verdict(ACTION_BLOCK, CODE_BLOCK_WILDCARD,
                       ["glob targets are opaque; enumerate explicitly "
                        "(safe_delete expands globs itself)"])

    missing = [s for s in specs if not s.exists]
    if len(missing) == len(specs):
        return Verdict(ACTION_ALLOW, CODE_ALLOW_NOOP, ["nothing to delete"])

    # ---- Authorization gate: RESTRICTED allows narrow single-file deletes only
    if ctx.mode == MODE_RESTRICTED:
        narrow_ok = all((s.is_file or s.is_symlink) for s in specs)
        if narrow_ok:
            return Verdict(ACTION_RELOCATE, CODE_RELOCATE_NARROW,
                           ["restricted mode: named files only, quarantined"])
        return Verdict(
            ACTION_BLOCK, CODE_BLOCK_RESTRICTED_MODE,
            ["restricted mode permits only explicit single-file deletes "
             "inside the workspace"],
        )

    # ---- NORMAL mode
    if recursive and regenerable(specs, ctx):
        return Verdict(ACTION_ALLOW, CODE_ALLOW_REGENERABLE,
                       ["all targets are git-ignored and match known "
                        "artifact patterns"])
    if recursive:
        dirs = [s.raw for s in specs if s.is_dir]
        if dirs:
            return Verdict(ACTION_RELOCATE, CODE_RELOCATE_TREE,
                           ["rooted recursive delete relocated whole"])
        return Verdict(ACTION_RELOCATE, CODE_RELOCATE_PATHS,
                       ["named targets relocated"])
    return Verdict(ACTION_RELOCATE, CODE_RELOCATE_PATHS,
                   ["named targets relocated"])


def decide_op(spec: OpSpec, ctx: PolicyContext) -> Optional[Verdict]:
    """Map one classified operation to its verdict. None => not destructive."""
    if spec.kind == KIND_UNKNOWN:
        return _block_undeterminable(spec)

    # Authorization gate first: in RESTRICTED mode every non-filesystem
    # destructive family is disabled outright. Narrow single-file fs deletes
    # are still judged inside decide_path_batch below.
    if ctx.mode == MODE_RESTRICTED and spec.kind != KIND_FS_DELETE:
        return Verdict(
            ACTION_BLOCK, CODE_BLOCK_RESTRICTED_MODE,
            [f"restricted mode disables {spec.kind} operations"],
        )

    if spec.kind == KIND_FS_DELETE:
        if spec.undeterminable:
            return _block_undeterminable(spec)
        if not spec.targets:
            return Verdict(ACTION_ALLOW, CODE_ALLOW_NOOP, ["no targets"])
        path_specs = classify_paths(
            spec.targets, ctx.base_dir, ctx.workspace, ctx.trash_root)
        return decide_path_batch(path_specs, ctx, recursive=spec.recursive)

    if spec.kind == KIND_GIT_CLEAN:
        if spec.dry_run:
            return Verdict(ACTION_ALLOW, CODE_ALLOW_NOOP, ["git clean dry run"])
        if spec.undeterminable:
            return _block_undeterminable(spec)
        if spec.wildcard:
            return Verdict(ACTION_BLOCK, CODE_BLOCK_WILDCARD,
                           ["git clean path globs are opaque"])
        return Verdict(
            ACTION_COMPENSATE, CODE_COMPENSATE_CLEAN_ENUMERATE,
            ["enumerate via git clean -n, relocate matches, then let the "
             "command run"],
            payload={"paths": spec.targets},
        )

    if spec.kind == KIND_GIT_RESET_HARD:
        return Verdict(
            ACTION_COMPENSATE, CODE_COMPENSATE_SNAPSHOT,
            ["snapshot tracked modifications via git stash create/store "
             "before reset --hard"],
        )

    if spec.kind == KIND_GIT_DISCARD:
        if spec.undeterminable:
            return _block_undeterminable(spec)
        if spec.wildcard:
            return Verdict(ACTION_BLOCK, CODE_BLOCK_WILDCARD,
                           ["discard globs are opaque"])
        return Verdict(
            ACTION_COMPENSATE, CODE_COMPENSATE_SNAPSHOT,
            ["snapshot tracked modifications before discarding working-tree "
             "changes"],
        )

    if spec.kind == KIND_GIT_PUSH_FORCE:
        return Verdict(ACTION_BLOCK, CODE_BLOCK_FORCE_PUSH,
                       list(spec.notes) or ["remote history destruction"])

    return None  # KIND_OTHER / unrecognized: not our business


def decide_ops(specs: List[OpSpec], ctx: PolicyContext) -> List[Verdict]:
    """All verdicts for a command line; empty list means nothing destructive."""
    verdicts = []
    for spec in specs:
        verdict = decide_op(spec, ctx)
        if verdict is not None:
            verdict.payload.setdefault("op", spec.op)
            verdict.payload.setdefault("kind", spec.kind)
            verdicts.append(verdict)
    return verdicts


def worst(verdicts: List[Verdict]) -> Verdict:
    """Aggregate: BLOCK > COMPENSATE > RELOCATE > ALLOW."""
    rank = {ACTION_ALLOW: 0, ACTION_RELOCATE: 1, ACTION_COMPENSATE: 2,
            ACTION_BLOCK: 3}
    if not verdicts:
        return Verdict(ACTION_ALLOW, CODE_ALLOW_NOOP, ["no destructive operation"])
    return max(verdicts, key=lambda v: rank[v.action])
