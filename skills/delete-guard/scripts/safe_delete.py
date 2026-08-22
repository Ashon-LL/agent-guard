#!/usr/bin/env python3
"""safe_delete - the recoverable deletion tool for AI agents.

    safe_delete.py [--json] [--dry-run] [--reason TEXT] PATH...

Globs are expanded here, explicitly, before classification: an opaque
wildcard never reaches the filesystem unexamined. Every verdict is audited.
Blocked requests exit 2 and leave the filesystem untouched.
"""
from __future__ import annotations

import argparse
import glob as globlib
import json
import os
import shutil
import sys

import _bootstrap  # noqa: F401

from core import AUDIT_NAME, TRASH_DIRNAME, audit
from core import classifier, policy, recovery


def expand_globs(patterns):
    """Expand globs explicitly. Returns (concrete_paths, unmatched_patterns).

    A pattern with no matches is NOT passed on as an opaque wildcard - it is
    reported as 'no matches' instead of triggering a misleading BLOCK.
    """
    out = []
    unmatched = []
    for pattern in patterns:
        matches = globlib.glob(os.path.expanduser(pattern), recursive=True)
        if matches:
            out.extend(sorted(matches))
        elif any(c in pattern for c in ("*", "?", "[")):
            unmatched.append(pattern)
        else:
            out.append(pattern)  # literal path: let policy report the miss
    return out, unmatched


def delete_directly(spec):
    """Physically remove one concrete target (regenerable / trash GC only)."""
    path = spec.resolved
    if spec.is_symlink or spec.is_file:
        os.unlink(path)
        return "deleted"
    if spec.is_dir:
        shutil.rmtree(path)
        return "deleted-tree"
    return "absent"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+", help="paths or globs to delete")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--reason", default="", help="why this deletion is needed")
    args = ap.parse_args()

    base = os.getcwd()
    workspace = classifier.discover_workspace(base)
    trash_root = os.environ.get(
        "AGENT_GUARD_TRASH", os.path.join(workspace, TRASH_DIRNAME))
    mode = policy.load_mode(trash_root)["mode"]
    ctx = policy.PolicyContext(
        workspace=workspace, trash_root=trash_root, base_dir=base, mode=mode)

    concrete, unmatched = expand_globs(args.paths)
    specs = classifier.classify_paths(concrete, base, workspace, trash_root)
    if not specs and unmatched:
        result = {
            "tool": "safe_delete",
            "mode": mode,
            "workspace": workspace,
            "verdict": {"action": "ALLOW", "code": "ALLOW_NOOP",
                        "reasons": ["no matches for: " + ", ".join(unmatched)]},
            "targets": list(args.paths),
            "dry_run": args.dry_run,
            "outcome": "nothing to do (no matches)",
            "exit": 0,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.as_json
              else result["outcome"])
        return 0
    verdict = policy.decide_path_batch(specs, ctx, recursive=True)
    engine = recovery.RecoveryEngine(workspace, trash_root)

    result = {
        "tool": "safe_delete",
        "mode": mode,
        "workspace": workspace,
        "verdict": {"action": verdict.action, "code": verdict.code,
                    "reasons": verdict.reasons},
        "targets": [s.raw for s in specs],
        "no_match": unmatched,
        "dry_run": args.dry_run,
    }

    if verdict.blocked:
        audit.append({"event": "decision", "tool": "safe_delete",
                      "action": "BLOCK", "code": verdict.code,
                      "reasons": verdict.reasons, "targets": result["targets"],
                      "reason": args.reason},
                     os.path.join(trash_root, AUDIT_NAME))
        result["exit"] = 2
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.as_json
              else f"BLOCKED [{verdict.code}]: {verdict.reasons}")
        return 2

    if verdict.code == policy.CODE_ALLOW_NOOP:
        result["outcome"] = "nothing to do"
    elif args.dry_run:
        result["outcome"] = f"would {verdict.action.lower()} ({verdict.code})"
    elif verdict.code == policy.CODE_ALLOW_REGENERABLE:
        deleted = [delete_directly(s) for s in specs]
        result["outcome"] = "deleted directly (provably regenerable)"
        result["deleted"] = deleted
    elif verdict.code == policy.CODE_ALLOW_TRASH_GC:
        deleted = [delete_directly(s) for s in specs]
        result["outcome"] = "deleted directly (quarantine housekeeping)"
        result["deleted"] = deleted
    else:  # RELOCATE_*
        report = engine.relocate(specs, meta={
            "tool": "safe_delete", "code": verdict.code, "reason": args.reason})
        result["outcome"] = "relocated to quarantine"
        result["txid"] = report["txid"]
        result["moved"] = report["moved"]
        result["skipped"] = report["skipped"]

    audit.append({"event": "decision", "tool": "safe_delete",
                  "action": verdict.action, "code": verdict.code,
                  "targets": result["targets"], "txid": result.get("txid"),
                  "reason": args.reason},
                 os.path.join(trash_root, AUDIT_NAME))
    result["exit"] = 0
    if args.as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result["outcome"] + (f" txid={result['txid']}" if result.get("txid") else ""))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # internal error: fail loudly, change nothing
        print(f"agent-guard internal error: {exc}", file=sys.stderr)
        sys.exit(1)
