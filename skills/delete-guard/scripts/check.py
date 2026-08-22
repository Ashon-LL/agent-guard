#!/usr/bin/env python3
"""check - classify a shell command before it runs (harness adapter entry).

    check.py [--cwd DIR] [--enforce] [--json] -- COMMAND...

Advisory mode (default): prints the verdict, touches nothing.
--enforce: performs the compensations first (relocate targets / git snapshot
/ git-clean enumeration+relocation) and tells the caller to PROCEED, or
refuses with BLOCKED. Any BLOCK in the line means nothing is executed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import _bootstrap  # noqa: F401

from core import AUDIT_NAME, TRASH_DIRNAME
from core import audit, classifier, policy, recovery


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cwd")
    ap.add_argument("--enforce", action="store_true")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    cmd_tokens = [t for t in args.command if t != "--"]
    cmd = " ".join(cmd_tokens)

    base = os.path.abspath(args.cwd) if args.cwd else os.getcwd()
    workspace = classifier.discover_workspace(base)
    trash_root = os.environ.get(
        "AGENT_GUARD_TRASH", os.path.join(workspace, TRASH_DIRNAME))
    mode = policy.load_mode(trash_root)["mode"]
    ctx = policy.PolicyContext(
        workspace=workspace, trash_root=trash_root, base_dir=base, mode=mode)
    engine = recovery.RecoveryEngine(workspace, trash_root)
    audit_path = os.path.join(trash_root, AUDIT_NAME)

    specs, parse_error = classifier.classify_command(cmd)
    verdicts = policy.decide_ops(specs, ctx) if not parse_error else [
        policy.Verdict(policy.ACTION_BLOCK, policy.CODE_BLOCK_UNDETERMINABLE,
                       [f"parse error: {parse_error}"])]
    top = policy.worst(verdicts)

    out = {
        "command": cmd,
        "mode": mode,
        "action": top.action,
        "code": top.code,
        "reasons": top.reasons,
        "ops": [{"op": s.op, "kind": s.kind,
                 "undeterminable": s.undeterminable, "notes": s.notes}
                for s in specs],
        "enforced": bool(args.enforce),
    }

    def finish(code):
        out["exit"] = code
        if args.as_json:
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            summary = f"{out['action']} [{out['code']}] {cmd[:120]}"
            print(summary)
            for reason in out["reasons"][:4]:
                print(f"  - {reason}")
        return code

    if not args.enforce:
        audit.append({"event": "check", "action": top.action,
                      "code": top.code, "command": cmd[:500]},
                     audit_path)
        return finish(0)

    if top.blocked:
        audit.append({"event": "enforce-block", "code": top.code,
                      "command": cmd[:500], "reasons": top.reasons},
                     audit_path)
        return finish(2)

    # Execute compensations in order; collect evidence of recoverability.
    compensations = []
    try:
        for spec, verdict in zip(specs, verdicts):
            if spec.kind == classifier.KIND_FS_DELETE and \
                    verdict.action == policy.ACTION_RELOCATE:
                target_specs = classifier.classify_paths(
                    spec.targets, base, workspace, trash_root)
                report = engine.relocate(target_specs, meta={
                    "tool": "check --enforce", "command": cmd[:300]})
                compensations.append({"strategy": "relocate",
                                      "txid": report["txid"],
                                      "moved": len(report["moved"])})
            elif verdict.code == policy.CODE_COMPENSATE_CLEAN_ENUMERATE:
                flags = getattr(spec, "extra_flags", [])
                paths, err = engine.enumerate_git_clean(base, flags)
                if err and not paths:
                    out["warnings"] = [f"git clean enumeration: {err}"]
                target_specs = classifier.classify_paths(
                    paths, base, workspace, trash_root)
                report = engine.relocate(target_specs, meta={
                    "tool": "check --enforce", "strategy": "clean-enumerate",
                    "command": cmd[:300]})
                compensations.append({"strategy": "clean-enumerate",
                                      "txid": report["txid"],
                                      "moved": len(report["moved"])})
            elif verdict.code == policy.CODE_COMPENSATE_SNAPSHOT:
                snap = engine.snapshot_git(cwd=base, meta={
                    "tool": "check --enforce", "command": cmd[:300]})
                compensations.append({"strategy": "snapshot",
                                      "txid": snap["txid"],
                                      "sha": snap["sha"]})
    except Exception as exc:  # compensation failed: refuse to proceed
        out["action"], out["code"] = "BLOCKED", "COMPENSATION_FAILED"
        out["reasons"] = [f"compensation error: {exc}"]
        audit.append({"event": "enforce-error", "command": cmd[:500],
                      "error": str(exc)}, audit_path)
        return finish(2)

    out["compensations"] = compensations
    out["action"] = "PROCEED"
    audit.append({"event": "enforce-proceed", "command": cmd[:500],
                  "compensations": compensations}, audit_path)
    return finish(0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"agent-guard internal error: {exc}", file=sys.stderr)
        sys.exit(1)
