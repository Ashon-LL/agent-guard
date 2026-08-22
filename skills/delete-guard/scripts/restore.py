#!/usr/bin/env python3
"""restore - undo a guarded deletion transaction.

    restore.py list [--json]
    restore.py TXID [--force] [--json]

Restore is non-destructive by default: it refuses to overwrite anything now
occupying an origin path. --force is an explicit human decision.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import _bootstrap  # noqa: F401

from core import AUDIT_NAME, TRASH_DIRNAME, audit
from core import classifier, policy, recovery


def context():
    base = os.getcwd()
    workspace = classifier.discover_workspace(base)
    trash_root = os.environ.get(
        "AGENT_GUARD_TRASH", os.path.join(workspace, TRASH_DIRNAME))
    return recovery.RecoveryEngine(workspace, trash_root)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    lp = sub.add_parser("list")
    lp.add_argument("--json", action="store_true", dest="as_json")
    rp = sub.add_parser("restore")
    rp.add_argument("txid")
    rp.add_argument("--force", action="store_true")
    rp.add_argument("--json", action="store_true", dest="as_json")
    # Allow the ergonomic form: restore.py <txid> == restore.py restore <txid>
    argv = sys.argv[1:]
    if argv and argv[0] not in ("list", "restore", "-h", "--help"):
        argv = ["restore"] + argv
    args = ap.parse_args(argv)

    engine = context()

    if args.cmd == "list":
        txs = engine.transactions()
        usage = engine.usage()
        listing = [{"txid": t["txid"], "ts": t.get("ts"),
                    "items": len(t["items"]),
                    "strategies": sorted({i.get("type") for i in t["items"]})}
                   for t in txs.values()]
        if args.as_json:
            print(json.dumps({"transactions": listing, "usage": usage},
                             ensure_ascii=False, indent=2))
        else:
            print(f"quarantine: {engine.trash_root}")
            print(f"files={usage['files']} bytes={usage['bytes']} "
                  f"transactions={usage['transactions']}")
            for item in listing[-20:]:
                print(f"  {item['txid']}  {item['items']:>3} items  "
                      f"{','.join(item['strategies'])}")
        return 0

    report = engine.restore(args.txid, force=args.force)
    workspace = engine.workspace
    audit.append({"event": "restore", "txid": args.txid, "force": args.force,
                  "ok": report.get("ok"), "restored": report.get("restored"),
                  "conflicts": report.get("conflicts"),
                  "errors": report.get("errors")},
                 os.path.join(engine.trash_root, AUDIT_NAME))
    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for path in report.get("restored", []):
            print(f"restored: {path}")
        for path in report.get("conflicts", []):
            print(f"conflict (exists; use --force): {path}")
        for err in report.get("errors", []):
            print(f"error: {err}", file=sys.stderr)
    if report.get("errors"):
        return 1
    if report.get("conflicts"):
        return 3
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"agent-guard internal error: {exc}", file=sys.stderr)
        sys.exit(1)
