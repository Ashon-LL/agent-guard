"""Auditability pillar: append-only JSONL evidence log.

Every decision the guard makes - allow, relocate, compensate, block - is
appended as one JSON object per line. The log is intentionally dumb: no
rotation, no aggregation, no mutation. Post-hoc verification reads it
sequentially. A torn or corrupt line is skipped on read, never rewritten.
"""
from __future__ import annotations

import getpass
import json
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

_APPEND_LOCK = threading.Lock()


def utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_txid() -> str:
    """Compensation transaction id: sortable timestamp + random suffix."""
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + uuid.uuid4().hex[:8]


def session_id() -> str:
    """Best-effort identity of the acting session.

    An agent harness may identify itself through AGENT_GUARD_SESSION.
    This is correlation metadata, not authentication.
    """
    env = os.environ.get("AGENT_GUARD_SESSION")
    if env:
        return env
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover - exotic passwd setups
        user = "unknown"
    return f"{user}@{os.uname().nodename}:{os.getpid()}"


def append(record: Dict[str, Any], audit_path: str) -> Dict[str, Any]:
    """Append one record; returns the stored record (with defaults filled)."""
    stored = dict(record)
    stored.setdefault("ts", utc_now_iso())
    stored.setdefault("session", session_id())
    line = json.dumps(stored, ensure_ascii=False, sort_keys=True)
    directory = os.path.dirname(audit_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with _APPEND_LOCK:
        with open(audit_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    return stored


def tail(audit_path: str, n: int = 20) -> List[Dict[str, Any]]:
    """Read the last n valid records. Corrupt/torn lines are skipped."""
    if not os.path.exists(audit_path):
        return []
    records: List[Dict[str, Any]] = []
    with open(audit_path, "r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
    return records[-max(n, 0):]


def find_by_txid(audit_path: str, txid: str) -> List[Dict[str, Any]]:
    """All audit records belonging to one compensation transaction."""
    return [r for r in tail(audit_path, n=100_000) if r.get("txid") == txid]
