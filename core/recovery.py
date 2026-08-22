"""Recoverability pillar: the Compensation Engine.

Two compensation strategies, chosen by the caller (policy decides which):

  relocate     - move targets into the quarantine tree, preserving their
                 workspace-relative structure under one transaction id
  snapshot_git - capture tracked modifications as a stash commit WITHOUT
                 changing the working tree (git stash create + store), so a
                 subsequent reset --hard / restore stays reversible

Everything lands in an append-only manifest (JSONL). Restore is itself
non-destructive: it refuses to overwrite anything that now exists at the
origin path unless the human passes force explicitly.

The quarantine directory is excluded from git via .git/info/exclude - never
by touching the user's .gitignore.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import errno
from typing import Any, Dict, List, Optional, Tuple

from . import MANIFEST_NAME, TRASH_DIRNAME
from .audit import new_txid, utc_now_iso
from .classifier import PathSpec


class RecoveryEngine:
    def __init__(self, workspace: str, trash_root: Optional[str] = None):
        self.workspace = os.path.normpath(os.path.abspath(workspace))
        self.trash_root = os.path.normpath(os.path.abspath(
            trash_root or os.path.join(self.workspace, TRASH_DIRNAME)))

    # ------------------------------------------------------------- layout

    @property
    def manifest_path(self) -> str:
        return os.path.join(self.trash_root, MANIFEST_NAME)

    def ensure_layout(self) -> None:
        os.makedirs(self.trash_root, exist_ok=True)
        self._exclude_from_git()

    def _exclude_from_git(self) -> None:
        """Hide the quarantine from git status via .git/info/exclude."""
        git_dir = os.path.join(self.workspace, ".git")
        if not os.path.isdir(git_dir):  # not a repo root; nothing to exclude
            return
        info = os.path.join(git_dir, "info")
        exclude = os.path.join(info, "exclude")
        os.makedirs(info, exist_ok=True)
        try:
            with open(exclude, "r", encoding="utf-8") as fh:
                existing = fh.read()
        except OSError:
            existing = ""
        for line in existing.splitlines():
            if line.strip() == TRASH_DIRNAME:
                return
        with open(exclude, "a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write(f"# added by agent-guard (quarantine is not project data)\n")
            fh.write(f"{TRASH_DIRNAME}\n")

    # ------------------------------------------------------------ manifest

    def _manifest_append(self, records: List[Dict[str, Any]]) -> None:
        self.ensure_layout()
        with open(self.manifest_path, "a", encoding="utf-8") as fh:
            for record in records:
                record.setdefault("ts", utc_now_iso())
                fh.write(json.dumps(record, ensure_ascii=False,
                                    sort_keys=True) + "\n")

    def read_manifest(self) -> List[Dict[str, Any]]:
        path = self.manifest_path
        if not os.path.exists(path):
            return []
        out: List[Dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    out.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
        return out

    # -------------------------------------------------------------- move

    @staticmethod
    def _move(src: str, dest: str) -> None:
        """Move file/symlink/dir preserving symlink semantics.

        Same-filesystem moves are plain renames. Cross-device fallbacks keep
        symlinks as symlinks (never materialize what they point at).
        """
        try:
            os.rename(src, dest)
            return
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
        if os.path.islink(src):
            link_target = os.readlink(src)
            os.symlink(link_target, dest)
            os.unlink(src)
        elif os.path.isdir(src):
            shutil.copytree(src, dest, symlinks=True)
            shutil.rmtree(src)
        else:
            shutil.copy2(src, dest)
            os.unlink(src)

    # ----------------------------------------------------------- relocate

    def relocate(self, specs: List[PathSpec], txid: Optional[str] = None,
                 meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Move every concrete target into trash/<txid>/<workspace-relative>."""
        txid = txid or new_txid()
        records: List[Dict[str, Any]] = [{
            "type": "tx-start", "txid": txid, "strategy": "relocate",
            "meta": meta or {},
        }]
        moved: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        for spec in specs:
            src = spec.resolved
            entry_base = {"raw": spec.raw}
            if spec.wildcard or spec.indeterminable or not src:
                skipped.append({**entry_base, "reason": "not concretely resolved"})
                continue
            if not os.path.lexists(src):
                skipped.append({**entry_base, "reason": "already absent"})
                continue
            rel = os.path.relpath(src, self.workspace)
            dest = os.path.join(self.trash_root, txid, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            self._move(src, dest)
            item = {"type": "relocate", "txid": txid,
                    "origin_path": src, "trash_path": dest}
            records.append(item)
            moved.append({"origin": src, "trash": dest})
        self._manifest_append(records)
        return {"txid": txid, "moved": moved, "skipped": skipped}

    # ------------------------------------------------------ git snapshot

    def snapshot_git(self, cwd: Optional[str] = None,
                     txid: Optional[str] = None,
                     meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Stash-create tracked modifications without touching the tree.

        Returns sha=None when there is nothing to snapshot (clean tree) -
        that is success, not failure.
        """
        cwd = cwd or self.workspace
        txid = txid or new_txid()
        create = subprocess.run(["git", "-C", cwd, "stash", "create"],
                                capture_output=True, text=True, timeout=30)
        if create.returncode != 0:
            return {"txid": txid, "sha": None, "stored": False,
                    "error": (create.stderr or "git stash create failed").strip()}
        sha = create.stdout.strip()
        if not sha:
            self._manifest_append([{
                "type": "snapshot", "txid": txid, "sha": None,
                "note": "working tree clean; nothing to snapshot",
                "meta": meta or {},
            }])
            return {"txid": txid, "sha": None, "stored": False}
        store = subprocess.run(
            ["git", "-C", cwd, "stash", "store", "-m", f"agent-guard:{txid}", sha],
            capture_output=True, text=True, timeout=30)
        self._manifest_append([{
            "type": "snapshot", "txid": txid, "sha": sha,
            "stored": store.returncode == 0, "meta": meta or {},
        }])
        return {"txid": txid, "sha": sha, "stored": store.returncode == 0}

    # --------------------------------------------------- git clean enum

    def enumerate_git_clean(self, cwd: Optional[str],
                            clean_flags: List[str]) -> Tuple[List[str], str]:
        """Dry-run `git clean` mirroring the caller's scope flags.

        Returns (untracked_paths, stderr). Nested repositories are reported
        by git as 'Would skip' and are intentionally left alone.
        """
        cwd = cwd or self.workspace
        mirror = ["-n"]
        allowed = {"-d", "-x", "-X", "--directory", "--ignored"}
        for flag in clean_flags:
            if flag in allowed:
                mirror.append(flag)
        proc = subprocess.run(["git", "-C", cwd, "clean"] + mirror,
                              capture_output=True, text=True, timeout=60)
        paths: List[str] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("Would remove "):
                continue  # 'Would skip repository ...' etc. stay untouched
            target = line[len("Would remove "):].strip()
            if target.startswith('"') and target.endswith('"'):
                target = target[1:-1]  # core.quotePath escaping; best effort
            paths.append(target)
        return paths, proc.stderr.strip()

    # ------------------------------------------------------------- restore

    def transactions(self) -> Dict[str, Dict[str, Any]]:
        """Group manifest entries by transaction id (insertion order)."""
        out: Dict[str, Dict[str, Any]] = {}
        for record in self.read_manifest():
            txid = record.get("txid")
            if not txid:
                continue
            slot = out.setdefault(txid, {"txid": txid, "items": []})
            if record.get("type") == "tx-start":
                slot["meta"] = record.get("meta", {})
                slot["ts"] = record.get("ts")
            else:
                slot["items"].append(record)
        return out

    def restore(self, txid: str, force: bool = False,
                cwd: Optional[str] = None) -> Dict[str, Any]:
        """Undo one transaction. Refuses to overwrite unless force is set.

        Relocate items move back to their origin paths; snapshot items apply
        the stored stash (apply, never drop - the evidence stays until a
        human prunes it).
        """
        tx = self.transactions().get(txid)
        if not tx:
            return {"ok": False, "error": f"unknown transaction: {txid}"}
        restored: List[str] = []
        conflicts: List[str] = []
        errors: List[str] = []
        for item in tx["items"]:
            if item.get("type") == "relocate":
                origin = item["origin_path"]
                trash = item["trash_path"]
                if not os.path.lexists(trash):
                    errors.append(f"quarantine copy vanished: {trash}")
                    continue
                if os.path.lexists(origin):
                    if not force:
                        conflicts.append(origin)
                        continue
                    if os.path.isdir(origin) and not os.path.islink(origin):
                        shutil.rmtree(origin)
                    else:
                        os.unlink(origin)
                parent = os.path.dirname(origin)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                try:
                    self._move(trash, origin)
                    restored.append(origin)
                except OSError as exc:
                    errors.append(f"{origin}: {exc}")
            elif item.get("type") == "snapshot":
                sha = item.get("sha")
                if not sha:
                    continue
                apply = subprocess.run(
                    ["git", "-C", cwd or self.workspace, "stash", "apply", sha],
                    capture_output=True, text=True, timeout=60)
                if apply.returncode == 0:
                    restored.append(f"stash:{sha}")
                else:
                    errors.append(
                        f"stash apply {sha}: {(apply.stderr or '').strip()}")

        self._manifest_append([{
            "type": "restore", "txid": txid, "force": force,
            "restored": restored, "conflicts": conflicts, "errors": errors,
        }])
        # drop empty quarantine directories for tidy listings
        txdir = os.path.join(self.trash_root, txid)
        try:
            if os.path.isdir(txdir) and not os.listdir(txdir):
                os.rmdir(txdir)
        except OSError:
            pass
        return {"ok": not errors and not conflicts,
                "restored": restored, "conflicts": conflicts, "errors": errors}

    # ------------------------------------------------------------- status

    def usage(self) -> Dict[str, Any]:
        """Size/count summary of the quarantine tree (for status/GC later)."""
        files = 0
        total = 0
        for root, _dirs, names in os.walk(self.trash_root):
            for name in names:
                path = os.path.join(root, name)
                if os.path.islink(path):
                    files += 1
                    continue
                try:
                    total += os.lstat(path).st_size
                    files += 1
                except OSError:
                    pass
        return {"files": files, "bytes": total,
                "transactions": len(self.transactions())}
