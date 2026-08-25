"""Compensation engine: relocate / snapshot / restore semantics."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import RepoFixture, git_available

from core.classifier import classify_paths
from core.recovery import RecoveryEngine


def specs_for(engine, rels):
    return classify_paths(rels, engine.workspace, engine.workspace,
                          engine.trash_root)


@unittest.skipUnless(git_available(), "git required")
class RelocateTests(RepoFixture):
    def test_structure_preserved_and_manifest_written(self):
        engine = RecoveryEngine(self.root)
        self.write("deep/nested/leaf.txt", "payload")
        specs = specs_for(engine, ["deep"])
        report = engine.relocate(specs, meta={"tool": "test"})
        self.assertFalse(os.path.exists(os.path.join(self.root, "deep")))
        moved = report["moved"][0]
        self.assertTrue(os.path.isdir(moved["trash"]))
        leaf = os.path.join(moved["trash"], "nested", "leaf.txt")
        self.assertTrue(os.path.isfile(leaf))
        self.assertEqual(Path(leaf).read_text(), "payload")
        lines = [json.loads(line) for line in
                 Path(engine.manifest_path).read_text().splitlines()
                 if line.strip()]
        types = {r["type"] for r in lines}
        self.assertIn("relocate", types)
        self.assertIn("tx-start", types)

    def test_symlink_stays_symlink(self):
        outside = os.path.join(os.path.dirname(self.root), "outside-target")
        with open(outside, "w") as fh:
            fh.write("far away")
        link = os.path.join(self.root, "link")
        os.symlink(outside, link)
        engine = RecoveryEngine(self.root)
        report = engine.relocate(specs_for(engine, ["link"]))
        trash_link = report["moved"][0]["trash"]
        self.assertTrue(os.path.islink(trash_link))
        self.assertEqual(os.readlink(trash_link), outside)
        self.assertTrue(os.path.exists(outside))  # target untouched

    def test_restore_roundtrip_and_conflict(self):
        engine = RecoveryEngine(self.root)
        self.write("precious.txt", "keep me")
        tx = engine.relocate(specs_for(engine, ["precious.txt"]))["txid"]
        self.assertFalse(os.path.exists(
            os.path.join(self.root, "precious.txt")))
        # conflict: something now occupies the origin path
        self.write("precious.txt", "someone else lives here now")
        blocked = engine.restore(tx)
        self.assertFalse(blocked["ok"])          # conflicts reported
        self.assertEqual(Path(self.root, "precious.txt").read_text(),
                         "someone else lives here now")  # non-destructive!
        forced = engine.restore(tx, force=True)
        self.assertTrue(forced["ok"])
        self.assertEqual(Path(self.root, "precious.txt").read_text(),
                         "keep me")

    def test_initial_journal_failure_moves_nothing(self):
        engine = RecoveryEngine(self.root)
        origin = self.write("precious.txt", "keep")
        specs = specs_for(engine, ["precious.txt"])
        with mock.patch.object(
                engine, "_manifest_append",
                side_effect=PermissionError("manifest is read-only")):
            with self.assertRaises(PermissionError):
                engine.relocate(specs)
        self.assertTrue(os.path.exists(origin))
        self.assertEqual(Path(origin).read_text(), "keep")

    def test_intent_without_completion_is_discoverable_and_restorable(self):
        engine = RecoveryEngine(self.root)
        origin = self.write("orphaned.txt", "recover me")
        specs = specs_for(engine, ["orphaned.txt"])
        real_append = engine._manifest_append
        calls = 0

        def fail_completion(records):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise PermissionError("completion journal failed")
            return real_append(records)

        with mock.patch.object(engine, "_manifest_append",
                               side_effect=fail_completion):
            with self.assertRaises(PermissionError):
                engine.relocate(specs)

        self.assertFalse(os.path.exists(origin))
        txs = engine.transactions()
        self.assertEqual(len(txs), 1)
        txid = next(iter(txs))
        self.assertEqual(len(txs[txid]["items"]), 1)
        self.assertTrue(txs[txid]["items"][0]["recovered_from_intent"])
        restored = engine.restore(txid)
        self.assertTrue(restored["ok"], restored)
        self.assertEqual(Path(origin).read_text(), "recover me")

    def test_multi_target_completion_failure_recovers_every_move(self):
        engine = RecoveryEngine(self.root)
        first = self.write("first.txt", "one")
        second = self.write("second.txt", "two")
        real_append = engine._manifest_append
        calls = 0

        def fail_second_completion(records):
            nonlocal calls
            calls += 1
            if calls == 5:
                raise PermissionError("second completion journal failed")
            return real_append(records)

        with mock.patch.object(engine, "_manifest_append",
                               side_effect=fail_second_completion):
            with self.assertRaises(PermissionError):
                engine.relocate(specs_for(
                    engine, ["first.txt", "second.txt"]))

        self.assertFalse(os.path.exists(first))
        self.assertFalse(os.path.exists(second))
        txid, transaction = next(iter(engine.transactions().items()))
        self.assertEqual(len(transaction["items"]), 2)
        restored = engine.restore(txid)
        self.assertTrue(restored["ok"], restored)
        self.assertEqual(Path(first).read_text(), "one")
        self.assertEqual(Path(second).read_text(), "two")

    def test_readonly_git_exclude_fails_before_move_when_not_ignored(self):
        engine = RecoveryEngine(self.root)
        origin = self.write("precious.txt", "keep")
        exclude = os.path.join(self.root, ".git", "info", "exclude")
        old_mode = os.stat(exclude).st_mode
        os.chmod(exclude, 0o444)
        try:
            with self.assertRaises(PermissionError):
                engine.relocate(specs_for(engine, ["precious.txt"]))
        finally:
            os.chmod(exclude, old_mode)
        self.assertTrue(os.path.exists(origin))
        self.assertFalse(os.path.exists(engine.trash_root))

    def test_preignored_trash_works_with_readonly_git_exclude(self):
        with open(os.path.join(self.root, ".gitignore"), "a") as fh:
            fh.write(".agent-trash/\n")
        engine = RecoveryEngine(self.root)
        self.write("precious.txt", "keep")
        exclude = os.path.join(self.root, ".git", "info", "exclude")
        old_mode = os.stat(exclude).st_mode
        os.chmod(exclude, 0o444)
        try:
            report = engine.relocate(specs_for(engine, ["precious.txt"]))
        finally:
            os.chmod(exclude, old_mode)
        self.assertEqual(len(report["moved"]), 1)
        self.assertIn(report["txid"], engine.transactions())

    def test_transaction_state_distinguishes_restore_from_restorable(self):
        engine = RecoveryEngine(self.root)
        origin = self.write("lifecycle.txt", "stateful")
        txid = engine.relocate(
            specs_for(engine, ["lifecycle.txt"]))["txid"]
        before = engine.transactions()[txid]
        self.assertEqual(before["state"], "RESTORABLE")
        self.assertEqual(before["restorable_items"], 1)
        self.assertEqual(engine.usage()["restorable_transactions"], 1)

        restored = engine.restore(txid)
        self.assertTrue(restored["ok"], restored)
        self.assertEqual(Path(origin).read_text(), "stateful")
        after = engine.transactions()[txid]
        self.assertEqual(after["state"], "RESTORED")
        self.assertEqual(after["restorable_items"], 0)
        self.assertEqual(engine.usage()["restorable_transactions"], 0)


@unittest.skipUnless(git_available(), "git required")
class SnapshotTests(RepoFixture):
    def stash_count(self):
        out = subprocess.run(["git", "-C", self.root, "stash", "list"],
                             capture_output=True, text=True).stdout
        return len(out.strip().splitlines()) if out.strip() else 0

    def test_clean_tree_snapshots_nothing(self):
        engine = RecoveryEngine(self.root)
        result = engine.snapshot_git()
        self.assertIsNone(result["sha"])

    def test_dirty_tree_snapshot_and_restore(self):
        engine = RecoveryEngine(self.root)
        main = os.path.join(self.root, "src", "main.py")
        with open(main, "a") as fh:
            fh.write("# precious uncommitted work\n")
        snap = engine.snapshot_git()
        self.assertIsNotNone(snap["sha"])
        self.assertEqual(self.stash_count(), 1)
        subprocess.run(["git", "-C", self.root, "reset", "-q", "--hard"])
        self.assertNotIn("# precious", Path(main).read_text())
        report = engine.restore(snap["txid"])
        self.assertTrue(report["ok"])
        self.assertIn("# precious", Path(main).read_text())
        # apply never drops: the evidence remains until a human prunes it
        self.assertGreaterEqual(self.stash_count(), 1)

    def test_enumerate_git_clean_lists_untracked_only(self):
        self.write("junk.tmp")
        engine = RecoveryEngine(self.root)
        paths, _err = engine.enumerate_git_clean(self.root, [])
        self.assertIn("junk.tmp", paths)
        self.assertNotIn("src/main.py", paths)

    def test_enumerate_git_clean_decodes_git_quoted_paths(self):
        names = [
            "中文笔记.txt",
            "line\nbreak.txt",
            'quote"backslash\\tab\t.txt',
        ]
        for name in names:
            self.write(name)
        subprocess.run(["git", "-C", self.root, "config",
                        "core.quotePath", "true"], check=True)
        engine = RecoveryEngine(self.root)
        paths, err = engine.enumerate_git_clean(self.root, [])
        self.assertEqual(err, "")
        self.assertEqual(set(paths), set(names))

    def test_snapshot_create_failure_is_not_clean_success(self):
        engine = RecoveryEngine(self.root)
        failed = subprocess.CompletedProcess(
            args=["git"], returncode=128, stdout="", stderr="fatal: denied")
        with mock.patch("core.recovery.subprocess.run", return_value=failed):
            result = engine.snapshot_git()
        self.assertFalse(result["ok"])
        self.assertFalse(result["clean"])
        self.assertIn("denied", result["error"])

    def test_snapshot_store_failure_is_not_recoverable_success(self):
        engine = RecoveryEngine(self.root)
        created = subprocess.CompletedProcess(
            args=["git"], returncode=0, stdout="deadbeef\\n", stderr="")
        failed_store = subprocess.CompletedProcess(
            args=["git"], returncode=1, stdout="", stderr="store denied")
        with mock.patch("core.recovery.subprocess.run",
                        side_effect=[created, failed_store]), \
                mock.patch.object(engine, "_manifest_append"):
            result = engine.snapshot_git()
        self.assertFalse(result["ok"])
        self.assertFalse(result["stored"])
        self.assertIn("store denied", result["error"])


if __name__ == "__main__":
    unittest.main()
