"""Compensation engine: relocate / snapshot / restore semantics."""
import json
import os
import subprocess
import sys
import unittest

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
        self.assertEqual(open(leaf).read(), "payload")
        lines = [json.loads(l) for l in
                 open(engine.manifest_path) if l.strip()]
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
        self.assertEqual(open(os.path.join(self.root, "precious.txt")).read(),
                         "someone else lives here now")  # non-destructive!
        forced = engine.restore(tx, force=True)
        self.assertTrue(forced["ok"])
        self.assertEqual(open(os.path.join(self.root, "precious.txt")).read(),
                         "keep me")


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
        self.assertNotIn("# precious", open(main).read())
        report = engine.restore(snap["txid"])
        self.assertTrue(report["ok"])
        self.assertIn("# precious", open(main).read())
        # apply never drops: the evidence remains until a human prunes it
        self.assertGreaterEqual(self.stash_count(), 1)

    def test_enumerate_git_clean_lists_untracked_only(self):
        self.write("junk.tmp")
        engine = RecoveryEngine(self.root)
        paths, _err = engine.enumerate_git_clean(self.root, [])
        self.assertIn("junk.tmp", paths)
        self.assertNotIn("src/main.py", paths)


if __name__ == "__main__":
    unittest.main()
