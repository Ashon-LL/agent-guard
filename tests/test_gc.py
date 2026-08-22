"""B4 retention policy: GC_ELIGIBLE marking, explicit purge, tombstones,
and the never-fallback-to-deletion storage principle."""
import json
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import RepoFixture, git_available

from core.recovery import RecoveryEngine, StorageUnavailable
from core.classifier import classify_paths


def specs_for(engine, rels):
    return classify_paths(rels, engine.workspace, engine.workspace,
                          engine.trash_root)


@unittest.skipUnless(git_available(), "git required")
class GcPlanTests(RepoFixture):
    def write_tx(self, rel, content="x", age_days=0.0):
        path = self.write(rel, content)
        engine = RecoveryEngine(self.root)
        report = engine.relocate(specs_for(engine, [rel]))
        if age_days:
            lines = open(engine.manifest_path).read().splitlines()
            for i, line in enumerate(lines):
                rec = json.loads(line)
                if rec.get("txid") == report["txid"] and \
                        rec.get("type") == "tx-start":
                    old = time.time() - age_days * 86400
                    rec["ts"] = time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(old))
                    lines[i] = json.dumps(rec, sort_keys=True)
            open(engine.manifest_path, "w").write("\n".join(lines) + "\n")
        return engine, report["txid"]

    def test_fresh_tx_not_eligible(self):
        engine, _ = self.write_tx("a.txt")
        plan = engine.gc_plan()
        self.assertEqual(plan["eligible"], [])

    def test_age_makes_tx_eligible(self):
        engine, txid = self.write_tx("old.txt", age_days=31)
        plan = engine.gc_plan()
        reasons = {e["txid"]: e["reason"] for e in plan["eligible"]}
        self.assertEqual(reasons.get(txid), "age")

    def test_capacity_marks_oldest_first(self):
        engine, old_id = self.write_tx("big-old.bin", content="B" * 2048,
                                       age_days=1)
        self.write_tx("new.bin", content="N" * 4096)
        plan = engine.gc_plan(size_limit_bytes=4096)
        eligible_ids = [e["txid"] for e in plan["eligible"]]
        self.assertEqual(eligible_ids, [old_id])  # oldest first, cap met

    def test_execute_purges_dir_and_writes_tombstone(self):
        engine, txid = self.write_tx("gone.txt", age_days=31)
        report = engine.gc_execute([txid])
        self.assertEqual(report["purged"], [txid])
        self.assertFalse(os.path.isdir(
            os.path.join(engine.trash_root, txid)))
        types = [json.loads(l)["type"] for l in open(engine.manifest_path)
                 if l.strip()]
        self.assertIn("purged", types)

    def test_execute_reports_unknown_txid(self):
        engine, _ = self.write_tx("x.txt")
        report = engine.gc_execute(["no-such-tx"])
        self.assertEqual(report["missing"], ["no-such-tx"])


@unittest.skipUnless(git_available(), "git required")
class StorageFailureTests(RepoFixture):
    def test_relocate_reports_storage_failure_and_keeps_origin(self):
        engine = RecoveryEngine(self.root)
        self.write("precious.txt", "keep")
        specs = specs_for(engine, ["precious.txt"])

        def full_disk(_self, src, dest):
            raise StorageUnavailable(28, "No space left on device")

        with mock.patch.object(RecoveryEngine, "_move", full_disk):
            report = engine.relocate(specs)

        self.assertTrue(report["storage_failure"])
        self.assertEqual(report["moved"], [])
        # the hard principle: origin untouched, nothing fell back to deletion
        self.assertTrue(os.path.exists(
            os.path.join(self.root, "precious.txt")))
        self.assertEqual(open(os.path.join(
            self.root, "precious.txt")).read(), "keep")


if __name__ == "__main__":
    unittest.main()
