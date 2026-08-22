"""End-to-end CLI tests through the skill scripts (subprocess)."""
import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import RepoFixture, git_available

SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "skills", "delete-guard", "scripts")


def run(script, *args, cwd):
    return subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, script), *args],
        capture_output=True, text=True, cwd=cwd, timeout=60)


@unittest.skipUnless(git_available(), "git required")
class SafeDeleteCLI(RepoFixture):
    def test_relocate_then_restore_roundtrip(self):
        self.write("report.txt", "data")
        proc = run("safe_delete.py", "--json", "report.txt", cwd=self.root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["verdict"]["action"], "RELOCATE")
        self.assertFalse(os.path.exists(os.path.join(self.root, "report.txt")))

        listing = json.loads(run("restore.py", "list", "--json",
                                 cwd=self.root).stdout)
        txid = listing["transactions"][-1]["txid"]
        back = run("restore.py", txid, cwd=self.root)   # bare-txid form
        self.assertEqual(back.returncode, 0, back.stderr)
        self.assertEqual(open(os.path.join(self.root, "report.txt")).read(),
                         "data")

    def test_blocked_outside_workspace_exit_2(self):
        outside = os.path.join(os.path.dirname(self.root), "keep-me.txt")
        with open(outside, "w") as fh:
            fh.write("do not touch")
        proc = run("safe_delete.py", "--json", outside, cwd=self.root)
        self.assertEqual(proc.returncode, 2)
        result = json.loads(proc.stdout)
        self.assertEqual(result["verdict"]["code"], "BLOCK_OUT_OF_WORKSPACE")
        self.assertTrue(os.path.exists(outside))

    def test_dry_run_touches_nothing(self):
        self.write("dry.txt")
        proc = run("safe_delete.py", "--json", "--dry-run", "dry.txt",
                   cwd=self.root)
        result = json.loads(proc.stdout)
        self.assertIn("would", result["outcome"])
        self.assertTrue(os.path.exists(os.path.join(self.root, "dry.txt")))


@unittest.skipUnless(git_available(), "git required")
class CheckCLI(RepoFixture):
    def test_advisory_block_exit_0(self):
        proc = run("check.py", "--json", "--", "rm -rf /", cwd=self.root)
        self.assertEqual(proc.returncode, 0)          # advisory never fails
        out = json.loads(proc.stdout)
        self.assertEqual(out["action"], "BLOCK")

    def test_enforce_proceeds_after_relocation(self):
        self.write("tmpbuild/o.js")
        proc = run("check.py", "--enforce", "--json", "--", "rm -rf tmpbuild",
                   cwd=self.root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["action"], "PROCEED")
        self.assertFalse(os.path.exists(os.path.join(self.root, "tmpbuild")))
        self.assertGreaterEqual(out["compensations"][0]["moved"], 1)

    def test_enforce_blocked_leaves_fs_untouched(self):
        proc = run("check.py", "--enforce", "--", "rm -rf .", cwd=self.root)
        self.assertEqual(proc.returncode, 2)
        self.assertTrue(os.path.exists(os.path.join(self.root, ".gitignore")))

    def test_wildcard_enforce_blocked(self):
        self.write("a.tmp")
        proc = run("check.py", "--enforce", "--", "rm *.tmp", cwd=self.root)
        self.assertEqual(proc.returncode, 2)
        self.assertTrue(os.path.exists(os.path.join(self.root, "a.tmp")))


@unittest.skipUnless(git_available(), "git required")
class StatusCLI(RepoFixture):
    def test_json_and_human_modes(self):
        run("safe_delete.py", "s.txt", cwd=self.root) if self.write("s.txt") else None
        human = run("status.py", cwd=self.root)
        self.assertEqual(human.returncode, 0)
        self.assertIn("mode      : NORMAL", human.stdout)
        js = json.loads(run("status.py", "--json", cwd=self.root).stdout)
        self.assertEqual(js["mode"], "NORMAL")
        self.assertIn("usage", js)


if __name__ == "__main__":
    unittest.main()
