"""F9 regression: a workspace reached through a SYMBOLIC LINK (macOS CI).

Upstream GitHub PR #4 turned the whole macOS matrix red while Linux and
Windows stayed green. The failing cases were all
`tests/test_dialect_phase2.py::CheckCliDialect`, and the reported verdicts
were BLOCK_OUT_OF_WORKSPACE for targets that plainly live inside the
workspace:

    test_advisory_mode_does_not_mutate          expected RELOCATE
    test_default_posix_behaviour_unchanged      expected RELOCATE
    test_powershell_tree_delete_relocates       expected ALLOW/RELOCATE_TREE

Root cause: macOS hands out temp directories under /var/folders/... and
/var is a symlink to /private/var (just as /tmp is a symlink to
/private/tmp). `unittest`'s TemporaryDirectory keeps the SYMLINKED spelling,
`check.py` passes that spelling as the workspace root, and
`discover_workspace()` realpath-resolved it (F8). Target paths, however,
were compared LEXICALLY: `/var/folders/.../build` shares no `commonpath`
prefix with the physical `/private/var/folders/...` root, so every target
was judged out of bounds. The failure was latent on Linux/macOS CI because
those runners put temp directories on non-symlinked paths.

These tests reproduce the platform divergence on ANY host by running the
fixture from a symlinked directory (ln -s SK-<tmp> SK-link-<...) and pin
the contract:

  - a target inside the tree is inside, no matter which spelling the caller
    used for the workspace root (both `check.py` paths: --dialect and the
    default POSIX path);
  - the quarantine still round-trips the target (RELOCATE is a promise);
  - the hard boundaries are NOT loosened by the normalization (outside
    targets and the workspace root itself stay BLOCKed).

The tests FAIL against the pre-fix classifier (targets reported
outside-workspace) and pass after it.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.classifier import classify_command, classify_paths, discover_workspace
from core.policy import PolicyContext, decide_ops, worst
from core.recovery import RecoveryEngine

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECK = os.path.join(ROOT, "skills", "delete-guard", "scripts", "check.py")


def symlink_supported() -> bool:
    """Some Windows/CI filesystems refuse symlinks (or need privileges)."""
    base = tempfile.mkdtemp(prefix="agent-guard-symprobe-")
    try:
        os.symlink(base, os.path.join(base, "link"))
        return True
    except (OSError, NotImplementedError):
        return False
    finally:
        shutil.rmtree(base, ignore_errors=True)


@unittest.skipUnless(symlink_supported(), "symlinks unavailable on this FS")
class SymlinkedWorkspaceFixture(unittest.TestCase):
    """A temp workspace whose parent is a symlink, i.e. the macOS layout."""

    def setUp(self):
        # The UNRESOLVED spelling is the point: on macOS this is
        # /var/folders/... while the physical tree is /private/var/folders/...
        self._tmp = tempfile.TemporaryDirectory(prefix="agent-guard-sym-")
        self.spelled = self._tmp.name
        self.real = os.path.realpath(self.spelled)
        # /tmp/SK-<rand>-link -> /tmp/SK-<rand>. The caller (fixture, shell,
        # harness) works from the link spelling; the kernel reports the real
        # one - exactly the /tmp vs /private/tmp split on macOS.
        self.link = os.path.join(
            os.path.dirname(self.real), os.path.basename(self.real) + "-link")
        os.symlink(self.real, self.link)
        self.addCleanup(self._drop_links)
        # An extra level of link indirection under the workspace itself.
        self.inner_link = os.path.join(self.link, "ws-link")
        os.symlink(self.real, self.inner_link)
        subprocess.run(["git", "init", "-q", self.real], check=False)
        self.write("build/nested/a.o", "artifact")
        # Linux temp dirs are usually canonical; on macOS they never are.
        # Either way the symlink below models the split.
        self.assertTrue(os.path.islink(self.link))
        self.assertEqual(os.path.realpath(self.link), self.real)

    def _drop_links(self):
        for path in (self.inner_link, self.link):
            if os.path.islink(path):
                os.unlink(path)
        self._tmp.cleanup()

    def write(self, rel: str, content: str = "x") -> str:
        path = os.path.join(self.real, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        return path

    def run_check(self, *argv):
        env = dict(os.environ)
        env.pop("AGENT_GUARD_DIALECT", None)
        env["GIT_CONFIG_GLOBAL"] = "/dev/null"
        proc = subprocess.run(
            [sys.executable, CHECK, "--cwd", self.link, "--json", *argv],
            capture_output=True, text=True, env=env, timeout=60)
        try:
            return json.loads(proc.stdout), proc
        except json.JSONDecodeError:
            self.fail(f"check.py emitted no JSON: {proc.stdout!r} "
                      f"{proc.stderr!r}")

    # -- the three upstream macOS failures, reproduced on any host -------

    def test_powershell_tree_delete_relocates_from_symlinked_workspace(self):
        """Upstream: powershell/tree delete expected RELOCATE_TREE."""
        out, proc = self.run_check("--dialect", "powershell", "--enforce",
                                   "--", "ri build -r -fo")
        self.assertEqual((out["decision"], out["code"]),
                         ("ALLOW", "RELOCATE_TREE"), (out["reasons"], proc.stderr))
        self.assertTrue(os.path.isdir(os.path.join(self.real, ".agent-trash")))

    def test_advisory_mode_does_not_mutate_from_symlinked_workspace(self):
        """Upstream: advisory powershell delete expected RELOCATE, no mutation."""
        out, _ = self.run_check("--dialect", "powershell", "--",
                                "ri build -r -fo")
        self.assertEqual(out["decision"], "RELOCATE")
        self.assertTrue(os.path.isdir(os.path.join(self.real, "build")))

    def test_default_posix_behaviour_unchanged_from_symlinked_workspace(self):
        """Upstream: plain `rm -rf build` with no --dialect expected RELOCATE."""
        out, _ = self.run_check("--", "rm -rf build")
        self.assertEqual(out["decision"], "RELOCATE")
        self.assertEqual(out["ops"][0]["op"], "rm")
        self.assertTrue(os.path.isdir(os.path.join(self.real, "build")))

    def test_enforce_relocation_survives_symlinked_workspace(self):
        """RELOCATE is only honest if restore can put the tree back."""
        out, proc = self.run_check("--dialect", "powershell", "--enforce",
                                   "--", "ri build -r -fo")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        txid = out["compensations"][0]["txid"]
        self.assertFalse(os.path.exists(os.path.join(self.real, "build")))
        engine = RecoveryEngine(self.link)
        restored = engine.restore(txid)
        self.assertTrue(restored["ok"], restored)
        self.assertEqual(
            open(os.path.join(self.real, "build", "nested", "a.o")).read(),
            "artifact")

    # -- boundary facts, independent of the CLI -------------------------

    def test_classify_paths_agrees_on_both_spellings(self):
        for root in (self.real, self.link, self.inner_link):
            workspace = discover_workspace(root)
            spec = classify_paths(["build"], self.link, workspace,
                                 os.path.join(workspace, ".agent-trash"))[0]
            self.assertTrue(spec.inside_workspace, root)
            self.assertIsNone(spec.protected, root)

    def test_lexical_spelling_of_target_is_preserved(self):
        """The comparison is physical; the reported path stays lexical."""
        workspace = discover_workspace(self.link)
        spec = classify_paths(["build"], self.link, workspace, None)[0]
        self.assertEqual(
            spec.resolved, os.path.normpath(os.path.abspath(
                os.path.join(self.link, "build"))))
        self.assertTrue(spec.resolved.startswith(self.link))

    def test_verdict_is_relocate_on_both_dialects(self):
        workspace = discover_workspace(self.link)
        ctx = PolicyContext(workspace=workspace,
                            trash_root=os.path.join(workspace, ".agent-trash"),
                            base_dir=self.link)
        for cmd, dialect in (("rm -rf build", "posix"),
                             ("ri build -r -fo", "powershell")):
            specs, err = classify_command(cmd, dialect)
            self.assertIsNone(err, cmd)
            verdict = worst(decide_ops(specs, ctx))
            self.assertEqual(verdict.decision, "RELOCATE", cmd)

    def test_trash_centre_stays_inside_and_never_relocated(self):
        workspace = discover_workspace(self.link)
        specs = [s for s in classify_command("rm -rf .agent-trash/x", "posix")[0]]
        ctx = PolicyContext(workspace=workspace,
                            trash_root=os.path.join(workspace, ".agent-trash"),
                            base_dir=self.link)
        verdict = worst(decide_ops(specs, ctx))
        self.assertEqual((verdict.decision, verdict.code),
                         ("ALLOW", "ALLOW_TRASH_GC"))

    # -- normalization must not loosen the hard boundaries ---------------

    def test_workspace_root_still_blocked(self):
        out, proc = self.run_check("--enforce", "--", "rm -rf .")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual((out["decision"], out["code"]),
                         ("BLOCK", "BLOCK_PROTECTED_PATH"))

    def test_genuinely_outside_target_still_blocked(self):
        outside = tempfile.mkdtemp(prefix="agent-guard-outside-")
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        victim = os.path.join(outside, "keep.txt")
        with open(victim, "w") as fh:
            fh.write("keep")
        out, proc = self.run_check("--enforce", "--", "rm -f", victim)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual((out["decision"], out["code"]),
                         ("BLOCK", "BLOCK_OUT_OF_WORKSPACE"))
        self.assertTrue(os.path.exists(victim))

    def test_escape_via_symlink_into_workspace_is_outside(self):
        """A path that is physically elsewhere stays outside, however spelled."""
        outside = tempfile.mkdtemp(prefix="agent-guard-outsidesym-")
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        with open(os.path.join(outside, "keep.txt"), "w") as fh:
            fh.write("keep")
        escape = os.path.join(self.link, "escape")
        os.symlink(outside, escape)
        specs = [s for s in classify_command("rm -rf escape/keep.txt",
                                             "posix")[0]]
        workspace = discover_workspace(self.link)
        ctx = PolicyContext(workspace=workspace,
                            trash_root=os.path.join(workspace, ".agent-trash"),
                            base_dir=self.link)
        verdict = worst(decide_ops(specs, ctx))
        self.assertEqual((verdict.decision, verdict.code),
                         ("BLOCK", "BLOCK_OUT_OF_WORKSPACE"))
        self.assertTrue(os.path.exists(os.path.join(outside, "keep.txt")))


class UnlinkedWorkspaceFixture(unittest.TestCase):
    """The canonical (non-symlinked) layout must not change at all."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="agent-guard-plain-")
        self.root = self._tmp.name
        os.makedirs(os.path.join(self.root, "build"))
        with open(os.path.join(self.root, "build", "a.o"), "w") as fh:
            fh.write("x")
        self.addCleanup(self._tmp.cleanup)

    def test_inside_still_inside_and_root_still_root(self):
        workspace = discover_workspace(self.root)
        inside = classify_paths(["build"], self.root, workspace, None)[0]
        self.assertTrue(inside.inside_workspace)
        self.assertIsNone(inside.protected)
        root = classify_paths(["."], self.root, workspace, None)[0]
        self.assertEqual(root.protected, "workspace-root")

    def test_nested_root_and_child_agree(self):
        workspace = discover_workspace(self.root)
        deep = os.path.join(self.root, "build")
        spec = classify_paths(["a.o"], deep, workspace, None)[0]
        self.assertTrue(spec.inside_workspace)
        self.assertIsNone(spec.protected)


if __name__ == "__main__":
    unittest.main()
