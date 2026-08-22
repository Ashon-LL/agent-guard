"""Classifier facts and policy verdicts (pure logic, no mutation)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import RepoFixture, git_available

from core.classifier import (
    KIND_FS_DELETE, KIND_GIT_CLEAN, KIND_GIT_DISCARD, KIND_GIT_PUSH_FORCE,
    KIND_GIT_RESET_HARD, KIND_UNKNOWN, classify_command, classify_paths,
)
from core.policy import (
    ACTION_ALLOW, ACTION_BLOCK, CODE_BLOCK_OUT_OF_WORKSPACE,
    CODE_BLOCK_PROTECTED_PATH, CODE_BLOCK_RESTRICTED_MODE,
    CODE_BLOCK_UNDETERMINABLE, CODE_BLOCK_WILDCARD, MODE_NORMAL,
    MODE_RESTRICTED, PolicyContext, decide_ops,
)


def one(specs):
    assert len(specs) == 1, f"expected 1 op, got {specs}"
    return specs[0]


def verdict_for(cmd, root, mode=MODE_NORMAL):
    from core.classifier import discover_workspace
    ctx = PolicyContext(
        workspace=root, trash_root=os.path.join(root, ".agent-trash"),
        base_dir=root, mode=mode)
    specs, err = classify_command(cmd)
    vs = decide_ops(specs, ctx)
    return vs[0] if vs else None


class ClassifierFacts(unittest.TestCase):
    def test_rm_combined_flags(self):
        spec = one(classify_command("rm -rf build")[0])
        self.assertEqual(spec.kind, KIND_FS_DELETE)
        self.assertTrue(spec.recursive and spec.force)

    def test_wildcard_detected(self):
        spec = one(classify_command("rm *.log")[0])
        self.assertTrue(spec.wildcard)

    def test_variable_undeterminable(self):
        spec = one(classify_command("rm -rf $DIR")[0])
        self.assertTrue(spec.undeterminable)

    def test_indirect_shell_smell(self):
        spec = one(classify_command('bash -c "rm -rf /tmp/x"')[0])
        self.assertEqual(spec.kind, KIND_UNKNOWN)

    def test_find_delete(self):
        spec = one(classify_command("find . -name '*.pyc' -delete")[0])
        self.assertEqual(spec.kind, KIND_FS_DELETE)
        self.assertTrue(spec.undeterminable)

    def test_git_clean_dry_run_vs_force(self):
        self.assertTrue(one(classify_command("git clean -nd")[0]).dry_run)
        forced = one(classify_command("git clean -fdx")[0])
        self.assertTrue(forced.force)
        self.assertEqual(sorted(forced.extra_flags), ["-d", "-x"])

    def test_git_reset_hard(self):
        self.assertEqual(one(classify_command("git reset --hard")[0]).kind,
                         KIND_GIT_RESET_HARD)

    def test_restore_staged_only_not_destructive(self):
        specs, _ = classify_command("git restore --staged src/main.py")
        self.assertEqual(specs, [])

    def test_checkout_dd_is_discard(self):
        spec = one(classify_command("git checkout -- src/main.py")[0])
        self.assertEqual(spec.kind, KIND_GIT_DISCARD)

    def test_push_force_variants(self):
        for cmd in ("git push --force origin main",
                    "git push -f origin main",
                    "git push origin +main",
                    "git push origin :feature/x",
                    "git push --mirror"):
            self.assertEqual(one(classify_command(cmd)[0]).kind,
                             KIND_GIT_PUSH_FORCE, cmd)

    def test_benign_command_yields_nothing(self):
        self.assertEqual(classify_command("ls -la && echo hi")[0], [])

    def test_f1_cd_before_destructive_blocks(self):
        spec = one(classify_command("cd sub && rm -rf build")[0])
        self.assertTrue(spec.undeterminable)
        self.assertTrue(any("F1" in n for n in spec.notes))

    def test_f1_destructive_before_cd_is_fine(self):
        spec = one(classify_command("rm -rf build && cd sub")[0])
        self.assertFalse(spec.undeterminable)

    def test_f1_applies_to_git_clean(self):
        spec = one(classify_command("cd sub && git clean -fd")[0])
        self.assertTrue(spec.undeterminable)

    def test_f2_create_then_delete_blocks(self):
        spec = one(classify_command("touch a.tmp && rm a.tmp")[0])
        self.assertTrue(any("F2" in n for n in spec.notes))
        self.assertTrue(spec.undeterminable)

    def test_f2_redirect_counts_as_creation(self):
        spec = one(classify_command("echo x > f.txt && rm f.txt")[0])
        self.assertTrue(any("F2" in n for n in spec.notes))

    def test_f2_delete_then_create_is_fine(self):
        spec = one(classify_command("rm -rf build && mkdir build")[0])
        self.assertFalse(spec.undeterminable)

    def test_f2_exempts_position_independent_kinds(self):
        spec = one(classify_command("touch f && git reset --hard")[0])
        self.assertEqual(spec.kind, KIND_GIT_RESET_HARD)
        self.assertFalse(spec.undeterminable)

    def test_subshell_parens_do_not_hide_operations(self):
        spec = one(classify_command("(rm -rf build)")[0])
        self.assertEqual(spec.kind, KIND_FS_DELETE)

    def test_heredoc_body_is_payload_not_syntax(self):
        # friction.md F5: quoted destructive text inside a heredoc is file
        # content, not an executed command.
        cmd = "cat > notes.md <<'EOF'\n" + \
              "run rm -rf build to clean\n" + \
              "and git clean -fd\n" + \
              "EOF\necho done"
        specs, err = classify_command(cmd)
        self.assertEqual((specs, err), ([], None))


class PolicyVerdicts(RepoFixture):
    def test_out_of_workspace_blocked(self):
        v = verdict_for("rm /etc/passwd", self.root)
        self.assertEqual((v.action, v.code),
                         (ACTION_BLOCK, CODE_BLOCK_OUT_OF_WORKSPACE))

    def test_workspace_root_blocked(self):
        v = verdict_for("rm -rf .", self.root)
        self.assertEqual(v.code, CODE_BLOCK_PROTECTED_PATH)

    def test_git_metadata_blocked(self):
        v = verdict_for("rm -rf .git", self.root)
        self.assertEqual(v.code, CODE_BLOCK_PROTECTED_PATH)

    def test_wildcard_blocked(self):
        v = verdict_for("rm *.log", self.root)
        self.assertEqual(v.code, CODE_BLOCK_WILDCARD)

    def test_variable_blocked(self):
        v = verdict_for("rm -rf $UNSET_DIR/", self.root)
        self.assertEqual(v.code, CODE_BLOCK_UNDETERMINABLE)

    def test_rooted_recursion_relocates(self):
        self.write("build/cache/o.js")
        v = verdict_for("rm -rf build", self.root)
        self.assertEqual(v.action, "RELOCATE")

    @unittest.skipUnless(git_available(), "git required")
    def test_regenerable_allowed(self):
        os.makedirs(os.path.join(self.root, "node_modules"), exist_ok=True)
        self.write("node_modules/pkg/index.js")
        v = verdict_for("rm -rf node_modules", self.root)
        self.assertEqual(v.action, ACTION_ALLOW)

    def test_restricted_narrow_file_ok(self):
        path = self.write("notes.txt")
        v = verdict_for(f"rm {path}", self.root, mode=MODE_RESTRICTED)
        self.assertEqual(v.action, "RELOCATE")

    def test_restricted_recursion_blocked(self):
        self.write("dir/inner.txt")
        v = verdict_for("rm -rf dir", self.root, mode=MODE_RESTRICTED)
        self.assertEqual((v.action, v.code),
                         (ACTION_BLOCK, CODE_BLOCK_RESTRICTED_MODE))

    def test_restricted_git_blocked(self):
        v = verdict_for("git reset --hard", self.root, mode=MODE_RESTRICTED)
        self.assertEqual(v.code, CODE_BLOCK_RESTRICTED_MODE)


if __name__ == "__main__":
    unittest.main()
