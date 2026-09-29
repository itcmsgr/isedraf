# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The GA push policy holds: the engineering tree is never pushed, main never directly.
# Implements: D-73, D-110, D-119
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="bash,git"
# =============================================================================
"""git-hooks/pre-push at GA (D-119). The prototype refused every push (A-005). At GA the
public repository takes pull requests, so the hook now draws the two lines that matter: the
engineering repository, which holds the private history, is never pushed at all, and main
is never pushed directly. The hook is run the way git runs it: in a repository, with one
line per ref on stdin."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOOK = ROOT / "git-hooks" / "pre-push"
ZERO = "0" * 40
SHA = "1" * 40


class PrePushPolicy(unittest.TestCase):

    def repo(self, engineering):
        d = pathlib.Path(tempfile.mkdtemp(prefix="isedraf-prepush-"))
        self.addCleanup(shutil.rmtree, str(d), True)
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        subprocess.run(["git", "init", "-q", str(d)], check=True, env=env)
        if engineering:
            (d / "CLAUDE.md").write_text("engineering\n")
        return d, env

    def push(self, engineering, remote_ref):
        d, env = self.repo(engineering)
        line = "refs/heads/x %s %s %s\n" % (SHA, remote_ref, ZERO)
        return subprocess.run(["bash", str(HOOK), "origin", "https://example.invalid/r.git"],
                              cwd=str(d), env=env, input=line, universal_newlines=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

    def test_the_engineering_tree_is_never_pushed(self):
        for ref in ("refs/heads/feature", "refs/heads/main", "refs/tags/v9"):
            r = self.push(True, ref)
            self.assertEqual(r.returncode, 1, ref)
            self.assertIn("engineering repository", r.stderr)

    def test_the_register_alone_marks_the_engineering_tree(self):
        d, env = self.repo(False)
        (d / "docs" / "architecture").mkdir(parents=True)
        (d / "docs" / "architecture" / "DECISIONS_REGISTER.md").write_text("register\n")
        r = subprocess.run(["bash", str(HOOK), "origin", "u"], cwd=str(d), env=env,
                           input="refs/heads/x %s refs/heads/x %s\n" % (SHA, ZERO),
                           universal_newlines=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(r.returncode, 1)

    def test_the_public_tree_never_pushes_main_directly(self):
        r = self.push(False, "refs/heads/main")
        self.assertEqual(r.returncode, 1)
        self.assertIn("pull request", r.stderr)

    def test_the_public_tree_pushes_a_branch(self):
        r = self.push(False, "refs/heads/sync/ga-0.1.0")
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
