# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The USER_PRODUCTION store: its root is checked, and unsuitable storage fails closed.
# Implements: STORE-026, STORE-027, SCOPE-071, PRIV-004
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================
"""GA v0.1 user-mode production store (D-116, D-117)."""
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import cli, exitcodes, stateroot, verify                   # noqa: E402

MOUNTINFO = (
    "22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/root rw\n"
    "40 22 0:40 / /home rw,relatime shared:2 - btrfs /dev/nvme0n1p3 rw\n"
    "41 40 0:41 / /home/u/nfs rw - nfs4 server:/export rw\n"
    "42 40 0:42 / /home/u/sshfs rw - fuse.sshfs u@host: rw\n"
    "43 40 0:43 / /home/u/odd rw - weirdfs none rw\n"
    "44 40 0:44 / /home/u/with\\040space rw - cifs //srv/share rw\n"
)


class StorageSuitability(unittest.TestCase):
    """STORE-027: a USER_PRODUCTION commit fails closed on unsuitable storage."""

    def setUp(self):
        fd, self.info = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.unlink, self.info)
        with open(self.info, "w") as fh:
            fh.write(MOUNTINFO)

    def check(self, path):
        return stateroot.storage_suitability(path, mountinfo=self.info)

    def test_local_filesystems_are_suitable(self):
        for path in ("/home/u/.local/state/isedraf", "/srv/isedraf"):
            ok, reason = self.check(path)
            self.assertTrue(ok, (path, reason))

    def test_known_remote_or_fuse_filesystems_are_refused_by_name(self):
        for path, fstype in (("/home/u/nfs/state", "nfs4"), ("/home/u/sshfs/x", "fuse.sshfs"),
                             ("/home/u/with space/x", "cifs")):
            ok, reason = self.check(path)
            self.assertFalse(ok, path)
            self.assertIn(fstype, reason)
            self.assertIn("STORAGE_UNSUITABLE", reason)

    def test_an_unknown_filesystem_is_refused_as_not_established(self):
        ok, reason = self.check("/home/u/odd/x")
        self.assertFalse(ok)
        self.assertIn("STORAGE_NOT_ESTABLISHED", reason)

    def test_unreadable_mount_information_is_refused(self):
        ok, reason = stateroot.storage_suitability("/home/u", mountinfo="/nonexistent/mi")
        self.assertFalse(ok)
        self.assertIn("STORAGE_NOT_ESTABLISHED", reason)


class UserRootChecks(unittest.TestCase):
    """STORE-026: an existing root that is not the invoking UID's 0700 directory is refused,
    never silently relocated."""

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base)

    def test_a_permissive_root_is_refused(self):
        root = os.path.join(self.base, "isedraf")
        os.mkdir(root, 0o755)
        os.chmod(root, 0o755)
        with self.assertRaises(stateroot.StateRootError):
            stateroot.check_user_root(root, os.geteuid())

    def test_a_foreign_owner_is_refused(self):
        root = os.path.join(self.base, "isedraf")
        os.mkdir(root, 0o700)
        with self.assertRaises(stateroot.StateRootError):
            stateroot.check_user_root(root, os.geteuid() + 1)

    def test_a_symlink_root_is_refused(self):
        target = os.path.join(self.base, "real")
        os.mkdir(target, 0o700)
        root = os.path.join(self.base, "isedraf")
        os.symlink(target, root)
        with self.assertRaises(stateroot.StateRootError):
            stateroot.check_user_root(root, os.geteuid())

    def test_the_invoking_users_private_directory_is_accepted(self):
        root = os.path.join(self.base, "isedraf")
        os.mkdir(root, 0o700)
        os.chmod(root, 0o700)
        stateroot.check_user_root(root, os.geteuid())
        stateroot.check_user_root(os.path.join(self.base, "absent"), os.geteuid())


class EndToEnd(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home)
        self.host = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.host)
        for rel, text in (("etc/machine-id", "3f9a1c0b7d2e4a68b5c6d7e8f9a0b1c2\n"),
                          ("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n"),
                          ("proc/sys/kernel/hostname", "h\n")):
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)

    def run_cli(self, argv, env, suitable=(True, None)):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(stateroot, "storage_suitability", return_value=suitable), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_an_audit_commits_user_production_evidence(self):
        env = {"HOME": self.home, "PATH": os.environ.get("PATH", "")}
        code, out, err = self.run_cli(["audit", "--root", self.host], env)
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)
        self.assertIn("UNPRIVILEGED", out)
        root = os.path.join(self.home, ".local", "state", "isedraf")
        self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
        snap = os.listdir(os.path.join(root, "snapshots"))[0]
        with open(os.path.join(root, "snapshots", snap, "manifest.json")) as fh:
            self.assertEqual(json.load(fh)["manifest_core"]["state_root"], "USER_PRODUCTION")
        self.assertEqual(verify.verify_store(root), [])

    def test_unsuitable_storage_refuses_before_anything_is_written(self):
        env = {"HOME": self.home, "PATH": os.environ.get("PATH", "")}
        code, _out, err = self.run_cli(
            ["audit", "--root", self.host], env,
            suitable=(False, "STORAGE_UNSUITABLE: nfs4"))
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertIn("STORAGE_UNSUITABLE", err)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "state", "isedraf")))

    def test_the_verifier_refuses_an_unknown_state_root_literal(self):
        env = {"HOME": self.home, "PATH": os.environ.get("PATH", "")}
        self.run_cli(["audit", "--root", self.host], env)
        root = os.path.join(self.home, ".local", "state", "isedraf")
        snap = os.listdir(os.path.join(root, "snapshots"))[0]
        path = os.path.join(root, "snapshots", snap, "manifest.json")
        with open(path) as fh:
            text = fh.read()
        os.chmod(path, 0o600)
        with open(path, "w") as fh:
            fh.write(text.replace('"USER_PRODUCTION"', '"PRODUCTION"'))
        self.assertTrue(any("state_root" in p for p in verify.verify_store(root)))


if __name__ == "__main__":
    unittest.main(verbosity=0)
