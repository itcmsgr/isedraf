# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: sudo isedraf list reads the system store's metadata only and never changes it.
# Implements: AUTH-035, AUTH-019, AUTH-032, D-129
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""AUTH-035: the read-only system-store listing (D-129 point 12), and the H8/H9 refusals."""
import fcntl
import hashlib
import io
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import cli, ledger, stateroot, summary                   # noqa: E402
from isedraf.launcher import listunit, outer, store                   # noqa: E402

UID, GID = os.getuid(), os.getgid()
HOST = {"etc/machine-id": "0123456789abcdef0123456789abcdef\n",
        "etc/passwd": "root:x:0:0:root:/root:/bin/sh\n", "etc/group": "root:x:0:\n"}


def fingerprint(base):
    h = hashlib.sha256()
    for top, dirs, files in sorted(os.walk(base)):
        dirs.sort()
        for name in sorted(dirs + files):
            path = os.path.join(top, name)
            st = os.lstat(path)
            h.update(("%s %o %d %d\n" % (os.path.relpath(path, base), st.st_mode, st.st_size,
                                         st.st_mtime_ns)).encode())
    return h.hexdigest()


class ListRoute(unittest.TestCase):

    def setUp(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        host = os.path.join(base, "host")
        for rel, text in HOST.items():
            path = os.path.join(host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        self.root = os.path.join(base, "root")
        with mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.root}):
            for _ in range(2):
                code = cli.cmd_audit(type("A", (), {"root": host})(), out=io.StringIO(),
                                     err=io.StringIO())
                self.assertIn(code, (0, 2))
        for patch in (mock.patch.object(store, "OWNER_UID", UID),
                      mock.patch.object(store, "OWNER_GID", GID)):
            patch.start()
            self.addCleanup(patch.stop)

    def run_list(self, scope="newest", root=None):
        out, err = io.StringIO(), io.StringIO()
        code = listunit.run(scope, root or self.root, out, err)
        return code, out.getvalue(), err.getvalue()

    def test_runs_come_from_the_ledger(self):
        code, out, err = self.run_list()
        self.assertEqual((code, err), (0, ""))
        self.assertIn("| sudo isedraf list", out.splitlines()[1])
        self.assertIn("Runs (2 committed; collection time, UTC):", out)
        for core in ledger.snapshot_records(self.root):
            self.assertIn(core["snapshot_id"], out)
        for line in out.splitlines():                       # 80 columns, IDs whole
            self.assertLessEqual(len(line), 80, line)

    def test_the_listing_never_touches_the_store(self):
        before = fingerprint(self.root)
        self.run_list("all")
        self.assertEqual(fingerprint(self.root), before)

    def test_no_snapshot_file_or_evaluation_artifact_is_opened(self):
        evl = os.path.join(self.root, "evaluations", "EVL-20261116T000000Z-0123456789abcdef")
        os.makedirs(evl, mode=0o700)
        os.chmod(os.path.join(self.root, "evaluations"), 0o700)
        opened = []
        real_open = os.open

        def watch(path, *a, **k):
            opened.append(path)
            return real_open(path, *a, **k)
        with mock.patch.object(os, "open", watch):
            code, out, _err = self.run_list()
        self.assertEqual(code, 0)
        self.assertIn("EVL-20261116T000000Z-0123456789abcdef", out)
        self.assertIn("identities only", out)
        for path in opened:
            self.assertNotIn("/snapshots/", path)
            self.assertNotIn("/evaluations/", path)

    def test_the_system_listing_shows_the_private_export_not_saved_reports(self):
        _code, out, _err = self.run_list()
        self.assertIn(summary.EXPORT_COMMAND, out)

    def test_an_unledgered_snapshot_is_counted_never_listed(self):
        stray = "SDS-20261116T000000Z-0000000000000000"
        os.makedirs(os.path.join(self.root, "snapshots", stray), mode=0o700)
        _code, out, _err = self.run_list()
        self.assertNotIn(stray, out)
        self.assertIn("1 snapshot directory is not in the ledger", out)

    def test_a_held_lock_is_66_with_the_next_command(self):
        fd = os.open(os.path.join(self.root, stateroot.LOCK_NAME), os.O_RDONLY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, _out, err = self.run_list()
        self.assertEqual(code, 66)
        self.assertIn("next: wait for the other ISEDRAF run to finish", err)

    def test_a_non_conforming_store_is_67_and_untouched(self):
        os.chmod(self.root, 0o755)
        before = fingerprint(self.root)
        code, _out, err = self.run_list()
        self.assertEqual(code, 67)
        self.assertIn("Nothing was read or written.", err)
        self.assertEqual(fingerprint(self.root), before)

    def test_an_absent_store_is_reported_never_created(self):
        absent = self.root + "-absent"
        code, out, _err = self.run_list(root=absent)
        self.assertEqual(code, 0)
        self.assertIn("never created at runtime", out)
        self.assertFalse(os.path.lexists(absent))


class RootRoute(unittest.TestCase):
    """The list forms are admitted and run in the read-only unit; the refusals explain."""

    def test_the_list_unit_is_the_report_unit_without_write_access(self):
        argv = outer.list_unit_argv("RUN-20261116T000000Z-0123456789abcdef", "all")
        self.assertIn("--property", argv)
        props = [argv[i + 1] for i, a in enumerate(argv) if a == "--property"]
        self.assertEqual(tuple(props), outer.REPORT_PROPERTIES)
        self.assertFalse(any(p.startswith("ReadWritePaths=") for p in props))
        self.assertEqual(argv[-2:], ["RUN-20261116T000000Z-0123456789abcdef", "all"])

    def test_list_forms_are_admitted_and_no_other_list_form(self):
        self.assertEqual(set(outer.LIST_INVOCATIONS), {("list",), ("list", "--all")})
        err = io.StringIO()
        with mock.patch.object(os, "geteuid", return_value=0):
            for argv in (["list", "--json"], ["list", "/var/lib/isedraf"], ["list", "all"]):
                self.assertEqual(outer.main(argv, err), 70, argv)

    def test_the_refusal_names_the_list_route_and_the_private_export(self):
        self.assertIn("  sudo isedraf list ", outer.REFUSAL)
        self.assertIn(summary.EXPORT_COMMAND, outer.REFUSAL)
        self.assertIn("Nothing was collected or written.", outer.REFUSAL)
        for line in ("isedraf: " + outer.REFUSAL).splitlines():   # only the first is prefixed
            self.assertLessEqual(len(line), 80, line)

    def test_a_sudo_entered_account_is_told_why_and_what_works(self):
        err = io.StringIO()
        with mock.patch.object(os, "geteuid", return_value=1000):
            self.assertEqual(outer.main(["audit"], err), 70)
        text = err.getvalue()
        self.assertIn("started through sudo for a non-root account", text)
        self.assertIn("su - <account>", text)
        self.assertIn("SCOPE-071", text)
        for line in text.splitlines():
            self.assertLessEqual(len(line), 80, line)


class PlainRefusals(unittest.TestCase):
    """H8: plain words first; the reason token stays whole; what was written; what next."""

    def test_a_personal_store_baseline_refusal_says_where_baselines_come_from(self):
        text = summary.explained("BASELINE_CLASS_NOT_ADMITTED", "USER_PRODUCTION (BASE-021)",
                                 "Approval refused; nothing was written.")
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("isedraf: this is your personal evidence store"))
        self.assertIn("  reason: BASELINE_CLASS_NOT_ADMITTED: USER_PRODUCTION (BASE-021)", lines)
        self.assertIn("  Approval refused; nothing was written.", lines)
        self.assertTrue(lines[-1].startswith("  next: sudo isedraf audit"))

    def test_each_blocking_section_keeps_its_own_line(self):
        text = summary.explained("INCOMPLETE_FOR_BASELINE",
                                 "profile p requires a, b; not COLLECTED in SDS-x:\n  a is "
                                 "PARTIAL: r1\n  b is NOT_TESTED: r2", "Nothing was written.")
        self.assertIn("    - a is PARTIAL: r1", text)
        self.assertIn("    - b is NOT_TESTED: r2", text)

    def test_tokens_ids_and_paths_are_never_split(self):
        long_id = "SDS-20261116T000000Z-0123456789abcdef"
        text = summary.explained("FULL_AUDIT_UNSUPPORTED", ("x " * 40) + long_id +
                                 " /var/lib/isedraf/snapshots", "Nothing was written.")
        self.assertIn(long_id, text)
        self.assertIn("/var/lib/isedraf/snapshots", text)
        for line in text.splitlines():
            self.assertLessEqual(len(line), summary.WIDTH, line)


if __name__ == "__main__":
    unittest.main(verbosity=0)
