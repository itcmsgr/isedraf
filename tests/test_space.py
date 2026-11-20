# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The free-space preflight refuses a run that does not fit, writes nothing, deletes nothing.
# Implements: STORE-016, STORE-022, D-129
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""v0.5 S1: free-space preflight (D-129 Q4), user route and Full Audit launcher."""
import errno
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

from isedraf import cli, exitcodes, space                             # noqa: E402
from isedraf.launcher import unit                                      # noqa: E402

MIB = space.MIB


def tree(base):
    return sorted(os.path.relpath(os.path.join(t, n), base)
                  for t, ds, fs in os.walk(base) for n in ds + fs)


class Estimate(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def snapshot(self, name, size):
        path = os.path.join(self.root, "snapshots", name, "sections")
        os.makedirs(path)
        with open(os.path.join(path, "x.json"), "wb") as fh:
            fh.write(b"x" * size)

    def test_a_store_without_snapshots_is_estimated_at_the_floor(self):
        self.assertEqual(space.run_estimate(self.root), space.RUN_FLOOR)
        self.assertEqual(space.run_estimate(os.path.join(self.root, "absent")), space.RUN_FLOOR)

    def test_a_large_recent_snapshot_raises_the_estimate_by_the_margin(self):
        self.snapshot("SDS-20261101T000000Z-0000000000000001", 1 * MIB)
        self.snapshot("SDS-20261102T000000Z-0000000000000002", 3 * MIB)
        self.assertEqual(space.run_estimate(self.root), space.RUN_MARGIN * 3 * MIB)

    def test_only_the_newest_snapshots_are_measured(self):
        self.snapshot("SDS-20260101T000000Z-0000000000000001", 9 * MIB)   # old, large
        for day in range(2, 2 + space.RECENT_SNAPSHOTS):
            self.snapshot("SDS-202611%02dT000000Z-000000000000000%d" % (day, day), 1024)
        self.assertEqual(space.run_estimate(self.root), space.RUN_FLOOR)

    def test_a_link_in_a_snapshot_is_never_followed(self):
        self.snapshot("SDS-20261101T000000Z-0000000000000001", 10)
        big = os.path.join(self.root, "big")
        with open(big, "wb") as fh:
            fh.write(b"x" * (3 * MIB))
        os.symlink(big, os.path.join(self.root, "snapshots",
                                     "SDS-20261101T000000Z-0000000000000001", "link"))
        self.assertEqual(space.run_estimate(self.root), space.RUN_FLOOR)


class Preflight(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def test_enough_space_passes(self):
        with mock.patch.object(space, "available", return_value=1024 * MIB):
            free, estimate = space.preflight(self.root)
        self.assertEqual(estimate, space.RUN_FLOOR)

    def test_the_recovery_reserve_is_required_on_top_of_the_run(self):
        just_short = space.RUN_FLOOR + space.RECOVERY_RESERVE - 1
        with mock.patch.object(space, "available", return_value=just_short):
            with self.assertRaises(space.InsufficientSpace) as caught:
                space.preflight(self.root)
        exc = caught.exception
        self.assertEqual(exc.required, space.RUN_FLOOR + space.RECOVERY_RESERVE)
        text = str(exc)
        self.assertTrue(text.startswith("INSUFFICIENT_SPACE: "))
        self.assertIn("available; this run needs 9.0 MiB (8.0 MiB estimated for the run, "
                      "1.0 MiB kept for a ledger recovery record)", text)

    def test_out_of_space_is_recognised_through_the_cause_chain(self):
        try:
            try:
                raise OSError(errno.ENOSPC, "No space left on device")
            except OSError as inner:
                raise ValueError("commit failed") from inner
        except ValueError as outer:
            self.assertTrue(space.out_of_space(outer))
        self.assertTrue(space.out_of_space(OSError(errno.EDQUOT, "quota")))
        self.assertFalse(space.out_of_space(OSError(errno.EACCES, "denied")))
        self.assertFalse(space.out_of_space(None))


class UserRoute(unittest.TestCase):
    """A refused run collects nothing, writes nothing, and exits 68."""

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base)
        self.store = os.path.join(self.base, "store")
        patcher = mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.store})
        patcher.start()
        self.addCleanup(patcher.stop)

    def audit(self):
        out, err = io.StringIO(), io.StringIO()
        args = type("A", (), {"root": "/nonexistent-host-root"})()
        code = cli.cmd_audit(args, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def test_too_little_space_refuses_before_anything_is_written_or_collected(self):
        collect = mock.Mock(side_effect=AssertionError("collected"))
        with mock.patch.object(space, "available", return_value=1 * MIB), \
                mock.patch.object(cli.identity, "collect", collect), \
                mock.patch.object(cli.audit_mod, "collect", collect):
            code, out, err = self.audit()
        self.assertEqual(code, exitcodes.INSUFFICIENT_SPACE)
        self.assertEqual(out, "")
        self.assertIn("INSUFFICIENT_SPACE", err)
        self.assertIn("1.0 MiB available", err)
        self.assertIn("Nothing was collected or written.", err)
        self.assertIn("never deletes evidence", err)
        self.assertEqual(tree(self.base), [])                 # not even the store root

    def test_a_disk_that_fills_during_the_commit_is_68_and_not_committed(self):
        os.makedirs(self.store, mode=0o700)
        fill = mock.Mock(side_effect=OSError(errno.ENOSPC, "No space left on device"))
        with mock.patch.object(space, "available", return_value=1024 * MIB), \
                mock.patch.object(cli.ledger, "append", fill):
            code, out, err = self.audit()
        self.assertEqual(code, exitcodes.INSUFFICIENT_SPACE)
        self.assertIn("filled during the run", err)
        self.assertIn("No run was committed", err)
        self.assertFalse(os.path.exists(os.path.join(self.store, "ledger", "segment-000001.jsonl"))
                         and os.path.getsize(os.path.join(self.store, "ledger",
                                                          "segment-000001.jsonl")))


class FullAuditLauncher(unittest.TestCase):

    def test_the_launcher_refuses_with_68_before_preparing_the_store(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base)
        prepare = mock.Mock(side_effect=AssertionError("store prepared"))
        err = io.StringIO()
        with mock.patch.object(space, "available", return_value=1 * MIB), \
                mock.patch.object(unit.store, "prepare", prepare):
            code = unit.run("RUN-20261115T000000Z-0123456789abcdef", root=base, err=err)
        self.assertEqual(code, exitcodes.INSUFFICIENT_SPACE)
        self.assertIn("INSUFFICIENT_SPACE", err.getvalue())
        self.assertEqual(tree(base), [])
        for line in err.getvalue().splitlines():           # rc2: 80 columns, path whole
            self.assertLessEqual(len(line), 80, line)
        self.assertIn(base, err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=0)
