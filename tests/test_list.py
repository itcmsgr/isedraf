# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: isedraf list shows what the store holds from committed metadata, and changes nothing.
# Implements: D-129, SNAP-018, STORE-001
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""v0.5 R1: isedraf list (D-129 point 11)."""
import contextlib
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

from isedraf import cli, exitcodes, listing, report, summary          # noqa: E402

FIXTURE_HOST = {"etc/machine-id": "0123456789abcdef0123456789abcdef\n",
                "etc/passwd": "root:x:0:0:root:/root:/bin/sh\n",
                "etc/group": "root:x:0:\n"}


def digest_tree(base):
    h = hashlib.sha256()
    for top, dirs, files in sorted(os.walk(base)):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(top, name)
            st = os.lstat(path)
            h.update(("%s %o %d\n" % (os.path.relpath(path, base), st.st_mode,
                                      st.st_size)).encode())
            with open(path, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()


class List(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base)
        self.host = os.path.join(self.base, "host")
        for rel, text in FIXTURE_HOST.items():
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        self.store = os.path.join(self.base, "store")
        patcher = mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.store})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def audit(self):
        code, _out, err = self.run_cli(["audit", "--root", self.host])
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)

    def test_no_store_yet_is_not_an_error(self):
        code, out, err = self.run_cli(["list"])
        self.assertEqual((code, err), (exitcodes.OK, ""))
        self.assertIn("No evidence store yet", out)
        self.assertIn("isedraf audit", out)
        self.assertFalse(os.path.exists(self.store))

    def test_committed_runs_are_listed_from_the_ledger(self):
        self.audit()
        self.audit()
        found = listing.collect(self.store)
        self.assertEqual(len(found["runs"]), 2)
        code, out, err = self.run_cli(["list"])
        self.assertEqual((code, err), (exitcodes.OK, ""))
        self.assertIn("| isedraf list", out.splitlines()[1])
        self.assertIn("Runs (2 committed; collection time, UTC):", out)
        for run in found["runs"]:
            self.assertIn("  %s  %s\n" % (run["snapshot_id"], run["collected_at"]), out)
        self.assertIn("Baseline:\n  none approved", out)

    def test_listing_changes_nothing(self):
        self.audit()
        before = digest_tree(self.store)
        self.run_cli(["list", "--all"])
        self.assertEqual(digest_tree(self.store), before)

    def test_an_unledgered_snapshot_is_counted_never_listed(self):
        self.audit()
        stray = os.path.join(self.store, "snapshots", "SDS-20261115T000000Z-0000000000000000")
        os.makedirs(stray)
        code, out, _err = self.run_cli(["list"])
        self.assertEqual(code, exitcodes.OK)
        self.assertNotIn("SDS-20261115T000000Z-0000000000000000", out)
        self.assertIn("1 snapshot directory is not in the ledger", out)

    def test_saved_reports_are_listed_with_absolute_paths(self):
        self.audit()
        code, out, err = self.run_cli(["report", "--save"])
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)
        self.assertTrue(os.path.isabs(out.strip()), out)            # R2: one absolute path
        self.assertIn("View it with less:\n  %s" % out.strip(), err)
        found = listing.collect(self.store)
        self.assertEqual(len(found["reports"]), 1)
        path = found["reports"][0]["path"]
        self.assertTrue(os.path.isabs(path) and os.path.isfile(path))
        self.assertIn(path, self.run_cli(["list"])[1])

    def test_only_the_newest_are_shown_without_all(self):
        runs = [{"snapshot_id": "SDS-%02d" % i, "collected_at": "t%d" % i, "state_root": "DEV"}
                for i in range(summary.LIST_NEWEST + 3)]
        found = {"runs": runs, "baselines": [], "evaluations": [], "reports": [],
                 "unledgered": 0}
        text = summary.listing_text(found, "DEV", "/s")
        self.assertIn("... 3 older; isedraf list --all shows every one", text)
        self.assertNotIn("SDS-00 ", text)
        self.assertIn("SDS-00 ", summary.listing_text(found, "DEV", "/s", show_all=True))

    def test_a_personal_store_that_does_not_conform_is_refused_with_67(self):
        xdg = os.path.join(self.base, "xdg")
        os.makedirs(os.path.join(xdg, "isedraf"), mode=0o755)
        os.chmod(os.path.join(xdg, "isedraf"), 0o755)
        env = dict((k, v) for k, v in os.environ.items() if k != "ISEDRAF_STATE_ROOT")
        env["XDG_STATE_HOME"] = xdg
        with mock.patch.dict(os.environ, env, clear=True):
            code, out, err = self.run_cli(["list"])
        self.assertEqual(code, exitcodes.STATE_ROOT_UNUSABLE, err)
        self.assertIn("Nothing was read or written.", err)

    def test_a_full_listing_fits_80_columns_with_identifiers_whole(self):
        sid = "SDS-20261112T200325Z-e95505c94e37e402"
        found = {"runs": [{"snapshot_id": sid, "collected_at": "2026-11-12T20:03:25Z",
                           "state_root": "SYSTEM_PRODUCTION"}],
                 "baselines": [{"revision": "BL-000001", "snapshot_id": sid,
                                "approved_at": "2026-11-12T20:03:26Z"}],
                 "evaluations": [{"evaluation_id": "EVL-20261112T200327Z-487ba10290238ab1",
                                  "identity_only": True}],
                 "reports": [], "unledgered": 2}
        text = summary.listing_text(found, "SYSTEM_PRODUCTION", "/var/lib/isedraf")
        for line in text.splitlines():
            self.assertLessEqual(len(line), 80, line)
        self.assertIn("  BL-000001  for %s\n    approved 2026-11-12T20:03:26Z" % sid, text)
        self.assertIn("%s  2026-11-12T20:03:25Z  [baseline]" % sid, text)

    def test_the_reports_directory_is_the_one_report_writes(self):
        self.assertEqual(listing.REPORTS_DIRECTORY, report.REPORTS_DIRECTORY)


if __name__ == "__main__":
    unittest.main(verbosity=0)
