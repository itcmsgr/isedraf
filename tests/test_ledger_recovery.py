# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: STORE-016 ledger recovery: torn tails kept and sealed, nothing lost, nothing doubled.
# Implements: STORE-016, STORE-010, STORE-022, STORE-024, D-129
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""STORE-016 (v0.5): short write, ENOSPC, interruption at each recovery step, repetition."""
import contextlib
import errno
import hashlib
import io
import os
import pathlib
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import cli, exitcodes, ledger, verify                     # noqa: E402
from isedraf.launcher import reportunit                                 # noqa: E402

HOST = {"etc/machine-id": "0123456789abcdef0123456789abcdef\n",
        "etc/passwd": "root:x:0:0:root:/root:/bin/sh\n", "etc/group": "root:x:0:\n"}
WHEN, EVT = "2026-11-16T21:00:00Z", "EVT-20261116T210000Z-0123456789abcdef"


def ledger_only(fault):
    """os.write that applies `fault` to ledger and recovery-staging writes only."""
    real = os.write

    def write(fd, data):
        try:
            path = os.readlink("/proc/self/fd/%d" % fd)
        except OSError:
            path = ""
        if "/ledger/" in path or "ledger-recovery-" in path:
            return fault(real, fd, data)
        return real(fd, data)
    return write


def short_write(real, fd, data):
    return real(fd, data[:20])


def no_space(real, fd, data):
    raise OSError(errno.ENOSPC, "No space left on device")


class Store(unittest.TestCase):

    def setUp(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        self.host = os.path.join(base, "host")
        for rel, text in HOST.items():
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        self.root = os.path.join(base, "root")
        patch = mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.root})
        patch.start()
        self.addCleanup(patch.stop)

    def audit(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["audit", "--root", self.host])
        return code, out.getvalue(), err.getvalue()

    def segment(self, number=1):
        return ledger.segment_path(self.root, number)

    def tear(self, keep=30):
        """A torn tail: the first `keep` bytes of a record that was never completed."""
        with open(self.segment(), "rb") as fh:
            whole = fh.read()
        last = whole[whole.rstrip(b"\n").rfind(b"\n") + 1:]
        with open(self.segment(), "ab") as fh:
            fh.write(last[:keep])
        return last[:keep]

    def bytes_of(self, number=1):
        with open(self.segment(number), "rb") as fh:
            return fh.read()

    def recover(self, **kw):
        return ledger.recover(self.root, "DEV", WHEN, EVT, **kw)


class Recovery(Store):

    def test_a_torn_tail_is_kept_byte_for_byte_and_sealed(self):
        self.audit()
        self.audit()
        tail = self.tear()
        damaged = self.bytes_of(1)
        before = [r["record_hash"] for r in ledger.read_records(self.root)]
        core = self.recover()
        self.assertEqual(core["damaged_segment"], "segment-000001.jsonl")
        self.assertEqual(core["torn_tail_hash"], "sha256:" + hashlib.sha256(tail).hexdigest())
        self.assertEqual(core["verified_length"], len(damaged) - len(tail))
        self.assertEqual(self.bytes_of(1), damaged)                 # never rewritten
        self.assertEqual(stat.S_IMODE(os.stat(self.segment(1)).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.segment(2)).st_mode), 0o600)
        rows = ledger.read_records(self.root)
        self.assertEqual([r["record_hash"] for r in rows[:-1]], before)   # nothing lost
        self.assertEqual(rows[-1]["record_core"]["event"], "ledger_recovered")
        self.assertEqual(verify.verify_store(self.root), [])

    def test_the_ledger_continues_in_the_new_segment_and_runs_go_on(self):
        self.audit()
        self.tear()
        code, _out, err = self.audit()
        self.assertIn(code, (0, 2), err)
        self.assertIn("LEDGER_RECOVERED: segment-000001.jsonl", err)
        rows = ledger.read_records(self.root)
        self.assertEqual([r["record_core"]["event"] for r in rows],
                         ["snapshot_committed", "ledger_recovered", "snapshot_committed"])
        self.assertEqual([r["record_core"]["sequence"] for r in rows], [1, 2, 3])
        self.assertEqual(len(self.bytes_of(2).splitlines()), 2)
        self.assertEqual(verify.verify_store(self.root), [])

    def test_a_second_recovery_of_the_same_segment_never_happens(self):
        self.audit()
        self.tear()
        self.recover()
        self.assertIsNone(self.recover())
        self.assertEqual(ledger.segment_names(self.root),
                         ["segment-000001.jsonl", "segment-000002.jsonl"])

    def test_an_intact_ledger_is_not_touched(self):
        self.audit()
        before = self.bytes_of(1)
        self.assertIsNone(self.recover())
        self.assertEqual(self.bytes_of(1), before)
        self.assertEqual(ledger.segment_names(self.root), ["segment-000001.jsonl"])

    def test_repeated_audits_after_a_recovery_stay_verified(self):
        self.audit()
        self.tear()
        for _ in range(3):
            code, _o, err = self.audit()
            self.assertIn(code, (0, 2), err)
        rows = ledger.read_records(self.root)
        self.assertEqual(len(rows), 5)
        self.assertEqual(verify.verify_store(self.root), [])


class Refusals(Store):
    """Only an interruption of the last record is recovered; anything else is refused."""

    def assert_refused_unchanged(self):
        before = dict((n, self.bytes_of(int(n[8:14]))) for n in ledger.segment_names(self.root))
        with self.assertRaises(ledger.IntegrityFailure):
            self.recover()
        after = dict((n, self.bytes_of(int(n[8:14]))) for n in ledger.segment_names(self.root))
        self.assertEqual(after, before)
        code, _out, err = self.audit()
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertIn("LEDGER_INTEGRITY_FAILURE", err)
        self.assertIn("Nothing was collected or written.", err)

    def test_a_damaged_earlier_record_is_refused(self):
        self.audit()
        self.audit()
        data = self.bytes_of(1)
        with open(self.segment(), "wb") as fh:
            fh.write(data.replace(b"snapshot_committed", b"snapshot_comXitted", 1))
        self.assert_refused_unchanged()

    def test_a_complete_last_line_that_does_not_verify_is_refused(self):
        self.audit()
        with open(self.segment(), "ab") as fh:
            fh.write(b'{"record_core": {}, "record_hash": "sha256:00"}\n')
        self.assert_refused_unchanged()

    def test_a_sealed_segment_that_changes_afterwards_is_an_integrity_failure(self):
        self.audit()
        self.tear()
        self.recover()
        with open(self.segment(1), "ab") as fh:
            fh.write(b"x")
        self.assertTrue(any("ledger_recovered" in p or "LEDGER_INTEGRITY_FAILURE" in p
                            for p in verify.verify_store(self.root)))

    def test_a_tail_longer_than_one_record_is_refused(self):
        self.audit()
        with open(self.segment(), "ab") as fh:
            fh.write(b"x" * (ledger.TAIL_BOUND + 1))
        with self.assertRaises(ledger.IntegrityFailure):
            self.recover()


class Interruptions(Store):
    """A new interruption during recovery: no loss, no duplicate, no false success."""

    def test_short_write_on_append_is_refused_and_recovered_by_the_next_run(self):
        self.audit()
        with mock.patch.object(ledger.os, "write", ledger_only(short_write)):
            code, _out, err = self.audit()
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertIn("No run was committed", err)
        self.assertIsNotNone(ledger.torn_tail(self.root))
        self.assertEqual(len(ledger.unledgered_snapshots(self.root)), 1)
        code, _out, err = self.audit()                 # the next run recovers, then commits
        self.assertIn(code, (0, 2), err)
        self.assertIn("LEDGER_RECOVERED", err)
        self.assertIsNone(ledger.torn_tail(self.root))

    def test_enospc_on_append_writes_no_record_and_reports_68(self):
        self.audit()
        before = self.bytes_of(1)
        with mock.patch.object(ledger.os, "write", ledger_only(no_space)):
            code, _out, err = self.audit()
        self.assertEqual(code, exitcodes.INSUFFICIENT_SPACE)
        self.assertEqual(self.bytes_of(1), before)

    def test_enospc_during_recovery_changes_nothing_and_is_68(self):
        self.audit()
        self.tear()
        damaged = self.bytes_of(1)
        with mock.patch.object(ledger.os, "write", ledger_only(no_space)):
            code, _out, err = self.audit()
        self.assertEqual(code, exitcodes.INSUFFICIENT_SPACE)
        self.assertIn("Nothing was collected or written.", err)
        self.assertEqual(self.bytes_of(1), damaged)
        self.assertEqual(ledger.segment_names(self.root), ["segment-000001.jsonl"])
        self.assertIsNotNone(self.recover())           # once there is room, it completes

    def test_an_interruption_before_the_rename_leaves_the_store_as_it_was(self):
        self.audit()
        self.tear()
        damaged = self.bytes_of(1)

        def stop():
            raise KeyboardInterrupt("stopped between the steps")
        with self.assertRaises(KeyboardInterrupt):
            self.recover(before_rename=stop)
        self.assertEqual(self.bytes_of(1), damaged)
        self.assertEqual(ledger.segment_names(self.root), ["segment-000001.jsonl"])
        core = self.recover()                          # repeated: completes exactly once
        self.assertEqual(core["damaged_segment"], "segment-000001.jsonl")
        self.assertIsNone(self.recover())
        self.assertEqual(verify.verify_store(self.root), [])

    def test_a_short_write_of_the_recovery_record_never_becomes_a_segment(self):
        self.audit()
        self.tear()
        with mock.patch.object(ledger.os, "write", ledger_only(short_write)):
            with self.assertRaises(ledger.WriteIncomplete):
                self.recover()
        self.assertEqual(ledger.segment_names(self.root), ["segment-000001.jsonl"])
        self.assertIsNotNone(self.recover())


class ReadOnlyRoutes(Store):

    def test_the_root_side_reads_every_segment_and_refuses_an_unrecovered_tail(self):
        self.audit()
        self.tear()
        segments = ledger.read_segments(self.root)
        with self.assertRaises(reportunit.Refused) as caught:
            reportunit.verified_cores(segments)
        self.assertIn("LEDGER_TORN_TAIL", str(caught.exception))
        self.recover()
        cores = reportunit.verified_cores(ledger.read_segments(self.root))
        self.assertEqual([c["event"] for c in cores], ["snapshot_committed", "ledger_recovered"])

    def test_report_list_and_evaluate_refuse_and_write_nothing(self):
        # The owner's distinction (2026-11-16): evaluate writes evaluations, never the ledger;
        # like report and list it never recovers. All three refuse an unrecovered tail with 64.
        self.audit()
        self.tear()
        damaged = self.bytes_of(1)
        evaluations = os.path.join(self.root, "evaluations")
        before = sorted(os.listdir(evaluations)) if os.path.isdir(evaluations) else []
        for argv in (["report"], ["report", "--json"], ["list"], ["evaluate"]):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
            self.assertEqual(code, exitcodes.USAGE_OR_ENGINE, argv)
            self.assertIn("LEDGER_TORN_TAIL", err.getvalue(), argv)
            self.assertEqual(self.bytes_of(1), damaged, argv)
            self.assertEqual(ledger.segment_names(self.root), ["segment-000001.jsonl"], argv)
            after = sorted(os.listdir(evaluations)) if os.path.isdir(evaluations) else []
            self.assertEqual(after, before, argv)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main(["report"])
        self.assertIn("next: isedraf audit", err.getvalue())

    def test_the_root_report_refusal_fits_80_columns(self):
        self.audit()
        self.tear()
        err = io.StringIO()
        with mock.patch.object(reportunit.store, "OWNER_UID", os.getuid()), \
                mock.patch.object(reportunit.store, "OWNER_GID", os.getgid()):
            code = reportunit.run("markdown", self.root, err, engine_uid=os.getuid())
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertIn("LEDGER_TORN_TAIL", err.getvalue())
        for line in err.getvalue().splitlines():
            self.assertLessEqual(len(line), 80, line)

    def test_the_four_rc1_messages_fit_80_columns_with_tokens_whole(self):
        # 0.5.0-rc1 acceptance found these four over 80 columns (owner: fix in rc2).
        self.audit()
        self.tear()
        texts = {}
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["evaluate"])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        texts["user evaluate"] = err.getvalue()
        from isedraf.launcher import evalunit
        err = io.StringIO()
        with mock.patch.object(reportunit.store, "OWNER_UID", os.getuid()), \
                mock.patch.object(reportunit.store, "OWNER_GID", os.getgid()):
            code = evalunit.run(self.root, err, io.StringIO(), engine_uid=os.getuid(),
                                state_root_class="DEV")
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        texts["root evaluate"] = err.getvalue()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["audit", "--root", self.host])
        self.assertIn(code, (0, 2))
        texts["recovered"] = err.getvalue()
        from isedraf import summary
        texts["notice"] = summary.recovered_notice("segment-000123.jsonl")
        for name, text in texts.items():
            self.assertTrue(text, name)
            for line in text.splitlines():
                self.assertLessEqual(len(line), 80, "%s: %s" % (name, line))
        for name, token in (("user evaluate", "LEDGER_TORN_TAIL:"), ("root evaluate",
                             "LEDGER_TORN_TAIL:"), ("recovered", "LEDGER_RECOVERED:")):
            words = texts[name].split()               # each token and ID whole, never split
            self.assertIn(token, words, name)
            self.assertIn("segment-000001.jsonl", words, name)

    def test_verify_reports_an_unrecovered_tail_and_names_what_recovers_it(self):
        self.audit()
        self.tear()
        problems = verify.verify_store(self.root)
        self.assertTrue(any("LEDGER_TORN_TAIL" in p and "next audit" in p for p in problems))


if __name__ == "__main__":
    unittest.main(verbosity=0)
