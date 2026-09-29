# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: A bounded read that stopped early is never complete evidence.
# Implements: SCOPE-022, GOV-002
#
# Owner invariant (2026-09-24): truncated input is NEVER COLLECTED-complete. hostio read up
# to OUTPUT_LIMIT (1 MiB) and returned what it had as a successful read, so a UID-0 account
# past the first MiB of /etc/passwd vanished while the source reported COLLECTED.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""Bounded reads report truncation instead of hiding it."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf import coverage, hostio                              # noqa: E402
from isedraf.accounts import acquire, model                       # noqa: E402


class Truncation(unittest.TestCase):

    def file_of(self, size):
        fd, path = tempfile.mkstemp()
        os.write(fd, b"x" * size)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_a_file_exactly_at_the_limit_is_read_completely(self):
        for read in (hostio.read_file, hostio.read_file_lossless):
            outcome = read(self.file_of(hostio.OUTPUT_LIMIT))
            self.assertTrue(outcome.ok, read.__name__)
            self.assertEqual(len(outcome.value), hostio.OUTPUT_LIMIT)

    def test_one_byte_past_the_limit_is_truncated_never_ok(self):
        for read in (hostio.read_file, hostio.read_file_lossless):
            outcome = read(self.file_of(hostio.OUTPUT_LIMIT + 1))
            self.assertFalse(outcome.ok, read.__name__)
            self.assertEqual(outcome.detail, hostio.TRUNCATED, read.__name__)
            self.assertEqual(outcome.reason, "SOURCE_TRUNCATED", read.__name__)

    def test_a_small_explicit_limit_is_honoured_the_same_way(self):
        outcome = hostio.read_file(self.file_of(11), limit=10)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.detail, hostio.TRUNCATED)

    def test_truncation_is_a_coverage_outcome(self):
        entry = coverage.source("test", "etc/x", model.ERROR, hostio.TRUNCATED,
                                coverage.OP_FILE_READ, reason="SOURCE_TRUNCATED",
                                universe=coverage.UNIVERSE_INCOMPLETE)
        self.assertEqual(entry["access_outcome"], hostio.TRUNCATED)


class SpecialFiles(unittest.TestCase):

    def test_a_fifo_is_refused_not_waited_on(self):
        # Hardening red team F10: os.open on a FIFO with no writer blocks forever.
        import signal
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base)
        fifo = os.path.join(base, "passwd")
        os.mkfifo(fifo)

        def hang(signum, frame):
            raise AssertionError("the read blocked on a FIFO")
        previous = signal.signal(signal.SIGALRM, hang)
        signal.alarm(5)
        try:
            outcome = hostio.read_file_lossless(fifo)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.reason, "SOURCE_NOT_REGULAR")


class TruncatedAccountSourceIsNeverCollected(unittest.TestCase):

    def test_an_account_past_the_limit_never_yields_collected(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.mkdir(os.path.join(root, "etc"))
        head = b"root:x:0:0::/r:/bin/sh\n"
        filler = b"#" + b"x" * (hostio.OUTPUT_LIMIT - len(head) - 2) + b"\n"
        with open(os.path.join(root, "etc", "passwd"), "wb") as fh:
            fh.write(head + filler + b"evil:x:0:0::/r:/bin/sh\n")
        for name, text in (("group", b"root:x:0:\n"), ("shadow", b"root:*:1:0:9:7:::\n")):
            with open(os.path.join(root, "etc", name), "wb") as fh:
                fh.write(text)
        r = acquire.collect(root)
        self.assertNotEqual(r["sources"]["etc/passwd"]["status"], model.COLLECTED)
        self.assertNotEqual(r["collection_status"], model.COLLECTED)
        self.assertIn("TRUNCATED", r["sources"]["etc/passwd"]["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=0)
