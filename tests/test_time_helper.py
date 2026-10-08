# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: A failing optional time helper is a recorded limitation, never silence.
# Implements: SCOPE-022, PRIV-021, REC-005
#
# IQ-054 fix (1), standard route. When chronyc is present and `chronyc tracking` fails, the
# time source, stratum and offset stay null. Before this fix the time subdomain still said
# COLLECTED, which claims a complete observation that did not happen.
#
# Unprivileged and fixture-only: helpers are scripted, nothing runs a host tool.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""IQ-054 (1): chronyc failure makes the time subdomain PARTIAL HELPER_FAILED."""
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))

from isedraf import hostio                                      # noqa: E402
from isedraf.inventory import collectors                        # noqa: E402

TIMEDATECTL = "Timezone=UTC\nNTP=yes\nNTPSynchronized=yes\n"
TRACKING = "Reference ID    : 5F85C251 (x)\nStratum         : 2\nSystem time     : 0.000001872 seconds fast\n"


class Scripted(object):
    def __init__(self, results):
        self.results, self.calls = results, []

    def __call__(self, argv, timeout=None):
        self.calls.append(list(argv))
        return self.results.get(argv[0], hostio.Outcome(ok=False, reason="NOT_TESTED"))


class TimeIsNeverSilentlyComplete(unittest.TestCase):

    def collect(self, results, chronyc=True):
        run = Scripted(results)
        with mock.patch.object(collectors, "run", run), \
                mock.patch.object(collectors, "_live", lambda root: True), \
                mock.patch.object(collectors, "which",
                                  lambda name: "/usr/bin/chronyc"
                                  if chronyc and name == "chronyc" else None):
            block = collectors.collect_time("/")
        return block, run.calls

    def test_a_working_chronyc_is_collected(self):
        block, _calls = self.collect({"timedatectl": hostio.Outcome(value=TIMEDATECTL),
                                      "chronyc": hostio.Outcome(value=TRACKING)})
        self.assertEqual(block["collection_status"], "COLLECTED")
        self.assertIsNone(block["reason"])
        self.assertEqual(block["data"]["stratum"], 2)
        self.assertEqual(block["data"]["offset_nanoseconds"], 1872)

    def test_a_failing_chronyc_is_never_silently_collected(self):
        block, _calls = self.collect({"timedatectl": hostio.Outcome(value=TIMEDATECTL),
                                      "chronyc": hostio.Outcome(ok=False, reason="ERROR")})
        self.assertEqual(block["collection_status"], "PARTIAL")
        self.assertTrue(block["reason"].startswith("HELPER_FAILED: "), block["reason"])
        self.assertIn("possible", block["reason"])
        self.assertIsNone(block["data"]["stratum"])
        self.assertIsNone(block["data"]["source"])
        self.assertIsNone(block["data"]["offset_nanoseconds"])
        # what was observed is kept
        self.assertTrue(block["data"]["synchronized"])

    def test_both_limitations_are_kept_when_timedatectl_also_fails(self):
        block, _calls = self.collect({"chronyc": hostio.Outcome(ok=False, reason="ERROR")})
        self.assertEqual(block["collection_status"], "PARTIAL")
        self.assertTrue(block["reason"].startswith("NOT_TESTED: timedatectl"), block["reason"])
        self.assertIn("HELPER_FAILED: ", block["reason"])

    def test_without_chronyc_nothing_changes(self):
        block, calls = self.collect({"timedatectl": hostio.Outcome(value=TIMEDATECTL)},
                                    chronyc=False)
        self.assertFalse([c for c in calls if c[0] == "chronyc"], calls)
        self.assertEqual(block["collection_status"], "COLLECTED")
        self.assertIsNone(block["reason"])


if __name__ == "__main__":
    unittest.main()
