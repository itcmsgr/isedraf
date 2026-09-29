# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Replay the recorded glibc differential corpus against the account parser.
# Implements: GOV-002, IDENT-041, IDENT-060, SCOPE-022
#
# The make-check half of the differential harness (owner ruling N1/N2, 2026-09-26). The
# corpus holds generated cases with glibc's recorded answers, so this replay needs no
# namespace and no glibc: every case must still satisfy the owner's table - MATCH, or
# explicit PARTIAL / untrusted - and never a confident different result. The sweep in
# tests/glibc_differential.py regenerates the answers from the live glibc and records any
# new mismatch as a case.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================
"""Every recorded case matches glibc or is explicitly conservative."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import glibc_differential as differential                       # noqa: E402


class RecordedGlibcCorpus(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(differential.CORPUS) as fh:
            cls.corpus = json.load(fh)

    def test_the_corpus_covers_every_class_the_harness_found(self):
        ids = [entry["case"]["id"] for entry in self.corpus]
        for prefix in ("pw-prefix-", "pw-name-", "sh-name-", "pw-uid-", "gr-gid-",
                       "pw-trailer-", "sh-trailer-", "gr-members-", "sh-age-", "sh-dup-",
                       "gr-line-", "bare-", "empty-name", "cp-name-", "cp-bare-",
                       "mix-bare-", "amb-name-", "undecl-name-", "p7-", "rnd-"):
            self.assertTrue(any(i.startswith(prefix) for i in ids), prefix)
        self.assertGreaterEqual(len(ids), 1000)

    def test_every_case_carries_the_nss_configuration_it_was_measured_under(self):
        # IQ-036: file syntax without the configuration that gives it meaning is not a case.
        for entry in self.corpus:
            self.assertIn("nsswitch", entry["case"], entry["case"]["id"])

    def test_every_case_matches_glibc_or_is_explicitly_conservative(self):
        failing = []
        for entry in self.corpus:
            problems = differential.compare(entry["case"], entry["glibc"])
            if problems:
                failing.append("%s: %s" % (entry["case"]["id"], problems[0][:200]))
        self.assertEqual(failing, [], "\n".join(failing[:20]))


if __name__ == "__main__":
    unittest.main(verbosity=0)
