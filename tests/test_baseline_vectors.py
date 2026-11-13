# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: v0.4 golden vectors: production reproduces the independently generated values.
# Implements: NORM-039, SCOPE-073, SCOPE-074, SCOPE-045, SCOPE-047
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""test-vectors/v04/v1: profile hash, BL-000001, section projections."""
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
VEC = ROOT / "test-vectors" / "v04" / "v1"

from isedraf.baseline import profile, projection, revision      # noqa: E402

sys.path.insert(0, str(ROOT / "scripts" / "vectors"))
import v04_tables                                                # noqa: E402


class Vectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = json.loads((VEC / "cases.json").read_text())
        cls.expected = json.loads((VEC / "expected.json").read_text())

    def test_tables_are_the_production_tables(self):
        """A reclassification changes the vectors visibly (SCOPE-047)."""
        self.assertEqual(json.loads((VEC / "tables.json").read_text()), v04_tables.tables())

    def test_reference_reproduces(self):
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "vectors" /
                                                  "v04_reference.py"), "--check"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_profile(self):
        self.assertEqual(self.cases["profile"], profile.DEFAULT)
        self.assertEqual(profile.profile_bytes(profile.DEFAULT).decode("utf-8"),
                         self.expected["profile_canonical"])
        self.assertEqual(profile.profile_hash(profile.DEFAULT), self.expected["profile_hash"])

    def test_baseline_revision(self):
        b = self.expected["baseline"]
        self.assertEqual(revision.revision_hash(b["manifest_hash"],
                                                self.expected["profile_hash"]),
                         b["revision_hash"])

    def test_sections(self):
        for case, exp in zip(self.cases["sections"], self.expected["sections"]):
            self.assertEqual(case["case"], exp["case"])
            name, sect = case["name"], case["section"]
            self.assertEqual(projection.projection_bytes(name, sect).decode("utf-8"),
                             exp["projection_canonical"], case["case"])
            self.assertEqual(projection.state_hash(name, sect), exp["state_hash"])
            self.assertEqual(projection.method_fingerprint(name, sect),
                             exp["method_fingerprint"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
