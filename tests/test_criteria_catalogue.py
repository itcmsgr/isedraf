# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The native criteria catalogue is the registry, in a file a spreadsheet opens.
# Implements: D-130, D-111, EVAL-002
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================
"""D-130: NATIVE_CRITERIA.csv - generated, UTF-8 without BOM, RFC 4180, CRLF, one row each."""
import copy
import csv
import io
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "scripts" / "docs"))

from isedraf import catalog       # noqa: E402
import criteria_catalogue as cc   # noqa: E402


class Catalogue(unittest.TestCase):

    def setUp(self):
        self.registry, _raw = catalog.load()
        self.data = (ROOT / "docs" / "reference" / "NATIVE_CRITERIA.csv").read_bytes()

    def test_the_committed_file_is_exactly_the_generated_one(self):
        self.assertEqual(self.data.decode("utf-8"), cc.render(self.registry))
        self.assertEqual(cc.problems(), [])

    def test_utf8_without_bom_and_crlf_line_ends(self):
        self.assertFalse(self.data.startswith(b"\xef\xbb\xbf"))
        self.data.decode("utf-8")
        self.assertEqual(self.data.count(b"\n"), self.data.count(b"\r\n"))
        self.assertTrue(self.data.endswith(b"\r\n"))

    def test_a_csv_reader_round_trips_one_row_per_admitted_criterion(self):
        rows = list(csv.reader(io.StringIO(self.data.decode("utf-8"), newline="")))
        self.assertEqual(rows[0], [name for name, _get in cc.COLUMNS])
        self.assertEqual([r[0] for r in rows[1:]],
                         [c["criterion_id"] for c in self.registry["criteria"]])
        self.assertTrue(all(len(r) == len(cc.COLUMNS) for r in rows))
        for row in rows[1:]:
            self.assertTrue(all("\n" not in cell and "\r" not in cell for cell in row))

    def test_criterion_version_and_release_are_separate_columns(self):
        rows = list(csv.DictReader(io.StringIO(self.data.decode("utf-8"), newline="")))
        for row, record in zip(rows, self.registry["criteria"]):
            self.assertEqual(row["criterion_version"], str(record["version"]))
            self.assertEqual(row["introduced_in_release"], record["introduced_in"])
            self.assertEqual(row["family"], record["criterion_id"].split("-")[1])
            self.assertIn("necessary, not sufficient", row["collection_requirements"])

    def test_quoting_survives_commas_quotes_and_non_ascii(self):
        registry = copy.deepcopy(self.registry)
        registry["criteria"][0]["title"] = 'A "quoted", comma é title'
        rows = list(csv.reader(io.StringIO(cc.render(registry), newline="")))
        self.assertEqual(rows[1][2], 'A "quoted", comma é title')

    def test_a_cell_that_would_run_as_a_formula_is_refused(self):
        # A leading tab or carriage return never reaches a cell: one_line() normalises whitespace.
        self.assertEqual(cc.one_line("\tX\r"), "X")
        for lead in ("=", "+", "-", "@"):
            registry = copy.deepcopy(self.registry)
            registry["criteria"][0]["title"] = lead + "SUM(A1)"
            with mock.patch.object(cc.catalog, "load", return_value=(registry, None)):
                found = cc.problems()
            self.assertTrue(any("formula" in p for p in found), (lead, found))

    def test_a_stale_file_and_a_missing_criterion_are_reported(self):
        registry = copy.deepcopy(self.registry)
        registry["criteria"][0]["title"] = "A different title"
        with mock.patch.object(cc.catalog, "load", return_value=(registry, None)):
            self.assertTrue(any("stale" in p for p in cc.problems()))
        registry = copy.deepcopy(self.registry)
        registry["criteria"].append(dict(registry["criteria"][0], criterion_id="ISE-SSH-999"))
        with mock.patch.object(cc.catalog, "load", return_value=(registry, None)):
            self.assertTrue(any("the catalogue lists" in p for p in cc.problems()))


if __name__ == "__main__":
    unittest.main(verbosity=0)
