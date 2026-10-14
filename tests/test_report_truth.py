# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The v0.2 report says what the Full Audit evidence says, and no more (F1-F5).
# Implements: AUTH-009, AUTH-031, AUTH-032, SCOPE-020, D-79
#
# The report-truth review of 2026-10-10 against the four-platform Full Audit reports found:
# F1 the HTML privilege line showed the store class, not AUTH-009's FULL_AUDIT; F2 the Markdown
# report hid the SSH dimensions; F3 the SSH dimensions shared one status; F4 no acquisition
# authority was shown; F5 the authorized-keys limit of Full Audit was not stated. Standard and
# 0.1.x reports must not change.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""F1-F5: report truth for Full Audit runs."""
import copy
import io
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, HERE)

from isedraf import cli, report                                       # noqa: E402
from isedraf.report import model as report_model                      # noqa: E402
from isedraf.report import sections                                   # noqa: E402
import test_report_route as route                                     # noqa: E402


def ssh_evidence(declared, resolved, n_declared=3, n_settings=5, declared_reason=None,
                 resolved_reason=None):
    records = ([{"kind": "DIRECTIVE"}] * n_declared
               + ([{"kind": "RESOLVED_SETTING"}] * n_settings if resolved == "COLLECTED" else []))
    return {"records": records,
            "provenance": {"declared": {"status": declared, "reason": declared_reason},
                           "resolved": {"status": resolved, "reason": resolved_reason}}}


class Dimensions(unittest.TestCase):

    def test_each_dimension_keeps_its_own_status(self):
        cases = [("COLLECTED", "COLLECTED"), ("PARTIAL", "COLLECTED"), ("COLLECTED", "ERROR"),
                 ("NOT_TESTED", "NOT_TESTED"), ("ERROR", "NOT_TESTED")]
        for declared, resolved in cases:
            dims = sections.ssh_dimensions(ssh_evidence(
                declared, resolved, declared_reason="D-REASON", resolved_reason="R-REASON"))
            self.assertEqual([d[1] for d in dims], [declared, resolved, "NOT_TESTED"],
                             (declared, resolved))
            self.assertEqual("D-REASON" in dims[0][2], declared != "COLLECTED")
            self.assertEqual(dims[1][2], "5 settings" if resolved == "COLLECTED" else "R-REASON")

    def test_the_match_row_never_claims_universal_effect(self):
        label, status, detail = sections.ssh_dimensions(ssh_evidence("COLLECTED", "COLLECTED"))[2]
        self.assertEqual(status, "NOT_TESTED")
        self.assertIn("not resolved by this audit", detail)
        for row in sections.ssh_dimensions(ssh_evidence("COLLECTED", "COLLECTED")):
            self.assertNotIn("all connections", " ".join(row).lower())
        self.assertIn("global only", sections.ssh_dimensions(
            ssh_evidence("COLLECTED", "COLLECTED"))[1][0])

    def test_a_section_without_the_declared_record_says_so(self):
        evidence = ssh_evidence("COLLECTED", "COLLECTED")
        del evidence["provenance"]["declared"]
        self.assertEqual(sections.ssh_dimensions(evidence)[0][1], "NOT RECORDED SEPARATELY")

    def test_a_declared_only_section_has_no_dimensions(self):
        self.assertIsNone(sections.ssh_dimensions({"records": [], "provenance": {}}))
        self.assertEqual(sections.dimensions("ssh", {"evidence": {"records": [],
                                                                  "provenance": {}}}), [])


class Authority(unittest.TestCase):

    def test_it_is_derived_from_the_manifest_as_recorded(self):
        manifest = {"sources": [
            {"acquisition_mode": "SUPERVISOR_FIXED_OPERATION", "operation_id": "read_x_v1",
             "domain": "ssh"},
            {"acquisition_mode": "SUPERVISOR_FIXED_OPERATION", "operation_id": "read_x_v1",
             "domain": "ssh"},
            {"acquisition_mode": "SUPERVISOR_FIXED_OPERATION", "operation_id": "read_y_v1",
             "domain": "sudo"},
            {"acquisition_mode": "CURRENT_IDENTITY", "domain": "pam"},
            {"acquisition_mode": "SOMETHING_ELSE", "domain": "mounts"},
            {"domain": "nss"}]}
        text = report_model.acquisition_authority(manifest)
        self.assertIn("3 source(s) through fixed privileged operations: read_x_v1 (ssh, 2), "
                      "read_y_v1 (sudo, 1)", text)
        self.assertIn("1 by the audit's own reduced identity (CURRENT_IDENTITY)", text)
        self.assertIn("1 with acquisition mode SOMETHING_ELSE", text)
        self.assertIn("1 with acquisition mode not recorded", text)
        self.assertIsNone(report_model.acquisition_authority(None))


class Rendering(unittest.TestCase):

    def setUp(self):
        self.case = route.ReportRoute("test_the_root_side_reads_the_ledger_and_the_d50_snapshot_only")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.root

    def model(self, full_audit):
        committed = report.committed_run(self.root)
        real = report_model.identity_evidence

        def identity(root):
            block = real(root)
            if full_audit:
                block["run_mode"] = "FULL_AUDIT"
                block["state_root_class"] = "SYSTEM_PRODUCTION"
            return block
        sections_in = copy.deepcopy(committed["sections"])
        if full_audit:
            sections_in["ssh"]["evidence"] = ssh_evidence("COLLECTED", "COLLECTED")
        with mock.patch.object(report_model, "identity_evidence", identity):
            return report.build(self.root, sections_in["inventory"]["evidence"],
                                audit_sections=sections_in, audit_digests=committed["digests"],
                                coverage_manifest=committed.get("evidence_limits"))

    def test_full_audit_markdown_and_html_say_the_same(self):
        m = self.model(True)
        md, html = report.render.to_markdown(m), report.render.to_html(m)
        for label in ("Declared configuration", "Global effective configuration (sshd -T, global only)",
                      "Match-dependent (connection-specific) values"):
            self.assertIn("SSH server configuration · %s" % label, md)
            self.assertIn(label, html)
        self.assertIn("| Acquisition authority |", md)
        self.assertIn("Acquisition authority", html)
        self.assertIn(report_model.FULL_AUDIT_KEYS_LIMITATION, md)
        self.assertIn("PRIVILEGE LEVEL: FULL_AUDIT", html)                 # F1, AUTH-009
        self.assertNotIn("PRIVILEGE LEVEL: SYSTEM_PRODUCTION", html)

    def test_a_standard_report_keeps_its_shape(self):
        m = self.model(False)
        self.assertNotIn("acquisition_authority", m)
        self.assertFalse(any("dimensions" in s for s in m["audit_sections"].values()))
        self.assertNotIn(report_model.FULL_AUDIT_KEYS_LIMITATION, m["limitations"])
        self.assertIn("PRIVILEGE LEVEL: UNPRIVILEGED", report.render.to_html(m))
        self.assertNotIn("Acquisition authority", report.render.to_markdown(m))


if __name__ == "__main__":
    unittest.main()
