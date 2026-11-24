# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The two D-132 report additions - nullok beside ISE-ACCOUNT-002, maximum password age.
# Implements: D-132, OUT-010, SCOPE-063
#
# Both are read from the committed sections of the reported snapshot. The nullok observation is
# never part of the evaluation: the criterion keeps the result its committed evaluation recorded,
# NOT_EVALUATED included. The maximum password age keeps "no limit", a number of days (99999
# included) and "not collected" apart, with no threshold.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""D-132 (3): report additions."""
import copy
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, HERE)

from isedraf import report                                            # noqa: E402
from isedraf.report import model as report_model                      # noqa: E402
from isedraf.report import render                                     # noqa: E402
import test_report_route as route                                     # noqa: E402


def rule(service, rtype, module, args, line=1, kind="RULE"):
    return {"kind": kind, "service": service, "type": rtype, "module": module,
            "arguments": args, "control": "required", "source_line": line,
            "source_path": "/etc/pam.d/" + service}


def pam(records, status="COLLECTED"):
    return {"pam": {"collection_status": status, "reason": None,
                    "evidence": {"records": records}}}


class Nullok(unittest.TestCase):

    def test_only_an_auth_line_of_pam_unix_with_nullok_is_observed(self):
        block = report_model.pam_nullok(pam([
            rule("common-auth", "auth", "pam_unix.so", ["nullok", "try_first_pass"], 17),
            rule("common-password", "password", "pam_unix.so", ["nullok", "yescrypt"]),
            rule("system-auth", "auth", "/usr/lib64/security/pam_unix.so", ["nullok"], 5),
            rule("other", "auth", "pam_unix.so", ["nullok_secure"]),
            rule("other", "auth", "pam_unix_extra.so", ["nullok"]),
            rule("other", "auth", "pam_unix.so", ["nullok"], kind="UNSUPPORTED"),
        ]), "SDS-1")
        self.assertEqual(block["status"], "OBSERVED")
        self.assertEqual([(x["service"], x["source_path"], x["source_line"]) for x in block["lines"]],
                         [("common-auth", "/etc/pam.d/common-auth", 17),
                          ("system-auth", "/etc/pam.d/system-auth", 5)])
        self.assertEqual((block["beside"], block["snapshot_id"]), ("ISE-ACCOUNT-002", "SDS-1"))
        text = render.nullok_lines(block)
        self.assertIn("service common-auth (/etc/pam.d/common-auth line 17)", text[0])
        self.assertIn("keeps the result its committed evaluation recorded", text[-1])

    def test_none_found_is_said_only_as_far_as_the_section_allows(self):
        self.assertEqual(report_model.pam_nullok(pam([rule("login", "auth", "pam_unix.so", [])]),
                                                 "S")["status"], "NOT_OBSERVED")
        partial = report_model.pam_nullok(pam([], status="PARTIAL"), "S")
        self.assertEqual(partial["status"], "NOT_ESTABLISHED")
        self.assertIn("not excluded", render.nullok_lines(partial)[0])
        for sections in ({}, {"pam": {"collection_status": "NOT_TESTED", "evidence": None}}):
            block = report_model.pam_nullok(sections, "S")
            self.assertEqual(block["status"], "NOT_COLLECTED")
            self.assertIn("not collected", render.nullok_lines(block)[0])

    def test_the_criterion_keeps_its_committed_result_even_not_evaluated(self):
        native = {"status": "EVALUATED", "evaluation_id": "EVL-1", "results": [
            {"criterion_id": "ISE-ACCOUNT-002", "criterion_version": 1, "result": "NOT_EVALUATED",
             "reason": "shadow not read", "scope": "local accounts", "observations": []}]}
        before = copy.deepcopy(native)
        block = report_model.pam_nullok(pam([rule("common-auth", "auth", "pam_unix.so",
                                                  ["nullok"], 3)]), "S")
        md = render._native_markdown(native, block)
        self.assertEqual(native, before)
        self.assertIn("| ISE-ACCOUNT-002 v1 | NOT_EVALUATED | — | shadow not read |", md)
        at = md.index("- ISE-ACCOUNT-002 scope: local accounts")
        self.assertIn("pam_unix with nullok", md[at + 1])

    def test_without_an_evaluation_the_observation_is_still_shown(self):
        block = report_model.pam_nullok(pam([rule("login", "auth", "pam_unix.so", ["nullok"])]), "S")
        md = render._native_markdown({"status": "NO_EVALUATION", "reason": "not evaluated"}, block)
        self.assertTrue(any("pam_unix with nullok" in line for line in md))


def account(name, uid, shadow=None, relation="PRESENT", line=1):
    return {"name": name, "uid": uid, "passwd_line": line, "shadow_record": relation,
            "shadow": shadow, "name_bytes_hex": None}


def ages(accounts, status="COLLECTED", reason=None):
    return {"accounts": {"collection_status": status, "reason": reason,
                         "evidence": {"local_accounts": accounts}}}


class MaxAge(unittest.TestCase):

    def test_no_limit_days_and_not_collected_stay_apart(self):
        block = report_model.password_max_age(ages([
            account("root", 0, {"max_days": 99999, "max_days_source": "OBSERVED"}),
            account("svc", 990, {"max_days": None, "max_days_source": "UNSPECIFIED"}),
            account("alice", 1000, {"max_days": 90, "max_days_source": "OBSERVED"}),
            account("bob", 1001, {"max_days": -1, "max_days_source": "OBSERVED"}),
            account("bad", 1002, {"max_days": None, "max_days_source": "MALFORMED"}),
            account("ghost", 1003, relation="ABSENT_FROM_COLLECTED_SOURCE"),
            account("unread", 1004, relation="SOURCE_NOT_COLLECTED"),
        ]), "S")
        got = [(r["name"], r["max_age"], r["max_days"]) for r in block["rows"]]
        self.assertEqual(got, [("root", "DAYS", 99999), ("svc", "NO_LIMIT", None),
                               ("alice", "DAYS", 90), ("bob", "DAYS", -1),
                               ("bad", "NOT_COLLECTED", None), ("ghost", "NOT_COLLECTED", None),
                               ("unread", "NOT_COLLECTED", None)])
        text = [render.max_age_text(r) for r in block["rows"]]
        self.assertEqual(text, ["99999 days (as written)", "no limit (field empty)",
                                "90 days (as written)", "-1 days (as written)",
                                "not collected (field malformed)",
                                "not collected (no /etc/shadow record)",
                                "not collected (/etc/shadow not read (SOURCE_NOT_COLLECTED))"])

    def test_an_incomplete_accounts_section_is_stated(self):
        block = report_model.password_max_age(ages([], status="PARTIAL", reason="shadow unreadable"),
                                              "S")
        md = "\n".join(render._max_age_markdown(block))
        self.assertIn("The accounts section is PARTIAL: shadow unreadable.", md)
        self.assertIn("No local account record", md)
        self.assertEqual(report_model.password_max_age({}, "S")["rows"], [])


class Rendering(unittest.TestCase):

    def setUp(self):
        self.case = route.ReportRoute("test_the_root_side_reads_the_ledger_and_the_d50_snapshot_only")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.root

    def test_both_formats_carry_both_additions(self):
        committed = report.committed_run(self.root)
        m = report.build(self.root, committed["sections"]["inventory"]["evidence"],
                         audit_sections=committed["sections"], audit_digests=committed["digests"])
        self.assertEqual(m["report_schema_version"], 5)
        self.assertIn("status", m["pam_nullok"])
        md, html = report.render.to_markdown(m), report.render.to_html(m)
        for text in (md, html):
            self.assertIn("Maximum password age per local account", text)
            self.assertIn("ISE-ACCOUNT-002 report observation (PAM", text)

    def test_a_report_without_audit_sections_has_neither(self):
        committed = report.committed_run(self.root)
        m = report.build(self.root, committed["sections"]["inventory"]["evidence"])
        self.assertIsNone(m["pam_nullok"])
        self.assertIsNone(m["password_max_age"])
        self.assertNotIn("Maximum password age", report.render.to_markdown(m))


if __name__ == "__main__":
    unittest.main(verbosity=0)
