# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: ISE-PRIV-001 and ISE-PRIV-002 over the declared local sudo policy.
# Implements: D-131, D-111, EVAL-004
#
# The records come from the real sudo parser (sudo/sources.py); the section around them states
# its coverage explicitly, as a Full Audit through read_sudoers_graph_v1 would record it.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""D-131: the first PRIV criteria, every rule of their definitions."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import catalog                          # noqa: E402
from isedraf.evaluate import criteria                # noqa: E402
from isedraf.sudo import sources                     # noqa: E402

DIGESTS = {"manifest.json": "m", "sections/sudo.json": "u"}
ROOT_ENTRY = {"source": "/etc/sudoers", "operation_id": "read_sudoers_graph_v1",
              "status": "COLLECTED", "access_outcome": "READ_OK"}


def section(*files, root=None, status="COLLECTED", include_status="COLLECTED", malformed=None):
    """files: (path, text) pairs, read in this order, as the include graph would."""
    records, bad, ordinal = [], 0, 0
    for path, text in files:
        parsed, n = sources.parse(text, path, ordinal)
        records.extend(parsed)
        bad += n
        ordinal += len(parsed)
    return {"section": "sudo", "schema_version": criteria.SECTION_SCHEMA_VERSION,
            "collection_status": status, "reason": None,
            "evidence": {"records": records, "provenance": {
                "coverage": [root or ROOT_ENTRY], "include_status": include_status,
                "malformed_count": bad if malformed is None else malformed}}}


def run(cid, sec):
    registry, _raw = catalog.load()
    fn, _p, _n = criteria.EVALUATORS[cid]
    return fn(sec, catalog.criterion(registry, cid), DIGESTS)


def priv1(text):
    return run("ISE-PRIV-001", section(("/etc/sudoers", text)))


class Priv001(unittest.TestCase):

    def test_the_lab_account_general_grant_is_a_fail_as_defined(self):
        # Recorded as expected (owner 2026-11-23): the lab VMs carry this rule.
        r = priv1("lab ALL=(ALL) NOPASSWD: ALL\n")
        self.assertEqual(r[0:2], ("FAIL", "UNAUTHENTICATED_ALL_AS_ROOT"))
        self.assertEqual(r[3][0]["principals"], ["lab"])

    def test_groups_and_everyone_are_principals_too(self):
        self.assertEqual(priv1("%wheel ALL=(ALL) NOPASSWD: ALL\n")[0], "FAIL")
        self.assertEqual(priv1("ALL ALL=(ALL) NOPASSWD: ALL\n")[0], "FAIL")
        self.assertEqual(priv1("bob ALL=(root) NOPASSWD: ALL\n")[0], "FAIL")
        self.assertEqual(priv1("bob ALL= NOPASSWD: ALL\n")[0], "FAIL")      # no run-as: root

    def test_a_declaration_only_for_root_is_excluded(self):
        self.assertEqual(priv1("root ALL=(ALL) NOPASSWD: ALL\n")[0:2],
                         ("PASS", "NO_UNAUTHENTICATED_ALL_AS_ROOT"))

    def test_what_is_outside_the_criterion_passes(self):
        for text in ("%admin ALL=(ALL) ALL\n",                         # password required
                     "bob ALL=(postgres) NOPASSWD: ALL\n",              # not as root
                     "bob ALL=(:wheel) NOPASSWD: ALL\n",                # as the invoking user
                     "bob ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n"):   # not every command
            self.assertEqual(priv1(text)[0], "PASS", text)

    def test_an_alias_a_named_host_or_a_negation_that_decides_is_manual_review(self):
        cases = {
            "bob web1=(ALL) NOPASSWD: ALL\n": "a named or negated host",
            "User_Alias ADMINS = bob\nADMINS ALL=(ALL) NOPASSWD: ALL\n": "a principal alias",
            "Cmnd_Alias SHELLS = /bin/sh\nbob ALL=(ALL) NOPASSWD: SHELLS\n": "a command alias",
            "bob ALL=(ALL) NOPASSWD: ALL, !/usr/bin/su\n": "a negated command",
            "ALL, !bob ALL=(ALL) NOPASSWD: ALL\n": "a negated principal",
            "Runas_Alias OPS = root\nbob ALL=(OPS) NOPASSWD: ALL\n": "a run-as alias or negation",
        }
        for text, why in cases.items():
            r = priv1(text)
            self.assertEqual(r[0:2], ("MANUAL_REVIEW", "CANDIDATE_NOT_RESOLVED"), text)
            self.assertIn(why, r[3][0]["undecided_by"], text)

    def test_an_unresolved_candidate_blocks_pass_and_a_decisive_one_wins(self):
        self.assertEqual(priv1("bob web1=(ALL) NOPASSWD: ALL\n")[0], "MANUAL_REVIEW")
        r = priv1("bob web1=(ALL) NOPASSWD: ALL\nlab ALL=(ALL) NOPASSWD: ALL\n")
        self.assertEqual(r[0], "FAIL")
        self.assertEqual(sorted(o["kind"] for o in r[3]),
                         ["UNAUTHENTICATED_ALL_AS_ROOT", "UNRESOLVED_CANDIDATE"])

    def test_a_rule_without_run_as_runs_as_runas_default(self):
        # sudoers(5): "the command may only be run as the runas_default user (root by default)".
        self.assertEqual(priv1("Defaults runas_default=backup\nalice ALL=NOPASSWD: ALL\n")[0], "PASS")
        self.assertEqual(priv1("Defaults runas_default=root\nalice ALL=NOPASSWD: ALL\n")[0], "FAIL")
        self.assertEqual(priv1("alice ALL=NOPASSWD: ALL\n")[0], "FAIL")          # never set: root
        # An explicit (ALL) still includes root, whatever runas_default says.
        self.assertEqual(priv1("Defaults runas_default=backup\nalice ALL=(ALL) NOPASSWD: ALL\n")[0],
                         "FAIL")
        for text in ("Defaults:alice runas_default=backup\nalice ALL=NOPASSWD: ALL\n",
                     "Defaults runas_default=backup\nDefaults runas_default=root\n"
                     "alice ALL=NOPASSWD: ALL\n"):
            r = priv1(text)
            self.assertEqual(r[0], "MANUAL_REVIEW", text)
            self.assertIn("runas_default set in a way the evidence does not decide",
                          r[3][0]["undecided_by"], text)

    def test_insufficient_evidence_is_never_a_result(self):
        standard = dict(ROOT_ENTRY, operation_id=None)
        self.assertEqual(run("ISE-PRIV-001", section(("/etc/sudoers", "lab ALL=(ALL) NOPASSWD: ALL\n"),
                                                     root=standard))[0:2],
                         ("NOT_EVALUATED", "SOURCE_NOT_TESTED"))
        absent = dict(ROOT_ENTRY, status="NOT_TESTED", access_outcome="NOT_FOUND")
        r = run("ISE-PRIV-001", section(root=absent))
        self.assertEqual(r[0:2], ("NOT_EVALUATED", "SUDOERS_ABSENT"))
        self.assertIn("not established", r[2])
        self.assertEqual(run("ISE-PRIV-001", section(("/etc/sudoers", "lab ALL=(ALL) NOPASSWD: ALL\n"),
                                                     include_status="PARTIAL"))[0:2],
                         ("NOT_EVALUATED", "INCLUDES_INCOMPLETE"))
        self.assertEqual(run("ISE-PRIV-001", section(("/etc/sudoers", "lab ALL=(ALL) NOPASSWD: ALL\n"),
                                                     malformed=1))[0:2],
                         ("NOT_EVALUATED", "UNSUPPORTED_LINES"))

    def test_the_result_is_deterministic(self):
        text = "bob web1=(ALL) NOPASSWD: ALL\nlab ALL=(ALL) NOPASSWD: ALL\n"
        self.assertEqual(priv1(text), priv1(text))


def priv2(*files):
    return run("ISE-PRIV-002", section(*files))


class Priv002(unittest.TestCase):

    def test_a_global_bang_authenticate_is_a_fail(self):
        r = priv2(("/etc/sudoers", "Defaults !authenticate\n"))
        self.assertEqual(r[0:2], ("FAIL", "AUTHENTICATION_DISABLED"))
        self.assertEqual((r[3][0]["scope_type"], r[3][0]["scope_member"]), ("GLOBAL", "*"))

    def test_the_last_setting_in_one_file_decides(self):
        self.assertEqual(priv2(("/etc/sudoers",
                                "Defaults !authenticate\nDefaults authenticate\n"))[0], "PASS")
        self.assertEqual(priv2(("/etc/sudoers",
                                "Defaults authenticate\nDefaults !authenticate\n"))[0], "FAIL")

    def test_a_scope_is_its_type_and_each_member_as_written(self):
        r = priv2(("/etc/sudoers",
                   "Defaults:alice,bob !authenticate\nDefaults:bob authenticate\n"))
        self.assertEqual(r[0], "FAIL")
        self.assertEqual([(o["scope_type"], o["scope_member"]) for o in r[3]],
                         [("USER", "alice")])

    def test_an_alias_or_negated_scope_is_manual_review(self):
        for text in ("User_Alias ADMINS = bob\nDefaults:ADMINS !authenticate\n",
                     "Defaults:!bob !authenticate\n"):
            self.assertEqual(priv2(("/etc/sudoers", text))[0:2],
                             ("MANUAL_REVIEW", "SCOPE_NOT_RESOLVED"), text)

    def test_disagreeing_settings_in_several_files_are_manual_review(self):
        r = priv2(("/etc/sudoers", "Defaults !authenticate\n"),
                  ("/etc/sudoers.d/90-local", "Defaults authenticate\n"))
        self.assertEqual(r[0:2], ("MANUAL_REVIEW", "SCOPE_NOT_RESOLVED"))
        self.assertIn("order between files", r[3][0]["undecided_by"])

    def test_agreeing_settings_in_several_files_are_decided(self):
        r = priv2(("/etc/sudoers", "Defaults !authenticate\n"),
                  ("/etc/sudoers.d/90-local", "Defaults !authenticate\n"))
        self.assertEqual(r[0], "FAIL")

    def test_a_policy_that_never_sets_authenticate_passes(self):
        self.assertEqual(priv2(("/etc/sudoers", "Defaults env_reset\nroot ALL=(ALL) ALL\n"))[0:2],
                         ("PASS", "AUTHENTICATION_NOT_DISABLED"))

    def test_insufficient_evidence_is_never_a_result(self):
        absent = dict(ROOT_ENTRY, status="NOT_TESTED", access_outcome="NOT_FOUND")
        self.assertEqual(run("ISE-PRIV-002", section(root=absent))[0:2],
                         ("NOT_EVALUATED", "SUDOERS_ABSENT"))


class Registry(unittest.TestCase):

    def test_the_records_declare_exactly_what_the_evaluators_read(self):
        registry, _raw = catalog.load()
        for cid in ("ISE-PRIV-001", "ISE-PRIV-002"):
            record = catalog.criterion(registry, cid)
            self.assertTrue(criteria.pointers_match(record, criteria.EVALUATORS[cid][1]), cid)
            self.assertEqual(record["default_severity"], "high")
            self.assertEqual(record["introduced_in"], "0.6.0")
            self.assertEqual(record["evaluation_semantics"]["never_produced"], ["NOT_APPLICABLE"])


if __name__ == "__main__":
    unittest.main(verbosity=0)
