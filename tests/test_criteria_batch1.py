# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: ISE-ACCOUNT-002, -003, -004 and ISE-SSH-001 - every justified result and boundary.
# Implements: D-121, D-125, CMP-003, EVAL-004, ISE-ACCOUNT-002, ISE-ACCOUNT-003,
#             ISE-ACCOUNT-004, ISE-SSH-001
#
# Account criteria run on real fixture audits (the fixture's /etc/shadow is readable, so
# a DEV audit collects it) plus synthetic objects for states the collector cannot produce.
# ISE-SSH-001 runs on synthetic ssh sections shaped as the collector writes them.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================
"""The second batch of native criteria (owner ruling 2026-11-04)."""
import copy
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import audit, catalog, exitcodes                       # noqa: E402
from isedraf.evaluate import criteria                               # noqa: E402

PASSWD = "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n"
SHADOW_OK = "root:*:19000:0:99999:7:::\nalice:!:19000::::::\n"
SHA512 = "$6$" + "s" * 16 + "$" + "h" * 86
MD5 = "$1$" + "s" * 8 + "$" + "h" * 22
HOST = {"etc/machine-id": "3f9a1c0b7d2e4a68b5c6d7e8f9a0b1c2\n", "etc/passwd": PASSWD,
        "etc/group": "root:x:0:\nalice:x:1000:\nbob:x:1001:\n", "etc/shadow": SHADOW_OK,
        "etc/nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\n",
        "etc/hostname": "fx\n", "proc/sys/kernel/hostname": "fx\n"}
DIGESTS = {"manifest.json": "m", "sections/accounts.json": "a", "sections/ssh.json": "s"}


def record(cid):
    registry, _raw = catalog.load()
    return catalog.criterion(registry, cid)


class Accounts(unittest.TestCase):
    """Real fixture audits: the accounts section exactly as the collector writes it."""

    def section(self, **files):
        host = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, host)
        merged = dict(HOST, **files)
        for rel, text in merged.items():
            path = os.path.join(host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        sections, _status = audit.collect(host)
        return json.loads(json.dumps(sections["accounts"]))

    def run_rule(self, cid, section):
        fn, _p, _n = criteria.EVALUATORS[cid]
        return fn(section, record(cid), DIGESTS)

    # -- ISE-ACCOUNT-002 ---------------------------------------------------------------

    def test_002_pass_locked_and_disabled_are_not_empty(self):
        r = self.run_rule("ISE-ACCOUNT-002", self.section())
        self.assertEqual(r[:2], ("PASS", "NO_EMPTY_SHADOW_PASSWORD_FIELD"))

    def test_002_fail_on_an_empty_unlocked_shadow_field(self):
        r = self.run_rule("ISE-ACCOUNT-002", self.section(**{"etc/shadow": "root:*:19000:0:99999:7:::\nalice::19000::::::\n"}))
        self.assertEqual(r[:2], ("FAIL", "EMPTY_SHADOW_PASSWORD_FIELD"))
        self.assertEqual([o["name"] for o in r[3]], ["alice"])
        self.assertIn("not a test of whether a login succeeds", r[2])

    def test_002_an_account_without_a_shadow_record_is_not_evaluated(self):
        r = self.run_rule("ISE-ACCOUNT-002", self.section(**{"etc/shadow": "root:*:19000:0:99999:7:::\n"}))
        self.assertEqual(r[:2], ("NOT_EVALUATED", "SHADOW_RECORD_ABSENT"))
        self.assertIn("IQ-077", r[2])

    def test_002_shadow_not_collected_is_not_evaluated(self):
        s = self.section()
        s["evidence"]["sources"]["etc/shadow"]["status"] = "NOT_TESTED"
        for a in s["evidence"]["local_accounts"]:
            a["shadow_record"], a["shadow"] = "SOURCE_NOT_COLLECTED", None
        self.assertEqual(self.run_rule("ISE-ACCOUNT-002", s)[:2], ("NOT_EVALUATED", "SOURCE_NOT_TESTED"))

    # -- ISE-ACCOUNT-003 ---------------------------------------------------------------

    def test_003_pass_with_unique_uids(self):
        self.assertEqual(self.run_rule("ISE-ACCOUNT-003", self.section())[:2], ("PASS", "UIDS_UNIQUE"))

    def test_003_fail_when_two_names_share_a_uid(self):
        r = self.run_rule("ISE-ACCOUNT-003", self.section(**{
            "etc/passwd": PASSWD + "bob:x:1000:1001::/home/bob:/bin/sh\n",
            "etc/shadow": SHADOW_OK + "bob:!:19000::::::\n"}))
        self.assertEqual(r[:2], ("FAIL", "UID_SHARED_BY_NAMES"))
        self.assertEqual(r[3][0]["kind"], "UID_SHARED_BY_NAMES")

    def synthetic(self):
        s = self.section()
        rows = s["evidence"]["local_accounts"]
        return s, rows

    def test_003_one_name_with_two_uids_is_manual_review_when_both_lines_are_kept(self):
        s, rows = self.synthetic()
        twin = copy.deepcopy(rows[1])
        twin.update(uid=1005, passwd_line=3)
        rows.append(twin)
        r = self.run_rule("ISE-ACCOUNT-003", s)
        self.assertEqual(r[:2], ("MANUAL_REVIEW", "NAME_WITH_SEVERAL_UIDS"))

    def test_003_a_collision_takes_precedence_over_ambiguity(self):
        s, rows = self.synthetic()
        twin = copy.deepcopy(rows[1]); twin.update(uid=1005, passwd_line=3)
        other = copy.deepcopy(rows[1]); other.update(name="carol", name_bytes_hex="6361726f6c",
                                                     uid=1000, passwd_line=4)
        rows.extend([twin, other])
        self.assertEqual(self.run_rule("ISE-ACCOUNT-003", s)[:2], ("FAIL", "UID_SHARED_BY_NAMES"))

    def test_003_a_repeated_identical_entry_is_an_observation_only(self):
        s, rows = self.synthetic()
        twin = copy.deepcopy(rows[1]); twin.update(passwd_line=3)
        rows.append(twin)
        r = self.run_rule("ISE-ACCOUNT-003", s)
        self.assertEqual(r[0], "PASS")
        self.assertEqual([o["kind"] for o in r[3]], ["REPEATED_ENTRY"])

    def test_003_partial_passwd_is_not_evaluated(self):
        r = self.run_rule("ISE-ACCOUNT-003", self.section(**{"etc/passwd": PASSWD + "broken\n"}))
        self.assertEqual(r[:2], ("NOT_EVALUATED", "SOURCE_PARTIAL"))

    # -- ISE-ACCOUNT-004 ---------------------------------------------------------------

    def test_004_pass_with_a_non_md5_hash(self):
        r = self.run_rule("ISE-ACCOUNT-004", self.section(**{"etc/shadow": "root:%s:19000:0:99999:7:::\nalice:!:19000::::::\n" % SHA512}))
        self.assertEqual(r[:2], ("PASS", "NO_MD5_PASSWORD_HASH"))

    def test_004_fail_on_md5_even_when_locked(self):
        r = self.run_rule("ISE-ACCOUNT-004", self.section(**{"etc/shadow": "root:*:19000:0:99999:7:::\nalice:!%s:19000::::::\n" % MD5}))
        self.assertEqual(r[:2], ("FAIL", "MD5_PASSWORD_HASH"))
        self.assertEqual((r[3][0]["hash_scheme"], r[3][0]["locked"]), ("MD5_CRYPT", True))
        self.assertIn("not whether the account can log in", r[2])

    def test_004_other_never_passes(self):
        des = "ab" + "c" * 11                        # traditional DES: no $id$ prefix
        r = self.run_rule("ISE-ACCOUNT-004", self.section(**{"etc/shadow": "root:%s:19000:0:99999:7:::\nalice:!:19000::::::\n" % des}))
        self.assertEqual(r[:2], ("NOT_EVALUATED", "UNCLASSIFIED_PASSWORD_FIELD"))

    def test_004_an_orphan_shadow_line_blocks_pass(self):
        r = self.run_rule("ISE-ACCOUNT-004", self.section(**{"etc/shadow": SHADOW_OK + "ghost:%s:19000::::::\n" % SHA512}))
        self.assertEqual(r[:2], ("NOT_EVALUATED", "SHADOW_STATE_NOT_RECORDED"))

    # -- malformed is refused ----------------------------------------------------------

    def test_undefined_states_are_refused(self):
        base = self.section()
        mutations = [
            lambda e: e["local_accounts"][0].update(shadow_record="MAYBE"),
            lambda e: e["local_accounts"][0]["shadow"]["password_state"].update(content="BLANK"),
            lambda e: e["local_accounts"][0]["shadow"]["password_state"].update(lock_prefix="?"),
            lambda e: e["local_accounts"][0]["shadow"]["password_state"].update(hash_scheme="SHA512_CRYPT"),
            lambda e: e["local_accounts"][0].update(shadow_record="ABSENT_FROM_COLLECTED_SOURCE"),
            lambda e: e.update(orphan_shadow_records="none"),
        ]
        for i, mutate in enumerate(mutations):
            s = copy.deepcopy(base)
            mutate(s["evidence"])
            for cid in ("ISE-ACCOUNT-002", "ISE-ACCOUNT-004"):
                if i == 5 and cid == "ISE-ACCOUNT-002":
                    continue                          # 002 does not read the orphans
                with self.assertRaises(criteria.MalformedEvidence, msg="%s mutation %d" % (cid, i)):
                    self.run_rule(cid, s)


def ssh_section(status="COLLECTED", value="no", reason=None, match=None, count=1, entry=True):
    records = [{"kind": "DIRECTIVE", "keyword": "permitemptypasswords", "value": "no",
                "scope": "GLOBAL", "match_index": None}]
    if match is not None:
        records.append({"kind": "DIRECTIVE", "keyword": "permitemptypasswords", "value": match,
                        "scope": "MATCH", "match_index": 0})
    records += [{"kind": "RESOLVED_SETTING", "keyword": "permitemptypasswords", "value": value,
                 "occurrence": n, "ordinal": n} for n in range(count)]
    coverage = [{"domain": "ssh", "source": "/etc/ssh", "status": "COLLECTED", "operation": "file_read",
                 "operation_id": "read_sshd_declared_config_v1"}]
    if entry:
        coverage.append({"domain": "ssh", "source": "sshd -T", "status": status, "reason": reason,
                         "operation": "command", "operation_id": "resolve_sshd_effective_config_v1"})
    return {"schema_version": 2, "section": "ssh", "collection_status": "COLLECTED",
            "evidence": {"status": "COLLECTED", "records": records,
                         "provenance": {"coverage": coverage}}}


class Ssh(unittest.TestCase):

    def run_rule(self, section):
        return criteria.ise_ssh_001(section, record("ISE-SSH-001"), DIGESTS)

    def test_pass_fail_and_the_scope_note(self):
        for value, result in (("no", "PASS"), ("yes", "FAIL")):
            r = self.run_rule(ssh_section(value=value))
            self.assertEqual(r[0], result)
            self.assertIn("Global effective SSH configuration only. Connection-specific Match "
                          "values are not resolved.", r[2])

    def test_tool_absent_is_not_evaluated_never_not_applicable(self):
        r = self.run_rule(ssh_section(status="NOT_TESTED",
                                      reason="TOOL_ABSENT: /usr/sbin/sshd is not present"))
        self.assertEqual(r[:2], ("NOT_EVALUATED", "SOURCE_NOT_TESTED"))
        self.assertIn("TOOL_ABSENT", r[2])

    def test_a_standard_audit_has_no_resolved_entry(self):
        self.assertEqual(self.run_rule(ssh_section(entry=False))[:2], ("NOT_EVALUATED", "SOURCE_NOT_TESTED"))

    def test_a_match_override_is_an_observation_and_never_changes_the_result(self):
        r = self.run_rule(ssh_section(value="no", match="yes"))
        self.assertEqual(r[0], "PASS")
        self.assertEqual(r[3], [{"declared_in_match": 0, "value": "yes"}])

    def test_a_setting_not_reported_once_or_an_odd_value_is_not_evaluated(self):
        self.assertEqual(self.run_rule(ssh_section(count=0))[1], "SETTING_NOT_REPORTED_ONCE")
        self.assertEqual(self.run_rule(ssh_section(count=2))[1], "SETTING_NOT_REPORTED_ONCE")
        self.assertEqual(self.run_rule(ssh_section(value="maybe"))[1], "SETTING_VALUE_UNKNOWN")

    def test_undefined_shapes_are_refused(self):
        bad = ssh_section()
        bad["evidence"]["provenance"]["coverage"].append(dict(bad["evidence"]["provenance"]["coverage"][1]))
        for section in (bad, dict(ssh_section(), section="accounts"),
                        dict(ssh_section(), collection_status="MAYBE"),
                        ssh_section(status="SOMETIMES")):
            with self.assertRaises(criteria.MalformedEvidence):
                self.run_rule(section)


class Rendering(unittest.TestCase):
    """Regression: the CLI and the report assumed every observation had ISE-ACCOUNT-001's
    shape (passwd_line, name) and `isedraf evaluate` crashed on ISE-ACCOUNT-003's."""

    def test_every_observation_shape_renders(self):
        from isedraf.report import render
        shapes = [
            {"passwd_line": 1, "name": "root", "name_bytes_hex": "726f6f74", "uid": 0},
            {"passwd_line": 2, "name": None, "name_bytes_hex": "ff00", "uid": 0},
            {"uid": 1000, "kind": "UID_SHARED_BY_NAMES",
             "entries": [{"passwd_line": 2, "name": "alice"}, {"passwd_line": 3, "name": "bob"}]},
            {"passwd_line": 3, "name": "alice", "shadow_field": "EMPTY_UNLOCKED"},
            {"passwd_line": 3, "name": "alice", "hash_scheme": "MD5_CRYPT", "locked": True},
            {"declared_in_match": 0, "value": "yes"},
        ]
        texts = [render.observation_text(o) for o in shapes]
        self.assertIn("name=hex:ff00", texts[1])
        self.assertIn("kind=UID_SHARED_BY_NAMES", texts[2])
        self.assertIn("name=bob", texts[2])
        self.assertIn("declared_in_match=0", texts[5])
        self.assertTrue(all("UID 0" not in t for t in texts[2:]))
        md = "\n".join(render._native_markdown({"status": "EVALUATED", "evaluation_id": "EVL-x",
                                                "results": [{"criterion_id": "ISE-ACCOUNT-003",
                                                             "criterion_version": 1, "result": "FAIL",
                                                             "reason": "r", "scope": "s",
                                                             "observations": [shapes[2]]}]}))
        self.assertIn("kind=UID_SHARED_BY_NAMES", md)


class Catalog(unittest.TestCase):

    def test_every_criterion_has_an_evaluator_reading_its_pointers(self):
        registry, _raw = catalog.load()
        self.assertEqual([c["criterion_id"] for c in registry["criteria"]],
                         ["ISE-ACCOUNT-001", "ISE-ACCOUNT-002", "ISE-ACCOUNT-003",
                          "ISE-ACCOUNT-004", "ISE-SSH-001", "ISE-ACCOUNT-005",
                          "ISE-AUTH-001", "ISE-SSH-002"])
        for c in registry["criteria"]:
            _fn, pointers, _needs = criteria.EVALUATORS[c["criterion_id"]]
            self.assertTrue(criteria.pointers_match(c, pointers), c["criterion_id"])

    def test_severities_are_the_ruled_ones(self):
        self.assertEqual({c: record(c)["default_severity"] for c in
                          ("ISE-ACCOUNT-002", "ISE-ACCOUNT-003", "ISE-ACCOUNT-004", "ISE-SSH-001")},
                         {"ISE-ACCOUNT-002": "high", "ISE-ACCOUNT-003": "medium",
                          "ISE-ACCOUNT-004": "medium", "ISE-SSH-001": "high"})


if __name__ == "__main__":
    unittest.main()
