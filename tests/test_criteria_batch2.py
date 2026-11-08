# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: ISE-ACCOUNT-005, ISE-AUTH-001 and ISE-SSH-002 - every justified result and boundary.
# Implements: D-121, D-125, CMP-003, EVAL-004, ISE-ACCOUNT-005, ISE-AUTH-001, ISE-SSH-002
#
# ISE-ACCOUNT-005 and ISE-AUTH-001 run on real fixture audits (the collector writes the
# accounts and loginpolicy sections exactly as on a host), plus synthetic edits for
# states the collector cannot produce. ISE-SSH-002 runs on synthetic ssh sections shaped
# as the collector writes them.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================
"""The third batch of native criteria (owner ruling 2026-11-05)."""
import copy
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import audit, catalog                                  # noqa: E402
from isedraf.evaluate import criteria                               # noqa: E402

PASSWD = "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n"
GROUP = "root:x:0:\nalice:x:1000:\nbob:x:1001:\n"
HOST = {"etc/machine-id": "3f9a1c0b7d2e4a68b5c6d7e8f9a0b1c2\n", "etc/passwd": PASSWD,
        "etc/group": GROUP, "etc/shadow": "root:*:19000:0:99999:7:::\nalice:!:19000::::::\n",
        "etc/nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\n",
        "etc/login.defs": "PASS_MAX_DAYS 99999\nENCRYPT_METHOD SHA512\nUMASK 022\n",
        "etc/hostname": "fx\n", "proc/sys/kernel/hostname": "fx\n"}
DIGESTS = {"manifest.json": "m", "sections/accounts.json": "a", "sections/ssh.json": "s",
           "sections/loginpolicy.json": "l"}
SCOPE = "Global effective SSH configuration only. Connection-specific Match values are not resolved."


def record(cid):
    registry, _raw = catalog.load()
    return catalog.criterion(registry, cid)


def run_rule(cid, section):
    fn, _p, _n = criteria.EVALUATORS[cid]
    return fn(section, record(cid), DIGESTS)


class Fixture(unittest.TestCase):

    def sections(self, drop=(), **files):
        host = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, host)
        merged = dict(HOST, **files)
        for rel, text in merged.items():
            if rel in drop:
                continue
            path = os.path.join(host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        sections, _status = audit.collect(host)
        return json.loads(json.dumps(sections))


class Groups(Fixture):
    """ISE-ACCOUNT-005 over /etc/group as committed."""

    def accounts(self, **files):
        return self.sections(**files)["accounts"]

    def test_pass_with_unique_gids(self):
        r = run_rule("ISE-ACCOUNT-005", self.accounts())
        self.assertEqual(r[:2], ("PASS", "GIDS_UNIQUE"))
        self.assertEqual(r[3], [])

    def test_fail_when_two_names_share_a_gid(self):
        r = run_rule("ISE-ACCOUNT-005", self.accounts(**{"etc/group": GROUP + "staff:x:1001:\n"}))
        self.assertEqual(r[:2], ("FAIL", "GID_SHARED_BY_NAMES"))
        self.assertEqual(r[3][0]["kind"], "GID_SHARED_BY_NAMES")
        self.assertEqual(sorted(e["name"] for e in r[3][0]["entries"]), ["bob", "staff"])
        cited = [e["pointer"] for e in r[4]]
        self.assertIn("/evidence/local_groups/2/gid", cited)
        self.assertIn("/evidence/local_groups/3/gid", cited)

    def synthetic(self):
        s = self.accounts()
        return s, s["evidence"]["local_groups"]

    def test_one_name_with_two_gids_is_manual_review_when_both_lines_are_kept(self):
        s, rows = self.synthetic()
        twin = copy.deepcopy(rows[1]); twin.update(gid=1005, group_line=4)
        rows.append(twin)
        self.assertEqual(run_rule("ISE-ACCOUNT-005", s)[:2],
                         ("MANUAL_REVIEW", "GROUP_NAME_WITH_SEVERAL_GIDS"))

    def test_a_collision_takes_precedence_over_ambiguity(self):
        s, rows = self.synthetic()
        twin = copy.deepcopy(rows[1]); twin.update(gid=1005, group_line=4)
        other = copy.deepcopy(rows[1]); other.update(name="carol", name_bytes_hex="6361726f6c",
                                                     gid=1000, group_line=5)
        rows.extend([twin, other])
        self.assertEqual(run_rule("ISE-ACCOUNT-005", s)[:2], ("FAIL", "GID_SHARED_BY_NAMES"))

    def test_a_repeated_identical_entry_is_an_observation_only(self):
        s, rows = self.synthetic()
        twin = copy.deepcopy(rows[1]); twin.update(group_line=4)
        rows.append(twin)
        r = run_rule("ISE-ACCOUNT-005", s)
        self.assertEqual(r[0], "PASS")
        self.assertEqual([o["kind"] for o in r[3]], ["REPEATED_GROUP_ENTRY"])

    def test_partial_group_is_not_evaluated_and_a_duplicate_there_is_an_observation(self):
        r = run_rule("ISE-ACCOUNT-005", self.accounts(**{
            "etc/group": GROUP + "staff:x:1001:\nbroken\n"}))
        self.assertEqual(r[:2], ("NOT_EVALUATED", "SOURCE_PARTIAL"))
        self.assertEqual(r[3][0]["kind"], "GID_SHARED_BY_NAMES")

    def test_a_compat_include_in_group_is_not_evaluated(self):
        s = self.accounts()
        s["evidence"]["remote_identity_inclusion"]["via_compat_directives_in"] = ["etc/group"]
        self.assertEqual(run_rule("ISE-ACCOUNT-005", s)[:2], ("NOT_EVALUATED", "SOURCE_NOT_TESTED"))

    def test_an_include_in_passwd_alone_does_not_touch_the_group_conclusion(self):
        s = self.accounts()
        s["evidence"]["remote_identity_inclusion"]["via_compat_directives_in"] = ["etc/passwd"]
        self.assertEqual(run_rule("ISE-ACCOUNT-005", s)[0], "PASS")

    def test_unreadable_group_is_not_evaluated(self):
        s = self.accounts()
        s["evidence"]["sources"]["etc/group"]["status"] = "NOT_TESTED"
        self.assertEqual(run_rule("ISE-ACCOUNT-005", s)[:2], ("NOT_EVALUATED", "SOURCE_NOT_TESTED"))

    def test_undefined_states_are_refused(self):
        base = self.accounts()
        mutations = [
            lambda e: e["sources"]["etc/group"].update(status="MAYBE"),
            lambda e: e.update(local_groups="none"),
            lambda e: e["local_groups"][0].update(gid="0"),
            lambda e: e["local_groups"][0].update(name_bytes_hex="xyz"),
            lambda e: e["local_groups"][0].pop("group_line"),
            lambda e: e["local_groups"][0].update(gid=None),       # COLLECTED, yet no GID
        ]
        for i, mutate in enumerate(mutations):
            s = copy.deepcopy(base)
            mutate(s["evidence"])
            with self.assertRaises(criteria.MalformedEvidence, msg="mutation %d" % i):
                run_rule("ISE-ACCOUNT-005", s)


class LoginDefs(Fixture):
    """ISE-AUTH-001 over the ENCRYPT_METHOD declared in /etc/login.defs."""

    def login(self, text=None, drop=()):
        files = {} if text is None else {"etc/login.defs": text}
        return self.sections(drop=drop, **files)["loginpolicy"]

    def rule(self, text=None, drop=()):
        return run_rule("ISE-AUTH-001", self.login(text, drop))

    def test_sha512_and_sha256_pass_for_the_declared_setting_only(self):
        for value in ("SHA512", "SHA256"):
            r = self.rule("ENCRYPT_METHOD %s\n" % value)
            self.assertEqual(r[:2], ("PASS", "DECLARED_METHOD_NOT_LEGACY"), value)
            self.assertIn("does not establish that the system as a whole", r[2])
            self.assertIn("the method PAM applies", r[2])
            self.assertEqual(r[3], [{"key": "ENCRYPT_METHOD", "value": value,
                                     "retention": "RETAIN_VALUE"}])

    def test_md5_and_des_fail(self):
        for value in ("MD5", "DES"):
            self.assertEqual(self.rule("ENCRYPT_METHOD %s\n" % value)[:2],
                             ("FAIL", "LEGACY_METHOD_DECLARED"), value)

    def test_yescrypt_and_bcrypt_are_not_evaluated_without_platform_evidence(self):
        for value in ("YESCRYPT", "BCRYPT"):
            self.assertEqual(self.rule("ENCRYPT_METHOD %s\n" % value)[:2],
                             ("NOT_EVALUATED", "PLATFORM_SUPPORT_NOT_EVIDENCED"), value)

    def test_an_unrecognised_or_differently_spelled_value_never_passes(self):
        for value in ("sha512", "Sha512", "md5", "SHA1024", "SHA512 # strong"):
            self.assertEqual(self.rule("ENCRYPT_METHOD %s\n" % value)[:2],
                             ("NOT_EVALUATED", "METHOD_NOT_RECOGNISED"), value)

    def test_no_declaration_is_not_evaluated(self):
        self.assertEqual(self.rule("PASS_MAX_DAYS 90\n")[:2],
                         ("NOT_EVALUATED", "ENCRYPT_METHOD_NOT_DECLARED"))

    def test_a_repeated_declaration_never_passes(self):
        for text in ("ENCRYPT_METHOD MD5\nENCRYPT_METHOD SHA512\n",
                     "ENCRYPT_METHOD SHA512\nENCRYPT_METHOD SHA512\n"):
            r = self.rule(text)
            self.assertEqual(r[:2], ("NOT_EVALUATED", "ENCRYPT_METHOD_DECLARED_MORE_THAN_ONCE"))
            self.assertEqual(len(r[3]), 2)

    def test_an_absent_file_is_not_evaluated(self):
        r = self.rule(drop=("etc/login.defs",))
        self.assertEqual(r[0], "NOT_EVALUATED")
        self.assertTrue(r[1].startswith("SOURCE_"), r[1])

    def test_a_malformed_line_makes_the_source_incomplete(self):
        self.assertEqual(self.rule("ENCRYPT_METHOD SHA512\nNOVALUE\n")[:2],
                         ("NOT_EVALUATED", "SOURCE_PARTIAL"))

    def test_a_value_not_retained_is_not_evaluated(self):
        s = self.login()
        for r in s["evidence"]["records"]:
            if r.get("key") == "ENCRYPT_METHOD":
                r.update(value=None, retention="REDACT_VALUE")
        self.assertEqual(run_rule("ISE-AUTH-001", s)[:2], ("NOT_EVALUATED", "VALUE_NOT_RETAINED"))

    def test_evidence_cites_the_source_and_the_record(self):
        r = self.rule()
        cited = [e["pointer"] for e in r[4]]
        self.assertTrue(any(p.endswith("/status") and "/provenance/sources/" in p for p in cited))
        self.assertTrue(any(p.endswith("/value") and p.startswith("/evidence/records/") for p in cited))

    def test_undefined_states_are_refused(self):
        base = self.login()

        def source(e):
            return [x for x in e["provenance"]["sources"] if x["family"] == "LOGIN_DEFS"][0]

        def ours(e):
            return [x for x in e["records"] if x.get("key") == "ENCRYPT_METHOD"][0]
        mutations = [
            lambda e: source(e).update(status="MAYBE"),
            lambda e: e["provenance"].update(sources=[x for x in e["provenance"]["sources"]
                                                     if x["family"] != "LOGIN_DEFS"]),
            lambda e: e.update(records="none"),
            lambda e: ours(e).update(retention="KEEP"),
            lambda e: ours(e).update(value=512),
            lambda e: ours(e).update(malformed="no"),
            lambda e: ours(e).update(malformed=True),           # COLLECTED, yet malformed
        ]
        for i, mutate in enumerate(mutations):
            s = copy.deepcopy(base)
            mutate(s["evidence"])
            with self.assertRaises(criteria.MalformedEvidence, msg="mutation %d" % i):
                run_rule("ISE-AUTH-001", s)
        with self.assertRaises(criteria.MalformedEvidence):
            run_rule("ISE-AUTH-001", dict(base, section="ssh"))


def ssh_section(status="COLLECTED", value="yes", reason=None, count=1, entry=True):
    records = [{"kind": "DIRECTIVE", "keyword": "strictmodes", "value": "yes",
                "scope": "GLOBAL", "match_index": None}]
    records += [{"kind": "RESOLVED_SETTING", "keyword": "strictmodes", "value": value,
                 "occurrence": n, "ordinal": n} for n in range(count)]
    coverage = [{"domain": "ssh", "source": "/etc/ssh", "status": "COLLECTED", "operation": "file_read",
                 "operation_id": "read_sshd_declared_config_v1"}]
    if entry:
        coverage.append({"domain": "ssh", "source": "sshd -T", "status": status, "reason": reason,
                         "operation": "command", "operation_id": "resolve_sshd_effective_config_v1"})
    return {"schema_version": 2, "section": "ssh", "collection_status": "COLLECTED",
            "evidence": {"status": "COLLECTED", "records": records,
                         "provenance": {"coverage": coverage}}}


class StrictModes(unittest.TestCase):
    """ISE-SSH-002 over the global sshd -T strictmodes."""

    def rule(self, section):
        return run_rule("ISE-SSH-002", section)

    def test_yes_passes_no_fails_and_both_carry_the_scope_note(self):
        for value, expect in (("yes", ("PASS", "GLOBAL_STRICTMODES_YES")),
                              ("no", ("FAIL", "GLOBAL_STRICTMODES_NO"))):
            r = self.rule(ssh_section(value=value))
            self.assertEqual(r[:2], expect)
            self.assertIn(SCOPE, r[2])

    def test_tool_absent_is_not_evaluated_never_not_applicable(self):
        r = self.rule(ssh_section(status="NOT_TESTED", reason="TOOL_ABSENT: /usr/sbin/sshd is not present"))
        self.assertEqual(r[:2], ("NOT_EVALUATED", "SOURCE_NOT_TESTED"))
        self.assertIn("TOOL_ABSENT", r[2])

    def test_a_standard_audit_has_no_resolved_entry(self):
        r = self.rule(ssh_section(entry=False))
        self.assertEqual(r[:2], ("NOT_EVALUATED", "SOURCE_NOT_TESTED"))
        self.assertIn(SCOPE, r[2])

    def test_a_declared_directive_alone_never_decides(self):
        s = ssh_section(count=0)
        self.assertEqual(self.rule(s)[:2], ("NOT_EVALUATED", "SETTING_NOT_REPORTED_ONCE"))

    def test_not_reported_once_or_an_odd_value_is_not_evaluated(self):
        self.assertEqual(self.rule(ssh_section(count=2))[1], "SETTING_NOT_REPORTED_ONCE")
        self.assertEqual(self.rule(ssh_section(value="maybe"))[1], "SETTING_VALUE_UNKNOWN")
        self.assertEqual(self.rule(ssh_section(value="YES"))[1], "SETTING_VALUE_UNKNOWN")

    def test_a_failed_sshd_t_is_not_evaluated(self):
        self.assertEqual(self.rule(ssh_section(status="ERROR", reason="EXIT_1"))[:2],
                         ("NOT_EVALUATED", "SOURCE_ERROR"))

    def test_undefined_shapes_are_refused(self):
        bad = ssh_section()
        bad["evidence"]["provenance"]["coverage"].append(dict(bad["evidence"]["provenance"]["coverage"][1]))
        for section in (bad, dict(ssh_section(), section="accounts"),
                        dict(ssh_section(), collection_status="MAYBE"),
                        ssh_section(status="SOMETIMES")):
            with self.assertRaises(criteria.MalformedEvidence):
                self.rule(section)


class Rendering(unittest.TestCase):

    def test_the_new_observation_shapes_render(self):
        from isedraf.report import render
        texts = [render.observation_text(o) for o in (
            {"gid": 1001, "kind": "GID_SHARED_BY_NAMES",
             "entries": [{"group_line": 3, "name": "bob"}, {"group_line": 4, "name": "staff"}]},
            {"key": "ENCRYPT_METHOD", "value": "MD5", "retention": "RETAIN_VALUE"})]
        self.assertIn("name=staff", texts[0])
        self.assertIn("value=MD5", texts[1])


class Catalog(unittest.TestCase):

    def test_severities_check_types_and_pointers_are_the_ruled_ones(self):
        expect = {"ISE-ACCOUNT-005": ("low", "local account identity"),
                  "ISE-AUTH-001": ("medium", "password hashing policy"),
                  "ISE-SSH-002": ("medium", "effective daemon configuration")}
        for cid, (severity, check_type) in expect.items():
            r = record(cid)
            self.assertEqual((r["default_severity"], r["check_type"]), (severity, check_type))
            self.assertTrue(criteria.pointers_match(r, criteria.EVALUATORS[cid][1]), cid)
            self.assertIn("NOT_APPLICABLE", r["evaluation_semantics"]["never_produced"])

    def test_auth_001_claims_nothing_about_pam(self):
        r = record("ISE-AUTH-001")
        self.assertIn("without claiming the effective PAM password hashing behaviour", r["purpose"])
        self.assertTrue(any("does not mean that the system uses a secure password hashing policy"
                            in x for x in r["limitations"]))

    def test_ssh_002_states_the_resolved_scope(self):
        self.assertEqual(criteria.SCOPE_DIMENSION.get("ISE-SSH-002"), "resolved")


if __name__ == "__main__":
    unittest.main()
