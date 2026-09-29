# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The local account source contract, asserted rather than described.
# Implements: SCOPE-022, SCOPE-045, IDENT-013, IDENT-041, IDENT-060
#
# Every password-shaped string in this file is unmistakably fake fixture material. None
# is a real hash, none authenticates anything, and the redaction tests assert that not
# one of them survives into a normalized record.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""The local account-file evidence contract."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.accounts import acquire, model, sources      # noqa: E402
from isedraf.nss import acquire as nss_acquire            # noqa: E402
from isedraf import textbytes                               # noqa: E402


def textbytes_hex(text):
    return textbytes.hex_of(text)

# The explicit NSS context for tests that describe compat semantics (IQ-036).
COMPAT_EVERYWHERE = {"etc/passwd": model.NSS_COMPAT, "etc/group": model.NSS_COMPAT,
                     "etc/shadow": model.NSS_COMPAT}

# Fixture credentials. FIXTURE_ONLY appears inside each so that a leak is obvious in any
# diff, any report and any grep, rather than looking like a plausible hash.
FAKE_SHA512 = "$6$FIXTUREONLYsalt$FIXTUREONLYdigestFIXTUREONLYdigestFIXTUREONLY"
FAKE_MD5 = "$1$FIXTUREONLY$FIXTUREONLYdigest"
FAKE_DES = "FIXTUREONLYdes1"

NORMAL_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n"
    "svc:x:999:999::/nonexistent:/usr/sbin/nologin\n")
NORMAL_GROUP = (
    "root:x:0:\n"
    "sudo:x:27:alice\n"
    "alice:x:1000:\n")
NORMAL_SHADOW = (
    "root:%s:19000:0:99999:7:::\n" % FAKE_SHA512 +
    "daemon:*:19000:0:99999:7:::\n" +
    "alice:%s:19500:0:99999:7:14:20000:\n" % FAKE_SHA512 +
    "svc:!:19000::::::\n")


def tree(**files):
    """A hermetic fixture root. Only what is written here exists."""
    base = tempfile.mkdtemp()
    os.mkdir(os.path.join(base, "etc"))
    for name, text in files.items():
        path = os.path.join(base, "etc", name)
        with open(path, "w") as fh:
            fh.write(text)
    return base


class SourceStatus(unittest.TestCase):
    """SCOPE-022 applied per source, then aggregated. Never the other way round."""

    def test_all_three_readable_is_collected(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["collection_status"], model.COLLECTED)
        self.assertIsNone(r["reason"])

    def test_shadow_permission_denied_is_not_tested_and_never_collected(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        os.chmod(os.path.join(root, "etc", "shadow"), 0)
        if os.geteuid() == 0:
            self.skipTest("root ignores the permission bits this test depends on")
        r = acquire.collect(root)
        self.assertEqual(r["sources"]["etc/shadow"]["status"], model.NOT_TESTED)
        # Defect A, one layer up: a readable passwd must not satisfy completeness for
        # an unreadable shadow.
        self.assertEqual(r["collection_status"], model.PARTIAL)
        self.assertIn("permission denied", r["reason"])
        self.assertIn("etc/shadow", r["reason"])

    def test_shadow_absent_is_not_tested_with_a_distinct_reason(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["sources"]["etc/shadow"]["status"], model.NOT_TESTED)
        self.assertIn("SOURCE_ABSENT", r["sources"]["etc/shadow"]["reason"])
        self.assertEqual(r["collection_status"], model.PARTIAL)

    def test_passwd_absent_gives_no_account_universe(self):
        root = tree(group=NORMAL_GROUP)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["collection_status"], model.NOT_TESTED)
        self.assertEqual(r["local_accounts"], [])

    def test_empty_source_is_collected_with_zero_records(self):
        # Owner ruling Q3. Abnormal is not incomplete: read succeeded, parse succeeded,
        # zero records. Calling it PARTIAL would mix collection truth with security
        # interpretation. A criterion may later call zero local accounts a finding.
        root = tree(passwd="", group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.COLLECTED)
        self.assertIsNone(r["sources"]["etc/passwd"]["reason"])
        self.assertEqual(r["local_accounts"], [])

    def test_every_record_malformed_is_error_not_partial(self):
        # Owner ruling Q1: ERROR only when no trustworthy normalized interpretation can
        # be produced. Every line failing is that case.
        root = tree(passwd="garbage\nmore garbage\n", group=NORMAL_GROUP,
                    shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.ERROR)
        self.assertIn("UNPARSEABLE", r["sources"]["etc/passwd"]["reason"])
        self.assertEqual(r["collection_status"], model.ERROR)

    def test_malformed_line_is_partial_and_retained_not_skipped(self):
        root = tree(passwd=NORMAL_PASSWD + "broken:line:only\n",
                    group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.PARTIAL)
        # Retained, not dropped: five lines in, five records out.
        self.assertEqual(len(r["local_accounts"]), 5)
        self.assertTrue(any(a["passwd_anomalies"] for a in r["local_accounts"]))


class ShadowJoin(unittest.TestCase):
    """The three-way distinction the contract exists to preserve."""

    def test_present(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        alice = self._named(acquire.collect(root), "alice")
        self.assertEqual(alice["shadow_record"], model.RECORD_PRESENT)
        self.assertEqual(alice["shadow"]["max_days"], 99999)

    def test_absent_from_a_source_that_was_read(self):
        shadow = NORMAL_SHADOW.replace("alice:%s:19500:0:99999:7:14:20000:\n"
                                       % FAKE_SHA512, "")
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=shadow)
        self.addCleanup(shutil.rmtree, root)
        alice = self._named(acquire.collect(root), "alice")
        self.assertEqual(alice["shadow_record"],
                         model.RECORD_ABSENT_FROM_COLLECTED_SOURCE)
        self.assertIsNone(alice["shadow"])

    def test_source_not_collected_is_not_the_same_as_absent(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP)
        self.addCleanup(shutil.rmtree, root)
        alice = self._named(acquire.collect(root), "alice")
        self.assertEqual(alice["shadow_record"], model.RECORD_SOURCE_NOT_COLLECTED)
        self.assertIsNone(alice["shadow"])
        # The whole point: these two must not be the same value.
        self.assertNotEqual(model.RECORD_SOURCE_NOT_COLLECTED,
                            model.RECORD_ABSENT_FROM_COLLECTED_SOURCE)

    def test_shadow_orphan_is_reported(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP,
                    shadow=NORMAL_SHADOW + "ghost:!:19000::::::\n")
        self.addCleanup(shutil.rmtree, root)
        # Owner ruling N3 (2026-09-26): an orphan is reported by line and name length,
        # never by its name text.
        self.assertEqual(acquire.collect(root)["orphan_shadow_records"], [{"line": 5, "name_length": 5}])

    def test_orphans_are_not_claimed_when_shadow_was_never_read(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP)
        self.addCleanup(shutil.rmtree, root)
        # Absence of evidence is not evidence of absence.
        self.assertEqual(acquire.collect(root)["orphan_shadow_records"], [])

    def _named(self, result, name):
        return [a for a in result["local_accounts"] if a["name"] == name][0]


class AbsenceInvariantBothDirections(unittest.TestCase):
    """NOT PRESENT is not the same fact as PRESENT BUT NOT OBSERVABLE.

    Recorded here as project-wide semantics, not an account-lane detail. The same
    invariant has been violated three times in three shapes: this join, PAM's
    cycle-versus-diamond, and login-policy dropping a refused source family from its
    aggregate. Both directions are asserted, because getting either one wrong is a
    different lie.
    """

    PASSWD = ("root:x:0:0::/root:/bin/sh\n"
              "alice:x:1000:1000::/home/alice:/bin/sh\n")

    def _root(self, shadow_mode=None, shadow_text="root:!:19000::::::\n"):
        base = tempfile.mkdtemp()
        os.mkdir(os.path.join(base, "etc"))
        with open(os.path.join(base, "etc", "passwd"), "w") as fh:
            fh.write(self.PASSWD)
        with open(os.path.join(base, "etc", "group"), "w") as fh:
            fh.write("root:x:0:\n")
        if shadow_mode is not None:
            path = os.path.join(base, "etc", "shadow")
            with open(path, "w") as fh:
                fh.write(shadow_text)
            os.chmod(path, shadow_mode)
        # rmtree only; a mode-0 FILE in a writable directory unlinks fine, and an
        # addCleanup(chmod) would run AFTER rmtree - cleanups are LIFO - on a path that
        # no longer exists.
        self.addCleanup(shutil.rmtree, base, True)
        return base

    def _alice(self, base):
        result = acquire.collect(base)
        return result, [a for a in result["local_accounts"]
                        if a["name"] == "alice"][0]

    def test_absent_counterpart_yields_unknown_never_absence(self):
        result, alice = self._alice(self._root(shadow_mode=None))
        self.assertEqual(alice["shadow_record"], model.RECORD_SOURCE_NOT_COLLECTED)
        self.assertEqual(result["collection_status"], model.PARTIAL)

    def test_refused_counterpart_yields_unknown_never_absence(self):
        # The recurring defect. The file EXISTS. Reporting alice as absent from it would
        # be an accusation manufactured from a gap in our own reading.
        if os.geteuid() == 0:
            self.skipTest("root ignores the permission bits this test depends on")
        result, alice = self._alice(self._root(shadow_mode=0))
        self.assertEqual(alice["shadow_record"], model.RECORD_SOURCE_NOT_COLLECTED)
        self.assertEqual(result["collection_status"], model.PARTIAL)

    def test_refused_and_absent_are_indistinguishable_only_at_the_relationship(self):
        # Both are "we do not know". They differ in the REASON, which is what lets an
        # operator tell "shadow is not configured" from "you need privilege".
        if os.geteuid() == 0:
            self.skipTest("root ignores the permission bits this test depends on")
        absent = acquire.collect(self._root(shadow_mode=None))
        refused = acquire.collect(self._root(shadow_mode=0))
        self.assertIn("SOURCE_ABSENT", absent["sources"]["etc/shadow"]["reason"])
        self.assertIn("permission denied", refused["sources"]["etc/shadow"]["reason"])

    def test_only_a_completely_read_counterpart_supports_an_absence_claim(self):
        result, alice = self._alice(self._root(shadow_mode=0o644))
        self.assertEqual(alice["shadow_record"],
                         model.RECORD_ABSENT_FROM_COLLECTED_SOURCE)
        self.assertEqual(result["collection_status"], model.COLLECTED)

    def test_a_partially_read_counterpart_does_not_support_an_absence_claim(self):
        # shadow readable but containing a malformed line: alice may be in the part that
        # did not parse.
        base = self._root(shadow_mode=0o644,
                          shadow_text="root:!:19000::::::\n!!!broken!!!\n")
        result, alice = self._alice(base)
        self.assertEqual(result["sources"]["etc/shadow"]["status"], model.PARTIAL)
        self.assertEqual(alice["shadow_record"], model.RECORD_SOURCE_NOT_COLLECTED)


class PasswordRedaction(unittest.TestCase):
    """The credential verifier never leaves the parser."""

    def test_hash_is_never_retained_anywhere_in_the_result(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        blob = json.dumps(acquire.collect(root))
        self.assertNotIn("FIXTUREONLY", blob)
        self.assertNotIn(FAKE_SHA512, blob)
        self.assertNotIn("salt", blob)

    def test_lock_prefix_and_content_are_independent(self):
        # `passwd -l` leaves the hash in place behind a '!'. Collapsing these two into
        # one enum is how "locked" becomes "has no password".
        state = sources._password_state("!" + FAKE_SHA512)
        self.assertEqual(state["lock_prefix"], model.LOCK_PREFIX_PRESENT)
        self.assertEqual(state["content"], model.CONTENT_HASH_PRESENT)

    def test_each_content_form(self):
        cases = ((("", model.CONTENT_EMPTY)),
                 ("*", model.CONTENT_DISABLED_TOKEN),
                 (FAKE_SHA512, model.CONTENT_HASH_PRESENT),
                 (FAKE_DES, model.CONTENT_OTHER))
        for raw, expected in cases:
            self.assertEqual(sources._password_state(raw)["content"], expected, raw)

    def test_locked_with_empty_body_is_not_reported_as_having_a_password(self):
        state = sources._password_state("!")
        self.assertEqual(state["lock_prefix"], model.LOCK_PREFIX_PRESENT)
        self.assertEqual(state["content"], model.CONTENT_EMPTY)

    def test_scheme_is_a_bounded_normalized_identifier(self):
        self.assertEqual(sources._password_state(FAKE_SHA512)["hash_scheme"],
                         "SHA512_CRYPT")
        self.assertEqual(sources._password_state(FAKE_MD5)["hash_scheme"], "MD5_CRYPT")
        self.assertIsNone(sources._password_state("*")["hash_scheme"])

    def test_unknown_scheme_does_not_leak_raw_password_field_material(self):
        # Owner ruling Q2. An unrecognized $id$ is an arbitrary string lifted out of the
        # credential field; publishing it verbatim would leak what this boundary contains.
        state = sources._password_state("$SECRETPREFIXFIXTUREONLY$salt$digest")
        self.assertEqual(state["content"], model.CONTENT_HASH_PRESENT)
        self.assertEqual(state["hash_scheme"], model.HASH_SCHEME_OTHER)
        self.assertNotIn("SECRETPREFIX", json.dumps(state))


class NoInterpretation(unittest.TestCase):
    """Facts only. Every one of these labels belongs to a later criterion."""

    def setUp(self):
        self.root = tree(passwd=NORMAL_PASSWD + "root2:x:0:0::/root:/bin/sh\n",
                         group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, self.root)
        self.result = acquire.collect(self.root)
        self.blob = json.dumps(self.result)

    def test_no_policy_vocabulary_anywhere(self):
        for word in ("human", "service", "system_account", "interactive", "inactive",
                     "administrator", "privileged", "sudoer", "compliant", "expired",
                     "active"):
            self.assertNotIn('"%s"' % word, self.blob, word)

    def test_uid_zero_is_a_number_not_a_verdict(self):
        zeros = [a["name"] for a in self.result["local_accounts"] if a["uid"] == 0]
        self.assertEqual(sorted(zeros), ["root", "root2"])
        # Two UID 0 accounts is exactly the fact a parser must not resolve away.
        self.assertNotIn("is_root", self.blob)

    def test_sudo_group_membership_does_not_confer_privilege(self):
        alice = [a for a in self.result["local_accounts"] if a["name"] == "alice"][0]
        self.assertNotIn("privileged", alice)
        sudo = [g for g in self.result["local_groups"] if g["name"] == "sudo"][0]
        self.assertEqual(sudo["explicit_members"], ["alice"])
        self.assertNotIn("grants_privilege", sudo)

    def test_nologin_shell_is_a_string(self):
        svc = [a for a in self.result["local_accounts"] if a["name"] == "svc"][0]
        self.assertEqual(svc["shell"], "/usr/sbin/nologin")

    def test_no_creation_time_is_invented(self):
        for key in ("created", "created_at", "creation_time", "account_created"):
            self.assertNotIn(key, self.blob)


class GroupProvenance(unittest.TestCase):

    def test_primary_membership_is_not_merged_into_explicit_members(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        alice_group = [g for g in r["local_groups"] if g["name"] == "alice"][0]
        # alice's PRIMARY gid is 1000, but /etc/group lists no explicit member. The two
        # sources disagree only if you merge them without saying you did.
        self.assertEqual(alice_group["explicit_members"], [])
        alice = [a for a in r["local_accounts"] if a["name"] == "alice"][0]
        self.assertEqual(alice["primary_gid"], 1000)

    def test_group_member_referencing_an_absent_account(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP + "ops:x:50:nobodyhere\n",
                    shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        self.assertEqual(acquire.collect(root)["orphan_group_members"],
                         [{"group": "ops", "member": "nobodyhere"}])


class Duplicates(unittest.TestCase):
    """A dictionary would make each of these disappear."""

    def test_duplicate_username_keeps_both(self):
        p = sources.parse_passwd(NORMAL_PASSWD + "alice:x:1001:1001::/home/a2:/bin/sh\n")
        self.assertEqual(len([r for r in p.records if r["name"] == "alice"]), 2)
        self.assertTrue(any(a["anomaly"] == model.ANOMALY_DUPLICATE_NAME
                            for a in p.anomalies))

    def test_duplicate_uid_is_named(self):
        p = sources.parse_passwd(NORMAL_PASSWD + "bob:x:1000:1000::/home/bob:/bin/sh\n")
        dupes = [a for a in p.anomalies if a["anomaly"] == model.ANOMALY_DUPLICATE_ID]
        self.assertEqual(len(dupes), 1)
        self.assertIn("1000", dupes[0]["detail"])

    def test_duplicate_gid_is_named(self):
        g = sources.parse_group(NORMAL_GROUP + "wheel:x:27:\n")
        self.assertTrue(any(a["anomaly"] == model.ANOMALY_DUPLICATE_ID
                            for a in g.anomalies))


class MalformedFields(unittest.TestCase):

    def test_non_numeric_uid_is_recorded_not_defaulted(self):
        p = sources.parse_passwd("weird:x:notanumber:0::/tmp:/bin/sh\n")
        self.assertIsNone(p.records[0]["uid"])
        self.assertTrue(any(a["anomaly"] == model.ANOMALY_NON_NUMERIC_ID
                            for a in p.anomalies))

    def test_malformed_ageing_value_is_distinct_from_unspecified(self):
        s = sources.parse_shadow("u:*:notaday::99999:7:::\n")
        rec = s.records[0]
        self.assertIsNone(rec["last_change_days"])
        self.assertEqual(rec["last_change_days_source"], "MALFORMED")
        self.assertIsNone(rec["min_days"])
        self.assertEqual(rec["min_days_source"], "UNSPECIFIED")
        self.assertEqual(rec["max_days"], 99999)
        self.assertEqual(rec["max_days_source"], "OBSERVED")

    def test_sentinel_values_are_preserved_not_computed(self):
        s = sources.parse_shadow("u:*:19000:0:99999:7:-1:-1:\n")
        self.assertEqual(s.records[0]["expire_days"], -1)
        self.assertEqual(s.records[0]["inactive_days"], -1)

    def test_very_large_ids(self):
        p = sources.parse_passwd("big:x:4294967294:4294967294::/tmp:/bin/sh\n")
        self.assertEqual(p.records[0]["uid"], 4294967294)

    def test_missing_home_and_shell_are_none_not_empty_string(self):
        p = sources.parse_passwd("m:x:5:5:::\n")
        self.assertIsNone(p.records[0]["home"])
        self.assertIsNone(p.records[0]["shell"])

    def test_comments_and_blank_lines_are_not_anomalies(self):
        p = sources.parse_passwd("# a comment\n\nroot:x:0:0:root:/root:/bin/bash\n")
        self.assertEqual(p.line_count, 1)
        self.assertEqual(p.malformed_count, 0)


class FixtureConfinement(unittest.TestCase):
    """A fixture run must describe the fixture, never the machine running the test."""

    def test_fixture_root_does_not_fall_back_to_the_live_host(self):
        root = tree(passwd="only:x:4242:4242::/tmp:/bin/sh\n")
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        names = [a["name"] for a in r["local_accounts"]]
        self.assertEqual(names, ["only"])
        # The negative control: the account running these tests must be absent.
        live = os.environ.get("USER") or ""
        if live:
            self.assertNotIn(live, names)
        self.assertNotIn("root", names)

    def test_empty_fixture_root_reports_absence_not_the_real_etc(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["collection_status"], model.NOT_TESTED)
        self.assertEqual(r["local_accounts"], [])
        self.assertEqual(r["local_groups"], [])

    def test_parsers_take_text_and_cannot_touch_the_filesystem(self):
        # Purity is the property that makes the fixtures deterministic: a parser test
        # cannot pass or fail because of the permissions of the host running it.
        import inspect
        for fn in (sources.parse_passwd, sources.parse_group, sources.parse_shadow):
            src = inspect.getsource(fn)
            for forbidden in ("open(", "os.", "read_file", "subprocess"):
                self.assertNotIn(forbidden, src, "%s uses %s" % (fn.__name__, forbidden))


class ScopeHonesty(unittest.TestCase):
    """This is the local account files, not the identities of the host."""

    def test_scope_and_limitation_travel_with_the_result(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["scope"], "LOCAL_ACCOUNT_FILES")
        self.assertIn("SSSD", r["limitation"])
        self.assertIn("not a complete list", r["limitation"])

    def test_every_entity_records_its_nss_source(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        for entity in r["local_accounts"] + r["local_groups"]:
            self.assertEqual(entity["nss_source"], "files")   # IDENT-041


class JoinInvariant(unittest.TestCase):
    """ABSENT_FROM_COLLECTED_SOURCE requires a COMPLETE counterpart source."""

    def _alice(self, result):
        return [a for a in result["local_accounts"] if a["name"] == "alice"][0]

    def test_partial_shadow_with_no_matching_record_is_unknown_not_absent(self):
        # alice's record may have been one of the lines that failed to parse. Claiming
        # she is absent from shadow would be an accusation built from a gap in our
        # own reading.
        shadow = NORMAL_SHADOW.replace(
            "alice:%s:19500:0:99999:7:14:20000:\n" % FAKE_SHA512, "") + "!!!broken!!!\n"
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=shadow)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["sources"]["etc/shadow"]["status"], model.PARTIAL)
        self.assertEqual(self._alice(r)["shadow_record"],
                         model.RECORD_SOURCE_NOT_COLLECTED)

    def test_a_parsed_record_is_present_even_when_the_source_is_partial(self):
        # These two facts are compatible: the record is evidence regardless of what
        # happened to other lines.
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP,
                    shadow=NORMAL_SHADOW + "!!!broken!!!\n")
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["sources"]["etc/shadow"]["status"], model.PARTIAL)
        self.assertEqual(self._alice(r)["shadow_record"], model.RECORD_PRESENT)
        self.assertEqual(self._alice(r)["shadow"]["max_days"], 99999)

    def test_absent_only_when_shadow_fully_collected(self):
        shadow = NORMAL_SHADOW.replace(
            "alice:%s:19500:0:99999:7:14:20000:\n" % FAKE_SHA512, "")
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=shadow)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["sources"]["etc/shadow"]["status"], model.COLLECTED)
        self.assertEqual(self._alice(r)["shadow_record"],
                         model.RECORD_ABSENT_FROM_COLLECTED_SOURCE)


class AbsenceRequiresCompleteEvidence(unittest.TestCase):
    """A missing-relationship claim requires a complete counterpart source."""

    def test_partial_passwd_does_not_support_a_shadow_orphan_claim(self):
        root = tree(passwd=NORMAL_PASSWD + "broken:line:only\n", group=NORMAL_GROUP,
                    shadow=NORMAL_SHADOW + "ghost:!:19000::::::\n")
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.PARTIAL)
        self.assertEqual(r["orphan_shadow_records"], [])
        self.assertFalse(r["absence_claims_supported"]["shadow_orphans"])

    def test_complete_passwd_does_support_it(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP,
                    shadow=NORMAL_SHADOW + "ghost:!:19000::::::\n")
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["orphan_shadow_records"], [{"line": 5, "name_length": 5}])
        self.assertTrue(r["absence_claims_supported"]["shadow_orphans"])

    def test_partial_passwd_does_not_support_a_group_member_orphan_claim(self):
        root = tree(passwd=NORMAL_PASSWD + "broken:line:only\n",
                    group=NORMAL_GROUP + "ops:x:50:nobodyhere\n", shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        self.assertEqual(acquire.collect(root)["orphan_group_members"], [])

    def test_primary_gid_orphan_requires_a_complete_group_source(self):
        passwd = NORMAL_PASSWD + "odd:x:1500:4242::/home/odd:/bin/sh\n"
        root = tree(passwd=passwd, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        # daemon and svc are orphans too in this fixture, which is the point: the claim
        # is made for every account whose primary GID has no group, not just the
        # interesting one.
        self.assertIn({"account": "odd", "primary_gid": 4242}, r["orphan_primary_gids"])
        self.assertTrue(r["absence_claims_supported"]["primary_gid_orphans"])
        # Now break the group source: every one of those claims must retract.
        root2 = tree(passwd=passwd, group=NORMAL_GROUP + "bad:line\n",
                     shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root2)
        r2 = acquire.collect(root2)
        self.assertEqual(r2["sources"]["etc/group"]["status"], model.PARTIAL)
        self.assertEqual(r2["orphan_primary_gids"], [])
        self.assertFalse(r2["absence_claims_supported"]["primary_gid_orphans"])


class Classification(unittest.TestCase):
    """SCOPE-045, the frozen four. Every emitted field declares exactly one."""

    def test_gecos_is_observation_not_state(self):
        # Owner ruling Q4: a GECOS edit must not become a security baseline delta, and
        # free-form personal metadata must not be bound into hashed state.
        self.assertEqual(model.CLASSIFICATION["gecos"], model.OBSERVATION)

    def test_identity_determining_fields_are_state(self):
        for field in ("name", "uid", "primary_gid", "home", "shell", "nss_source"):
            self.assertEqual(model.CLASSIFICATION[field], model.STATE, field)

    def test_every_category_is_one_of_the_frozen_four(self):
        allowed = {model.STATE, model.OBSERVATION, model.DERIVED, model.PROVENANCE}
        for field, category in model.CLASSIFICATION.items():
            self.assertIn(category, allowed, field)

    def test_every_emitted_account_field_is_classified(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        account = r["local_accounts"][0]
        for key in account:
            if key == "shadow":
                continue
            self.assertIn(key, model.CLASSIFICATION, key)
        for key in r["local_groups"][0]:
            self.assertIn("group." + key, model.CLASSIFICATION, key)


def full_state(r):
    """Every STATE field of the account and group records, dotted ones included.

    Red team pass 4 (L6): the projection the proofs used dropped every dotted key, so
    shadow.* and group.* STATE never took part.
    """
    from isedraf import canonical
    cls = model.CLASSIFICATION
    accounts = []
    for a in r["local_accounts"]:
        item = {k: a.get(k) for k, v in cls.items() if v == model.STATE and "." not in k}
        shadow = a.get("shadow") or {}
        # Strictly STATE: shadow_line and *_source are PROVENANCE (red team pass 5, M3).
        item["shadow"] = {k.split(".", 1)[1]: shadow.get(k.split(".", 1)[1])
                          for k, v in cls.items() if v == model.STATE
                          and k.startswith("shadow.") and k.count(".") == 1}
        item["shadow_password_state"] = shadow.get("password_state")
        accounts.append(item)
    groups = [{k: g.get(k.split(".", 1)[1]) for k, v in cls.items()
               if v == model.STATE and k.startswith("group.")} for g in r["local_groups"]]
    return canonical.canonical_bytes({"accounts": accounts, "groups": groups})


class CompatDirectiveOrderIsSourceIdentity(unittest.TestCase):
    """Owner ruling F6 (2026-09-24): compat directive order is collection/method identity.

    Under `compat`, "-alice" before a local alice line excludes her, and "+" before a local
    line can shadow it. That changes resolution, not identity, so it moves the compat
    topology digest and never the account STATE projection.
    """

    def collect(self, passwd):
        root = tree(passwd=passwd, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        return acquire.collect(root, nss_context=COMPAT_EVERYWHERE)

    def state(self, r):
        return full_state(r)

    ALICE = "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"

    def assert_order_moves_source_not_state(self, first, second):
        a, b = self.collect(first), self.collect(second)
        self.assertEqual(self.state(a), self.state(b))
        self.assertNotEqual(a["compat_directive_topology_digest"],
                            b["compat_directive_topology_digest"])

    def test_an_exclude_before_or_after_a_local_account(self):
        self.assert_order_moves_source_not_state("-alice::::::\n" + self.ALICE,
                                                 self.ALICE + "-alice::::::\n")

    def test_an_include_before_or_after_a_local_account(self):
        self.assert_order_moves_source_not_state("+\n" + self.ALICE, self.ALICE + "+\n")

    def test_formatting_alone_does_not_move_the_digest(self):
        a = self.collect(self.ALICE + "+\n")
        b = self.collect("# comment\n\n" + self.ALICE + "\n+\n")
        self.assertEqual(a["compat_directive_topology_digest"],
                         b["compat_directive_topology_digest"])

    def test_a_gecos_override_does_not_move_it_and_a_shell_override_does(self):
        base = self.collect(self.ALICE + "+bob::::G1:/h:/s\n")
        gecos = self.collect(self.ALICE + "+bob::::G2:/h:/s\n")
        shell = self.collect(self.ALICE + "+bob::::G1:/h:/bin/zsh\n")
        self.assertEqual(base["compat_directive_topology_digest"],
                         gecos["compat_directive_topology_digest"])
        self.assertNotEqual(base["compat_directive_topology_digest"],
                            shell["compat_directive_topology_digest"])
        self.assertNotIn("G1", json.dumps(base["compat_directive_topology"]))

    def test_no_secret_text_in_the_topology(self):
        # Password and override fields only: a secret written AS a valid name is the
        # recorded pass-3 F9 residual - syntax cannot tell a name from a secret.
        r = self.collect(self.ALICE + "+bob:%s:::::\n-carol:%s::::::\n+dave::%s::::\n"
                         % (FAKE_SHA512, FAKE_DES, FAKE_MD5))
        self.assertNotIn("FIXTUREONLY", json.dumps(r["compat_directive_topology"]))

    def test_p4_m1_which_local_lines_surround_a_directive_matters(self):
        # glibc: alice / -alice / bob resolves alice; bob / -alice / alice excludes her.
        bob = "bob:x:1001:1001::/home/bob:/bin/sh\n"
        a = self.collect(self.ALICE + "-alice::::::\n" + bob)
        b = self.collect(bob + "-alice::::::\n" + self.ALICE)
        self.assertNotEqual(a["compat_directive_topology_digest"],
                            b["compat_directive_topology_digest"])

    def test_p4_m1_an_account_after_every_directive_does_not_move_it(self):
        a = self.collect(self.ALICE + "+\n")
        b = self.collect(self.ALICE + "+\nbob:x:1001:1001::/home/bob:/bin/sh\n")
        self.assertEqual(a["compat_directive_topology_digest"],
                         b["compat_directive_topology_digest"])

    def test_p4_l1_overrides_glibc_ignores_do_not_move_it(self):
        # glibc ignores passwd uid/gid overrides and every group override under compat.
        a = self.collect(self.ALICE + "+bob::::G:/h:/s\n")
        b = self.collect(self.ALICE + "+bob::5:5:G:/h:/s\n")
        self.assertEqual(a["compat_directive_topology_digest"],
                         b["compat_directive_topology_digest"])

    def test_p4_l1_bare_and_all_empty_passwd_directives_are_the_same(self):
        a = self.collect(self.ALICE + "+bob\n")
        b = self.collect(self.ALICE + "+bob::::::\n")
        self.assertEqual(a["compat_directive_topology_digest"],
                         b["compat_directive_topology_digest"])

    def test_p4_l3_a_malformed_directive_keeps_its_real_target(self):
        r = self.collect(self.ALICE + "-@bad ng::::::\n+al ice::::::\n")
        d = r["compat_directives"]["etc/passwd"]
        self.assertEqual([(x["target"], x["malformed"]) for x in d],
                         [("NETGROUP", True), ("NAME", True)])

    # --- owner ruling M2 (2026-09-24): valid shadow ageing integers are source identity ---

    def shadow(self, directive):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP,
                    shadow=directive + "\n" + NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        return acquire.collect(root, nss_context=COMPAT_EVERYWHERE)

    def test_m2_a_different_max_days_moves_the_digest_and_not_state(self):
        # glibc applies max_days 3 vs 99999 from these directives.
        a, b = self.shadow("+alice::::3::::"), self.shadow("+alice::::99999::::")
        self.assertEqual(full_state(a), full_state(b))
        self.assertNotEqual(a["compat_directive_topology_digest"],
                            b["compat_directive_topology_digest"])

    def test_m2_only_password_text_changing_keeps_the_digest_and_leaks_nothing(self):
        a = self.shadow("+alice:%s:::3::::" % FAKE_SHA512)
        b = self.shadow("+alice:$6$FIXTUREONLYother$FIXTUREONLYother:::3::::")
        self.assertEqual(a["compat_directive_topology_digest"],
                         b["compat_directive_topology_digest"])
        self.assertNotIn("FIXTUREONLY", json.dumps(a))

    def test_m2_integer_to_non_integer_is_malformed_shape_only_and_leaks_nothing(self):
        r = self.shadow("+alice::::%s::::" % FAKE_SHA512)
        d = r["compat_directives"]["etc/shadow"][0]
        self.assertTrue(d["malformed"])
        self.assertIsNone(d["ageing_values"])
        self.assertNotIn("FIXTUREONLY", json.dumps(r))

    def test_m2_the_same_integer_written_differently_is_the_same_digest(self):
        a, b = self.shadow("+alice::::3::::"), self.shadow("+alice::::03::::")
        self.assertEqual(a["compat_directive_topology_digest"],
                         b["compat_directive_topology_digest"])

    def test_m2_bare_and_all_empty_shadow_directives_differ(self):
        # glibc: the all-empty form clears lastchg, min and max; the bare form does not.
        a, b = self.shadow("+alice"), self.shadow("+alice::::::::")
        self.assertNotEqual(a["compat_directive_topology_digest"],
                            b["compat_directive_topology_digest"])

    # --- red-team pass 5 on the topology, each written before its fix -------------------

    def test_p5_h1_a_hash_shaped_local_name_never_enters_the_topology(self):
        shadow = NORMAL_SHADOW + "alice%s:19000:0:99999:7:::\n+::::::::\n" % FAKE_SHA512
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=shadow)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root, nss_context=COMPAT_EVERYWHERE)
        self.assertNotIn("FIXTUREONLY", json.dumps(r["compat_directive_topology"]))

    def test_p5_h2_an_ageing_value_outside_int64_never_crashes(self):
        for value in ("9223372036854775808", "-9223372036854775809", "9" * 5000):
            r = self.shadow("+alice::::%s::::" % value)
            d = r["compat_directives"]["etc/shadow"][0]
            self.assertTrue(d["malformed"], value[:20])
            self.assertIsNone(d["ageing_values"], value[:20])

    def test_p5_h3_the_topology_is_linear(self):
        import time
        lines = "".join("u%d:x:%d:1::/:/bin/sh\n" % (i, 2000 + i) for i in range(3000))
        start = time.time()
        r = self.collect(lines + "-a::::::\n" * 3000)
        self.assertLess(time.time() - start, 10)
        size = sum(len(x) for x in r["compat_directive_topology"].values() if x)
        self.assertLess(size, 7000)

    def test_p5_m1_a_duplicate_around_a_directive_is_order(self):
        bad = "alice:x:abc:1000:A:/home/alice:/bin/bash\n"
        good = "alice:x:1001:1001:A:/home/good:/bin/bash\n"
        a = self.collect(bad + "-alice::::::\n" + good)
        b = self.collect(bad + good + "-alice::::::\n")
        self.assertNotEqual(a["compat_directive_topology_digest"],
                            b["compat_directive_topology_digest"])

    def test_p5_m2_a_directive_between_valid_duplicates_is_order(self):
        a1 = "alice:x:1000:1000:A:/home/a1:/bin/bash\n"
        a2 = "alice:x:1001:1000:A:/home/a2:/bin/bash\n"
        a = self.collect(a1 + "+alice:x::::/X:\n" + a2)
        b = self.collect(a1 + a2 + "+alice:x::::/X:\n")
        self.assertNotEqual(a["compat_directive_topology_digest"],
                            b["compat_directive_topology_digest"])

    def test_p5_la_a_comment_never_moves_it_even_near_a_nameless_record(self):
        rec = ":x:1002:1002::/h:/bin/sh\n"
        a = self.collect(rec + "-bob::::::\n")
        b = self.collect("# c\n" + rec + "-bob::::::\n")
        self.assertEqual(a["compat_directive_topology_digest"],
                         b["compat_directive_topology_digest"])

    def test_p5_lc_a_group_password_override_glibc_ignores_does_not_move_it(self):
        def g(line):
            root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP + line, shadow=NORMAL_SHADOW)
            self.addCleanup(shutil.rmtree, root)
            return acquire.collect(root, nss_context=COMPAT_EVERYWHERE)["compat_directive_topology_digest"]
        self.assertEqual(g("+staff\n"), g("+staff:NEWPW::\n"))

    # --- red-team pass 6, lane-local findings, each written before its fix ---------------

    def test_p6_1_a_long_leading_zero_token_is_its_value_and_never_crashes(self):
        # glibc's strtol reads '0'*4300+'5' as 5; int() on the raw string exceeds Python's
        # 4300-digit limit (3.11+ and patch releases of 3.7-3.10).
        token = "0" * 4300 + "5"
        r = self.shadow("+alice::::%s::::" % token)
        d = r["compat_directives"]["etc/shadow"][0]
        self.assertFalse(d["malformed"])
        self.assertEqual(d["ageing_values"][2], 5)
        for line in ("+bob::%s:::/h:/s" % token, "-" + "0" * 5000):
            self.collect(self.ALICE + line + "\n")      # must not raise

    def test_p6_5_a_malformed_local_record_never_enters_by_name(self):
        # A DES hash has no "/" or "$" in it, so name+hash passes a character check.
        shadow = NORMAL_SHADOW + "aliceFIXTUREONLYdes:19000:0:99999:7:::\n+::::::::\n"
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=shadow)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root, nss_context=COMPAT_EVERYWHERE)
        self.assertNotIn("FIXTUREONLY", json.dumps(r["compat_directive_topology"]))

    def test_the_topology_is_provenance_never_state(self):
        for key in ("compat_directive_topology", "compat_directive_topology_digest"):
            self.assertEqual(model.CLASSIFICATION[key], model.PROVENANCE, key)


class NotCollected(unittest.TestCase):
    """Owner ruling Q6: /etc/gshadow is out of scope and the limit is stated."""

    def test_gshadow_is_declared_uncollected(self):
        root = tree(passwd=NORMAL_PASSWD, group=NORMAL_GROUP, shadow=NORMAL_SHADOW)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertIn("etc/gshadow", r["not_collected"])
        self.assertIn("gshadow", r["group_limitation"])
        self.assertIn("complete group administration state is not claimed",
                      r["group_limitation"])


class IdentifierTruth(unittest.TestCase):
    """Observed identifier bytes must never silently become a different identifier."""

    def _root(self, raw_passwd):
        base = tempfile.mkdtemp()
        os.mkdir(os.path.join(base, "etc"))
        with open(os.path.join(base, "etc", "passwd"), "wb") as fh:
            fh.write(raw_passwd)
        self.addCleanup(shutil.rmtree, base)
        return base

    def test_undecodable_name_is_null_never_a_replacement_character(self):
        r = acquire.collect(self._root(b"jos\xe9:x:1000:1000::/home:/bin/sh\n"))
        account = r["local_accounts"][0]
        self.assertIsNone(account["name"])
        self.assertEqual(account["name_encoding"], model.NAME_UNDECODABLE)
        self.assertNotIn("\ufffd", json.dumps(r))

    def test_undecodable_bytes_are_preserved_exactly(self):
        r = acquire.collect(self._root(b"jos\xe9:x:1000:1000::/home:/bin/sh\n"))
        recovered = bytes(bytearray.fromhex(r["local_accounts"][0]["name_bytes_hex"]))
        self.assertEqual(recovered, b"jos\xe9")

    def test_two_different_undecodable_names_do_not_collapse(self):
        # errors="replace" mapped both of these to the same string, so a delta could not
        # tell them apart. That is the defect this representation exists to prevent.
        r = acquire.collect(self._root(
            b"a\xe9:x:1:1::/h:/bin/sh\nb\xff:x:2:2::/h:/bin/sh\n"))
        hexes = [a["name_bytes_hex"] for a in r["local_accounts"]]
        self.assertEqual(len(set(hexes)), 2)

    def test_valid_utf8_name_is_kept_and_marked(self):
        r = acquire.collect(self._root(
            "josé:x:1000:1000::/home:/bin/sh\n".encode("utf-8")))
        account = r["local_accounts"][0]
        self.assertEqual(account["name"], "jos\u00e9")
        self.assertEqual(account["name_encoding"], model.NAME_UTF8)
        self.assertTrue(account["name_non_ascii"])

    def test_ascii_name_is_not_flagged(self):
        r = acquire.collect(self._root(b"admin:x:1:1::/h:/bin/sh\n"))
        self.assertFalse(r["local_accounts"][0]["name_non_ascii"])

    def test_homoglyph_administrator_is_flagged_non_ascii(self):
        # IDENT-070's determined half: a Cyrillic U+0430 impersonating "admin". No
        # external confusables table and no Unicode version dependence, so this is
        # reproducible on every supported interpreter. The CONFUSABLE half is IQ-012.
        r = acquire.collect(self._root(
            "\u0430dmin:x:1001:1001::/home:/bin/sh\n".encode("utf-8")))
        account = r["local_accounts"][0]
        self.assertTrue(account["name_non_ascii"])
        self.assertEqual(account["name_encoding"], model.NAME_UTF8)

    def test_the_whole_result_is_canonically_serializable(self):
        # A lone surrogate would raise here, which is exactly why undecodable names are
        # represented rather than carried through.
        r = acquire.collect(self._root(b"jos\xe9:x:1:1::/h:/bin/sh\n"))
        from isedraf import canonical
        self.assertTrue(canonical.canonical_bytes(r["local_accounts"][0]))


class GlibcParsingSemantics(unittest.TestCase):
    """Hardening lane: the account files parsed the way glibc 2.43's files backend reads them.

    Owner principle (2026-09-24): model the evidence-relevant parsing semantics of the libc
    behaviour we claim to model. Each test is tagged:
        MODEL         glibc accepts it and it affects evidence -> modelled exactly
        REJECT        glibc rejects the line -> never trustworthy local identity
        CONSERVATIVE  ISEDRAF is stricter than glibc -> explicit PARTIAL, never silent
    Every glibc fact cited was measured with getent in an unprivileged private namespace
    against synthetic files; nothing on the host was read or changed.
    """

    def raw(self, passwd=None, group=None, shadow=None):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.mkdir(os.path.join(root, "etc"))
        for name, data in (("passwd", passwd), ("group", group), ("shadow", shadow)):
            data = {"passwd": NORMAL_PASSWD, "group": NORMAL_GROUP,
                    "shadow": NORMAL_SHADOW}[name] if data is None else data
            with open(os.path.join(root, "etc", name), "wb") as fh:
                fh.write(data if isinstance(data, bytes) else data.encode())
        return acquire.collect(root)

    def names(self, r):
        return [(a["name"], a["uid"]) for a in r["local_accounts"]]

    def test_model_a_non_ascii_blank_before_hash_is_an_account_not_a_comment(self):
        # glibc: "\xc2\xa0#evil:x:0:0" is returned by getent. Python's lstrip() is
        # Unicode-aware, so the parser skipped it as a comment: a hidden UID-0 account.
        r = self.raw(passwd=b"root:x:0:0::/r:/bin/sh\n\xc2\xa0#evil:x:0:0::/root:/bin/sh\n")
        self.assertIn(("\xa0#evil", 0), self.names(r))

    def test_model_ascii_blanks_before_hash_make_a_comment(self):
        r = self.raw(passwd="root:x:0:0::/r:/bin/sh\n  #c1:x:1:0::/a:/bin/sh\n"
                            "\t#c2:x:2:0::/a:/bin/sh\n\x0b#c3:x:3:0::/a:/bin/sh\n")
        self.assertEqual(self.names(r), [("root", 0)])
        self.assertEqual(r["collection_status"], model.COLLECTED, r["reason"])

    def test_model_leading_ascii_blanks_are_not_part_of_the_name(self):
        r = self.raw(passwd="root:x:0:0::/r:/bin/sh\n  lead:x:9:0::/l:/bin/sh\n")
        self.assertIn(("lead", 9), self.names(r))

    def test_model_only_newline_ends_a_line(self):
        # glibc: "\f", "\v", "\r", "\x1c", U+2028 do not split; they stay in the field.
        for sep in ("\x0c", "\x0b", "\x1c", "\u2028"):
            r = self.raw(passwd="root:x:0:0::/r:/bin/sh\ncarol:x:5:5::/h:/bin/sh%s-alice\n" % sep)
            self.assertEqual(len(r["local_accounts"]), 2, repr(sep))
            carol = [a for a in r["local_accounts"] if a["name"] == "carol"][0]
            self.assertEqual(carol["shell"], "/bin/sh%s-alice" % sep, repr(sep))

    def test_model_a_nul_byte_ends_the_line(self):
        r = self.raw(passwd=b"root:x:0:0::/r:/bin/sh\nnul:x:6:0::/a:/bin/sh\x00tail\n")
        nul = [a for a in r["local_accounts"] if a["name"] == "nul"][0]
        self.assertEqual(nul["shell"], "/bin/sh")

    def test_model_signed_and_blank_padded_ids_are_their_value(self):
        # glibc: uid "+0" and " 0" are uid 0; gid "+10" is 10; shadow "+3" is 3.
        r = self.raw(passwd="root:x:0:0::/r:/bin/sh\nevil:x:+0:0::/e:/bin/sh\n"
                            "sp:x: 0:0::/s:/bin/sh\n",
                     group="root:x:0:\nstaff:x:+10:\n",
                     shadow="root:*:1:0:9:7:::\nevil:*:+3:0:99999:7:::\n")
        self.assertIn(("evil", 0), self.names(r))
        self.assertIn(("sp", 0), self.names(r))
        self.assertIn(10, [g["gid"] for g in r["local_groups"]])
        evil = [a for a in r["local_accounts"] if a["name"] == "evil"][0]
        self.assertEqual(evil["shadow"]["last_change_days"], 3)
        self.assertEqual(r["collection_status"], model.COLLECTED, r["reason"])

    def test_reject_a_non_numeric_or_empty_id_is_not_trustworthy_and_partial(self):
        # glibc drops these lines entirely. The record is kept (never silently skipped,
        # W1-D §9) but counted malformed, so the source is PARTIAL.
        for uid in ("abc", "", "1e3"):
            r = self.raw(passwd="root:x:0:0::/r:/bin/sh\nbad:x:%s:0::/b:/bin/sh\n" % uid)
            self.assertEqual(r["sources"]["etc/passwd"]["status"], model.PARTIAL, uid)

    def test_reject_a_shadow_line_glibc_rejects_is_never_the_joined_record(self):
        # glibc rejects "alice:!:abc:..." and returns the later line (max_days 5).
        shadow = NORMAL_SHADOW.replace(
            "alice:%s:19500:0:99999:7:14:20000:\n" % FAKE_SHA512,
            "alice:!:abc:0:99999:7:::\nalice:!:1:0:5:7:::\n")
        r = self.raw(shadow=shadow)
        alice = [a for a in r["local_accounts"] if a["name"] == "alice"][0]
        # Differential harness (N2): with a malformed line first, ISEDRAF cannot be sure
        # which line glibc uses, so the relation is unknown - never the rejected values.
        self.assertEqual(alice["shadow_record"], model.RECORD_SOURCE_NOT_COLLECTED)
        self.assertIsNone(alice["shadow"])
        self.assertEqual(r["sources"]["etc/shadow"]["status"], model.PARTIAL)

    def test_conservative_a_negative_or_overflowing_id_is_partial(self):
        # glibc wraps "-1" and clamps "4294967296" to 4294967295; ISEDRAF does not state a
        # uid glibc had to invent, and says so.
        for uid in ("-1", "4294967296"):
            r = self.raw(passwd="root:x:0:0::/r:/bin/sh\nx:x:%s:0::/x:/bin/sh\n" % uid)
            self.assertEqual(r["sources"]["etc/passwd"]["status"], model.PARTIAL, uid)

    def test_bound_a_huge_numeric_field_never_crashes(self):
        r = self.raw(passwd="root:x:0:0::/r:/bin/sh\nx:x:%s:0::/x:/bin/sh\n" % ("9" * 5000),
                     shadow="root:*:%s:0:9:7:::\n" % ("9" * 5000))
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.PARTIAL)
        r = self.raw(passwd="root:x:%s0:0::/r:/bin/sh\n" % ("0" * 5000))
        self.assertIn(("root", 0), self.names(r))

    # --- hardening red-team, each written before its fix ------------------------------

    def test_rt_f1_reject_shadow_field_9_is_validated_like_glibc(self):
        # glibc rejects a shadow line whose reserved field is not a number, including the
        # "\r" a CRLF edit leaves: the second (active hash) line is what glibc returns.
        passwd = "root:x:0:0::/:/bin/sh\nnm:x:1:1::/:/bin/sh\n"
        shadow = ("root:*:1:0:99999:7:::\nnm:!*:1:0:99999:7:::\r\n"
                  "nm:%s:19000:0:99999:7:::\n" % FAKE_SHA512)
        r = self.raw(passwd=passwd, shadow=shadow)
        nm = [a for a in r["local_accounts"] if a["name"] == "nm"][0]
        # Never reported locked from the line glibc rejects. With that line first, the
        # relation is unknown rather than a guess at which line glibc uses (N2).
        self.assertNotEqual(nm["shadow_record"], model.RECORD_PRESENT)
        self.assertIsNone(nm["shadow"])
        self.assertEqual(r["sources"]["etc/shadow"]["status"], model.PARTIAL)

    def test_rt_f1_reject_a_lone_crlf_shadow_line_is_never_collected_present(self):
        r = self.raw(passwd="root:x:0:0::/:/bin/sh\n",
                     shadow="root:%s:1:0:99999:7:::\r\n" % FAKE_SHA512)
        self.assertNotEqual(r["sources"]["etc/shadow"]["status"], model.COLLECTED)
        root = r["local_accounts"][0]
        self.assertNotEqual(root["shadow_record"], model.RECORD_PRESENT)

    def test_rt_f2_model_group_members_lose_leading_blanks_like_glibc(self):
        r = self.raw(group="root:x:0:\nwheel:x:10: alice ,\tbob,\x0bcarol\n",
                     passwd="root:x:0:0::/:/bin/sh\nalice:x:1:1::/:/bin/sh\n"
                            "bob:x:2:2::/:/bin/sh\ncarol:x:3:3::/:/bin/sh\n")
        wheel = [g for g in r["local_groups"] if g["name"] == "wheel"][0]
        self.assertEqual(wheel["explicit_members"], ["alice ", "bob", "carol"])

    def test_rt_f2_model_a_blank_only_member_list_is_empty(self):
        r = self.raw(group="root:x:0:\nwheel:x:10: \n")
        wheel = [g for g in r["local_groups"] if g["name"] == "wheel"][0]
        self.assertEqual(wheel["explicit_members"], [])

    def test_rt_f3_model_minus_zero_is_zero(self):
        r = self.raw(passwd="root:x:0:0::/:/bin/sh\nnm:x:-0:0::/:/bin/sh\n",
                     group="root:x:0:\nz:x:-0:\n")
        self.assertIn(("nm", 0), self.names(r))
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.COLLECTED, r["reason"])
        self.assertIn(0, [g["gid"] for g in r["local_groups"] if g["name"] == "z"])

    def test_rt_f4_conservative_shadow_values_glibc_transforms_are_partial(self):
        # glibc: other negatives become -1; above 2**31-1 they wrap or become -1.
        # A valid line alongside: with every line malformed, owner ruling Q1 makes the
        # source ERROR rather than PARTIAL - also "not complete", but not what is tested.
        for value in ("-5", "4294967294", "2147483648"):
            r = self.raw(shadow="root:*:1:0:9:7:::\nx:*:1:0:%s:7:::\n" % value)
            self.assertEqual(r["sources"]["etc/shadow"]["status"], model.PARTIAL, value)
        for value in ("-1", "-0", "2147483647"):
            r = self.raw(shadow="root:*:1:0:%s:7:::\n" % value)
            self.assertEqual(r["sources"]["etc/shadow"]["status"], model.COLLECTED, value)

    def test_rt_f5_model_an_undecodable_name_joins_by_its_exact_bytes(self):
        r = self.raw(passwd=b"root:x:0:0::/:/bin/sh\nnm\xff:x:5:5::/:/bin/sh\n",
                     shadow=b"root:*:1:0:9:7:::\nnm\xff:*:1:0:9:7:::\n",
                     group=b"root:x:0:nm\xff\n")
        nm = [a for a in r["local_accounts"] if a["name"] is None][0]
        self.assertEqual(nm["shadow_record"], model.RECORD_PRESENT)
        from isedraf import canonical
        self.assertTrue(canonical.canonical_bytes(r["local_groups"]))
        self.assertEqual(r["orphan_group_members"], [])

    def test_rt_f5_an_undecodable_duplicate_name_is_a_duplicate(self):
        r = self.raw(passwd=b"root:x:0:0::/:/bin/sh\nnm\xff:x:5:5::/:/bin/sh\n"
                            b"nm\xff:x:6:6::/:/bin/sh\n")
        kinds = [a["anomaly"] for a in r["anomalies"]["etc/passwd"]]
        self.assertIn(model.ANOMALY_DUPLICATE_NAME, kinds)

    def test_rt_f6_leak_a_crypt_shaped_name_never_appears_as_an_orphan(self):
        shadow = NORMAL_SHADOW + "nm$6$FIXTUREONLYsalt$FIXTUREONLYdigest:1:0:99999:7::::\n"
        r = self.raw(shadow=shadow)
        self.assertNotIn("FIXTUREONLY", json.dumps(r))

    def test_n5_bound_a_long_zero_run_parses_in_linear_time(self):
        import time
        start = time.time()
        for n in (20000, 200000):
            sources.parse_passwd("x:x:%sx:0::/:/bin/sh\n" % ("0" * n))
            sources.parse_shadow("x:*:%sx:0:9:7:::\n" % ("0" * n))
        self.assertLess(time.time() - start, 2)

    def test_n6_orphans_of_undecodable_groups_are_not_merged(self):
        r = self.raw(group=b"root:x:0:\ng\xff:x:10:ghost\ng\xfe:x:11:ghost\n")
        self.assertEqual(len(r["orphan_group_members"]), 2)

    def test_n3_orphan_records_carry_no_name_text_even_for_valid_names(self):
        r = self.raw(shadow=NORMAL_SHADOW + "zelda:!:19000::::::\n"
                            # 9 fields: glibc accepts it, reading name+hash as the name.
                            "nm$6$FIXTUREONLYsalt$FIXTUREONLYdigest:1:0:99999:7::::\n")
        self.assertNotIn("zelda", json.dumps(r["orphan_shadow_records"]))
        self.assertNotIn("FIXTUREONLY", json.dumps(r))
        self.assertEqual(sorted(o["line"] for o in r["orphan_shadow_records"]), [5, 6])

    def test_n3_duplicate_details_carry_no_name_text_even_for_valid_names(self):
        r = self.raw(passwd=NORMAL_PASSWD + "alice:x:2000:2000::/h:/bin/sh\n")
        details = json.dumps(r["anomalies"]["etc/passwd"])
        self.assertIn("DUPLICATE_NAME", details)
        self.assertNotIn("alice", details)

    def test_leak_orphan_shadow_records_never_carry_malformed_line_text(self):
        shadow = NORMAL_SHADOW + "carol%s:19000:0:99999:7:::\n" % FAKE_SHA512
        r = self.raw(shadow=shadow)
        self.assertNotIn("FIXTUREONLY", json.dumps(r))

    def test_leak_duplicate_anomalies_never_carry_malformed_name_text(self):
        line = "carol%s:19000:0:99999:7:::\n" % FAKE_DES
        r = self.raw(shadow=NORMAL_SHADOW + line + line)
        self.assertNotIn("FIXTUREONLY", json.dumps(r))

    # Final re-check R3-1..R3-3 (reproduced first by the differential harness).

    def test_conservative_a_commented_group_entry_is_never_complete_evidence(self):
        # glibc: getgrent skips "#wheel:x:10:alice", but initgroups/getgrouplist does not,
        # so alice holds gid 10 (measured). Reporting /etc/group COLLECTED without that
        # membership was a false-complete path.
        for comment in ("#wheel:x:10:alice\n", "  # wheel:x:0:alice\n", "#wheel:x:10:alice"):
            r = self.raw(group=NORMAL_GROUP + comment)
            self.assertEqual(r["sources"]["etc/group"]["status"], model.PARTIAL, comment)
            self.assertNotEqual(r["collection_status"], model.COLLECTED, comment)

    def test_model_a_prose_comment_in_group_stays_a_comment(self):
        r = self.raw(group="# local groups only\n" + NORMAL_GROUP)
        self.assertEqual(r["sources"]["etc/group"]["status"], model.COLLECTED)

    def test_conservative_an_empty_account_name_is_never_trustworthy_identity(self):
        # glibc: getspnam("") finds ":hash:..." for the account ":x:0:0...". ISEDRAF reported
        # that UID-0 account's shadow relation as ABSENT under COLLECTED.
        r = self.raw(passwd=NORMAL_PASSWD + ":x:0:0::/h:/bin/sh\n",
                     shadow=NORMAL_SHADOW + ":%s:19000:0:99999:7:::\n" % FAKE_SHA512)
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.PARTIAL)
        self.assertEqual(r["sources"]["etc/shadow"]["status"], model.PARTIAL)
        for db in ("passwd", "group", "shadow"):
            self.assertEqual(self.raw(**{db: {"passwd": NORMAL_PASSWD, "group": NORMAL_GROUP,
                                              "shadow": NORMAL_SHADOW}[db]
                                         + {"passwd": ":x:5:5::/h:/bin/sh\n",
                                            "group": ":x:5:\n",
                                            "shadow": ":!:19000::::::\n"}[db]}
                                      )["sources"]["etc/" + db]["status"], model.PARTIAL, db)

    def test_orphans_are_never_built_from_malformed_records(self):
        # A malformed group line's members, and a malformed account's gid, are untrusted
        # text: they never become orphan claims (R3-3).
        r = self.raw(group=NORMAL_GROUP + "#wheel:x:10:SECRETMEMBER\nbad:x:zz:OTHERSECRET\n")
        self.assertNotIn("SECRETMEMBER", json.dumps(r["orphan_group_members"]))
        self.assertNotIn("OTHERSECRET", json.dumps(r["orphan_group_members"]))
        r = self.raw(passwd=NORMAL_PASSWD + "bad:x:77:4242::\n")      # 6 fields
        self.assertNotIn(4242, [o["primary_gid"] for o in r["orphan_primary_gids"]])

    # Re-check R4: untrusted record text never reaches STATE.

    def test_r4_1_a_commented_group_line_carries_no_text_into_state(self):
        r = self.raw(group=NORMAL_GROUP + "# vault login: admin: pw: S3cretToken,other\n")
        self.assertEqual(r["sources"]["etc/group"]["status"], model.PARTIAL)
        self.assertNotIn("S3cretToken", json.dumps(r))
        self.assertNotIn("vault", json.dumps(r))
        kept = [g for g in r["local_groups"] if g["group_anomalies"]]
        self.assertEqual(len(kept), 1)                  # retained and counted (W1-D §9)
        self.assertIsNone(kept[0]["name"])
        self.assertEqual(kept[0]["explicit_members"], [])
        self.assertEqual(kept[0]["member_count"], 2)

    def test_r4_2_a_malformed_account_line_never_carries_a_hash_into_state(self):
        r = self.raw(passwd=NORMAL_PASSWD + "bob$6$salt$HASHHASH:1001:1001::/h:/bin/sh\n",
                     group=NORMAL_GROUP + "wheel$6$salt$HASHHASH:10:alice\n")
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.PARTIAL)
        self.assertEqual(r["sources"]["etc/group"]["status"], model.PARTIAL)
        self.assertNotIn("HASHHASH", json.dumps(r))
        bad = [a for a in r["local_accounts"] if a["passwd_anomalies"]]
        self.assertEqual(len(bad), 1)
        self.assertIsNone(bad[0]["name"])
        self.assertIsNone(bad[0]["name_bytes_hex"])
        self.assertEqual(bad[0]["name_length"], len("bob$6$salt$HASHHASH"))

    def test_r4_well_formed_records_are_unchanged(self):
        r = self.raw()
        for a in r["local_accounts"]:
            self.assertNotIn("name_length", a)
            self.assertIsNotNone(a["name"])
        for g in r["local_groups"]:
            self.assertNotIn("member_count", g)


class CompatDirectives(unittest.TestCase):
    """W1-D §9 clarification (owner, 2026-09-24): compat directives are not accounts.

    `+`, `+NAME`, `+@NETGROUP`, `-NAME` and `-@NETGROUP` in /etc/passwd, /etc/group and
    /etc/shadow are NSS inclusion and exclusion directives for the NIS map. They were
    parsed as accounts named "+@admins", "-user" and "+", each stamped nss_source
    "files", each forcing PARTIAL as malformed. A valid directive is directive evidence:
    never an account, never identity STATE, and not PARTIAL by itself.
    """

    PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
              "+@admins::::::\n"
              "-user::::::\n"
              "+\n")

    def collect(self, passwd, group=NORMAL_GROUP, shadow=NORMAL_SHADOW):
        # These tests describe compat semantics, so they state the context that gives the
        # syntax that meaning (owner ruling IQ-036).
        root = tree(passwd=passwd, group=group, shadow=shadow)
        self.addCleanup(shutil.rmtree, root)
        return acquire.collect(root, nss_context=COMPAT_EVERYWHERE)

    def test_valid_directives_are_not_accounts(self):
        r = self.collect(self.PASSWD)
        self.assertEqual([a["name"] for a in r["local_accounts"]], ["root"])

    def test_valid_directives_are_retained_as_directive_evidence(self):
        r = self.collect(self.PASSWD)
        found = [(d["line"], d["kind"], d["target"], d["name"])
                 for d in r["compat_directives"]["etc/passwd"]]
        self.assertEqual(found, [(2, "INCLUDE", "NETGROUP", "admins"),
                                 (3, "EXCLUDE", "NAME", "user"),
                                 (4, "INCLUDE", "ALL", None)])

    def test_remote_identity_scope_is_detected_and_not_enumerated(self):
        r = self.collect(self.PASSWD)
        self.assertTrue(r["remote_identity_inclusion"]["detected"])
        self.assertEqual(r["remote_identity_inclusion"]["enumerated"], False)
        self.assertEqual(len(r["local_accounts"]), 1)

    def test_valid_directives_do_not_force_partial(self):
        r = self.collect(self.PASSWD)
        self.assertEqual(r["collection_status"], model.COLLECTED, r["reason"])

    def test_a_malformed_directive_forces_partial_and_is_retained(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n+@::::::\n")
        self.assertEqual(r["collection_status"], model.PARTIAL)
        bad = r["compat_directives"]["etc/passwd"]
        self.assertEqual(len(bad), 1)
        self.assertTrue(bad[0]["malformed"])
        self.assertEqual([a["name"] for a in r["local_accounts"]], ["root"])

    def test_a_directive_with_the_wrong_field_count_is_malformed(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n+user:x\n")
        self.assertEqual(r["collection_status"], model.PARTIAL)
        self.assertTrue(r["compat_directives"]["etc/passwd"][0]["malformed"])

    def test_a_malformed_account_is_still_partial(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\nbroken:line:only\n")
        self.assertEqual(r["collection_status"], model.PARTIAL)
        self.assertEqual(r["compat_directives"]["etc/passwd"], [])

    def test_a_directive_never_carries_nss_source_files(self):
        r = self.collect(self.PASSWD)
        for d in r["compat_directives"]["etc/passwd"]:
            self.assertNotIn("nss_source", d)

    def test_a_group_directive_is_not_a_group(self):
        r = self.collect(self.PASSWD, group=NORMAL_GROUP + "+staff:::\n")
        self.assertNotIn("+staff", [g["name"] for g in r["local_groups"]])
        self.assertEqual(r["compat_directives"]["etc/group"][0]["target"], "NAME")
        self.assertEqual(r["collection_status"], model.COLLECTED, r["reason"])

    def test_a_netgroup_directive_in_group_is_malformed(self):
        # nsswitch.conf(5) defines +@netgroup for passwd and shadow only.
        r = self.collect(self.PASSWD, group=NORMAL_GROUP + "+@staff:::\n")
        self.assertTrue(r["compat_directives"]["etc/group"][0]["malformed"])
        self.assertEqual(r["collection_status"], model.PARTIAL)

    def test_a_bare_minus_is_malformed(self):
        # nsswitch.conf(5) defines a bare "+" and no bare "-".
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n-\n")
        self.assertTrue(r["compat_directives"]["etc/passwd"][0]["malformed"])

    def test_every_directive_field_is_classified_and_none_is_state(self):
        r = self.collect(self.PASSWD)
        for d in r["compat_directives"]["etc/passwd"]:
            for key in d:
                category = model.CLASSIFICATION.get("directive." + key)
                self.assertIsNotNone(category, key)
                self.assertNotEqual(category, model.STATE, key)

    def test_a_shadow_directive_never_retains_a_password_hash(self):
        # W1-D §7 outranks "verbatim": a credential field is never retained raw.
        shadow = NORMAL_SHADOW + "+alice:%s:::::::\n" % FAKE_SHA512
        r = self.collect(self.PASSWD, shadow=shadow)
        self.assertNotIn("FIXTUREONLY", json.dumps(r["compat_directives"]))
        self.assertEqual(r["compat_directives"]["etc/shadow"][0]["name"], "alice")

    def test_a_passwd_directive_never_retains_a_password_field(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n+alice:%s:::::\n" % FAKE_DES)
        self.assertNotIn("FIXTUREONLY", json.dumps(r["compat_directives"]))

    def test_only_directives_is_zero_local_accounts_and_collected(self):
        r = self.collect("+\n")
        self.assertEqual(r["local_accounts"], [])
        self.assertTrue(r["remote_identity_inclusion"]["detected"])

    # --- red-team findings, regression tests written before the fixes -----------------

    def test_rt_f6_a_hash_in_a_shadow_override_field_is_never_retained(self):
        # Only field 2 was redacted; override_fields kept the rest verbatim.
        shadow = NORMAL_SHADOW + "+alice::%s:0:99999:7:::\n" % FAKE_SHA512
        r = self.collect(self.PASSWD, shadow=shadow)
        self.assertNotIn("FIXTUREONLY", json.dumps(r))

    def test_rt_f6_a_malformed_directive_retains_no_override_text(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n+alice:x:1:2:3:4:5:6:%s\n"
                         % FAKE_SHA512)
        self.assertNotIn("FIXTUREONLY", json.dumps(r))
        self.assertTrue(r["compat_directives"]["etc/passwd"][0]["malformed"])

    def test_rt_f5_a_blank_before_a_directive_never_makes_an_account(self):
        # glibc ignores leading C-locale blanks, so "\t+alice" is the directive "+alice"
        # under compat: never an account, and valid. The pass-1 expectation (malformed,
        # PARTIAL) predates the hardened parser and is obsolete (owner, 2026-09-27).
        for line in ("\t+alice:x:1000:1000::/h:/bin/sh\n", " +::::::\n"):
            r = self.collect("root:x:0:0:root:/root:/bin/bash\n" + line)
            self.assertEqual([a["name"] for a in r["local_accounts"]], ["root"], line)
            d = r["compat_directives"]["etc/passwd"]
            self.assertEqual(len(d), 1, line)
            self.assertFalse(d[0]["malformed"], line)
            self.assertEqual(r["sources"]["etc/passwd"]["status"], model.COLLECTED, line)

    def test_rt_f12_a_malformed_include_keeps_its_sign(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n+foo bar::::::\n")
        d = r["compat_directives"]["etc/passwd"][0]
        self.assertTrue(d["malformed"])
        self.assertEqual(d["kind"], "INCLUDE")

    def test_rt_f8_an_undecodable_directive_name_is_serializable_and_exact(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.mkdir(os.path.join(root, "etc"))
        for name, data in (("passwd", b"root:x:0:0::/r:/bin/sh\n+ali\xffce::::::\n"),
                           ("group", NORMAL_GROUP.encode()),
                           ("shadow", NORMAL_SHADOW.encode())):
            with open(os.path.join(root, "etc", name), "wb") as fh:
                fh.write(data)
        from isedraf import canonical
        r = acquire.collect(root, nss_context=COMPAT_EVERYWHERE)
        self.assertTrue(canonical.canonical_bytes(r["compat_directives"]))
        d = r["compat_directives"]["etc/passwd"][0]
        # Superseded by red-team pass 2 (#6): an undecodable name is not a valid name, so
        # the directive is malformed and keeps no name text - not even as hex - because a
        # line that failed to parse may carry a credential in any field. Its length stays.
        self.assertTrue(d["malformed"])
        self.assertIsNone(d["name"])
        self.assertIsNone(d["name_bytes_hex"])
        self.assertEqual(d["name_length"], 6)

    def test_p2_6_a_hash_in_a_directive_name_is_never_retained(self):
        # A shadow line missing its first colon put the whole hash into the name field.
        shadow = NORMAL_SHADOW + "+alice%s\n" % FAKE_SHA512
        r = self.collect(self.PASSWD, shadow=shadow)
        self.assertNotIn("FIXTUREONLY", json.dumps(r["compat_directives"]))
        self.assertTrue(r["compat_directives"]["etc/shadow"][0]["malformed"])

    def test_p2_6_a_malformed_directive_keeps_no_name_text(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n-alice%s:::::::\n" % FAKE_SHA512)
        d = r["compat_directives"]["etc/passwd"][0]
        self.assertIsNone(d["name"])
        self.assertIsNone(d["name_bytes_hex"])
        self.assertNotIn("FIXTUREONLY", json.dumps(r["compat_directives"]))

    def test_p2_6_a_machine_account_name_ending_in_dollar_is_valid(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n+host01$::::::\n")
        d = r["compat_directives"]["etc/passwd"][0]
        self.assertFalse(d["malformed"])
        self.assertEqual(d["name"], "host01$")

    def test_p3_f2_an_include_withdraws_absence_claims(self):
        # W1-D §11a: an absence claim needs complete evidence over the source DOMAIN, and
        # "+" includes the NIS map, which may hold exactly the entries missing locally.
        r = self.collect("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:5000::/h:/bin/sh\n+\n",
                         group="root:x:0:\nwheel:x:10:bob\n+\n",
                         shadow="root:*:19000:0:99999:7:::\n+\n")
        self.assertEqual(r["collection_status"], model.COLLECTED, r["reason"])
        self.assertEqual(r["orphan_group_members"], [])
        self.assertEqual(r["orphan_primary_gids"], [])
        self.assertFalse(any(r["absence_claims_supported"].values()))
        alice = [a for a in r["local_accounts"] if a["name"] == "alice"][0]
        self.assertEqual(alice["shadow_record"], model.RECORD_SOURCE_NOT_COLLECTED)

    def test_p3_f2_an_exclude_alone_keeps_absence_claims(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n-bob::::::\n")
        self.assertTrue(r["absence_claims_supported"]["group_member_orphans"])

    def test_p3_f1_a_hash_in_a_passwd_id_override_is_malformed_and_not_kept(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n+alice::%s::::\n" % FAKE_SHA512)
        d = r["compat_directives"]["etc/passwd"][0]
        self.assertTrue(d["malformed"])
        self.assertNotIn("FIXTUREONLY", json.dumps(r))
        self.assertEqual(r["collection_status"], model.PARTIAL)

    def test_p3_f1_a_hash_in_a_group_gid_override_is_malformed_and_not_kept(self):
        r = self.collect(self.PASSWD, group=NORMAL_GROUP + "+staff:x:%s:bob\n" % FAKE_SHA512)
        self.assertTrue(r["compat_directives"]["etc/group"][0]["malformed"])
        self.assertNotIn("FIXTUREONLY", json.dumps(r))

    def test_p3_f1_integer_id_overrides_stay_valid(self):
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n+alice::0:0:G:/h:/s\n")
        self.assertFalse(r["compat_directives"]["etc/passwd"][0]["malformed"])

    def test_p3_f8_a_malformed_include_still_counts_as_detected(self):
        # glibc applies "\t+alice…"; the malformed label is conservative, and the
        # inclusion must not be reported as absent.
        r = self.collect("root:x:0:0:root:/root:/bin/bash\n\t+alice::::G:/h:/s\n")
        self.assertTrue(r["remote_identity_inclusion"]["detected"])

    def test_no_directive_means_no_remote_inclusion_detected(self):
        r = self.collect(NORMAL_PASSWD)
        self.assertFalse(r["remote_identity_inclusion"]["detected"])
        self.assertEqual(r["compat_directives"]["etc/passwd"], [])



class NssModeDecidesCompatMeaning(unittest.TestCase):
    """Owner ruling IQ-036 (2026-09-27): "+"/"-" lines mean compat directives only where the
    host's NSS configuration establishes compat for that database.

    Under "passwd: files" glibc enumerates "+alice:x:1000:..." as a literal entry and a
    bare "+" line with uid 0 (measured), so reading them as directives there was a
    confident result different from glibc's. The parser stays context-free; the collection
    layer receives the context explicitly and never reads nsswitch.conf itself.
    """

    PASSWD = NORMAL_PASSWD + "+alice:x:1000:1000::/h:/bin/sh\n+SECRETNAME::::::\n"

    def root(self, nsswitch=None, passwd=None, group=NORMAL_GROUP, shadow=NORMAL_SHADOW):
        root = tree(passwd=self.PASSWD if passwd is None else passwd, group=group,
                    shadow=shadow)
        self.addCleanup(shutil.rmtree, root)
        if nsswitch is not None:
            with open(os.path.join(root, "etc", "nsswitch.conf"), "w") as fh:
                fh.write(nsswitch)
        return root

    def collect(self, nsswitch=None, **files):
        root = self.root(nsswitch, **files)
        context = acquire.compat_context(nss_acquire.collect(root))
        return acquire.collect(root, nss_context=context)

    def test_compat_mode_gives_directive_semantics(self):
        r = self.collect("passwd: compat\ngroup: compat\nshadow: compat\n")
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.COLLECTED)
        self.assertEqual(len(r["compat_directives"]["etc/passwd"]), 2)
        self.assertTrue(r["remote_identity_inclusion"]["detected"])

    def test_files_mode_never_reinterprets_and_is_partial(self):
        r = self.collect("passwd: files\ngroup: files\nshadow: files\n")
        src = r["sources"]["etc/passwd"]
        self.assertEqual(src["status"], model.PARTIAL)
        self.assertIn(model.REASON_COMPAT_WITHOUT_COMPAT, src["reason"])
        self.assertEqual(r["compat_directives"]["etc/passwd"], [])
        self.assertFalse(r["remote_identity_inclusion"]["detected"])
        self.assertNotIn("+alice", [a["name"] for a in r["local_accounts"]])
        self.assertEqual([u["line"] for u in r["uninterpreted_compat_syntax"]["etc/passwd"]],
                         [5, 6])

    def test_unknown_mode_is_partial_and_never_guesses_compat(self):
        for nsswitch in (None, "passwd: files compat\n", "passwd: compat\npasswd: files\n",
                         "passwd: compat [BOGUS=return]\n", "group: files\n"):
            r = self.collect(nsswitch)
            src = r["sources"]["etc/passwd"]
            self.assertEqual(src["status"], model.PARTIAL, nsswitch)
            self.assertIn(model.REASON_NSS_MODE_NOT_ASSERTED, src["reason"], nsswitch)
            self.assertEqual(r["compat_directives"]["etc/passwd"], [], nsswitch)

    def test_no_context_at_all_is_not_asserted(self):
        root = self.root()
        r = acquire.collect(root)
        self.assertIn(model.REASON_NSS_MODE_NOT_ASSERTED, r["sources"]["etc/passwd"]["reason"])

    def test_a_host_without_compat_syntax_is_unaffected(self):
        for nsswitch in (None, "passwd: files\n", "passwd: sss files\n"):
            r = self.collect(nsswitch, passwd=NORMAL_PASSWD)
            self.assertEqual(r["collection_status"], model.COLLECTED, nsswitch)

    def test_each_database_uses_its_own_mode(self):
        r = self.collect("passwd: compat\ngroup: files\nshadow: files\n",
                         group=NORMAL_GROUP + "+\n", shadow=NORMAL_SHADOW + "+alice::::::::\n")
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.COLLECTED)
        for rel in ("etc/group", "etc/shadow"):
            self.assertEqual(r["sources"][rel]["status"], model.PARTIAL, rel)
            self.assertIn(model.REASON_COMPAT_WITHOUT_COMPAT, r["sources"][rel]["reason"])

    def test_uninterpreted_lines_carry_no_text(self):
        r = self.collect("passwd: files\n")
        blob = json.dumps(r["uninterpreted_compat_syntax"])
        self.assertNotIn("SECRETNAME", blob)
        self.assertNotIn("alice", blob)
        self.assertNotIn("SECRETNAME", json.dumps(r["compat_directive_topology"]))

    def test_compat_local_record_after_an_include_is_not_complete(self):
        # glibc, compat, the map unavailable: "+\nalice:..." does not resolve the local
        # alice (measured by the NSS-aware harness). With the map available it may supply
        # or shadow her. Her effective resolution is not established locally.
        compat = "passwd: compat\ngroup: compat\nshadow: compat\n"
        for include in ("+", "+::::::", "+@ng::::::", "+bob::::::"):
            r = self.collect(compat, passwd=NORMAL_PASSWD + include + "\nzed:x:7:7::/z:/bin/sh\n")
            src = r["sources"]["etc/passwd"]
            self.assertEqual(src["status"], model.PARTIAL, include)
            self.assertIn(model.REASON_COMPAT_LOCAL_AFTER_INCLUDE, src["reason"], include)
            # Per record, too: zed is not a confident local account.
            zed = [x for x in r["local_accounts"] if x["name"] == "zed"][0]
            self.assertIn(model.ANOMALY_AFTER_COMPAT_INCLUDE, zed["passwd_anomalies"], include)
            root_ = [x for x in r["local_accounts"] if x["name"] == "root"][0]
            self.assertEqual(root_["passwd_anomalies"], [], include)
        # The classic NIS host: "+" last. Every local line precedes it and resolves locally.
        r = self.collect(compat, passwd=NORMAL_PASSWD + "+::::::\n")
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.COLLECTED)
        # An EXCLUDE naming nobody after it leaves the file complete. (One naming a later
        # local line does not: red team pass 7, F2, test_p7_f2_...)
        r = self.collect(compat, passwd="-nobody::::::\n" + NORMAL_PASSWD)
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.COLLECTED)

    SPACED = NORMAL_PASSWD + "a b:x:2001:2001::/h:/bin/sh\nc d:x:2002:2002::/h:/bin/sh\n"

    def compat_digests(self, **files):
        r = self.collect("passwd: compat\ngroup: compat\nshadow: compat\n", **files)
        return r, r["compat_directive_topology_digest"]

    def test_p6_2_invalid_topology_names_keep_distinct_text_free_references(self):
        # "a b" and "c d" are accounts glibc accepts; neither may appear as text in the
        # topology. A local shadow line before "+" resolves locally, one absent resolves
        # from the map, so which of the two precedes "+" is a different resolution.
        ra, da = self.compat_digests(passwd=self.SPACED,
                                     shadow=NORMAL_SHADOW + "a b:!:19000::::::\n+\n")
        rb, db = self.compat_digests(passwd=self.SPACED,
                                     shadow=NORMAL_SHADOW + "c d:!:19000::::::\n+\n")
        self.assertEqual(ra["sources"]["etc/shadow"]["status"], model.COLLECTED)
        self.assertNotEqual(da, db)
        for r in (ra, rb):
            blob = json.dumps(r["compat_directive_topology"])
            self.assertNotIn("a b", blob)
            self.assertNotIn("c d", blob)

    def test_p6_3_malformed_name_directives_of_one_length_do_not_collide(self):
        ra, da = self.compat_digests(passwd=self.SPACED + "-a b::::::\n")
        rb, db = self.compat_digests(passwd=self.SPACED + "-c d::::::\n")
        self.assertTrue(ra["compat_directives"]["etc/passwd"][0]["malformed"])
        self.assertNotEqual(da, db)
        for r in (ra, rb):
            blob = json.dumps([r["compat_directive_topology"], r["compat_directives"]])
            self.assertNotIn("a b", blob)
            self.assertNotIn("c d", blob)

    def test_directive_name_keys_are_never_output(self):
        r, _ = self.compat_digests(passwd=self.SPACED + "-SECRET X::::::\n")
        self.assertNotIn("SECRET", json.dumps(r))
        self.assertNotIn(textbytes_hex("SECRET X"), json.dumps(r))

    # Red team pass 7 (each reproduced by the NSS-aware harness first).
    COMPAT = "passwd: compat\ngroup: compat\nshadow: compat\n"
    ALICE = "zed:x:1007:1007::/h:/bin/sh\n"

    def test_p7_f1_initgroups_reading_the_file_literally_is_not_compat(self):
        for ig in ("files", "files [SUCCESS=continue]", "sss files", "db files"):
            r = self.collect("passwd: compat\ngroup: compat\ninitgroups: %s\nshadow: compat\n"
                             % ig, passwd=NORMAL_PASSWD + self.ALICE,
                             group=NORMAL_GROUP + "+wheel:x:0:zed\n")
            src = r["sources"]["etc/group"]
            self.assertEqual(src["status"], model.PARTIAL, ig)
            self.assertIn(model.REASON_NSS_MODE_NOT_ASSERTED, src["reason"], ig)
        r = self.collect("passwd: compat\ngroup: compat\ninitgroups: compat\nshadow: compat\n",
                         passwd=NORMAL_PASSWD + self.ALICE, group=NORMAL_GROUP + "+\n")
        self.assertEqual(r["sources"]["etc/group"]["status"], model.COLLECTED)

    def test_p7_f2_a_local_record_after_an_exclude_naming_it_is_not_confident(self):
        for exclude in ("-zed\n", "-zed::::::\n", "-@ng::::::\n"):
            r = self.collect(self.COMPAT, passwd=NORMAL_PASSWD + exclude + self.ALICE)
            src = r["sources"]["etc/passwd"]
            self.assertEqual(src["status"], model.PARTIAL, exclude)
            self.assertIn(model.REASON_COMPAT_LOCAL_AFTER_EXCLUDE, src["reason"], exclude)
            alice = [x for x in r["local_accounts"] if x["name"] == "zed"][0]
            self.assertIn(model.ANOMALY_AFTER_COMPAT_EXCLUDE, alice["passwd_anomalies"], exclude)
        # An EXCLUDE naming someone else leaves zed alone.
        r = self.collect(self.COMPAT, passwd=NORMAL_PASSWD + "-bob\n" + self.ALICE)
        self.assertEqual(r["sources"]["etc/passwd"]["status"], model.COLLECTED)
        # Group and shadow too.
        r = self.collect(self.COMPAT, group=NORMAL_GROUP + "-wheel\nwheel:x:10:alice\n")
        self.assertEqual(r["sources"]["etc/group"]["status"], model.PARTIAL)

    def test_p7_f3_the_shadow_join_never_trusts_a_compat_uncertain_record(self):
        for shadow in ("+zed\nzed:$6$s$h:1:2:3:4:::\n", "-zed\nzed:$6$s$h:1:2:3:4:::\n",
                       "+\nzed:$6$s$h:1:2:3:4:::\n"):
            r = self.collect(self.COMPAT, passwd=NORMAL_PASSWD + self.ALICE,
                             shadow=NORMAL_SHADOW + shadow)
            alice = [x for x in r["local_accounts"] if x["name"] == "zed"][0]
            self.assertEqual(alice["shadow_record"], model.RECORD_SOURCE_NOT_COLLECTED, shadow)
            self.assertIsNone(alice["shadow"], shadow)

    def test_p7_f4_records_after_compat_syntax_in_an_unknown_mode_are_not_confident(self):
        r = self.collect("passwd: files\npasswd: compat\ngroup: compat\nshadow: compat\n",
                         passwd=NORMAL_PASSWD + "+\n" + self.ALICE)
        alice = [x for x in r["local_accounts"] if x["name"] == "zed"][0]
        self.assertIn(model.ANOMALY_AFTER_UNINTERPRETED_COMPAT, alice["passwd_anomalies"])
        root_ = [x for x in r["local_accounts"] if x["name"] == "root"][0]
        self.assertEqual(root_["passwd_anomalies"], [])

    def test_p7_f5_undecodable_override_bytes_never_crash_and_serialize(self):
        from isedraf import canonical
        for passwd, group in ((b"+alice:x::::/home/j\xf6rg:/bin/sh\n", None),
                              (b"+alice:x:::J\xf6rg::\n", None),
                              (None, b"+wheel:x::j\xf6rg\n")):
            root = self.root(self.COMPAT)
            for name, extra, base in (("passwd", passwd, NORMAL_PASSWD),
                                      ("group", group, NORMAL_GROUP)):
                if extra:
                    with open(os.path.join(root, "etc", name), "wb") as fh:
                        fh.write(base.encode() + extra)
            context = acquire.compat_context(nss_acquire.collect(root))
            r = acquire.collect(root, nss_context=context)
            canonical.canonical_bytes(r)

    def test_p7_f7_group_directives_keep_no_override_text(self):
        r = self.collect(self.COMPAT, group=NORMAL_GROUP + "+wheel:x::SECRETMEMBER\n")
        self.assertNotIn("SECRETMEMBER", json.dumps(r))

    # Owner ruling IQ-037: collection truth is not effective-resolution truth.

    def effectiveness(self, nsswitch):
        return acquire.file_effectiveness(nss_acquire.collect(self.root(nsswitch)))

    def test_iq037_file_effectiveness_is_its_own_fact(self):
        cases = {
            "passwd: files\n": model.FILES_ACTIVE,
            "passwd: compat\n": model.FILES_ACTIVE,
            "passwd: sss files\n": model.FILES_ACTIVE,
            "passwd: files systemd\n": model.FILES_ACTIVE,
            "passwd: sss\n": model.FILES_INACTIVE,
            "passwd: ldap systemd\n": model.FILES_INACTIVE,
            "passwd: Compat\n": model.FILES_NOT_ASSERTED,
            "passwd: extrausers files\n": model.FILES_NOT_ASSERTED,
            "group: files\n": model.FILES_NOT_ASSERTED,          # passwd undeclared
            "passwd: files\npasswd: sss\n": model.FILES_NOT_ASSERTED,
            "passwd: files [MAYBE=return]\n": model.FILES_NOT_ASSERTED,
        }
        for text, expected in cases.items():
            self.assertEqual(self.effectiveness(text)["etc/passwd"]["files_effective"],
                             expected, text)
        self.assertEqual(acquire.file_effectiveness(None)["etc/passwd"]["files_effective"],
                         model.FILES_NOT_ASSERTED)
        e = self.effectiveness("passwd: sss\n")["etc/passwd"]
        self.assertEqual(e["configured_services"], ["sss"])

    def test_iq037_records_stay_collected_when_nss_ignores_the_file(self):
        root = self.root("passwd: sss\ngroup: sss\nshadow: sss\n", passwd=NORMAL_PASSWD)
        nss = nss_acquire.collect(root)
        r = acquire.collect(root, nss_context=acquire.compat_context(nss),
                            effectiveness=acquire.file_effectiveness(nss))
        self.assertEqual(r["collection_status"], model.COLLECTED)
        self.assertTrue(all(not a["passwd_anomalies"] for a in r["local_accounts"]))
        self.assertEqual(r["nss_file_effectiveness"]["etc/passwd"]["files_effective"],
                         model.FILES_INACTIVE)

    def test_iq037_without_nss_evidence_effectiveness_is_not_asserted(self):
        r = acquire.collect(self.root(None, passwd=NORMAL_PASSWD))
        self.assertEqual(r["nss_file_effectiveness"]["etc/passwd"]["files_effective"],
                         model.FILES_NOT_ASSERTED)

    # Red team pass 8 (each reproduced by the harness first).

    def test_p8_n1_a_compat_map_that_is_the_local_file_is_not_compat(self):
        nss = ("passwd: compat\npasswd_compat: files\ngroup: compat\ngroup_compat: files\n"
               "shadow: compat\nshadow_compat: files\n")
        r = self.collect(nss, passwd=NORMAL_PASSWD + "+::::::\n", group=NORMAL_GROUP + "+:::\n")
        for rel in ("etc/passwd", "etc/group"):
            self.assertEqual(r["sources"][rel]["status"], model.PARTIAL, rel)
            self.assertIn(model.REASON_NSS_MODE_NOT_ASSERTED, r["sources"][rel]["reason"], rel)
        ctx = self.collect("passwd: compat\npasswd_compat: sss\n")
        self.assertEqual(ctx["nss_compat_context"]["etc/passwd"], model.NSS_COMPAT)

    def test_p8_n3_initgroups_in_a_different_mode_from_group_is_not_asserted(self):
        r = self.collect("passwd: files\ngroup: files\ninitgroups: compat\nshadow: files\n",
                         passwd=NORMAL_PASSWD + self.ALICE, group=NORMAL_GROUP + "+\nwheel:x:10:zed\n")
        wheel = [g for g in r["local_groups"] if g["name"] == "wheel"][0]
        self.assertTrue(wheel["group_anomalies"])

    def test_p8_n2_an_earlier_same_name_line_glibc_accepts_shadows_a_later_one(self):
        for first in ("zed:x:0:0::/r:/bin/sh:extra\n", "zed:x:0:0::/r\n"):
            r = self.collect("passwd: files\ngroup: files\nshadow: files\n",
                             passwd=NORMAL_PASSWD + first + self.ALICE)
            later = [a for a in r["local_accounts"] if a["name"] == "zed"]
            self.assertEqual(len(later), 1, first)
            self.assertIn(model.ANOMALY_SHADOWED_BY_EARLIER_LINE, later[0]["passwd_anomalies"])
        r = self.collect("passwd: files\ngroup: files\nshadow: files\n",
                         group=NORMAL_GROUP + "wheel:x:0:zed:extra\nwheel:x:10:bob\n")
        wheel = [g for g in r["local_groups"] if g["name"] == "wheel"][0]
        self.assertIn(model.ANOMALY_SHADOWED_BY_EARLIER_LINE, wheel["group_anomalies"])

    def test_p8_n4_undecodable_record_text_is_exact_and_serializable(self):
        from isedraf import canonical
        root = self.root("passwd: files\ngroup: files\nshadow: files\n")
        with open(os.path.join(root, "etc", "passwd"), "wb") as fh:
            fh.write(NORMAL_PASSWD.encode() + b"zed:x:1:1:G\xf6:/h\xff:/bin/\xfe\n")
        nss = nss_acquire.collect(root)
        r = acquire.collect(root, nss_context=acquire.compat_context(nss),
                            effectiveness=acquire.file_effectiveness(nss))
        canonical.canonical_bytes(r)
        zed = [a for a in r["local_accounts"] if a["name"] == "zed"][0]
        self.assertEqual((zed["gecos"], zed["home"], zed["shell"]),
                         ("hex:47f6", "hex:2f68ff", "hex:2f62696e2ffe"))
        self.assertEqual(r["collection_status"], model.COLLECTED)

    def test_p8_l2_exclude_overrides_glibc_ignores_keep_no_text(self):
        r = self.collect(self.COMPAT, passwd=NORMAL_PASSWD + "-bob:x:::SECRETGECOS:/SECRETHOME:/bin/SECRETSH\n")
        self.assertNotIn("SECRET", json.dumps([r["compat_directives"], r["compat_directive_topology"]]))

    def test_context_derivation(self):
        cases = {
            "passwd: compat\n": model.NSS_COMPAT,
            "passwd: compat sss\n": model.NSS_COMPAT,
            "passwd: files\n": model.NSS_NOT_COMPAT,
            "passwd: files sss\n": model.NSS_NOT_COMPAT,
            "passwd: sss\n": model.NSS_NOT_COMPAT,
            "passwd: files compat\n": model.NSS_MODE_NOT_ASSERTED,
            "group: files\n": model.NSS_MODE_NOT_ASSERTED,
        }
        for text, expected in cases.items():
            root = self.root(text)
            ctx = acquire.compat_context(nss_acquire.collect(root))
            self.assertEqual(ctx["etc/passwd"], expected, text)
        self.assertEqual(acquire.compat_context(None)["etc/passwd"], model.NSS_MODE_NOT_ASSERTED)


if __name__ == "__main__":
    unittest.main(verbosity=0)
