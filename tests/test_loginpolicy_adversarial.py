# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Attack the login-policy lane from its contract, before the code exists.
# Implements: SCOPE-022, SCOPE-045, GOV-002
#
# RED, PASS 1. Written against LOGINPOLICY_LANE_CONTRACT.md with no implementation to
# read. The central attack is the one S1's grammar identity exists to make possible:
# a profile applied to the wrong source family. S1 can record WHICH grammar parsed a
# declaration, but only the domain can choose the right one, and choosing wrongly
# produces confident, well-provenanced nonsense.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""Independent adversarial attack on the login-policy lane."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import result                            # noqa: E402
from isedraf.loginpolicy import acquire, model               # noqa: E402


class Fixture(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)

    def write(self, relative, text, mode=None):
        path = os.path.join(self.base, relative)
        directory = os.path.dirname(path)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        with open(path, "w") as handle:
            handle.write(text)
        if mode is not None:
            os.chmod(path, mode)
        return path

    def collect(self, **files):
        for relative, text in files.items():
            self.write(relative.replace("__", "/"), text)
        return acquire.collect(self.base)

    def family(self, ev, name):
        return [r for r in ev.records if r["family"] == name]

    def keyed(self, ev, key):
        return [r for r in ev.records if r.get("key") == key]


class GrammarSelection(Fixture):
    """The domain must choose the right profile. S1 only records which one it used."""

    def test_login_defs_is_whitespace_delimited_not_equals(self):
        ev = self.collect(**{"etc__login.defs": "PASS_MAX_DAYS 90\n"})
        records = self.family(ev, model.LOGIN_DEFS)
        self.assertEqual(records[0]["key"], "PASS_MAX_DAYS")
        self.assertEqual(records[0]["value"], "90")

    def test_login_defs_value_containing_equals_is_not_split_on_it(self):
        # Applying a `=` profile here would produce key "PASS_MAX_DAYS 90" or truncate.
        ev = self.collect(**{"etc__login.defs": "ENCRYPT_METHOD SHA512\n"
                                                "CHFN_RESTRICT rwh\n"})
        self.assertEqual(len(self.family(ev, model.LOGIN_DEFS)), 2)

    def test_pwquality_is_equals_delimited(self):
        ev = self.collect(**{"etc__security__pwquality.conf": "minlen = 12\n"})
        record = self.family(ev, model.PWQUALITY)[0]
        self.assertEqual(record["key"], "minlen")
        self.assertEqual(record["value"], "12")

    def test_a_pwquality_line_is_not_parsed_with_the_login_defs_profile(self):
        # The decisive test. `minlen = 12` under a whitespace profile yields key "minlen"
        # and value "= 12", which is confident, well-provenanced nonsense.
        ev = self.collect(**{"etc__security__pwquality.conf": "minlen = 12\n"})
        self.assertEqual(self.family(ev, model.PWQUALITY)[0]["value"], "12")

    def test_a_login_defs_line_is_not_parsed_with_the_pwquality_profile(self):
        ev = self.collect(**{"etc__login.defs": "UMASK 022\n"})
        self.assertEqual(self.family(ev, model.LOGIN_DEFS)[0]["value"], "022")

    def test_each_family_records_a_distinct_grammar_digest(self):
        ev = self.collect(**{"etc__login.defs": "UMASK 022\n",
                             "etc__security__pwquality.conf": "minlen = 12\n"})
        digests = {r["family"]: r["grammar_digest"] for r in ev.records
                   if r.get("grammar_digest")}
        self.assertNotEqual(digests.get(model.LOGIN_DEFS),
                            digests.get(model.PWQUALITY))

    def test_limits_is_not_key_value_at_all(self):
        # Four positional fields. A key/value parser must not be used here: there is no
        # key, and inventing one is the mistake sudoers avoided.
        ev = self.collect(**{"etc__security__limits.conf": "* hard nofile 65535\n"})
        record = self.family(ev, model.LIMITS)[0]
        self.assertEqual(record["domain"], "*")
        self.assertEqual(record["limit_type"], "hard")
        self.assertEqual(record["item"], "nofile")
        self.assertEqual(record["value"], "65535")
        self.assertNotIn("key", record)

    def test_limits_negated_domain_is_preserved(self):
        ev = self.collect(**{"etc__security__limits.conf": "@staff soft nproc 100\n"
                                                           "%group hard nproc 200\n"})
        self.assertEqual(len(self.family(ev, model.LIMITS)), 2)

    def test_limits_with_wrong_field_count_is_unsupported_not_guessed(self):
        ev = self.collect(**{"etc__security__limits.conf": "* hard\n"})
        self.assertNotEqual(ev.status, result.COLLECTED)


class Declarations(Fixture):
    """Preserve what each source says. Resolve nothing across sources."""

    def test_duplicate_keys_are_both_kept(self):
        ev = self.collect(**{"etc__login.defs": "PASS_MAX_DAYS 90\n"
                                                "PASS_MAX_DAYS 30\n"})
        values = [r["value"] for r in self.keyed(ev, "PASS_MAX_DAYS")]
        self.assertEqual(values, ["90", "30"])

    def test_duplicate_is_marked(self):
        ev = self.collect(**{"etc__login.defs": "UMASK 022\nUMASK 077\n"})
        self.assertIsNotNone(self.keyed(ev, "UMASK")[1].get("duplicate_of"))

    def test_same_key_in_main_file_and_fragment_keeps_both(self):
        ev = self.collect(**{"etc__security__pwquality.conf": "minlen = 8\n",
                             "etc__security__pwquality.conf.d__50-x.conf": "minlen = 14\n"})
        self.assertEqual([r["value"] for r in self.keyed(ev, "minlen")], ["8", "14"])

    def test_no_effective_value_is_computed_across_sources(self):
        # login.defs PASS_MAX_DAYS and a per-account shadow value are evidence at
        # different layers. Collapsing them needs PAM, account state and distribution
        # behaviour, and none of that is available here.
        ev = self.collect(**{"etc__login.defs": "PASS_MAX_DAYS 90\n",
                             "etc__security__pwquality.conf": "minlen = 12\n"})
        # Scan the RECORDS, not the whole envelope. An earlier version of this test
        # searched the serialized result and failed on the limitation text, which uses
        # the word "effective" precisely to deny that any such value exists - and it
        # contradicted test_the_limitation_travels_with_the_evidence, which requires
        # that same word to be present. A test oracle defect, not an implementation one.
        blob = json.dumps(ev.records).lower()
        for word in ("effective", "resolved_value", "winner", "applied_value",
                     "final_value"):
            self.assertNotIn(word, blob, word)
        # And no record may claim authority over another source's declaration.
        for record in ev.records:
            self.assertNotIn("overrides", record)
            self.assertNotIn("overridden_by", record)

    def test_unknown_key_is_evidence_not_an_error(self):
        ev = self.collect(**{"etc__login.defs": "SOME_NEW_OPTION_2027 1\n"})
        self.assertEqual(ev.status, result.COLLECTED)

    def test_empty_value(self):
        ev = self.collect(**{"etc__security__pwquality.conf": "minlen =\n"})
        self.assertEqual(self.keyed(ev, "minlen")[0]["value"], "")

    def test_malformed_and_unusual_numeric_values_are_preserved_as_written(self):
        # The parser does not validate. -1, 0 and 99999 are sentinels in several of
        # these formats and turning them into anything else is interpretation.
        ev = self.collect(**{"etc__login.defs": "PASS_MIN_DAYS -1\n"
                                                "PASS_WARN_AGE notanumber\n"
                                                "UID_MAX 4294967295\n"})
        values = [r["value"] for r in self.family(ev, model.LOGIN_DEFS)]
        self.assertEqual(values, ["-1", "notanumber", "4294967295"])

    def test_comments_and_blank_lines_are_not_records(self):
        ev = self.collect(**{"etc__login.defs": "# comment\n\n   \nUMASK 022\n"})
        self.assertEqual(len(self.family(ev, model.LOGIN_DEFS)), 1)


class Fragments(Fixture):
    """The .d directories, through S5, with the domain choosing eligibility."""

    def test_empty_fragment_directory_is_a_normal_configuration(self):
        os.makedirs(os.path.join(self.base, "etc/security/limits.d"))
        ev = self.collect(**{"etc__security__limits.conf": "* hard nofile 1024\n"})
        self.assertEqual(ev.status, result.COLLECTED)

    def test_multiple_fragments_are_read_in_deterministic_order(self):
        ev = self.collect(**{"etc__security__limits.conf": "* hard nofile 1\n",
                             "etc__security__limits.d__20-b.conf": "* hard nproc 20\n",
                             "etc__security__limits.d__10-a.conf": "* hard nproc 10\n"})
        items = [r["value"] for r in self.family(ev, model.LIMITS)]
        self.assertEqual(items, ["1", "10", "20"])

    def test_undecodable_fragment_filename_does_not_crash_or_merge(self):
        directory = os.path.join(self.base, "etc/security/limits.d")
        os.makedirs(directory)
        for raw in (b"odd\xe9.conf", b"odd\xff.conf"):
            with open(os.path.join(os.fsencode(directory), raw), "wb") as handle:
                handle.write(b"* hard nproc 1\n")
        self.write("etc/security/limits.conf", "* hard nofile 1\n")
        self.assertIsNotNone(acquire.collect(self.base).status)

    def test_missing_source_is_reported_not_invented(self):
        ev = self.collect(**{"etc__login.defs": "UMASK 022\n"})
        sources = {s["family"]: s for s in ev.provenance["sources"]}
        self.assertEqual(sources[model.PWQUALITY]["status"], result.NOT_TESTED)

    def test_unreadable_source_is_not_tested_not_error(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores these permission bits")
        self.write("etc/login.defs", "UMASK 022\n", mode=0)
        ev = acquire.collect(self.base)
        sources = {s["family"]: s for s in ev.provenance["sources"]}
        self.assertEqual(sources[model.LOGIN_DEFS]["status"], result.NOT_TESTED)

    def test_no_source_at_all_is_not_tested(self):
        self.assertEqual(acquire.collect(self.base).status, result.NOT_TESTED)


class Confinement(Fixture):
    """The defect class the sudo lane found. Attack it directly."""

    def test_a_fixture_root_never_reads_the_live_etc(self):
        ev = self.collect(**{"etc__login.defs": "UMASK 022\n"})
        for record in ev.records:
            self.assertTrue(record["source_path"].startswith(self.base),
                            record["source_path"])
        for source in ev.provenance["sources"]:
            if source.get("path"):
                self.assertTrue(source["path"].startswith(self.base), source["path"])

    def test_the_main_source_path_is_resolved_under_the_collection_root(self):
        ev = self.collect(**{"etc__login.defs": "UMASK 022\n"})
        for source in ev.provenance["sources"]:
            if source.get("path"):
                self.assertTrue(source["path"].startswith(self.base), source["path"])

    def test_a_symlinked_fragment_is_not_followed_out_of_the_root(self):
        os.makedirs(os.path.join(self.base, "etc/security/limits.d"))
        os.symlink("/etc", os.path.join(self.base, "etc/security/limits.d/escape"))
        ev = self.collect(**{"etc__security__limits.conf": "* hard nofile 1\n"})
        for record in ev.records:
            self.assertTrue(record["source_path"].startswith(self.base))


class Privacy(Fixture):

    def test_the_limitation_travels_with_the_evidence(self):
        ev = self.collect(**{"etc__login.defs": "UMASK 022\n"})
        self.assertIn("effective", ev.provenance["limitation"].lower())

    def test_unparsed_line_content_is_digested_not_retained(self):
        # A mistyped pwquality entry would otherwise retain its dictpath verbatim: for a
        # malformed line the key/value parser keeps the WHOLE line as key_raw, having
        # found no delimiter. sudo, ssh and pam all digest unparsed content; this domain
        # does the same.
        ev = self.collect(**{"etc__security__pwquality.conf":
                             "dictpath /usr/local/LPSECRETFIXTUREONLY/words\n"})
        import json as _json
        self.assertNotIn("LPSECRETFIXTUREONLY", _json.dumps(ev.records))
        self.assertTrue(ev.records[0]["raw_digest"].startswith("sha256:"))

    def test_no_security_verdict_vocabulary(self):
        ev = self.collect(**{"etc__security__pwquality.conf": "minlen = 4\n"})
        blob = json.dumps(ev.records).lower()
        for word in ("weak", "strong", "insecure", "compliant", "too_short",
                     "recommended", "violation"):
            self.assertNotIn(word, blob, word)


if __name__ == "__main__":
    unittest.main(verbosity=0)
