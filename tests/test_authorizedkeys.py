# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The authorized-key source lane: what it records, and what it refuses to say.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, IDENT-041, GOV-002
#
# The fingerprint tests use `ssh-keygen -lf` as an EXECUTABLE ORACLE. A digest scheme
# that only agrees with itself is a scheme nobody has checked, and this one is meant to
# be the same value an administrator sees in their own tooling.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3,ssh-keygen"
# =============================================================================

"""Candidate authorized-key sources: observation, completeness and restraint."""
import ast
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.accounts import acquire as accounts_acquire       # noqa: E402
from isedraf.authorizedkeys import acquire, model, sources     # noqa: E402
from isedraf.shared import result                              # noqa: E402
from isedraf.ssh import acquire as ssh_acquire                 # noqa: E402

HAVE_KEYGEN = bool(shutil.which("ssh-keygen"))

# A syntactically valid ed25519 entry that is not anyone's key: generated once, by
# ssh-keygen, into a temporary directory, and pasted here so the grammar tests do not
# depend on a binary being present.
KEY_A = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb6vY0nYQ5oYtPLDkbXPVi5Ij7C5Ks6q"
         "Vn7z3Wm4Xqk")
KEY_B = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA+9ZPcLNBT0mVVdEZYkT1p7wS0OcdDs0"
         "nIKQhVyEaZn")


class Fixture(unittest.TestCase):
    """A collection root with a sibling that must never be reached."""

    def setUp(self):
        self.enclosure = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.enclosure, True)
        self.root = os.path.join(self.enclosure, "root")
        self.outside = os.path.join(self.enclosure, "outside")
        os.makedirs(os.path.join(self.root, "etc", "ssh"))
        os.makedirs(self.outside)

    def write(self, relative, text):
        path = os.path.join(self.root, relative)
        directory = os.path.dirname(path)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        with open(path, "w") as handle:
            handle.write(text)
        return path

    def host(self, passwd=None, sshd_config="Port 22\n", shadow=None):
        self.write("etc/passwd",
                   passwd or "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n")
        self.write("etc/group", "alice:x:1000:\n")
        if shadow is not None:
            self.write("etc/shadow", shadow)
        self.write("etc/ssh/sshd_config", sshd_config)

    def collect(self, **extra):
        return acquire.collect(self.root,
                               accounts_acquire.collect(self.root),
                               ssh_acquire.collect(self.root), **extra)

    def blob(self, evidence):
        return json.dumps({"records": evidence.records,
                           "provenance": evidence.provenance}, default=str)

    def plan(self, evidence, index=0):
        return evidence.provenance["source_plans"][index]


class NoDeclarationInventsNothing(Fixture):
    """The central refusal of the lane."""

    def test_a_conventional_file_is_not_read_without_a_declaration(self):
        self.host()
        self.write("home/alice/.ssh/authorized_keys", KEY_A + " alice@corp.example\n")
        evidence = self.collect()
        self.assertEqual(evidence.records, [])
        self.assertNotIn("AAAAC3NzaC1lZDI1NTE5AAAAIGb6", self.blob(evidence))
        self.assertNotIn("corp.example", self.blob(evidence))

    def test_the_universe_says_why(self):
        self.host()
        evidence = self.collect()
        self.assertIn(model.NO_DECLARATION_OBSERVED,
                      self.plan(evidence)["universe_reasons"])
        self.assertEqual(self.plan(evidence)["source_universe"],
                         model.UNIVERSE_INCOMPLETE)

    def test_no_candidate_path_is_produced_at_all(self):
        self.host()
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        self.assertEqual(self.plan(self.collect())["candidates"], [])

    def test_the_status_is_not_tested_not_collected(self):
        # COLLECTED would say "we looked and there is nothing". There was no place to
        # look, which is a different statement.
        self.host()
        self.assertEqual(self.collect().status, model.NOT_TESTED)


class DeclaredCandidates(Fixture):

    def test_a_relative_value_is_resolved_against_the_accounts_home(self):
        self.host(sshd_config="AuthorizedKeysFile .ssh/authorized_keys\n")
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        evidence = self.collect()
        self.assertEqual(len(evidence.records), 1)
        candidate = self.plan(evidence)["candidates"][0]
        self.assertEqual(candidate["observation"], model.FILE_READ)
        self.assertTrue(candidate["path"].startswith(self.root))

    def test_an_absolute_value_is_mapped_under_the_collection_root(self):
        self.host(sshd_config="AuthorizedKeysFile /etc/ssh/keys/alice\n")
        self.write("etc/ssh/keys/alice", KEY_A + "\n")
        evidence = self.collect()
        self.assertEqual(len(evidence.records), 1)
        self.assertEqual(self.plan(evidence)["candidates"][0]["path"],
                         os.path.join(self.root, "etc/ssh/keys/alice"))

    def test_several_values_on_one_declaration_become_several_candidates(self):
        self.host(sshd_config=("AuthorizedKeysFile .ssh/authorized_keys "
                               ".ssh/authorized_keys2\n"))
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        self.write("home/alice/.ssh/authorized_keys2", KEY_B + "\n")
        evidence = self.collect()
        self.assertEqual(len(self.plan(evidence)["candidates"]), 2)
        self.assertEqual(len(evidence.records), 2)

    def test_none_is_a_declaration_not_a_path(self):
        self.host(sshd_config="AuthorizedKeysFile none\n")
        candidate = self.plan(self.collect())["candidates"][0]
        self.assertEqual(candidate["resolution"], model.DECLARED_NONE)
        self.assertIsNone(candidate["path"])

    def test_an_absent_candidate_is_recorded_as_absent(self):
        self.host(sshd_config="AuthorizedKeysFile .ssh/authorized_keys\n")
        candidate = self.plan(self.collect())["candidates"][0]
        self.assertEqual(candidate["observation"], model.FILE_ABSENT)


class MatchScopeSurvives(Fixture):

    CONFIG = ("AuthorizedKeysFile .ssh/authorized_keys\n"
              "Match User alice\n"
              "    AuthorizedKeysFile /etc/ssh/match/%u\n")

    def test_a_match_scoped_candidate_is_never_resolved(self):
        self.host(sshd_config=self.CONFIG)
        self.write("etc/ssh/match/alice", KEY_A + "\n")
        plan = self.plan(self.collect())
        scoped = [c for c in plan["candidates"]
                  if c["declaration"]["scope"] == "MATCH"]
        self.assertEqual(len(scoped), 1)
        self.assertEqual(scoped[0]["applicability"], model.UNRESOLVED_MATCH_SCOPED)
        self.assertEqual(scoped[0]["resolution"], model.PATH_DERIVED)

    def test_the_criteria_travel_with_the_candidate(self):
        self.host(sshd_config=self.CONFIG)
        plan = self.plan(self.collect())
        scoped = [c for c in plan["candidates"]
                  if c["declaration"]["scope"] == "MATCH"][0]
        self.assertEqual(scoped["declaration"]["match_criteria"],
                         [{"keyword": "user", "values": ["alice"], "negated": False}])

    def test_a_match_scoped_declaration_makes_the_universe_incomplete(self):
        self.host(sshd_config=self.CONFIG)
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        self.write("etc/ssh/match/alice", KEY_B + "\n")
        plan = self.plan(self.collect())
        self.assertEqual(plan["source_universe"], model.UNIVERSE_INCOMPLETE)
        self.assertIn(model.MATCH_SCOPED_DECLARATION, plan["universe_reasons"])

    def test_records_from_a_match_scope_carry_it(self):
        self.host(sshd_config=self.CONFIG)
        self.write("etc/ssh/match/alice", KEY_A + "\n")
        evidence = self.collect()
        scoped = [r for r in evidence.records if r["declaration_scope"] == "MATCH"]
        self.assertEqual(len(scoped), 1)
        self.assertEqual(scoped[0]["declaration_applicability"],
                         model.UNRESOLVED_MATCH_SCOPED)

    def test_the_lane_never_claims_a_candidate_applies_to_the_account(self):
        self.host(sshd_config=self.CONFIG)
        for candidate in self.plan(self.collect())["candidates"]:
            self.assertEqual(candidate["applies_to_account"], "UNDETERMINED")


class ObservedIsNotComplete(Fixture):
    """A file read perfectly settles that file, and nothing else."""

    def test_one_good_read_beside_one_unresolved_declaration(self):
        self.host(sshd_config=("AuthorizedKeysFile .ssh/authorized_keys\n"
                               "Match User alice\n"
                               "    AuthorizedKeysFile .ssh/extra\n"))
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        evidence = self.collect()
        self.assertEqual(len(evidence.records), 1)
        self.assertEqual(self.plan(evidence)["source_universe"],
                         model.UNIVERSE_INCOMPLETE)

    def test_an_unreadable_candidate_is_not_an_empty_one(self):
        self.host(sshd_config="AuthorizedKeysFile .ssh/authorized_keys\n")
        path = self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        os.chmod(path, 0)
        # LIFO: registered after the enclosure rmtree, so it runs BEFORE it.
        self.addCleanup(os.chmod, path, 0o600)
        plan = self.plan(self.collect())
        self.assertEqual(plan["candidates"][0]["observation"], model.FILE_UNREADABLE)
        self.assertIn(model.CANDIDATE_NOT_OBSERVED, plan["universe_reasons"])

    def test_incomplete_account_evidence_propagates(self):
        self.host(sshd_config="AuthorizedKeysFile .ssh/authorized_keys\n")
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        # No etc/shadow, so the account evidence is itself PARTIAL.
        plan = self.plan(self.collect())
        self.assertIn(model.ACCOUNT_EVIDENCE_INCOMPLETE, plan["universe_reasons"])

    def test_a_complete_universe_is_reachable(self):
        # Otherwise INCOMPLETE would be a constant rather than a finding.
        self.host(sshd_config="AuthorizedKeysFile .ssh/authorized_keys\n",
                  shadow="alice:!:19000:0:99999:7:::\n")
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        plan = self.plan(self.collect())
        self.assertEqual(plan["universe_reasons"], [])
        self.assertEqual(plan["source_universe"], model.UNIVERSE_COMPLETE)


@unittest.skipIf(os.geteuid() == 0, "root bypasses the permission bits these cases need")
class DeniedIsNotAbsent(Fixture):
    """IQ-044: a path the collector cannot examine is unobserved, never absent.

    ENOENT is absence; EACCES or EPERM on lstat is a statement about who is asking. GA
    0.1.0 recorded the second as FILE_ABSENT, which left the universe COMPLETE, the
    section COLLECTED and the coverage entry free to claim absence.
    """

    DECLARED = "AuthorizedKeysFile .ssh/authorized_keys\n"
    SHADOW = "alice:!:19000:0:99999:7:::\n"

    def deny(self, relative):
        path = os.path.join(self.root, relative)
        os.chmod(path, 0)
        # LIFO: registered after the enclosure rmtree, so it runs BEFORE it.
        self.addCleanup(os.chmod, path, 0o700)

    def coverage_for(self, evidence, suffix):
        entries = [c for c in evidence.provenance["coverage"]
                   if c["source"].endswith(suffix)]
        self.assertEqual(len(entries), 1, entries)
        return entries[0]

    def test_an_untraversable_home_is_not_absent(self):
        self.host(sshd_config=self.DECLARED, shadow=self.SHADOW)
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        self.deny("home/alice")
        evidence = self.collect()
        plan = self.plan(evidence)
        candidate = plan["candidates"][0]
        self.assertNotEqual(candidate["observation"], model.FILE_ABSENT)
        self.assertEqual(candidate["observation"], model.FILE_UNREADABLE)
        self.assertEqual(candidate["observation_detail"], "PERMISSION_DENIED")
        self.assertIn(model.CANDIDATE_NOT_OBSERVED, plan["universe_reasons"])
        self.assertEqual(plan["source_universe"], model.UNIVERSE_INCOMPLETE)
        self.assertEqual(evidence.status, result.PARTIAL)

    def test_an_untraversable_home_never_permits_an_absence_claim(self):
        self.host(sshd_config=self.DECLARED, shadow=self.SHADOW)
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        self.deny("home/alice")
        entry = self.coverage_for(self.collect(), "authorized_keys")
        self.assertEqual(entry["access_outcome"], "PERMISSION_DENIED")
        self.assertTrue(entry["privilege_limited"])
        self.assertFalse(entry["absence_claim_allowed"])

    def test_an_untraversable_parent_of_a_declared_absolute_path(self):
        self.host(sshd_config="AuthorizedKeysFile /etc/ssh/keys/%u\n",
                  shadow=self.SHADOW)
        self.write("etc/ssh/keys/alice", KEY_A + "\n")
        self.deny("etc/ssh/keys")
        evidence = self.collect()
        plan = self.plan(evidence)
        self.assertEqual(plan["candidates"][0]["observation"], model.FILE_UNREADABLE)
        self.assertEqual(plan["source_universe"], model.UNIVERSE_INCOMPLETE)
        self.assertEqual(evidence.status, result.PARTIAL)

    def test_a_truly_absent_file_is_still_absent_and_complete(self):
        # The fix must not turn real absence into doubt: ENOENT stays FILE_ABSENT, and
        # with nothing else unobserved the universe stays COMPLETE.
        self.host(sshd_config=self.DECLARED, shadow=self.SHADOW)
        os.makedirs(os.path.join(self.root, "home", "alice"))
        evidence = self.collect()
        plan = self.plan(evidence)
        self.assertEqual(plan["candidates"][0]["observation"], model.FILE_ABSENT)
        self.assertEqual(plan["source_universe"], model.UNIVERSE_COMPLETE)
        self.assertEqual(evidence.status, result.COLLECTED)
        entry = self.coverage_for(evidence, "authorized_keys")
        self.assertEqual(entry["access_outcome"], "NOT_FOUND")
        self.assertTrue(entry["absence_claim_allowed"])

    def test_a_present_readable_file_is_observed(self):
        self.host(sshd_config=self.DECLARED, shadow=self.SHADOW)
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        evidence = self.collect()
        self.assertEqual(self.plan(evidence)["candidates"][0]["observation"],
                         model.FILE_READ)
        self.assertEqual(evidence.status, result.COLLECTED)


class Tokens(Fixture):

    def test_percent_h_expands_to_the_rooted_home(self):
        self.host(sshd_config="AuthorizedKeysFile %h/.ssh/keys\n")
        self.write("home/alice/.ssh/keys", KEY_A + "\n")
        self.assertEqual(len(self.collect().records), 1)

    def test_percent_u_expands_to_the_account_name(self):
        self.host(sshd_config="AuthorizedKeysFile /etc/ssh/keys/%u\n")
        self.write("etc/ssh/keys/alice", KEY_A + "\n")
        self.assertEqual(len(self.collect().records), 1)

    def test_percent_capital_u_expands_to_the_uid(self):
        self.host(sshd_config="AuthorizedKeysFile /etc/ssh/keys/%U\n")
        self.write("etc/ssh/keys/1000", KEY_A + "\n")
        self.assertEqual(len(self.collect().records), 1)

    def test_double_percent_is_a_literal(self):
        self.host(sshd_config="AuthorizedKeysFile /etc/ssh/%%keys\n")
        self.write("etc/ssh/%keys", KEY_A + "\n")
        self.assertEqual(len(self.collect().records), 1)

    def test_an_unknown_token_is_never_guessed(self):
        self.host(sshd_config="AuthorizedKeysFile /etc/ssh/keys/%q\n")
        self.write("etc/ssh/keys/alice", KEY_A + "\n")
        evidence = self.collect()
        candidate = self.plan(evidence)["candidates"][0]
        self.assertEqual(candidate["resolution"], model.UNEXPANDED_TOKEN)
        self.assertIsNone(candidate["path"])
        self.assertEqual(evidence.records, [])
        self.assertIn(model.TOKEN_NOT_EXPANDED, self.plan(evidence)["universe_reasons"])

    def test_a_relative_value_without_a_home_is_not_guessed(self):
        self.host(passwd="alice:x:1000:1000:Alice::/bin/bash\n",
                  sshd_config="AuthorizedKeysFile .ssh/authorized_keys\n")
        plan = self.plan(self.collect())
        self.assertEqual(plan["candidates"][0]["resolution"],
                         model.HOME_NOT_AVAILABLE)
        self.assertIn(model.HOME_UNKNOWN, plan["universe_reasons"])


class Globs(Fixture):

    def test_a_glob_matching_several_files_yields_several_reads(self):
        self.host(sshd_config="AuthorizedKeysFile /etc/ssh/keys/*.pub\n")
        self.write("etc/ssh/keys/one.pub", KEY_A + "\n")
        self.write("etc/ssh/keys/two.pub", KEY_B + "\n")
        self.write("etc/ssh/keys/notes.txt", "ignored\n")
        evidence = self.collect()
        self.assertEqual(len(evidence.records), 2)

    def test_a_glob_matching_nothing_is_not_a_missing_file(self):
        self.host(sshd_config="AuthorizedKeysFile /etc/ssh/keys/*.pub\n")
        self.write("etc/ssh/keys/notes.txt", "ignored\n")
        candidate = self.plan(self.collect())["candidates"][0]
        self.assertEqual(candidate["observation"], model.GLOB_NO_MATCH)
        self.assertNotEqual(candidate["observation"], model.FILE_ABSENT)

    def test_an_unenumerable_glob_makes_the_universe_incomplete(self):
        self.host(sshd_config="AuthorizedKeysFile /etc/ssh/keys/*.pub\n")
        directory = os.path.join(self.root, "etc", "ssh", "keys")
        os.makedirs(directory)
        os.chmod(directory, 0)
        self.addCleanup(os.chmod, directory, 0o700)
        plan = self.plan(self.collect())
        self.assertIn(model.GLOB_NOT_ENUMERABLE, plan["universe_reasons"])


class RootContainment(Fixture):
    """hostpath consumer #3. Bait in a sibling of the root, never the live host."""

    def bait(self, name="bait"):
        path = os.path.join(self.outside, name)
        with open(path, "w") as handle:
            handle.write(KEY_A + " outside-the-collection-root\n")
        return path

    def test_a_declaration_climbing_out_is_contained(self):
        self.bait()
        self.host(sshd_config="AuthorizedKeysFile /etc/../../outside/bait\n")
        evidence = self.collect()
        self.assertNotIn("outside-the-collection-root", self.blob(evidence))
        path = self.plan(evidence)["candidates"][0]["path"]
        self.assertTrue(path.startswith(self.root), path)

    def test_a_home_climbing_out_is_contained(self):
        self.bait()
        self.host(passwd="alice:x:1000:1000:A:/home/../../outside:/bin/sh\n",
                  sshd_config="AuthorizedKeysFile bait\n")
        evidence = self.collect()
        self.assertNotIn("outside-the-collection-root", self.blob(evidence))

    def test_a_relative_value_climbing_out_is_contained(self):
        self.bait()
        self.host(sshd_config="AuthorizedKeysFile ../../../outside/bait\n")
        evidence = self.collect()
        self.assertNotIn("outside-the-collection-root", self.blob(evidence))


class Privacy(Fixture):

    CONFIG = "AuthorizedKeysFile .ssh/authorized_keys\n"

    def keys(self, line):
        self.host(sshd_config=self.CONFIG)
        self.write("home/alice/.ssh/authorized_keys", line)
        return self.collect()

    def test_a_comment_is_not_retained(self):
        evidence = self.keys(KEY_A + " alice.smith@corp.example\n")
        self.assertNotIn("alice.smith", self.blob(evidence))
        self.assertNotIn("corp.example", self.blob(evidence))
        self.assertTrue(evidence.records[0]["comment_present"])
        self.assertEqual(evidence.records[0]["comment_retention"], result.NOT_RETAINED)

    def test_a_command_value_is_not_retained_but_its_name_is(self):
        # The values are canaries rather than realistic ones. A test that proved this
        # with a real-looking address would be a test that publishes a real-looking
        # address, and the privacy gate is right to refuse it.
        evidence = self.keys('command="NEVER-RETAIN-THIS-COMMAND" ' + KEY_A + "\n")
        blob = self.blob(evidence)
        self.assertNotIn("NEVER-RETAIN-THIS-COMMAND", blob)
        option = evidence.records[0]["options"][0]
        self.assertEqual(option["name"], "command")
        self.assertTrue(option["value_present"])
        self.assertIsNone(option["value"])
        self.assertEqual(option["value_retention"], result.NOT_RETAINED)

    def test_a_from_value_is_not_retained(self):
        evidence = self.keys('from="NEVER-RETAIN-THIS-ORIGIN" ' + KEY_A + "\n")
        self.assertNotIn("NEVER-RETAIN-THIS-ORIGIN", self.blob(evidence))
        self.assertEqual(evidence.records[0]["options"][0]["name"], "from")

    def test_a_flag_option_retains_its_name_and_says_nothing_was_withheld(self):
        evidence = self.keys("no-pty,restrict " + KEY_A + "\n")
        names = [o["name"] for o in evidence.records[0]["options"]]
        self.assertEqual(names, ["no-pty", "restrict"])
        for option in evidence.records[0]["options"]:
            self.assertFalse(option["value_present"])
            self.assertEqual(option["value_retention"], result.RETAIN_VALUE)

    def test_an_unknown_value_bearing_option_defaults_to_not_retained(self):
        evidence = self.keys('x-future-option="secret-payload" ' + KEY_A + "\n")
        self.assertNotIn("secret-payload", self.blob(evidence))
        self.assertEqual(evidence.records[0]["options"][0]["value_retention"],
                         result.NOT_RETAINED)


class Grammar(unittest.TestCase):
    """The pure parser. No filesystem anywhere in this class."""

    def parse(self, text):
        return sources.parse(text, "/x")

    def test_a_plain_key_parses(self):
        records, malformed = self.parse(KEY_A + "\n")
        self.assertEqual(malformed, 0)
        self.assertEqual(records[0]["key_type"], "ssh-ed25519")
        self.assertEqual(records[0]["blob_type_agreement"], model.BLOB_TYPE_MATCHES)

    def test_blank_and_comment_lines_produce_no_records(self):
        records, _ = self.parse("\n# a comment\n   \n\t# another\n")
        self.assertEqual(records, [])

    def test_crlf_endings_do_not_corrupt_the_key(self):
        records, malformed = self.parse(KEY_A + "\r\n")
        self.assertEqual(malformed, 0)
        self.assertEqual(records[0]["key_type"], "ssh-ed25519")

    def test_malformed_base64_is_recorded_not_dropped(self):
        records, malformed = self.parse("ssh-rsa !!!!notbase64!!!! x\n")
        self.assertEqual(len(records), 1)
        self.assertEqual(malformed, 1)
        self.assertEqual(records[0]["parse_status"], model.PARSE_MALFORMED_BASE64)
        self.assertIsNone(records[0]["key_fingerprint"])

    def test_a_line_with_no_material_is_recorded(self):
        records, malformed = self.parse("ssh-ed25519\n")
        self.assertEqual(records[0]["parse_status"], model.PARSE_NO_KEY_MATERIAL)
        self.assertEqual(malformed, 1)

    def test_a_comma_inside_a_quoted_value_stays_in_one_option(self):
        records, _ = self.parse('command="sleep 1, then exit",no-pty ' + KEY_A + "\n")
        names = [o["name"] for o in records[0]["options"]]
        self.assertEqual(names, ["command", "no-pty"])

    def test_whitespace_inside_a_quoted_value_does_not_split_the_line(self):
        records, malformed = self.parse('command="a b c" ' + KEY_A + "\n")
        self.assertEqual(malformed, 0)
        self.assertEqual(records[0]["key_type"], "ssh-ed25519")

    def test_an_unterminated_quote_is_malformed_not_silently_accepted(self):
        records, _ = self.parse('command="unterminated ' + KEY_A + "\n")
        self.assertEqual(records[0]["parse_status"], model.PARSE_MALFORMED_OPTIONS)

    def test_an_escaped_quote_inside_a_value_is_not_a_terminator(self):
        records, malformed = self.parse('command="say \\"hi\\"" ' + KEY_A + "\n")
        self.assertEqual(malformed, 0)
        self.assertEqual(records[0]["options"][0]["name"], "command")

    def test_options_before_the_key_type(self):
        records, malformed = self.parse("restrict " + KEY_A + "\n")
        self.assertEqual(malformed, 0)
        self.assertEqual(records[0]["structure"], sources.STRUCTURE_OPTIONS_AND_KEY)
        self.assertEqual(records[0]["key_type"], "ssh-ed25519")

    def test_an_ambiguous_malformed_line_claims_no_structure(self):
        # `no-pty ssh-rsa <broken>` and `ssh-rsa <broken> comment` have one shape, and
        # only a maintained list of key types would separate them. Saying so beats
        # picking one and reporting it as fact.
        records, _ = self.parse("no-pty ssh-rsa BROKEN!!\n")
        self.assertEqual(records[0]["structure"], sources.STRUCTURE_UNDETERMINED)
        self.assertIsNone(records[0]["key_type"])
        self.assertEqual(records[0]["options"], [])

    def test_a_duplicate_key_is_marked_and_kept(self):
        records, _ = self.parse(KEY_A + "\n" + KEY_A + "\n")
        self.assertEqual(len(records), 2)
        self.assertIsNone(records[0]["duplicate_of"])
        self.assertEqual(records[1]["duplicate_of"], records[0]["ordinal"])

    def test_the_same_key_with_different_options_is_still_a_duplicate_key(self):
        records, _ = self.parse(KEY_A + "\nno-pty " + KEY_A + "\n")
        self.assertEqual(records[1]["duplicate_of"], 0)
        self.assertEqual([o["name"] for o in records[1]["options"]], ["no-pty"])

    def test_different_keys_are_not_duplicates(self):
        records, _ = self.parse(KEY_A + "\n" + KEY_B + "\n")
        self.assertIsNone(records[1]["duplicate_of"])
        self.assertNotEqual(records[0]["key_fingerprint"],
                            records[1]["key_fingerprint"])

    def test_source_order_is_preserved(self):
        records, _ = self.parse(KEY_B + "\n" + KEY_A + "\n")
        self.assertEqual([r["source_line"] for r in records], [1, 2])
        self.assertEqual([r["ordinal"] for r in records], [0, 1])


class Fingerprint(unittest.TestCase):

    def test_the_same_key_yields_the_same_fingerprint(self):
        first, _ = sources.parse(KEY_A + "\n")
        second, _ = sources.parse(KEY_A + " a different comment\n")
        self.assertEqual(first[0]["key_fingerprint"], second[0]["key_fingerprint"])

    @unittest.skipUnless(HAVE_KEYGEN, "ssh-keygen is not installed")
    def test_it_is_the_value_ssh_keygen_prints(self):
        """EXECUTABLE ORACLE. A digest that only agrees with itself proves nothing."""
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "k")
        subprocess.check_call(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", path,
             "-C", "oracle@example.invalid"],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        with open(path + ".pub") as handle:
            public = handle.read()
        expected = subprocess.check_output(
            ["ssh-keygen", "-lf", path + ".pub"],
            universal_newlines=True).split()[1]
        records, _ = sources.parse(public)
        self.assertEqual(records[0]["key_fingerprint"], expected)

    @unittest.skipUnless(HAVE_KEYGEN, "ssh-keygen is not installed")
    def test_the_oracle_agrees_for_an_rsa_key_too(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "k")
        subprocess.check_call(
            ["ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-f", path, "-C", ""],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        with open(path + ".pub") as handle:
            public = handle.read()
        expected = subprocess.check_output(
            ["ssh-keygen", "-lf", path + ".pub"],
            universal_newlines=True).split()[1]
        records, _ = sources.parse(public)
        self.assertEqual(records[0]["key_fingerprint"], expected)


class NoSecondAccountModel(unittest.TestCase):
    """One account model, one acquisition path for it."""

    def modules(self):
        return (acquire, model, sources)

    def test_the_lane_never_names_the_passwd_file(self):
        for module in self.modules():
            source = inspect.getsource(module)
            self.assertNotIn("/etc/passwd", source)

    def test_the_lane_does_not_import_the_account_acquisition_path(self):
        for module in self.modules():
            tree = ast.parse(inspect.getsource(module))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    names = [a.name for a in node.names]
                    self.assertNotIn("accounts", (node.module or "").split("."))
                    self.assertNotIn("accounts", names)

    def test_identity_is_referenced_not_recomputed(self):
        reference = acquire._account_ref(
            {"name": "alice", "name_encoding": "UTF8", "name_bytes_hex": "616c696365",
             "uid": 1000, "nss_source": "files", "passwd_line": 7})
        self.assertEqual(reference["source"], "LOCAL_ACCOUNT_FILES")
        self.assertEqual(reference["passwd_line"], 7)
        self.assertEqual(sorted(reference),
                         ["name", "name_bytes_hex", "nss_source", "passwd_line",
                          "source", "uid"])

    def test_an_undecodable_account_name_still_has_an_identity(self):
        reference = acquire._account_ref(
            {"name": "jos\udce9", "name_encoding": "UNDECODABLE",
             "name_bytes_hex": "6a6f73e9", "uid": 1000, "nss_source": "files",
             "passwd_line": 3})
        self.assertIsNone(reference["name"])
        self.assertEqual(reference["name_bytes_hex"], "6a6f73e9")


class Restraint(Fixture):
    """The words this lane may not use."""

    def test_no_verdict_vocabulary_reaches_the_evidence(self):
        self.host(sshd_config="AuthorizedKeysFile .ssh/authorized_keys\n")
        self.write("home/alice/.ssh/authorized_keys",
                   'command="x",no-pty,cert-authority ' + KEY_A + " a@b\n")
        blob = self.blob(self.collect())
        for claim in model.PROHIBITED_CLAIMS:
            self.assertNotIn('"%s"' % claim, blob, "the lane claimed %s" % claim)

    def test_the_limitation_states_what_was_not_determined(self):
        self.host(sshd_config="AuthorizedKeysFile .ssh/authorized_keys\n")
        limitation = self.collect().provenance["limitation"]
        for phrase in ("Match blocks are recorded and not evaluated",
                       "compiled-in defaults are not known",
                       "not a key that grants access"):
            self.assertIn(phrase, limitation)

    def test_what_was_not_collected_is_listed(self):
        self.host(sshd_config="AuthorizedKeysFile .ssh/authorized_keys\n")
        not_collected = self.collect().provenance["not_collected"]
        self.assertIn("AuthorizedKeysCommand output", not_collected)
        self.assertIn("compiled-in AuthorizedKeysFile default", not_collected)

    def test_cert_authority_is_a_fact_not_a_finding(self):
        self.host(sshd_config="AuthorizedKeysFile .ssh/authorized_keys\n")
        self.write("home/alice/.ssh/authorized_keys", "cert-authority " + KEY_A + "\n")
        record = self.collect().records[0]
        self.assertEqual([o["name"] for o in record["options"]], ["cert-authority"])
        self.assertNotIn("finding", json.dumps(record))


class Purity(unittest.TestCase):

    def test_sources_touches_nothing_outside_its_arguments(self):
        tree = ast.parse(inspect.getsource(sources))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attributes = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("open", "listdir", "stat", "lstat", "scandir", "environ",
                          "getcwd", "expanduser", "realpath", "Popen", "check_output",
                          "socket", "urlopen", "time"):
            self.assertNotIn(forbidden, names + attributes,
                             "sources used %r" % forbidden)

    def test_the_model_declares_no_behaviour(self):
        tree = ast.parse(inspect.getsource(model))
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, ast.FunctionDef)


class IQ014OwnerRuling(Fixture):
    """The six cases the owner required before this bridge could freeze.

    The ruling in one line: a Match-scoped candidate IS read when its path can be built
    deterministically, and reading it proves candidate evidence and nothing else. The
    danger the cases guard is not that the file gets read - it is that having read it,
    something later calls it an effective source.
    """

    GLOBAL_ONLY = "AuthorizedKeysFile .ssh/authorized_keys\n"
    MATCH_ONLY = ("Match User alice\n"
                  "    AuthorizedKeysFile /etc/ssh/match/%u\n")
    TWO_MATCHES = ("Match User alice\n"
                   "    AuthorizedKeysFile /etc/ssh/match/%u\n"
                   "Match Group staff\n"
                   "    AuthorizedKeysFile /etc/ssh/staff/%u\n")

    def alice_plan(self, evidence):
        for plan in evidence.provenance["source_plans"]:
            if plan["account_ref"]["name"] == "alice":
                return plan
        self.fail("alice has no source plan")

    # 1 --------------------------------------------------------------------------
    def test_a_global_declaration_is_read_and_is_unconditional(self):
        self.host(sshd_config=self.GLOBAL_ONLY, shadow="alice:!:1:0:9:7:::\n")
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        plan = self.alice_plan(self.collect())
        candidate = plan["candidates"][0]
        self.assertEqual(candidate["observation"], model.FILE_READ)
        self.assertEqual(candidate["applicability"], model.UNCONDITIONAL)
        self.assertEqual(candidate["resolution"], model.PATH_DERIVED)

    # 2 --------------------------------------------------------------------------
    def test_a_match_declaration_is_read_but_never_effective(self):
        self.host(sshd_config=self.MATCH_ONLY)
        self.write("etc/ssh/match/alice", KEY_A + "\n")
        evidence = self.collect()
        plan = self.alice_plan(evidence)
        candidate = plan["candidates"][0]
        self.assertEqual(candidate["observation"], model.FILE_READ,
                         "the owner ruling says a derivable Match candidate is read")
        self.assertEqual(candidate["scope"], "MATCH")
        self.assertEqual(candidate["applicability"], model.UNRESOLVED_MATCH_SCOPED)
        self.assertEqual(candidate["applies_to_account"], "UNDETERMINED")
        self.assertEqual(plan["effective_source_universe"],
                         model.EFFECTIVE_NOT_EVALUATED)
        record = [r for r in evidence.records
                  if r["account_ref"]["name"] == "alice"][0]
        self.assertEqual(record["declaration_applicability"],
                         model.UNRESOLVED_MATCH_SCOPED)
        self.assertEqual(record["effective_source"], model.EFFECTIVE_NOT_EVALUATED)

    # 3 --------------------------------------------------------------------------
    def test_two_match_declarations_are_both_observed_and_neither_promoted(self):
        self.host(sshd_config=self.TWO_MATCHES)
        self.write("etc/ssh/match/alice", KEY_A + "\n")
        self.write("etc/ssh/staff/alice", KEY_B + "\n")
        plan = self.alice_plan(self.collect())
        self.assertEqual(len(plan["candidates"]), 2)
        for candidate in plan["candidates"]:
            self.assertEqual(candidate["observation"], model.FILE_READ)
            self.assertEqual(candidate["applicability"],
                             model.UNRESOLVED_MATCH_SCOPED)
        self.assertEqual(plan["effective_source_universe"],
                         model.EFFECTIVE_NOT_EVALUATED)

    # 4 --------------------------------------------------------------------------
    def test_an_unreadable_match_candidate_is_a_refusal_never_an_absence(self):
        self.host(sshd_config=self.MATCH_ONLY)
        path = self.write("etc/ssh/match/alice", KEY_A + "\n")
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, 0o600)
        plan = self.alice_plan(self.collect())
        candidate = plan["candidates"][0]
        self.assertEqual(candidate["observation"], model.FILE_UNREADABLE)
        self.assertNotEqual(candidate["observation"], model.FILE_ABSENT)
        self.assertIn(model.CANDIDATE_NOT_OBSERVED, plan["universe_reasons"])

    # 5 --------------------------------------------------------------------------
    def test_no_declaration_means_the_conventional_file_is_not_acquired(self):
        self.host(sshd_config="PermitRootLogin no\n")
        self.write("home/alice/.ssh/authorized_keys", KEY_A + " canary\n")
        evidence = self.collect()
        self.assertEqual(self.alice_plan(evidence)["candidates"], [])
        self.assertNotIn("canary", self.blob(evidence))
        self.assertNotIn(KEY_A.split()[1][:24], self.blob(evidence))

    # 6 --------------------------------------------------------------------------
    def test_every_candidate_read_still_leaves_the_effective_universe_unknown(self):
        """The claim this bridge must never make.

        Candidate acquisition COMPLETE and effective-source universe COMPLETE are two
        questions, and the second is not asked in R1.5. A lane that answered it from a
        run where every file happened to be readable would be reporting the absence of
        an obstacle as the presence of knowledge.
        """
        self.host(sshd_config=self.GLOBAL_ONLY + self.MATCH_ONLY,
                  shadow="alice:!:1:0:9:7:::\n")
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        self.write("etc/ssh/match/alice", KEY_B + "\n")
        plan = self.alice_plan(self.collect())
        self.assertTrue(all(c["observation"] == model.FILE_READ
                            for c in plan["candidates"]),
                        "the fixture must read every candidate or it proves nothing")
        self.assertEqual(plan["effective_source_universe"],
                         model.EFFECTIVE_NOT_EVALUATED)
        self.assertIn(model.EFFECTIVE_REASON_MATCH_UNRESOLVED,
                      plan["effective_source_reasons"])
        self.assertEqual(plan["source_universe"], model.UNIVERSE_INCOMPLETE)

    def test_the_two_universes_are_separate_fields(self):
        # Collapsing them is the failure; a single field could not carry both answers.
        self.host(sshd_config=self.GLOBAL_ONLY, shadow="alice:!:1:0:9:7:::\n")
        self.write("home/alice/.ssh/authorized_keys", KEY_A + "\n")
        plan = self.alice_plan(self.collect())
        self.assertEqual(plan["source_universe"], model.UNIVERSE_COMPLETE)
        self.assertEqual(plan["effective_source_universe"],
                         model.EFFECTIVE_NOT_EVALUATED)
        self.assertNotEqual(plan["source_universe"],
                            plan["effective_source_universe"])


class ContainmentAtTheProductionRoot(unittest.TestCase):
    """The blind spot every fixture-based test in this project shares.

    `_inside` was written and tested entirely against fixture roots, where
    `base + os.sep` is a sensible prefix. At the PRODUCTION root it is "//", which no
    absolute path starts with, so the check refused every candidate and the lane read no
    authorized_keys file at all. 191 tests passed while the collector was inert on a real
    host, because not one of them ran at root "/".

    Found by the mounts lane copying the same check and hitting it on its first live run.
    """

    def test_an_ordinary_path_is_inside_the_production_root(self):
        self.assertTrue(acquire._inside("/", "/etc/ssh/keys"))

    def test_the_production_root_contains_itself(self):
        self.assertTrue(acquire._inside("/", "/"))

    def test_containment_still_refuses_an_escape_under_a_fixture_root(self):
        self.assertFalse(acquire._inside("/fixture", "/elsewhere/x"))

    def test_a_trailing_slash_on_the_root_does_not_break_it(self):
        self.assertTrue(acquire._inside("/fixture/", "/fixture/x"))

    def test_a_sibling_whose_name_extends_the_root_is_not_inside(self):
        # /fixture-evil must not count as inside /fixture.
        self.assertFalse(acquire._inside("/fixture", "/fixture-evil/x"))


if __name__ == "__main__":
    unittest.main(verbosity=0)
