# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Attack the sudo policy evidence lane from the specification, not the code.
# Implements: SCOPE-022, SCOPE-045, GOV-002
#
# WORKER B, PASS 1. Written against CONTRACT-sudo.md BEFORE any implementation existed,
# so these expectations come from sudoers semantics and the S2/S4/S5 contracts rather
# than from whatever the implementation happens to do. A test written after the code
# tends to agree with the code.
#
# The question these ask is "did ISEDRAF preserve exactly what the policy source says?"
# It is NOT "can alice become root?" - effective privilege is a later layer and nothing
# here may assert it.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""Independent adversarial attack on the sudo policy evidence lane."""
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import result                            # noqa: E402
from isedraf.sudo import acquire                             # noqa: E402


class Fixture(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)
        os.makedirs(os.path.join(self.base, "etc"))

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

    def collect(self, sudoers, **extra):
        self.write("etc/sudoers", sudoers)
        for relative, text in extra.items():
            self.write(relative.replace("__", "/"), text)
        return acquire.collect(self.base)

    def kinds(self, ev, kind):
        return [r for r in ev.records if r["kind"] == kind]

    def events(self, ev):
        return set(e.get("event") for e in ev.provenance.get("include_events", [])
                   if e.get("event"))


class IncludeGraph(Fixture):
    """S2 drives this. The domain decides what each event MEANS for sudoers."""

    def test_literal_include_is_followed(self):
        ev = self.collect("#include /etc/sudoers.extra\n",
                          **{"etc__sudoers.extra": "Defaults env_reset\n"})
        self.assertEqual(len(self.kinds(ev, "DEFAULTS")), 1)

    def test_missing_literal_include_is_not_silently_ignored(self):
        ev = self.collect("#include /etc/nowhere\nDefaults env_reset\n")
        self.assertNotEqual(ev.status, result.COLLECTED)
        self.assertIn("MISSING_TARGET", str(self.events(ev)))
        # Evidence collected before/around the failure survives.
        self.assertEqual(len(self.kinds(ev, "DEFAULTS")), 1)

    def test_unreadable_include_is_reported(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores these permission bits")
        self.write("etc/secret", "Defaults env_reset\n", mode=0)
        ev = self.collect("#include /etc/secret\n")
        self.assertNotEqual(ev.status, result.COLLECTED)

    def test_empty_includedir_is_a_normal_configuration(self):
        os.makedirs(os.path.join(self.base, "etc/sudoers.d"))
        ev = self.collect("#includedir /etc/sudoers.d\nDefaults env_reset\n")
        # An empty sudoers.d is the default state of most Linux hosts. If this is not
        # COLLECTED the status is worthless, because nearly every host will be PARTIAL.
        self.assertEqual(ev.status, result.COLLECTED)

    def test_includedir_files_are_all_read(self):
        ev = self.collect("#includedir /etc/sudoers.d\n",
                          **{"etc__sudoers.d__10-one": "Defaults env_reset\n",
                             "etc__sudoers.d__20-two": "Defaults !visiblepw\n"})
        self.assertEqual(len(self.kinds(ev, "DEFAULTS")), 2)

    def test_includedir_ordering_is_deterministic_and_declared(self):
        ev = self.collect("#includedir /etc/sudoers.d\n",
                          **{"etc__sudoers.d__20-b": "Defaults b\n",
                             "etc__sudoers.d__10-a": "Defaults a\n"})
        names = [r["options"][0]["name"] for r in self.kinds(ev, "DEFAULTS")]
        self.assertEqual(names, ["a", "b"])

    def test_sudoers_ignores_files_its_own_semantics_exclude(self):
        # sudoers skips names containing '.' and names ending in '~'. If the domain
        # adapter did not say so, a generic enumerator would include them and ISEDRAF
        # would report policy the host does not apply.
        ev = self.collect("#includedir /etc/sudoers.d\n",
                          **{"etc__sudoers.d__good": "Defaults good\n",
                             "etc__sudoers.d__bad.bak": "Defaults frombackup\n",
                             "etc__sudoers.d__old~": "Defaults fromtilde\n"})
        names = [r["options"][0]["name"] for r in self.kinds(ev, "DEFAULTS")]
        self.assertEqual(names, ["good"])

    def test_include_cycle_terminates_and_is_reported(self):
        ev = self.collect("#include /etc/a\n", **{"etc__a": "#include /etc/sudoers\n"})
        self.assertIn("CYCLE", str(self.events(ev)))

    def test_duplicate_include_is_recorded(self):
        ev = self.collect("#include /etc/a\n#include /etc/a\n",
                          **{"etc__a": "Defaults env_reset\n"})
        # sudoers applies it twice; both must be present, not de-duplicated.
        self.assertEqual(len(self.kinds(ev, "DEFAULTS")), 2)

    def test_undecodable_filename_in_includedir_does_not_crash_or_merge(self):
        directory = os.path.join(self.base, "etc/sudoers.d")
        os.makedirs(directory)
        for raw in (b"odd\xe9", b"odd\xff"):
            with open(os.path.join(os.fsencode(directory), raw), "wb") as handle:
                handle.write(b"Defaults env_reset\n")
        ev = self.collect("#includedir /etc/sudoers.d\n")
        self.assertIsNotNone(ev.status)

    def test_symlinked_include_target_is_read_not_walked_outside(self):
        self.write("etc/real", "Defaults env_reset\n")
        os.symlink(os.path.join(self.base, "etc/real"),
                   os.path.join(self.base, "etc/link"))
        ev = self.collect("#include /etc/link\n")
        for record in ev.records:
            self.assertTrue(record["source_path"].startswith(self.base))


class GrammarPreservation(Fixture):
    """Exactly what the source says, and nothing the source does not say."""

    def test_user_spec_components_are_preserved_separately(self):
        ev = self.collect("alice ALL=(root) /bin/ls\n")
        spec = self.kinds(ev, "SPEC")[0]
        self.assertEqual([p["value"] for p in spec["principals"]], ["alice"])
        self.assertEqual(spec["host"]["value"], "ALL")
        self.assertEqual([c["command"] for c in spec["commands"]], ["/bin/ls"])

    def test_group_principal_is_distinguished_from_a_user(self):
        ev = self.collect("%wheel ALL=(ALL) ALL\n")
        principal = self.kinds(ev, "SPEC")[0]["principals"][0]
        self.assertEqual(principal["kind"], "GROUP")
        # The leading % is syntax, not part of the name.
        self.assertEqual(principal["value"], "wheel")

    def test_netgroup_principal_is_distinguished(self):
        ev = self.collect("+netgroup ALL=(ALL) ALL\n")
        self.assertEqual(self.kinds(ev, "SPEC")[0]["principals"][0]["kind"], "NETGROUP")

    def test_negation_is_preserved_not_dropped(self):
        # Dropping a ! inverts the policy. This is the single most dangerous silent
        # simplification available in this grammar.
        ev = self.collect("alice ALL=(ALL) !/bin/su\n")
        command = self.kinds(ev, "SPEC")[0]["commands"][0]
        self.assertTrue(command["negated"])
        self.assertEqual(command["command"], "/bin/su")

    def test_negated_principal_is_preserved(self):
        ev = self.collect("!alice ALL=(ALL) ALL\n")
        self.assertTrue(self.kinds(ev, "SPEC")[0]["principals"][0]["negated"])

    def test_multiple_commands_are_all_kept_in_order(self):
        ev = self.collect("alice ALL=(ALL) /bin/ls, /bin/cat, !/bin/su\n")
        commands = self.kinds(ev, "SPEC")[0]["commands"]
        self.assertEqual([c["command"] for c in commands],
                         ["/bin/ls", "/bin/cat", "/bin/su"])
        self.assertEqual([c["negated"] for c in commands], [False, False, True])

    def test_tags_are_attached_to_the_right_command(self):
        # NOPASSWD applies from where it appears onward. Attaching it to the wrong
        # command misreports which command needs a password.
        ev = self.collect("alice ALL=(ALL) /bin/ls, NOPASSWD: /bin/cat\n")
        commands = self.kinds(ev, "SPEC")[0]["commands"]
        self.assertEqual(commands[0]["tags"], [])
        self.assertIn("NOPASSWD", commands[1]["tags"])

    def test_tag_ordering_pairs_are_both_representable(self):
        ev = self.collect("alice ALL=(ALL) NOEXEC: NOPASSWD: /bin/ls\n")
        tags = self.kinds(ev, "SPEC")[0]["commands"][0]["tags"]
        self.assertIn("NOEXEC", tags)
        self.assertIn("NOPASSWD", tags)

    def test_runas_user_and_group_are_separate_fields(self):
        ev = self.collect("alice ALL=(root:wheel) ALL\n")
        spec = self.kinds(ev, "SPEC")[0]
        self.assertEqual([u["value"] for u in spec["runas_users"]], ["root"])
        self.assertEqual([g["value"] for g in spec["runas_groups"]], ["wheel"])

    def test_absent_runas_is_null_not_an_invented_default(self):
        # sudoers defaults to root when (…) is absent. That default is RESOLUTION.
        # The parser must say the source did not specify it.
        ev = self.collect("alice ALL=ALL\n")
        self.assertIsNone(self.kinds(ev, "SPEC")[0]["runas_users"])

    def test_line_continuation_is_joined(self):
        ev = self.collect("alice ALL=(ALL) /bin/ls, \\\n    /bin/cat\n")
        self.assertEqual(len(self.kinds(ev, "SPEC")[0]["commands"]), 2)

    def test_comments_are_not_records_but_include_directives_are(self):
        ev = self.collect("# an ordinary comment\nDefaults env_reset\n")
        self.assertEqual(len(ev.records), 1)


class Aliases(Fixture):

    def test_each_alias_type_is_recorded_with_its_members(self):
        ev = self.collect("User_Alias ADMINS = alice, bob\n"
                          "Runas_Alias OPS = root\n"
                          "Host_Alias LOCAL = localhost\n"
                          "Cmnd_Alias READ = /bin/cat, /bin/less\n")
        aliases = {a["name"]: a for a in self.kinds(ev, "ALIAS")}
        self.assertEqual(aliases["ADMINS"]["alias_type"], "USER")
        self.assertEqual([m["value"] for m in aliases["ADMINS"]["members"]],
                         ["alice", "bob"])
        self.assertEqual(aliases["READ"]["alias_type"], "CMND")

    def test_duplicate_alias_name_keeps_both(self):
        ev = self.collect("User_Alias A = alice\nUser_Alias A = bob\n")
        self.assertEqual(len(self.kinds(ev, "ALIAS")), 2)

    def test_undefined_alias_reference_is_not_resolved_away(self):
        # The parser records the reference. Whether it resolves is a later layer's
        # problem, and inventing an empty membership would hide a broken policy.
        ev = self.collect("MISSINGALIAS ALL=(ALL) ALL\n")
        principal = self.kinds(ev, "SPEC")[0]["principals"][0]
        self.assertEqual(principal["value"], "MISSINGALIAS")

    def test_negated_alias_member_is_preserved(self):
        ev = self.collect("User_Alias A = alice, !bob\n")
        members = self.kinds(ev, "ALIAS")[0]["members"]
        self.assertEqual([m["negated"] for m in members], [False, True])


class Defaults(Fixture):

    def test_global_defaults(self):
        ev = self.collect("Defaults env_reset\n")
        record = self.kinds(ev, "DEFAULTS")[0]
        self.assertEqual(record["scope_type"], "GLOBAL")
        self.assertIsNone(record["scope"])

    def test_negated_option(self):
        ev = self.collect("Defaults !visiblepw\n")
        self.assertTrue(self.kinds(ev, "DEFAULTS")[0]["options"][0]["negated"])

    def test_scoped_defaults_keep_their_qualifier(self):
        for text, scope_type, scope in (("Defaults:alice env_reset", "USER", "alice"),
                                        ("Defaults>root env_reset", "RUNAS", "root"),
                                        ("Defaults@host env_reset", "HOST", "host"),
                                        ("Defaults!/bin/ls env_reset", "COMMAND",
                                         "/bin/ls")):
            ev = self.collect(text + "\n")
            record = self.kinds(ev, "DEFAULTS")[0]
            self.assertEqual(record["scope_type"], scope_type, text)
            self.assertEqual(record["scope"], scope, text)

    def test_operators_are_distinguished(self):
        ev = self.collect("Defaults env_keep = \"A B\"\n"
                          "Defaults env_keep += \"C\"\n"
                          "Defaults env_keep -= \"A\"\n")
        operators = [r["options"][0]["operator"] for r in self.kinds(ev, "DEFAULTS")]
        self.assertEqual(operators, ["=", "+=", "-="])

    def test_multiple_options_on_one_line(self):
        ev = self.collect("Defaults env_reset, !visiblepw, timestamp_timeout=5\n")
        options = self.kinds(ev, "DEFAULTS")[0]["options"]
        self.assertEqual(len(options), 3)


class Robustness(Fixture):

    def test_malformed_line_is_recorded_not_skipped(self):
        ev = self.collect("Defaults env_reset\n!!! total nonsense !!!\n")
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertEqual(len(self.kinds(ev, "UNSUPPORTED")), 1)
        self.assertEqual(len(self.kinds(ev, "DEFAULTS")), 1)

    def test_unsupported_line_content_is_not_retained_verbatim(self):
        # A sudoers line can name commands, hosts and arguments. An unparsed line is
        # exactly the case where the content is least understood, so it is digested
        # rather than copied into evidence.
        ev = self.collect("SOMETHINGSECRETFIXTUREONLY = nonsense (((\n")
        blob = json.dumps(ev.records)
        self.assertNotIn("SOMETHINGSECRETFIXTUREONLY", blob)
        self.assertTrue(self.kinds(ev, "UNSUPPORTED")[0]["raw_digest"]
                        .startswith("sha256:"))

    def test_empty_sudoers_is_collected(self):
        ev = self.collect("")
        self.assertEqual(ev.status, result.COLLECTED)

    def test_missing_sudoers_is_not_tested(self):
        ev = acquire.collect(self.base)
        self.assertEqual(ev.status, result.NOT_TESTED)

    def test_every_record_carries_provenance(self):
        ev = self.collect("#includedir /etc/sudoers.d\nDefaults env_reset\n",
                          **{"etc__sudoers.d__x": "alice ALL=(ALL) ALL\n"})
        for record in ev.records:
            self.assertIn("source_path", record)
            self.assertIn("source_line", record)
            self.assertIn("ordinal", record)
        # Ordinals are unique and ordered across the whole graph.
        ordinals = [r["ordinal"] for r in ev.records]
        self.assertEqual(ordinals, sorted(ordinals))
        self.assertEqual(len(set(ordinals)), len(ordinals))

    def test_file_metadata_is_observed_for_every_policy_file(self):
        ev = self.collect("Defaults env_reset\n")
        files = ev.provenance["files"]
        self.assertTrue(files)
        for entry in files:
            for field in ("requested_path", "uid", "gid", "mode", "file_type"):
                self.assertIn(field, entry)


class NoVerdicts(Fixture):
    """Evidence only. Effective privilege is a later layer."""

    def test_no_privilege_vocabulary_anywhere(self):
        ev = self.collect("%wheel ALL=(ALL) NOPASSWD: ALL\n"
                          "alice ALL=(root) /bin/su\n")
        # Structured records only. Scanning the envelope would also scan the
        # limitation prose, which names the very concepts it denies - the defect
        # that bit the login-policy lane.
        blob = json.dumps(ev.records).lower()
        for word in ("can_become_root", "is_admin", "privileged", "effective",
                     "has_sudo", "is_sudoer", "secure", "unsafe", "compliant",
                     "root_equivalent"):
            self.assertNotIn(word, blob, word)

    def test_all_is_a_token_not_an_expansion(self):
        ev = self.collect("alice ALL=(ALL) ALL\n")
        spec = self.kinds(ev, "SPEC")[0]
        self.assertEqual(spec["commands"][0]["command"], "ALL")

    def test_nopasswd_does_not_become_a_finding(self):
        ev = self.collect("alice ALL=(ALL) NOPASSWD: ALL\n")
        blob = json.dumps(ev.records)
        self.assertNotIn("finding", blob.lower())
        self.assertIn("NOPASSWD", self.kinds(ev, "SPEC")[0]["commands"][0]["tags"])


# =============================================================================
# WORKER B, PASS 2 — written AFTER reading Worker A's implementation.
#
# Pass 1 attacked the specification. These attack the choices the implementation
# actually made: the regexes it settled on, the assumptions encoded in them, and the
# branches nothing in pass 1 happened to reach. Several of these could not have been
# written without seeing the code, which is the point of running the pass separately.
# =============================================================================


class ImplementationDirected(Fixture):

    def test_upper_case_username_is_not_silently_called_an_alias(self):
        # _principal guesses ALIAS_REFERENCE from an upper-case name. That is a
        # convention, not a rule: a real account may be upper-case. The guess must not
        # change the VALUE, only the kind, so no evidence is lost either way.
        ev = self.collect("BACKUP ALL=(ALL) ALL\n")
        principal = self.kinds(ev, "SPEC")[0]["principals"][0]
        self.assertEqual(principal["value"], "BACKUP")

    def test_double_negation_collapses_correctly(self):
        # _negatable loops on '!'. Two negations are not a negation.
        ev = self.collect("alice ALL=(ALL) !!/bin/ls\n")
        self.assertFalse(self.kinds(ev, "SPEC")[0]["commands"][0]["negated"])

    def test_command_with_arguments_is_kept_whole(self):
        ev = self.collect("alice ALL=(ALL) /bin/ls -la /tmp\n")
        self.assertEqual(self.kinds(ev, "SPEC")[0]["commands"][0]["command"],
                         "/bin/ls -la /tmp")

    def test_quoted_comma_inside_a_value_does_not_split_the_list(self):
        # _split respects quotes. A naive split(",") would produce two options here.
        ev = self.collect('Defaults env_keep = "A,B"\n')
        self.assertEqual(len(self.kinds(ev, "DEFAULTS")[0]["options"]), 1)

    def test_parenthesised_runas_with_comma_is_not_split(self):
        ev = self.collect("alice ALL=(root,bob) ALL\n")
        spec = self.kinds(ev, "SPEC")[0]
        self.assertEqual([u["value"] for u in spec["runas_users"]], ["root", "bob"])

    def test_runas_group_only(self):
        # `(:wheel)` - empty user list, group present. The partition() branch.
        ev = self.collect("alice ALL=(:wheel) ALL\n")
        spec = self.kinds(ev, "SPEC")[0]
        self.assertEqual(spec["runas_users"], [])
        self.assertEqual([g["value"] for g in spec["runas_groups"]], ["wheel"])

    def test_unterminated_runas_parenthesis_does_not_swallow_the_line(self):
        ev = self.collect("alice ALL=(root /bin/ls\n")
        self.assertTrue(ev.records)

    def test_tag_reset_applies_onward_only_from_its_position(self):
        # PASSWD after NOPASSWD: both accumulate on later commands. The implementation
        # appends rather than replacing, so this records what the source said.
        ev = self.collect("alice ALL=(ALL) NOPASSWD: /bin/a, PASSWD: /bin/b\n")
        commands = self.kinds(ev, "SPEC")[0]["commands"]
        self.assertIn("NOPASSWD", commands[0]["tags"])
        self.assertIn("PASSWD", commands[1]["tags"])

    def test_a_word_that_looks_like_a_tag_but_is_not_one_stays_a_command(self):
        ev = self.collect("alice ALL=(ALL) NOTATAG: /bin/ls\n")
        command = self.kinds(ev, "SPEC")[0]["commands"][0]["command"]
        self.assertIn("NOTATAG", command)

    def test_defaults_with_no_options_is_not_a_crash(self):
        ev = self.collect("Defaults\n")
        self.assertTrue(ev.records)

    def test_at_include_form_is_accepted(self):
        # sudo accepts @include as well as #include. The adapter handles both; if it
        # did not, the directive would be read as a comment and silently dropped.
        ev = self.collect("@include /etc/extra\n",
                          **{"etc__extra": "Defaults env_reset\n"})
        self.assertEqual(len(self.kinds(ev, "DEFAULTS")), 1)

    def test_include_with_no_target_is_not_treated_as_a_valid_directive(self):
        ev = self.collect("#include\nDefaults env_reset\n")
        self.assertEqual(len(self.kinds(ev, "DEFAULTS")), 1)

    def test_ordinals_remain_unique_across_multiple_included_files(self):
        # acquire.py threads `ordinal` across files. An off-by-one would duplicate them
        # and break any later reference to "record N".
        ev = self.collect("#includedir /etc/sudoers.d\nDefaults a\n",
                          **{"etc__sudoers.d__10": "Defaults b\nDefaults c\n",
                             "etc__sudoers.d__20": "Defaults d\n"})
        ordinals = [r["ordinal"] for r in ev.records]
        self.assertEqual(len(set(ordinals)), len(ordinals))
        self.assertEqual(ordinals, sorted(ordinals))

    def test_metadata_is_observed_even_for_an_unreadable_policy_file(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores these permission bits")
        self.write("etc/locked", "Defaults env_reset\n", mode=0)
        ev = self.collect("#include /etc/locked\n")
        paths = [f["requested_path"] for f in ev.provenance["files"]]
        self.assertTrue(any(p.endswith("/etc/locked") for p in paths))

    def test_excluded_includedir_entries_are_reported_not_merely_dropped(self):
        # The domain excludes .bak files. An operator needs to know a file is being
        # ignored, because "my rule is not applying" is exactly the question they ask.
        ev = self.collect("#includedir /etc/sudoers.d\n",
                          **{"etc__sudoers.d__x.bak": "Defaults frombackup\n"})
        excluded = ev.provenance["includedir_entries_excluded"]
        self.assertTrue(any(e.get("name") == "x.bak" for e in excluded))
        self.assertTrue(any(e["reason"] == "IGNORED_BY_SUDOERS_FILENAME_RULE"
                            for e in excluded))


class RootEscape(unittest.TestCase):
    """A `..` in a sudoers include target must not reach outside the collection root.

    Hermetic by construction: the bait lives in a SIBLING of the collection root, inside
    this test's own temporary directory. The attack is therefore observable without the
    machine running the test being involved at all - a test that proved this by reading
    the live /etc would itself be the defect.
    """

    BAIT = 'baitdetector ALL=(ALL) NOPASSWD: ALL\n'
    TOKEN = 'baitdetector'

    def setUp(self):
        self.enclosure = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.enclosure, True)
        self.root = os.path.join(self.enclosure, "root")
        self.outside = os.path.join(self.enclosure, "outside")
        os.makedirs(os.path.join(self.root, "etc"))
        os.makedirs(self.outside)
        with open(os.path.join(self.outside, 'bait'), "w") as handle:
            handle.write(self.BAIT)

    def collect_with(self, text):
        path = os.path.join(self.root, "etc", "sudoers")
        with open(path, "w") as handle:
            handle.write(text)
        return acquire.collect(self.root)

    def absolute_paths(self, ev):
        """Every absolute path anywhere in the evidence, normalised.

        Collecting them from the serialised object rather than from one known key is
        deliberate: an escape that surfaced only in a reason string would still be an
        escape, and it is the kind a targeted assertion walks straight past.
        """
        found = []
        blob = json.dumps({"r": ev.records, "p": ev.provenance}, default=str)
        for candidate in re.findall(r"/[A-Za-z0-9_./*-]+", blob):
            found.append(os.path.normpath(candidate))
        return found

    def assert_contained(self, ev, directive):
        for path in self.absolute_paths(ev):
            if path.startswith(self.enclosure) or path.startswith("/tmp"):
                self.assertTrue(
                    path == self.root or path.startswith(self.root + os.sep),
                    "%r produced %r, outside the collection root" % (directive, path))

    def test_absolute_target_climbing_above_the_root_stays_inside_it(self):
        directive = '#include /etc/../../outside/bait\n'
        self.assert_contained(self.collect_with(directive), directive)

    def test_relative_target_climbing_above_the_root_stays_inside_it(self):
        directive = '#include ../../outside/bait\n'
        self.assert_contained(self.collect_with(directive), directive)

    def test_the_bait_is_never_read(self):
        for directive in ('#include /etc/../../outside/bait\n', '#include ../../outside/bait\n', '#includedir /etc/../../outside\n', '#includedir ../../outside\n'):
            ev = self.collect_with(directive)
            self.assertNotIn(self.TOKEN, json.dumps(ev.records, default=str),
                             "%r read a file outside the collection root" % directive)

    def test_the_host_meaning_of_the_path_is_still_honoured(self):
        # Clamping everything to the root would pass the tests above and be wrong.
        # `/etc/../sudoers.extra` names `/sudoers.extra` on a host, so under a root it
        # names that path beneath the root - and the file there must still be read.
        with open(os.path.join(self.root, "sudoers.extra"), "w") as handle:
            handle.write('insidemarker ALL=(ALL) ALL\n')
        ev = self.collect_with('#include /etc/../sudoers.extra\n')
        self.assertIn('insidemarker', json.dumps(ev.records, default=str))


if __name__ == "__main__":
    unittest.main(verbosity=0)
