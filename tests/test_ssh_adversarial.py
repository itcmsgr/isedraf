# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Attack the SSH lane from its contract, before the code exists.
# Implements: SCOPE-022, SCOPE-045, GOV-002
#
# RED, PASS 1. The central attack is structural. A parser that returns correct
# keyword/value pairs and loses Match scope has produced evidence that reads as
# authoritative and answers the wrong question - "PasswordAuthentication is both yes and
# no" is not a fact about any host.
#
# Assertions here read structured fields, never the serialized envelope. Three separate
# occasions have now proved prose assertions are too weak: a docstring mistaken for code
# behaviour, a comment mistaken for privacy data, and limitation text mistaken for a
# semantic value.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""Independent adversarial attack on the SSH declared-configuration lane."""
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import result                            # noqa: E402
from isedraf.ssh import acquire, model                       # noqa: E402


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

    def collect(self, config, **extra):
        self.write("etc/ssh/sshd_config", config)
        for relative, text in extra.items():
            self.write(relative.replace("__", "/"), text)
        return acquire.collect(self.base)

    def directives(self, ev, keyword):
        return [r for r in ev.records
                if r["kind"] == model.DIRECTIVE and r["keyword"] == keyword.lower()]

    def events(self, ev):
        return set(e.get("event") for e in ev.provenance.get("include_events", [])
                   if e.get("event"))


class MatchScope(Fixture):
    """The structural attack. A flattened parse is authoritative-looking nonsense."""

    CONFIG = ("PasswordAuthentication no\n"
              "\n"
              "Match User backup\n"
              "    PasswordAuthentication yes\n")

    def test_global_and_match_declarations_are_distinguishable(self):
        ev = self.collect(self.CONFIG)
        records = self.directives(ev, "PasswordAuthentication")
        self.assertEqual(len(records), 2)
        scopes = [r["scope"] for r in records]
        self.assertEqual(scopes, [model.GLOBAL, model.MATCH])

    def test_a_match_declaration_carries_its_criteria(self):
        ev = self.collect(self.CONFIG)
        scoped = [r for r in self.directives(ev, "PasswordAuthentication")
                  if r["scope"] == model.MATCH][0]
        criteria = scoped["match_criteria"]
        self.assertEqual(criteria[0]["keyword"], "user")
        self.assertEqual(criteria[0]["values"], ["backup"])

    def test_global_declarations_carry_no_match_index(self):
        ev = self.collect(self.CONFIG)
        globals_ = [r for r in self.directives(ev, "PasswordAuthentication")
                    if r["scope"] == model.GLOBAL]
        self.assertIsNone(globals_[0]["match_index"])

    def test_multiple_match_blocks_are_indexed_separately(self):
        ev = self.collect("Match User a\n  X11Forwarding yes\n"
                          "Match User b\n  X11Forwarding no\n")
        indexes = [r["match_index"] for r in self.directives(ev, "X11Forwarding")]
        self.assertEqual(indexes, [0, 1])

    def test_multiple_criteria_on_one_match_are_all_kept(self):
        ev = self.collect("Match User backup Address 10.0.0.0/8\n  PermitTTY no\n")
        criteria = self.directives(ev, "PermitTTY")[0]["match_criteria"]
        keywords = [c["keyword"] for c in criteria]
        self.assertIn("user", keywords)
        self.assertIn("address", keywords)

    def test_a_directive_after_a_match_block_stays_in_that_block(self):
        # sshd has no "end match": a Match block runs until the next Match or EOF.
        # Treating a later directive as global would silently widen its effect.
        ev = self.collect("Match User a\n  AllowTcpForwarding no\n"
                          "  X11Forwarding no\n")
        for keyword in ("AllowTcpForwarding", "X11Forwarding"):
            self.assertEqual(self.directives(ev, keyword)[0]["scope"], model.MATCH)

    def test_a_directive_before_any_match_is_global(self):
        ev = self.collect("Port 22\nMatch User a\n  PermitTTY no\n")
        self.assertEqual(self.directives(ev, "Port")[0]["scope"], model.GLOBAL)

    def test_match_all_is_recorded_as_criteria_not_dropped(self):
        ev = self.collect("Match all\n  PermitTTY yes\n")
        self.assertTrue(self.directives(ev, "PermitTTY")[0]["match_criteria"])

    def test_negated_match_criterion_is_preserved(self):
        ev = self.collect("Match User !root\n  PermitTTY no\n")
        criterion = self.directives(ev, "PermitTTY")[0]["match_criteria"][0]
        self.assertTrue(criterion.get("negated") or "!" in str(criterion["values"]))


class Grammar(Fixture):

    def test_keyword_is_case_insensitive_but_the_raw_form_survives(self):
        ev = self.collect("permitrootlogin no\n")
        record = self.directives(ev, "PermitRootLogin")[0]
        self.assertEqual(record["keyword"], "permitrootlogin")
        self.assertEqual(record["keyword_raw"], "permitrootlogin")

    def test_equals_form_is_accepted(self):
        # sshd accepts `Port=22` as well as `Port 22`. A whitespace-only parse yields
        # keyword "port=22" with no value.
        ev = self.collect("Port=2222\n")
        self.assertEqual(self.directives(ev, "Port")[0]["value"], "2222")

    def test_whitespace_form_is_accepted(self):
        ev = self.collect("Port   2222\n")
        self.assertEqual(self.directives(ev, "Port")[0]["value"], "2222")

    def test_quoted_value_is_preserved_without_its_quotes(self):
        ev = self.collect('Banner "/etc/issue net"\n')
        self.assertEqual(self.directives(ev, "Banner")[0]["value"], "/etc/issue net")

    def test_hash_inside_a_value_is_not_an_inline_comment(self):
        # sshd has no inline comments. Truncating here would silently change a value.
        ev = self.collect("Ciphers aes256-ctr#notacomment\n")
        self.assertIn("#", self.directives(ev, "Ciphers")[0]["value"])

    def test_full_line_comments_and_blanks_are_not_records(self):
        ev = self.collect("# comment\n\n   \nPort 22\n")
        self.assertEqual(len([r for r in ev.records
                              if r["kind"] == model.DIRECTIVE]), 1)

    def test_unknown_newer_directive_is_evidence_not_an_error(self):
        ev = self.collect("SomeOptionFrom2029 yes\n")
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual(self.directives(ev, "SomeOptionFrom2029")[0]["value"], "yes")

    def test_keyword_with_no_value_is_recorded_as_unsupported(self):
        ev = self.collect("Port\n")
        self.assertTrue([r for r in ev.records if r["kind"] == model.UNSUPPORTED])

    def test_duplicate_global_directives_are_both_kept(self):
        # sshd takes the FIRST. Recording only one would hide the second from an
        # operator asking why their later edit has no effect.
        ev = self.collect("Port 22\nPort 2222\n")
        self.assertEqual([r["value"] for r in self.directives(ev, "Port")],
                         ["22", "2222"])

    def test_first_wins_is_recorded_not_applied(self):
        ev = self.collect("Port 22\nPort 2222\n")
        self.assertIn("FIRST", str(ev.provenance.get("duplicate_policy", "")).upper())


class Includes(Fixture):

    def test_absolute_include_under_a_fixture_root_does_not_read_the_live_host(self):
        # The defect class the sudo lane found on first contact. sshd_config Include
        # paths are absolute on a real host.
        ev = self.collect("Include /etc/ssh/sshd_config.d/*.conf\n",
                          **{"etc__ssh__sshd_config.d__10-x.conf": "Port 2222\n"})
        for record in ev.records:
            self.assertTrue(record["source_path"].startswith(self.base),
                            record["source_path"])
        self.assertEqual(self.directives(ev, "Port")[0]["value"], "2222")

    def test_relative_include(self):
        ev = self.collect("Include extra.conf\n",
                          **{"etc__ssh__extra.conf": "Port 2222\n"})
        self.assertEqual(len(self.directives(ev, "Port")), 1)

    def test_zero_match_wildcard_is_a_normal_configuration(self):
        os.makedirs(os.path.join(self.base, "etc/ssh/sshd_config.d"))
        ev = self.collect("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
        self.assertEqual(ev.status, result.COLLECTED)

    def test_missing_literal_include_is_reported(self):
        ev = self.collect("Include /etc/ssh/nowhere.conf\nPort 22\n")
        self.assertNotEqual(ev.status, result.COLLECTED)
        self.assertEqual(len(self.directives(ev, "Port")), 1)

    def test_multiple_included_files_are_ordered_deterministically(self):
        ev = self.collect("Include /etc/ssh/sshd_config.d/*.conf\n",
                          **{"etc__ssh__sshd_config.d__20-b.conf": "Port 20\n",
                             "etc__ssh__sshd_config.d__10-a.conf": "Port 10\n"})
        self.assertEqual([r["value"] for r in self.directives(ev, "Port")], ["10", "20"])

    def test_unreadable_include_is_reported(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores these permission bits")
        self.write("etc/ssh/secret.conf", "Port 22\n", mode=0)
        ev = self.collect("Include /etc/ssh/secret.conf\n")
        self.assertNotEqual(ev.status, result.COLLECTED)

    def test_include_cycle_terminates(self):
        ev = self.collect("Include /etc/ssh/a.conf\n",
                          **{"etc__ssh__a.conf": "Include /etc/ssh/sshd_config\n"})
        self.assertIn("CYCLE", str(self.events(ev)))

    def test_ordinals_are_unique_and_ordered_across_included_files(self):
        ev = self.collect("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n",
                          **{"etc__ssh__sshd_config.d__10.conf": "X11Forwarding no\n"})
        ordinals = [r["ordinal"] for r in ev.records]
        self.assertEqual(ordinals, sorted(ordinals))
        self.assertEqual(len(set(ordinals)), len(ordinals))

    def test_an_include_inside_match_is_conditional_inclusion(self):
        # SSH_INCLUDE_MATCH_CONTEXT_001. This assertion was inverted and certified the
        # defect. sshd_config(5) permits Include inside Match precisely so the included
        # configuration is conditional; reporting it as GLOBAL turns conditional
        # configuration into unconditional configuration, which is wrong in the
        # dangerous direction.
        ev = self.collect("Match User a\n  Include /etc/ssh/inc.conf\n",
                          **{"etc__ssh__inc.conf": "X11Forwarding no\n"})
        record = self.directives(ev, "X11Forwarding")[0]
        self.assertEqual(record["scope"], model.MATCH)
        self.assertEqual(record["match_criteria"][0]["values"], ["a"])

    def test_a_child_match_does_not_clobber_the_containing_file(self):
        # OpenSSH saves and restores the containing Match state around an include.
        ev = self.collect("Match User a\n"
                          "  Include /etc/ssh/inc.conf\n"
                          "  AllowTcpForwarding no\n",
                          **{"etc__ssh__inc.conf": "Match Group g\n  PermitTTY no\n"})
        after = self.directives(ev, "AllowTcpForwarding")[0]
        self.assertEqual(after["match_criteria"][0]["keyword"], "user")
        self.assertEqual(after["match_criteria"][0]["values"], ["a"])
        inside = self.directives(ev, "PermitTTY")[0]
        self.assertEqual(inside["match_criteria"][0]["keyword"], "group")

    def test_an_include_inherits_the_scope_at_its_own_line_not_the_last_in_the_file(self):
        # Distinguishes "the scope where the Include is written" from "the last Match in
        # the containing file". Without a fixture where those differ, a lookup that
        # silently used the wrong one would be indistinguishable from a correct one.
        ev = self.collect("Match User a\n"
                          "  Include /etc/ssh/inc.conf\n"
                          "Match User b\n"
                          "  X11Forwarding no\n",
                          **{"etc__ssh__inc.conf": "PermitTTY no\n"})
        self.assertEqual(self.directives(ev, "PermitTTY")[0]["match_criteria"][0]
                         ["values"], ["a"])
        self.assertEqual(self.directives(ev, "X11Forwarding")[0]["match_criteria"][0]
                         ["values"], ["b"])

    def test_an_include_from_global_scope_stays_global(self):
        ev = self.collect("Include /etc/ssh/inc.conf\n",
                          **{"etc__ssh__inc.conf": "X11Forwarding no\n"})
        self.assertEqual(self.directives(ev, "X11Forwarding")[0]["scope"], model.GLOBAL)

    def test_a_missing_include_under_match_does_not_reset_the_parent_scope(self):
        ev = self.collect("Match User a\n"
                          "  Include /etc/ssh/nowhere.conf\n"
                          "  PermitTTY no\n")
        self.assertEqual(self.directives(ev, "PermitTTY")[0]["scope"], model.MATCH)


class Robustness(Fixture):

    def test_missing_sshd_config_is_not_tested(self):
        self.assertEqual(acquire.collect(self.base).status, result.NOT_TESTED)

    def test_empty_sshd_config_is_collected(self):
        self.assertEqual(self.collect("").status, result.COLLECTED)

    def test_unsupported_line_content_is_digested_not_retained(self):
        ev = self.collect("!!!SECRETFIXTUREONLY!!!\n")
        unsupported = [r for r in ev.records if r["kind"] == model.UNSUPPORTED]
        self.assertTrue(unsupported)
        self.assertTrue(unsupported[0]["raw_digest"].startswith("sha256:"))
        for record in ev.records:
            for value in record.values():
                if isinstance(value, str):
                    self.assertNotIn("SECRETFIXTUREONLY", value)

    def test_file_metadata_is_observed_for_every_config_file(self):
        ev = self.collect("Port 22\n")
        self.assertTrue(ev.provenance["files"])
        for entry in ev.provenance["files"]:
            self.assertIn("mode", entry)

    def test_no_security_verdict_fields(self):
        ev = self.collect("PermitRootLogin yes\nPasswordAuthentication yes\n")
        for record in ev.records:
            for field in ("secure", "weak", "hardened", "risk", "finding",
                          "recommended", "compliant"):
                self.assertNotIn(field, record)

    def test_sshd_dash_T_is_not_executed(self):
        ev = self.collect("Port 22\n")
        self.assertEqual(ev.provenance["dimension"], model.DECLARED)


class RootEscape(unittest.TestCase):
    """An sshd_config Include must not reach outside the collection root.

    Hermetic by construction: the bait lives in a SIBLING of the collection root, inside
    this test's own temporary directory. The attack is therefore observable without the
    machine running the test being involved at all - a test that proved this by reading
    the live /etc would itself be the defect.
    """

    BAIT = 'Port 31337\n'
    TOKEN = '31337'

    def setUp(self):
        self.enclosure = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.enclosure, True)
        self.root = os.path.join(self.enclosure, "root")
        self.outside = os.path.join(self.enclosure, "outside")
        os.makedirs(os.path.join(self.root, "etc", "ssh"))
        os.makedirs(self.outside)
        with open(os.path.join(self.outside, 'bait.conf'), "w") as handle:
            handle.write(self.BAIT)

    def collect_with(self, text):
        path = os.path.join(self.root, "etc", "ssh", "sshd_config")
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
        directive = 'Include /etc/ssh/../../../outside/bait.conf\n'
        self.assert_contained(self.collect_with(directive), directive)

    def test_relative_target_climbing_above_the_root_stays_inside_it(self):
        directive = 'Include ../../outside/bait.conf\n'
        self.assert_contained(self.collect_with(directive), directive)

    def test_the_bait_is_never_read(self):
        for directive in ('Include /etc/ssh/../../../outside/bait.conf\n', 'Include ../../outside/bait.conf\n', 'Include /etc/ssh/../../../outside/*.conf\n', 'Include ../../outside/*.conf\n'):
            ev = self.collect_with(directive)
            self.assertNotIn(self.TOKEN, json.dumps(ev.records, default=str),
                             "%r read a file outside the collection root" % directive)

    def test_the_host_meaning_of_the_path_is_still_honoured(self):
        # Clamping everything to the root would pass the tests above and be wrong.
        # `/etc/ssh/../extra.conf` names `/etc/extra.conf` on a host, so under a root it
        # names that path beneath the root - and the file there must still be read.
        with open(os.path.join(self.root, "etc", "extra.conf"), "w") as handle:
            handle.write('Port 2222\n')
        ev = self.collect_with('Include /etc/ssh/../extra.conf\n')
        self.assertIn('2222', json.dumps(ev.records, default=str))


if __name__ == "__main__":
    unittest.main(verbosity=0)
