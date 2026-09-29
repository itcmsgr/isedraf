# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The login-policy lane's own contract: right profile, right parser, no reuse theatre.
# Implements: SCOPE-022, SCOPE-045, GOV-001, GOV-002
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""Login-policy lane: profile selection, domain parser, shared-primitive reuse."""
import ast
import inspect
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import keyvalue, result                  # noqa: E402
from isedraf.loginpolicy import acquire, model, sources      # noqa: E402


def _calls(module):
    """Dotted call targets actually invoked in `module`, from the AST.

    Not a text grep. ARCH-02 flagged seven assertions that searched module SOURCE for a
    call name: they match a mention in a comment as readily as a call, and they break
    when someone adds an explanatory comment. PAM's header discusses why S2 is not used,
    so `assertNotIn("include_graph", source)` was one clarifying sentence away from
    failing for the wrong reason. Three separate prose-assertion defects in this project
    already; this removes the remaining instances of the pattern.
    """
    import ast
    import inspect
    out = set()
    for node in ast.walk(ast.parse(inspect.getsource(module))):
        if isinstance(node, ast.Call):
            target = node.func
            parts = []
            while isinstance(target, ast.Attribute):
                parts.append(target.attr)
                target = target.value
            if isinstance(target, ast.Name):
                parts.append(target.id)
            if parts:
                out.add(".".join(reversed(parts)))
    return out


def _imported(module):
    import ast
    import inspect
    names = set()
    for node in ast.walk(ast.parse(inspect.getsource(module))):
        if isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
    return names



class ProfileSelection(unittest.TestCase):
    """Four families, four grammars. S1 records which; the domain chooses which."""

    def test_login_defs_and_pwquality_do_not_share_a_grammar(self):
        self.assertTrue(model.PROFILES[model.LOGIN_DEFS].whitespace_delimited)
        self.assertFalse(model.PROFILES[model.PWQUALITY].whitespace_delimited)

    def test_applying_the_wrong_profile_produces_visibly_wrong_evidence(self):
        # Demonstrates WHY the domain must choose. Parsed with the whitespace profile,
        # `minlen = 12` yields the value "= 12" - wrong, and carrying a digest that
        # proves which wrong grammar produced it.
        wrong = keyvalue.parse("minlen = 12\n", model.PROFILES[model.LOGIN_DEFS])
        self.assertEqual(wrong.records[0]["value"], "= 12")
        right = keyvalue.parse("minlen = 12\n", model.PROFILES[model.PWQUALITY])
        self.assertEqual(right.records[0]["value"], "12")

    def test_every_key_value_family_has_a_profile(self):
        for family in (model.LOGIN_DEFS, model.PWQUALITY, model.FAILLOCK):
            self.assertIn(family, model.PROFILES)
        # LIMITS deliberately has none: it is not key/value.
        self.assertNotIn(model.LIMITS, model.PROFILES)

    def test_grammar_digest_is_recorded_on_every_key_value_record(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        os.makedirs(os.path.join(base, "etc"))
        with open(os.path.join(base, "etc/login.defs"), "w") as handle:
            handle.write("UMASK 022\n")
        ev = acquire.collect(base)
        self.assertTrue(ev.records[0]["grammar_digest"].startswith("sha256:"))


class LimitsIsNotKeyValue(unittest.TestCase):
    """The deliberate non-use of S1, and the reason for it."""

    def test_the_domain_parser_owns_limits(self):
        records, malformed = sources.parse_limits("* hard nofile 65535\n")
        self.assertEqual(malformed, 0)
        self.assertEqual(records[0]["item"], "nofile")
        # No key, because there is none to invent.
        self.assertNotIn("key", records[0])

    def test_limits_parser_is_pure(self):
        tree = ast.parse(inspect.getsource(sources))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("open", "listdir", "lstat", "Popen", "socket", "read_file"):
            self.assertNotIn(forbidden, names + attrs, forbidden)

    def test_negated_domain_is_a_field_not_part_of_the_name(self):
        records, _ = sources.parse_limits("!root hard nproc 10\n")
        self.assertEqual(records[0]["domain"], "root")
        self.assertTrue(records[0]["domain_negated"])

    def test_unknown_limit_type_is_recorded_not_rejected(self):
        records, malformed = sources.parse_limits("* weird nofile 1\n")
        self.assertEqual(malformed, 0)
        self.assertIn("UNKNOWN_LIMIT_TYPE", records[0]["anomalies"])

    def test_too_few_fields_is_malformed_not_guessed(self):
        records, malformed = sources.parse_limits("* hard\n")
        self.assertEqual(malformed, 1)
        self.assertIsNone(records[0]["item"])


class SharedPrimitiveReuse(unittest.TestCase):
    """Reuse where the contract fits; a domain parser where it does not."""

    def test_key_value_families_go_through_S1(self):
        self.assertIn("keyvalue.parse", _calls(acquire))

    def test_fragment_directories_go_through_S5(self):
        self.assertIn("bounded.enumerate_paths", _calls(acquire))
        tree = ast.parse(inspect.getsource(acquire))
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for reimplemented in ("listdir", "glob", "walk", "scandir"):
            self.assertNotIn(reimplemented, attrs, reimplemented)

    def test_file_metadata_goes_through_S4(self):
        self.assertIn("filemeta.observe", _calls(acquire))

    def test_reading_goes_through_the_single_host_io_boundary(self):
        self.assertIn("hostio.read_file_lossless", _calls(acquire))
        tree = ast.parse(inspect.getsource(acquire))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        self.assertNotIn("open", names)

    def test_the_domain_decides_fragment_eligibility(self):
        self.assertTrue(model.fragment_eligible("50-x.conf"))
        self.assertFalse(model.fragment_eligible("50-x.conf.bak"))


class AbsentIsNotRefused(unittest.TestCase):
    """ARCH-02 blocker. Defect A, in a new domain."""

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)
        os.makedirs(os.path.join(self.base, "etc/security"))
        with open(os.path.join(self.base, "etc/security/pwquality.conf"), "w") as h:
            h.write("minlen = 12\n")

    def _login_defs(self, mode):
        path = os.path.join(self.base, "etc/login.defs")
        with open(path, "w") as handle:
            handle.write("UMASK 022\n")
        os.chmod(path, mode)
        self.addCleanup(os.chmod, path, 0o644)

    def test_an_absent_family_is_not_configured_and_does_not_reduce_completeness(self):
        self.assertEqual(acquire.collect(self.base).status, result.COLLECTED)

    def test_a_refused_family_is_unseen_evidence_and_does_reduce_completeness(self):
        # login.defs EXISTS and could not be read. One readable family never satisfies
        # completeness for one that was refused - the invariant the account contract
        # froze, checked here because ARCH-02 found it violated.
        if os.geteuid() == 0:
            self.skipTest("root ignores these permission bits")
        self._login_defs(0)
        ev = acquire.collect(self.base)
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn("SOURCE_UNREADABLE", ev.reason)

    def test_the_refused_source_is_still_NOT_TESTED_per_source(self):
        # SCOPE-022 puts privilege denial at NOT_TESTED for the SOURCE. The aggregate is
        # a different question, and both answers coexist.
        if os.geteuid() == 0:
            self.skipTest("root ignores these permission bits")
        self._login_defs(0)
        sources_meta = {s["family"]: s
                        for s in acquire.collect(self.base).provenance["sources"]}
        self.assertEqual(sources_meta[model.LOGIN_DEFS]["status"], result.NOT_TESTED)


class NoCrossSourceResolution(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)

    def write(self, relative, text):
        path = os.path.join(self.base, relative)
        directory = os.path.dirname(path)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        with open(path, "w") as handle:
            handle.write(text)

    def test_families_are_kept_apart(self):
        self.write("etc/login.defs", "PASS_MAX_DAYS 90\n")
        self.write("etc/security/pwquality.conf", "minlen = 12\n")
        ev = acquire.collect(self.base)
        families = set(r["family"] for r in ev.records)
        self.assertEqual(families, {model.LOGIN_DEFS, model.PWQUALITY})

    def test_the_limitation_names_what_is_not_reconciled(self):
        self.write("etc/login.defs", "UMASK 022\n")
        limitation = acquire.collect(self.base).provenance["limitation"]
        self.assertIn("shadow", limitation)
        self.assertIn("PAM", limitation)

    def test_every_emitted_field_is_classified(self):
        self.write("etc/login.defs", "UMASK 022\n")
        self.write("etc/security/limits.conf", "* hard nofile 1\n")
        for record in acquire.collect(self.base).records:
            for key in record:
                self.assertIn(key, model.CLASSIFICATION, key)

    def test_faillock_bare_boolean_is_reclassified_by_the_domain_not_by_S1(self):
        # S1 correctly calls a line with no delimiter malformed; that IS the answer from
        # a key/value grammar. The domain knows faillock accepts bare keys, so it
        # reclassifies rather than teaching S1 a special case one consumer wants.
        self.write("etc/security/faillock.conf", "silent\ndeny = 3\n")
        ev = acquire.collect(self.base)
        records = [r for r in ev.records if r["family"] == model.FAILLOCK]
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual(records[0]["key"], "silent")
        self.assertIsNone(records[0]["value"])


if __name__ == "__main__":
    unittest.main(verbosity=0)
