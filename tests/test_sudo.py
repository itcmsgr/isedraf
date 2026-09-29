# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The sudo lane's own contract: shared-primitive reuse, purity, and limits.
# Implements: SCOPE-022, SCOPE-045, GOV-001, GOV-002
#
# The adversarial lane attacks the grammar. This one asserts the things the domain lane
# is responsible for: that it consumes the shared primitives rather than reimplementing
# them, that its parser stays pure, and that it never crosses into evaluation.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""Sudo lane: shared-primitive reuse, purity, scope."""
import ast
import inspect
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import result                            # noqa: E402
from isedraf.sudo import acquire, model, sources             # noqa: E402


class SharedPrimitiveReuse(unittest.TestCase):
    """A domain reimplementing Batch 1 mechanics is presumed wrong."""

    def test_the_include_graph_is_S2_not_a_second_traversal(self):
        source = inspect.getsource(acquire)
        self.assertIn("include_graph.resolve", source)
        for reimplemented in ("def _walk", "def _traverse", "visiting", "def _resolve_"):
            self.assertNotIn(reimplemented, source, reimplemented)

    def test_file_metadata_is_S4_not_a_second_stat(self):
        source = inspect.getsource(acquire)
        self.assertIn("filemeta.observe", source)
        tree = ast.parse(source)
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for reimplemented in ("lstat", "stat"):
            self.assertNotIn(reimplemented, attrs, reimplemented)

    def test_directory_listing_is_S5_not_a_second_enumerator(self):
        source = inspect.getsource(acquire)
        self.assertIn("bounded.enumerate_paths", source)
        tree = ast.parse(source)
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for reimplemented in ("listdir", "walk", "glob", "scandir"):
            self.assertNotIn(reimplemented, attrs, reimplemented)

    def test_the_status_vocabulary_is_the_shared_one(self):
        self.assertEqual(model.COLLECTED, result.COLLECTED)
        self.assertEqual(model.PARTIAL, result.PARTIAL)

    def test_the_domain_decides_includedir_eligibility_not_the_enumerator(self):
        # S5 reports what it saw; sudoers semantics decide what counts. The rule lives
        # in the domain, which is what the S2/S5 correction was for.
        self.assertTrue(model.includedir_eligible("50-admins"))
        self.assertFalse(model.includedir_eligible("50-admins.bak"))
        self.assertFalse(model.includedir_eligible("50-admins~"))


class ParserPurity(unittest.TestCase):

    def test_the_grammar_parser_performs_no_io(self):
        tree = ast.parse(inspect.getsource(sources))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("open", "listdir", "lstat", "Popen", "system", "socket",
                          "read_file", "check_output"):
            self.assertNotIn(forbidden, names + attrs, forbidden)

    def test_the_grammar_parser_imports_no_acquisition(self):
        tree = ast.parse(inspect.getsource(sources))
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                modules.append(node.module or "")
        for module in modules:
            for forbidden in ("hostio", "bounded", "filemeta", "include_graph"):
                self.assertNotIn(forbidden, module, module)

    def test_parsing_is_a_pure_function_of_its_text(self):
        text = "alice ALL=(ALL) /bin/ls\n"
        first, _ = sources.parse(text, "/a")
        second, _ = sources.parse(text, "/a")
        self.assertEqual(first, second)


class ScopeBoundary(unittest.TestCase):
    """Declared policy. Not an answer to who can become root."""

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)
        os.makedirs(os.path.join(self.base, "etc"))

    def collect(self, text):
        with open(os.path.join(self.base, "etc/sudoers"), "w") as handle:
            handle.write(text)
        return acquire.collect(self.base)

    def test_the_limitation_travels_with_the_evidence(self):
        ev = self.collect("alice ALL=(ALL) ALL\n")
        limitation = ev.provenance["limitation"]
        self.assertIn("not resolved", limitation)
        self.assertIn("last-match precedence rule is not applied", limitation)
        self.assertEqual(ev.provenance["scope"], "DECLARED_LOCAL_SUDO_POLICY")

    def test_what_is_not_collected_is_named(self):
        ev = self.collect("alice ALL=(ALL) ALL\n")
        self.assertIn("sudo -l", ev.provenance["not_collected"])

    def test_sudo_dash_l_is_never_executed(self):
        # IDENT-040 freezes this: `sudo -l -U` SHALL NEVER be run by default, and it is
        # a host-changing command under CLAUDE.md's audit-is-observation rule.
        for module in (acquire, sources):
            source = inspect.getsource(module)
            self.assertNotIn("sudo -l", source.replace("# ", "").replace('"sudo -l"', ""))
            tree = ast.parse(inspect.getsource(module))
            attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
            self.assertNotIn("run", attrs)

    def test_alias_references_are_recorded_never_expanded(self):
        ev = self.collect("User_Alias ADMINS = alice\nADMINS ALL=(ALL) ALL\n")
        spec = [r for r in ev.records if r["kind"] == model.SPEC][0]
        self.assertEqual(spec["principals"][0]["value"], "ADMINS")
        self.assertEqual(spec["principals"][0]["kind"], model.ALIAS_REFERENCE)
        # alice must not have been substituted in.
        self.assertNotIn("alice", json.dumps(spec))

    def test_every_emitted_field_is_classified(self):
        ev = self.collect("Defaults env_reset\nUser_Alias A = alice\n"
                          "alice ALL=(ALL) /bin/ls\nnonsense (((\n")
        for record in ev.records:
            for key in record:
                self.assertIn(key, model.CLASSIFICATION, key)


class FixtureConfinement(unittest.TestCase):
    """An include path must resolve inside the root it was given."""

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)
        os.makedirs(os.path.join(self.base, "etc"))

    def test_absolute_include_stays_inside_the_collection_root(self):
        with open(os.path.join(self.base, "etc/sudoers"), "w") as handle:
            handle.write("#include /etc/passwd\n")
        ev = acquire.collect(self.base)
        for entry in ev.provenance["files"]:
            self.assertTrue(entry["requested_path"].startswith(self.base),
                            entry["requested_path"])

    def test_a_fixture_never_reads_the_live_host(self):
        with open(os.path.join(self.base, "etc/sudoers"), "w") as handle:
            handle.write("#includedir /etc/sudoers.d\n")
        ev = acquire.collect(self.base)
        for record in ev.records:
            self.assertTrue(record["source_path"].startswith(self.base))

    def test_production_behaviour_is_unchanged_at_root(self):
        adapter = acquire.SudoersIncludes("/")
        self.assertEqual(adapter._rebase("/etc/sudoers.d", "/etc/sudoers"),
                         "/etc/sudoers.d")


if __name__ == "__main__":
    unittest.main(verbosity=0)
