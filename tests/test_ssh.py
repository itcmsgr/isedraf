# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The SSH lane's own contract: reuse where it fits, scope, declared-only.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, GOV-001
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""SSH lane: shared-primitive reuse, the S1 non-use, scope, and declared-only."""
import ast
import inspect
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import keyvalue, result                  # noqa: E402
from isedraf.ssh import acquire, model, sources              # noqa: E402


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



class WhyNotS1(unittest.TestCase):
    """The non-use is a finding, so it is demonstrated rather than asserted."""

    def test_no_single_S1_profile_expresses_the_sshd_line_grammar(self):
        # sshd accepts BOTH forms. A whitespace profile mangles one, a '=' profile
        # mangles the other, and each produces a confident wrong value with a digest.
        class Whitespace(keyvalue.Profile):
            name = "ws"
            whitespace_delimited = True

        class Equals(keyvalue.Profile):
            name = "eq"

        # Each profile fails on the form the other handles, and in different ways:
        # the whitespace profile finds no delimiter at all, the '=' profile splits at
        # the wrong place. Neither produces the right answer for both.
        whitespace = keyvalue.parse("Port=22\n", Whitespace()).records[0]
        self.assertTrue(whitespace["malformed"])
        self.assertEqual(whitespace["key_raw"], "Port=22")
        equals = keyvalue.parse("Port 22\n", Equals()).records[0]
        self.assertTrue(equals["malformed"])
        # The domain parser handles both.
        for text, expected in (("Port=22\n", "22"), ("Port 22\n", "22")):
            records, _, _, _ = sources.parse(text)
            self.assertEqual(records[0]["value"], expected)

    def test_the_domain_parser_is_pure(self):
        tree = ast.parse(inspect.getsource(sources))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("open", "listdir", "lstat", "Popen", "socket", "read_file"):
            self.assertNotIn(forbidden, names + attrs, forbidden)


class SharedPrimitiveReuse(unittest.TestCase):

    def test_the_include_graph_is_S2(self):
        source = inspect.getsource(acquire)
        self.assertIn("include_graph.resolve", source)
        for reimplemented in ("def _walk", "visiting", "def _expand"):
            self.assertNotIn(reimplemented, source, reimplemented)

    def test_file_metadata_is_S4(self):
        self.assertIn("filemeta.observe", _calls(acquire))
        tree = ast.parse(inspect.getsource(acquire))
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        self.assertNotIn("lstat", attrs)

    def test_no_second_reader(self):
        tree = ast.parse(inspect.getsource(acquire))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        self.assertNotIn("open", names)


class Scope(unittest.TestCase):
    """The structural property the lane exists to preserve."""

    def test_an_included_file_is_parsed_under_the_scope_that_included_it(self):
        # SSH_INCLUDE_MATCH_CONTEXT_001. The earlier expectation here was inverted: it
        # asserted every included file resets to GLOBAL, which certified the defect
        # rather than catching it. sshd_config(5) permits Include inside Match for
        # conditional inclusion, and OpenSSH parses the included file under the
        # containing Match state. Verified against OpenSSH 10.2p1 with `sshd -T -C`.
        entry = (model.MATCH_SCOPE,
                 [{"keyword": "user", "values": ["alice"], "negated": False}], 0)
        records, _, _, _ = sources.parse("X11Forwarding no\n", "/inc", 0, 3, entry)
        self.assertEqual(records[0]["scope"], model.MATCH_SCOPE)
        self.assertEqual(records[0]["match_criteria"][0]["values"], ["alice"])

    def test_a_file_entered_globally_stays_global(self):
        records, _, _, _ = sources.parse("X11Forwarding no\n", "/inc", 0, 0)
        self.assertEqual(records[0]["scope"], model.GLOBAL)
        self.assertIsNone(records[0]["match_index"])

    def test_scope_at_line_reports_the_scope_an_include_was_written_in(self):
        # Recorded before the line is interpreted, so an Include carries the scope it
        # sits in rather than any scope it goes on to establish.
        _, _, _, scope_at_line = sources.parse(
            "Port 22\nMatch User a\nInclude x.conf\n")
        self.assertEqual(scope_at_line[1][0], model.GLOBAL)
        self.assertEqual(scope_at_line[3][0], model.MATCH_SCOPE)

    def test_match_index_continues_across_files(self):
        _, _, next_index, _ = sources.parse("Match User a\n  PermitTTY no\n")
        self.assertEqual(next_index, 1)
        records, _, after, _ = sources.parse("Match User b\n  PermitTTY no\n", None, 0,
                                             next_index)
        self.assertEqual(records[0]["match_index"], 1)
        self.assertEqual(after, 2)

    def test_criteria_are_structured_not_a_string(self):
        records, _, _, _ = sources.parse(
            "Match User a,b Address 10.0.0.0/8\n  PermitTTY no\n")
        criteria = records[1]["match_criteria"]
        self.assertEqual(criteria[0]["values"], ["a", "b"])
        self.assertEqual(criteria[1]["keyword"], "address")


class DeclaredOnly(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)
        os.makedirs(os.path.join(self.base, "etc/ssh"))

    def collect(self, text):
        with open(os.path.join(self.base, "etc/ssh/sshd_config"), "w") as handle:
            handle.write(text)
        return acquire.collect(self.base)

    def test_the_dimension_is_declared(self):
        self.assertEqual(self.collect("Port 22\n").provenance["dimension"],
                         model.DECLARED)

    def test_sshd_T_is_named_as_not_collected(self):
        self.assertIn("sshd -T", self.collect("Port 22\n").provenance["not_collected"])

    def test_no_subprocess_anywhere_in_the_lane(self):
        for module in (acquire, sources, model):
            tree = ast.parse(inspect.getsource(module))
            attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
            for forbidden in ("run", "Popen", "check_output", "system"):
                self.assertNotIn(forbidden, attrs, "%s: %s" % (module.__name__,
                                                               forbidden))

    def test_duplicate_policy_is_recorded_not_applied(self):
        ev = self.collect("Port 22\nPort 2222\n")
        self.assertEqual(ev.provenance["duplicate_policy"], "FIRST_WINS")
        self.assertEqual(len([r for r in ev.records
                              if r["kind"] == model.DIRECTIVE]), 2)

    def test_every_emitted_field_is_classified(self):
        ev = self.collect("Port 22\nMatch User a\n  PermitTTY no\nbroken\n")
        for record in ev.records:
            for key in record:
                self.assertIn(key, model.CLASSIFICATION, key)

    def test_the_limitation_states_what_declared_does_not_mean(self):
        limitation = self.collect("Port 22\n").provenance["limitation"]
        self.assertIn("sshd -T is not run", limitation)
        self.assertIn("reject, override or ignore", limitation)


class RootedPaths(unittest.TestCase):
    """SHARED_ABSTRACTION_CANDIDATE consumer #2. Same semantics as sudo, domain-local."""

    def test_absolute_include_maps_under_the_collection_root(self):
        adapter = acquire.SshdIncludes("/fixture")
        self.assertEqual(adapter._rebase("/etc/ssh/x.conf", "/fixture/etc/ssh/sshd_config"),
                         "/fixture/etc/ssh/x.conf")

    def test_production_root_is_the_identity(self):
        adapter = acquire.SshdIncludes("/")
        self.assertEqual(adapter._rebase("/etc/ssh/x.conf", "/etc/ssh/sshd_config"),
                         "/etc/ssh/x.conf")

    def test_relative_include_resolves_against_the_including_file(self):
        adapter = acquire.SshdIncludes("/fixture")
        self.assertEqual(adapter._rebase("x.conf", "/fixture/etc/ssh/sshd_config"),
                         "/fixture/etc/ssh/x.conf")

    def test_no_realpath_is_used(self):
        tree = ast.parse(inspect.getsource(acquire))
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        self.assertNotIn("realpath", attrs)


if __name__ == "__main__":
    unittest.main(verbosity=0)
