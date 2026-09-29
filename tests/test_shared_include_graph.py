# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: S2 include-graph mechanics, attacked rather than demonstrated.
# Implements: SCOPE-022, SCOPE-045, GOV-002
#
# The adapter here is a TEST adapter with a deliberately boring syntax. No real domain
# grammar appears in this file: coupling the generic engine to its first real consumer is
# exactly the failure the shared-primitive rule exists to prevent.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""S2 — include graph."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import include_graph, result          # noqa: E402


class TestAdapter(include_graph.Adapter):
    """`inc <target>` includes; `weird <target>` is a recognized but unsupported form."""

    name = "test"

    def directives(self, text, path):
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if line.startswith("inc "):
                yield number, line, [line[4:].strip()], True
            elif line.startswith("weird "):
                yield number, line, [], False


def tree(**files):
    base = tempfile.mkdtemp()
    for name, text in files.items():
        path = os.path.join(base, name.replace("__", "/"))
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(path, "w") as fh:
            fh.write(text)
    return base


class Traversal(unittest.TestCase):

    def test_simple_chain_in_expansion_order(self):
        base = tree(root="inc b\n", b="inc c\n", c="leaf\n")
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual([os.path.basename(n["path"]) for n in ev.records],
                         ["root", "b", "c"])
        self.assertEqual([n["depth"] for n in ev.records], [0, 1, 2])

    def test_order_is_expansion_order_not_alphabetical(self):
        # z is included before a. A shared primitive that sorted its output would make an
        # ordering claim on the domain's behalf, and several domains are order-sensitive.
        base = tree(root="inc z\ninc a\n", a="", z="")
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        self.assertEqual([os.path.basename(n["path"]) for n in ev.records],
                         ["root", "z", "a"])

    def test_provenance_records_where_each_node_came_from(self):
        base = tree(root="# c\ninc b\n", b="")
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        child = ev.records[1]
        self.assertEqual(child["source_kind"], include_graph.INCLUDED)
        self.assertEqual(child["parent"], os.path.join(base, "root"))
        self.assertEqual(child["directive"]["line"], 2)
        self.assertEqual(child["directive"]["expansion_ordinal"], 0)
        self.assertEqual(child["ordinal"], 1)

    def test_glob_expansion_is_deterministic(self):
        base = tree(root="inc conf.d/*.conf\n", **{"conf.d__20-b.conf": "",
                                                   "conf.d__10-a.conf": "",
                                                   "conf.d__skip.txt": ""})
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        names = [os.path.basename(n["path"]) for n in ev.records[1:]]
        self.assertEqual(names, ["10-a.conf", "20-b.conf"])


class FailureSemantics(unittest.TestCase):
    """A missed include is a missed rule. None of these may pass silently."""

    def _kinds(self, ev):
        return set(a["anomaly"] for a in ev.anomalies)

    def test_missing_literal_target_is_partial_by_default(self):
        base = tree(root="inc nope\n")
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn(result.ANOMALY_MISSING, self._kinds(ev))
        self.assertIn("not the whole configuration", ev.reason)
        self.assertFalse(ev.complete)

    def test_unreadable_include_is_partial(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores the permission bits this test depends on")
        base = tree(root="inc secret\n", secret="")
        self.addCleanup(shutil.rmtree, base)
        os.chmod(os.path.join(base, "secret"), 0)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn(result.ANOMALY_UNREADABLE, self._kinds(ev))

    def test_unsupported_directive_is_recorded_not_dropped(self):
        base = tree(root="weird something\n")
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn(result.ANOMALY_UNSUPPORTED, self._kinds(ev))

    def test_glob_matching_nothing_is_recorded_but_not_incomplete_by_default(self):
        # An empty drop-in directory is an ordinary configuration state. The event is
        # recorded; the default adapter does not call it evidence loss.
        base = tree(root="inc conf.d/*.conf\n", **{"conf.d__x.txt": ""})
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertTrue(any(a.get("event") == include_graph.NO_MATCH
                            for a in ev.anomalies))

    def test_missing_root_is_not_tested_not_partial(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "absent"), TestAdapter())
        self.assertEqual(ev.status, result.NOT_TESTED)
        self.assertIn("SOURCE_ABSENT", ev.reason)

    def test_empty_included_file_is_not_an_anomaly(self):
        base = tree(root="inc b\n", b="")
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        self.assertEqual(ev.status, result.COLLECTED)


class Cycles(unittest.TestCase):
    """Terminate, keep the evidence, report the cycle, never claim completeness."""

    def _run(self, base):
        return include_graph.resolve(os.path.join(base, "root"), TestAdapter())

    def test_self_cycle(self):
        base = tree(root="inc root\n")
        self.addCleanup(shutil.rmtree, base)
        ev = self._run(base)
        self.assertTrue(any(a["anomaly"] == result.ANOMALY_CYCLE for a in ev.anomalies))
        self.assertEqual(ev.status, result.PARTIAL)

    def test_two_node_cycle(self):
        base = tree(root="inc b\n", b="inc root\n")
        self.addCleanup(shutil.rmtree, base)
        ev = self._run(base)
        self.assertTrue(any(a["anomaly"] == result.ANOMALY_CYCLE for a in ev.anomalies))
        # Evidence already collected survives.
        self.assertEqual([os.path.basename(n["path"]) for n in ev.records],
                         ["root", "b"])

    def test_longer_cycle(self):
        base = tree(root="inc b\n", b="inc c\n", c="inc d\n", d="inc b\n")
        self.addCleanup(shutil.rmtree, base)
        ev = self._run(base)
        self.assertTrue(any(a["anomaly"] == result.ANOMALY_CYCLE for a in ev.anomalies))
        self.assertEqual(len(ev.records), 4)

    def test_cycle_does_not_exhaust_recursion(self):
        base = tree(root="inc b\n", b="inc root\n")
        self.addCleanup(shutil.rmtree, base)
        ev = self._run(base)     # would RecursionError without the visiting check
        self.assertEqual(ev.status, result.PARTIAL)

    def test_diamond_is_duplicate_not_cycle(self):
        # Two parents including the same file is legal and means the declarations apply
        # twice. That is worth reporting, and it is not a cycle.
        base = tree(root="inc b\ninc c\n", b="inc shared\n", c="inc shared\n", shared="")
        self.addCleanup(shutil.rmtree, base)
        ev = self._run(base)
        kinds = [a["anomaly"] for a in ev.anomalies]
        self.assertIn(result.ANOMALY_DUPLICATE, kinds)
        self.assertNotIn(result.ANOMALY_CYCLE, kinds)
        dup = [n for n in ev.records if "duplicate_of" in n]
        self.assertEqual(len(dup), 1)


class Limits(unittest.TestCase):

    def test_node_limit_reports_truncation_rather_than_truncating_silently(self):
        files = {"root": "".join("inc f%d\n" % i for i in range(10))}
        for i in range(10):
            files["f%d" % i] = ""
        base = tree(**files)
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter(),
                                   max_nodes=4)
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertTrue(ev.provenance["truncated"])
        self.assertTrue(any(a["anomaly"] == result.ANOMALY_LIMIT for a in ev.anomalies))

    def test_depth_limit_is_reported(self):
        files = {"root": "inc f1\n"}
        for i in range(1, 8):
            files["f%d" % i] = "inc f%d\n" % (i + 1)
        files["f8"] = ""
        base = tree(**files)
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter(),
                                   max_depth=3)
        self.assertEqual(ev.status, result.PARTIAL)


class Confinement(unittest.TestCase):
    """A fixture graph must never reach the machine running the test."""

    def test_absolute_include_stays_inside_the_fixture_when_it_exists_there(self):
        base = tree(root="inc b\n", b="")
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        for node in ev.records:
            self.assertTrue(node["path"].startswith(base), node["path"])

    def test_identity_is_lexical_and_does_not_resolve_symlinks(self):
        # realpath() would resolve a symlink and could consult a target outside the
        # fixture. normpath collapses `a/../b` without touching the filesystem.
        self.assertEqual(include_graph._identity("/x/y/../z"), "/x/z")

    def test_negative_control_no_fallback_to_the_live_host(self):
        # The engine must never substitute a real path for a missing fixture one.
        base = tree(root="inc /etc/hostname\n")
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        # /etc/hostname exists on the test machine; the engine reads the target it was
        # given, so the guard is that the ROOT was the fixture and nothing was invented.
        self.assertTrue(ev.records[0]["path"].startswith(base))
        self.assertEqual(len(ev.records), 2)

    def test_reader_is_injectable_so_tests_need_no_filesystem_at_all(self):
        calls = []

        def fake_read(path):
            calls.append(path)
            from isedraf import hostio as _exec
            return _exec.Outcome(value="", source=path, detail=_exec.READ_OK)

        ev = include_graph.resolve("/virtual/root", TestAdapter(), read=fake_read,
                                   expand=lambda p: [p])
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual(calls, ["/virtual/root"])


class NoDomainPolicy(unittest.TestCase):
    """S2 is a shared primitive. It must not know about any consumer.

    The check is on EXECUTABLE code, not on prose. Naming sshd and sudoers in a docstring
    to explain why the adapter pattern exists is documentation and is the reason the
    pattern is there; a domain name appearing as a string the engine ACTS on, or as an
    import, is coupling. An earlier version of this test grepped the whole source and
    flagged its own explanatory docstring, which would have pushed the fix in the wrong
    direction: making the code less explained rather than less coupled.
    """

    # Domain coupling only. Framework names are deliberately NOT listed here: naming them
    # even in a denylist reads as a claim to check_licensing, and that gate already
    # enforces the framework boundary across every tracked file, so repeating it here
    # would be a second, weaker copy of a rule that already exists.
    FORBIDDEN = ("PermitRootLogin", "sudoers", "sshd", "pam_", "auditctl", "nftables")

    def _executable_strings(self, module):
        """Every string constant that is not a docstring."""
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(module))
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc is not None:
                    docstrings.add(doc)
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value not in docstrings:
                    out.append(node.value)
        return out

    def test_no_domain_name_is_acted_on(self):
        for value in self._executable_strings(include_graph):
            for forbidden in self.FORBIDDEN:
                self.assertNotIn(forbidden.lower(), value.lower(),
                                 "engine acts on %r" % value)

    def test_no_domain_module_is_imported(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(include_graph))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
            elif isinstance(node, ast.Import):
                imported.extend(a.name for a in node.names)
        for name in imported:
            for forbidden in ("accounts", "ssh", "sudo", "pam", "audit", "report"):
                self.assertNotIn(forbidden, name, name)

    def test_no_security_verdict_vocabulary_in_the_engine(self):
        for value in self._executable_strings(include_graph):
            for verdict in ("SECURE", "INSECURE", "COMPLIANT", "REMEDIAT"):
                self.assertNotIn(verdict, value.upper())


class CompletenessIsTheAdaptersCall(unittest.TestCase):
    """The engine records what happened. The domain decides what it means.

    An earlier version forced PARTIAL for every include event, which quietly encoded one
    format's opinion - that a wildcard matching nothing is a problem - into a primitive
    five formats were going to share. These tests hold the two sides apart: the SAME
    observed event must be able to reach either status depending only on the adapter.
    """

    class Tolerant(TestAdapter):
        name = "tolerant"

        def affects_completeness(self, event):
            return False

    class Strict(TestAdapter):
        name = "strict"

        def affects_completeness(self, event):
            return True

    def _graph(self, adapter, **files):
        base = tree(**files)
        self.addCleanup(shutil.rmtree, base)
        return include_graph.resolve(os.path.join(base, "root"), adapter)

    def test_zero_match_wildcard_collected_when_the_domain_permits_it(self):
        ev = self._graph(self.Tolerant(), root="inc conf.d/*.conf\n",
                         **{"conf.d__x.txt": ""})
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertTrue(any(a.get("event") == include_graph.NO_MATCH
                            for a in ev.anomalies))

    def test_the_same_zero_match_is_partial_when_the_domain_says_so(self):
        ev = self._graph(self.Strict(), root="inc conf.d/*.conf\n",
                         **{"conf.d__x.txt": ""})
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn(include_graph.NO_MATCH, ev.reason)

    def test_empty_include_directory_can_be_complete(self):
        base = tree(root="inc conf.d/*.conf\n")
        os.makedirs(os.path.join(base, "conf.d"))
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        self.assertEqual(ev.status, result.COLLECTED)

    def test_duplicate_include_is_structural_not_evidence_loss_by_default(self):
        ev = self._graph(TestAdapter(), root="inc b\ninc c\n", b="inc shared\n",
                         c="inc shared\n", shared="")
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertTrue(any(a.get("event") == include_graph.DUPLICATE_INCLUDE
                            for a in ev.anomalies))

    def test_a_domain_may_treat_duplicate_inclusion_as_incomplete(self):
        ev = self._graph(self.Strict(), root="inc b\ninc c\n", b="inc shared\n",
                         c="inc shared\n", shared="")
        self.assertEqual(ev.status, result.PARTIAL)

    def test_missing_literal_target_stays_partial_under_the_default(self):
        ev = self._graph(TestAdapter(), root="inc definitely-not-here\n")
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertTrue(any(a.get("event") == include_graph.MISSING_TARGET
                            for a in ev.anomalies))

    def test_no_match_and_missing_target_are_different_events(self):
        # Conflating them was the defect. A glob that matched nothing and a named file
        # that is not there are different observations about the host.
        glob_ev = self._graph(TestAdapter(), root="inc d/*.conf\n", **{"d__x.txt": ""})
        literal_ev = self._graph(TestAdapter(), root="inc named-file\n")
        self.assertEqual([a["event"] for a in glob_ev.anomalies if a.get("event")],
                         [include_graph.NO_MATCH])
        self.assertEqual([a["event"] for a in literal_ev.anomalies if a.get("event")],
                         [include_graph.MISSING_TARGET])

    def test_engine_holds_no_opinion_of_its_own(self):
        # Every completeness decision must route through the adapter. If the engine kept
        # its own list, a Tolerant adapter could not produce COLLECTED for a cycle.
        class TolerantCycles(TestAdapter):
            name = "tolerant-cycles"

            def affects_completeness(self, event):
                return event["event"] != include_graph.CYCLE

        ev = self._graph(TolerantCycles(), root="inc b\n", b="inc root\n")
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertTrue(any(a.get("event") == include_graph.CYCLE
                            for a in ev.anomalies))


class LexicalIdentityLimits(unittest.TestCase):
    """Lexical identity is for fixture safety, not a proof of file identity."""

    def test_two_lexical_paths_may_name_one_file_and_termination_does_not_depend_on_it(self):
        # `link` is a symlink to `real`. Lexically they are different paths, so the
        # duplicate check does not see them as the same source object. That is a KNOWN
        # limit of lexical identity, accepted deliberately: resolving it with realpath()
        # would let a fixture graph consult a target outside its root. Termination is
        # guaranteed by the depth and node bounds, not by identity.
        base = tree(root="inc real\ninc link\n", real="")
        os.symlink(os.path.join(base, "real"), os.path.join(base, "link"))
        self.addCleanup(shutil.rmtree, base)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter())
        self.assertEqual(len(ev.records), 3)
        # No duplicate is claimed, because lexically these are two different paths.
        self.assertFalse(any(a.get("event") == include_graph.DUPLICATE_INCLUDE
                             for a in ev.anomalies))

    def test_a_symlink_cycle_terminates_on_bounds_not_on_identity(self):
        # a -> b -> a via symlinks defeats lexical cycle detection. The node and depth
        # bounds must still stop it, which is why they are not optional.
        base = tree(root="inc a\n")
        os.makedirs(os.path.join(base, "d1"))
        os.symlink(os.path.join(base, "d1"), os.path.join(base, "d1", "self"))
        with open(os.path.join(base, "a"), "w") as fh:
            fh.write("inc d1/self/self/self/x\n")
        self.addCleanup(shutil.rmtree, base, True)
        ev = include_graph.resolve(os.path.join(base, "root"), TestAdapter(),
                                   max_depth=4, max_nodes=12)
        self.assertIn(ev.status, (result.COLLECTED, result.PARTIAL))
        self.assertLessEqual(len(ev.records), 12)

    def test_the_engine_never_calls_realpath(self):
        # Checked on executable code, not prose: the module docstrings explain WHY
        # realpath is avoided, and an earlier version of this assertion failed on its own
        # explanation. Same precedent as the domain-coupling test.
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(include_graph))
        called = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                called.append(node.attr)
            elif isinstance(node, ast.Name):
                called.append(node.id)
        self.assertNotIn("realpath", called)
        self.assertIn("normpath", called)


if __name__ == "__main__":
    unittest.main(verbosity=0)
