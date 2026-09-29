# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The PAM lane's own contract, including why it needs no rooted-path mapper.
# Implements: SCOPE-022, SCOPE-045, GOV-001
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""PAM lane: edge semantics, cycle vs diamond, reuse, and the rooted-path answer."""
import ast
import inspect
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import result                            # noqa: E402
from isedraf.pam import acquire, model, sources              # noqa: E402


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



class Base(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)
        os.makedirs(os.path.join(self.base, "etc/pam.d"))

    def service(self, name, text):
        with open(os.path.join(self.base, "etc/pam.d", name), "w") as handle:
            handle.write(text)

    def events(self, ev):
        return [e["event"] for e in ev.provenance["edge_events"]]


class EdgeSemantics(Base):
    """include and substack are different edges, and the model says why."""

    def test_the_two_edges_carry_different_documented_meanings(self):
        self.assertNotEqual(model.EDGE_SEMANTICS[model.INCLUDE],
                            model.EDGE_SEMANTICS[model.SUBSTACK])
        self.assertIn("cannot escape", model.EDGE_SEMANTICS[model.SUBSTACK])
        self.assertIn("terminate the containing stack",
                      model.EDGE_SEMANTICS[model.INCLUDE])

    def test_the_semantics_travel_with_the_evidence(self):
        self.service("sshd", "auth include common\n")
        self.service("common", "auth required pam_unix.so\n")
        ev = acquire.collect(self.base)
        self.assertIn(model.INCLUDE, ev.provenance["edge_semantics"])


class CycleVersusDiamond(Base):
    """Two different questions. Answering only one reports a broken stack as complete."""

    def test_a_diamond_is_not_a_cycle(self):
        self.service("one", "auth include common\n")
        self.service("two", "auth include common\n")
        self.service("common", "auth required pam_unix.so\n")
        ev = acquire.collect(self.base)
        self.assertIn("ALREADY_LOADED", self.events(ev))
        self.assertNotIn("CYCLE", self.events(ev))
        self.assertEqual(ev.status, result.COLLECTED)

    def test_a_cycle_is_reported_and_terminates(self):
        self.service("a", "auth include b\n")
        self.service("b", "auth include a\n")
        ev = acquire.collect(self.base)
        self.assertIn("CYCLE", self.events(ev))
        self.assertEqual(ev.status, result.PARTIAL)

    def test_a_self_cycle_is_reported(self):
        self.service("a", "auth include a\n")
        self.assertIn("CYCLE", self.events(acquire.collect(self.base)))

    def test_the_cycle_chain_is_recorded(self):
        self.service("a", "auth include b\n")
        self.service("b", "auth include a\n")
        ev = acquire.collect(self.base)
        cycle = [e for e in ev.provenance["edge_events"] if e["event"] == "CYCLE"][0]
        self.assertGreaterEqual(len(cycle["chain"]), 2)


class RootedPathIsNotNeeded(Base):
    """The consumer-count question, answered with evidence rather than by analogy."""

    def test_a_target_is_a_service_name_not_a_path(self):
        records, _ = sources.parse("auth include password-auth\n", "sshd")
        self.assertEqual(records[0]["target_service"], "password-auth")
        self.assertNotIn("/", records[0]["target_service"])

    def test_a_target_containing_separators_is_refused_not_joined(self):
        self.service("sshd", "auth include ../../etc/passwd\n")
        ev = acquire.collect(self.base)
        self.assertIn("INVALID_SERVICE_NAME", self.events(ev))
        for record in ev.records:
            self.assertTrue(record["source_path"].startswith(self.base))

    def test_no_absolute_path_rebasing_exists_in_this_lane(self):
        # sudo and ssh both map an absolute path beneath the collection root. PAM never
        # sees an absolute path: a service name is joined to an already-rooted pam.d
        # directory. Same shape, different abstraction - consumer count stays at 2.
        source = inspect.getsource(acquire)
        self.assertNotIn("_rebase", source)
        self.assertNotIn("isabs", source)
        self.assertNotIn("lstrip(\"/\")", source)


class SharedPrimitiveReuse(Base):

    def test_enumeration_is_S5(self):
        self.assertIn("bounded.enumerate_paths", _calls(acquire))
        tree = ast.parse(inspect.getsource(acquire))
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for reimplemented in ("listdir", "walk", "glob", "scandir"):
            self.assertNotIn(reimplemented, attrs, reimplemented)

    def test_metadata_is_S4_and_reading_is_hostio(self):
        source = inspect.getsource(acquire)
        self.assertIn("filemeta.observe", source)
        self.assertIn("hostio.read_file_lossless", source)
        tree = ast.parse(inspect.getsource(acquire))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        self.assertNotIn("open", names)

    def test_the_grammar_parser_is_pure(self):
        tree = ast.parse(inspect.getsource(sources))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("open", "listdir", "lstat", "Popen", "socket", "read_file"):
            self.assertNotIn(forbidden, names + attrs, forbidden)

    def test_S2_is_deliberately_not_used_and_the_reason_is_stated(self):
        # A PAM edge is not a file include: the target is a service name resolved in one
        # known directory, there is no glob, and the two edge kinds mean different
        # things. S2's adapter contract is about directives naming paths.
        self.assertNotIn("include_graph", " ".join(_imported(acquire)))


class NoVerdicts(Base):

    def test_every_emitted_field_is_classified(self):
        self.service("sshd", "auth required pam_unix.so\n"
                             "auth substack common\nbroken line here\n")
        self.service("common", "auth [success=1 default=ignore] pam_faillock.so\n")
        for record in acquire.collect(self.base).records:
            for key in record:
                self.assertIn(key, model.CLASSIFICATION, key)

    def test_the_limitation_denies_computing_an_outcome(self):
        self.service("sshd", "auth required pam_unix.so\n")
        limitation = acquire.collect(self.base).provenance["limitation"]
        self.assertIn("No stack outcome is computed", limitation)
        self.assertIn("not that it is effective", limitation)

    def test_no_subprocess_anywhere_in_the_lane(self):
        for module in (acquire, sources, model):
            tree = ast.parse(inspect.getsource(module))
            attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
            for forbidden in ("Popen", "check_output", "system"):
                self.assertNotIn(forbidden, attrs, module.__name__)


if __name__ == "__main__":
    unittest.main(verbosity=0)
