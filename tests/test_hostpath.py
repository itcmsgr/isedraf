# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The rooted-path primitive, and the live-host escape it exists to prevent.
# Implements: SCOPE-022, GOV-001, GOV-002
#
# Two properties carry everything: root "/" is the identity, and no input reaches outside
# the root. The second is the one an adversary attacks, so it is tested against the paths
# an adversary would write rather than the ones a tidy host contains.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================

"""The shared rooted-path mapping: identity at "/", containment everywhere else."""
import ast
import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf import hostpath                               # noqa: E402
from isedraf.ssh import acquire as ssh_acquire             # noqa: E402
from isedraf.sudo import acquire as sudo_acquire           # noqa: E402

# Paths a configuration file may legitimately contain, and paths an adversary writes.
HOSTILE = [
    "/etc/../../tmp/x",
    "/etc/../../../../../../../../etc/shadow",
    "/..",
    "/../..",
    "/./../etc/passwd",
    "//etc/x",
    "///",
    "/etc//ssh///sshd_config",
    "/etc/ssh/.",
    "/etc/ssh/..",
]


class Identity(unittest.TestCase):
    """With root "/" the mapping must change nothing an operator could observe."""

    def test_ordinary_path_is_unchanged(self):
        self.assertEqual(hostpath.under("/", "/etc/sudoers"), "/etc/sudoers")

    def test_root_itself_is_root(self):
        self.assertEqual(hostpath.under("/", "/"), "/")

    def test_identity_equals_what_the_kernel_would_resolve_lexically(self):
        # normpath is the lexical part of POSIX resolution: `..` above `/` is `/`.
        #
        # It is NOT the oracle for leading slashes. POSIX leaves exactly two of them
        # implementation-defined and normpath preserves them; Linux does not, and
        # stat("/etc"), stat("//etc") and stat("///etc") return one dev/ino on this
        # kernel. Identity here means "names the same object", so the collapse is
        # correct and normpath is the function that differs.
        for path in HOSTILE:
            expected = os.path.normpath("/" + path.lstrip("/"))
            self.assertEqual(hostpath.under("/", path), expected,
                             "root '/' altered %r" % path)

    def test_repeated_leading_slashes_name_the_same_object(self):
        for path in ("//etc/x", "///etc/x", "////etc/x"):
            self.assertEqual(hostpath.under("/", path), "/etc/x")
            self.assertEqual(hostpath.under("/fix", path), "/fix/etc/x")


class Mapping(unittest.TestCase):

    def test_absolute_path_lands_under_the_root(self):
        self.assertEqual(hostpath.under("/fix", "/etc/sudoers"), "/fix/etc/sudoers")

    def test_a_relative_root_is_honoured(self):
        self.assertEqual(hostpath.under("corpus/h1", "/etc/sudoers"),
                         "corpus/h1/etc/sudoers")

    def test_trailing_slash_on_the_root_does_not_double(self):
        self.assertEqual(hostpath.under("/fix/", "/etc/sudoers"), "/fix/etc/sudoers")

    def test_the_root_itself_is_the_mapped_form_of_slash(self):
        self.assertEqual(hostpath.under("/fix", "/"), "/fix")

    def test_undecodable_bytes_in_a_path_survive_the_mapping(self):
        name = os.fsdecode(b"/etc/\xff\xfe")
        mapped = hostpath.under("/fix", name)
        self.assertEqual(os.fsencode(mapped), b"/fix/etc/\xff\xfe")


class NoLiveHostFallthrough(unittest.TestCase):
    """The defect class: a fixture run reading the machine that runs the tool."""

    def test_dot_dot_cannot_climb_out_of_the_root(self):
        for path in HOSTILE:
            mapped = hostpath.under("/fix", path)
            self.assertTrue(mapped == "/fix" or mapped.startswith("/fix/"),
                            "%r escaped to %r" % (path, mapped))

    def test_the_naive_join_this_replaces_did_escape(self):
        # Not a style preference. The expression both lanes carried independently,
        # applied to a path a sudoers file may contain, resolves to the live host.
        naive = os.path.join("/fix", "/etc/../../tmp/x".lstrip("/"))
        self.assertEqual(os.path.normpath(naive), "/tmp/x")
        self.assertEqual(hostpath.under("/fix", "/etc/../../tmp/x"), "/fix/tmp/x")

    def test_host_meaning_is_preserved_not_merely_contained(self):
        # Clamping everything to the root would be safe and wrong: on the host
        # /etc/../../tmp/x names /tmp/x, so under a root it names <root>/tmp/x.
        self.assertEqual(hostpath.under("/fix", "/etc/../tmp/x"), "/fix/tmp/x")
        self.assertEqual(hostpath.under("/fix", "/etc/../../../tmp/x"), "/fix/tmp/x")

    def test_no_result_ever_contains_a_parent_component(self):
        for path in HOSTILE:
            self.assertNotIn("..", hostpath.under("/fix", path).split(os.sep))


class RelativeIsRefused(unittest.TestCase):
    """A shared helper must not guess an anchor only the domain knows."""

    def test_relative_path_raises(self):
        for path in ("etc/sudoers", "../x", ".ssh/authorized_keys", ""):
            with self.assertRaises(ValueError):
                hostpath.under("/fix", path)

    def test_the_message_says_why(self):
        try:
            hostpath.under("/fix", "sudoers.d/x")
        except ValueError as error:
            self.assertIn("relative", str(error))
        else:
            self.fail("a relative path was accepted")


class Beneath(unittest.TestCase):
    """The relative branch escapes the same way, and is closed the same way."""

    def test_a_rooted_path_with_dot_dot_is_clamped(self):
        self.assertEqual(hostpath.beneath("/fix", "/fix/etc/../../tmp/x"),
                         "/fix/tmp/x")

    def test_root_slash_is_plain_normalisation(self):
        self.assertEqual(hostpath.beneath("/", "/etc/../../tmp/x"), "/tmp/x")

    def test_the_root_itself_round_trips(self):
        self.assertEqual(hostpath.beneath("/fix", "/fix"), "/fix")

    def test_a_path_not_built_from_the_root_is_refused(self):
        # Silently treating it as host-absolute would invent a declaration.
        with self.assertRaises(ValueError):
            hostpath.beneath("/fix", "/etc/sudoers")

    def test_nothing_escapes(self):
        for path in HOSTILE:
            rooted = "/fix" + path
            self.assertTrue(hostpath.beneath("/fix", rooted).startswith("/fix"))


class Purity(unittest.TestCase):
    """String arithmetic over two arguments. Nothing else."""

    def test_the_module_touches_no_filesystem(self):
        tree = ast.parse(inspect.getsource(hostpath))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("open", "listdir", "lstat", "stat", "scandir", "exists",
                          "isfile", "isdir", "readlink", "realpath", "islink",
                          "Popen", "check_output", "environ", "getcwd", "expanduser"):
            self.assertNotIn(forbidden, names + attrs,
                             "hostpath used %r; its result must depend only on its "
                             "arguments" % forbidden)

    def test_it_imports_nothing_from_isedraf(self):
        tree = ast.parse(inspect.getsource(hostpath))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = getattr(node, "module", None) or ""
                self.assertNotIn("isedraf", module)
                for alias in node.names:
                    self.assertNotIn("isedraf", alias.name)


class Consumers(unittest.TestCase):
    """Extraction means the copies are gone, not that a third copy has company."""

    def _source(self, module):
        return inspect.getsource(module)

    def test_neither_lane_still_joins_a_root_by_hand(self):
        for module in (sudo_acquire, ssh_acquire):
            source = self._source(module)
            self.assertNotIn('lstrip("/")', source,
                             "%s still carries its own rooted-path arithmetic"
                             % module.__name__)

    def test_both_lanes_route_through_the_primitive(self):
        for module in (sudo_acquire, ssh_acquire):
            source = self._source(module)
            self.assertIn("hostpath.under", source)
            self.assertIn("hostpath.beneath", source)

    def test_the_adapters_still_own_the_grammar(self):
        # The branch on absoluteness is domain knowledge and must NOT have moved into
        # the shared helper: sshd anchors a relative Include to the including file,
        # authorized_keys will anchor a relative path to a home directory.
        for module in (sudo_acquire, ssh_acquire):
            self.assertIn("os.path.isabs", self._source(module))


class Containment(unittest.TestCase):
    """Component containment, and the two string-prefix bugs it cannot express.

    Both were real. `root + os.sep` is "//" at the production root, so the collector
    refused every path and read nothing; and `startswith(root)` without a separator
    accepts a SIBLING whose name merely extends the root's. One test suite missed the
    first for an entire frozen lane because no fixture root can be "/".
    """

    def test_the_production_root_contains_everything_absolute(self):
        for path in ("/", "/etc", "/tmp/x", "/etc/ssh/keys"):
            self.assertTrue(hostpath.contains("/", path), path)

    def test_a_fixture_root_contains_itself_and_its_children(self):
        self.assertTrue(hostpath.contains("/fixture", "/fixture"))
        self.assertTrue(hostpath.contains("/fixture", "/fixture/etc/x"))

    def test_a_sibling_that_merely_extends_the_root_is_outside(self):
        self.assertFalse(hostpath.contains("/fixture", "/fixture-evil"))
        self.assertFalse(hostpath.contains("/fixture", "/fixture-evil/etc/x"))

    def test_an_unrelated_path_is_outside(self):
        self.assertFalse(hostpath.contains("/fixture", "/tmp/x"))

    def test_a_partial_component_is_not_containment(self):
        self.assertFalse(hostpath.contains("/a/b", "/a/bc"))
        self.assertTrue(hostpath.contains("/a/b", "/a/b/c"))

    def test_a_trailing_slash_on_the_root_changes_nothing(self):
        self.assertTrue(hostpath.contains("/fixture/", "/fixture/x"))

    def test_relative_input_is_refused_rather_than_guessed(self):
        for root, candidate in (("fixture", "/x"), ("/fixture", "x"), ("", "/x")):
            with self.assertRaises(ValueError):
                hostpath.contains(root, candidate)

    def test_it_performs_no_resolution_of_its_own(self):
        # The caller owns realpath; this owns containment. A helper that resolved would
        # decide WHICH containment was being asked, which is the caller's question.
        tree = ast.parse(inspect.getsource(hostpath.contains))
        names = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("realpath", "islink", "readlink", "exists", "stat"):
            self.assertNotIn(forbidden, names)


if __name__ == "__main__":
    unittest.main(verbosity=0)
