# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: S5 — complete over the requested universe, never over the filesystem.
# Implements: SCOPE-022, SCOPE-045, GOV-002
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""S5 — bounded enumeration."""
import ast
import inspect
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import bounded, result                 # noqa: E402


class Base(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)

    def p(self, *parts):
        return os.path.join(self.base, *parts)

    def touch(self, name, content=""):
        path = self.p(name)
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(path, "w") as fh:
            fh.write(content)
        return path

    def events(self, ev):
        return set(a["event"] for a in ev.anomalies if a.get("event"))

    def names(self, ev):
        return [r["name"] for r in ev.records]


class RequestedUniverse(Base):
    """Complete means complete over what was ASKED, not over the filesystem."""

    def test_obeying_the_requested_depth_is_still_complete(self):
        # The decisive case. Deeper directories exist; the caller asked for depth 1; the
        # honest answer is COLLECTED. Reporting PARTIAL here would make every bounded
        # question permanently incomplete.
        self.touch("a.conf")
        self.touch("sub/deep.conf")
        ev = bounded.enumerate_paths(self.base)
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertIn(bounded.DEPTH_BOUNDARY, self.events(ev))
        self.assertEqual(self.names(ev), ["a.conf"])

    def test_safety_cap_reached_is_incomplete(self):
        # The cap firing means eligible entries exist that were never examined. That is
        # not the same as obeying a boundary.
        for i in range(20):
            self.touch("f%02d.conf" % i)
        class Capped(bounded.Universe):
            name = "capped"
            max_entries = 5
        ev = bounded.enumerate_paths(self.base, Capped())
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn(bounded.LIMIT_REACHED, self.events(ev))
        self.assertTrue(ev.provenance["safety_cap_reached"])
        # The status reason names the EVENT; the anomaly carries the detail.
        self.assertIn(bounded.LIMIT_REACHED, ev.reason)
        capped = [a for a in ev.anomalies if a.get("event") == bounded.LIMIT_REACHED]
        self.assertIn("safety cap", capped[0]["detail"])
        self.assertIn("were not examined", capped[0]["detail"])
        # Evidence collected before the cap is retained, not discarded.
        self.assertEqual(len(ev.records), 5)

    def test_boundary_and_cap_are_different_events(self):
        self.touch("sub/x.conf")
        ev = bounded.enumerate_paths(self.base)
        self.assertIn(bounded.DEPTH_BOUNDARY, self.events(ev))
        self.assertNotIn(bounded.LIMIT_REACHED, self.events(ev))

    def test_a_universe_may_declare_the_depth_boundary_incomplete(self):
        class Strict(bounded.Universe):
            name = "strict"
            def affects_completeness(self, event):
                return True
        self.touch("sub/x.conf")
        self.assertEqual(bounded.enumerate_paths(self.base, Strict()).status,
                         result.PARTIAL)

    def test_a_universe_may_tolerate_the_safety_cap(self):
        # Proves the engine holds no list of its own.
        class Tolerant(bounded.Universe):
            name = "tolerant"
            max_entries = 2
            def affects_completeness(self, event):
                return False
        for i in range(10):
            self.touch("f%d" % i)
        self.assertEqual(bounded.enumerate_paths(self.base, Tolerant()).status,
                         result.COLLECTED)

    def test_deeper_depth_descends(self):
        self.touch("sub/deep.conf")
        class Deep(bounded.Universe):
            name = "deep"
            max_depth = 2
        ev = bounded.enumerate_paths(self.base, Deep())
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertIn("deep.conf", self.names(ev))

    def test_empty_directory_is_complete_with_no_entries(self):
        ev = bounded.enumerate_paths(self.base)
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual(ev.records, [])

    def test_missing_root_is_not_tested(self):
        ev = bounded.enumerate_paths(self.p("absent"))
        self.assertEqual(ev.status, result.NOT_TESTED)
        self.assertIn(bounded.ROOT_MISSING, self.events(ev))

    def test_pattern_and_type_filters_define_the_universe(self):
        self.touch("a.conf")
        self.touch("b.txt")
        os.mkdir(self.p("d"))
        class OnlyConf(bounded.Universe):
            name = "conf"
            pattern = "*.conf"
        self.assertEqual(self.names(bounded.enumerate_paths(self.base, OnlyConf())),
                         ["a.conf"])


class Ordering(Base):
    """Deterministic, locale-independent, byte-safe."""

    def test_order_is_by_filename_bytes(self):
        for name in ("b", "A", "a", "C", "_", "0"):
            self.touch(name)
        ev = bounded.enumerate_paths(self.base)
        expected = sorted(["b", "A", "a", "C", "_", "0"],
                          key=lambda n: n.encode("utf-8"))
        self.assertEqual(self.names(ev), expected)

    def test_order_is_stable_across_calls(self):
        for i in range(30):
            self.touch("f%02d" % i)
        first = self.names(bounded.enumerate_paths(self.base))
        second = self.names(bounded.enumerate_paths(self.base))
        self.assertEqual(first, second)

    def test_locale_does_not_change_the_order(self):
        # Byte ordering, not collation. A tool that sorted by locale would produce a
        # different digest on a differently configured host.
        import locale
        for name in ("a", "B", "z", "A"):
            self.touch(name)
        before = self.names(bounded.enumerate_paths(self.base))
        try:
            locale.setlocale(locale.LC_COLLATE, "C.UTF-8")
        except locale.Error:
            pass
        self.addCleanup(locale.setlocale, locale.LC_COLLATE, "C")
        self.assertEqual(before, self.names(bounded.enumerate_paths(self.base)))

    def test_undecodable_filenames_do_not_collapse(self):
        # Two distinct byte names that a replacement character would merge into one.
        for raw in (b"bad\xe9name", b"bad\xffname"):
            with open(os.path.join(os.fsencode(self.base), raw), "wb") as fh:
                fh.write(b"")
        ev = bounded.enumerate_paths(self.base)
        hexes = [r["name_bytes_hex"] for r in ev.records]
        self.assertEqual(len(set(hexes)), 2)
        for record in ev.records:
            self.assertEqual(record["name_encoding"], "UNDECODABLE")
            self.assertIsNone(record["name"])

    def test_decodable_and_undecodable_are_both_represented(self):
        self.touch("plain")
        with open(os.path.join(os.fsencode(self.base), b"odd\xe9"), "wb") as fh:
            fh.write(b"")
        ev = bounded.enumerate_paths(self.base)
        encodings = sorted(r["name_encoding"] for r in ev.records)
        self.assertEqual(encodings, ["UNDECODABLE", "UTF8"])


class Confinement(Base):
    """A symlink is an entry, not permission to walk somewhere."""

    def test_symlink_is_not_followed_by_default(self):
        os.mkdir(self.p("realdir"))
        self.touch("realdir/inside.conf")
        os.symlink(self.p("realdir"), self.p("link"))
        class Deep(bounded.Universe):
            name = "deep"
            max_depth = 5
        ev = bounded.enumerate_paths(self.base, Deep())
        self.assertIn(bounded.SYMLINK_SKIPPED, self.events(ev))
        # inside.conf is reached once, through the real directory, not twice.
        self.assertEqual(self.names(ev).count("inside.conf"), 1)

    def test_absolute_symlink_to_the_live_host_is_not_walked(self):
        os.symlink("/etc", self.p("escape"))
        class Deep(bounded.Universe):
            name = "deep"
            max_depth = 5
        ev = bounded.enumerate_paths(self.base, Deep())
        for record in ev.records:
            if record["path"]:
                self.assertTrue(record["path"].startswith(self.base), record["path"])
        self.assertNotIn("passwd", self.names(ev))

    def test_traversal_symlink_is_not_walked(self):
        os.symlink("../../../../../../etc", self.p("up"))
        class Deep(bounded.Universe):
            name = "deep"
            max_depth = 5
        ev = bounded.enumerate_paths(self.base, Deep())
        self.assertNotIn("shadow", self.names(ev))

    def test_symlink_loop_terminates(self):
        os.mkdir(self.p("d"))
        os.symlink(self.p("d"), self.p("d", "self"))
        class Deep(bounded.Universe):
            name = "deep"
            max_depth = 8
        ev = bounded.enumerate_paths(self.base, Deep())
        self.assertIn(ev.status, (result.COLLECTED, result.PARTIAL))
        self.assertLessEqual(len(ev.records), ev.provenance["max_entries"])

    def test_skipping_a_symlink_does_not_make_the_answer_incomplete(self):
        os.symlink("/etc", self.p("escape"))
        ev = bounded.enumerate_paths(self.base)
        self.assertEqual(ev.status, result.COLLECTED)


class PartialEvidenceSurvives(Base):

    def test_entries_collected_before_a_failure_are_retained(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores the permission bits this test depends on")
        for i in range(5):
            self.touch("f%d.conf" % i)
        os.mkdir(self.p("locked"))
        self.touch("locked/hidden.conf")
        os.chmod(self.p("locked"), 0)
        self.addCleanup(os.chmod, self.p("locked"), 0o700)
        class Deep(bounded.Universe):
            name = "deep"
            max_depth = 3
        ev = bounded.enumerate_paths(self.base, Deep())
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertEqual(len(ev.records), 5)
        self.assertIn("retained", ev.reason)

    def test_unreadable_subdirectory_is_reported_not_swallowed(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores the permission bits this test depends on")
        os.mkdir(self.p("locked"))
        os.chmod(self.p("locked"), 0)
        self.addCleanup(os.chmod, self.p("locked"), 0o700)
        class Deep(bounded.Universe):
            name = "deep"
            max_depth = 3
        ev = bounded.enumerate_paths(self.base, Deep())
        self.assertIn(bounded.ENTRY_UNREADABLE, self.events(ev))


class NoDomainPolicy(Base):

    def test_no_subprocess_or_network(self):
        tree = ast.parse(inspect.getsource(bounded))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("Popen", "system", "socket", "urlopen", "walk", "realpath"):
            self.assertNotIn(forbidden, names + attrs, forbidden)

    def test_no_security_verdict_vocabulary(self):
        import json
        self.touch("f")
        blob = json.dumps(bounded.enumerate_paths(self.base).records).lower()
        for word in ("secure", "unsafe", "sensitive", "compliant"):
            self.assertNotIn(word, blob)


if __name__ == "__main__":
    unittest.main(verbosity=0)
