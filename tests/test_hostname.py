# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The hostname declared-vs-active contract, asserted before the collector existed.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045
#
# Written from docs/development/NSS_HOSTNAME_LANE_CONTRACT.md §6 and hostname(5). Every
# hostname here is synthetic. The production-root case asserts structure only.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""The hostname declared-vs-active evidence contract."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.hostname import acquire, model, sources            # noqa: E402


def tree(declared=None, active=None):
    """Fixture root with /etc/hostname and /proc/sys/kernel/hostname, either optional."""
    base = tempfile.mkdtemp()
    os.makedirs(os.path.join(base, "etc"))
    os.makedirs(os.path.join(base, "proc", "sys", "kernel"))
    if declared is not None:
        with open(os.path.join(base, "etc", "hostname"), "wb") as fh:
            fh.write(declared if isinstance(declared, bytes) else declared.encode())
    if active is not None:
        with open(os.path.join(base, "proc", "sys", "kernel", "hostname"), "w") as fh:
            fh.write(active)
    return base


class Relation(unittest.TestCase):

    def collect(self, declared, active="web01\n"):
        root = tree(declared, active)
        self.addCleanup(shutil.rmtree, root)
        return acquire.collect(root)

    def test_equal(self):
        r = self.collect("web01\n")
        self.assertEqual(r["relation"], model.EQUAL)
        self.assertEqual(r["declared"]["value"], "web01")
        self.assertEqual(r["active"]["value"], "web01")

    def test_different(self):
        self.assertEqual(self.collect("db02\n")["relation"], model.DIFFERENT)

    def test_short_name_and_fqdn_are_never_equal(self):
        self.assertEqual(self.collect("web01.example.test\n")["relation"], model.DIFFERENT)

    def test_absent_is_not_comparable_and_is_a_fact_not_an_error(self):
        r = self.collect(None)
        self.assertEqual(r["relation"], model.NOT_COMPARABLE)
        self.assertEqual(r["declared"]["state"], model.ABSENT)
        self.assertIn("absent", r["relation_reason"])
        self.assertNotEqual(r["declared"]["status"], model.ERROR)

    def test_empty_is_not_comparable(self):
        r = self.collect("")
        self.assertEqual(r["declared"]["state"], model.EMPTY)
        self.assertEqual(r["relation"], model.NOT_COMPARABLE)

    def test_two_lines_is_malformed_and_partial(self):
        r = self.collect("web01\nweb02\n")
        self.assertEqual(r["declared"]["state"], model.MALFORMED)
        self.assertEqual(r["declared"]["status"], model.PARTIAL)
        self.assertEqual(r["relation"], model.NOT_COMPARABLE)

    def test_comments_are_skipped(self):
        self.assertEqual(self.collect("# set by installer\nweb01\n")["relation"], model.EQUAL)

    def test_one_trailing_newline_is_stripped_and_recorded(self):
        r = self.collect("web01\n")
        self.assertTrue(r["declared"]["trailing_newline"])
        r = self.collect("web01")
        self.assertFalse(r["declared"]["trailing_newline"])
        self.assertEqual(r["relation"], model.EQUAL)

    def test_other_whitespace_is_retained_as_an_anomaly(self):
        r = self.collect("web01 \n")
        self.assertEqual(r["declared"]["value"], "web01 ")
        self.assertTrue(r["declared"]["anomalies"])
        self.assertEqual(r["relation"], model.NOT_COMPARABLE)

    def test_a_template_is_not_compared(self):
        # hostname(5): "?" is replaced from machine-id(5) when applied. Not emulated.
        r = self.collect("web-????\n", active="web-92a9\n")
        self.assertEqual(r["relation"], model.NOT_COMPARABLE)
        self.assertIn("template", r["relation_reason"])

    def test_characters_filtered_on_apply_are_not_compared(self):
        # hostname(5): invalid characters are filtered when applied. Not emulated, and an
        # upper-case letter is one of them.
        r = self.collect("Web01\n")
        self.assertEqual(r["relation"], model.NOT_COMPARABLE)
        self.assertIn("filter", r["relation_reason"])

    def test_undecodable_bytes_are_malformed_never_replaced(self):
        r = self.collect(b"web\xff01\n")
        self.assertEqual(r["declared"]["state"], model.MALFORMED)
        self.assertNotIn("�", str(r["declared"]["value"]))

    def test_active_unreadable_is_not_comparable(self):
        root = tree("web01\n", None)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertEqual(r["relation"], model.NOT_COMPARABLE)
        self.assertNotEqual(r["active"]["status"], model.COLLECTED)

    def test_a_fixture_root_never_falls_through_to_the_live_host(self):
        # Mounts ruling E: an absent fixture file is absent, not this machine's hostname.
        root = tree(None, None)
        self.addCleanup(shutil.rmtree, root)
        r = acquire.collect(root)
        self.assertIsNone(r["active"]["value"])
        self.assertIsNone(r["declared"]["value"])


class RedTeamRegressions(unittest.TestCase):
    """Findings of the independent adversarial pass, each written before its fix."""

    def test_f7_an_unreadable_declared_file_never_crashes(self):
        root = tree(None, "web01\n")
        self.addCleanup(shutil.rmtree, root)
        os.mkdir(os.path.join(root, "etc", "hostname"))          # a directory, not a file
        r = acquire.collect(root)
        self.assertEqual(r["relation"], model.NOT_COMPARABLE)
        self.assertNotEqual(r["declared"]["status"], model.COLLECTED)

    def test_f8_an_undecodable_active_name_is_serializable_and_not_compared(self):
        root = tree("web01\n", None)
        self.addCleanup(shutil.rmtree, root)
        with open(os.path.join(root, "proc", "sys", "kernel", "hostname"), "wb") as fh:
            fh.write(b"web\xff01\n")
        from isedraf import canonical
        r = acquire.collect(root)
        self.assertTrue(canonical.canonical_bytes({k: v for k, v in r.items()
                                                   if k != "coverage"}))
        self.assertEqual(r["relation"], model.NOT_COMPARABLE)

    def test_f9_a_symlink_never_escapes_a_fixture_root(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside)
        with open(os.path.join(outside, "hostname"), "w") as fh:
            fh.write("live-host\n")
        root = tree(None, "web01\n")
        self.addCleanup(shutil.rmtree, root)
        os.symlink(os.path.join(outside, "hostname"), os.path.join(root, "etc", "hostname"))
        r = acquire.collect(root)
        self.assertIsNone(r["declared"]["value"])
        self.assertIn("SOURCE_OUTSIDE_COLLECTION_ROOT", r["declared"]["reason"])

    def test_f10_a_name_longer_than_the_kernel_limit_is_not_compared(self):
        # hostname(5): up to 64 characters; the kernel limits the name to 64.
        root = tree("a" * 70 + "\n", "a" * 64 + "\n")
        self.addCleanup(shutil.rmtree, root)
        self.assertEqual(acquire.collect(root)["relation"], model.NOT_COMPARABLE)

    def test_f10_a_name_that_is_not_a_valid_dns_name_is_not_compared(self):
        # hostname(5): a name not forming a valid DNS domain name is cleaned when applied.
        for declared in ("foo.", ".foo", "-foo", "foo-", "foo..bar"):
            root = tree(declared + "\n", "foo\n")
            self.addCleanup(shutil.rmtree, root)
            self.assertEqual(acquire.collect(root)["relation"], model.NOT_COMPARABLE,
                             declared)

    def test_low_an_indented_hash_is_not_a_comment(self):
        # hostname(5): "lines starting with a #".
        root = tree(" #c\nweb01\n", "web01\n")
        self.addCleanup(shutil.rmtree, root)
        self.assertEqual(acquire.collect(root)["declared"]["state"], model.MALFORMED)


class RedTeamPass2(unittest.TestCase):
    """Pass-2 findings on hostname, each written before its fix."""

    def test_p2_11_a_multi_line_file_keeps_its_lines(self):
        root = tree("foo\nbar\n", "foo\n")
        self.addCleanup(shutil.rmtree, root)
        d = acquire.collect(root)["declared"]
        self.assertEqual(d["state"], model.MALFORMED)
        self.assertEqual(d["lines"], ["foo", "bar"])

    def test_p2_11_an_undecodable_declared_name_keeps_its_bytes(self):
        root = tree(b"fo\xe9\n", "foo\n")
        self.addCleanup(shutil.rmtree, root)
        d = acquire.collect(root)["declared"]
        self.assertEqual(d["value_bytes_hex"], "666fe9")

    def test_p2_11_an_undecodable_active_name_fully_kept_is_collected(self):
        root = tree("foo\n", None)
        self.addCleanup(shutil.rmtree, root)
        with open(os.path.join(root, "proc", "sys", "kernel", "hostname"), "wb") as fh:
            fh.write(b"fo\xe9\n")
        a = acquire.collect(root)["active"]
        self.assertEqual(a["status"], model.COLLECTED)
        self.assertEqual(a["value_bytes_hex"], "666fe9")

    def test_p2_13_a_fifo_is_refused_not_read(self):
        root = tree(None, "web01\n")
        self.addCleanup(shutil.rmtree, root)
        os.mkfifo(os.path.join(root, "etc", "hostname"))
        d = acquire.collect(root)["declared"]
        self.assertNotEqual(d["status"], model.COLLECTED)
        self.assertIn("not a regular file", d["reason"])


class RedTeamPass3(unittest.TestCase):

    def test_p3_f10_a_declared_file_that_is_the_active_interface_is_not_compared(self):
        root = tree(None, "web01\n")
        self.addCleanup(shutil.rmtree, root)
        os.symlink("../proc/sys/kernel/hostname", os.path.join(root, "etc", "hostname"))
        r = acquire.collect(root)
        self.assertEqual(r["relation"], model.NOT_COMPARABLE)
        self.assertIn("same file", r["relation_reason"])


class Classification(unittest.TestCase):

    def test_every_category_is_one_of_the_frozen_four(self):
        allowed = {model.STATE, model.OBSERVATION, model.DERIVED, model.PROVENANCE}
        for field, cls in model.CLASSIFICATION.items():
            self.assertIn(cls, allowed, field)

    def test_the_relation_is_derived_not_state(self):
        self.assertEqual(model.CLASSIFICATION["relation"], model.DERIVED)

    def test_both_names_are_state(self):
        self.assertEqual(model.CLASSIFICATION["declared.value"], model.STATE)
        self.assertEqual(model.CLASSIFICATION["active.value"], model.STATE)


class ParserIsPure(unittest.TestCase):

    def test_parse_needs_no_filesystem(self):
        p = sources.parse_hostname_file("web01\n")
        self.assertEqual(p["value"], "web01")
        self.assertEqual(p["state"], model.PRESENT)


class ProductionRoot(unittest.TestCase):
    """Ruling F, structurally. Nothing is asserted about this host's name."""

    def test_collect_at_root_reads_the_real_paths(self):
        r = acquire.collect("/")
        self.assertEqual(r["declared"]["source"], "/etc/hostname")
        self.assertEqual(r["active"]["source"], "/proc/sys/kernel/hostname")
        self.assertIn(r["relation"], (model.EQUAL, model.DIFFERENT, model.NOT_COMPARABLE))


if __name__ == "__main__":
    unittest.main(verbosity=0)
