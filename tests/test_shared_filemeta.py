# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: S4 — the object at the path, never the object it points to.
# Implements: SCOPE-022, SCOPE-045, GOV-002
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""S4 — targeted file metadata."""
import ast
import inspect
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import filemeta, result                # noqa: E402


class Base(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)

    def path(self, name):
        return os.path.join(self.base, name)

    def write(self, name, text="content\n", mode=None):
        p = self.path(name)
        with open(p, "w") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(p, mode)
        return p

    def only(self, ev):
        return ev.records[0]


class ObjectTypes(Base):

    def test_regular_file(self):
        ev = filemeta.observe(self.write("f"))
        r = self.only(ev)
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual(r["file_type"], filemeta.REGULAR)
        self.assertTrue(r["exists"])
        self.assertFalse(r["is_symlink"])

    def test_directory(self):
        os.mkdir(self.path("d"))
        self.assertEqual(self.only(filemeta.observe(self.path("d")))["file_type"],
                         filemeta.DIRECTORY)

    def test_fifo(self):
        os.mkfifo(self.path("p"))
        self.assertEqual(self.only(filemeta.observe(self.path("p")))["file_type"],
                         filemeta.FIFO)

    def test_socket(self):
        import socket
        s = socket.socket(socket.AF_UNIX)
        self.addCleanup(s.close)
        s.bind(self.path("s"))
        self.assertEqual(self.only(filemeta.observe(self.path("s")))["file_type"],
                         filemeta.SOCKET)

    def test_missing_object_is_not_tested(self):
        ev = filemeta.observe(self.path("absent"))
        self.assertEqual(ev.status, result.NOT_TESTED)
        self.assertIn("SOURCE_ABSENT", ev.reason)
        self.assertFalse(self.only(ev)["exists"])

    def test_unreadable_parent_is_not_tested_not_error(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores the permission bits this test depends on")
        os.mkdir(self.path("locked"))
        self.write("locked/inner")
        os.chmod(self.path("locked"), 0)
        self.addCleanup(os.chmod, self.path("locked"), 0o700)
        ev = filemeta.observe(self.path("locked/inner"))
        self.assertEqual(ev.status, result.NOT_TESTED)
        self.assertIn("permission denied", ev.reason)


class ModeFacts(Base):
    """Raw bits and a rendering, and no opinion about either."""

    def test_permission_bits_and_rendering_agree(self):
        r = self.only(filemeta.observe(self.write("f", mode=0o640)))
        self.assertEqual(r["permission_bits"], 0o640)
        self.assertEqual(r["mode_octal"], "0640")

    def test_setuid_setgid_sticky_are_separate_facts(self):
        p = self.write("f")
        os.chmod(p, 0o4755)
        r = self.only(filemeta.observe(p))
        self.assertTrue(r["setuid"])
        self.assertFalse(r["setgid"])
        self.assertFalse(r["sticky"])
        self.assertEqual(r["permission_bits"], 0o755)

    def test_sticky_directory(self):
        os.mkdir(self.path("d"))
        os.chmod(self.path("d"), 0o1777)
        self.assertTrue(self.only(filemeta.observe(self.path("d")))["sticky"])

    def test_no_security_verdict_anywhere(self):
        blob = json.dumps(filemeta.observe(self.write("f", mode=0o600)).records)
        for word in ("secure", "insecure", "unsafe", "sensitive", "weak", "compliant",
                     "world_readable", "too_permissive"):
            self.assertNotIn(word, blob.lower(), word)


class SymlinksAreNotTheirTargets(Base):
    """The frozen invariant: metadata describes the object AT the path."""

    def test_symlink_reports_itself_not_its_target(self):
        target = self.write("target", mode=0o600)
        link = self.path("link")
        os.symlink(target, link)
        r = self.only(filemeta.observe(link))
        self.assertEqual(r["file_type"], filemeta.SYMLINK)
        self.assertTrue(r["is_symlink"])
        self.assertEqual(r["symlink_target_text"], target)
        # A stat() would have reported the target's 0600. lstat reports the link.
        self.assertNotEqual(r["permission_bits"], 0o600)

    def test_dangling_symlink_still_exists_as_an_object(self):
        os.symlink(self.path("nowhere"), self.path("dangling"))
        ev = filemeta.observe(self.path("dangling"))
        r = self.only(ev)
        # The LINK exists even though its target does not. os.path.exists() would say
        # False here, which is the wrong answer to "what is at this path".
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertTrue(r["exists"])
        self.assertEqual(r["file_type"], filemeta.SYMLINK)

    def test_absolute_target_on_the_live_machine_is_recorded_never_visited(self):
        # The decisive confinement case. /etc/passwd exists on the test machine; the
        # observation must describe the fixture symlink, not that file.
        link = self.path("escape")
        os.symlink("/etc/passwd", link)
        r = self.only(filemeta.observe(link))
        self.assertEqual(r["file_type"], filemeta.SYMLINK)
        self.assertEqual(r["symlink_target_text"], "/etc/passwd")
        live = os.lstat("/etc/passwd")
        self.assertNotEqual(r["inode"], live.st_ino)

    def test_traversal_target_is_a_string_not_a_journey(self):
        os.symlink("../../../../../../etc/shadow", self.path("up"))
        r = self.only(filemeta.observe(self.path("up")))
        self.assertEqual(r["symlink_target_text"], "../../../../../../etc/shadow")
        self.assertEqual(r["file_type"], filemeta.SYMLINK)

    def test_digest_of_a_symlink_does_not_follow_it(self):
        self.write("real", "secret-content\n")
        os.symlink(self.path("real"), self.path("link"))
        ev = filemeta.observe(self.path("link"), digest=True)
        r = self.only(ev)
        # Either not-applicable (it is not a regular file) or unreadable (O_NOFOLLOW
        # refused). Never a digest of the target's bytes.
        self.assertIn(r["digest_status"],
                      (filemeta.DIGEST_NOT_APPLICABLE, filemeta.DIGEST_UNREADABLE))
        self.assertIsNone(r["digest"])

    def test_no_stat_follow_call_exists_in_the_module(self):
        tree = ast.parse(inspect.getsource(filemeta))
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        self.assertIn("lstat", attrs)
        self.assertNotIn("realpath", attrs)
        # os.stat() on a path would follow; os.fstat() on our own fd does not.
        self.assertNotIn("stat", [a for a in attrs if a == "stat"])


class DigestCoherence(Base):
    """Metadata and content are two operations. Never claim they saw one object."""

    def test_digest_only_when_requested(self):
        r = self.only(filemeta.observe(self.write("f")))
        self.assertEqual(r["digest_status"], filemeta.DIGEST_NOT_REQUESTED)
        self.assertIsNone(r["digest"])

    def test_digest_collected_for_a_regular_file(self):
        ev = filemeta.observe(self.write("f", "abc"), digest=True)
        r = self.only(ev)
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual(r["digest_status"], filemeta.DIGEST_COLLECTED)
        self.assertTrue(r["digest"].startswith("sha256:"))

    def test_directory_digest_is_not_applicable_not_an_error(self):
        os.mkdir(self.path("d"))
        ev = filemeta.observe(self.path("d"), digest=True)
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual(self.only(ev)["digest_status"],
                         filemeta.DIGEST_NOT_APPLICABLE)

    def test_metadata_survives_when_content_cannot_be_read(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores the permission bits this test depends on")
        p = self.write("f", mode=0)
        ev = filemeta.observe(p, digest=True)
        r = self.only(ev)
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertEqual(r["digest_status"], filemeta.DIGEST_UNREADABLE)
        # The whole point: the metadata is still there.
        self.assertEqual(r["file_type"], filemeta.REGULAR)
        self.assertEqual(r["permission_bits"], 0)
        self.assertIn("no content digest is claimed", ev.reason)

    def test_object_replaced_between_lstat_and_open_is_refused(self):
        # The path stops naming what was measured. Combining metadata from one inode with
        # content from another and calling it one observation would be a quiet lie.
        decoy = self.write("decoy", "decoy\n")
        real = self.write("real", "real\n")
        original_lstat = filemeta.os.lstat

        def lying_lstat(path):
            # Report the decoy's identity for the real path, simulating a replacement
            # that happened between the two syscalls.
            return original_lstat(decoy) if path == real else original_lstat(path)

        filemeta.os.lstat = lying_lstat
        self.addCleanup(setattr, filemeta.os, "lstat", original_lstat)
        ev = filemeta.observe(real, digest=True)
        r = self.only(ev)
        self.assertEqual(r["digest_status"], filemeta.DIGEST_OBJECT_CHANGED)
        self.assertIsNone(r["digest"])
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn("would not describe one file", r["digest_reason"])

    def test_no_atomicity_is_claimed_in_provenance(self):
        ev = filemeta.observe(self.write("f"), digest=True)
        blob = json.dumps(ev.records).lower()
        for word in ("atomic", "consistent_snapshot", "coherent_guarantee"):
            self.assertNotIn(word, blob)


class NoDomainPolicy(Base):

    def test_module_names_no_domain_and_performs_no_subprocess_or_network(self):
        tree = ast.parse(inspect.getsource(filemeta))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("Popen", "system", "socket", "urlopen", "check_output"):
            self.assertNotIn(forbidden, names + attrs, forbidden)

    def test_every_emitted_field_is_classified(self):
        r = self.only(filemeta.observe(self.write("f"), digest=True))
        for key in r:
            self.assertIn(key, filemeta.CLASSIFICATION, key)

    def test_no_timestamp_is_collected(self):
        # Timestamps look harmless and then become an invented creation date. EVID-020
        # already forbids that inference; not collecting them removes the temptation.
        r = self.only(filemeta.observe(self.write("f"), digest=True))
        for key in r:
            self.assertNotIn("time", key.lower(), key)
            self.assertNotIn("ctime", key.lower(), key)


if __name__ == "__main__":
    unittest.main(verbosity=0)
