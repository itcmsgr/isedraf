# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The SBOM generator never writes outside its extraction directory.
# Implements: D-86, D-90
#
# Regression for IQ-071 (CodeQL py/tarslip on scripts/ci/generate_sbom.py): `unpack` called
# tarfile.extractall on the deb data member and the source tarball without checking member
# paths. Every crafted archive here is refused before anything is written.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""IQ-071: archive member paths are checked before extraction."""
import importlib.util
import io
import os
import pathlib
import shutil
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "generate_sbom", str(ROOT / "scripts" / "ci" / "generate_sbom.py"))
sbom = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sbom)


class SafeUnpack(unittest.TestCase):

    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.base), True)
        self.dest = self.base / "work"
        self.dest.mkdir()

    def archive(self, *members):
        """A .tar.gz built in memory from (TarInfo fields, data) pairs."""
        path = self.base / "fixture.tar.gz"
        with tarfile.open(str(path), "w:gz") as tf:
            for name, kind, data, link in members:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = link or ""
                info.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
                payload = data or b""
                info.size = len(payload) if kind == tarfile.REGTYPE else 0
                tf.addfile(info, io.BytesIO(payload) if kind == tarfile.REGTYPE else None)
        return path

    def written_outside(self):
        return sorted(str(p.relative_to(self.base)) for p in self.base.rglob("*")
                      if not str(p.relative_to(self.base)).startswith(("work", "fixture")))

    def assert_refused(self, *members):
        path = self.archive(*members)
        with self.assertRaises(sbom.UnsafeArchive):
            sbom.unpack(path, self.dest)
        self.assertEqual(self.written_outside(), [])
        payload = self.dest / "payload"
        self.assertFalse(payload.exists() and any(payload.rglob("*")),
                         "something was extracted before the refusal")

    def test_a_normal_payload_is_extracted(self):
        path = self.archive(("./", tarfile.DIRTYPE, None, None),
                            ("./usr/bin/isedraf", tarfile.REGTYPE, b"#!/bin/sh\n", None))
        kind, root = sbom.unpack(path, self.dest)
        self.assertEqual(kind, "tarball")
        self.assertEqual((root / "usr" / "bin" / "isedraf").read_bytes(), b"#!/bin/sh\n")

    def test_a_parent_traversal_is_refused(self):
        self.assert_refused(("../escaped", tarfile.REGTYPE, b"x", None))

    def test_a_traversal_inside_the_path_is_refused(self):
        self.assert_refused(("usr/../../escaped", tarfile.REGTYPE, b"x", None))

    def test_an_absolute_path_is_refused(self):
        self.assert_refused((str(self.base / "escaped"), tarfile.REGTYPE, b"x", None))

    def test_a_symlink_is_refused(self):
        self.assert_refused(("usr/link", tarfile.SYMTYPE, None, "/etc"),
                            ("usr/link/escaped", tarfile.REGTYPE, b"x", None))

    def test_a_hard_link_is_refused(self):
        self.assert_refused(("usr/hard", tarfile.LNKTYPE, None, "/etc/passwd"))

    def test_a_fifo_is_refused(self):
        self.assert_refused(("usr/fifo", tarfile.FIFOTYPE, None, None))

    def test_the_refusal_comes_before_any_write(self):
        # A benign member first, the escape last: nothing at all is extracted.
        self.assert_refused(("usr/ok", tarfile.REGTYPE, b"ok", None),
                            ("../escaped", tarfile.REGTYPE, b"x", None))

    def test_cpio_member_names_follow_the_same_rule(self):
        for good in ("./usr/bin/isedraf", "usr/lib/isedraf/cli.py", ".", "./"):
            self.assertEqual(sbom.check_member_name(good), good)
        for bad in ("../x", "/etc/passwd", "./usr/../../x", ".."):
            with self.assertRaises(sbom.UnsafeArchive):
                sbom.check_member_name(bad)


if __name__ == "__main__":
    unittest.main(verbosity=0)
