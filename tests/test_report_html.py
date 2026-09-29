# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Report 0.1 - a static, escaped HTML rendering of one committed audit run.
# Implements: OUT-013, D-117
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================
"""GA track: the first human report."""
import io
import os
import pathlib
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import audit, cli, exitcodes                               # noqa: E402

HOSTILE = "<script>alert(1)</script>&x"


class HtmlReport(unittest.TestCase):

    def setUp(self):
        self.host = tempfile.mkdtemp()
        self.state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.host)
        self.addCleanup(shutil.rmtree, self.state)
        for rel, text in (("etc/machine-id", "3f9a1c0b7d2e4a68b5c6d7e8f9a0b1c2\n"),
                          ("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n"
                                         "alice:x:1000:1000:<b>Alice</b>:/home/alice:/bin/sh\n"),
                          ("etc/group", "root:x:0:\n"),
                          ("etc/nsswitch.conf", "passwd: files\ngroup: files\nshadow: files\n"),
                          ("proc/sys/kernel/hostname", HOSTILE + "\n")):
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        patcher = mock.patch.dict(os.environ,
                                  {"ISEDRAF_STATE_ROOT": os.path.join(self.state, "r")})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def html(self, broken=None):
        with mock.patch.dict(audit.COLLECTORS, broken or {}):
            self.run_cli(["audit", "--root", self.host])
        with mock.patch("isedraf.inventory.collect", side_effect=AssertionError("collected")):
            code, out, err = self.run_cli(["report", "--html"])
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)
        return out

    def test_the_banner_states_the_evidence_boundary(self):
        page = self.html()
        self.assertIn("PRIVILEGE LEVEL: UNPRIVILEGED", page)
        self.assertIn("OVERALL EVIDENCE: PARTIAL", page)
        self.assertIn("does not mean those controls passed", page)

    def test_every_section_is_present_with_its_status_and_evidence_reference(self):
        page = self.html()
        for name in audit.SECTIONS:
            self.assertIn('id="section-%s"' % name, page)
            self.assertIn("sections/%s.json" % name, page)
        self.assertRegex(page, r"sha256:[0-9a-f]{64}")

    def test_host_values_are_escaped(self):
        page = self.html()
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;&amp;x", page)
        self.assertNotIn("<b>Alice</b>", page)

    def test_the_page_is_static_and_self_contained(self):
        page = self.html()
        self.assertNotIn("<script", page.lower())
        self.assertIsNone(re.search(r"(src|href)\s*=\s*[\"']?(https?:|//)", page))
        self.assertNotIn("@import", page)

    def test_an_error_section_renders_its_reason(self):
        def boom(*a, **k):
            raise RuntimeError("detail")
        page = self.html(broken={"pam": boom})
        section = page[page.index('id="section-pam"'):]
        self.assertIn("ERROR", section[:2000])
        self.assertIn("COLLECTOR_ERROR", section[:2000])


if __name__ == "__main__":
    unittest.main(verbosity=0)
