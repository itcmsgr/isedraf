# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: `isedraf audit` - every built collector once, one committed run, a report
#          rendered from that run and nothing else.
# Implements: SCOPE-022, SCOPE-077, SNAP-014, SNAP-020
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================
"""GA track: the unified audit command and the committed-evidence report."""
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import audit, cli, exitcodes, snapshot, verify               # noqa: E402

MACHINE_ID = "3f9a1c0b7d2e4a68b5c6d7e8f9a0b1c2\n"
FILES = {
    "etc/machine-id": MACHINE_ID,
    "etc/passwd": "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n",
    "etc/group": "root:x:0:\nalice:x:1000:\n",
    "etc/shadow": "root:*:19000:0:99999:7:::\nalice:!:19000::::::\n",
    "etc/nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\n",
    "etc/hostname": "fixturehost\n",
    "proc/sys/kernel/hostname": "fixturehost\n",
}


class MethodIdentity(unittest.TestCase):
    """IQ-042 (1), CMP-020: every section names the collector that produced it, as
    structured method identity, so a collector change is never read as host drift."""

    def setUp(self):
        self.host = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.host)
        for rel, text in FILES.items():
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)

    def test_the_method_table_covers_exactly_the_sections(self):
        self.assertEqual(sorted(audit.METHODS), sorted(audit.SECTIONS))

    def test_every_section_carries_structured_method_identity(self):
        sections, _status = audit.collect(self.host)
        for name, section in sections.items():
            self.assertEqual(section["schema_version"], 2)
            method = section["method"]
            self.assertEqual(sorted(method),
                             ["collector_id", "collector_version", "parser_version"], name)
            self.assertEqual(method["collector_id"], "isedraf." + name)
            for value in method.values():
                self.assertTrue(isinstance(value, str) and value, (name, method))

    def test_method_identity_is_stable(self):
        first, _ = audit.collect(self.host)
        second, _ = audit.collect(self.host)
        self.assertEqual({n: s["method"] for n, s in first.items()},
                         {n: s["method"] for n, s in second.items()})

    def test_a_crashed_collector_still_names_itself(self):
        def boom(*a, **k):
            raise RuntimeError("SECRET-DETAIL")
        with mock.patch.dict(audit.COLLECTORS, {"sudo": boom}):
            sections, _status = audit.collect(self.host)
        self.assertEqual(sections["sudo"]["collection_status"], "ERROR")
        self.assertEqual(sections["sudo"]["method"]["collector_id"], "isedraf.sudo")


class Audit(unittest.TestCase):

    def setUp(self):
        self.host = tempfile.mkdtemp()
        self.state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.host)
        self.addCleanup(shutil.rmtree, self.state)
        for rel, text in FILES.items():
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        env = {"ISEDRAF_STATE_ROOT": os.path.join(self.state, "root")}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            try:
                code = cli.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def audit(self):
        return self.run_cli(["audit", "--root", self.host])

    def snapshot_dir(self):
        snaps = os.path.join(self.state, "root", "snapshots")
        names = sorted(os.listdir(snaps))
        self.assertEqual(len(names), 1)
        return os.path.join(snaps, names[0])

    def test_every_section_is_collected_once_and_committed(self):
        calls = {}
        real = dict(audit.COLLECTORS)

        def counting(name):
            def wrapper(*a, **k):
                calls[name] = calls.get(name, 0) + 1
                return real[name](*a, **k)
            return wrapper
        with mock.patch.dict(audit.COLLECTORS, {n: counting(n) for n in real}):
            code, _out, err = self.audit()
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)
        self.assertEqual(calls, {n: 1 for n in audit.SECTIONS})
        snap = self.snapshot_dir()
        for name in audit.SECTIONS:
            self.assertTrue(os.path.exists(os.path.join(snap, "sections", name + ".json")), name)
        self.assertEqual(verify.verify_store(os.path.join(self.state, "root")), [])

    def test_sections_are_bound_and_tampering_is_detected(self):
        self.audit()
        snap = self.snapshot_dir()
        with open(os.path.join(snap, "manifest.json")) as fh:
            core = json.load(fh)["manifest_core"]
        for name in audit.SECTIONS:
            self.assertIn("sections/%s.json" % name, core["auxiliary_artifacts"])
        # Host-state identity is unchanged by sections: they are outside state_hash.
        self.assertEqual(list(core["sections"]), [snapshot.SECTION])
        path = os.path.join(snap, "sections", "inventory.json")
        os.chmod(path, 0o600)
        with open(path, "ab") as fh:
            fh.write(b" ")
        self.assertTrue(any("sections/inventory.json" in p
                            for p in verify.verify_store(os.path.join(self.state, "root"))))

    def test_a_collector_crash_is_an_error_section_not_a_crash(self):
        def boom(*a, **k):
            raise RuntimeError("SECRET-DETAIL")
        with mock.patch.dict(audit.COLLECTORS, {"sudo": boom}):
            code, _out, err = self.audit()
        self.assertEqual(code, exitcodes.INCOMPLETE, err)
        with open(os.path.join(self.snapshot_dir(), "sections", "sudo.json")) as fh:
            section = json.load(fh)
        self.assertEqual(section["collection_status"], "ERROR")
        self.assertNotIn("SECRET-DETAIL", json.dumps(section))

    def test_accounts_receive_the_nss_context_explicitly(self):
        self.audit()
        with open(os.path.join(self.snapshot_dir(), "sections", "accounts.json")) as fh:
            accounts = json.load(fh)["evidence"]
        self.assertEqual(accounts["nss_file_effectiveness"]["etc/passwd"]["files_effective"],
                         "ACTIVE")
        self.assertEqual(accounts["nss_compat_context"]["etc/passwd"], "NOT_COMPAT")

    def test_the_report_renders_the_committed_run_and_never_collects(self):
        self.audit()
        with mock.patch.dict(audit.COLLECTORS, {n: None for n in audit.SECTIONS}), \
                mock.patch("isedraf.inventory.collect", side_effect=AssertionError("collected")):
            code, out, err = self.run_cli(["report", "--json"])
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)
        model = json.loads(out)
        self.assertEqual(model["target"]["hostname"], "fixturehost")
        self.assertEqual(sorted(model["audit_sections"]), sorted(audit.SECTIONS))

    def test_an_orphaned_snapshot_is_never_reported_as_the_run(self):
        # D-50: a snapshot renamed into place whose ledger append never happened is not
        # committed; the report must describe the last LEDGERED run.
        self.audit()
        snaps = os.path.join(self.state, "root", "snapshots")
        committed = sorted(os.listdir(snaps))[0]
        orphan = os.path.join(snaps, "SDS-29991231T235959Z-0000000000000000")
        shutil.copytree(os.path.join(snaps, committed), orphan)
        code, out, _err = self.run_cli(["report", "--json"])
        self.assertEqual(json.loads(out)["identity_evidence"]["snapshot_id"], committed)

    def test_a_partial_run_is_never_reported_complete(self):
        # Inventory fully COLLECTED, one audited section NOT_TESTED: the report status
        # followed inventory alone and said COMPLETE (GA smoke test, 2026-09-27).
        from isedraf import report
        self.audit()
        root = os.path.join(self.state, "root")
        committed = report.committed_run(root)
        sections = dict(committed["sections"])
        sections["sudo"] = dict(sections["sudo"], collection_status="NOT_TESTED",
                                reason="SOURCE_UNREADABLE: test")
        complete = [{"subdomain": "host", "collection_status": "COLLECTED",
                     "method": "test", "reason": None}]
        with mock.patch("isedraf.report.model._collection_summary", return_value=complete):
            model = report.build(root, committed["sections"]["inventory"]["evidence"],
                                 audit_sections=sections)
            self.assertEqual(model["report"]["status"], "PARTIAL")
            everything = {n: dict(s, collection_status="COLLECTED", reason=None)
                          for n, s in sections.items()}
            model = report.build(root, committed["sections"]["inventory"]["evidence"],
                                 audit_sections=everything)
            self.assertEqual(model["report"]["status"], "COMPLETE")

    def test_the_default_report_lists_every_area_in_plain_words(self):
        # The default (Markdown) report omitted nine of the ten areas and showed internal
        # labels (public docs review, 2026-09-28).
        from isedraf.report import sections as titles
        self.audit()
        code, out, err = self.run_cli(["report"])
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)
        self.assertIn("## Audit sections", out)
        for name in audit.SECTIONS:
            self.assertIn(titles.TITLES[name], out)
        for label in ("W1-A", "W1-C", "SNAP-0", "D-114"):
            self.assertNotIn(label, out)

    def test_report_without_a_committed_audit_run_refuses(self):
        code, _out, err = self.run_cli(["report"])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertIn("isedraf audit", err)


if __name__ == "__main__":
    unittest.main(verbosity=0)
