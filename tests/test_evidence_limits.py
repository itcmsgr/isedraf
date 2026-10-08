# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: `isedraf audit` writes the Evidence Limits Manifest, schema 2, and it moves
#          manifest_hash and never state_hash.
# Implements: D-122, D-115, CMP-020, SCOPE-022
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3,git"
# =============================================================================

"""IQ-042 (2): the writer, validated by the D-122 gate's own rules."""
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
sys.path.insert(0, str(ROOT / "scripts" / "ci"))

from isedraf import audit, canonical, cli, identity, snapshot, verify   # noqa: E402
import check_evidence_limits_schema as gate                            # noqa: E402

FILES = {
    "etc/machine-id": "3f9a1c0b7d2e4a68b5c6d7e8f9a0b1c2\n",
    "etc/passwd": "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n",
    "etc/group": "root:x:0:\nalice:x:1000:\n",
    "etc/shadow": "root:*:19000:0:99999:7:::\nalice:!:19000::::::\n",
    "etc/nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\n",
    "etc/hostname": "fixturehost\n",
    "proc/sys/kernel/hostname": "fixturehost\n",
}


class Host(unittest.TestCase):

    def setUp(self):
        self.host = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.host, True)
        for rel, text in FILES.items():
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)

    def deny(self, rel):
        path = os.path.join(self.host, rel)
        os.chmod(path, 0)
        # LIFO: registered after the enclosure rmtree, so it runs BEFORE it.
        self.addCleanup(os.chmod, path, 0o644)

    def limits(self):
        sections, _status = audit.collect(self.host)
        return sections, audit.evidence_limits(sections, self.host)

    def conforms(self, manifest):
        errors = gate.validate(canonical.canonical_bytes(manifest), gate.vocabulary())
        self.assertEqual(errors, [])

    def sources(self, manifest, section):
        return [s for s in manifest["sources"] if s["domain"] == section]


class TheWriterEmitsSchema2(Host):

    def test_the_manifest_conforms_to_schema_2(self):
        _sections, manifest = self.limits()
        self.assertEqual(manifest["schema_version"], 2)
        self.conforms(manifest)

    def test_every_requested_section_is_reported_or_unreported(self):
        _sections, manifest = self.limits()
        self.assertEqual(manifest["requested_sections"], sorted(audit.SECTIONS))
        reported = set(s["domain"] for s in manifest["sources"])
        unreported = set(u["section"] for u in manifest["unreported_sections"])
        self.assertEqual(reported | unreported, set(audit.SECTIONS))
        self.assertEqual(reported & unreported, set())

    def test_a_collected_source_is_complete_and_carries_its_collector(self):
        sections, manifest = self.limits()
        passwd = [s for s in self.sources(manifest, "accounts")
                  if s["source"] == "etc/passwd"][0]
        self.assertEqual(passwd["status"], "COLLECTED")
        self.assertIsNone(passwd["reason"])
        self.assertEqual(passwd["collector"], sections["accounts"]["method"])
        self.assertEqual(passwd["acquisition_mode"], "CURRENT_IDENTITY")
        self.assertIsNone(passwd["operation_id"])

    def test_sources_are_collection_root_relative(self):
        _sections, manifest = self.limits()
        for s in manifest["sources"]:
            self.assertFalse(s["source"].startswith(self.host), s["source"])

    def test_a_not_tested_section_is_a_limitation(self):
        # No /etc/sudoers in the fixture: the sudo section is NOT_TESTED.
        sections, manifest = self.limits()
        self.assertEqual(sections["sudo"]["collection_status"], "NOT_TESTED")
        sudo = self.sources(manifest, "sudo")
        self.assertTrue(sudo)
        self.assertTrue(all(s in manifest["limitations"] for s in sudo))

    def test_a_crashed_collector_is_an_explicit_unreported_section(self):
        def boom(*a, **k):
            raise RuntimeError("SECRET-DETAIL")
        with mock.patch.dict(audit.COLLECTORS, {"pam": boom}):
            sections, manifest = self.limits()
        self.assertEqual(sections["pam"]["collection_status"], "ERROR")
        unreported = dict((u["section"], u["reason"])
                          for u in manifest["unreported_sections"])
        self.assertIn("pam", unreported)
        self.assertTrue(unreported["pam"].startswith("COLLECTOR_ERROR:"))
        self.assertNotIn("SECRET-DETAIL", json.dumps(manifest))
        self.conforms(manifest)

    def test_the_writer_is_deterministic(self):
        _s1, first = self.limits()
        _s2, second = self.limits()
        self.assertEqual(canonical.canonical_bytes(first), canonical.canonical_bytes(second))

    def test_no_evaluation_vocabulary_appears(self):
        _sections, manifest = self.limits()
        blob = json.dumps(manifest)
        for word in ('"PASS"', '"FAIL"', '"MANUAL_REVIEW"', '"NOT_EVALUATED"', "severity"):
            self.assertNotIn(word, blob)


@unittest.skipIf(os.geteuid() == 0, "root bypasses the permission bits these cases need")
class LimitationsAreNeverSilent(Host):

    def test_a_partial_section_emits_its_limitation(self):
        self.deny("etc/shadow")
        sections, manifest = self.limits()
        self.assertEqual(sections["accounts"]["collection_status"], "PARTIAL")
        shadow = [s for s in self.sources(manifest, "accounts")
                  if s["source"] == "etc/shadow"][0]
        self.assertIn(shadow, manifest["limitations"])
        self.assertEqual(shadow["access_outcome"], "PERMISSION_DENIED")
        self.assertTrue(shadow["privilege_limited"])
        self.assertTrue(shadow["reason"].split(":")[0].isupper())
        self.conforms(manifest)

    def test_several_limitations_in_one_section(self):
        self.deny("etc/shadow")
        self.deny("etc/group")
        _sections, manifest = self.limits()
        limited = [s["source"] for s in manifest["limitations"] if s["domain"] == "accounts"]
        self.assertIn("etc/shadow", limited)
        self.assertIn("etc/group", limited)
        self.conforms(manifest)


class HashesAndCommit(Host):

    def built(self, coverage):
        sections, _status = audit.collect(self.host)
        ident = identity.collect(os.path.join(self.host, "etc/machine-id"))
        manifest = audit.evidence_limits(sections, self.host) if coverage else None
        return snapshot.build(ident, "SDS-20261007T000000Z-" + "a" * 16,
                              "RUN-20261007T000000Z-" + "b" * 16, "2026-10-07T00:00:00Z",
                              "DEV", "0.0.0", coverage_manifest=manifest,
                              sections=sections)

    def test_state_hash_does_not_move_and_manifest_hash_does(self):
        without, with_limits = self.built(False), self.built(True)
        state = lambda built: built["manifest_core"]["sections"][snapshot.SECTION]["state_hash"]
        self.assertIsNotNone(state(without))
        self.assertEqual(state(without), state(with_limits))
        self.assertEqual(without["state"], with_limits["state"])
        self.assertNotEqual(without["manifest_hash"], with_limits["manifest_hash"])
        self.assertIn("coverage/evidence_limits.json",
                      with_limits["manifest_core"]["auxiliary_artifacts"])

    def test_isedraf_audit_commits_and_verifies_the_manifest(self):
        state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, state, True)
        with mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": os.path.join(state, "r")}):
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
                cli.main(["audit", "--root", self.host])
            snaps = os.path.join(state, "r", "snapshots")
            snap = os.path.join(snaps, sorted(os.listdir(snaps))[0])
            path = os.path.join(snap, "coverage", "evidence_limits.json")
            with open(path, "rb") as fh:
                raw = fh.read()
            self.assertEqual(gate.validate(raw, gate.vocabulary()), [])
            self.assertEqual(verify.verify_store(os.path.join(state, "r")), [], err.getvalue())



class ReportShowsLimits(Host):
    """IQ-042 (3): the report renders evidence limits as assurance limitations - section,
    source, status, reason and impact - never as findings, severities or verdicts."""

    def invoke(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            try:
                cli.main(argv)
            except SystemExit:
                pass
        return out.getvalue()

    def audited(self, patches=None):
        state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, state, True)
        env = mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": os.path.join(state, "r")})
        env.start()
        self.addCleanup(env.stop)
        if patches:
            with patches:
                self.invoke(["audit", "--root", self.host])
        else:
            self.invoke(["audit", "--root", self.host])

    def report_json(self):
        return json.loads(self.invoke(["report", "--json"]))

    def test_a_crashed_section_is_shown_as_unreported(self):
        def boom(*a, **k):
            raise RuntimeError("SECRET-DETAIL")
        self.audited(mock.patch.dict(audit.COLLECTORS, {"pam": boom}))
        items = self.report_json()["evidence_limitations"]["items"]
        pam = [i for i in items if i["section"] == "pam"]
        self.assertEqual(len(pam), 1)
        self.assertEqual(pam[0]["status"], "NOT_REPORTED")
        self.assertIsNone(pam[0]["source"])

    def test_no_limitation_is_dressed_as_a_finding(self):
        self.audited()
        section = json.dumps(self.report_json()["evidence_limitations"])
        for word in ("severity", '"FAIL"', '"PASS"', "finding", "remediation"):
            self.assertNotIn(word, section)

    def test_a_run_without_the_manifest_says_coverage_is_not_established(self):
        # GA 0.1.x committed runs carry no coverage/evidence_limits.json.
        self.audited(mock.patch.object(audit, "evidence_limits", lambda s, r: None))
        limits = self.report_json()["evidence_limitations"]
        self.assertFalse(limits["recorded"])
        self.assertEqual(limits["items"], [])
        markdown = self.invoke(["report"])
        self.assertIn("## Evidence limitations", markdown)
        self.assertIn("not established", markdown)


@unittest.skipIf(os.geteuid() == 0, "root bypasses the permission bits these cases need")
class ReportShowsRefusals(ReportShowsLimits):

    def test_a_refused_source_is_listed_with_its_impact(self):
        self.deny("etc/shadow")
        self.audited()
        limits = self.report_json()["evidence_limitations"]
        self.assertTrue(limits["recorded"])
        shadow = [i for i in limits["items"]
                  if i["section"] == "accounts" and i["source"] == "etc/shadow"]
        self.assertEqual(len(shadow), 1)
        self.assertEqual(shadow[0]["status"], "NOT_TESTED")
        self.assertTrue(shadow[0]["reason"])
        self.assertTrue(any("access" in line for line in shadow[0]["impact"]))
        self.assertTrue(any("cannot be established" in line for line in shadow[0]["impact"]))

    def test_markdown_and_html_render_the_limitation(self):
        self.deny("etc/shadow")
        self.audited()
        markdown = self.invoke(["report"])
        self.assertIn("## Evidence limitations", markdown)
        self.assertIn("etc/shadow", markdown)
        page = self.invoke(["report", "--html"])
        self.assertIn("Evidence limitations", page)
        self.assertIn("etc/shadow", page)

if __name__ == "__main__":
    unittest.main()
