# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: W1-C2 report engine tests.
# Implements: SNAP-020, SNAP-021, STORE-001, REC-005, NORM-034, NORM-035
#
# The test that matters most: assessment metadata must not move a single evidence byte.
# The same collection must be renderable as an internal note and as a customer report
# without the evidence differing, or the report is rewriting what it claims to describe.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="temporary directories only"
# meta:binaries="git"
# =============================================================================

"""Model, renderers, evidence binding, and the separation of report from evidence."""
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import canonical, cli, inventory, report, stateroot      # noqa: E402
from isedraf.inventory import model as inventory_model                # noqa: E402
from isedraf.report import artifact, model as report_model, profile, render  # noqa: E402

PROFILE = {
    "prepared_by": "A. Reviewer", "role": "Infrastructure Security Engineer",
    "organization": "ITCMS", "customer": "Example Company S.A.",
    "engagement": "Annual Linux Security Review", "reference": "AUDIT-2026-017",
    "report_title": "Linux Host Assurance Assessment",
}


def synthetic_inventory(**overrides):
    """A complete inventory shaped like the real one, with the awkward cases present."""
    def block(status, data, method="fixture", reason=None):
        return inventory_model.subdomain(status, data, method=method, reason=reason)
    inv = {
        "schema_version": inventory_model.INVENTORY_SCHEMA_VERSION,
        "collection_status": inventory_model.COLLECTED,
        "subdomains": {
            # COLLECTED: a host with no locally resolvable FQDN is normal, not partial.
            "host": block(inventory_model.COLLECTED,
                          {"hostname": "fixture-host", "fqdn": None,
                           "fqdn_source": "NOT_AVAILABLE_LOCALLY"}),
            "platform": block(inventory_model.COLLECTED,
                              {"id": "rocky", "version_id": "9.7",
                               "pretty_name": "Rocky Linux 9.7", "family": "rhel",
                               "kernel_release": "5.14.0", "architecture": "x86_64",
                               "init_system": "systemd"}),
            "machine": block(inventory_model.COLLECTED,
                             {"virtualized": True, "hypervisor": "kvm",
                              "vendor": "QEMU", "product": "Standard PC"}),
            "compute": block(inventory_model.COLLECTED,
                             {"cpu_vendor": "GenuineIntel", "cpu_model": "Xeon",
                              "sockets": 2, "cores_per_socket": 4, "logical_cpus": 16}),
            "memory": block(inventory_model.COLLECTED,
                            {"total_bytes": 34359738368, "swap_total_bytes": 0}),
            "storage": block(inventory_model.COLLECTED, {
                "devices": [{"name": "vda", "size_bytes": 250000000000,
                             "type": inventory_model.DEVICE_VIRTUAL,
                             "removable": False, "model": "QEMU"},
                            {"name": "sr0", "size_bytes": 1073741824,
                             "type": inventory_model.DEVICE_OPTICAL,
                             "removable": True, "model": "QEMU DVD-ROM"}],
                "filesystems": [{"source": "/dev/vda1", "mount_point": "/",
                                 "fstype": "xfs", "options": ["rw", "relatime"],
                                 "read_only": False},
                                {"source": "/dev/vdb1", "mount_point": "/data",
                                 "fstype": "ext4", "options": ["ro"],
                                 "read_only": True}],
                "utilisation": [{"mount_point": "/", "total_bytes": 250000000000,
                                 "available_bytes": 150000000000, "used_permille": 400}],
            }),
            "network": block(inventory_model.COLLECTED, {
                "interfaces": [{"name": "lo", "state": "UNKNOWN", "mtu": 65536,
                                "loopback": True},
                               {"name": "eth0", "state": "UP", "mtu": 1500,
                                "loopback": False}],
                "ipv4": [{"interface": "eth0", "address": "10.0.0.5",
                          "prefix_length": 24, "scope": "global", "loopback": False}],
                "ipv6_stable": [{"interface": "eth0", "address": "2001:db8::5",
                                 "prefix_length": 64, "scope": "global",
                                 "classification": inventory_model.IPV6_GLOBAL_STABLE}],
                "ipv6_volatile": [{"interface": "eth0", "address": "2001:db8::dead",
                                   "prefix_length": 64, "scope": "global",
                                   "classification":
                                       inventory_model.IPV6_TEMPORARY_PRIVACY}],
                "default_routes": [{"family": "inet", "gateway": "10.0.0.1",
                                    "interface": "eth0"}],
            }),
            "dns": block(inventory_model.COLLECTED,
                         {"servers": ["10.0.0.1"], "method": "/etc/resolv.conf",
                          "note": None}),
            "time": block(inventory_model.COLLECTED,
                          {"timezone": "UTC", "provider": "chrony", "ntp_enabled": True,
                           "synchronized": True, "source": "10.0.0.1", "stratum": 3,
                           "offset_nanoseconds": 144339, "uptime_seconds": 1000}),
        },
    }
    for path, value in overrides.items():
        sub, _, field = path.partition(".")
        inv["subdomains"][sub]["data"][field] = value
    return inv


class ReportCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "state")
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        with open(os.path.join(self.src, "machine-id"), "wb") as fh:
            fh.write(b"7f8e9a0b1c2d3e4f5061728394a5b6c7\n")
        self._env = dict(os.environ)
        os.environ["ISEDRAF_STATE_ROOT"] = self.root
        os.environ.pop("SUDO_USER", None)
        self.addCleanup(self._restore)
        args = type("A", (), {"source": os.path.join(self.src, "machine-id")})()
        cli.cmd_identity(args, out=io.StringIO(), err=io.StringIO())

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)

    def build(self, inv=None, assessment=None):
        return report.build(self.root, inv or synthetic_inventory(),
                            assessment=assessment)


class TestEvidenceBinding(ReportCase):
    def test_identity_evidence_is_bound_and_verified(self):
        m = self.build()
        ident = m["identity_evidence"]
        self.assertTrue(ident["available"])
        self.assertTrue(ident["snapshot_id"].startswith("SDS-"))
        self.assertTrue(ident["manifest_hash"].startswith("sha256:"))
        self.assertEqual(ident["ledger_sequence"], 1)
        self.assertTrue(ident["ledger_record_hash"].startswith("sha256:"))
        self.assertTrue(ident["verification"]["verified"])
        self.assertEqual(ident["verification"]["problems"], [])

    def test_inventory_is_bound_separately_and_never_called_a_snapshot(self):
        m = self.build()
        inv = m["inventory"]
        self.assertTrue(inv["collection_id"].startswith("INV-"))
        self.assertTrue(inv["artifact_digest"].startswith("sha256:"))
        self.assertIn("NOT part of the frozen W1-A snapshot", inv["maturity"])
        self.assertNotIn("manifest_hash", inv)
        self.assertNotIn("snapshot_id", inv)

    def test_the_two_maturities_are_different(self):
        m = self.build()
        self.assertNotEqual(m["identity_evidence"]["maturity"], m["inventory"]["maturity"])
        self.assertIn("CERTIFIED", m["identity_evidence"]["maturity"])

    def test_artifact_digest_covers_the_artifact_without_itself(self):
        inv = synthetic_inventory()
        a = artifact.build(inv, collected_at="2026-09-18T00:00:00Z",
                           collection_id="INV-20260918T000000Z-" + "a" * 16)
        self.assertNotIn(b"artifact_digest", a["canonical_bytes"])
        b = artifact.build(inv, collected_at="2026-09-18T00:00:00Z",
                           collection_id="INV-20260918T000000Z-" + "a" * 16)
        self.assertEqual(a["artifact_digest"], b["artifact_digest"])

    def test_artifact_bytes_are_canonical(self):
        a = artifact.build(synthetic_inventory())
        self.assertTrue(a["canonical_bytes"].endswith(b"\n"))
        self.assertEqual(a["canonical_bytes"].count(b"\n"), 1)
        self.assertEqual(canonical.canonical_bytes(a["core"]), a["canonical_bytes"])

    def test_no_report_field_reuses_a_frozen_hash_domain(self):
        text = json.dumps(self.build())
        for domain in ("ISEDRAF:SNAPSHOT-MANIFEST:V1", "ISEDRAF:STATE:V1",
                       "ISEDRAF:LEDGER-RECORD:V1"):
            self.assertNotIn(domain, text)


class TestAssessmentProfile(ReportCase):
    def test_report_without_profile_omits_the_section(self):
        m = self.build()
        self.assertIsNone(m["assessment"])
        self.assertNotIn("## Assessment", render.to_markdown(m))
        self.assertNotIn("Not specified", render.to_markdown(m))

    def test_report_with_profile_renders_it(self):
        text = render.to_markdown(self.build(assessment=PROFILE))
        self.assertIn("## Assessment", text)
        for value in ("A. Reviewer", "ITCMS", "Example Company S.A.", "AUDIT-2026-017"):
            self.assertIn(value, text)

    def test_assessment_metadata_changes_no_evidence(self):
        """The same collection, two audiences, one set of evidence."""
        inv = synthetic_inventory()
        art = artifact.build(inv, collected_at="2026-09-18T00:00:00Z",
                             collection_id="INV-20260918T000000Z-" + "b" * 16)
        plain = report.build(self.root, inv, inventory_artifact=art)
        with_profile = report.build(self.root, inv, assessment=PROFILE,
                                    inventory_artifact=art)
        self.assertEqual(plain["identity_evidence"], with_profile["identity_evidence"])
        self.assertEqual(plain["inventory"]["artifact_digest"],
                         with_profile["inventory"]["artifact_digest"])
        self.assertEqual(plain["target"], with_profile["target"])
        # ... and the report content digest DOES differ, because the report differs.
        self.assertNotEqual(report.content_digest(plain),
                            report.content_digest(with_profile))

    def test_rendering_a_report_does_not_touch_the_evidence_store(self):
        def fingerprint():
            out = {}
            for base, _dirs, files in os.walk(self.root):
                for name in files:
                    path = os.path.join(base, name)
                    with open(path, "rb") as fh:
                        out[path] = fh.read()
            return out
        before = fingerprint()
        m = self.build(assessment=PROFILE)
        render.to_markdown(m)
        render.to_json(m)
        self.assertEqual(before, fingerprint())

    def test_profile_file_loading(self):
        path = os.path.join(self.tmp, "profile.json")
        with open(path, "w") as fh:
            json.dump(PROFILE, fh)
        self.assertEqual(profile.load(path), PROFILE)
        self.assertIsNone(profile.load(None))

    def test_profile_rejects_unknown_fields_rather_than_ignoring_them(self):
        path = os.path.join(self.tmp, "bad.json")
        with open(path, "w") as fh:
            json.dump({"prepared_by": "x", "signature": "forged"}, fh)
        with self.assertRaises(profile.ProfileError):
            profile.load(path)

    def test_empty_values_are_absence_not_blank_labels(self):
        path = os.path.join(self.tmp, "empty.json")
        with open(path, "w") as fh:
            json.dump({"prepared_by": "  ", "organization": None}, fh)
        self.assertIsNone(profile.load(path))

    def test_identity_disclaimer_is_always_present(self):
        text = render.to_markdown(self.build(assessment=PROFILE))
        self.assertIn("NOT cryptographically authenticated", text)
        self.assertIn("not signed", text)


class TestContent(ReportCase):
    def test_no_secure_insecure_verdict_is_invented(self):
        text = render.to_markdown(self.build())
        self.assertEqual(self.build()["report"]["status"], "COMPLETE")
        for forbidden in ("SECURE", "INSECURE", "PASS/FAIL", "compliant"):
            self.assertNotIn(forbidden, text)

    def test_fqdn_absence_is_stated_not_fabricated(self):
        text = render.to_markdown(self.build())
        self.assertIn("not resolvable locally", text)
        self.assertNotIn("fixture-host.", text)

    def test_temporary_ipv6_is_separated_and_explained(self):
        text = render.to_markdown(self.build())
        self.assertIn("TEMPORARY_PRIVACY", text)
        self.assertIn("RFC 4941", text)

    def test_multiple_storage_devices_and_read_only_mount(self):
        text = render.to_markdown(self.build())
        self.assertIn("`vda`", text)
        self.assertIn("`sr0`", text)
        self.assertIn("read-only", text)

    def test_optical_device_is_not_reported_as_solid_state(self):
        text = render.to_markdown(self.build())
        self.assertIn("OPTICAL", text)
        self.assertNotIn("SOLID_STATE", text)

    def test_unsynchronized_clock_raises_rec005(self):
        inv = synthetic_inventory(**{"time.synchronized": False})
        text = render.to_markdown(self.build(inv=inv))
        self.assertIn("CLOCK_UNSYNCHRONIZED", text)
        self.assertIn("REC-005", text)
        self.assertIn("no ordering guarantee", text)

    def test_unknown_sync_state_is_not_reported_as_healthy(self):
        inv = synthetic_inventory(**{"time.synchronized": None})
        m = self.build(inv=inv)
        joined = " ".join(m["limitations"])
        self.assertIn("could not be determined", joined)
        self.assertIn("not a statement that the clock is correct", joined)

    def test_partial_collection_is_visible_and_always_explained(self):
        inv = synthetic_inventory()
        inv["subdomains"]["dns"] = inventory_model.subdomain(
            inventory_model.NOT_TESTED, {"servers": [], "method": None, "note": None},
            method="/etc/resolv.conf", reason="SOURCE_ABSENT: no resolver configuration")
        inv["collection_status"] = inventory_model.PARTIAL
        text = render.to_markdown(self.build(inv=inv))
        self.assertIn("Collection completeness", text)
        self.assertIn("NOT_TESTED", text)
        # The report promises that incomplete observations explain themselves.
        self.assertIn("SOURCE_ABSENT: no resolver configuration", text)

    def test_collection_summary_covers_every_subdomain(self):
        rows = self.build()["collection_summary"]
        self.assertEqual(sorted(r["subdomain"] for r in rows),
                         sorted(inventory_model.SUBDOMAINS))


class TestRenderers(ReportCase):
    def test_json_is_deterministic_for_the_same_model(self):
        m = self.build(assessment=PROFILE)
        self.assertEqual(render.to_json(m), render.to_json(m))
        self.assertEqual(json.loads(render.to_json(m)), m)

    def test_content_digest_excludes_only_what_must_differ(self):
        inv = synthetic_inventory()
        art = artifact.build(inv, collected_at="2026-09-18T00:00:00Z",
                             collection_id="INV-20260918T000000Z-" + "c" * 16)
        a = report.build(self.root, inv, inventory_artifact=art,
                         generated_at="2026-09-18T01:00:00Z", report_id="RPT-A")
        b = report.build(self.root, inv, inventory_artifact=art,
                         generated_at="2026-09-18T02:00:00Z", report_id="RPT-B")
        self.assertNotEqual(a["report"], b["report"])
        self.assertEqual(report.content_digest(a), report.content_digest(b))

    def test_markdown_comes_only_from_the_model(self):
        m = self.build(assessment=PROFILE)
        text = render.to_markdown(m)
        self.assertIn(m["report"]["report_id"], text)
        self.assertIn(m["inventory"]["artifact_digest"], text)
        self.assertIn(m["identity_evidence"]["manifest_hash"], text)

    def test_no_raw_machine_id_in_any_rendering(self):
        m = self.build(assessment=PROFILE)
        for text in (render.to_markdown(m), render.to_json(m)):
            self.assertNotIn("7f8e9a0b1c2d3e4f5061728394a5b6c7", text)


class TestStorageAndCLI(ReportCase):
    def test_report_is_written_under_the_state_root(self):
        m = self.build()
        path = report.write(self.root, m, render.to_markdown(m), "md")
        self.assertTrue(path.startswith(os.path.join(self.root, "reports")))
        self.assertIn("/2026/09/", path)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertNotIn("/var/log", path)

    def test_cli_markdown_and_json(self):
        for as_json in (False, True):
            out, err = io.StringIO(), io.StringIO()
            args = type("A", (), {"json": as_json, "profile": None, "save": False})()
            code = cli.cmd_report(args, out=out, err=err)
            self.assertIn(code, (0, 2), err.getvalue())
            if as_json:
                json.loads(out.getvalue())
            else:
                self.assertIn("ISEDRAF System Assurance Report", out.getvalue())

    def test_cli_rejects_a_missing_profile_rather_than_ignoring_it(self):
        out, err = io.StringIO(), io.StringIO()
        args = type("A", (), {"json": False, "profile": "/nonexistent/p.json",
                              "save": False})()
        self.assertEqual(cli.cmd_report(args, out=out, err=err), 64)
        self.assertIn("does not exist", err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
