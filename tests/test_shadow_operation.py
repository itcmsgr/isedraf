# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: read_shadow_v1, the first privileged vertical slice, as the accounts section uses it.
# Implements: AUTH-004, AUTH-015, AUTH-016, AUTH-017, AUTH-024, ELIM-008
#
# v0.2 P5c. The accounts collector, given the supervisor channel, acquires /etc/shadow by the
# registered fixed operation and interprets the returned bytes exactly as a file it read
# itself; the coverage record names the operation. Without a channel nothing changes. The
# channel here is scripted: the supervisor itself is held by tests/test_supervisor.py and the
# whole route, against fixtures, by tests/test_launcher_route.py.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""v0.2 P5c: the accounts section over read_shadow_v1."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, os.path.join(HERE, "..", "scripts", "ci"))
sys.path.insert(0, HERE)

from isedraf import audit, canonical, coverage                     # noqa: E402
from isedraf.accounts import acquire as accounts                    # noqa: E402
from isedraf.supervisor import protocol                             # noqa: E402
import check_evidence_limits_schema as gate                         # noqa: E402
import test_evidence_limits as fixtures                             # noqa: E402

SHADOW = fixtures.FILES["etc/shadow"].encode()


class Scripted(object):
    """A supervisor channel that answers from a script and records what was asked."""

    def __init__(self, result=None, raises=None):
        self.result, self.raises, self.asked = result, raises, []

    def request(self, operation_id):
        self.asked.append(operation_id)
        if self.raises is not None:
            raise self.raises
        return self.result


def completed(data=SHADOW):
    return protocol.result("read_shadow_v1", protocol.COMPLETED, data)


def failed(token):
    return protocol.result("read_shadow_v1", protocol.FAILED, stderr=token)


def shadow_record(evidence):
    return [r for r in evidence["coverage"] if r["source"] == "etc/shadow"][0]


class TheSectionUsesTheOperation(fixtures.Host):

    def collect(self, channel=None):
        return accounts.collect(self.host, channel=channel)

    def test_the_section_asks_for_exactly_read_shadow_v1_once(self):
        channel = Scripted(completed())
        self.collect(channel)
        self.assertEqual(channel.asked, ["read_shadow_v1"])

    def test_a_completed_operation_is_parsed_like_a_file_and_names_its_operation(self):
        evidence = self.collect(Scripted(completed()))
        self.assertEqual(evidence["sources"]["etc/shadow"]["status"], "COLLECTED")
        record = shadow_record(evidence)
        self.assertEqual((record["acquisition_mode"], record["operation_id"]),
                         ("SUPERVISOR_FIXED_OPERATION", "read_shadow_v1"))
        self.assertEqual(record["access_outcome"], coverage.READ_OK)
        for other in evidence["coverage"]:
            if other["source"] != "etc/shadow":
                self.assertNotIn("operation_id", other)
        self.assertEqual(evidence["collection_status"], "COLLECTED")

    def test_the_bytes_give_the_same_accounts_as_reading_the_file(self):
        supervised = self.collect(Scripted(completed()))
        direct = self.collect()
        self.assertEqual(canonical.canonical_bytes(supervised["local_accounts"]),
                         canonical.canonical_bytes(direct["local_accounts"]))

    def test_each_supervisor_outcome_maps_onto_the_source(self):
        for result, status, outcome, code in (
                (failed(b"ENOENT"), "NOT_TESTED", coverage.NOT_FOUND, "SOURCE_ABSENT"),
                (failed(b"EACCES"), "NOT_TESTED", coverage.PERMISSION_DENIED,
                 "SOURCE_UNREADABLE"),
                (failed(b"ELOOP"), "ERROR", coverage.IO_ERROR, "SOURCE_UNREADABLE"),
                (protocol.result("read_shadow_v1", protocol.TRUNCATED), "ERROR",
                 coverage.TRUNCATED, "SOURCE_TRUNCATED"),
                (protocol.result("read_shadow_v1", protocol.REFUSED, stderr=b"NOT_ENABLED"),
                 "NOT_TESTED", coverage.NOT_SUPPORTED, "SUPERVISOR_REFUSED")):
            evidence = self.collect(Scripted(result))
            record = shadow_record(evidence)
            self.assertEqual((record["status"], record["access_outcome"]), (status, outcome),
                             result)
            self.assertTrue(record["reason"].startswith(code + ": "), record["reason"])
            self.assertEqual(record["operation_id"], "read_shadow_v1")
            self.assertNotEqual(evidence["collection_status"], "COLLECTED")

    def test_a_broken_channel_is_an_error_never_a_silent_absence(self):
        evidence = self.collect(Scripted(raises=protocol.ProtocolError("frame")))
        record = shadow_record(evidence)
        self.assertEqual(record["status"], "ERROR")
        self.assertTrue(record["reason"].startswith("SUPERVISOR_CHANNEL_FAILED: "))

    def test_a_completed_operation_does_not_complete_the_section_alone(self):
        # AUTH-016: the section derives its status from every source it requires.
        self.deny("etc/group")
        evidence = self.collect(Scripted(completed()))
        self.assertEqual(shadow_record(evidence)["status"], "COLLECTED")
        self.assertNotEqual(evidence["collection_status"], "COLLECTED")

    def test_without_a_channel_nothing_names_an_operation(self):
        # AUTH-024 item 4: the STANDARD_AUDIT path is unchanged.
        evidence = self.collect()
        for record in evidence["coverage"]:
            self.assertNotIn("acquisition_mode", record)
            self.assertNotIn("operation_id", record)


class TheManifestRecordsTheAuthority(fixtures.Host):

    def manifest(self, channel):
        sections, _status = audit.collect(self.host, channel=channel)
        return audit.evidence_limits(sections, self.host)

    def test_the_shadow_entry_is_supervisor_acquired_and_the_rest_current_identity(self):
        m = self.manifest(Scripted(completed()))
        entries = [s for s in m["sources"] if s["domain"] == "accounts"]
        modes = dict((s["source"], (s["acquisition_mode"], s["operation_id"])) for s in entries)
        self.assertEqual(modes["etc/shadow"], ("SUPERVISOR_FIXED_OPERATION", "read_shadow_v1"))
        self.assertEqual(modes["etc/passwd"], ("CURRENT_IDENTITY", None))
        self.assertEqual(m["acquisition_modes"], ["CURRENT_IDENTITY",
                                                  "SUPERVISOR_FIXED_OPERATION"])
        self.assertEqual(gate.validate(canonical.canonical_bytes(m), gate.vocabulary()), [])

    def test_a_standard_run_manifest_has_one_authority(self):
        m = self.manifest(None)
        self.assertEqual(m["acquisition_modes"], ["CURRENT_IDENTITY"])
        self.assertTrue(all(s["operation_id"] is None for s in m["sources"]))

    def test_the_section_named_by_the_registry_requests_the_operation(self):
        # AUTH-024 item 3, the code side of what check-privileged-operations holds.
        self.assertEqual(accounts.SHADOW_OPERATION, "read_shadow_v1")


if __name__ == "__main__":
    unittest.main()
