# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Full Audit never reports the sandbox as the host, and a failing helper is not silence.
# Implements: AUTH-005, SCOPE-022, PRIV-021, D-124
#
# v0.2 P6 found two false-confidence paths (IQ-053, IQ-054):
#
#   F1  the reduced engine reads the unit's private mount namespace, so its active mounts and
#       the inventory's filesystem list were the sandbox's, reported COLLECTED;
#   F2  under no-new-privileges, chronyc's SELinux domain transition is denied on EL9; the
#       time-sync fields went null while the time subdomain stayed COLLECTED, and every
#       run left an AVC record. The collector also recorded nothing when an optional helper
#       failed - in the standard route as well.
#
# Unprivileged and fixture-only: helpers are scripted, nothing runs a host tool.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""v0.2 P6 fixes and IQ-055: PID 1's mount table, HELPER_FAILED, MAC_DOMAIN_TRANSITION_UNAVAILABLE."""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))

from isedraf import hostio, inventory                           # noqa: E402
from isedraf.inventory import collectors                        # noqa: E402
from isedraf.mounts import acquire as mounts                    # noqa: E402

FSTAB = "UUID=abc / ext4 defaults 0 1\n"
MOUNTINFO = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
MOUNTS = "/dev/sda1 / ext4 rw,relatime 0 0\n"
# What the Full Audit sandbox sees of itself: / read-only, plus a mount the host does not have.
SANDBOX_MOUNTINFO = (MOUNTINFO.replace(" rw,relatime ", " ro,relatime ") +
                     "31 22 0:31 / /run/sandbox-only rw - tmpfs tmpfs rw\n")
SANDBOX_MOUNTS = MOUNTS.replace(" rw,relatime ", " ro,relatime ") + \
    "tmpfs /run/sandbox-only tmpfs rw 0 0\n"
TIMEDATECTL = "Timezone=UTC\nNTP=yes\nNTPSynchronized=yes\n"
TRACKING = "Reference ID    : 5F85C251 (x)\nStratum         : 2\nSystem time     : 0.000001872 seconds fast\n"


class Fixture(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        for rel, text in (("etc/fstab", FSTAB), ("proc/self/mountinfo", MOUNTINFO),
                          ("proc/self/mounts", MOUNTS), ("proc/1/mountinfo", MOUNTINFO),
                          ("proc/1/mounts", MOUNTS), ("sys/block/sda/size", "2048\n")):
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)


class TheSandboxIsNeverTheHost(Fixture):
    """IQ-053 (F1), as resolved by IQ-055 (A): in Full Audit the host table is PID 1's, read by
    the engine itself; the sandbox's own table is never read and never stands in for it."""

    def setUp(self):
        super(TheSandboxIsNeverTheHost, self).setUp()
        # The sandbox's own tables say something different, so reading them would show.
        for rel, text in (("proc/self/mountinfo", SANDBOX_MOUNTINFO),
                          ("proc/self/mounts", SANDBOX_MOUNTS),
                          ("proc/1/mountinfo", MOUNTINFO), ("proc/1/mounts", MOUNTS)):
            with open(os.path.join(self.root, rel), "w") as fh:
                fh.write(text)

    @staticmethod
    def host_entry(evidence):
        return [c for c in evidence["provenance"]["coverage"]
                if c["source"].endswith("proc/1/mountinfo")][0]

    def reading(self, call):
        reads = []
        real_lossless, real_lines = hostio.read_file_lossless, collectors.read_lines
        with mock.patch.object(hostio, "read_file_lossless",
                               lambda p, *a: reads.append(p) or real_lossless(p, *a)), \
                mock.patch.object(collectors, "read_lines",
                                  lambda p, *a: reads.append(p) or real_lines(p, *a)):
            out = call()
        return out, reads

    def test_full_audit_active_mounts_are_pid_1s_table(self):
        evidence = mounts.collect(self.root, sandboxed=True).as_dict()
        active = evidence["provenance"]["active"]
        self.assertEqual([r["mount_point"] for r in active["records"]], ["/"])
        self.assertEqual(self.host_entry(evidence)["status"], "COLLECTED")

    def test_the_sandboxed_collector_never_reads_its_own_mount_table(self):
        _evidence, reads = self.reading(lambda: mounts.collect(self.root, sandboxed=True))
        self.assertFalse([q for q in reads if "proc/self/" in q], reads)

    def test_an_unreadable_host_table_is_not_tested_and_never_replaced(self):
        os.remove(os.path.join(self.root, "proc/1/mountinfo"))
        evidence, reads = self.reading(
            lambda: mounts.collect(self.root, sandboxed=True).as_dict())
        entry = self.host_entry(evidence)
        self.assertEqual(entry["status"], "NOT_TESTED")
        self.assertEqual(evidence["provenance"]["active"]["records"], [])
        self.assertTrue(entry["reason"].startswith("HOST_MOUNT_TABLE_UNREADABLE: "),
                        entry["reason"])
        self.assertFalse([q for q in reads if "proc/self/" in q], reads)

    def test_the_declared_side_is_still_host_truth(self):
        evidence = mounts.collect(self.root, sandboxed=True).as_dict()
        self.assertTrue(evidence["provenance"]["declared"]["records"])

    def test_the_standard_route_still_reads_its_namespace(self):
        evidence = mounts.collect(self.root).as_dict()
        self.assertEqual([r["mount_point"] for r in evidence["provenance"]["active"]["records"]],
                         ["/", "/run/sandbox-only"])

    def storage(self, identity):
        """Full Audit storage with the in-sandbox measurement scripted: `identity` maps a
        mount point to the device the sandbox path turned out to be on."""
        def measure(target, device):
            if identity.get(target) != device:
                return None
            return os.statvfs_result((4096, 4096, 1000, 400, 400, 100, 50, 50, 0, 255))
        with mock.patch.object(collectors, "_same_filesystem_statvfs", measure):
            return self.reading(lambda: collectors.collect_storage(self.root, sandboxed=True))

    def test_full_audit_storage_takes_filesystems_from_the_host_table(self):
        block, reads = self.storage({"/": os.makedev(8, 1)})
        self.assertEqual(block["collection_status"], "COLLECTED", block["reason"])
        self.assertEqual([f["mount_point"] for f in block["data"]["filesystems"]], ["/"])
        # read-write as the host has it; the sandbox's view says read-only
        self.assertFalse(block["data"]["filesystems"][0]["read_only"])
        self.assertEqual([u["mount_point"] for u in block["data"]["utilisation"]], ["/"])
        self.assertEqual([d["name"] for d in block["data"]["devices"]], ["sda"])
        self.assertFalse([q for q in reads if "proc/self/" in q], reads)

    def test_space_is_never_reported_when_the_filesystem_is_not_the_same(self):
        block, _reads = self.storage({"/": os.makedev(0, 99)})
        self.assertEqual(block["collection_status"], "PARTIAL")
        self.assertEqual(block["data"]["utilisation"], [])
        self.assertIn("FILESYSTEM_IDENTITY_NOT_PROVEN", block["reason"])
        self.assertEqual([f["mount_point"] for f in block["data"]["filesystems"]], ["/"])

    def test_an_unreadable_host_table_leaves_storage_partial_without_filesystems(self):
        os.remove(os.path.join(self.root, "proc/1/mounts"))
        block, reads = self.storage({"/": os.makedev(8, 1)})
        self.assertEqual(block["collection_status"], "PARTIAL")
        self.assertTrue(block["reason"].startswith("HOST_MOUNT_TABLE_UNREADABLE: "),
                        block["reason"])
        self.assertIsNone(block["data"]["filesystems"])
        self.assertIsNone(block["data"]["utilisation"])
        self.assertEqual([d["name"] for d in block["data"]["devices"]], ["sda"])
        self.assertFalse([q for q in reads if "proc/self/" in q], reads)

    def test_tables_that_disagree_give_topology_without_space(self):
        with open(os.path.join(self.root, "proc/1/mountinfo"), "a") as fh:
            fh.write("40 22 0:40 / /extra rw - tmpfs tmpfs rw\n")
        block, _reads = self.storage({"/": os.makedev(8, 1)})
        self.assertEqual(block["collection_status"], "PARTIAL")
        self.assertEqual(block["data"]["utilisation"], [])
        self.assertIn("FILESYSTEM_IDENTITY_NOT_PROVEN", block["reason"])

    def test_the_real_measurement_compares_device_identity_not_the_path(self):
        here = os.stat(self.root).st_dev
        self.assertIsNotNone(collectors._same_filesystem_statvfs(self.root, here))
        self.assertIsNone(collectors._same_filesystem_statvfs(self.root, here + 1))

    def test_standard_storage_is_unchanged(self):
        block = collectors.collect_storage(self.root)
        self.assertEqual([f["mount_point"] for f in block["data"]["filesystems"]],
                         ["/", "/run/sandbox-only"])

    def test_inventory_passes_the_flag_only_where_it_matters(self):
        inv = inventory.collect(self.root, sandboxed=True)
        self.assertIn(inv["subdomains"]["storage"]["collection_status"],
                      ("COLLECTED", "PARTIAL"))
        self.assertIsNotNone(inv["subdomains"]["storage"]["data"]["filesystems"])


class Scripted(object):
    def __init__(self, results):
        self.results, self.calls = results, []

    def __call__(self, argv, timeout=None):
        self.calls.append(list(argv))
        return self.results.get(argv[0], hostio.Outcome(ok=False, reason="NOT_TESTED"))


class TimeIsNeverSilentlyComplete(unittest.TestCase):
    """IQ-054 (F2), both fixes."""

    def collect(self, results, sandboxed=False, enforcing=False, label=None):
        run = Scripted(results)
        with mock.patch.object(collectors, "run", run), \
                mock.patch.object(collectors, "_live", lambda root: True), \
                mock.patch.object(collectors, "which",
                                  lambda name: "/usr/bin/" + name if name == "chronyc" else None), \
                mock.patch.object(collectors, "selinux_enforcing", lambda: enforcing), \
                mock.patch.object(collectors, "selinux_label", lambda path: label):
            block = collectors.collect_time("/", sandboxed=sandboxed)
        return block, run.calls

    def test_a_working_chronyc_is_collected(self):
        block, _calls = self.collect({"timedatectl": hostio.Outcome(value=TIMEDATECTL),
                                      "chronyc": hostio.Outcome(value=TRACKING)})
        self.assertEqual(block["collection_status"], "COLLECTED")
        self.assertEqual(block["data"]["stratum"], 2)

    def test_a_failing_chronyc_is_never_silently_collected(self):
        # Fix 1, both modes.
        block, _calls = self.collect({"timedatectl": hostio.Outcome(value=TIMEDATECTL),
                                      "chronyc": hostio.Outcome(ok=False, reason="ERROR")})
        self.assertEqual(block["collection_status"], "PARTIAL")
        self.assertTrue(block["reason"].startswith("HELPER_FAILED: "), block["reason"])
        self.assertIn("possible", block["reason"])
        self.assertIsNone(block["data"]["stratum"])

    def test_full_audit_on_selinux_does_not_execute_a_transitioning_chronyc(self):
        # Fix 2: known from runtime state, never inferred after a failure.
        block, calls = self.collect({"timedatectl": hostio.Outcome(value=TIMEDATECTL),
                                     "chronyc": hostio.Outcome(value=TRACKING)},
                                    sandboxed=True, enforcing=True,
                                    label="system_u:object_r:chronyc_exec_t:s0")
        self.assertFalse([c for c in calls if c[0] == "chronyc"], calls)
        self.assertEqual(block["collection_status"], "PARTIAL")
        self.assertTrue(block["reason"].startswith("MAC_DOMAIN_TRANSITION_UNAVAILABLE: "))
        self.assertIsNone(block["data"]["stratum"])

    def test_the_standard_route_on_selinux_still_executes_chronyc(self):
        block, calls = self.collect({"timedatectl": hostio.Outcome(value=TIMEDATECTL),
                                     "chronyc": hostio.Outcome(value=TRACKING)},
                                    sandboxed=False, enforcing=True,
                                    label="system_u:object_r:chronyc_exec_t:s0")
        self.assertTrue([c for c in calls if c[0] == "chronyc"])
        self.assertEqual(block["collection_status"], "COLLECTED")

    def test_full_audit_without_selinux_executes_chronyc(self):
        block, calls = self.collect({"timedatectl": hostio.Outcome(value=TIMEDATECTL),
                                     "chronyc": hostio.Outcome(value=TRACKING)},
                                    sandboxed=True, enforcing=False, label=None)
        self.assertTrue([c for c in calls if c[0] == "chronyc"])
        self.assertEqual(block["collection_status"], "COLLECTED")

    def test_an_unmeasured_label_is_executed_and_judged_by_its_result(self):
        block, calls = self.collect({"timedatectl": hostio.Outcome(value=TIMEDATECTL),
                                     "chronyc": hostio.Outcome(value=TRACKING)},
                                    sandboxed=True, enforcing=True,
                                    label="system_u:object_r:bin_t:s0")
        self.assertTrue([c for c in calls if c[0] == "chronyc"])


if __name__ == "__main__":
    unittest.main()
