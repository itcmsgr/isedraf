# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: W1-C1 host inventory tests — parsing, classification, and quiet behaviour.
# Implements: SCOPE-022, SCOPE-045, SCOPE-063, REC-005, NORM-034
#
# The noise test is the one that matters. Collecting facts is easy; not turning ordinary
# Linux volatility into security drift is the part that decides whether an operator keeps
# reading the output.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="temporary directories only"
# meta:binaries="git"
# =============================================================================

"""Fixture-root parsing, classification coverage, and the repeated-run noise test."""
import io
import os
import pathlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import cli, inventory                                    # noqa: E402
from isedraf.inventory import collectors, model                       # noqa: E402

CPUINFO = """processor\t: 0
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) Silver 4210
physical id\t: 0
cpu cores\t: 2
flags\t\t: fpu vme hypervisor lm

processor\t: 1
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) Silver 4210
physical id\t: 0
cpu cores\t: 2
flags\t\t: fpu vme hypervisor lm

"""
MEMINFO = "MemTotal:        4028132 kB\nSwapTotal:       2097148 kB\nMemFree:  10 kB\n"


def build_root(files, links=None):
    base = tempfile.mkdtemp()
    for path, content in files.items():
        full = os.path.join(base, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fh:
            fh.write(content)
    for path, target in (links or {}).items():
        full = os.path.join(base, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        os.symlink(target, full)
    return base


class TestParsers(unittest.TestCase):
    def setUp(self):
        self.base = build_root({
            "proc/sys/kernel/hostname": "fixture-host\n",
            "etc/hosts": "127.0.0.1 localhost\n10.0.0.5 fixture-host.example.test fixture-host\n",
            "etc/os-release": 'ID=rocky\nVERSION_ID="9.7"\nPRETTY_NAME="Rocky Linux 9.7"\n'
                              'ID_LIKE="rhel centos fedora"\n',
            "proc/1/comm": "systemd\n",
            "proc/cpuinfo": CPUINFO,
            "proc/meminfo": MEMINFO,
            "proc/uptime": "1234.56 9876.54\n",
            "sys/class/dmi/id/sys_vendor": "QEMU\n",
            "sys/class/dmi/id/product_name": "Standard PC\n",
            "etc/resolv.conf": "nameserver 10.0.0.1\nnameserver 10.0.0.2\n",
        })
        self.addCleanup(shutil.rmtree, self.base, True)

    def test_hostname_and_fqdn_from_hosts(self):
        block = collectors.collect_host(self.base)
        self.assertEqual(block["collection_status"], model.COLLECTED)
        self.assertEqual(block["data"]["hostname"], "fixture-host")
        self.assertEqual(block["data"]["fqdn"], "fixture-host.example.test")
        self.assertEqual(block["data"]["fqdn_source"], "/etc/hosts")

    def test_fqdn_is_never_fabricated_and_absence_is_not_incomplete(self):
        """Most standalone, lab and edge hosts have no locally resolvable FQDN.

        That is their normal state, not a failure to observe one. Marking it PARTIAL put
        almost every such host into an incomplete report while everything else had been
        collected in full, which is how a status stops meaning anything. The absence is
        still reported explicitly; it is simply not a defect.
        """
        base = build_root({"proc/sys/kernel/hostname": "lonely\n",
                           "etc/hosts": "127.0.0.1 localhost\n"})
        self.addCleanup(shutil.rmtree, base, True)
        block = collectors.collect_host(base)
        self.assertIsNone(block["data"]["fqdn"])
        self.assertEqual(block["data"]["fqdn_source"], "NOT_AVAILABLE_LOCALLY")
        self.assertEqual(block["collection_status"], model.COLLECTED)
        self.assertIsNone(block["reason"])


    def test_platform(self):
        data = collectors.collect_platform(self.base)["data"]
        self.assertEqual(data["id"], "rocky")
        self.assertEqual(data["version_id"], "9.7")
        self.assertEqual(data["family"], "rhel centos fedora")
        self.assertEqual(data["init_system"], "systemd")

    def test_cpu(self):
        data = collectors.collect_compute(self.base)["data"]
        self.assertEqual(data["cpu_vendor"], "GenuineIntel")
        self.assertEqual(data["logical_cpus"], 2)
        self.assertEqual(data["sockets"], 1)
        self.assertEqual(data["cores_per_socket"], 2)

    def test_memory_is_bytes_not_kb(self):
        data = collectors.collect_memory(self.base)["data"]
        self.assertEqual(data["total_bytes"], 4028132 * 1024)
        self.assertEqual(data["swap_total_bytes"], 2097148 * 1024)

    def test_virtualization_detected_from_cpu_flags(self):
        data = collectors.collect_machine(self.base)["data"]
        self.assertEqual(data["vendor"], "QEMU")
        self.assertTrue(data["virtualized"])

    def test_dns(self):
        data = collectors.collect_dns(self.base)["data"]
        self.assertEqual(data["servers"], ["10.0.0.1", "10.0.0.2"])
        self.assertIsNone(data["note"])

    def test_dns_behind_a_local_stub_reports_the_upstreams(self):
        base = build_root({
            "etc/resolv.conf": "nameserver 127.0.0.53\n",
            "run/systemd/resolve/resolv.conf": "nameserver 9.9.9.9\n"})
        self.addCleanup(shutil.rmtree, base, True)
        data = collectors.collect_dns(base)["data"]
        self.assertEqual(data["note"], "LOCAL_STUB_RESOLVER")
        self.assertEqual(data["servers"], ["9.9.9.9"])

    def test_missing_sources_are_reported_not_emptied(self):
        base = build_root({})
        self.addCleanup(shutil.rmtree, base, True)
        for collector in (collectors.collect_host, collectors.collect_compute,
                          collectors.collect_memory):
            block = collector(base)
            self.assertIn(block["collection_status"], (model.ERROR, model.NOT_TESTED))
            self.assertIsNotNone(block["reason"])
        self.assertEqual(collectors.collect_dns(base)["collection_status"],
                         model.NOT_TESTED)

    def test_proc_files_are_read_to_eof(self):
        """A single os.read() on /proc returns one page and silently truncates."""
        big = "".join(CPUINFO for _ in range(400))
        base = build_root({"proc/cpuinfo": big})
        self.addCleanup(shutil.rmtree, base, True)
        self.assertGreater(len(big), 65536)
        self.assertEqual(collectors.collect_compute(base)["data"]["logical_cpus"], 800)


class TestFixtureIsolation(unittest.TestCase):
    """A fixture root describes a filesystem, not a running system."""

    def test_host_commands_do_not_run_against_a_fixture_root(self):
        base = build_root({"proc/uptime": "10.0 5.0\n"},
                          links={"etc/localtime": "../usr/share/zoneinfo/Antarctica/Troll"})
        self.addCleanup(shutil.rmtree, base, True)
        # If timedatectl were consulted, this would become the RUNNING host's timezone -
        # which is how a CI runner silently overwrote a fixture and the test still passed
        # locally, because the two machines happened to agree.
        self.assertEqual(collectors.collect_time(base)["data"]["timezone"],
                         "Antarctica/Troll")
        self.assertEqual(collectors.collect_network(base)["collection_status"],
                         model.NOT_TESTED)


class TestIPv6Classification(unittest.TestCase):
    """RFC 4941 temporary addresses rotate by design; they must never be stable state."""

    def test_classes(self):
        cases = [
            ("2001:db8::1", "global", [], model.IPV6_GLOBAL_STABLE),
            ("2001:db8::dead", "global", ["temporary"], model.IPV6_TEMPORARY_PRIVACY),
            ("fe80::1", "link", [], model.IPV6_LINK_LOCAL),
            ("::1", "host", [], model.IPV6_LOOPBACK),
            ("fd00::1", "site", [], model.IPV6_OTHER),
        ]
        for address, scope, flags, expected in cases:
            self.assertEqual(collectors._classify_ipv6(address, scope, flags), expected)

    def test_temporary_wins_over_global_scope(self):
        self.assertEqual(
            collectors._classify_ipv6("2001:db8::x", "global", ["temporary", "dynamic"]),
            model.IPV6_TEMPORARY_PRIVACY)


class TestTime(unittest.TestCase):
    def test_timezone_from_symlink(self):
        base = build_root({"proc/uptime": "10.0 5.0\n"},
                          links={"etc/localtime": "../usr/share/zoneinfo/Europe/Athens"})
        self.addCleanup(shutil.rmtree, base, True)
        self.assertEqual(collectors.collect_time(base)["data"]["timezone"],
                         "Europe/Athens")

    def test_enabled_and_synchronized_are_separate_facts(self):
        """The whole point: NTP configured on says nothing about the clock being right."""
        self.assertIn("time.ntp_enabled", model.CLASSIFICATION)
        self.assertIn("time.synchronized", model.CLASSIFICATION)
        self.assertEqual(model.CLASSIFICATION["time.ntp_enabled"],
                         model.NETWORK_CONFIGURATION)
        self.assertEqual(model.CLASSIFICATION["time.synchronized"],
                         model.VOLATILE_OBSERVATION)

    def test_rec005_signal(self):
        def inv(value):
            return {"subdomains": {"time": {"data": {"synchronized": value}}}}
        self.assertIs(inventory.clock_unsynchronized(inv(False)), True)
        self.assertIs(inventory.clock_unsynchronized(inv(True)), False)
        # Unknown is NOT an assertion that the clock is fine.
        self.assertIsNone(inventory.clock_unsynchronized(inv(None)))


class TestModel(unittest.TestCase):
    def test_every_produced_field_is_classified(self):
        """SCOPE-045: no implicit default. An unclassified field is a defect."""
        flat = inventory.flatten(inventory.collect())
        unclassified = sorted(set(flat) - set(model.CLASSIFICATION))
        self.assertEqual(unclassified, [], "unclassified inventory fields")

    def test_every_subdomain_is_present_even_when_empty(self):
        inv = inventory.collect()
        self.assertEqual(sorted(inv["subdomains"]), sorted(model.SUBDOMAINS))
        for block in inv["subdomains"].values():
            for key in ("collection_status", "reason", "method", "state_dimension",
                        "data"):
                self.assertIn(key, block)

    def test_no_sensitive_identifier_is_exported(self):
        """Raw machine-id, DMI UUID and hardware serials stay out of the inventory."""
        import json
        text = json.dumps(inventory.collect())
        for forbidden in ("product_uuid", "board_serial", "product_serial",
                          "machine-id", "machine_id"):
            self.assertNotIn(forbidden, text)
        machine_id = pathlib.Path("/etc/machine-id")
        if machine_id.exists():
            value = machine_id.read_text().strip()
            # An empty machine-id is a real state on some images, and `x in text` is
            # True for the empty string, so the guard would fail on every host that has
            # one. Absence of a value is not a leak.
            if value:
                self.assertNotIn(value, text)


class TestNoise(unittest.TestCase):
    """The acceptance condition: an unchanged host must not manufacture changes."""

    def test_repeated_collection_changes_only_volatile_fields(self):
        first = inventory.flatten(inventory.collect())
        second = inventory.flatten(inventory.collect())
        changed = sorted(k for k in first if first[k] != second.get(k))
        unexpected = [k for k in changed if k not in model.VOLATILE_FIELDS]
        self.assertEqual(unexpected, [],
                         "non-volatile inventory fields changed between two immediate "
                         "collections: %s" % unexpected)

    def test_volatile_fields_are_declared_not_discovered(self):
        """Every VOLATILE_OBSERVATION is named in the table, so the noise test above
        cannot be satisfied by quietly widening what counts as volatile."""
        self.assertIn("time.uptime_seconds", model.VOLATILE_FIELDS)
        self.assertIn("storage.utilisation", model.VOLATILE_FIELDS)
        self.assertIn("network.ipv6_volatile", model.VOLATILE_FIELDS)
        self.assertNotIn("platform.kernel_release", model.VOLATILE_FIELDS)
        self.assertNotIn("network.ipv4", model.VOLATILE_FIELDS)


class TestCLI(unittest.TestCase):
    def test_human_output(self):
        out, err = io.StringIO(), io.StringIO()
        args = type("A", (), {"json": False, "root": "/"})()
        code = cli.cmd_inventory(args, out=out, err=err)
        text = out.getvalue()
        self.assertIn("ISEDRAF host inventory", text)
        for section in ("PLATFORM", "COMPUTE", "STORAGE", "NETWORK", "TIME"):
            self.assertIn(section, text)
        self.assertIn(code, (0, 2))

    def test_json_output_is_the_normalized_object(self):
        import json
        out, err = io.StringIO(), io.StringIO()
        args = type("A", (), {"json": True, "root": "/"})()
        cli.cmd_inventory(args, out=out, err=err)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["schema_version"], model.INVENTORY_SCHEMA_VERSION)
        self.assertEqual(sorted(parsed["subdomains"]), sorted(model.SUBDOMAINS))


class TestDeviceClassification(unittest.TestCase):
    """`rotational == 0` is true of an optical drive as well as an SSD."""

    def device(self, name, rotational=None, removable=None, scsi_type=None,
               devmodel=None, devvendor=None, subsystem=None):
        files = {"proc/self/mounts": ""}
        base = "sys/block/%s" % name
        files[base + "/size"] = "2097152\n"
        if rotational is not None:
            files[base + "/queue/rotational"] = "%s\n" % rotational
        if removable is not None:
            files[base + "/removable"] = "%s\n" % removable
        if scsi_type is not None:
            files[base + "/device/type"] = "%s\n" % scsi_type
        if devmodel is not None:
            files[base + "/device/model"] = "%s\n" % devmodel
        if devvendor is not None:
            files[base + "/device/vendor"] = "%s\n" % devvendor
        root = build_root(files)
        self.addCleanup(shutil.rmtree, root, True)
        # D-114: kernel_subsystem comes from the kernel's own link, so a fixture that
        # claims to test a subsystem must PROVIDE one. A RELATIVE link, and the
        # collector reads it lexically - FIXTURE-CONFINEMENT-001. A target that does
        # not exist is deliberate in one test: resolving it is not required.
        if subsystem is not None:
            devdir = os.path.join(root, "sys/block", name, "device")
            if not os.path.isdir(devdir):
                os.makedirs(devdir)
            os.symlink("../../../bus/%s" % subsystem,
                       os.path.join(devdir, "subsystem"))
        return collectors.collect_storage(root)["data"]["devices"][0]

    # ---- INV-MACHINE-NODMI-001 ---------------------------------------------------

    def _machine(self, files):
        root = build_root(files)
        self.addCleanup(shutil.rmtree, root, True)
        return collectors.collect_machine(root)

    def test_absent_dmi_is_never_reported_as_collected(self):
        """Defect A. Virtualization detection is not machine identity.

        The previous rule counted non-null values across the whole subdomain, and
        `virtualized` and `hypervisor` counted toward the threshold - so on any
        virtualized host without SMBIOS, DMI could be entirely absent and the
        subdomain still reported COLLECTED with vendor and product null and no
        reason. An incomplete collection reported as complete.
        """
        for name, files in (
                ("no DMI, no hypervisor",
                 {"proc/cpuinfo": "Hardware\t: BCM2835\n"}),
                ("no DMI, hypervisor present",
                 {"proc/cpuinfo": "flags\t: hypervisor\n",
                  "sys/hypervisor/type": "kvm\n"})):
            sd = self._machine(files)
            self.assertEqual(sd["collection_status"], model.PARTIAL, name)
            self.assertIsNone(sd["data"]["vendor"], name)
            self.assertIsNone(sd["data"]["product"], name)
            self.assertTrue(sd.get("reason"), "%s: PARTIAL with no reason" % name)
            self.assertIn("SOURCE_ABSENT", sd["reason"], name)

    def test_partial_dmi_is_still_incomplete(self):
        """One identity field present and one absent is not a complete collection."""
        sd = self._machine({"proc/cpuinfo": "x\n",
                            "sys/class/dmi/id/sys_vendor": "QEMU\n"})
        self.assertEqual(sd["collection_status"], model.PARTIAL)
        self.assertIn("product", sd["reason"])

    def test_complete_dmi_collects_without_a_reason(self):
        sd = self._machine({"proc/cpuinfo": "x\n",
                            "sys/class/dmi/id/sys_vendor": "Dell Inc.\n",
                            "sys/class/dmi/id/product_name": "PowerEdge R640\n"})
        self.assertEqual(sd["collection_status"], model.COLLECTED)
        self.assertIsNone(sd.get("reason"))

    # ---- D-114 / STORAGE-SEMANTICS-001 -------------------------------------------
    #
    # The tests these replace asserted the DEFECT as expected behaviour. The worst was
    # `test_real_ssd_is_solid_state`: its fixture proved only that a SCSI device
    # reported non-rotational, and it asserted SOLID_STATE - exactly the inference
    # D-114 prohibits. STORAGE-SEMANTICS-002 says such a test is replaced by a test of
    # the corrected model, and that deleting it is not sufficient: the inverse must be
    # asserted.

    def test_no_device_reports_a_physical_medium(self):
        """STORAGE-SEMANTICS-001. The retired field must not come back under any name."""
        for kwargs in ({"rotational": 0, "scsi_type": 0, "subsystem": "scsi"},
                       {"rotational": 1, "subsystem": "scsi"},
                       {"rotational": 0, "subsystem": "nvme"},
                       {"rotational": 0, "subsystem": "mmc"},
                       {"rotational": 0, "scsi_type": 5, "subsystem": "scsi"}):
            dev = self.device("dev0", **kwargs)
            for retired in ("type", "physical_medium", "transport", "is_aggregate"):
                self.assertNotIn(retired, dev,
                                 "%s reappeared for %r" % (retired, kwargs))
            self.assertNotIn("SOLID_STATE", repr(dev))

    def test_non_rotational_scsi_is_not_called_solid_state(self):
        """Replaces test_real_ssd_is_solid_state, whose premise was false.

        The fixture proves a SCSI device reports non-rotational. It proves nothing
        about the medium, and the record must say exactly that much.
        """
        dev = self.device("sda", rotational=0, removable=0, scsi_type=0,
                          subsystem="scsi")
        self.assertEqual(dev["kernel_subsystem"], "scsi")
        self.assertIs(dev["queue_rotational"], False)
        self.assertEqual(dev["scsi_peripheral_type"], 0)

    def test_queue_rotational_false_is_retained_as_evidence(self):
        """Positive control. Without it, a future 'fix' could delete the observation
        instead of the inference, and every negative test would still pass."""
        dev = self.device("sdc", rotational=0, subsystem="scsi")
        self.assertIn("queue_rotational", dev)
        self.assertIs(dev["queue_rotational"], False)

    def test_optical_is_recorded_as_a_scsi_peripheral_type(self):
        """The sr0 regression, carried across the schema change.

        Its meaning survives: a DVD-ROM is never reported as solid-state. Its old
        assertion could not, because it interrogated the retired field.
        """
        dev = self.device("sr0", rotational=0, removable=1, scsi_type=5,
                          devmodel="QEMU DVD-ROM", subsystem="scsi")
        self.assertEqual(dev["scsi_peripheral_type"], 5)
        self.assertIs(dev["kernel_removable"], True)
        self.assertNotIn("SOLID_STATE", repr(dev))

    def test_scsi_peripheral_type_is_null_outside_the_scsi_family(self):
        """Family scoping belongs to the field definition, not to a branch."""
        for sub in ("nvme", "mmc", "virtio"):
            dev = self.device("dev0", rotational=0, scsi_type=5, subsystem=sub)
            self.assertIsNone(dev["scsi_peripheral_type"],
                              "scsi_peripheral_type leaked into %s" % sub)

    def test_subsystem_comes_from_the_kernel_not_the_name(self):
        """D-114: device/subsystem is authoritative; a name prefix is not."""
        self.assertIsNone(self.device("nvme0n1", rotational=0)["kernel_subsystem"])
        self.assertEqual(
            self.device("sdz", rotational=0, subsystem="nvme")["kernel_subsystem"],
            "nvme")

    def test_subsystem_link_is_read_lexically_and_never_resolved(self):
        """FIXTURE-CONFINEMENT-001. The target deliberately does not exist.

        A lexical read returns the name. Any implementation calling realpath, stat or
        exists fails here - and would, in a real fixture, read the HOST's /sys/bus
        while believing it was reading the fixture root.
        """
        dev = self.device("sdq", rotational=0, subsystem="example_fake_subsystem")
        self.assertEqual(dev["kernel_subsystem"], "example_fake_subsystem")

    def test_missing_rotational_attribute_is_unknown_not_assumed(self):
        dev = self.device("sdd", subsystem="scsi")
        self.assertIsNone(dev["queue_rotational"])

    def test_every_device_carries_stable_keys(self):
        """Object shape does not vary by subsystem (SNAP-023 idiom)."""
        keys = {"name", "size_bytes", "kernel_subsystem", "queue_rotational",
                "kernel_removable", "scsi_peripheral_type", "vendor", "model"}
        for sub in ("scsi", "nvme", "mmc", "virtio", None):
            dev = self.device("dev0", rotational=0, subsystem=sub)
            self.assertEqual(set(dev), keys, "shape varies for subsystem=%r" % sub)

    def test_raid_logical_volume_claims_no_physical_disk(self):
        """Measured on a real Smart Array: four disks behind one block device."""
        dev = self.device("sda", rotational=1, removable=0, scsi_type=0,
                          devvendor="HP", devmodel="LOGICAL VOLUME",
                          subsystem="scsi")
        self.assertEqual(dev["vendor"], "HP")
        self.assertEqual(dev["model"], "LOGICAL VOLUME")
        self.assertIs(dev["queue_rotational"], True)
        self.assertNotIn("is_aggregate", dev)


    def test_unknown_when_nothing_says(self):
        # D-114: unknown is expressed by null in each dimension, not by one
        # UNKNOWN token standing in for four different unanswered questions.
        dev = self.device("xyz0")
        self.assertIsNone(dev["kernel_subsystem"])
        self.assertIsNone(dev["queue_rotational"])
        self.assertIsNone(dev["scsi_peripheral_type"])


class TestIncompleteAlwaysExplains(unittest.TestCase):
    """The report tells its reader that incomplete observations explain themselves."""

    def test_partial_without_a_reason_is_refused(self):
        with self.assertRaises(ValueError):
            model.subdomain(model.PARTIAL, {}, method="x")
        with self.assertRaises(ValueError):
            model.subdomain(model.ERROR, {}, method="x")
        with self.assertRaises(ValueError):
            model.subdomain(model.NOT_TESTED, {}, method="x")

    def test_collected_needs_no_reason(self):
        self.assertIsNone(model.subdomain(model.COLLECTED, {})["reason"])

    def test_every_incomplete_subdomain_on_this_host_explains_itself(self):
        for name, block in inventory.collect()["subdomains"].items():
            if block["collection_status"] != model.COLLECTED:
                self.assertTrue(block["reason"],
                                "%s is %s with no reason"
                                % (name, block["collection_status"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
