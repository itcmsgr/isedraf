# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: ISE-SSH-003, -004, -005 and ISE-STORAGE-001, every rule of their definitions.
# Implements: D-132, D-111, EVAL-004
#
# The sections carry only the fields the evaluators read, shaped as the ssh and mounts collectors
# shape them. The lab hosts' real values (PermitRootLogin without-password, HostbasedAuthentication
# no, IgnoreRhosts yes, /dev/shm rw,nosuid,nodev) are among the cases.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""D-132: the second v0.6 batch of native criteria."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import catalog                          # noqa: E402
from isedraf.evaluate import criteria                # noqa: E402

DIGESTS = {"manifest.json": "m", "sections/ssh.json": "s", "sections/mounts.json": "t"}
COV = {"operation_id": "resolve_sshd_effective_config_v1", "status": "COLLECTED"}


def ssh(settings, coverage=(COV,)):
    records = [{"kind": "RESOLVED_SETTING", "keyword": k, "value": v} for k, v in settings]
    return {"section": "ssh", "schema_version": criteria.SECTION_SCHEMA_VERSION,
            "collection_status": "COLLECTED",
            "evidence": {"records": records, "provenance": {"coverage": list(coverage)}}}


def mounts(entries, source="/proc/1/mountinfo", active_status="COLLECTED", complete=True):
    records = [{"mount_point": mp, "fstype": "tmpfs", "mount_options": opts, "parse_status": "OK",
                "source_path": source} for mp, opts in entries]
    return {"section": "mounts", "schema_version": criteria.SECTION_SCHEMA_VERSION,
            "collection_status": "COLLECTED",
            "evidence": {"records": [], "provenance": {
                "comparison": {"active_status": active_status},
                "active": {"universe_complete": complete, "records": records}}}}


def run(cid, section):
    registry, _raw = catalog.load()
    fn, _p, _n = criteria.EVALUATORS[cid]
    return fn(section, catalog.criterion(registry, cid), DIGESTS)


class PermitRootLogin(unittest.TestCase):

    def result(self, value):
        return run("ISE-SSH-003", ssh([("permitrootlogin", value)]))

    def test_each_value(self):
        self.assertEqual(self.result("no")[0], "PASS")
        self.assertEqual(self.result("yes")[0], "FAIL")
        self.assertEqual(self.result("forced-commands-only")[0:2],
                         ("MANUAL_REVIEW", "ROOT_LOGIN_FORCED_COMMANDS"))
        self.assertEqual(self.result("bogus")[0:2], ("NOT_EVALUATED", "SETTING_VALUE_UNKNOWN"))

    def test_the_two_names_of_prohibit_password_give_one_result_and_keep_the_value(self):
        a, b = self.result("prohibit-password"), self.result("without-password")
        self.assertEqual(a[0:2], ("MANUAL_REVIEW", "ROOT_LOGIN_WITHOUT_PASSWORD"))
        self.assertEqual(b[0:2], a[0:2])
        self.assertEqual(b[3], [{"permitrootlogin": "without-password"}])      # the lab hosts
        self.assertIn("without-password", b[2])

    def test_missing_or_unrun_is_not_evaluated(self):
        self.assertEqual(run("ISE-SSH-003", ssh([]))[0:2],
                         ("NOT_EVALUATED", "SETTING_NOT_REPORTED_ONCE"))
        self.assertEqual(run("ISE-SSH-003", ssh([("permitrootlogin", "no")], coverage=()))[0:2],
                         ("NOT_EVALUATED", "SOURCE_NOT_TESTED"))


class Hostbased(unittest.TestCase):

    def test_each_value(self):
        f = lambda v: run("ISE-SSH-004", ssh([("hostbasedauthentication", v)]))   # noqa: E731
        self.assertEqual(f("no")[0], "PASS")
        self.assertEqual(f("yes")[0], "FAIL")
        self.assertIn("host-based authentication", f("yes")[2])
        self.assertEqual(f("maybe")[0], "NOT_EVALUATED")


class IgnoreRhosts(unittest.TestCase):

    def result(self, hostbased, ignore):
        return run("ISE-SSH-005", ssh([("hostbasedauthentication", hostbased),
                                       ("ignorerhosts", ignore)]))

    def test_not_applicable_when_host_based_authentication_is_off(self):
        self.assertEqual(self.result("no", "yes")[0:2], ("NOT_APPLICABLE", "HOSTBASED_OFF"))
        self.assertEqual(self.result("no", "no")[0], "NOT_APPLICABLE")

    def test_with_host_based_authentication_on(self):
        self.assertEqual(self.result("yes", "yes")[0], "PASS")
        r = self.result("yes", "no")
        self.assertEqual(r[0:2], ("FAIL", "USER_TRUST_FILES_USED"))
        self.assertIn(".rhosts and .shosts", r[2])
        r = self.result("yes", "shosts-only")
        self.assertEqual(r[0:2], ("FAIL", "USER_SHOSTS_USED"))
        self.assertIn(".shosts", r[2])

    def test_missing_or_unknown_is_not_evaluated(self):
        self.assertEqual(run("ISE-SSH-005", ssh([("hostbasedauthentication", "yes")]))[0],
                         "NOT_EVALUATED")
        self.assertEqual(self.result("yes", "sometimes")[0], "NOT_EVALUATED")
        self.assertEqual(self.result("perhaps", "yes")[0], "NOT_EVALUATED")


class DevShm(unittest.TestCase):

    def test_nosuid_passes_and_its_absence_fails_with_the_options_shown(self):
        r = run("ISE-STORAGE-001", mounts([("/", ["rw"]), ("/dev/shm", ["rw", "nosuid", "nodev"])]))
        self.assertEqual(r[0:2], ("PASS", "DEV_SHM_NOSUID"))
        r = run("ISE-STORAGE-001", mounts([("/dev/shm", ["rw", "nodev"])]))
        self.assertEqual(r[0:2], ("FAIL", "DEV_SHM_SUID_ALLOWED"))
        self.assertEqual(r[3][0]["mount_options"], ["rw", "nodev"])

    def test_an_unclear_mount_or_namespace_is_not_evaluated(self):
        cases = {
            "HOST_NAMESPACE_NOT_ESTABLISHED": mounts([("/dev/shm", ["nosuid"])],
                                                     source="/proc/self/mountinfo"),
            "NO_DEV_SHM_MOUNT": mounts([("/", ["rw"])]),
            "DEV_SHM_MOUNTED_MORE_THAN_ONCE": mounts([("/dev/shm", ["nosuid"]),
                                                      ("/dev/shm", ["rw"])]),
            "ACTIVE_MOUNTS_NOT_COLLECTED": mounts([("/dev/shm", ["nosuid"])], complete=False),
        }
        for reason, section in cases.items():
            self.assertEqual(run("ISE-STORAGE-001", section)[0:2], ("NOT_EVALUATED", reason))


class Registry(unittest.TestCase):

    def test_the_records_declare_exactly_what_the_evaluators_read(self):
        registry, _raw = catalog.load()
        for cid in ("ISE-SSH-003", "ISE-SSH-004", "ISE-SSH-005", "ISE-STORAGE-001"):
            record = catalog.criterion(registry, cid)
            self.assertTrue(criteria.pointers_match(record, criteria.EVALUATORS[cid][1]), cid)
            self.assertEqual(record["introduced_in"], "0.6.0")
            self.assertEqual(record["minimum_run"]["route"], "FULL_AUDIT")


if __name__ == "__main__":
    unittest.main(verbosity=0)
