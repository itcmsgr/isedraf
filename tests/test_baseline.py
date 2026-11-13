# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: v0.4 slice 1 - DEV baseline approval, verification and comparison, end to end.
# Implements: BASE-002, BASE-003, BASE-007, BASE-008, BASE-009, BASE-021, BASE-024,
#             BASE-026, CMP-021, CMP-030, CMP-031, DELTA-006, DELTA-010, EVAL-005, EVAL-007
#
# Synthetic fixture hosts only. The real-host refusals are the lab step of the acceptance
# plan; their evidence stays outside the repository.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="temporary directories only"
# meta:binaries=""
# =============================================================================
"""v0.4 slice 1: `isedraf baseline approve` and the comparison inside `isedraf evaluate`."""
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

from isedraf import audit, canonical, cli, exitcodes, ledger, stateroot, verify  # noqa: E402
from isedraf.baseline import approve, profile, projection, revision          # noqa: E402

SSHD = "PermitRootLogin no\nPasswordAuthentication no\nMatch User alice\n    X11Forwarding no\n"
FILES = {
    "etc/machine-id": "3f9a1c0b7d2e4a68b5c6d7e8f9a0b1c2\n",
    "etc/passwd": "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:Room 12:/home/alice:/bin/sh\n",
    "etc/group": "root:x:0:\nalice:x:1000:\n",
    "etc/shadow": "root:*:19000:0:99999:7:::\nalice:!:19000::::::\n",
    "etc/nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\n",
    "etc/hostname": "fixturehost\n",
    "proc/sys/kernel/hostname": "fixturehost\n",
    "etc/ssh/sshd_config": SSHD,
    "etc/login.defs": "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\n",
    "etc/security/pwquality.conf": "minlen = 12\n",
    "etc/security/faillock.conf": "deny = 5\n",
    "etc/security/limits.conf": "* hard core 0\n",
}
NOT_ROOT = unittest.skipIf(os.geteuid() == 0, "file permissions do not bind root")


def read_json(path):
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


class Store(unittest.TestCase):
    """One fixture host, one DEV store, the CLI as an operator runs it."""

    def setUp(self):
        self.host = tempfile.mkdtemp()
        self.state = tempfile.mkdtemp()
        self.addCleanup(self._cleanup)
        self.store = os.path.join(self.state, "root")
        patcher = mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.store})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("SUDO_USER", None)
        self.files = dict(FILES)

    def _cleanup(self):
        for base, _dirs, names in os.walk(self.host):
            for n in names:
                try:
                    os.chmod(os.path.join(base, n), 0o600)
                except OSError:
                    pass
        shutil.rmtree(self.host, ignore_errors=True)
        shutil.rmtree(self.state, ignore_errors=True)

    def write_host(self, **changes):
        self.files.update(changes)
        for rel, text in self.files.items():
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.exists(path):
                os.chmod(path, 0o600)
            with open(path, "w") as fh:
                fh.write(text)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            try:
                code = cli.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def audit(self, **changes):
        """One committed run; returns its snapshot id."""
        self.write_host(**changes)
        code, out, err = self.run_cli(["audit", "--root", self.host])
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), out + err)
        return ledger.snapshot_records(self.store)[-1]["snapshot_id"]

    def approve(self, sid, expect=exitcodes.OK):
        code, out, err = self.run_cli(["baseline", "approve", sid])
        self.assertEqual(code, expect, out + err)
        return out, err

    def evaluate(self, expect=exitcodes.OK):
        code, out, err = self.run_cli(["evaluate"])
        self.assertEqual(code, expect, out + err)
        return out, err

    def latest_changes(self):
        base = os.path.join(self.store, "evaluations")
        latest = ledger.snapshot_records(self.store)[-1]["snapshot_id"]
        for name in sorted(os.listdir(base)):
            m = read_json(os.path.join(base, name, "manifest.json"))
            if m["snapshot_id"] == latest:
                found = name
        return read_json(os.path.join(base, found, "changes.json"))

    def rows(self):
        return self.latest_changes()["changes"]

    def bl_path(self):
        return os.path.join(self.store, "baselines", "BL-000001.json")

    def current(self):
        return os.path.join(self.store, "baselines", "current")

    def approved_store(self):
        sid = self.audit()
        self.approve(sid)
        return sid


class Approval(Store):
    def test_complete_dev_snapshot_is_approved(self):
        sid = self.approved_store()
        obj = read_json(self.bl_path())
        self.assertEqual(obj["revision_id"], "BL-000001")
        self.assertEqual(obj["baseline_class"], "DEV")
        self.assertEqual(obj["snapshot_id"], sid)
        self.assertEqual(sorted(obj["sections"]), sorted(profile.DEFAULT["required_sections"]))
        p_hash = profile.profile_hash(profile.DEFAULT)
        self.assertEqual(obj["revision_hash"],
                         revision.revision_hash(obj["manifest_hash"], p_hash))
        records = ledger.read_records(self.store)
        self.assertEqual([r["record_core"]["event"] for r in records],
                         ["snapshot_committed", "baseline_approved"])
        rec = records[-1]["record_core"]
        with open(self.bl_path(), "rb") as fh:
            self.assertEqual(rec["artifact_digest"], revision.digest(fh.read()))
        self.assertEqual(verify.verify_store(self.store), [])
        self.assertEqual(os.stat(self.bl_path()).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.current()).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(self.bl_path())).st_mode & 0o777, 0o700)
        self.assertEqual(os.listdir(os.path.join(self.store, "tmp")), [])

    def test_audit_never_creates_baselines(self):
        self.audit()
        self.assertFalse(os.path.exists(os.path.join(self.store, "baselines")))

    def test_second_approval_is_refused(self):
        self.approved_store()
        sid2 = self.audit()
        _out, err = self.approve(sid2, exitcodes.APPROVAL_REFUSED)
        self.assertIn("BASELINE_ALREADY_APPROVED", err)
        self.assertEqual(len(ledger.baseline_records(self.store)), 1)

    @NOT_ROOT
    def test_incomplete_snapshot_is_refused_naming_each_section(self):
        self.write_host(**{"etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n" + SSHD,
                           "etc/ssh/sshd_config.d/10-x.conf": "MaxAuthTries 3\n"})
        os.chmod(os.path.join(self.host, "etc/shadow"), 0)
        os.chmod(os.path.join(self.host, "etc/ssh/sshd_config.d/10-x.conf"), 0)
        code, out, err = self.run_cli(["audit", "--root", self.host])
        sid = ledger.snapshot_records(self.store)[-1]["snapshot_id"]
        _out, err = self.approve(sid, exitcodes.APPROVAL_REFUSED)
        self.assertIn("INCOMPLETE_FOR_BASELINE", err)
        self.assertIn("accounts is PARTIAL", err)
        self.assertIn("ssh is PARTIAL", err)
        self.assertFalse(os.path.exists(os.path.join(self.store, "baselines")))
        self.assertEqual(ledger.baseline_records(self.store), [])

    def test_unknown_snapshot_is_a_usage_error(self):
        self.audit()
        _out, err = self.approve("SDS-20260101T000000Z-0000000000000000", exitcodes.USAGE_OR_ENGINE)
        self.assertFalse(os.path.exists(os.path.join(self.store, "baselines")))

    def test_root_is_refused(self):
        sid = self.audit()
        with mock.patch.object(os, "geteuid", return_value=0):
            self.approve(sid, exitcodes.PRIVILEGE_REFUSED)

    def test_lock_held_is_refused(self):
        sid = self.audit()
        with stateroot.RunLock(self.store):
            self.approve(sid, exitcodes.RUN_IN_PROGRESS)

    def test_no_subcommand_is_usage(self):
        code, _o, _e = self.run_cli(["baseline"])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)


class ClassRefusal(unittest.TestCase):
    """D1: USER_PRODUCTION is refused for its class, before completeness is looked at."""

    def test_user_production_snapshot_is_refused_for_its_class(self):
        host, home = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, host)
        self.addCleanup(shutil.rmtree, home)
        for rel, text in FILES.items():
            path = os.path.join(host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        env = {"XDG_STATE_HOME": os.path.join(home, "state")}
        with mock.patch.dict(os.environ, env):
            os.environ.pop("ISEDRAF_STATE_ROOT", None)
            os.environ.pop("SUDO_USER", None)
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
                code = cli.main(["audit", "--root", host])
            if code == exitcodes.STATE_ROOT_UNUSABLE:
                self.skipTest("the temporary directory's filesystem is not a USER_PRODUCTION "
                              "store here: %s" % err.getvalue())
            store = os.path.join(home, "state", "isedraf")
            sid = ledger.snapshot_records(store)[-1]["snapshot_id"]
            with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
                code = cli.main(["baseline", "approve", sid])
        self.assertEqual(code, exitcodes.APPROVAL_REFUSED)
        self.assertIn("BASELINE_CLASS_NOT_ADMITTED", err.getvalue())
        self.assertFalse(os.path.exists(os.path.join(store, "baselines")))

    def test_build_checks_class_before_completeness(self):
        core = {"state_root": "USER_PRODUCTION", "sections": {}}
        with self.assertRaises(revision.ApprovalRefused) as ctx:
            revision.build("SDS-x", "sha256:" + "0" * 64, core, {}, "USER_PRODUCTION")
        self.assertEqual(ctx.exception.token, "BASELINE_CLASS_NOT_ADMITTED")


class Comparison(Store):
    def test_no_baseline_keeps_the_v03_record(self):
        self.audit()
        self.evaluate()
        changes = self.latest_changes()
        expected = {"comparison_performed": False,
                    "reason": "NO_BASELINE: baseline and delta are v0.4 (D-120)",
                    "baseline_revision": None, "changes": []}
        for k, v in expected.items():
            self.assertEqual(changes[k], v)
        self.assertEqual(sorted(changes),
                         sorted(list(expected) + ["schema_version", "evaluation_id",
                                                  "snapshot_id", "state_root"]))

    def test_ten_unchanged_runs_give_no_rows(self):
        self.approved_store()
        for _ in range(10):
            self.audit()
            self.evaluate()
            changes = self.latest_changes()
            self.assertTrue(changes["comparison_performed"])
            self.assertEqual(changes["changes"], [])
            self.assertEqual(set(s["result"] for s in changes["sections"].values()),
                             {"UNCHANGED"})

    def _one_change(self, section, **files):
        self.approved_store()
        self.audit(**files)
        self.evaluate()
        rows = self.rows()
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["section"], section)
        self.assertEqual(rows[0]["primitive"], "MODIFIED")
        self.assertEqual(rows[0]["interpretation"], "REVIEW_REQUIRED")
        self.assertNotEqual(rows[0]["before_state_hash"], rows[0]["after_state_hash"])

    def test_account_change_is_one_row(self):
        self._one_change("accounts", **{"etc/passwd": FILES["etc/passwd"].replace(
            "/home/alice:/bin/sh", "/home/alice:/bin/bash")})

    def test_ssh_change_is_one_row(self):
        self._one_change("ssh", **{"etc/ssh/sshd_config": SSHD.replace(
            "PermitRootLogin no", "PermitRootLogin yes")})

    def test_loginpolicy_change_is_one_row(self):
        self._one_change("loginpolicy", **{"etc/login.defs": "PASS_MAX_DAYS 60\nPASS_MIN_DAYS 1\n"})

    def test_reorder_is_reported(self):
        self._one_change("ssh", **{"etc/ssh/sshd_config":
                                   "PasswordAuthentication no\nPermitRootLogin no\n"
                                   "Match User alice\n    X11Forwarding no\n"})

    def test_observation_and_provenance_changes_are_quiet(self):
        self.approved_store()
        self.audit(**{"etc/passwd": FILES["etc/passwd"].replace("Room 12", "Room 14"),
                      "etc/ssh/sshd_config": "# a comment\n\n" + SSHD})
        self.evaluate()
        self.assertEqual(self.rows(), [])

    def test_method_change_with_identical_state_is_silent(self):
        self.approved_store()
        methods = dict(audit.METHODS)
        methods["ssh"] = dict(methods["ssh"], collector_version="2")
        with mock.patch.object(audit, "METHODS", methods):
            self.audit()
        self.evaluate()
        changes = self.latest_changes()
        self.assertEqual(changes["changes"], [])
        self.assertTrue(changes["sections"]["ssh"]["method_changed"])
        self.assertFalse(changes["sections"]["accounts"]["method_changed"])

    def test_method_change_with_different_state_is_review_required(self):
        self.approved_store()
        methods = dict(audit.METHODS)
        methods["ssh"] = dict(methods["ssh"], collector_version="2")
        with mock.patch.object(audit, "METHODS", methods):
            self.audit(**{"etc/ssh/sshd_config": SSHD.replace("no\nPassword", "yes\nPassword")})
        self.evaluate()
        (row,) = self.rows()
        self.assertEqual((row["section"], row["interpretation"], row["method_changed"]),
                         ("ssh", "REVIEW_REQUIRED", True))

    @NOT_ROOT
    def test_partial_section_is_not_comparable_never_removed(self):
        self.approved_store()
        self.write_host()
        os.chmod(os.path.join(self.host, "etc/shadow"), 0)
        self.run_cli(["audit", "--root", self.host])
        self.evaluate()
        (row,) = self.rows()
        self.assertEqual((row["section"], row["primitive"]), ("accounts", "NOT_COMPARABLE"))
        self.assertIn("PARTIAL", row["reason"])
        for r in self.latest_changes()["changes"]:
            self.assertNotEqual(r["primitive"], "REMOVED")
            self.assertNotIn("IMPROVEMENT", r.get("interpretation") or "")

    def test_other_host_is_not_applicable(self):
        self.approved_store()
        self.audit(**{"etc/machine-id": "0123456789abcdef0123456789abcdef\n"})
        self.evaluate()
        changes = self.latest_changes()
        self.assertEqual(changes["applicability"], "BASELINE_NOT_APPLICABLE")
        self.assertFalse(changes["comparison_performed"])
        self.assertEqual(changes["changes"], [])

    def test_the_report_shows_the_evaluation_after_a_baseline(self):
        """Regression (found by the D-128 lab, 2026-11-11): the report computed the
        evaluation identity without the baseline and said NO_EVALUATION after approval."""
        from isedraf.report import model as report_model
        self.approved_store()
        sid = self.audit()
        self.evaluate()
        native = report_model.native_results(self.store, sid)
        self.assertEqual(native["status"], "EVALUATED", native)

    def report(self, *flags):
        code, out, err = self.run_cli(["report"] + list(flags))
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)
        return out

    def test_the_report_says_when_there_is_no_baseline(self):
        self.audit()
        self.evaluate()
        md = self.report()
        self.assertIn("## Baseline comparison", md)
        self.assertIn("No approved baseline: nothing was compared.", md)
        self.assertEqual(json.loads(self.report("--json"))["baseline_comparison"]["status"],
                         "NO_BASELINE")

    def test_the_report_shows_an_unchanged_comparison(self):
        sid = self.approved_store()
        self.audit()
        self.evaluate()
        md = self.report()
        self.assertIn("Baseline `BL-000001`, approved from `%s`" % sid, md)
        self.assertIn("No change rows", md)
        self.assertIn("| ssh | UNCHANGED | no |", md)
        cmp_ = json.loads(self.report("--json"))["baseline_comparison"]
        self.assertEqual((cmp_["status"], cmp_["changes"]), ("COMPARED", []))
        self.assertIn("Baseline comparison", self.report("--html"))

    def test_the_report_shows_a_change_as_review_required(self):
        self.approved_store()
        self.audit(**{"etc/ssh/sshd_config": SSHD.replace("PermitRootLogin no",
                                                         "PermitRootLogin yes")})
        self.evaluate()
        md = self.report()
        self.assertIn("- ssh MODIFIED, REVIEW_REQUIRED", md)
        self.assertNotIn("No change rows", md)

    def test_the_report_without_an_evaluation_shows_no_comparison(self):
        self.approved_store()
        self.audit()
        md = self.report()
        self.assertIn("Not shown: the run has not been evaluated", md)

    def assert_report_metadata_matches_latest(self):
        """Regression (owner review 2026-11-12): identity_evidence reused `core` for the
        ledger record, so host_id, created_at, run_id and run_mode came out null."""
        sid = ledger.snapshot_records(self.store)[-1]["snapshot_id"]
        core = read_json(os.path.join(self.store, "snapshots", sid, "manifest.json"))["manifest_core"]
        ident = json.loads(self.report("--json"))["identity_evidence"]
        self.assertEqual(ident["snapshot_id"], sid)
        for field in ("host_id", "created_at", "run_id", "run_mode"):
            self.assertIsNotNone(core.get(field), field)
            self.assertEqual(ident[field], core.get(field), field)
        self.assertEqual(ident["state_root_class"], core.get("state_root"))
        self.assertTrue(ident["verification"]["verified"])

    def test_report_metadata_matches_the_snapshot_before_and_after_approval(self):
        sid = self.audit()
        self.assert_report_metadata_matches_latest()             # before approval
        self.approve(sid)
        self.assert_report_metadata_matches_latest()             # after approval
        self.audit()
        self.evaluate()
        self.assert_report_metadata_matches_latest()             # after a later run

    def test_evaluation_key_names_the_baseline(self):
        self.approved_store()
        self.audit()
        self.evaluate()
        base = os.path.join(self.store, "evaluations")
        latest = ledger.snapshot_records(self.store)[-1]["snapshot_id"]
        (m,) = [read_json(os.path.join(base, n, "manifest.json")) for n in os.listdir(base)
                if read_json(os.path.join(base, n, "manifest.json"))["snapshot_id"] == latest]
        self.assertEqual(m["key"]["baseline_revision"]["revision_id"], "BL-000001")
        self.assertEqual(m["key"]["profile"]["profile_id"], "v0.4-default-1")


class Integrity(Store):
    """BASE-008: exit 5, nothing written, for each way the baseline can stop verifying."""

    def setUp(self):
        Store.setUp(self)
        self.approved_store()
        self.audit()

    def assert_integrity(self, token):
        before = sorted(os.listdir(os.path.join(self.store, "evaluations"))
                        if os.path.isdir(os.path.join(self.store, "evaluations")) else [])
        _out, err = self.evaluate(exitcodes.TOOL_INTEGRITY_FAILURE)
        self.assertIn(token, err)
        after = sorted(os.listdir(os.path.join(self.store, "evaluations"))
                       if os.path.isdir(os.path.join(self.store, "evaluations")) else [])
        self.assertEqual(before, after)

    def rewrite(self, path, data):
        os.chmod(path, 0o600)
        with open(path, "wb") as fh:
            fh.write(data)

    def test_edited_revision(self):
        obj = read_json(self.bl_path())
        obj["tracked_sections"] = ["host_identity"]
        self.rewrite(self.bl_path(), canonical.canonical_bytes(obj))
        self.assert_integrity("BASELINE_ARTIFACT_INVALID")

    def test_forged_revision_with_forged_ledger_tail(self):
        """The digest alone is not trusted: a stored state hash the evidence does not give
        is caught by re-derivation even when the file and its ledger record agree."""
        obj = read_json(self.bl_path())
        obj["sections"]["ssh"]["state_hash"] = "sha256:" + "ab" * 32
        raw = canonical.canonical_bytes(obj)
        self.rewrite(self.bl_path(), raw)
        rows = ledger.read_records(self.store)
        core = dict(rows[1]["record_core"], artifact_digest=revision.digest(raw))
        _c, _canon, rhash = ledger._sealed(core)
        rows[1] = {"record_core": core, "record_hash": rhash}
        # the snapshot record after it chains to the old hash; rebuild the tail.
        for i in range(2, len(rows)):
            c = dict(rows[i]["record_core"], previous_record_hash=rows[i - 1]["record_hash"])
            _c, _canon, h = ledger._sealed(c)
            rows[i] = {"record_core": c, "record_hash": h}
        self.rewrite(ledger.segment_path(self.store),
                     b"".join(canonical.canonical_bytes(r) for r in rows))
        cur = revision.current_bytes(obj, revision.digest(raw))
        self.rewrite(self.current(), cur)
        self.assertEqual(verify.verify_ledger(self.store), [])
        self.assert_integrity("BASELINE_ARTIFACT_INVALID")

    def test_missing_pointer(self):
        os.unlink(self.current())
        self.assert_integrity("BASELINE_POINTER_MISSING")

    def test_mismatching_pointer(self):
        self.rewrite(self.current(), b'{"revision_id":"BL-000001"}\n')
        self.assert_integrity("BASELINE_POINTER_MISMATCH")

    def test_missing_revision(self):
        os.unlink(self.bl_path())
        self.assert_integrity("BASELINE_ARTIFACT_INVALID")

    def test_altered_approved_snapshot(self):
        sid = ledger.baseline_records(self.store)[0]["snapshot_id"]
        path = os.path.join(self.store, "snapshots", sid, "sections", "ssh.json")
        with open(path, "rb") as fh:
            data = fh.read()
        self.rewrite(path, data.replace(b"PermitRootLogin", b"PermitRootLogon"))
        self.assert_integrity("BASELINE_SOURCE_INVALID")

    def test_pointer_without_ledger_record(self):
        rows = ledger.read_records(self.store)
        keep = [r for r in rows if r["record_core"]["event"] != "baseline_approved"]
        for i in range(len(keep)):
            prev = keep[i - 1]["record_hash"] if i else ledger.GENESIS_PREVIOUS
            c = dict(keep[i]["record_core"], sequence=i + 1, previous_record_hash=prev)
            _c, _canon, h = ledger._sealed(c)
            keep[i] = {"record_core": c, "record_hash": h}
        self.rewrite(ledger.segment_path(self.store),
                     b"".join(canonical.canonical_bytes(r) for r in keep))
        self.assert_integrity("BASELINE_LEDGER_INVALID")


class Interrupted(Store):
    """D-127's interrupted-write table, by fault injection at each step."""

    def test_crash_before_link_leaves_only_scratch(self):
        sid = self.audit()
        with mock.patch.object(os, "link", side_effect=OSError("injected")):
            code, _o, _e = self.run_cli(["baseline", "approve", sid])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertFalse(os.path.exists(self.bl_path()))
        self.evaluate()
        self.assertFalse(self.latest_changes()["comparison_performed"])
        self.approve(sid)
        self.assertEqual(os.listdir(os.path.join(self.store, "tmp")), [])

    def test_crash_before_ledger_append(self):
        sid = self.audit()
        with mock.patch.object(ledger, "append", side_effect=OSError("injected")):
            code, _o, _e = self.run_cli(["baseline", "approve", sid])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertTrue(os.path.exists(self.bl_path()))
        self.assertEqual(ledger.baseline_records(self.store), [])
        self.evaluate()
        changes = self.latest_changes()
        self.assertEqual(changes["baseline_revision"], None)
        self.assertEqual(changes["unledgered_revision"], "BL-000001")
        other = self.audit()
        _o, err = self.approve(other, exitcodes.APPROVAL_REFUSED)
        self.assertIn("UNLEDGERED_REVISION_PRESENT", err)
        out, _e = self.approve(sid)
        self.assertIn("interrupted approval was completed", out)
        self.assertEqual(len(ledger.baseline_records(self.store)), 1)
        self.evaluate()

    def test_crash_before_pointer(self):
        sid = self.audit()
        with mock.patch.object(approve, "_write_current", side_effect=OSError("injected")):
            code, _o, _e = self.run_cli(["baseline", "approve", sid])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertEqual(len(ledger.baseline_records(self.store)), 1)
        self.assertFalse(os.path.exists(self.current()))
        _out, err = self.evaluate(exitcodes.TOOL_INTEGRITY_FAILURE)
        self.assertIn("BASELINE_POINTER_MISSING", err)
        other = self.audit()
        _o, err = self.approve(other, exitcodes.APPROVAL_REFUSED)
        self.assertIn("BASELINE_ALREADY_APPROVED", err)
        out, _e = self.approve(sid)
        self.assertIn("interrupted approval was completed", out)
        self.evaluate()
        self.assertTrue(self.latest_changes()["comparison_performed"])


class Projection(unittest.TestCase):
    """D-127 projection rules on hand-made sections."""

    def section(self, records):
        return {"schema_version": 2, "section": "ssh",
                "method": {"collector_id": "isedraf.ssh", "collector_version": "1",
                           "parser_version": "1"},
                "collection_status": "COLLECTED", "reason": None,
                "evidence": {"status": "COLLECTED", "reason": None, "source": "/",
                             "anomalies": [], "provenance": {}, "records": records}}

    def rec(self, value, line=1):
        return {"kind": "DIRECTIVE", "keyword": "permitrootlogin",
                "keyword_raw": "PermitRootLogin", "value": value, "scope": "GLOBAL",
                "match_index": None, "match_criteria": None, "source_path": "/x",
                "source_line": line, "ordinal": line}

    def test_provenance_is_out_state_is_in(self):
        a = projection.project("ssh", self.section([self.rec("no", 1)]))
        b = projection.project("ssh", self.section([self.rec("no", 9)]))
        self.assertEqual(a, b)
        self.assertNotIn("source_line", a["lists"]["records"][0])

    def test_order_and_duplicates_are_kept(self):
        one = projection.state_hash("ssh", self.section([self.rec("no"), self.rec("yes")]))
        two = projection.state_hash("ssh", self.section([self.rec("yes"), self.rec("no")]))
        self.assertNotEqual(one, two)
        dup = projection.project("ssh", self.section([self.rec("no"), self.rec("no")]))
        self.assertEqual(len(dup["lists"]["records"]), 2)

    def test_null_and_missing_differ(self):
        with_null = self.rec("no")
        without = dict(with_null)
        del without["match_criteria"]
        self.assertNotEqual(projection.state_hash("ssh", self.section([with_null])),
                            projection.state_hash("ssh", self.section([without])))

    def test_unclassified_field_is_not_projectable(self):
        bad = dict(self.rec("no"), surprise=1)
        with self.assertRaises(projection.NotProjectable) as ctx:
            projection.project("ssh", self.section([bad]))
        self.assertEqual(ctx.exception.token, "UNCLASSIFIED_FIELD")

    def test_unknown_section_key_is_not_projectable(self):
        sect = self.section([])
        sect["evidence"]["extra"] = []
        with self.assertRaises(projection.NotProjectable) as ctx:
            projection.project("ssh", sect)
        self.assertEqual(ctx.exception.token, "UNKNOWN_SECTION_FIELD")

    def test_nested_container(self):
        acct = {"name": "a", "name_encoding": "UTF8", "name_bytes_hex": "61",
                "name_non_ascii": False, "uid": 1, "primary_gid": 1, "home": "/", "shell": "/",
                "gecos": "", "nss_source": "files", "passwd_line": 1, "passwd_anomalies": [],
                "shadow_record": "ABSENT", "shadow": None}
        sect = {"evidence": dict((k, None) for k in projection.SECTIONS["accounts"]["outside"])}
        sect["evidence"].update(local_accounts=[acct], local_groups=[])
        null_shadow = projection.project("accounts", sect)["lists"]["local_accounts"][0]
        self.assertIn("shadow", null_shadow)
        self.assertIsNone(null_shadow["shadow"])
        self.assertNotIn("gecos", null_shadow)
        acct["shadow"] = {"password_state": {"lock_prefix": False, "content": "X",
                                             "hash_scheme": None}, "max_days": 5}
        full = projection.project("accounts", sect)["lists"]["local_accounts"][0]
        self.assertEqual(full["shadow.max_days"], 5)
        self.assertEqual(full["shadow.password_state.content"], "X")
        self.assertNotIn("shadow", full)

    def test_fingerprint_follows_versions(self):
        a = self.section([])
        b = self.section([])
        b["method"]["parser_version"] = "2"
        self.assertNotEqual(projection.method_fingerprint("ssh", a),
                            projection.method_fingerprint("ssh", b))


if __name__ == "__main__":
    unittest.main(verbosity=1)
