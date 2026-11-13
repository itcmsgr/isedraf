# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: `sudo isedraf baseline approve` - root decides from metadata, reduced side builds.
# Implements: D-128, AUTH-034, AUTH-022, AUTH-033, BASE-011, BASE-012, BASE-013
#
# As the evaluation route tests do: the store owner is patched to the test user and the
# reduced approver and evaluator run as real subprocesses, minus setpriv (which needs root).
# The lab acceptance runs the real route under root on DEB and RPM platforms.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="temporary directories only"
# meta:binaries=""
# =============================================================================
"""AUTH-034: the system-store baseline route, and the system readers that see its records."""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.abspath(os.path.join(HERE, "..", "lib"))
sys.path.insert(0, LIB)
sys.path.insert(0, HERE)

from isedraf import canonical, cli, ledger, stateroot                       # noqa: E402
from isedraf.baseline import approve, revision                              # noqa: E402
from isedraf.exitcodes import (APPROVAL_REFUSED, OK, PRIVILEGE_REFUSED,      # noqa: E402
                               STATE_ROOT_UNUSABLE, TOOL_INTEGRITY_FAILURE, USAGE_OR_ENGINE)
from isedraf.launcher import (baselineunit, evalunit, outer, reportunit,     # noqa: E402
                              store)
from isedraf.supervisor import frame                                        # noqa: E402
import test_evaluate_route as route                                         # noqa: E402

UID, GID = os.getuid(), os.getgid()
CLASS = stateroot.DEV
SSHD = "PermitRootLogin no\nPasswordAuthentication no\n"
HOST = dict(route.HOST, **{
    "etc/ssh/sshd_config": SSHD,
    "etc/login.defs": "PASS_MAX_DAYS 90\n",
    "etc/security/pwquality.conf": "minlen = 12\n",
    "etc/security/faillock.conf": "deny = 5\n",
    "etc/security/limits.conf": "* hard core 0\n",
    "etc/hostname": "fixturehost\n",
})
NOT_ROOT = unittest.skipIf(os.geteuid() == 0, "file permissions do not bind root")


def approver_argv(log):
    return [sys.executable, "-IB", "-c",
            "import sys; sys.path.insert(0, %r); sys.stderr = open(%r, 'w'); "
            "from isedraf.launcher import baselineunit, approver; baselineunit.CLASS = %r; "
            "approver.reduction_check = lambda: []; "
            "sys.exit(approver.main([]))" % (LIB, log, CLASS)]


def fake_approver(items):
    """A process that answers with the given (name, bytes) items, whatever it was sent."""
    data = frame.encode([frame.item(frame.ENTRY, n.encode("ascii"), frame.READ_OK,
                                    {"mode": 0o100600, "uid": UID, "gid": GID, "size": len(b)},
                                    b) for n, b in items])
    return [sys.executable, "-c", "import sys; sys.stdin.buffer.read(); "
            "sys.stdout.buffer.write(bytes.fromhex(%r))" % data.hex()]


class Route(route.NoLeakedPipe, unittest.TestCase):

    def setUp(self):
        base = tempfile.mkdtemp()
        self.base = base
        self.addCleanup(self._cleanup)
        self.host = os.path.join(base, "host")
        self.root = os.path.join(base, "root")
        self.write_host()
        self.audit()
        for patch in (mock.patch.object(store, "OWNER_UID", UID),
                      mock.patch.object(store, "OWNER_GID", GID),
                      mock.patch.object(evalunit, "CLASS", CLASS),
                      mock.patch.object(baselineunit, "CLASS", CLASS)):
            patch.start()
            self.addCleanup(patch.stop)
        route.private_catalog(self)
        del baselineunit._stop[:]
        del evalunit._stop[:]

    def _cleanup(self):
        for b, _d, names in os.walk(self.base):
            for n in names:
                try:
                    os.chmod(os.path.join(b, n), 0o600)
                except OSError:
                    pass
        shutil.rmtree(self.base, True)

    def write_host(self, **changes):
        files = dict(HOST, **changes)
        for rel, text in files.items():
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.exists(path):
                os.chmod(path, 0o600)
            with open(path, "w") as fh:
                fh.write(text)

    def audit(self, **changes):
        if changes:
            self.write_host(**changes)
        with mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.root}):
            code = cli.cmd_audit(type("A", (), {"root": self.host})(), out=io.StringIO(),
                                 err=io.StringIO())
        self.assertIn(code, (0, 2))
        return ledger.snapshot_records(self.root)[-1]["snapshot_id"]

    def approve(self, argv=None):
        out, err = io.StringIO(), io.StringIO()
        log = os.path.join(self.base, "approver.log")
        code = baselineunit.run(self.root, err, out, engine_uid=UID,
                                argv=argv or approver_argv(log))
        reduced = ""
        if os.path.exists(log):
            with open(log) as fh:
                reduced = fh.read()
            os.unlink(log)
        return code, out.getvalue(), err.getvalue() + reduced

    def evaluate(self):
        out, err = io.StringIO(), io.StringIO()
        log = os.path.join(self.base, "evaluator.log")
        code = evalunit.run(self.root, err, out, engine_uid=UID,
                            argv=route.evaluator_argv(log))
        reduced = ""
        if os.path.exists(log):
            with open(log) as fh:
                reduced = fh.read()
            os.unlink(log)
        return code, out.getvalue(), err.getvalue() + reduced

    def changes(self):
        latest = ledger.snapshot_records(self.root)[-1]["snapshot_id"]
        base = os.path.join(self.root, "evaluations")
        for name in sorted(os.listdir(base)):
            with open(os.path.join(base, name, "changes.json"), "rb") as fh:
                obj = json.loads(fh.read().decode("utf-8"))
            if obj["snapshot_id"] == latest:
                found = obj
        return found

    def bl(self):
        return os.path.join(self.root, "baselines", "BL-000001.json")

    def current(self):
        return os.path.join(self.root, "baselines", "current")

    # -- the route ----------------------------------------------------------------------

    def test_the_outer_entry_runs_the_baseline_unit_with_the_audit_properties(self):
        argv = outer.baseline_unit_argv("RUN-20261111T000000Z-0123456789abcdef")
        self.assertTrue(argv[5].startswith("--unit=isedraf-baseline-RUN-"))
        for prop in outer.PROPERTIES:
            self.assertIn(prop, argv)
        self.assertIn("isedraf.launcher.baselineunit", argv[-2])
        with self.assertRaises(ValueError):
            outer.baseline_unit_argv("/var/lib/isedraf")

    def test_a_named_snapshot_or_any_other_argument_is_refused_under_root(self):
        for argv in (["baseline", "approve", "SDS-20261111T000000Z-0123456789abcdef"],
                     ["baseline"], ["baseline", "approve", "--snapshot", "x"]):
            err = io.StringIO()
            with mock.patch.object(os, "geteuid", return_value=0):
                self.assertEqual(outer.main(argv, err), PRIVILEGE_REFUSED, argv)
            self.assertIn("sudo isedraf baseline approve", err.getvalue())

    def test_the_approver_command_is_the_engine_reduction_and_a_fixed_entry(self):
        argv = baselineunit.approve_argv()
        self.assertEqual(argv[:9], ["/usr/bin/setpriv", "--reuid=isedraf", "--regid=isedraf",
                                    "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
                                    "--bounding-set=-all", "--no-new-privs", "/usr/bin/python3"])
        self.assertIn("isedraf.launcher.approver", argv[-1])

    def test_the_latest_complete_run_is_approved_and_then_compared(self):
        sid = ledger.snapshot_records(self.root)[-1]["snapshot_id"]
        code, out, err = self.approve()
        self.assertEqual(code, OK, err)
        self.assertIn("approved in the system store", out)
        with open(self.bl(), "rb") as fh:
            obj = json.loads(fh.read().decode("utf-8"))
        self.assertEqual(obj["snapshot_id"], sid)
        self.assertEqual(os.stat(self.bl()).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(self.bl())).st_mode & 0o777, 0o700)
        self.assertEqual([r["record_core"]["event"] for r in ledger.read_records(self.root)],
                         ["snapshot_committed", "baseline_approved"])
        code, _o, err = self.evaluate()
        self.assertEqual(code, OK, err)
        changes = self.changes()
        self.assertTrue(changes["comparison_performed"])
        self.assertEqual(changes["changes"], [])

    def test_a_newer_changed_run_is_compared_with_the_approved_one(self):
        self.assertEqual(self.approve()[0], OK)
        self.audit(**{"etc/ssh/sshd_config": SSHD.replace("no\nPass", "yes\nPass")})
        code, _o, err = self.evaluate()
        self.assertEqual(code, OK, err)
        (row,) = self.changes()["changes"]
        self.assertEqual((row["section"], row["interpretation"]), ("ssh", "REVIEW_REQUIRED"))

    def test_the_report_route_reads_the_latest_run_after_a_baseline_record(self):
        self.assertEqual(self.approve()[0], OK)
        items = reportunit.acquire(self.root, UID)
        names = [i["name"].decode("ascii") for i in items]
        sid = ledger.snapshot_records(self.root)[-1]["snapshot_id"]
        self.assertIn("snapshots/%s/manifest.json" % sid, names)

    @NOT_ROOT
    def test_an_incomplete_run_is_refused_naming_each_section(self):
        os.chmod(os.path.join(self.host, "etc/shadow"), 0)
        self.audit()
        code, _o, err = self.approve()
        self.assertEqual(code, APPROVAL_REFUSED, err)
        self.assertIn("INCOMPLETE_FOR_BASELINE", err)
        self.assertIn("accounts is PARTIAL", err)
        self.assertFalse(os.path.exists(os.path.join(self.root, "baselines")))
        self.assertEqual(ledger.baseline_records(self.root), [])

    def test_a_second_approval_is_refused_by_the_root_side(self):
        self.assertEqual(self.approve()[0], OK)
        self.audit()
        code, _o, err = self.approve(argv=["/nonexistent-approver"])
        self.assertEqual(code, APPROVAL_REFUSED, err)
        self.assertIn("BASELINE_ALREADY_APPROVED", err)

    def test_an_interrupted_pointer_is_completed_for_the_recorded_snapshot(self):
        self.assertEqual(self.approve()[0], OK)
        recorded = ledger.baseline_records(self.root)[0]["snapshot_id"]
        os.unlink(self.current())
        code, _o, err = self.evaluate()
        self.assertEqual(code, TOOL_INTEGRITY_FAILURE, err)
        self.assertIn("BASELINE_POINTER_MISSING", err)
        self.audit()                                   # a newer run does not change it
        code, out, err = self.approve()
        self.assertEqual(code, OK, err)
        self.assertIn("completed", out)
        with open(self.bl(), "rb") as fh:
            self.assertEqual(json.loads(fh.read().decode("utf-8"))["snapshot_id"], recorded)
        self.assertEqual(self.evaluate()[0], OK)

    def test_an_interruption_before_the_ledger_record_is_resumed(self):
        with mock.patch.object(ledger, "append", side_effect=OSError("injected")):
            code, _o, _e = self.approve()
        self.assertEqual(code, USAGE_OR_ENGINE)
        self.assertTrue(os.path.exists(self.bl()))
        self.assertEqual(ledger.baseline_records(self.root), [])
        code, out, err = self.approve()
        self.assertEqual(code, OK, err)
        self.assertIn("completed", out)
        self.assertEqual(len(ledger.baseline_records(self.root)), 1)

    def test_a_pointer_without_a_ledger_record_is_an_integrity_failure(self):
        os.makedirs(os.path.dirname(self.current()), 0o700)
        with open(self.current(), "wb") as fh:
            fh.write(b"{}\n")
        os.chmod(self.current(), 0o600)
        code, _o, err = self.approve(argv=["/nonexistent-approver"])
        self.assertEqual(code, TOOL_INTEGRITY_FAILURE, err)

    def test_a_non_conforming_baselines_directory_is_refused(self):
        os.makedirs(os.path.join(self.root, "baselines"), 0o755)
        os.chmod(os.path.join(self.root, "baselines"), 0o755)
        code, _o, err = self.approve()
        self.assertEqual(code, STATE_ROOT_UNUSABLE, err)

    def test_an_answer_for_another_snapshot_is_refused(self):
        _action, obj, raw = approve.plan(
            self.root, CLASS, ledger.snapshot_records(self.root)[-1]["snapshot_id"],
            lambda s: __import__("isedraf.evaluate.run", fromlist=["run"]).verified_run(
                self.root, s))
        forged = dict(obj, snapshot_id="SDS-20260101T000000Z-0000000000000000")
        code, _o, err = self.approve(argv=fake_approver(
            [("action", b"NEW"), ("baselines/BL-000001.json", canonical.canonical_bytes(forged))]))
        self.assertEqual(code, USAGE_OR_ENGINE, err)
        self.assertFalse(os.path.exists(os.path.join(self.root, "baselines")))

    def test_an_answer_with_another_action_is_refused(self):
        _action, _obj, raw = approve.plan(
            self.root, CLASS, ledger.snapshot_records(self.root)[-1]["snapshot_id"],
            lambda s: __import__("isedraf.evaluate.run", fromlist=["run"]).verified_run(
                self.root, s))
        code, _o, err = self.approve(argv=fake_approver(
            [("action", b"WRITE_POINTER"), ("baselines/BL-000001.json", raw)]))
        self.assertEqual(code, USAGE_OR_ENGINE, err)
        self.assertIn("action", err)
        self.assertFalse(os.path.exists(os.path.join(self.root, "baselines")))

    def test_a_stop_before_the_first_write_writes_nothing(self):
        baselineunit._stop.append(15)
        code, _o, _e = self.approve()
        self.assertEqual(code, baselineunit.INTERRUPTED)
        self.assertFalse(os.path.exists(self.bl()))
        self.assertEqual(ledger.baseline_records(self.root), [])

    def test_a_tampered_baseline_fails_the_system_evaluation(self):
        self.assertEqual(self.approve()[0], OK)
        with open(self.bl(), "rb") as fh:
            obj = json.loads(fh.read().decode("utf-8"))
        obj["tracked_sections"] = ["host_identity"]
        with open(self.bl(), "wb") as fh:
            fh.write(canonical.canonical_bytes(obj))
        code, _o, err = self.evaluate()
        self.assertEqual(code, TOOL_INTEGRITY_FAILURE, err)
        self.assertIn("BASELINE_ARTIFACT_INVALID", err)


    def rendered_identity(self):
        from isedraf.launcher import renderer
        data = frame.encode(reportunit.acquire(self.root, UID))
        out, err = io.StringIO(), io.StringIO()
        code = renderer.render("json", data, out, err)
        self.assertIn(code, (0, 2), err.getvalue())
        return json.loads(out.getvalue())["identity_evidence"]

    def assert_matches_latest(self):
        sid = ledger.snapshot_records(self.root)[-1]["snapshot_id"]
        with open(os.path.join(self.root, "snapshots", sid, "manifest.json"), "rb") as fh:
            core = json.loads(fh.read().decode("utf-8"))["manifest_core"]
        ident = self.rendered_identity()
        self.assertEqual(ident["snapshot_id"], sid)
        for field in ("host_id", "created_at", "run_id", "run_mode"):
            self.assertIsNotNone(core.get(field), field)
            self.assertEqual(ident[field], core.get(field), field)
        self.assertTrue(ident["verification"]["verified"])

    def test_report_metadata_matches_the_snapshot_before_and_after_approval(self):
        """Regression (owner review 2026-11-12) through the Full Audit report route: the
        root-side frame and the reduced renderer, before approval, after it, after a later run."""
        self.assert_matches_latest()
        self.assertEqual(self.approve()[0], OK)
        self.assert_matches_latest()
        self.audit()
        self.assert_matches_latest()


class Readers(unittest.TestCase):
    """The system-store readers tell snapshot records from baseline records (D-128)."""

    def test_latest_snapshot_skips_a_trailing_baseline_record(self):
        cores = [{"event": "snapshot_committed",
                  "snapshot_id": "SDS-20261111T000000Z-0000000000000001", "manifest_hash": "a"},
                 {"event": "baseline_approved",
                  "snapshot_id": "SDS-20261111T000000Z-0000000000000001", "manifest_hash": "a"},
                 {"event": "snapshot_committed",
                  "snapshot_id": "SDS-20261111T000000Z-0000000000000002", "manifest_hash": "b"},
                 {"event": "baseline_approved",
                  "snapshot_id": "SDS-20261111T000000Z-0000000000000001", "manifest_hash": "a"}]
        self.assertEqual(reportunit.latest_snapshot(cores),
                         ("SDS-20261111T000000Z-0000000000000002", "b"))
        with self.assertRaises(reportunit.Refused):
            reportunit.baseline_record(cores)

    def test_no_snapshot_record_is_no_committed_run(self):
        with self.assertRaises(reportunit.NoCommittedRun):
            reportunit.latest_snapshot([{"event": "baseline_approved"}])


if __name__ == "__main__":
    unittest.main(verbosity=1)
