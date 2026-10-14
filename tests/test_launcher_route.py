# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The Full Audit route: outer refusals, constant unit, and the in-unit launcher.
# Implements: AUTH-019, AUTH-020, AUTH-021, AUTH-022, AUTH-023, AUTH-026, AUTH-027, EXEC-010,
#             IQ-063
#
# v0.2 P5b-3. Unprivileged. The outer entry is exercised with euid replaced and its relay
# captured (IQ-062); the in-unit launcher runs end to end in a temporary store whose owner
# constants are this test's uid, with stand-in programs in place of the reduced engine and its cleanup
# that use exactly the same descriptor placement. The stand-in engine asks the supervisor
# for read_shadow_v1 over fds 3 and 4 and must be refused: the channel is served, and
# nothing is enabled. Root, setpriv and systemd themselves are proven on the lab corpus (P6).
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3,true,false"
# =============================================================================
"""v0.2 P5b-3: outer entry refusals, the constant systemd-run command, the unit launcher."""
import fcntl
import io
import os
import shutil
import signal
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "lib")
sys.path.insert(0, LIB)
sys.path.insert(0, os.path.join(HERE, "..", "scripts", "ci"))
sys.path.insert(0, HERE)

from isedraf import ledger, snapshot, stateroot, verify              # noqa: E402
from isedraf.launcher import engine, outer, store, unit              # noqa: E402
from isedraf.supervisor import contracts                             # noqa: E402
import check_privileged_operations as gate                           # noqa: E402
import test_evidence_limits as fixtures                              # noqa: E402

UID, GID = os.getuid(), os.getgid()

ENGINE = r'''
import os, sys
sys.path.insert(0, %(lib)r)
from isedraf import fixedop, identity, snapshot
from isedraf.supervisor import protocol
mode = %(mode)r
channel = fixedop.Channel(3, 4)
res = channel.request("read_shadow_v1")
if res["status"] != protocol.COMPLETED or res["bytes"] != %(shadow)r:
    sys.exit(3)
os.close(3); os.close(4)
run_id = os.path.basename(os.getcwd())
ident = identity.collect(%(host)r + "/etc/machine-id")
created_at, sid, _r, _e = snapshot.new_ids()
built = snapshot.build(ident, sid, run_id, created_at, "SYSTEM_PRODUCTION", "0.0.0",
                       run_mode="FULL_AUDIT")
os.umask(0o077)
snapshot.write_bundle(".", built)
if mode == "fail":
    sys.exit(64)              # a complete, valid bundle - and a failed engine
if mode == "slow":
    import time
    time.sleep(30)            # IQ-063: still running when the stop arrives
if mode == "extra":
    with open("notes.txt", "w") as fh:
        fh.write("x")
sys.exit(0)
'''

CLEAN = ("import os, shutil\nfor n in os.listdir('.'):\n"
         "    shutil.rmtree(n) if os.path.isdir(n) and not os.path.islink(n) else os.unlink(n)\n")


def euid0():
    return mock.patch.object(os, "geteuid", return_value=0)


class OuterEntry(unittest.TestCase):

    def call(self, argv):
        err = io.StringIO()
        return outer.main(argv, err), err.getvalue()

    def test_anything_but_audit_and_report_is_refused_with_the_auth019_message(self):
        # AUTH-032: `report`, alone or with one format, is the one more root invocation;
        # nothing that writes into the store or names a path gets through.
        with euid0():
            for argv in ([], ["audit", "--root", "/tmp"], ["identity"], ["audit", "audit"],
                         ["report", "--save"], ["report", "--profile", "/tmp/p.json"],
                         ["report", "--json", "--html"], ["report", "/var/lib/isedraf"],
                         ["report", "--json", "--save"], ["inventory"]):
                code, err = self.call(argv)
                self.assertEqual(code, 70, argv)
                self.assertIn("runs only `sudo isedraf audit` (Full Audit) and `sudo isedraf "
                              "report`", err)

    def test_a_report_invocation_runs_the_read_only_report_unit(self):
        self.environment()
        for argv, fmt in ((["report"], "markdown"), (["report", "--json"], "json"),
                          (["report", "--html"], "html")):
            with mock.patch.object(outer, "relay", return_value=0) as relay:
                self.call(argv)
            unit_argv, env = relay.call_args[0][:2]
            self.assertEqual(unit_argv[-1], fmt)
            self.assertEqual(unit_argv, outer.report_unit_argv(unit_argv[-2], fmt))
            self.assertTrue(unit_argv[5].startswith("--unit=isedraf-report-RUN-"))
            self.assertEqual(env, outer.EXEC_ENVIRONMENT)

    def test_a_non_root_caller_is_refused(self):
        code, _err = self.call(["audit"])
        self.assertEqual(code, 70)

    def test_a_package_outside_the_root_owned_install_root_is_unsafe(self):
        with euid0():
            code, err = self.call(["audit"])
        self.assertEqual(code, 64)
        self.assertIn("ENGINE_UNSAFE_INSTALL", err)

    def environment(self, release="ID=debian\nVERSION_ID=\"12\"\n", systemd=True,
                    getent="/bin/true"):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        path = os.path.join(base, "os-release")
        with open(path, "w") as fh:
            fh.write(release)
        runtime = base if systemd else os.path.join(base, "absent")
        patches = [euid0(), mock.patch.object(outer, "unsafe_install", return_value=None),
                   mock.patch.object(outer, "OS_RELEASE", path),
                   mock.patch.object(outer, "SYSTEMD_RUNTIME", runtime),
                   mock.patch.object(outer, "SYSTEMD_RUN", "/bin/true"),
                   mock.patch.object(outer, "GETENT", getent)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_an_unsupported_platform_is_refused(self):
        self.environment(release="ID=fedora\nVERSION_ID=44\n")
        code, err = self.call(["audit"])
        self.assertEqual(code, 70)
        self.assertIn("FULL_AUDIT_UNSUPPORTED", err)

    def test_a_host_without_systemd_is_refused(self):
        self.environment(systemd=False)
        code, err = self.call(["audit"])
        self.assertEqual(code, 70)
        self.assertIn("FULL_AUDIT_UNSUPPORTED", err)

    def test_a_missing_isedraf_account_is_refused(self):
        self.environment(getent="/bin/false")
        code, err = self.call(["audit"])
        self.assertEqual(code, 70)
        self.assertIn("ENGINE_IDENTITY_MISSING", err)

    def test_a_supported_host_runs_exactly_the_constant_unit_through_the_relay(self):
        self.environment()
        with mock.patch.object(outer, "relay", return_value=0) as relay, \
                mock.patch.object(os, "execve") as execve:
            self.call(["audit"])
        execve.assert_not_called()
        argv, env, out_fd, err_fd = relay.call_args[0]
        self.assertEqual(argv[0], "/bin/true")
        self.assertEqual(env, outer.EXEC_ENVIRONMENT)
        self.assertEqual((out_fd, err_fd), (1, 2))
        run_id = argv[-1]
        with mock.patch.object(outer, "SYSTEMD_RUN", "/bin/true"):
            self.assertEqual(argv, outer.unit_argv(run_id))

    def test_platform_reads_only_id_and_version(self):
        self.assertEqual(outer.platform('ID="rocky"\nVERSION_ID="9.4"\nNAME=x\n'), ("rocky", "9"))
        self.assertEqual(outer.platform("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), ("ubuntu", "24.04"))


class TheUnitIsConstant(unittest.TestCase):

    def argv(self):
        return outer.unit_argv("RUN-20261008T000000Z-" + "a" * 16)

    def properties(self):
        argv = self.argv()
        return [argv[i + 1] for i, a in enumerate(argv) if a == "--property"]

    def test_the_bounding_set_is_the_measured_route_set(self):
        vocab = gate.vocabulary()
        bounding = [p for p in self.properties() if p.startswith("CapabilityBoundingSet=")]
        self.assertEqual(len(bounding), 1)
        self.assertEqual(sorted(bounding[0].split("=", 1)[1].split()),
                         sorted(vocab["capability_measured_route"]))

    def test_no_state_directory_and_a_missing_root_is_not_created(self):
        props = self.properties()
        self.assertFalse([p for p in props if p.startswith("StateDirectory")])
        self.assertIn("ReadWritePaths=-/var/lib/isedraf", props)
        self.assertIn("ProtectSystem=strict", props)

    def test_every_stop_of_the_unit_uses_a_signal_systemd_does_not_count_as_clean(self):
        # IQ-063: a SIGTERM death is reported by systemd-run as 0, a complete audit.
        self.assertIn("KillSignal=SIGUSR2", self.properties())

    def test_ambient_is_explicitly_empty_and_the_run_is_time_bounded(self):
        props = self.properties()
        self.assertIn("AmbientCapabilities=", props)
        self.assertTrue([p for p in props if p.startswith("RuntimeMaxSec=")])
        for cap in ("CAP_KILL", "CAP_CHOWN", "CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE"):
            self.assertNotIn(cap, " ".join(self.argv()))

    def test_the_report_unit_cannot_write_the_store(self):
        argv = outer.report_unit_argv("RUN-20261010T000000Z-" + "a" * 16, "markdown")
        props = [argv[i + 1] for i, a in enumerate(argv) if a == "--property"]
        self.assertFalse([p for p in props if p.startswith("ReadWritePaths=")])
        self.assertIn("ProtectSystem=strict", props)
        self.assertEqual(sorted(props), sorted(p for p in self.properties()
                                               if not p.startswith("ReadWritePaths=")))
        with self.assertRaises(ValueError):
            outer.report_unit_argv("RUN-20261010T000000Z-" + "a" * 16, "/etc/passwd")

    def test_only_the_run_id_varies_and_it_is_never_a_path(self):
        a = outer.unit_argv("RUN-20261008T000000Z-" + "a" * 16)
        b = outer.unit_argv("RUN-20261008T000001Z-" + "b" * 16)
        self.assertEqual([x for x, y in zip(a, b) if x != y],
                         ["--unit=isedraf-audit-RUN-20261008T000000Z-" + "a" * 16,
                          "RUN-20261008T000000Z-" + "a" * 16])
        for bad in ("../../etc", "RUN-x", "SDS-20261008T000000Z-" + "a" * 16):
            with self.assertRaises(ValueError):
                outer.unit_argv(bad)


class InTheUnit(fixtures.Host):

    def setUp(self):
        super().setUp()
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        self.root = os.path.join(base, "isedraf")
        os.mkdir(self.root, 0o700)
        os.chmod(self.root, 0o700)
        self.script = os.path.join(base, "engine.py")
        self.mode("ok")
        patches = [mock.patch.object(store, "OWNER_UID", UID),
                   mock.patch.object(store, "OWNER_GID", GID),
                   mock.patch.object(engine, "ARGV", (sys.executable, "-IB", self.script)),
                   mock.patch.object(engine, "CLEAN_ARGV", (sys.executable, "-IB", "-c", CLEAN)),
                   mock.patch.object(unit, "engine_uid", return_value=UID),
                   mock.patch.object(unit, "remaining_processes", return_value=[]),
                   # The supervisor performs read_shadow_v1 against the fixture host.
                   mock.patch.object(contracts, "HOST_ROOT", self.host)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        _ts, _s, self.run_id, _e = snapshot.new_ids()

    def mode(self, mode):
        with open(self.script, "w") as fh:
            fh.write(ENGINE % {"lib": os.path.abspath(LIB), "host": self.host, "mode": mode,
                               "shadow": fixtures.FILES["etc/shadow"].encode()})

    def launch(self):
        err = io.StringIO()
        return unit.run(self.run_id, self.root, err), err.getvalue()

    def snapshots(self):
        path = os.path.join(self.root, "snapshots")
        return sorted(os.listdir(path)) if os.path.isdir(path) else []

    def test_a_run_is_promoted_ledgered_and_verified(self):
        code, err = self.launch()
        self.assertIn(code, (0, 2), err)
        self.assertEqual(len(self.snapshots()), 1)
        self.assertEqual(len(ledger.read_records(self.root)), 1)
        self.assertEqual(verify.verify_store(self.root), [])
        self.assertEqual(os.listdir(os.path.join(self.root, "tmp")), [])

    # -- IQ-063: a stopped run is never committed; a committed run is never undone ----------

    def interrupted(self, when):
        """Send the unit's stop (SIGUSR2, as `systemctl kill --kill-whom=all` does) to the
        launcher - and, mid-run, to the engine - at `when`."""
        started = []
        real_start, real_check, real_promote = engine.start, store.check_staged, store.promote

        def start(*a, **k):
            proc = real_start(*a, **k)
            started.append(proc)
            if when == "mid-run":
                def stop():
                    os.kill(proc.pid, signal.SIGUSR2)
                    os.kill(os.getpid(), signal.SIGUSR2)
                threading.Timer(1.0, stop).start()
            return proc

        def check_staged(*a, **k):
            if when == "before-commit":
                os.kill(os.getpid(), signal.SIGUSR2)
            return real_check(*a, **k)

        def promote(*a, **k):
            if when == "during-commit":
                os.kill(os.getpid(), signal.SIGUSR2)     # blocked: delivered after the commit
            return real_promote(*a, **k)
        previous = dict((s, signal.getsignal(s)) for s in unit.STOP_SIGNALS)
        self.addCleanup(lambda: [signal.signal(s, h) for s, h in previous.items()])
        self.addCleanup(lambda: unit._stop.clear())       # main() clears it in production
        unit.install_stop_handler()
        with mock.patch.object(engine, "start", start), \
                mock.patch.object(store, "check_staged", check_staged), \
                mock.patch.object(store, "promote", promote):
            return self.launch()

    def test_a_stop_mid_run_commits_nothing_and_leaves_no_staging(self):
        self.mode("slow")
        code, err = self.interrupted("mid-run")
        self.assertEqual(code, 128 + signal.SIGTERM, err)
        self.assertIn("INTERRUPTED", err)
        self.assertEqual(self.snapshots(), [])
        self.assertEqual(ledger.read_records(self.root), [])
        self.assertEqual(os.listdir(os.path.join(self.root, "tmp")), [])

    def test_a_stop_just_before_the_commit_commits_nothing(self):
        code, err = self.interrupted("before-commit")
        self.assertEqual(code, 128 + signal.SIGTERM, err)
        self.assertEqual(self.snapshots(), [])
        self.assertEqual(ledger.read_records(self.root), [])
        self.assertEqual(os.listdir(os.path.join(self.root, "tmp")), [])

    def test_a_stop_during_the_commit_lets_it_finish_and_the_snapshot_stays_valid(self):
        code, err = self.interrupted("during-commit")
        self.assertIn(code, (0, 2), err)
        self.assertEqual(len(self.snapshots()), 1)
        self.assertEqual(len(ledger.read_records(self.root)), 1)
        self.assertEqual(verify.verify_store(self.root), [])

    def test_once_the_run_has_returned_a_late_stop_cannot_change_its_end(self):
        before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        self.addCleanup(signal.pthread_sigmask, signal.SIG_SETMASK, before)
        previous = dict((s, signal.getsignal(s)) for s in unit.STOP_SIGNALS)
        self.addCleanup(lambda: [signal.signal(s, h) for s, h in previous.items()])
        with mock.patch.object(unit, "run", return_value=2):
            self.assertEqual(unit.main([self.run_id]), 2)
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        self.assertTrue(set(unit.STOP_SIGNALS) <= set(blocked))

    def test_an_engine_that_dies_mid_response_never_crashes_the_launcher(self):
        with mock.patch.object(unit.serve, "serve", side_effect=BrokenPipeError(32, "EPIPE")):
            self.mode("fail")
            code, err = self.launch()
        self.assertEqual(code, 64, err)
        self.assertEqual(os.listdir(os.path.join(self.root, "tmp")), [])

    def test_a_missing_root_is_67_and_never_created(self):
        shutil.rmtree(self.root)
        code, err = self.launch()
        self.assertEqual(code, 67, err)
        self.assertFalse(os.path.lexists(self.root))

    def test_a_non_conforming_root_is_67_and_untouched(self):
        os.chmod(self.root, 0o755)
        code, _err = self.launch()
        self.assertEqual(code, 67)
        self.assertEqual(os.stat(self.root).st_mode & 0o777, 0o755)
        self.assertEqual(os.listdir(self.root), [])

    def test_a_held_lock_is_66_and_nothing_runs(self):
        store.prepare(self.root)
        fd = os.open(os.path.join(self.root, stateroot.LOCK_NAME), os.O_RDWR)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, _err = self.launch()
        self.assertEqual(code, 66)
        self.assertEqual(os.listdir(os.path.join(self.root, "tmp")), [])

    def test_a_failed_engine_is_never_promoted_and_its_staging_is_removed(self):
        self.mode("fail")
        code, err = self.launch()
        self.assertEqual(code, 64, err)
        self.assertEqual(self.snapshots(), [])
        self.assertEqual(os.listdir(os.path.join(self.root, "tmp")), [])

    def test_an_undeclared_staged_file_is_refused_and_removed(self):
        self.mode("extra")
        code, err = self.launch()
        self.assertEqual(code, 64)
        self.assertIn("undeclared", err)
        self.assertEqual(self.snapshots(), [])
        self.assertEqual(os.listdir(os.path.join(self.root, "tmp")), [])

    def test_a_remaining_engine_process_refuses_the_promotion(self):
        with mock.patch.object(unit, "remaining_processes", return_value=["4242"]):
            code, err = self.launch()
        self.assertEqual(code, 64)
        self.assertIn("ENGINE_PROCESS_REMAINS", err)
        self.assertEqual(self.snapshots(), [])

    def test_a_stale_staging_of_an_earlier_run_is_removed(self):
        store.prepare(self.root)
        _ts, _s, old, _e = snapshot.new_ids()
        stale = store.make_staging(self.root, old)
        os.mkdir(os.path.join(stale, "state"), 0o700)
        with open(os.path.join(stale, "state", "x.json"), "w") as fh:
            fh.write("{}")
        code, err = self.launch()
        self.assertIn(code, (0, 2), err)
        self.assertFalse(os.path.lexists(stale))

    def test_the_launcher_takes_exactly_one_run_id(self):
        self.assertEqual(unit.main([]), 64)
        self.assertEqual(unit.main(["RUN-x", "y"]), 64)
        err = io.StringIO()
        self.assertEqual(unit.run("../escape", self.root, err), 64)


if __name__ == "__main__":
    unittest.main()
