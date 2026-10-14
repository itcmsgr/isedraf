# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The outer entry owns the transport: systemd-run only ever sees its pipes (IQ-062).
# Implements: AUTH-020, OUT-003, IQ-063
#
# IQ-062: on AlmaLinux 9, `systemd-run --pipe` handed a regular-file stdout or stderr made
# PID 1 drop the request and stop answering D-Bus. The outer entry therefore runs
# systemd-run with stdin /dev/null and stdout and stderr on pipes it created, and copies the
# bytes to whatever the caller's descriptors are. Unprivileged: a stand-in program takes
# systemd-run's place and reports what it was given; systemd itself is proven on the lab
# corpus.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""IQ-062: the launcher relays systemd-run's output through pipes it owns."""
import hashlib
import io
import json
import os
import shutil
import signal
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))

from isedraf.launcher import outer                                    # noqa: E402

# The stand-in reports the file type of its descriptors 0, 1 and 2 on stdout.
REPORT = ("import json, os, stat\n"
          "kinds = {}\n"
          "for fd in (0, 1, 2):\n"
          "    st = os.fstat(fd)\n"
          "    kinds[fd] = ('FIFO' if stat.S_ISFIFO(st.st_mode) else 'REG' if stat.S_ISREG(st.st_mode)"
          " else 'CHR:%d' % st.st_rdev if stat.S_ISCHR(st.st_mode) else 'OTHER')\n"
          "print(json.dumps(kinds, sort_keys=True))\n")
MIB = 1024 * 1024


def child(code):
    return [sys.executable, "-I", "-c", code]


def volume(out_bytes, err_bytes, exit_code=0):
    """A stand-in that interleaves the two streams in 64 KiB blocks, then exits."""
    return child("import os, sys\n"
                 "o, e = %d, %d\n"
                 "while o or e:\n"
                 "    if o:\n"
                 "        n = min(o, 65536); os.write(1, b'o' * n); o -= n\n"
                 "    if e:\n"
                 "        n = min(e, 65536); os.write(2, b'e' * n); e -= n\n"
                 "sys.exit(%d)\n" % (out_bytes, err_bytes, exit_code))


class Relay(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)

    def regular(self, name):
        fd = os.open(os.path.join(self.base, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.addCleanup(os.close, fd)
        return fd

    def content(self, name):
        with open(os.path.join(self.base, name), "rb") as fh:
            return fh.read()

    def pipe_reader(self):
        """A pipe whose read end a thread drains, standing in for a terminal or `| tee`."""
        r, w = os.pipe()
        got = bytearray()

        def drain():
            while True:
                chunk = os.read(r, 65536)
                if not chunk:
                    break
                got.extend(chunk)
            os.close(r)
        reader = threading.Thread(target=drain)
        reader.start()
        return w, got, reader

    def run_relay(self, argv, out_fd, err_fd):
        return outer.relay(argv, {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, out_fd, err_fd)

    # -- the regression: no caller descriptor ever reaches systemd-run -------------------

    def test_a_regular_file_stdout_and_stderr_never_reach_systemd_run(self):
        out, err = self.regular("out"), self.regular("err")
        self.assertEqual(self.run_relay(child(REPORT), out, err), 0)
        kinds = json.loads(self.content("out").decode())
        self.assertEqual(kinds["1"], "FIFO")
        self.assertEqual(kinds["2"], "FIFO")
        self.assertEqual(kinds["0"], "CHR:%d" % os.stat(os.devnull).st_rdev)

    def test_a_pipe_stdout_is_relayed_through_the_launchers_own_pipe(self):
        w, got, reader = self.pipe_reader()
        err = self.regular("err")
        code = self.run_relay(child(REPORT), w, err)
        os.close(w)
        reader.join()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(got.decode())["1"], "FIFO")

    # -- the bytes arrive where the caller sent them ----------------------------------------

    def test_stdout_to_a_regular_file(self):
        out, err = self.regular("out"), self.regular("err")
        self.assertEqual(self.run_relay(volume(300000, 0), out, err), 0)
        self.assertEqual(self.content("out"), b"o" * 300000)
        self.assertEqual(self.content("err"), b"")

    def test_stderr_to_a_regular_file(self):
        w, got, reader = self.pipe_reader()
        err = self.regular("err")
        self.assertEqual(self.run_relay(volume(0, 300000), w, err), 0)
        os.close(w)
        reader.join()
        self.assertEqual(self.content("err"), b"e" * 300000)
        self.assertEqual(bytes(got), b"")

    def test_stdout_and_stderr_redirected_separately_stay_separate(self):
        out, err = self.regular("out"), self.regular("err")
        self.assertEqual(self.run_relay(volume(200000, 100000), out, err), 0)
        self.assertEqual(self.content("out"), b"o" * 200000)
        self.assertEqual(self.content("err"), b"e" * 100000)

    # -- failures of the downstream side ---------------------------------------------------

    def test_a_downstream_reader_that_closes_early_never_stops_the_run(self):
        r, w = os.pipe()
        os.close(r)
        self.addCleanup(os.close, w)
        err = self.regular("err")
        self.assertEqual(self.run_relay(volume(2 * MIB, 0, exit_code=3), w, err), 3)
        self.assertIn(b"EPIPE", self.content("err"))
        self.assertIn(b"exit code is unchanged", self.content("err"))

    def test_a_relay_write_failure_is_reported_and_the_exit_code_is_unchanged(self):
        full = os.open("/dev/full", os.O_WRONLY)
        self.addCleanup(os.close, full)
        err = self.regular("err")
        self.assertEqual(self.run_relay(volume(MIB, 0, exit_code=2), full, err), 2)
        self.assertIn(b"ENOSPC", self.content("err"))

    def test_both_streams_failing_still_returns_the_exit_code(self):
        full = os.open("/dev/full", os.O_WRONLY)
        self.addCleanup(os.close, full)
        self.assertEqual(self.run_relay(volume(MIB, MIB, exit_code=1), full, full), 1)

    # -- the exit status propagates (OUT-003) ------------------------------------------------

    def test_every_exit_code_propagates_unchanged(self):
        out, err = self.regular("out"), self.regular("err")
        for code in (0, 1, 2, 3, 4, 5, 6, 64, 65, 66, 67, 70):
            self.assertEqual(self.run_relay(child("import sys; sys.exit(%d)" % code), out, err),
                             code)

    def test_a_signal_death_is_reported_as_128_plus_the_signal(self):
        out, err = self.regular("out"), self.regular("err")
        code = self.run_relay(child("import os, signal; os.kill(os.getpid(), signal.SIGTERM)"),
                              out, err)
        self.assertEqual(code, 128 + signal.SIGTERM)

    # -- IQ-063: an interruption stops the audit unit; it is never committed afterwards ----

    def interrupt(self, signum, on_stop, normal=0, tag=""):
        """A stand-in systemd-run that exits `on_stop` when the stop reaches it (SIGUSR2,
        as `systemctl kill` delivers it to the unit) and `normal` otherwise; the outer entry
        is sent `signum` while it waits."""
        code = ("import os, signal, sys, time\n"
                "signal.signal(signal.SIGUSR2, lambda s, f: sys.exit(%d))\n"
                "print(os.getsid(0) == os.getpid(), flush=True)\n"
                "time.sleep(20)\nsys.exit(%d)\n" % (on_stop, normal))
        stops = []

        def stop(proc):
            stops.append(proc.pid)
            if len(stops) < 2:
                return False                     # the first request fails: it is retried
            os.kill(proc.pid, signal.SIGUSR2)
            return True
        out, err = self.regular("out" + tag), self.regular("err" + tag)
        timer = threading.Timer(0.5, os.kill, (os.getpid(), signum))
        timer.start()
        rc = outer.relay(child(code), {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, out, err,
                         stop=stop)
        timer.join()
        return rc, stops, self.content("out" + tag), self.content("err" + tag)

    def test_sigterm_stops_the_unit_and_nothing_committed_is_128_plus_15(self):
        before = signal.getsignal(signal.SIGTERM)
        rc, stops, out, err = self.interrupt(signal.SIGTERM, on_stop=outer.INTERRUPTED)
        self.assertEqual(rc, 128 + signal.SIGTERM)
        self.assertEqual(len(set(stops)), 1)
        self.assertGreaterEqual(len(stops), 2)
        self.assertIn(b"nothing was committed", err)
        self.assertEqual(out, b"True\n")            # systemd-run runs in its own session
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_sighup_and_sigint_stop_the_unit_the_same_way(self):
        for signum in (signal.SIGHUP, signal.SIGINT):
            rc, _stops, _out, err = self.interrupt(signum, on_stop=outer.INTERRUPTED,
                                                   tag=str(signum))
            self.assertEqual(rc, 128 + signum)
            self.assertIn(b"nothing was committed", err)

    def test_a_snapshot_committed_before_the_stop_keeps_its_audit_exit_code(self):
        rc, _stops, _out, err = self.interrupt(signal.SIGTERM, on_stop=2)
        self.assertEqual(rc, 2)
        self.assertIn(b"after the snapshot was committed", err)
        self.assertNotIn(b"nothing was committed", err)

    def test_an_unexplained_end_after_a_stop_claims_nothing_about_commitment(self):
        rc, _stops, _out, err = self.interrupt(signal.SIGTERM, on_stop=255)
        self.assertEqual(rc, 128 + signal.SIGTERM)
        self.assertNotIn(b"nothing was committed", err)
        self.assertNotIn(b"was committed", err.replace(b"nothing was committed", b""))

    def test_without_a_signal_no_stop_is_requested(self):
        stops = []
        out, err = self.regular("out"), self.regular("err")
        rc = outer.relay(child("import sys; sys.exit(2)"), {"PATH": "/usr/bin:/bin"}, out, err,
                         stop=lambda proc: stops.append(proc) or True)
        self.assertEqual((rc, stops), (2, []))

    def test_the_stop_is_the_fixed_systemctl_kill_of_this_runs_unit(self):
        run_id = "RUN-20261010T000000Z-" + "a" * 16
        self.assertEqual(outer.stop_argv(run_id),
                         ["/usr/bin/systemctl", "kill", "--kill-whom=all", "--signal=SIGUSR2",
                          "isedraf-audit-" + run_id + ".service"])
        with self.assertRaises(ValueError):
            outer.stop_argv("/etc/passwd")

    # -- volume: no buffering in memory, no deadlock -----------------------------------------

    def test_large_interleaved_output_neither_deadlocks_nor_loses_bytes(self):
        size = 16 * MIB
        w, got, reader = self.pipe_reader()
        err = self.regular("err")
        self.assertEqual(self.run_relay(volume(size, size), w, err), 0)
        os.close(w)
        reader.join()
        self.assertEqual(hashlib.sha256(bytes(got)).hexdigest(),
                         hashlib.sha256(b"o" * size).hexdigest())
        self.assertEqual(len(self.content("err")), size)


class OuterUsesTheRelay(unittest.TestCase):

    def test_the_constant_unit_runs_through_the_relay_never_execve(self):
        err = io.StringIO()
        with mock.patch.object(os, "geteuid", return_value=0), \
                mock.patch.object(outer, "unsafe_install", return_value=None), \
                mock.patch.object(outer, "platform", return_value=("debian", "12")), \
                mock.patch.object(outer.os.path, "isdir", return_value=True), \
                mock.patch.object(outer.os, "access", return_value=True), \
                mock.patch.object(outer.subprocess, "run",
                                  return_value=mock.Mock(returncode=0)), \
                mock.patch.object(outer, "relay", return_value=5) as relay, \
                mock.patch.object(os, "execve") as execve:
            self.assertEqual(outer.main(["audit"], err), 5)
        execve.assert_not_called()
        argv, env = relay.call_args[0][:2]
        self.assertEqual(env, outer.EXEC_ENVIRONMENT)
        self.assertEqual(argv, outer.unit_argv(argv[-1]))
        self.assertEqual(relay.call_args[0][2:], (1, 2))
        self.assertTrue(callable(relay.call_args[1]["stop"]))


if __name__ == "__main__":
    unittest.main()
