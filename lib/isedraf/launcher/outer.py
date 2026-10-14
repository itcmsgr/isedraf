# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The outer entry under root: refuse all but `audit` and `report`, then run systemd-run.
# Implements: AUTH-019, AUTH-020, AUTH-026, AUTH-027, PRIV-006, PRIV-008, EXEC-010, OUT-003
#
# bin/isedraf reaches this module, and only this module, when it runs as root or under sudo
# (AUTH-019). It is minimal and touches nothing: it never opens, creates, checks or repairs
# the state root (AUTH-026, PRIV-008), takes no option, and passes no operator environment
# on. It refuses with exit 70 every invocation that is not exactly `audit`, a host without
# systemd or outside the supported platforms (FULL_AUDIT_UNSUPPORTED, PRIV-006), and a host
# without the isedraf account (ENGINE_IDENTITY_MISSING). It refuses an install root that is
# not root-owned and closed to others (ENGINE_UNSAFE_INSTALL, EXEC-010). Then it runs
# systemd-run, whose properties are the constants below: the exit code of the run is the
# exit code of systemd-run (OUT-003).
#
# IQ-062: the outer entry owns the transport. systemd-run gets stdin /dev/null and stdout and
# stderr on pipes created here, never the caller's descriptors: on AlmaLinux 9 a regular-file
# stdout or stderr handed to `systemd-run --pipe` made PID 1 drop the request and stop
# answering D-Bus. The bytes are copied to the caller's stdout and stderr, whatever they are.
# If the caller's side cannot take them (a reader that closed early, a full disk), the rest
# is drained and discarded, the run is never interrupted, one line says so on stderr, and
# the exit code is unchanged.
#
# IQ-063: an interrupted audit is never committed afterwards. systemd-run runs in its own
# session, so a terminal's signals reach only the outer entry. On SIGTERM, SIGHUP or SIGINT
# the outer entry asks systemd to stop this run's unit - the fixed `systemctl kill` of the
# unit named by the run id, with SIGUSR2, retried until it is delivered - and keeps relaying
# until systemd-run reports the unit's end. The in-unit launcher discards staging and exits
# 143 (INTERRUPTED) when it was stopped before the commit; the caller then gets 128 + the
# signal and is told nothing was committed. A run that had already committed its snapshot
# ends with its own code (0 or 2): the caller gets that code and is told the snapshot is
# complete. Any other end after a stop is 128 + the signal with no claim either way.
# (Measured on systemd 252: a unit whose main process dies of SIGTERM is reported as exit 0,
# which is why the stop is SIGUSR2 - also the unit's KillSignal=, so a `systemctl stop` or the
# RuntimeMaxSec timeout behaves the same: unhandled, it ends as 255, never as an audit code.)
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="launcher (root, before the sandbox; touches nothing)"
# meta:mutates="none"
# meta:binaries="systemd-run,systemctl,getent"
# =============================================================================
"""Full Audit outer entry: refusals, then systemd-run with constant properties, relayed."""
import errno
import os
import select
import signal
import stat
import subprocess
import sys

from isedraf import ids
from isedraf.exitcodes import INCOMPLETE, OK, PRIVILEGE_REFUSED, USAGE_OR_ENGINE

SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"
GETENT = "/usr/bin/getent"
PYTHON = "/usr/bin/python3"
SYSTEMD_RUNTIME = "/run/systemd/system"
OS_RELEASE = "/etc/os-release"
INSTALL_ROOT = "/usr/lib"
PACKAGE = "/usr/lib/isedraf"
ENGINE_ACCOUNT = "isedraf"
EXEC_ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

# AUTH-019: the supported platforms, by os-release ID and the major part of VERSION_ID.
SUPPORTED = {("debian", "12"), ("ubuntu", "24.04"), ("rocky", "9"), ("almalinux", "9")}

REFUSAL = ("Under sudo or root, ISEDRAF runs only `sudo isedraf audit` (Full Audit) and "
           "`sudo isedraf report` (its report). Run other ISEDRAF commands as your normal user.")
# AUTH-032: the read-only report route - the invocations it admits and the format each names.
REPORT_INVOCATIONS = {("report",): "markdown", ("report", "--json"): "json",
                      ("report", "--html"): "html"}

# AUTH-020, AUTH-026, AUTH-027, EXEC-001, EXEC-002, PRIV-007, PRIV-009: constants of the
# package. The bounding set is the measured candidate set (AUTH-027); the ambient set is
# explicit and empty; there is no StateDirectory=; a missing root is ignored by systemd
# ("-") and refused by the launcher with 67 inside the unit.
CAPABILITY_BOUNDING_SET = "CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETPCAP CAP_SETUID"
RUNTIME_MAX_SECONDS = 900
PROPERTIES = (
    "ProtectSystem=strict",
    "ProtectHome=read-only",
    "ReadWritePaths=-/var/lib/isedraf",
    "PrivateTmp=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "CapabilityBoundingSet=" + CAPABILITY_BOUNDING_SET,
    "AmbientCapabilities=",
    "SystemCallFilter=~@mount @module @reboot @swap @raw-io @clock @cpu-emulation @obsolete",
    "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
    "IPAddressDeny=any",
    "UMask=0077",
    "RuntimeMaxSec=%d" % RUNTIME_MAX_SECONDS,
    # IQ-063: every stop of the unit - systemctl stop, the RuntimeMaxSec timeout, the outer
    # entry's kill - uses SIGUSR2. systemd counts a SIGTERM death as a clean exit and
    # systemd-run then reports 0 (measured, systemd 252): a run stopped before its Python
    # could install a handler read as a complete audit.
    "KillSignal=SIGUSR2",
)
UNIT_ENTRY = ("import sys; sys.path.insert(0, %r); from isedraf.launcher.unit import main; "
              "sys.exit(main(sys.argv[1:]))" % INSTALL_ROOT)
REPORT_ENTRY = ("import sys; sys.path.insert(0, %r); from isedraf.launcher.reportunit import "
                "main; sys.exit(main(sys.argv[1:]))" % INSTALL_ROOT)
# AUTH-032: the audit unit's constant properties without write access to the store, which
# ProtectSystem=strict then leaves read-only.
REPORT_PROPERTIES = tuple(p for p in PROPERTIES if not p.startswith("ReadWritePaths="))


def unit_argv(run_id):
    """The whole systemd-run command. Only the run id varies, and it is never a path."""
    if not ids.ID_RE.match(run_id or "") or not run_id.startswith("RUN-"):
        raise ValueError("not a run identifier: %r" % (run_id,))
    return _systemd_run("isedraf-audit-", run_id, PROPERTIES) + [PYTHON, "-IB", "-c",
                                                                  UNIT_ENTRY, run_id]


def report_unit_argv(run_id, fmt):
    """AUTH-032: the read-only report unit. Only the run id and the format vary."""
    if not ids.ID_RE.match(run_id or "") or not run_id.startswith("RUN-"):
        raise ValueError("not a run identifier: %r" % (run_id,))
    if fmt not in REPORT_INVOCATIONS.values():
        raise ValueError("not a report format: %r" % (fmt,))
    return _systemd_run("isedraf-report-", run_id, REPORT_PROPERTIES) + [
        PYTHON, "-IB", "-c", REPORT_ENTRY, run_id, fmt]


def _systemd_run(prefix, run_id, properties):
    argv = [SYSTEMD_RUN, "--wait", "--pipe", "--quiet", "--collect", "--unit=" + prefix + run_id]
    for prop in properties:
        argv += ["--property", prop]
    for key, value in sorted(EXEC_ENVIRONMENT.items()):
        argv += ["--setenv", "%s=%s" % (key, value)]
    return argv


def platform(os_release_text):
    """(ID, major VERSION_ID) from os-release, read for these two keys only."""
    values = {}
    for line in os_release_text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("ID", "VERSION_ID"):
            values[key] = value.strip().strip("\"'")
    version = values.get("VERSION_ID", "")
    if values.get("ID") in ("rocky", "almalinux"):
        version = version.split(".")[0]
    return values.get("ID", ""), version


def unsafe_install(package=PACKAGE):
    """EXEC-010: the package directory and every parent root-owned, not group/world-writable."""
    here = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    if here != package:
        return "the running package is %s, not %s" % (here, package)
    path = package
    while True:
        st = os.lstat(path)
        if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or \
                stat.S_ISLNK(st.st_mode):
            return "%s is not root-owned and closed to group and others" % path
        if path == "/":
            return None
        path = os.path.dirname(path)


# IQ-062: the relay. Chunk and poll interval bound memory and latency; after systemd-run
# exits, a pipe still open is drained for at most RELAY_DRAIN_POLLS idle polls.
RELAY_CHUNK = 65536
RELAY_POLL_MS = 100
RELAY_DRAIN_POLLS = 50
# IQ-063: the signals that stop the audit, and the in-unit launcher's "stopped before the
# commit" exit status (the same value as a SIGTERM death, 128 + 15).
STOP_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
INTERRUPTED = 128 + signal.SIGTERM
COMMITTED = (OK, INCOMPLETE)


def stop_argv(run_id, prefix="isedraf-audit-"):
    """The fixed stop of one run's unit. Only the run id varies, and it is never a path."""
    if not ids.ID_RE.match(run_id or "") or not run_id.startswith("RUN-"):
        raise ValueError("not a run identifier: %r" % (run_id,))
    if prefix not in ("isedraf-audit-", "isedraf-report-"):
        raise ValueError("not an ISEDRAF unit prefix: %r" % (prefix,))
    return [SYSTEMCTL, "kill", "--kill-whom=all", "--signal=SIGUSR2",
            "%s%s.service" % (prefix, run_id)]


def stop_unit(run_id, prefix="isedraf-audit-"):
    """True when systemd accepted the stop of this run's unit."""
    try:
        done = subprocess.run(stop_argv(run_id, prefix), stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env=dict(EXEC_ENVIRONMENT), timeout=10, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


def relay(argv, env, out_fd, err_fd, stop=None):
    """Run argv with stdin /dev/null and stdout and stderr on pipes owned here; copy them to
    out_fd and err_fd; return the exit status (OUT-003). On a STOP_SIGNALS signal, `stop`
    is called with the process until it returns True, and the result follows IQ-063."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, close_fds=True, shell=False,
                            start_new_session=True)
    received, stopped, previous = [], [], {}

    def note(signum, _frame):
        if not received:
            received.append(signum)

    def tick():
        if received and not stopped and stop is not None and proc.poll() is None:
            if stop(proc):
                stopped.append(True)
    try:
        for signum in STOP_SIGNALS:
            previous[signum] = signal.signal(signum, note)
        failed = _copy(proc, {proc.stdout.fileno(): out_fd, proc.stderr.fileno(): err_fd},
                       tick)
        code = proc.wait()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        proc.stdout.close()
        proc.stderr.close()
    for dest, reason in sorted(failed.items()):
        if err_fd not in failed:
            _write_all(err_fd, ("isedraf: the output for descriptor %d could not be written "
                                "(%s); the run was not interrupted and its exit code is "
                                "unchanged.\n" % (dest, reason)).encode())
    code = code if code >= 0 else 128 - code
    if not received:
        return code
    name = signal.Signals(received[0]).name
    if code in COMMITTED:
        _write_all(err_fd, ("isedraf: %s arrived after the snapshot was committed; the committed "
                            "snapshot is complete and the exit code is the audit's.\n"
                            % name).encode())
        return code
    if code == INTERRUPTED:
        _write_all(err_fd, ("isedraf: interrupted by %s; the audit was stopped and nothing was "
                            "committed.\n" % name).encode())
    else:
        _write_all(err_fd, ("isedraf: interrupted by %s; the audit ended with status %d.\n"
                            % (name, code)).encode())
    return 128 + received[0]


def _copy(proc, routes, tick=None):
    """Copy each source pipe to its destination until every pipe ends. A destination that
    fails is recorded and its bytes are discarded from then on, so the source never blocks.
    `tick` runs between polls."""
    failed = {}
    poller = select.poll()
    for src in routes:
        poller.register(src, select.POLLIN)
    open_fds = dict(routes)
    idle = 0
    while open_fds:
        if tick is not None:
            tick()
        events = poller.poll(RELAY_POLL_MS)
        if not events:
            if proc.poll() is not None:
                idle += 1
                if idle >= RELAY_DRAIN_POLLS:
                    break
            continue
        idle = 0
        for src, _mask in events:
            chunk = os.read(src, RELAY_CHUNK)
            if not chunk:
                poller.unregister(src)
                del open_fds[src]
                continue
            dest = open_fds[src]
            if dest not in failed:
                reason = _write_all(dest, chunk)
                if reason:
                    failed[dest] = reason
    return failed


def _write_all(fd, data):
    """Write all of data to fd; return None, or the errno name of the failure."""
    view = memoryview(data)
    while view:
        try:
            view = view[os.write(fd, view):]
        except BlockingIOError:
            select.select([], [fd], [], RELAY_POLL_MS / 1000.0)
        except OSError as exc:
            return errno.errorcode.get(exc.errno, "OSError")
    return None


def refuse(code, text, err):
    err.write("isedraf: %s\n" % text)
    return code


def main(argv, err=None):
    err = sys.stderr if err is None else err
    if os.geteuid() != 0 or (list(argv) != ["audit"]
                             and tuple(argv) not in REPORT_INVOCATIONS):
        return refuse(PRIVILEGE_REFUSED, REFUSAL, err)
    problem = unsafe_install()
    if problem:
        return refuse(USAGE_OR_ENGINE, "ENGINE_UNSAFE_INSTALL: %s" % problem, err)
    try:
        with open(OS_RELEASE) as fh:
            release = platform(fh.read())
    except OSError:
        release = ("", "")
    if (not os.path.isdir(SYSTEMD_RUNTIME) or not os.access(SYSTEMD_RUN, os.X_OK)
            or release not in SUPPORTED):
        return refuse(PRIVILEGE_REFUSED, "FULL_AUDIT_UNSUPPORTED: Full Audit needs systemd on "
                      "Debian 12, Ubuntu 24.04, Rocky 9 or AlmaLinux 9; nothing was run.", err)
    found = subprocess.run([GETENT, "passwd", ENGINE_ACCOUNT], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           env=dict(EXEC_ENVIRONMENT), timeout=10, shell=False)
    if found.returncode != 0:
        return refuse(PRIVILEGE_REFUSED, "ENGINE_IDENTITY_MISSING: the isedraf account the "
                      "package declares does not exist; nothing was run.", err)
    run_id = ids.new_id("RUN", ids.now_utc())
    if tuple(argv) in REPORT_INVOCATIONS:
        return relay(report_unit_argv(run_id, REPORT_INVOCATIONS[tuple(argv)]),
                     dict(EXEC_ENVIRONMENT), 1, 2,
                     stop=lambda _proc: stop_unit(run_id, "isedraf-report-"))
    return relay(unit_argv(run_id), dict(EXEC_ENVIRONMENT), 1, 2,
                 stop=lambda _proc: stop_unit(run_id))
