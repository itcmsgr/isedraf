# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The launcher inside the Full Audit unit: store, lock, engine, supervisor, promotion.
# Implements: AUTH-019, AUTH-020, AUTH-021, AUTH-022, AUTH-023, AUTH-027, PRIV-007, PRIV-008,
#             SNAP-014, SNAP-018, EXEC-020
#
# The order is the frozen one:
#
#   1. the state root is validated, never repaired; its entries created or refused (67)
#   2. the whole-run lock, before anything is collected (66)
#   3. a stale staging of an earlier run is emptied by the reduced identity and removed
#   4. the run's staging; the reduced engine started in it with the supervisor channel
#   5. the supervisor answers the engine's fixed-operation requests until the engine ends
#   6. no process of the engine remains in the unit
#   7. the mechanical check of the staged tree, the atomic rename, the ledger append
#
# The run's exit code is the engine's (0 complete, 2 incomplete) unless the launcher
# refuses: 67, 66, 64 for an engine failure, a refused staging or a remaining process.
# A refused or failed run is never promoted, and its staging is removed.
#
# IQ-063: a stop - SIGUSR2, the unit's KillSignal=, from the outer entry's `systemctl kill`, a
# `systemctl stop` or the RuntimeMaxSec timeout; SIGTERM too - is recorded by a handler installed first thing in main(). Before the commit it
# means: nothing is promoted, the staging is discarded, and the run exits 143 (INTERRUPTED).
# The commit itself - the rename and the ledger append - runs with those signals blocked, so
# a stop that arrives during it is delivered after it: the committed snapshot stays valid and
# the run ends with its own code; once run() has returned, the stop signals stay blocked until
# the process exits. An engine that ends while the supervisor is answering it (killed by the
# same stop) never crashes the launcher.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="launcher (root inside the Full Audit unit)"
# meta:mutates="state-root only"
# meta:binaries="id,setpriv"
# =============================================================================
"""Full Audit in-unit launcher."""
import os
import signal
import subprocess
import sys

from isedraf import ids, ledger, stateroot, verify
from isedraf.exitcodes import (INCOMPLETE, OK, RUN_IN_PROGRESS, STATE_ROOT_UNUSABLE,
                               USAGE_OR_ENGINE)
from isedraf.launcher import engine, store
from isedraf.supervisor import serve

ID = "/usr/bin/id"

# IQ-063: the stop signals, and the exit status of a run stopped before its commit.
STOP_SIGNALS = (signal.SIGUSR2, signal.SIGTERM)
INTERRUPTED = 128 + signal.SIGTERM
_stop = []


def _note_stop(signum, _frame):
    if not _stop:
        _stop.append(signum)


def install_stop_handler():
    del _stop[:]
    for signum in STOP_SIGNALS:
        signal.signal(signum, _note_stop)


class _Interrupted(Exception):
    pass


def engine_uid():
    """The isedraf account's uid, from a fixed command; only an integer is read."""
    out = subprocess.run([ID, "-u", engine.ENGINE_ACCOUNT], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         env=dict(engine.ENVIRONMENT), timeout=10, shell=False)
    value = out.stdout.decode("ascii", "replace").strip()
    if out.returncode != 0 or not value.isdigit() or int(value) == 0:
        raise store.PromotionRefused("the isedraf account cannot be resolved")
    return int(value)


def remaining_processes():
    """Processes of this unit other than the launcher itself (cgroup v2)."""
    with open("/proc/self/cgroup") as fh:
        group = [l.split("::", 1)[1] for l in fh.read().splitlines() if l.startswith("0::")]
    if len(group) != 1:
        return ["the unit's cgroup cannot be determined"]
    with open("/sys/fs/cgroup" + group[0] + "/cgroup.procs") as fh:
        pids = [p for p in fh.read().split() if p]
    return [p for p in pids if p != str(os.getpid())]


def discard(staging):
    """Empty a staging as the engine identity, then remove it. Best effort, reported."""
    try:
        os.chmod(staging, store.STAGING_MODE)
        engine.clean(staging)
        os.rmdir(staging)
    except OSError as exc:
        return "staging %s was not removed: %s" % (staging, exc)
    return None


def _stale(root, run_id, err):
    tmp = os.path.join(root, "tmp")
    for name in sorted(os.listdir(tmp)):
        path = os.path.join(tmp, name)
        if name == run_id or os.path.islink(path) or not os.path.isdir(path):
            continue
        problem = discard(path)
        if problem:
            err.write("isedraf: %s\n" % problem)


def _serve_engine(staging):
    req_r, req_w = os.pipe()
    resp_r, resp_w = os.pipe()
    try:
        proc = engine.start(staging, req_w, resp_r)
    finally:
        os.close(req_w)
        os.close(resp_r)
    try:
        serve.serve(req_r, resp_w)
    except OSError:
        pass        # the engine ended mid-exchange (a stop, a crash): its exit code decides
    finally:
        os.close(req_r)
        os.close(resp_w)
    return proc.wait()


def run(run_id, root=None, err=None):
    err = sys.stderr if err is None else err
    root = root or store.ROOT
    if not ids.ID_RE.match(run_id or "") or not run_id.startswith("RUN-"):
        err.write("isedraf: the launcher was given no run identifier\n")
        return USAGE_OR_ENGINE
    try:
        store.prepare(root)
    except store.Unusable as exc:
        err.write("isedraf: STATE_ROOT_UNUSABLE: %s\n" % exc)
        return STATE_ROOT_UNUSABLE
    try:
        with stateroot.RunLock(root):
            if len(ledger.unledgered_snapshots(root)) > 1:
                err.write("isedraf: STORE_DISCONTINUITY - snapshots are not in the ledger "
                          "(SNAP-018)\n")
                return INCOMPLETE
            _stale(root, run_id, err)
            if _stop:
                err.write("isedraf: INTERRUPTED: the audit was stopped before it started; "
                          "nothing was committed.\n")
                return INTERRUPTED
            staging = store.make_staging(root, run_id)
            code = _serve_engine(staging)
            try:
                if _stop:
                    raise _Interrupted()
                left = remaining_processes()
                if left:
                    raise store.PromotionRefused("ENGINE_PROCESS_REMAINS: %s" % " ".join(left))
                if code not in (OK, INCOMPLETE):
                    raise store.PromotionRefused("the engine ended with %d" % code)
                envelope = store.check_staged(staging, engine_uid(), run_id)
                signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
                try:
                    if _stop:
                        raise _Interrupted()
                    store.promote(root, staging, envelope)
                finally:
                    signal.pthread_sigmask(signal.SIG_UNBLOCK, STOP_SIGNALS)
            except _Interrupted:
                err.write("isedraf: INTERRUPTED: the audit was stopped before its snapshot was "
                          "committed; nothing was committed.\n")
                problem = discard(staging)
                if problem:
                    err.write("isedraf: %s\n" % problem)
                return INTERRUPTED
            except (store.PromotionRefused, OSError, ValueError) as exc:
                err.write("isedraf: the run was not committed: %s\n" % exc)
                problem = discard(staging)
                if problem:
                    err.write("isedraf: %s\n" % problem)
                return USAGE_OR_ENGINE
            problems = verify.verify_store(root)
    except stateroot.RunInProgress as exc:
        err.write("isedraf: RUN_IN_PROGRESS: %s\n" % exc)
        return RUN_IN_PROGRESS
    if problems:
        err.write("isedraf: the store does not verify after the commit: %s\n"
                  % "; ".join(problems))
        return USAGE_OR_ENGINE
    return code


def main(argv):
    install_stop_handler()
    if len(argv) != 1:
        sys.stderr.write("isedraf: the launcher takes exactly one run identifier\n")
        return USAGE_OR_ENGINE
    code = run(argv[0])
    # IQ-063: from here the run's outcome is decided. Interpreter shutdown restores the
    # default dispositions, so a stop arriving now would kill the process (seen in the lab
    # as status 255 after a committed snapshot); blocked, it stays pending and the run ends
    # with its own code.
    signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    return code
