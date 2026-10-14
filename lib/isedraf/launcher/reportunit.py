# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The report launcher inside the read-only report unit: read, frame, hand off.
# Implements: AUTH-032, AUTH-022, AUTH-021, AUTH-023, D-50
#
# `sudo isedraf report` (AUTH-032). The store is read-only in this unit (ProtectSystem=
# strict, no ReadWritePaths=). This launcher, root with the AUTH-028 set, does only this:
#
#   1. checks the fixed store as AUTH-022 states it, never touching it (67 on a deviation)
#   2. takes the whole-run lock on a read-only descriptor, so it never reads mid-promotion (66)
#   3. reads the ledger, bounded, and takes the snapshot of its last record (D-50)
#   4. reads that snapshot's declared files exactly as promotion reads a staged snapshot:
#      declared names only, no links, regular 0600 single-link files within the bound
#   5. frames the bytes and starts the renderer reduced as the engine is, the frame on its
#      stdin; the renderer verifies and renders, and its exit code is the run's
#
# It parses only ISEDRAF's own integrity metadata - one JSON line of the ledger - and never
# host evidence. Nothing comes back from the renderer but the report on stdout, so nothing
# the reduced side says can choose what is read.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="launcher (root inside the read-only report unit)"
# meta:mutates="none"
# meta:binaries="setpriv,python3"
# =============================================================================
"""AUTH-032 report launcher: the root side reads and frames; the reduced side renders."""
import fcntl
import json
import os
import signal
import stat
import subprocess
import sys

from isedraf import ids, stateroot
from isedraf.exitcodes import RUN_IN_PROGRESS, STATE_ROOT_UNUSABLE, USAGE_OR_ENGINE
from isedraf.launcher import engine, store
from isedraf.supervisor import frame

FORMATS = ("markdown", "json", "html")
LEDGER_BOUND = 64 * 1024 * 1024
FRAME_LIMIT = 160 * 1024 * 1024
FRAME_ITEMS = 1 + len(store.BUNDLE_FILES)
LEDGER_NAME = stateroot.LEDGER_SEGMENT
RENDER_ENTRY = ("import sys; sys.path.insert(0, %r); from isedraf.launcher.renderer import main; "
                "sys.exit(main(sys.argv[1:]))" % engine.INSTALL_ROOT)
INTERRUPTED = 128 + signal.SIGTERM
STOP_SIGNALS = (signal.SIGUSR2, signal.SIGTERM)


class Refused(Exception):
    """The store holds something AUTH-032 does not read; no report is rendered."""


class NoCommittedRun(Exception):
    """The store holds no committed Full Audit run."""


def render_argv(fmt):
    """The renderer's constant command: the engine reduction and a fixed entry."""
    if fmt not in FORMATS:
        raise ValueError("not a report format: %r" % (fmt,))
    return list(engine.ARGV[:9]) + ["-IB", "-c", RENDER_ENTRY, fmt]


def _read(path, bound, uid, gid, mode):
    """A no-follow read of one regular, single-link file of the stated owner (and group,
    unless None - promotion checks only the uid of engine-written files) and mode."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != mode
                or st.st_uid != uid or (gid is not None and st.st_gid != gid)):
            raise Refused("%s is not a %04o single-link regular file owned by uid %d"
                          % (path, mode, uid))
        if st.st_size > bound:
            raise Refused("%s exceeds %d bytes" % (path, bound))
        data = bytearray()
        while len(data) <= bound:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > bound:
            raise Refused("%s exceeds %d bytes" % (path, bound))
        meta = {"mode": st.st_mode, "uid": st.st_uid, "gid": st.st_gid, "size": len(data)}
        return bytes(data), meta
    finally:
        os.close(fd)


def _directory(path, uid, gid=None):
    st = os.lstat(path)
    if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)
            or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != uid
            or (gid is not None and st.st_gid != gid)):
        raise Refused("%s is not a 0700 directory owned by uid %d" % (path, uid))


def check_store(root):
    """AUTH-022, checked and never touched. Raises store.Unusable (67) or NoCommittedRun."""
    store.check_root(root)
    for name in ("snapshots", "ledger"):
        if store._conforms(os.path.join(root, name), True, 0o700,
                           store.OWNER_UID, store.OWNER_GID) is None:
            raise NoCommittedRun("%s has no %s/" % (root, name))
    if store._conforms(os.path.join(root, stateroot.LOCK_NAME), False, 0o600,
                       store.OWNER_UID, store.OWNER_GID) is None:
        raise NoCommittedRun("%s has no lock file" % root)


def acquire(root, engine_uid):
    """The ledger and the latest committed snapshot, as frame items. Under the lock."""
    ledger_path = os.path.join(root, LEDGER_NAME)
    if not os.path.lexists(ledger_path):
        raise NoCommittedRun("the ledger is empty")
    ledger_bytes, ledger_meta = _read(ledger_path, LEDGER_BOUND, store.OWNER_UID,
                                      store.OWNER_GID, 0o600)
    lines = [l for l in ledger_bytes.split(b"\n") if l.strip()]
    if not lines:
        raise NoCommittedRun("the ledger is empty")
    try:
        sid = json.loads(lines[-1].decode("utf-8"))["record_core"]["snapshot_id"]
    except (ValueError, KeyError, TypeError):
        raise Refused("the last ledger record is not a ledger record")
    if not isinstance(sid, str) or not ids.ID_RE.match(sid) or not sid.startswith("SDS-"):
        raise Refused("the last ledger record names no snapshot identifier")
    items = [frame.item(frame.ENTRY, LEDGER_NAME.encode("ascii"), frame.READ_OK, ledger_meta,
                        ledger_bytes)]
    base = os.path.join(root, "snapshots", sid)
    _directory(base, store.OWNER_UID, store.OWNER_GID)
    for name in sorted(os.listdir(base)):
        if name in store.BUNDLE_DIRECTORIES:
            _directory(os.path.join(base, name), engine_uid)
            children = [name + "/" + c for c in sorted(os.listdir(os.path.join(base, name)))]
        elif name in store.BUNDLE_FILES:
            children = [name]
        else:
            raise Refused("undeclared entry %s in snapshot %s" % (name, sid))
        for rel in children:
            if rel not in store.BUNDLE_FILES:
                raise Refused("undeclared file %s in snapshot %s" % (rel, sid))
            bound = store.MANIFEST_BOUND if rel == "manifest.json" else store.FILE_BOUND
            data, meta = _read(os.path.join(base, rel), bound, engine_uid, None, 0o600)
            items.append(frame.item(frame.ENTRY, ("snapshots/%s/%s" % (sid, rel)).encode("ascii"),
                                    frame.READ_OK, meta, data))
    return items


class _ReadOnlyLock(object):
    """The whole-run lock on a read-only descriptor: never created, never written."""

    def __init__(self, root):
        self._path = os.path.join(root, stateroot.LOCK_NAME)
        self._fd = None

    def __enter__(self):
        self._fd = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self._fd)
            self._fd = None
            raise stateroot.RunInProgress("another ISEDRAF run holds the lock")
        return self

    def __exit__(self, *exc):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        return False


def run(fmt, root=None, err=None, engine_uid=None):
    err = sys.stderr if err is None else err
    root = root or store.ROOT
    if fmt not in FORMATS:
        err.write("isedraf: the report launcher was given no report format\n")
        return USAGE_OR_ENGINE
    try:
        check_store(root)
        with _ReadOnlyLock(root):
            items = acquire(root, engine_uid if engine_uid is not None else _engine_uid())
    except store.Unusable as exc:
        err.write("isedraf: STATE_ROOT_UNUSABLE: %s\n" % exc)
        return STATE_ROOT_UNUSABLE
    except stateroot.RunInProgress as exc:
        err.write("isedraf: RUN_IN_PROGRESS: %s\n" % exc)
        return RUN_IN_PROGRESS
    except NoCommittedRun as exc:
        err.write("isedraf: no committed Full Audit run (%s); run `sudo isedraf audit` first. "
                  "A report renders committed evidence and never collects.\n" % exc)
        return USAGE_OR_ENGINE
    except (Refused, OSError, frame.FrameError) as exc:
        err.write("isedraf: REPORT_REFUSED: %s; no report was rendered.\n" % exc)
        return USAGE_OR_ENGINE
    data = frame.encode(items)
    if len(data) > FRAME_LIMIT:
        err.write("isedraf: REPORT_REFUSED: the evidence exceeds %d bytes; no report was "
                  "rendered.\n" % FRAME_LIMIT)
        return USAGE_OR_ENGINE
    proc = subprocess.Popen(render_argv(fmt), cwd="/", env=dict(engine.ENVIRONMENT),
                            stdin=subprocess.PIPE, close_fds=True, shell=False)
    try:
        proc.stdin.write(data)
        proc.stdin.close()
    except OSError:
        pass        # the renderer ended early; its exit code says why
    return proc.wait()


def _engine_uid():
    from isedraf.launcher import unit
    return unit.engine_uid()


_stop = []


def main(argv):
    for signum in STOP_SIGNALS:
        signal.signal(signum, lambda s, _f: _stop.append(s))
    if len(argv) != 2 or not ids.ID_RE.match(argv[0] or "") or not argv[0].startswith("RUN-"):
        sys.stderr.write("isedraf: the report launcher takes a run identifier and a format\n")
        return USAGE_OR_ENGINE
    code = run(argv[1])
    signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    return INTERRUPTED if _stop else code
