# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The report launcher inside the read-only report unit: read, frame, hand off.
# Implements: AUTH-032, AUTH-022, AUTH-021, AUTH-023, D-50, D-128
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
# AUTH-032 as extended by D-126: plus the committed evaluation's four artifacts, if any.
REPORT_FRAME_ITEMS = FRAME_ITEMS + 4
# D-128: the baseline state - the revision artifact, the pointer, and the approved snapshot
# when it is not the latest run.
BASELINE_NAMES = ("baselines/BL-000001.json", "baselines/current")
BASELINE_BOUND = 1024 * 1024
BASELINE_FRAME_ITEMS = FRAME_ITEMS + len(store.BUNDLE_FILES) + len(BASELINE_NAMES)
SNAPSHOT_COMMITTED = "snapshot_committed"
BASELINE_APPROVED = "baseline_approved"
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


def feed(proc, data):
    """Hand one frame to the reduced child and ALWAYS close the pipe.

    A child that refuses early (bad frame, ENGINE_NOT_REDUCED) closes its end: the write
    then raises BrokenPipeError, and closing our buffered end can raise it again while
    flushing. Both are expected and the child's exit code says why; leaving the pipe open
    instead leaked a descriptor (ResourceWarning in the route tests, 2026-11-05).
    """
    try:
        proc.stdin.write(data)
    except OSError:
        pass        # the child ended early; its exit code says why
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass


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


def ledger_cores(ledger_bytes):
    """record_core of every ledger record, in order. ISEDRAF metadata only, never evidence."""
    out = []
    for line in [l for l in ledger_bytes.split(b"\n") if l.strip()]:
        try:
            core = json.loads(line.decode("utf-8"))["record_core"]
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            raise Refused("a ledger line is not a ledger record")
        if not isinstance(core, dict):
            raise Refused("a ledger line is not a ledger record")
        out.append(core)
    return out


def _snapshot_id(core, what):
    sid = core.get("snapshot_id")
    if not isinstance(sid, str) or not ids.ID_RE.match(sid) or not sid.startswith("SDS-"):
        raise Refused("the %s names no snapshot identifier" % what)
    return sid


def latest_snapshot(cores):
    """(snapshot_id, manifest_hash) of the last snapshot_committed record - the latest run.

    D-128: since v0.4 the ledger also carries baseline_approved records, which name the
    snapshot they approve, not a run; "the last record" is no longer "the latest run".
    """
    runs = [c for c in cores if c.get("event") == SNAPSHOT_COMMITTED]
    if not runs:
        raise NoCommittedRun("the ledger records no committed run")
    return _snapshot_id(runs[-1], "last snapshot record"), runs[-1].get("manifest_hash")


def baseline_record(cores):
    """The baseline_approved record in force, or None. More than one is refused."""
    found = [c for c in cores if c.get("event") == BASELINE_APPROVED]
    if len(found) > 1:
        raise Refused("the ledger records %d baseline approvals" % len(found))
    return found[0] if found else None


def acquire(root, engine_uid):
    """The ledger and the latest committed snapshot, as frame items. Under the lock."""
    ledger_path = os.path.join(root, LEDGER_NAME)
    if not os.path.lexists(ledger_path):
        raise NoCommittedRun("the ledger is empty")
    ledger_bytes, ledger_meta = _read(ledger_path, LEDGER_BOUND, store.OWNER_UID,
                                      store.OWNER_GID, 0o600)
    cores = ledger_cores(ledger_bytes)
    if not cores:
        raise NoCommittedRun("the ledger is empty")
    sid, _hash = latest_snapshot(cores)
    items = [frame.item(frame.ENTRY, LEDGER_NAME.encode("ascii"), frame.READ_OK, ledger_meta,
                        ledger_bytes)]
    return items + snapshot_items(root, sid, engine_uid)


def snapshot_items(root, sid, engine_uid):
    """One committed snapshot's declared files, as frame items. Under the lock."""
    items = []
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


def baseline_state(root):
    """(artifact bytes or None, pointer bytes or None): the system store's baselines/.

    Root-owned 0600 files in a root-owned 0700 directory (AUTH-022 as amended by D-128),
    read no-follow and bounded; anything else is refused (67), never repaired.
    """
    directory = os.path.join(root, "baselines")
    if store._conforms(directory, True, 0o700, store.OWNER_UID, store.OWNER_GID) is None:
        return None, None
    out = []
    for name in BASELINE_NAMES:
        path = os.path.join(root, name)
        if store._conforms(path, False, 0o600, store.OWNER_UID, store.OWNER_GID) is None:
            out.append(None)
            continue
        data, _meta = _read(path, BASELINE_BOUND, store.OWNER_UID, store.OWNER_GID, 0o600)
        out.append(data)
    return out[0], out[1]


def acquire_baseline(root, items, engine_uid):
    """D-128: add the baseline state to an evidence frame. Under the lock.

    The revision artifact and the pointer when present, and the approved snapshot's files
    when it is not the latest run. Which snapshot that is comes from the ledger record,
    never from the reduced side or the caller.
    """
    ledger_bytes = [i["content"] for i in items if i["name"] == LEDGER_NAME.encode("ascii")][0]
    cores = ledger_cores(ledger_bytes)
    latest, _hash = latest_snapshot(cores)
    record = baseline_record(cores)
    artifact, pointer = baseline_state(root)
    for name, data in zip(BASELINE_NAMES, (artifact, pointer)):
        if data is not None:
            items.append(frame.item(frame.ENTRY, name.encode("ascii"), frame.READ_OK,
                                    {"mode": 0o100600, "uid": store.OWNER_UID,
                                     "gid": store.OWNER_GID, "size": len(data)}, data))
    if record is not None:
        approved = _snapshot_id(record, "baseline record")
        if approved != latest:
            items.extend(snapshot_items(root, approved, engine_uid))
    return items


def acquire_evaluation(root, items):
    """AUTH-032 as extended by D-126: the committed evaluation of the reported snapshot.

    Its identity is computed here, from the ledger, the snapshot's manifest header, the
    installed engine version and the installed catalog (EVAL-006); nothing from the reduced
    side names it. Absent is not an error: the report then says the run is not evaluated.
    """
    from isedraf.launcher import evalunit
    try:
        sid, _key, evl_id = evalunit.expected_identity(items, evalunit.read_catalog())
    except evalunit.Refused as exc:
        raise Refused(str(exc))
    base = os.path.join(root, "evaluations", evl_id)
    if not os.path.lexists(base):
        return []
    _directory(os.path.join(root, "evaluations"), store.OWNER_UID, store.OWNER_GID)
    _directory(base, store.OWNER_UID, store.OWNER_GID)
    names = sorted(os.listdir(base))
    if names != sorted(evalunit.ARTIFACTS):
        raise Refused("evaluation %s does not hold exactly its four artifacts" % evl_id)
    out = []
    for name in names:
        data, meta = _read(os.path.join(base, name), evalunit.ARTIFACT_BOUND, store.OWNER_UID,
                           store.OWNER_GID, 0o600)
        out.append(frame.item(frame.ENTRY, ("evaluations/%s/%s" % (evl_id, name)).encode("ascii"),
                              frame.READ_OK, meta, data))
    return out


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
            items += acquire_evaluation(root, items)
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
    feed(proc, data)
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
