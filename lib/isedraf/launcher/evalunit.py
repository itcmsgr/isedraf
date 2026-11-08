# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: `sudo isedraf evaluate`, the in-unit launcher: read, frame, promote (AUTH-033).
# Implements: AUTH-033, AUTH-022, AUTH-032, EVAL-005, EVAL-006, EVAL-007, STORE-020
#
# Root, inside the audit unit's sandbox, with the AUTH-028 set. This launcher does only
# this: validate the store (AUTH-022), take the whole-run lock, read the ledger and the
# latest committed snapshot exactly as the report route does (reportunit.acquire), read the
# installed catalog, compute the evaluation identity ITSELF, hand one frame to the reduced
# evaluator, and promote the four artifacts it returns under a closed contract. It never
# parses host evidence and never interprets a result: of the returned artifacts it reads
# only evaluation_id, snapshot_id, state_root and the manifest's digest map.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="root, in the evaluation unit (AUTH-033)"
# meta:mutates="/var/lib/isedraf/evaluations and /var/lib/isedraf/tmp"
# meta:binaries="setpriv,python3"
# =============================================================================
"""AUTH-033: the root side of system-store evaluation."""
import json
import os
import shutil
import signal
import stat
import subprocess
import sys

from isedraf import ENGINE_VERSION, canonical, catalog, ids, stateroot
from isedraf.evaluate import record
from isedraf.exitcodes import (OK, RUN_IN_PROGRESS, STATE_ROOT_UNUSABLE, USAGE_OR_ENGINE)
from isedraf.launcher import engine, reportunit, store
from isedraf.supervisor import frame

CLASS = stateroot.SYSTEM_PRODUCTION
CATALOG_NAME = "catalog/native_controls.json"
CATALOG_BOUND = 4 * 1024 * 1024
ARTIFACT_BOUND = 16 * 1024 * 1024
ARTIFACTS = ("manifest.json",) + record.ARTIFACTS
OUT_LIMIT = 4 * (ARTIFACT_BOUND + 4096)
FRAME_ITEMS = reportunit.FRAME_ITEMS + 1
EVALUATE_ENTRY = ("import sys; sys.path.insert(0, %r); from isedraf.launcher.evaluator import "
                  "main; sys.exit(main(sys.argv[1:]))" % engine.INSTALL_ROOT)
INTERRUPTED = reportunit.INTERRUPTED
STOP_SIGNALS = reportunit.STOP_SIGNALS


class Refused(Exception):
    """The evidence, the catalog or the evaluator's answer fails the contract (exit 64)."""


def evaluate_argv():
    """The evaluator's constant command: the engine reduction and a fixed entry."""
    return list(engine.ARGV[:9]) + ["-IB", "-c", EVALUATE_ENTRY]


def read_catalog(path=catalog.REGISTRY):
    """The installed catalog's bytes: a root-owned regular file, not writable by others."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != store.OWNER_UID
                or st.st_mode & 0o022 or st.st_size > CATALOG_BOUND):
            raise Refused("the installed catalog is not a root-owned, unshared regular file "
                          "within its bound")
        data = os.read(fd, CATALOG_BOUND + 1)
        if len(data) > CATALOG_BOUND:
            raise Refused("the installed catalog exceeds its bound")
        return data
    finally:
        os.close(fd)


def expected_identity(items, catalog_bytes, engine_version=ENGINE_VERSION):
    """(snapshot_id, key, evaluation_id) from ISEDRAF's own integrity metadata only:
    the last ledger record, the selected snapshot's manifest header and the catalog digest."""
    by_name = dict((i["name"].decode("ascii"), i["content"]) for i in items)
    lines = [l for l in by_name[reportunit.LEDGER_NAME].split(b"\n") if l.strip()]
    try:
        sid = json.loads(lines[-1].decode("utf-8"))["record_core"]["snapshot_id"]
        envelope = json.loads(by_name["snapshots/%s/manifest.json" % sid].decode("utf-8"))
        manifest_hash = envelope["manifest_hash"]
        created_at = envelope["manifest_core"]["created_at"]
    except (ValueError, KeyError, TypeError, IndexError):
        raise Refused("the latest committed snapshot has no readable manifest header")
    if not isinstance(created_at, str) or not ids.TS_RE.match(created_at):
        raise Refused("the snapshot manifest carries no valid creation time")
    the_key = record.key(sid, manifest_hash, engine_version, catalog.digest(catalog_bytes))
    try:
        return sid, the_key, record.evaluation_id(created_at, the_key)
    except ValueError as exc:
        raise Refused(str(exc))


def check_answer(data, sid, the_key, evl_id, state_root_class=None):
    state_root_class = state_root_class or CLASS
    """The closed promotion contract. Returns {name: bytes}; reads no result."""
    try:
        items = frame.decode(data, OUT_LIMIT, len(ARTIFACTS))
    except frame.FrameError as exc:
        raise Refused("the evaluator's answer is not a valid frame (%s)" % exc)
    out = {}
    for it in items:
        name = it["name"].decode("ascii", "replace")
        # The frame bound (four items) and the exact-set check below decide which names
        # are accepted; a repeated name would hide one of the four, so it is refused here.
        if (it["kind"] != frame.ENTRY or it["acquisition_outcome"] != frame.READ_OK
                or name in out):
            raise Refused("the evaluator returned an incomplete or repeated item")
        if len(it["content"]) > ARTIFACT_BOUND:
            raise Refused("%s exceeds its bound" % name)
        out[name] = it["content"]
    if sorted(out) != sorted(ARTIFACTS):
        raise Refused("the evaluator did not return exactly the four artifacts")
    objects = {}
    for name, raw in out.items():
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise Refused("%s is not JSON" % name)
        if not isinstance(obj, dict) or canonical.canonical_bytes(obj) != raw:
            raise Refused("%s is not canonical" % name)
        if (obj.get("evaluation_id") != evl_id or obj.get("snapshot_id") != sid
                or obj.get("state_root") != state_root_class):
            raise Refused("%s names another evaluation, snapshot or class" % name)
        objects[name] = obj
    manifest = objects["manifest.json"]
    if manifest.get("key") != the_key:
        raise Refused("the manifest carries another key")
    declared = manifest.get("artifacts")
    if not isinstance(declared, dict) or sorted(declared) != sorted(record.ARTIFACTS) or any(
            declared[n] != record.digest(out[n]) for n in record.ARTIFACTS):
        raise Refused("an artifact does not match the digest its manifest declares")
    return out


def _conforming_dir(path):
    if store._conforms(path, True, 0o700, store.OWNER_UID, store.OWNER_GID) is None:
        raise store.Unusable("%s is not a root-owned 0700 directory" % path)


def promote(root, evl_id, out):
    """(path, created). Under the lock, stop signals blocked by the caller (AUTH-033)."""
    evaluations = os.path.join(root, "evaluations")
    tmp = os.path.join(root, "tmp")
    previous = os.umask(0o077)
    try:
        for path in (evaluations, tmp):
            if not os.path.lexists(path):
                os.mkdir(path, 0o700)
            _conforming_dir(path)
        final = os.path.join(evaluations, evl_id)
        if os.path.lexists(final):
            _conforming_dir(final)
            names = sorted(os.listdir(final))
            same = names == sorted(out)
            for name in names if same else ():
                data, _meta = reportunit._read(os.path.join(final, name), ARTIFACT_BOUND,
                                               store.OWNER_UID, store.OWNER_GID, 0o600)
                same = same and data == out[name]
            if not same:
                raise Refused("%s already exists with different content; it is never "
                              "overwritten" % evl_id)
            return final, False
        staging = os.path.join(tmp, evl_id)
        os.mkdir(staging, 0o700)
        try:
            for name in sorted(out):
                stateroot.write_file(os.path.join(staging, name), out[name])
            stateroot.fsync_dir(staging)
            os.rename(staging, final)
            stateroot.fsync_dir(evaluations)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return final, True
    finally:
        os.umask(previous)


_stop = []


def run(root=None, err=None, out=None, engine_uid=None, argv=None, catalog_path=catalog.REGISTRY,
        state_root_class=None):
    state_root_class = state_root_class or CLASS
    err = sys.stderr if err is None else err
    out = sys.stdout if out is None else out
    root = root or store.ROOT
    try:
        reportunit.check_store(root)
        with reportunit._ReadOnlyLock(root):
            items = reportunit.acquire(root, engine_uid if engine_uid is not None
                                       else reportunit._engine_uid())
            catalog_bytes = read_catalog(catalog_path)
            sid, the_key, evl_id = expected_identity(items, catalog_bytes)
            items.append(frame.item(frame.ENTRY, CATALOG_NAME.encode("ascii"), frame.READ_OK,
                                    {"mode": 0o100644, "uid": store.OWNER_UID,
                                     "gid": store.OWNER_GID, "size": len(catalog_bytes)},
                                    catalog_bytes))
            data = frame.encode(items)
            if len(data) > reportunit.FRAME_LIMIT:
                raise Refused("the evidence exceeds %d bytes" % reportunit.FRAME_LIMIT)
            proc = subprocess.Popen(argv or evaluate_argv(), cwd="/", env=dict(engine.ENVIRONMENT),
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True,
                                    shell=False)
            reportunit.feed(proc, data)
            answer = proc.stdout.read(OUT_LIMIT + 1)
            proc.stdout.close()
            code = proc.wait()
            if code != OK:
                return code              # the evaluator refused and said why; nothing written
            if len(answer) > OUT_LIMIT:
                raise Refused("the evaluator's answer exceeds its bound")
            artifacts = check_answer(answer, sid, the_key, evl_id, state_root_class)
            signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
            if _stop:
                return INTERRUPTED       # a stop before the first write: nothing promoted
            path, created = promote(root, evl_id, artifacts)
    except store.Unusable as exc:
        err.write("isedraf: STATE_ROOT_UNUSABLE: %s\n" % exc)
        return STATE_ROOT_UNUSABLE
    except stateroot.RunInProgress as exc:
        err.write("isedraf: RUN_IN_PROGRESS: %s\n" % exc)
        return RUN_IN_PROGRESS
    except reportunit.NoCommittedRun as exc:
        err.write("isedraf: no committed Full Audit run (%s); run `sudo isedraf audit` first. "
                  "An evaluation reads committed evidence and never collects.\n" % exc)
        return USAGE_OR_ENGINE
    except (Refused, reportunit.Refused, OSError, frame.FrameError) as exc:
        err.write("isedraf: EVALUATION_REFUSED: %s; nothing was written.\n" % exc)
        return USAGE_OR_ENGINE
    out.write("isedraf: evaluation %s %s\n" % (evl_id, "committed in the system store"
                                               if created else "already committed, identical"))
    return OK


def main(argv):
    for signum in STOP_SIGNALS:
        signal.signal(signum, lambda s, _f: _stop.append(s))
    if len(argv) != 1 or not ids.ID_RE.match(argv[0] or "") or not argv[0].startswith("RUN-"):
        sys.stderr.write("isedraf: the evaluation launcher takes a run identifier\n")
        return USAGE_OR_ENGINE
    code = run()
    signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    return INTERRUPTED if _stop and code != OK else code
