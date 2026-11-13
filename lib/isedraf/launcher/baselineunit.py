# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: `sudo isedraf baseline approve`, the in-unit launcher: read, decide, check, write.
# Implements: D-128, AUTH-034, AUTH-022, AUTH-032, AUTH-033, BASE-003, BASE-007, BASE-011,
#             BASE-012, BASE-013, STORE-015
#
# Root, inside the audit unit's sandbox, with the AUTH-028 set. It validates the store
# (AUTH-022), takes the whole-run lock, reads the ledger, the latest committed run and the
# baseline state as the evaluation route does, and DERIVES THE ACTION ITSELF from ISEDRAF's
# own metadata - the ledger's events, and whether baselines/BL-000001.json and
# baselines/current exist. Host evidence is never parsed here: the reduced approver verifies
# it and builds the artifact. The root side accepts the answer only when the action is the
# one it derived and every field it can compute itself - the snapshot and manifest hash it
# selected, the revision hash (SCOPE-074), the class and the packaged profile - matches;
# then it performs BASE-012's writes. No argument: the snapshot is always the latest
# committed run, and an interrupted approval is completed for the snapshot its ledger
# record names (D-128).
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="root, in the baseline unit (AUTH-034)"
# meta:mutates="/var/lib/isedraf/baselines, /var/lib/isedraf/ledger, /var/lib/isedraf/tmp"
# meta:binaries="setpriv,python3"
# =============================================================================
"""AUTH-034: the root side of system-store baseline approval."""
import json
import signal
import subprocess
import sys

from isedraf import canonical, ids, stateroot
from isedraf.baseline import approve, profile as baseline_profile, revision
from isedraf.exitcodes import (APPROVAL_REFUSED, OK, RUN_IN_PROGRESS, STATE_ROOT_UNUSABLE,
                               TOOL_INTEGRITY_FAILURE, USAGE_OR_ENGINE)
from isedraf.launcher import engine, reportunit, store
from isedraf.supervisor import frame

CLASS = stateroot.SYSTEM_PRODUCTION
ACTION_NAME = "action"
ARTIFACT_NAME = "baselines/BL-000001.json"
ANSWER_LIMIT = reportunit.BASELINE_BOUND + 4096
APPROVE_ENTRY = ("import sys; sys.path.insert(0, %r); from isedraf.launcher.approver import "
                 "main; sys.exit(main(sys.argv[1:]))" % engine.INSTALL_ROOT)
INTERRUPTED = reportunit.INTERRUPTED
STOP_SIGNALS = reportunit.STOP_SIGNALS


class Refused(Exception):
    """The store's metadata or the approver's answer fails the contract (exit 64)."""


class AlreadyApproved(Exception):
    """BASE-013: a complete baseline exists (exit 65)."""


class LedgerInconsistent(Exception):
    """BASE-011: baselines/current without a ledger record (exit 5)."""


def approve_argv():
    """The approver's constant command: the engine reduction and a fixed entry."""
    return list(engine.ARGV[:9]) + ["-IB", "-c", APPROVE_ENTRY]


def expected(items, artifact, pointer):
    """(action, selected snapshot, its manifest hash, the record in force) - metadata only."""
    by_name = dict((i["name"].decode("ascii"), i["content"]) for i in items)
    try:
        cores = reportunit.ledger_cores(by_name[reportunit.LEDGER_NAME])
        sid, ledgered_hash = reportunit.latest_snapshot(cores)
        record = reportunit.baseline_record(cores)
        envelope = json.loads(by_name["snapshots/%s/manifest.json" % sid].decode("utf-8"))
    except (reportunit.Refused, reportunit.NoCommittedRun, ValueError, KeyError,
            UnicodeDecodeError) as exc:
        raise Refused("the store's metadata cannot be read (%s)" % exc)
    if envelope.get("manifest_hash") != ledgered_hash:
        raise Refused("the latest snapshot's manifest is not the one its ledger record binds")
    if record is not None:
        if pointer is not None:
            raise AlreadyApproved(
                "%s is already approved (from %s); this version does not replace a baseline"
                % (record.get("baseline_revision"), record.get("snapshot_id")))
        return approve.WRITE_POINTER, sid, ledgered_hash, record
    if pointer is not None:
        raise LedgerInconsistent("baselines/current exists but the ledger records no "
                                 "approved baseline")
    return (approve.RESUME_LEDGER if artifact is not None else approve.NEW), sid, \
        ledgered_hash, None


def check_answer(data, action, sid, manifest_hash, record, artifact):
    """The closed contract. Returns (revision object, artifact bytes)."""
    try:
        items = frame.decode(data, ANSWER_LIMIT, 2)
    except frame.FrameError as exc:
        raise Refused("the approver's answer is not a valid frame (%s)" % exc)
    got = {}
    for it in items:
        name = it["name"].decode("ascii", "replace")
        if (it["kind"] != frame.ENTRY or it["acquisition_outcome"] != frame.READ_OK
                or name in got):
            raise Refused("the approver returned an incomplete or repeated item")
        got[name] = it["content"]
    if sorted(got) != sorted([ACTION_NAME, ARTIFACT_NAME]):
        raise Refused("the approver did not return exactly the action and the artifact")
    if got[ACTION_NAME] != action.encode("ascii"):
        raise Refused("the approver's action is not the one the store's state gives")
    raw = got[ARTIFACT_NAME]
    if len(raw) > reportunit.BASELINE_BOUND:
        raise Refused("the artifact exceeds its bound")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise Refused("the artifact is not JSON")
    if not isinstance(obj, dict) or canonical.canonical_bytes(obj) != raw:
        raise Refused("the artifact is not canonical")
    if action == approve.WRITE_POINTER:
        if (raw != artifact or revision.digest(raw) != record.get("artifact_digest")
                or obj.get("revision_hash") != record.get("revision_hash")
                or obj.get("snapshot_id") != record.get("snapshot_id")):
            raise Refused("the artifact is not the one the ledger record binds")
        return obj, raw
    if action == approve.RESUME_LEDGER and raw != artifact:
        raise Refused("the artifact is not the unledgered one on disk")
    packaged = baseline_profile.default()
    p_hash = baseline_profile.profile_hash(packaged)
    checks = (
        (obj.get("revision_id"), revision.REVISION_ID),
        (obj.get("snapshot_id"), sid),
        (obj.get("manifest_hash"), manifest_hash),
        (obj.get("state_root"), CLASS),
        (obj.get("baseline_class"), CLASS),
        (obj.get("profile"), {"object": packaged, "profile_hash": p_hash}),
        (obj.get("required_sections"), packaged["required_sections"]),
        (obj.get("tracked_sections"), packaged["tracked_sections"]),
        (obj.get("revision_hash"), revision.revision_hash(manifest_hash, p_hash)),
    )
    if any(a != b for a, b in checks):
        raise Refused("the artifact does not name the selected run, the class, the packaged "
                      "profile or the revision hash the root side computes")
    return obj, raw


def _conforming(root):
    """tmp/ and, when present, baselines/: root-owned 0700 directories (AUTH-022, 67)."""
    for name in ("tmp", "baselines"):
        path = "%s/%s" % (root, name)
        if store._conforms(path, True, 0o700, store.OWNER_UID, store.OWNER_GID) is None \
                and name == "tmp":
            raise store.Unusable("%s does not exist" % path)


_stop = []


def run(root=None, err=None, out=None, engine_uid=None, argv=None):
    err = sys.stderr if err is None else err
    out = sys.stdout if out is None else out
    root = root or store.ROOT
    try:
        reportunit.check_store(root)
        with reportunit._ReadOnlyLock(root):
            uid = engine_uid if engine_uid is not None else reportunit._engine_uid()
            artifact, pointer = reportunit.baseline_state(root)
            items = reportunit.acquire(root, uid)
            action, sid, manifest_hash, record = expected(items, artifact, pointer)
            items = reportunit.acquire_baseline(root, items, uid)
            data = frame.encode(items)
            if len(data) > reportunit.FRAME_LIMIT:
                raise Refused("the evidence exceeds %d bytes" % reportunit.FRAME_LIMIT)
            proc = subprocess.Popen(argv or approve_argv(), cwd="/",
                                    env=dict(engine.ENVIRONMENT), stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, close_fds=True, shell=False)
            reportunit.feed(proc, data)
            answer = proc.stdout.read(ANSWER_LIMIT + 1)
            proc.stdout.close()
            code = proc.wait()
            if code != OK:
                return code              # the approver refused and said why; nothing written
            if len(answer) > ANSWER_LIMIT:
                raise Refused("the approver's answer exceeds its bound")
            obj, raw = check_answer(answer, action, sid, manifest_hash, record, artifact)
            _conforming(root)
            signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
            if _stop:
                return INTERRUPTED       # a stop before the first write: nothing written
            outcome = approve.commit(root, CLASS, action, obj, raw,
                                     record.get("artifact_digest") if record else None)
    except store.Unusable as exc:
        err.write("isedraf: STATE_ROOT_UNUSABLE: %s\n" % exc)
        return STATE_ROOT_UNUSABLE
    except stateroot.RunInProgress as exc:
        err.write("isedraf: RUN_IN_PROGRESS: %s\n" % exc)
        return RUN_IN_PROGRESS
    except reportunit.NoCommittedRun as exc:
        err.write("isedraf: no committed Full Audit run (%s); run `sudo isedraf audit` first.\n"
                  % exc)
        return USAGE_OR_ENGINE
    except AlreadyApproved as exc:
        err.write("isedraf: approval refused, nothing was written: %s: %s\n"
                  % (revision.BASELINE_ALREADY_APPROVED, exc))
        return APPROVAL_REFUSED
    except LedgerInconsistent as exc:
        err.write("isedraf: baseline integrity failure, nothing was written: %s: %s\n"
                  % (revision.BASELINE_LEDGER_INVALID, exc))
        return TOOL_INTEGRITY_FAILURE
    except (Refused, reportunit.Refused, OSError, frame.FrameError) as exc:
        err.write("isedraf: APPROVAL_REFUSED: %s; nothing was written.\n" % exc)
        return USAGE_OR_ENGINE
    out.write("isedraf: baseline %s %s in the system store\n" % (
        obj["revision_id"], "approved" if outcome == approve.APPROVED
        else "completed (an interrupted approval)"))
    out.write("isedraf: a production baseline means accepted, not secure.\n")
    return OK


def main(argv):
    for signum in STOP_SIGNALS:
        signal.signal(signum, lambda s, _f: _stop.append(s))
    if len(argv) != 1 or not ids.ID_RE.match(argv[0] or "") or not argv[0].startswith("RUN-"):
        sys.stderr.write("isedraf: the baseline launcher takes a run identifier\n")
        return USAGE_OR_ENGINE
    code = run()
    signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    return INTERRUPTED if _stop and code != OK else code
