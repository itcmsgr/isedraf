# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Baseline approval: plan (decide, verify, build) and commit (the only writer).
# Implements: BASE-002, BASE-003, BASE-007, BASE-009, BASE-012, BASE-013, BASE-021,
#             BASE-022, BASE-026, STORE-001, STORE-015, STORE-020, SNAP-014, D-128
#
# D-128: the system route runs `plan` in the reduced approver and `commit` on the root
# side, after the root side has re-derived the action from the store itself.
#
# Explicit only (BASE-002): nothing approves a snapshot by itself. The caller holds the
# whole-run lock. Write order (D-127), with the ledger append as the commit point:
#   1 compute the artifact   2 stage it in tmp/ + fsync   3 baselines/ 0700 + fsync root
#   4 link into baselines/ (never overwrites) + fsync   5 append baseline_approved + fsync
#   6 write baselines/current via tmp/ + rename + fsync
# An interrupted approval is completed by running the same approval again; what each
# interruption leaves, and what evaluate and approve then do, is D-127's table. Nothing
# here deletes anything outside tmp/.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="<state root>/baselines, <state root>/ledger and <state root>/tmp"
# meta:binaries=""
# =============================================================================
"""BASE-007: approve one verified DEV snapshot as BL-000001."""
import os

from .. import ids, ledger, stateroot
from . import revision

APPROVED = "APPROVED"
COMPLETED = "COMPLETED"            # an interrupted approval of the same snapshot finished


def _stage(root, name, data):
    """Write data to tmp/<name> exclusively; a stale staging file of that name is removed."""
    staging = os.path.join(root, "tmp", name)
    if os.path.lexists(staging):
        os.unlink(staging)                         # tmp/ is ISEDRAF scratch, never evidence
    stateroot.write_file(staging, data)
    return staging


def _write_current(root, obj, artifact_digest):
    staging = _stage(root, "baseline-current", revision.current_bytes(obj, artifact_digest))
    os.rename(staging, revision.current_path(root))
    stateroot.fsync_dir(revision.baselines_dir(root))


# The three write plans an approval can need (D-127 BASE-012; D-128 for the system route).
NEW = "NEW"                        # steps 2-6
RESUME_LEDGER = "RESUME_LEDGER"    # the artifact is linked, its record is not: steps 5-6
WRITE_POINTER = "WRITE_POINTER"    # the record exists, `current` does not: step 6


def plan(root, store_class, snapshot_id, load_snapshot, complete_recorded=False):
    """(action, revision object, artifact bytes). Decides and verifies; writes nothing.

    Raises revision.ApprovalRefused (65) or IntegrityFailure (5); `load_snapshot` raises for
    a snapshot that is unknown or does not verify (64). With `complete_recorded`, an
    interrupted approval is completed for the snapshot its ledger record names, whatever
    `snapshot_id` says: the system route names no snapshot (D-128).
    """
    core, manifest_hash, data = load_snapshot(snapshot_id)      # 64 when unknown (BASE-013)
    revision.check_class(snapshot_id, core, store_class)        # 65, class first
    records, existing, current = revision.store_state(root)
    if records:
        recorded = records[-1]
        if current is not None or (not complete_recorded
                                   and recorded.get("snapshot_id") != snapshot_id):
            raise revision.ApprovalRefused(revision.BASELINE_ALREADY_APPROVED, (
                "%s is already approved (from %s); this version does not replace a "
                "baseline" % (recorded.get("baseline_revision"), recorded.get("snapshot_id"))))
        # Interrupted after the ledger append: verify everything except the pointer, which
        # is exactly what is missing (BASE-011), then only the pointer is written.
        verified, _info = revision.verify(root, store_class, load_snapshot,
                                          require_pointer=False)
        return WRITE_POINTER, verified, existing
    obj = revision.build(snapshot_id, manifest_hash, core, data, store_class)   # 65
    raw = revision.artifact_bytes(obj)
    if existing is not None:
        if existing != raw:
            raise revision.ApprovalRefused(revision.UNLEDGERED_REVISION_PRESENT, (
                "baselines/%s.json exists without a ledger record and is not this "
                "approval; it is kept as found (ORPHANED_UNLEDGERED). Approve the "
                "snapshot it names, or remove it." % revision.REVISION_ID))
        return RESUME_LEDGER, obj, raw
    return NEW, obj, raw


def commit(root, store_class, action, obj, raw, artifact_digest=None):
    """BASE-012's writes for one planned action. The caller holds the whole-run lock.

    `artifact_digest` is the recorded digest for WRITE_POINTER; otherwise it is computed
    from `raw` here. Returns APPROVED or COMPLETED.
    """
    previous = os.umask(0o077)
    try:
        if action == WRITE_POINTER:
            _write_current(root, obj, artifact_digest)                            # step 6
            return COMPLETED
        artifact_digest = revision.digest(raw)
        if action == NEW:
            staging = _stage(root, revision.REVISION_ID + ".json", raw)          # step 2
            os.makedirs(revision.baselines_dir(root), mode=0o700, exist_ok=True)  # step 3
            stateroot.fsync_dir(root)
            os.link(staging, revision.revision_path(root))                      # step 4
            os.unlink(staging)
            stateroot.fsync_dir(revision.baselines_dir(root))
        elif action != RESUME_LEDGER:
            raise ValueError("not an approval action: %r" % (action,))
        occurred_at = ids.now_utc()
        rcore, _canon, rhash = ledger.build_baseline_record(
            root, obj["revision_id"], obj["revision_hash"], artifact_digest,
            obj["snapshot_id"], obj["manifest_hash"], ids.new_id("EVT", occurred_at),
            occurred_at, store_class)
        ledger.append(root, rcore, rhash)                                         # step 5
        _write_current(root, obj, artifact_digest)                                # step 6
    finally:
        os.umask(previous)
    return APPROVED if action == NEW else COMPLETED


def approve(root, store_class, snapshot_id, load_snapshot):
    """(outcome, revision object): the DEV command, plan and commit in one process.

    `load_snapshot(snapshot_id)` -> (core, manifest_hash, data) of a ledgered snapshot that
    verifies, or raises (the CLI maps that to 64, nothing written).
    """
    action, obj, raw = plan(root, store_class, snapshot_id, load_snapshot)
    digest = revision.digest(raw) if raw is not None else None
    if action == WRITE_POINTER:
        digest = revision.store_state(root)[0][-1]["artifact_digest"]
    return commit(root, store_class, action, obj, raw, digest), obj
