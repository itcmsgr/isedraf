# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The W1-A ledger — snapshot_committed records, hash-chained.
# Implements: STORE-024, STORE-001, SNAP-014, SNAP-018
#
# The ledger carries identifiers and hashes. It never duplicates host state and never
# carries personal data.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="state-root only"
# meta:binaries=""
# =============================================================================

"""STORE-024's record and chaining rule."""
import json
import os

from . import canonical, stateroot

LEDGER_SCHEMA_VERSION = 1
EVENT_SNAPSHOT_COMMITTED = "snapshot_committed"
GENESIS_PREVIOUS = "sha256:" + "0" * 64


def segment_path(root):
    return os.path.join(root, stateroot.LEDGER_SEGMENT)


def read_records(root):
    """Every record in the segment, in file order. Missing segment is an empty ledger."""
    path = segment_path(root)
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "rb") as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
    return out


def head(root):
    """(sequence, record_hash) of the last record, or (0, GENESIS_PREVIOUS)."""
    records = read_records(root)
    if not records:
        return 0, GENESIS_PREVIOUS
    last = records[-1]
    return last["record_core"]["sequence"], last["record_hash"]


def build_record(root, snapshot_id, manifest_hash, event_id, occurred_at,
                 state_root_class):
    """STORE-024: sequence strictly increments with no gaps; previous_record_hash links."""
    sequence, previous = head(root)
    core = {
        "ledger_schema_version": LEDGER_SCHEMA_VERSION,
        "sequence": sequence + 1,
        "event": EVENT_SNAPSHOT_COMMITTED,
        "event_id": event_id,
        "occurred_at": occurred_at,
        "previous_record_hash": previous,
        "snapshot_id": snapshot_id,
        "manifest_hash": manifest_hash,
        "state_root": state_root_class,
    }
    core_canonical = canonical.canonical_bytes(core)
    record_hash = canonical.rendered(
        canonical.hash_frame(canonical.DOMAIN_LEDGER_RECORD, core_canonical))
    return core, core_canonical, record_hash


def append(root, core, record_hash):
    """SNAP-014: ledger append + fsync, last, under the run lock. One physical line."""
    path = segment_path(root)
    row = canonical.canonical_bytes({"record_core": core, "record_hash": record_hash})
    previous = os.umask(0o077)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, row)
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.umask(previous)
    stateroot.fsync_dir(os.path.dirname(path))
    return record_hash


def unledgered_snapshots(root):
    """SNAP-018: SDS-* directories the ledger does not reference.

    The crash window SNAP-014 creates is between the atomic rename and the ledger append.
    Exactly one such directory is that crash and is recoverable; more than one is store
    discontinuity, which is a different thing and SHALL NOT be reported as a benign crash.
    """
    snapshots = os.path.join(root, "snapshots")
    if not os.path.isdir(snapshots):
        return []
    known = set(r["record_core"]["snapshot_id"] for r in read_records(root))
    return sorted(d for d in os.listdir(snapshots)
                  if d.startswith("SDS-") and d not in known)
