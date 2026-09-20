# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Re-verify committed evidence from the bytes on disk.
# Implements: NORM-038, SNAP-020, SNAP-021, SNAP-022, SNAP-023, STORE-024
#
# Recomputes every hash from the stored preimages rather than trusting any rendered
# value. It is deliberately NOT the golden-vector verifier: that one certifies the
# corpus, this one checks a live store, and neither is allowed to become the other.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Store verification: manifest hashes, state hashes and the ledger chain."""
import json
import os

from . import canonical, ledger


def _reserialize(obj):
    return canonical.canonical_bytes(obj)


def verify_snapshot(snapshot_dir):
    """Returns a list of problems; empty means the snapshot verifies."""
    problems = []
    mpath = os.path.join(snapshot_dir, "manifest.json")
    try:
        with open(mpath, "rb") as fh:
            raw = fh.read()
        envelope = json.loads(raw)
    except (OSError, ValueError) as exc:
        return ["%s: unreadable manifest: %s" % (snapshot_dir, exc)]
    if _reserialize(envelope) != raw:
        problems.append("%s: manifest.json is not canonical_bytes of its object"
                        % snapshot_dir)
    core = envelope.get("manifest_core")
    core_canonical = _reserialize(core)
    expected = canonical.rendered(
        canonical.hash_frame(canonical.DOMAIN_SNAPSHOT_MANIFEST, core_canonical))
    if envelope.get("manifest_hash") != expected:
        problems.append("%s: manifest_hash does not match its preimage" % snapshot_dir)

    section = core["sections"]["host_identity"]
    state_path = os.path.join(snapshot_dir, "state", "host_identity.json")
    if section["collection_status"] == "COLLECTED":
        if not os.path.exists(state_path):
            problems.append("%s: COLLECTED without state/host_identity.json (SNAP-021)"
                            % snapshot_dir)
        else:
            with open(state_path, "rb") as fh:
                state_raw = fh.read()
            state_hash = canonical.rendered(
                canonical.hash_frame(canonical.DOMAIN_STATE, state_raw))
            if section["state_hash"] != state_hash:
                problems.append("%s: state_hash does not match state/host_identity.json"
                                % snapshot_dir)
            host_id = json.loads(state_raw).get("host_id")
            # SNAP-023: the manifest host_id is byte-identical to the state object's.
            if core.get("host_id") != host_id:
                problems.append("%s: SNAP-023 manifest host_id != state host_id"
                                % snapshot_dir)
    else:
        if os.path.exists(state_path):
            problems.append("%s: state written although status is %s (SNAP-022)"
                            % (snapshot_dir, section["collection_status"]))
        if core.get("host_id") is not None:
            problems.append("%s: SNAP-023 host_id is not null for a %s section"
                            % (snapshot_dir, section["collection_status"]))
    if "host_id" not in core:
        problems.append("%s: SNAP-023 manifest_core has no host_id key" % snapshot_dir)
    return problems


def verify_ledger(root):
    """STORE-024: sequence strictly increments, previous_record_hash links, hashes hold."""
    problems = []
    previous = ledger.GENESIS_PREVIOUS
    for index, row in enumerate(ledger.read_records(root), start=1):
        core = row["record_core"]
        core_canonical = _reserialize(core)
        expected = canonical.rendered(
            canonical.hash_frame(canonical.DOMAIN_LEDGER_RECORD, core_canonical))
        if row.get("record_hash") != expected:
            problems.append("ledger record %d: record_hash does not match its preimage"
                            % index)
        if core.get("sequence") != index:
            problems.append("ledger record %d: sequence is %r (STORE-024)"
                            % (index, core.get("sequence")))
        if core.get("previous_record_hash") != previous:
            problems.append("ledger record %d: previous_record_hash breaks the chain"
                            % index)
        previous = row.get("record_hash")
    return problems


def verify_store(root):
    """Every snapshot, plus the chain. Returns a list of problems."""
    problems = list(verify_ledger(root))
    snapshots = os.path.join(root, "snapshots")
    if os.path.isdir(snapshots):
        for name in sorted(os.listdir(snapshots)):
            if name.startswith("SDS-"):
                problems.extend(verify_snapshot(os.path.join(snapshots, name)))
    return problems
