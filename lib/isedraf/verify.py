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

from . import canonical, ledger, snapshot as snapshot_mod, stateroot
from .supervisor import contracts

# AUTH-017. Recognised here only to refuse it out of place; coverage.MODES admits it
# when an operation is IMPLEMENTED (AUTH-007), and nothing here produces it.
SUPERVISOR_ACQUISITION = "SUPERVISOR_FIXED_OPERATION"


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
    if core.get("state_root") not in stateroot.STATE_ROOT_CLASSES:
        # STORE-026: one literal of a closed vocabulary; anything else names no class.
        problems.append("%s: state_root %r is not an artifact class (STORE-026)"
                        % (snapshot_dir, core.get("state_root")))

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
    problems.extend(_auxiliary(snapshot_dir, core))
    problems.extend(_authority(snapshot_dir, core))
    return problems


def _authority(snapshot_dir, core):
    """AUTH-017 and AUTH-018 (D-124). Refused, never repaired.

    The run mode, when recorded, is one of the two values and pairs with the class. Every
    source in the bound Evidence Limits Manifest then agrees with it: a supervisor
    acquisition only in a FULL_AUDIT run and only under the exact identifier of an
    operation this version has IMPLEMENTED; anything else carries a null operation_id.
    A snapshot without run_mode (GA 0.1.x, W1-A) is "not recorded", which is never
    FULL_AUDIT.
    """
    out = []
    run_mode = core.get("run_mode")
    if "run_mode" in core:
        if run_mode not in stateroot.RUN_MODES:
            out.append("%s: AUTH-018 run_mode %r is not a run mode" % (snapshot_dir, run_mode))
        elif run_mode != stateroot.RUN_MODE_OF_CLASS.get(core.get("state_root")):
            out.append("%s: AUTH-018 run_mode %s cannot pair with state_root %r"
                       % (snapshot_dir, run_mode, core.get("state_root")))
    if "coverage/evidence_limits.json" not in (core.get("auxiliary_artifacts") or {}):
        return out
    try:
        with open(os.path.join(snapshot_dir, "coverage", "evidence_limits.json"), "rb") as fh:
            limits = json.loads(fh.read())
        sources = list(limits.get("sources", []))
    except (OSError, ValueError, AttributeError, TypeError):
        return out + ["%s: AUTH-017 the bound evidence limits cannot be read" % snapshot_dir]
    for entry in sources:
        mode = entry.get("acquisition_mode") if isinstance(entry, dict) else None
        oid = entry.get("operation_id") if isinstance(entry, dict) else None
        where = "%s: AUTH-017 source %s/%s" % (
            snapshot_dir, entry.get("domain") if isinstance(entry, dict) else "?",
            entry.get("source") if isinstance(entry, dict) else "?")
        if mode == SUPERVISOR_ACQUISITION:
            if run_mode != stateroot.FULL_AUDIT:
                out.append("%s was acquired by the supervisor outside a FULL_AUDIT run" % where)
            if contracts.enabled(oid) is None:
                out.append("%s names %r, which is not an IMPLEMENTED operation" % (where, oid))
        elif oid is not None:
            out.append("%s carries operation_id %r without a supervisor acquisition"
                       % (where, oid))
    return out


def _auxiliary(snapshot_dir, core):
    """D-115. Every declared auxiliary artifact is OPENED and checked.

    Before this, `method/host_identity.json` sat in every bundle and nothing read it back:
    manifest_core carried the collector and parser versions but no digest of the file, so
    the bytes could be replaced and the snapshot would still verify. R1.5-P added a second
    artifact of the same class - the Evidence Limits Manifest, which decides
    absence_claim_allowed - and made the gap worth closing rather than recording.

    Both directions are checked. A declared artifact that is missing, modified or
    substituted fails; and an artifact the schema REQUIRES which is present in the bundle
    but absent from the declaration also fails, so binding cannot be evaded by removing
    the entry as well as changing the file.
    """
    out = []
    declared = core.get("auxiliary_artifacts")
    if declared is None:
        return ["%s: D-115 manifest_core has no auxiliary_artifacts key" % snapshot_dir]
    seen = set()
    for path, digest in sorted(declared.items()):
        if path not in snapshot_mod.AUXILIARY_ARTIFACTS:
            out.append("%s: D-115 auxiliary path %r is not in the authoritative set"
                       % (snapshot_dir, path))
            continue
        seen.add(path)
        full = os.path.join(snapshot_dir, path)
        try:
            with open(full, "rb") as handle:
                data = handle.read()
        except OSError:
            out.append("%s: D-115 bound auxiliary artifact %s is missing or unreadable"
                       % (snapshot_dir, path))
            continue
        if digest != snapshot_mod.auxiliary_digest(data):
            out.append("%s: D-115 auxiliary artifact %s does not match its binding"
                       % (snapshot_dir, path))
    for path in snapshot_mod.AUXILIARY_ARTIFACTS:
        if path in seen:
            continue
        present = os.path.exists(os.path.join(snapshot_dir, path))
        if present:
            out.append("%s: D-115 auxiliary artifact %s is in the bundle and is not "
                       "bound by manifest_core" % (snapshot_dir, path))
        elif path in snapshot_mod.REQUIRED_AUXILIARY:
            out.append("%s: D-115 required auxiliary artifact %s is absent"
                       % (snapshot_dir, path))
    return out


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
        if core.get("state_root") not in stateroot.STATE_ROOT_CLASSES:
            problems.append("ledger record %d: state_root %r is not an artifact class "
                            "(STORE-026)" % (index, core.get("state_root")))
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
