# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Build and commit a W1-A snapshot.
# Implements: SNAP-014, SNAP-019, SNAP-020, SNAP-021, SNAP-022, SNAP-023, CMP-020,
#             SCOPE-045, SCOPE-048
#
# A snapshot is observed state. It never contains findings, changes or an evaluation.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="state-root only"
# meta:binaries=""
# =============================================================================

"""SNAP-020's manifest and SNAP-021's three files, committed by SNAP-014's ordering."""
import os
import shutil

from . import canonical, identity, ids, stateroot

SCHEMA_VERSION = 1
SECTION = "host_identity"


def manifest_core(ident, snapshot_id, run_id, created_at, state_root_class,
                  engine_version):
    """SNAP-020's field table, with SNAP-023 deciding host_id.

    SNAP-023: host_id is the canonical identifier iff COLLECTED and IDENT-005 derived it;
    otherwise null. The key is present in both cases, because NORM-034 makes null and
    absent distinct. A COLLECTED section with no host_id is an invariant violation and is
    raised here rather than normalized into a valid-looking snapshot binding to no host.
    """
    if ident.collected and not ident.host_id:
        raise ValueError(
            "SNAP-023: COLLECTED with no derived host_id is an invariant violation")
    if not ident.collected and ident.host_id:
        raise ValueError(
            "SNAP-023: host_id derived for a %s section" % ident.status)
    return {
        "schema_version": SCHEMA_VERSION,
        "host_id": ident.host_id if ident.collected else None,
        "snapshot_id": snapshot_id,
        "run_id": run_id,
        "created_at": created_at,
        "state_root": state_root_class,          # PRIV-004's literal spelling
        "engine_version": engine_version,
        "sections": {SECTION: {
            "collection_status": ident.status,
            "state_hash": ident.state_hash,      # null unless COLLECTED (SNAP-022)
            "reason": ident.reason,              # null when COLLECTED (NORM-040)
            "collector_id": identity.COLLECTOR_ID,
            "collector_version": identity.COLLECTOR_VERSION,
            "parser_version": identity.PARSER_VERSION,
            "classification_table_version": identity.CLASSIFICATION_TABLE_VERSION,
            "source_id": identity.SOURCE_ID,     # CMP-020, IDENT-006
        }},
    }


def build(ident, snapshot_id, run_id, created_at, state_root_class, engine_version):
    """Everything a snapshot needs, computed before anything touches the store."""
    core = manifest_core(ident, snapshot_id, run_id, created_at, state_root_class,
                         engine_version)
    core_canonical = canonical.canonical_bytes(core)
    manifest_hash = canonical.rendered(
        canonical.hash_frame(canonical.DOMAIN_SNAPSHOT_MANIFEST, core_canonical))
    return {
        "manifest_core": core,
        "manifest_core_canonical": core_canonical,
        "manifest_hash": manifest_hash,
        "manifest": canonical.canonical_bytes(
            {"manifest_core": core, "manifest_hash": manifest_hash}),
        "method": canonical.canonical_bytes(identity.method_object()),
        "state": ident.state_canonical,
    }


def commit(root, built, snapshot_id):
    """SNAP-014's ordering: private temp dir -> write -> fsync -> atomic rename.

    SNAP-021: the directory holds manifest.json, method/host_identity.json and, when the
    section is COLLECTED, state/host_identity.json. Each is canonical_bytes of its object.
    SNAP-022: a non-COLLECTED snapshot is still committed — an honest record of what could
    not be collected is evidence.
    """
    tmp_parent = os.path.join(root, "tmp")
    staging = os.path.join(tmp_parent, snapshot_id)
    final = os.path.join(root, "snapshots", snapshot_id)
    if os.path.exists(final):
        raise ValueError("snapshot %s already exists" % snapshot_id)
    previous = os.umask(0o077)
    try:
        os.makedirs(staging, mode=0o700)
        os.makedirs(os.path.join(staging, "method"), mode=0o700)
        stateroot.write_file(os.path.join(staging, "manifest.json"), built["manifest"])
        stateroot.write_file(os.path.join(staging, "method", "host_identity.json"),
                             built["method"])
        if built["state"] is not None:
            os.makedirs(os.path.join(staging, "state"), mode=0o700)
            stateroot.write_file(os.path.join(staging, "state", "host_identity.json"),
                                 built["state"])
            stateroot.fsync_dir(os.path.join(staging, "state"))
        stateroot.fsync_dir(os.path.join(staging, "method"))
        stateroot.fsync_dir(staging)
        os.rename(staging, final)                       # atomic within the state root
        stateroot.fsync_dir(os.path.join(root, "snapshots"))
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        os.umask(previous)
    return final


def new_ids(created_at=None):
    ts = created_at or ids.now_utc()
    return ts, ids.new_id("SDS", ts), ids.new_id("RUN", ts), ids.new_id("EVT", ts)
