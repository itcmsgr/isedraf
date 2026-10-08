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

# D-115. THE AUTHORITATIVE AUXILIARY SET, written out rather than discovered.
#
# Explicit and bounded, deliberately. A recursive "hash everything under the snapshot
# directory" rule would make snapshot identity depend on whatever files happened to be
# there - an editor swap file would change the manifest - and it would also silently
# absorb a hostile addition instead of refusing it. Adding an artifact to the bundle is a
# contract change, so it appears here.
AUXILIARY_ARTIFACTS = ("coverage/evidence_limits.json", "method/host_identity.json")

# GA v0.1, `isedraf audit` (owner decision 2026-09-27; D-115 extension pending the
# owner's amendment): one report section per audited domain, bound as an auxiliary
# artifact - integrity-bound by manifest_core, outside state_hash. Named, not globbed.
SECTION_NAMES = ("inventory", "nss", "hostname", "accounts", "sudo", "ssh", "pam",
                 "loginpolicy", "mounts", "authorizedkeys")
SECTION_ARTIFACTS = tuple("sections/%s.json" % n for n in SECTION_NAMES)
AUXILIARY_ARTIFACTS = AUXILIARY_ARTIFACTS + SECTION_ARTIFACTS

# Which of them every snapshot must carry. `coverage/` is written only when a coverage
# manifest was produced; `method/` always is.
REQUIRED_AUXILIARY = ("method/host_identity.json",)


def auxiliary_digest(data):
    """The digest of one auxiliary artifact's exact bytes."""
    return canonical.rendered(
        canonical.hash_frame(canonical.DOMAIN_AUXILIARY_ARTIFACT, data))


def manifest_core(ident, snapshot_id, run_id, created_at, state_root_class,
                  engine_version, auxiliary=None):
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
        # D-115. Bound here, and therefore covered by manifest_hash and by the ledger
        # chain that binds it.
        #
        # A MAP keyed by bundle-relative path, not a list of objects. The first attempt
        # was a list and NORM-037 refused it: an array-typed field in W1-A needs a
        # schema-defined total ordering with a golden fixture, because an unordered
        # array is a set whose serialization nobody has pinned. A map has no such
        # question - canonical_bytes sorts object keys (NORM-035), so the ordering is
        # the serializer's and not this function's. It also follows the precedent
        # directly above: `sections` is a map keyed by section name for the same reason.
        #
        # This is NOT part of host-state identity. An auxiliary change moves
        # manifest_hash and leaves state_hash untouched, which is the whole point: a
        # coverage delta is not a host-state delta, and neither is a provenance delta.
        "auxiliary_artifacts": dict(auxiliary or {}),
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


def build(ident, snapshot_id, run_id, created_at, state_root_class, engine_version,
          coverage_manifest=None, sections=None):
    """Everything a snapshot needs, computed before anything touches the store.

    The Evidence Limits Manifest (`coverage_manifest`, schema 2, D-122) is PROVENANCE -
    what the collection could observe - and travels with the bundle as its own file,
    coverage/evidence_limits.json. D-115 binds it through manifest_core's
    auxiliary_artifacts, so it is covered by manifest_hash and never enters state_hash: a
    change in what the collection could see is never a change in host state. It also
    carries its own coverage_digest, which is what a later comparison needs.
    """
    method = canonical.canonical_bytes(identity.method_object())
    coverage_bytes = (None if coverage_manifest is None
                      else canonical.canonical_bytes(coverage_manifest))
    auxiliary = {"method/host_identity.json": auxiliary_digest(method)}
    if coverage_bytes is not None:
        auxiliary["coverage/evidence_limits.json"] = auxiliary_digest(coverage_bytes)
    section_bytes = {}
    for name, obj in sorted((sections or {}).items()):
        if name not in SECTION_NAMES:
            raise ValueError("section %r is not in the authoritative set" % name)
        section_bytes[name] = canonical.canonical_bytes(obj)
        auxiliary["sections/%s.json" % name] = auxiliary_digest(section_bytes[name])
    core = manifest_core(ident, snapshot_id, run_id, created_at, state_root_class,
                         engine_version, auxiliary)
    core_canonical = canonical.canonical_bytes(core)
    manifest_hash = canonical.rendered(
        canonical.hash_frame(canonical.DOMAIN_SNAPSHOT_MANIFEST, core_canonical))
    return {
        "manifest_core": core,
        "manifest_core_canonical": core_canonical,
        "manifest_hash": manifest_hash,
        "manifest": canonical.canonical_bytes(
            {"manifest_core": core, "manifest_hash": manifest_hash}),
        "method": method,
        "state": ident.state_canonical,
        "coverage": coverage_bytes,
        "coverage_digest": (None if coverage_manifest is None
                            else coverage_manifest["coverage_digest"]),
        "sections": section_bytes,
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
        if built.get("coverage") is not None:
            os.makedirs(os.path.join(staging, "coverage"), mode=0o700)
            stateroot.write_file(
                os.path.join(staging, "coverage", "evidence_limits.json"),
                built["coverage"])
            stateroot.fsync_dir(os.path.join(staging, "coverage"))
        if built.get("sections"):
            # Inside the same private staging directory, so the one atomic rename below
            # commits the identity snapshot and every section together, or neither.
            os.makedirs(os.path.join(staging, "sections"), mode=0o700)
            for name, data in sorted(built["sections"].items()):
                stateroot.write_file(os.path.join(staging, "sections", name + ".json"),
                                     data)
            stateroot.fsync_dir(os.path.join(staging, "sections"))
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
