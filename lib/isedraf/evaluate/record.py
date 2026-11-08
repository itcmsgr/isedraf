# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The evaluation record: its derived identity, and a read-only, verifying reader.
# Implements: SNAP-012, SNAP-013, EVAL-005, EVAL-006
#
# EVAL-006: an evaluation's identity is derived from the SNAP-012 key, so the same
# snapshot, engine and catalog name the same directory, and a reader can find the one
# evaluation that applies without scanning or choosing between several.
#
# This module never writes. The report reads evaluations through it; it is the writer's
# (evaluate/run.py) job alone to create one, and check_architecture.py keeps the report
# from importing the writer (EVAL-001: the report never evaluates).
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""EVAL-005/006: the evaluation record and its identity."""
import hashlib
import json
import os
import re

from .. import canonical

SCHEMA_VERSION = 1
ARTIFACTS = ("results.json", "findings.json", "changes.json")
EVL_RE = re.compile(r"^EVL-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")


def digest(data):
    """Plain SHA-256 of an artifact's bytes. Not a framed hash: no new domain (NORM-038)."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def key(snapshot_id, manifest_hash, engine_version, catalog_digest):
    """SNAP-012's key. baseline_revision is null until v0.4; profile is null (EVAL-005)."""
    return {"snapshot_id": snapshot_id, "snapshot_manifest_hash": manifest_hash,
            "baseline_revision": None, "engine_version": engine_version,
            "catalog_digest": catalog_digest, "profile": None}


def evaluation_id(created_at, the_key):
    """EVL-<snapshot created_at, compact>-<16 hex of SHA-256(canonical key)> (EVAL-006)."""
    compact = created_at.replace("-", "").replace(":", "")
    suffix = hashlib.sha256(canonical.canonical_bytes(the_key)).hexdigest()[:16]
    out = "EVL-%s-%s" % (compact, suffix)
    if not EVL_RE.match(out):
        raise ValueError("snapshot created_at %r does not give an EVL identifier" % created_at)
    return out


def load(root, evaluation_id_):
    """(manifest, {artifact: object}, problems) for one committed evaluation, or None.

    None means no evaluation with that identity exists. Problems are reported, never
    repaired: an evaluation whose artifacts do not match its manifest is not shown as
    a result.
    """
    base = os.path.join(root, "evaluations", evaluation_id_)
    if not os.path.isdir(base):
        return None
    problems, objects = [], {}
    try:
        with open(os.path.join(base, "manifest.json"), "rb") as fh:
            raw = fh.read()
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as exc:
        return {}, {}, ["%s: the evaluation manifest cannot be read: %s" % (evaluation_id_, exc)]
    if canonical.canonical_bytes(manifest) != raw:
        problems.append("%s: manifest.json is not canonical" % evaluation_id_)
    if manifest.get("evaluation_id") != evaluation_id_:
        problems.append("%s: the manifest names another evaluation" % evaluation_id_)
    bound = manifest.get("artifacts") if isinstance(manifest, dict) else None
    for name in ARTIFACTS:
        try:
            with open(os.path.join(base, name), "rb") as fh:
                data = fh.read()
        except OSError:
            problems.append("%s: %s is missing" % (evaluation_id_, name))
            continue
        if not isinstance(bound, dict) or bound.get(name) != digest(data):
            problems.append("%s: %s does not match its manifest digest" % (evaluation_id_, name))
            continue
        try:
            objects[name] = json.loads(data.decode("utf-8"))
        except ValueError:
            problems.append("%s: %s is not JSON" % (evaluation_id_, name))
    return manifest, objects, problems
