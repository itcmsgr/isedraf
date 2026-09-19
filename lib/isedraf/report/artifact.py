# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: A deterministic, addressable representation of one inventory collection.
# Implements: NORM-035, SNAP-019
#
# DELIBERATELY NOT A SNAPSHOT HASH. There is no HASH_FRAME_V1 domain here and there will
# not be one until a freeze set defines it: inventing a hash domain is a frozen
# architecture decision, and this is a content digest over a deterministic artifact.
# The naming says so everywhere, so the two can never be read as the same claim.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""The inventory artifact: canonical bytes, a content digest, and an identifier."""
import hashlib

from .. import canonical, ids

ARTIFACT_KIND = "isedraf.inventory-artifact"
ARTIFACT_VERSION = 1


def build(inventory, collected_at=None, collection_id=None):
    """Wrap one inventory collection into an addressable artifact.

    The digest covers the artifact WITHOUT its own digest, for the same reason
    `manifest_hash` is excluded from its own preimage (SNAP-020): a value cannot be an
    input to itself.
    """
    collected_at = collected_at or ids.now_utc()
    collection_id = collection_id or ids.new_id("INV", collected_at)
    core = {
        "artifact_kind": ARTIFACT_KIND,
        "artifact_version": ARTIFACT_VERSION,
        "collection_id": collection_id,
        "collected_at": collected_at,
        "inventory": inventory,
    }
    core_bytes = canonical.canonical_bytes(core)
    return {
        "core": core,
        "canonical_bytes": core_bytes,
        # A plain SHA-256 over canonical bytes. NOT HASH_FRAME_V1, NOT a snapshot hash,
        # and named so that no reader can mistake it for either.
        "artifact_digest": "sha256:" + hashlib.sha256(core_bytes).hexdigest(),
    }
