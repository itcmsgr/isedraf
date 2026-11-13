# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The packaged baseline profile of this release and its profile hash.
# Implements: BASE-005, BASE-020, BASE-021, SCOPE-073
#
# BASE-021: the required sections come from a versioned profile shipped with the release,
# never from the baseline being created. D-127 admits `v0.4-default-1` (owner rulings D2
# and O2, 2026-11-11) in the object shape SCOPE-073 freezes. It is immutable data in the
# installed package - packaging installs every .py under lib/isedraf, so the profile needs
# no separate data file and no packaging change.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""BASE-021: the release's default baseline profile."""
from .. import canonical

# SCOPE-073's shape; every list sorted (BASE-005). REQUIRED == TRACKED at first approval
# (BASE-022), and no section is narrowed to what a host can collect (BASE-026).
DEFAULT = {
    "optional_sections": [],
    "profile_id": "v0.4-default-1",
    "profile_version": 1,
    "required_sections": ["accounts", "host_identity", "loginpolicy", "ssh"],
    "tracked_sections": ["accounts", "host_identity", "loginpolicy", "ssh"],
}
PROFILES = {(DEFAULT["profile_id"], DEFAULT["profile_version"]): DEFAULT}


def profile_bytes(profile):
    """canonical_bytes of the object WITHOUT a profile_hash field (SCOPE-073)."""
    return canonical.canonical_bytes(dict(profile))


def profile_hash_raw(profile):
    return canonical.hash_frame(canonical.DOMAIN_PROFILE, profile_bytes(profile))


def profile_hash(profile):
    """HASH_FRAME_V1("ISEDRAF:PROFILE:V1", canonical_bytes(profile_object))."""
    return canonical.rendered(profile_hash_raw(profile))


def default():
    """A copy of the default profile, so no caller can change the packaged one."""
    return dict((k, list(v) if isinstance(v, list) else v) for k, v in DEFAULT.items())


def lookup(profile_id, profile_version):
    """The packaged profile with that identity, as a copy, or None."""
    found = PROFILES.get((profile_id, profile_version))
    if found is None:
        return None
    return dict((k, list(v) if isinstance(v, list) else v) for k, v in found.items())
