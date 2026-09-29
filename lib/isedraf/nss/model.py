# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The NSS topology vocabulary: service classes, action grammar, classification.
# Implements: IDENT-040, IDENT-041, CMP-020, SCOPE-045
#
# docs/development/NSS_HOSTNAME_LANE_CONTRACT.md §2-§4. Everything here describes HOW a
# host resolves names. None of it is an identity, so none of it is STATE: an NSS change
# must never touch the hashed identity surface, which is what lets the comparison stage
# (W1-C) read it as a method or scope change rather than as account drift.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""NSS topology vocabulary. Pure: no I/O."""
from ..status import COLLECTED, ERROR, NOT_TESTED, PARTIAL      # noqa: F401

STATE = "STATE"
OBSERVATION = "OBSERVATION"
DERIVED = "DERIVED"
PROVENANCE = "PROVENANCE"

SOURCE = "etc/nsswitch.conf"

# --- service classes, closed (§3) --------------------------------------------------------
LOCAL_FILES = "LOCAL_FILES"
COMPAT = "COMPAT"
LOCAL_NON_FILES = "LOCAL_NON_FILES"
REMOTE_DIRECTORY = "REMOTE_DIRECTORY"
RESOLVER = "RESOLVER"
UNKNOWN = "UNKNOWN"

SERVICE_CLASS = {
    "files": LOCAL_FILES,
    "compat": COMPAT,
    "systemd": LOCAL_NON_FILES, "myhostname": LOCAL_NON_FILES,
    "mymachines": LOCAL_NON_FILES, "db": LOCAL_NON_FILES,
    "sss": REMOTE_DIRECTORY, "ldap": REMOTE_DIRECTORY, "winbind": REMOTE_DIRECTORY,
    "nis": REMOTE_DIRECTORY, "nisplus": REMOTE_DIRECTORY, "hesiod": REMOTE_DIRECTORY,
    "dns": RESOLVER, "resolve": RESOLVER, "wins": RESOLVER,
    "mdns": RESOLVER, "mdns4": RESOLVER, "mdns6": RESOLVER, "mdns_minimal": RESOLVER,
    "mdns4_minimal": RESOLVER, "mdns6_minimal": RESOLVER,
}


def classify(service):
    """The class of a service name, exactly as written.

    Service names name `libnss_<service>.so`, and nsswitch.conf(5) does not declare their
    case insignificant, so "Files" is not "files". Anything unlisted is UNKNOWN, and UNKNOWN
    is never treated as local: a service nobody classified is outside the local-files
    guarantee until someone classifies it on purpose.
    """
    return SERVICE_CLASS.get(service, UNKNOWN)


# --- action grammar, nsswitch.conf(5) -------------------------------------------------------
# "The case of the keywords is not significant", so both are lower-cased. `merge` is
# glibc 2.24+; it is known and retained as data, and its effect is not modelled.
STATUSES = ("success", "notfound", "unavail", "tryagain")
ACTIONS = ("return", "continue", "merge")

# --- record semantics ---------------------------------------------------------------------
KNOWN = "KNOWN"
UNSUPPORTED = "UNSUPPORTED"          # retained verbatim; this lane cannot fully interpret it

ANOMALY_UNSUPPORTED = "UNSUPPORTED_SEMANTICS"
ANOMALY_DUPLICATE = "DUPLICATE_DATABASE"
ANOMALY_NO_DATABASE = "NO_DATABASE_NAME"
ANOMALY_UNDECODABLE = "UNDECODABLE"
# Owner ruling IQ-037 (2026-09-27): a service token no class covers, in an identity
# database, leaves the effective resolver semantics unknown - PARTIAL, never complete.
ANOMALY_UNKNOWN_SERVICE = "UNKNOWN_IDENTITY_SERVICE"

# --- identity scope (§4) ------------------------------------------------------------------
# The pseudo-databases passwd_compat, group_compat and shadow_compat name the source the
# `compat` service reads its +/- inclusions from ("By default, the source is nis, but
# this may be overridden", nsswitch.conf(5)), and `netgroup` resolves +@netgroup. Leaving
# them out let a remote identity source change without moving the digest (red team F4).
IDENTITY_DATABASES = ("passwd", "group", "shadow", "initgroups", "gshadow",
                      "passwd_compat", "group_compat", "shadow_compat", "netgroup")
# Required: absence of these is recorded. initgroups and gshadow are optional in glibc.
REQUIRED_IDENTITY_DATABASES = ("passwd", "group", "shadow")
# glibc applies a built-in default to an absent database line, and that default has
# changed across versions. It is recorded, never guessed.
DEFAULT_NOT_ASSERTED = "DEFAULT_NOT_ASSERTED"
# The digest of an absent file: distinct from every present configuration, and stable.
ABSENT_TOPOLOGY = "ABSENT"

# --- SCOPE-045 ----------------------------------------------------------------------------
CLASSIFICATION = {
    "records": OBSERVATION,
    "records.database": OBSERVATION,
    "records.line": PROVENANCE,
    "records.raw": OBSERVATION,
    "records.entries": OBSERVATION,
    "records.semantics": DERIVED,
    "records.unsupported": DERIVED,
    "records.database_bytes_hex": OBSERVATION,
    "records.raw_bytes_hex": OBSERVATION,
    "identity_nss_topology": PROVENANCE,
    "identity_nss_topology_digest": PROVENANCE,
    "non_files_identity_sources": DERIVED,
    "undeclared_identity_databases": DERIVED,
}
