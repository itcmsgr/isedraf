# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Hostname declared-vs-active vocabulary and classification.
# Implements: SCOPE-020, SCOPE-021, SCOPE-045
#
# NSS_HOSTNAME_LANE_CONTRACT.md §6. The configured name and the running name are two
# facts; an FQDN is a third and belongs to inventory/. No equivalence rule has been
# authorized, so there is no EQUIVALENT: a pair is EQUAL, DIFFERENT, or NOT_COMPARABLE
# with its reason.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Hostname vocabulary. Pure: no I/O."""
from ..status import COLLECTED, ERROR, NOT_TESTED, PARTIAL      # noqa: F401

STATE = "STATE"
OBSERVATION = "OBSERVATION"
DERIVED = "DERIVED"
PROVENANCE = "PROVENANCE"

DECLARED_SOURCE = "etc/hostname"
ACTIVE_SOURCE = "proc/sys/kernel/hostname"

# --- the declared file -------------------------------------------------------------------
PRESENT = "PRESENT"
ABSENT = "ABSENT"            # a fact: systemd may take the name from elsewhere
EMPTY = "EMPTY"
MALFORMED = "MALFORMED"

ANOMALY_WHITESPACE = "SURROUNDING_WHITESPACE"
ANOMALY_MULTIPLE = "MORE_THAN_ONE_NAME"
ANOMALY_UNDECODABLE = "UNDECODABLE"

# --- the relation ------------------------------------------------------------------------
EQUAL = "EQUAL"
DIFFERENT = "DIFFERENT"
NOT_COMPARABLE = "NOT_COMPARABLE"

# hostname(5): "7-bit ASCII lower-case alphanumeric characters or hyphens forming a valid
# DNS domain name", and "invalid characters will be filtered out" when applied. Filtering
# is not emulated, so a declared name outside this set is not compared.
APPLIED_UNCHANGED = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.")
KERNEL_NAME_LIMIT = 64        # hostname(5): "up to 64"; the kernel limits it to 64
TEMPLATE_CHARACTER = "?"      # hostname(5): substituted from machine-id(5) when applied

# --- SCOPE-045 ----------------------------------------------------------------------------
CLASSIFICATION = {
    "declared.value": STATE,
    "declared.state": OBSERVATION,
    "declared.trailing_newline": OBSERVATION,
    "declared.anomalies": DERIVED,
    "declared.lines": OBSERVATION,
    "declared.lines_bytes_hex": OBSERVATION,
    "declared.value_bytes_hex": STATE,
    "declared.source": PROVENANCE,
    "declared.status": PROVENANCE,
    "declared.reason": PROVENANCE,
    "active.value": STATE,
    "active.value_bytes_hex": STATE,
    "active.source": PROVENANCE,
    "active.status": PROVENANCE,
    "active.reason": PROVENANCE,
    "relation": DERIVED,
    "relation_reason": DERIVED,
}
