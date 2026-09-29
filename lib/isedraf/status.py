# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The one collection-status vocabulary, at a layer everything can reach.
# Implements: SCOPE-022
#
# These four values were defined in inventory/model.py, which made every consumer of
# SCOPE-022 import a DOMAIN model to learn what COLLECTED means. ARCH-01 caught the
# consequence: shared/result.py imported isedraf.inventory.model, and shared primitives
# therefore sat above the domain they are supposed to sit below.
#
# The vocabulary is not an inventory concept. It is the project's definition of collection
# truth, used by identity, inventory, accounts, the shared primitives and every domain
# still to come. It belongs where all of them can reach it without reaching sideways.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""SCOPE-022 collection status. One definition, one home."""

COLLECTED = "COLLECTED"
PARTIAL = "PARTIAL"
NOT_TESTED = "NOT_TESTED"
ERROR = "ERROR"

STATUSES = (COLLECTED, PARTIAL, NOT_TESTED, ERROR)


def requires_reason(status):
    """A status other than COLLECTED must explain itself.

    Stated once here so the rule cannot drift between the three places that enforce it.
    """
    return status != COLLECTED
