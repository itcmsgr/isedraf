# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The W1-A exit set — production implementation.
# Implements: SCOPE-077, SCOPE-071
#
# SCOPE-077 freezes the W1-A exit set as exactly 0, 2, 64, 70. Codes 1, 3, 4, 5, 6, 65,
# 66 and 67 belong to comparison, baseline and privileged execution and are NOT reachable
# in this slice. They are absent here rather than defined and unused.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""SCOPE-077."""

OK = 0                    # snapshot committed, host_identity COLLECTED
INCOMPLETE = 2            # committed with collection_status != COLLECTED, or SNAP-018
USAGE_OR_ENGINE = 64      # usage or engine error
PRIVILEGE_REFUSED = 70    # root or sudo execution refused (SCOPE-071)

W1A_SET = (OK, INCOMPLETE, USAGE_OR_ENGINE, PRIVILEGE_REFUSED)
