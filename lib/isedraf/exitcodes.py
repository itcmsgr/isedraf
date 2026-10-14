# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The W1-A exit set — production implementation.
# Implements: SCOPE-077, SCOPE-071, AUTH-023
#
# SCOPE-077 freezes the W1-A exit set as exactly 0, 2, 64, 70. Codes 1, 3, 4, 5, 6 and 65
# belong to comparison and baseline and are NOT reachable yet. They are absent here rather
# than defined and unused.
#
# AUTH-023 (D-124): from v0.2, 66 and 67 each have one meaning in every run mode and
# state-root class, and are never used for another outcome.
#
# OUT-001 (D-72): lib/isedraf/exitcodes.json is the single source; these constants are
# checked against it by scripts/ci/check_exitcodes.py in make check.
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
RUN_IN_PROGRESS = 66      # the whole-run lock was not acquired; nothing collected or written
STATE_ROOT_UNUSABLE = 67  # the state root is missing, not a conforming directory, or unsuitable

W1A_SET = (OK, INCOMPLETE, USAGE_OR_ENGINE, PRIVILEGE_REFUSED)
