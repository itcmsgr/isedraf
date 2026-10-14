# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The Full Audit supervisor: a privilege transport for fixed operations.
# Implements: D-123, AUTH-003, AUTH-006
#
# The supervisor is a privilege transport, not an intelligence layer. It performs registered
# fixed operations and returns bounded bytes and a status for each. It contains no parser,
# normalizer, evaluator or renderer, and it imports nothing from the engine: every module in
# this package imports only the standard library and isedraf.supervisor itself
# (tests/test_supervisor.py holds that).
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="supervisor (root in FULL_AUDIT, fixed operations only)"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Full Audit supervisor: fixed privileged operations, bounded bytes out."""
