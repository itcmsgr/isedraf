# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Baseline and delta (v0.4, slice 1: DEV baselines).
# Implements: D-120, BASE-007, BASE-008
#
# profile: the packaged profile. projection: section STATE, state hash, method fingerprint
# (pure). revision: the revision artifact, its verification and the comparison (no writes).
# approve: the only writer of baselines/.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""v0.4 baseline and delta."""
