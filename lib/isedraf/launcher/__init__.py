# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The Full Audit launcher: the only component that changes the privilege boundary.
# Implements: D-124, AUTH-019, AUTH-020, AUTH-021, AUTH-022, AUTH-027
#
# The launcher starts the sandboxed run, holds the lock, validates the production store,
# reduces the engine, and promotes what the engine built. It never parses host evidence: it
# reads ISEDRAF's own staged artifacts only to recompute their hashes. The fixed-operation
# supervisor it serves is isedraf.supervisor. This package is the only place where
# os.execv* may appear, always with fixed absolute paths (CLAUDE.md).
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="launcher (root inside the Full Audit unit)"
# meta:mutates="state-root only"
# meta:binaries=""
# =============================================================================
"""Full Audit launcher: sandboxed route, store validation, engine reduction, promotion."""
