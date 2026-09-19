# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The ISEDRAF production package.
# Implements: SNAP-020
#
# ENGINE_VERSION is embedded rather than read from a VERSION file at runtime: an
# installed package must not resolve paths relative to its own location to find its own
# identity (Z-20). tests/test_identity.py asserts it equals the repository VERSION file,
# so the two cannot drift.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""ISEDRAF — Linux host assurance, approved baseline, state delta and evidence engine."""

ENGINE_VERSION = "0.1.0-alpha1"        # SNAP-020: the VERSION file verbatim
__version__ = ENGINE_VERSION
