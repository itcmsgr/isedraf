# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Native evaluation of committed evidence (v0.3).
# Implements: D-125, EVAL-001
#
# criteria: pure evaluators. record: the evaluation's identity and a read-only reader.
# run: the writer behind `isedraf evaluate`, the only module that creates an evaluation.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""D-125: native evaluation of committed evidence."""
