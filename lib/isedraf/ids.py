# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Identifier and timestamp grammars — production implementation.
# Implements: SNAP-019
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""SNAP-019. The hex suffix comes from a cryptographic RNG and is NEVER derived from the
manifest, which contains the id and would be circular."""
import datetime
import re
import secrets

# SNAP-019 freezes SDS-, RUN- and EVT-, because those enter the manifest preimage.
# INV- and RPT- identify W1-C artifacts that are NOT in any frozen preimage. They
# reuse the same grammar deliberately - one shape for every ISEDRAF identifier -
# without claiming SNAP-019's frozen status.
FROZEN_PREFIXES = ("SDS", "RUN", "EVT")
REPORT_LAYER_PREFIXES = ("INV", "RPT")
ID_RE = re.compile(r"^(SDS|RUN|EVT|INV|RPT)-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def now_utc():
    """YYYY-MM-DDTHH:MM:SSZ. No fractional seconds, literal Z, never +00:00."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id(prefix, ts_utc):
    """SDS-/RUN-/EVT- + <YYYYMMDDTHHMMSSZ> + 16 lowercase hex."""
    if prefix not in FROZEN_PREFIXES + REPORT_LAYER_PREFIXES:
        raise ValueError("unknown identifier prefix %r" % prefix)
    compact = ts_utc.replace("-", "").replace(":", "")
    return "%s-%s-%s" % (prefix, compact, secrets.token_hex(8))
