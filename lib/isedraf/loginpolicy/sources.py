# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The one grammar in this domain that S1 cannot express.
# Implements: SCOPE-022, SCOPE-045
#
# Three of the four families are genuine key/value and S1 parses them unchanged. This
# file exists only for limits.conf:
#
#     *          hard    nofile    65535
#     @staff     soft    nproc     100
#
# Four positional fields. No key, no delimiter, and the first field carries its own
# sigils: `@group`, `%group`, and a bare name meaning a user. Inventing a key for it
# would produce key/value-shaped evidence that every later consumer has to take apart
# again - the same trap the sudoers lane declined.
#
# Pure: text in, records out, no filesystem.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""The limits.conf positional grammar."""

from . import model


def parse_limits(text, source=None, start_ordinal=0):
    """`<domain> <type> <item> <value>`. Returns (records, malformed_count)."""
    records, malformed = [], 0
    ordinal = start_ordinal
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        record = {"family": model.LIMITS, "source_path": source,
                  "source_line": line_number, "ordinal": ordinal,
                  "anomalies": [], "malformed": False}
        ordinal += 1
        fields = line.split()
        if len(fields) < 4:
            # Four fields or it is not a limits declaration. Guessing which one is
            # missing would invent a limit the host does not apply.
            malformed += 1
            record["malformed"] = True
            record["anomalies"].append("FIELD_COUNT")
            record.update({"domain": None, "domain_negated": None,
                           "limit_type": None, "item": None, "value": None})
            records.append(record)
            continue
        domain, limit_type, item = fields[0], fields[1], fields[2]
        # The value may legitimately contain spaces in no supported form, but joining
        # the remainder is safer than discarding it: a trailing token is evidence.
        value = " ".join(fields[3:])
        negated = domain.startswith("!")
        if negated:
            domain = domain[1:]
        if limit_type not in model.LIMIT_TYPES:
            record["anomalies"].append("UNKNOWN_LIMIT_TYPE")
        record.update({"domain": domain, "domain_negated": negated,
                       "limit_type": limit_type, "item": item, "value": value})
        records.append(record)
    return records, malformed
