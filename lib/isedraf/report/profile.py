# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The optional assessment profile — who prepared a report, and for whom.
# Implements: NORM-034
#
# Presentation metadata, never evidence. It is read from a file rather than passed on the
# command line because these are personal data and arguments land in shell history and in
# every process listing on the host.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Load an optional profile. Absence is normal and is not an error."""
import json
import os

FIELDS = ("prepared_by", "role", "organization", "email", "customer", "engagement",
          "reference", "report_title", "notes")

# What the report says about what a typed name is worth. Stated once, here, so it cannot
# drift between renderers.
IDENTITY_DISCLAIMER = (
    "Assessment details identify the person or organization declared in the report "
    "metadata. They are declarative and are NOT cryptographically authenticated; this "
    "report is not signed.")


class ProfileError(Exception):
    """The profile exists but cannot be used. Silently ignoring it would be worse."""


def load(path):
    """Returns a dict of the present fields, or None when there is no profile."""
    if not path:
        return None
    if not os.path.exists(path):
        raise ProfileError("assessment profile %s does not exist" % path)
    try:
        with open(path, "rb") as fh:
            raw = json.loads(fh.read().decode("utf-8"))
    except ValueError as exc:
        raise ProfileError("assessment profile %s is not valid JSON: %s" % (path, exc))
    if not isinstance(raw, dict):
        raise ProfileError("assessment profile %s is not an object" % path)
    unknown = sorted(set(raw) - set(FIELDS))
    if unknown:
        raise ProfileError("assessment profile %s has unknown field(s): %s"
                           % (path, ", ".join(unknown)))
    # Absent and empty are the same thing for presentation metadata: an empty string in a
    # report renders as a blank label, which reads as a defect rather than as absence.
    present = {k: v for k, v in raw.items()
               if v is not None and str(v).strip() != ""}
    return present or None
