# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The report layer — one model, several renderings.
# Implements: STORE-001
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="state-root reports/ only"
# meta:binaries=""
# =============================================================================

"""A report is a derived artifact. Producing one never changes evidence."""
import os

from . import artifact, model, profile, render
from .model import build, content_digest
from .profile import ProfileError

REPORTS_DIRECTORY = "reports"


def write(root, report, rendered, extension):
    """Store one rendering under <state root>/reports/<YYYY>/<MM>/.

    STORE-001 already lists `reports/` in the evidence root. STORE-025 says W1-A does not
    create it — W1-C2 does, which is the progression STORE-001 anticipated rather than a
    new location invented here. Nothing is written to /var/log.
    """
    generated = report["report"]["generated_at"]
    year, month = generated[0:4], generated[5:7]
    directory = os.path.join(root, REPORTS_DIRECTORY, year, month)
    previous = os.umask(0o077)
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        path = os.path.join(directory,
                            "%s.%s" % (report["report"]["report_id"], extension))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, rendered.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.umask(previous)
    return path
