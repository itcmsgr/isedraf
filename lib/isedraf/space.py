# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The free-space preflight of a run, shared by the user route and the Full Audit launcher.
# Implements: STORE-016, STORE-022, D-129
#
# Before a run collects anything, the filesystem holding the store must have room for the run
# and for one ledger recovery record (STORE-022). Too little refuses the run with
# INSUFFICIENT_SPACE (exit 68): nothing is collected or written, and committed evidence is
# untouched. ISEDRAF never deletes anything to make room.
#
# How the pending write is estimated. A run writes one snapshot bundle (staged, then renamed
# within the same filesystem, so it is written once) and one ledger record of a few hundred
# bytes. Its size depends on the host, not on ISEDRAF, so the estimate is taken from what this
# store has actually committed: the largest of its most recent snapshots, times a margin,
# and never less than a floor. Every number is a named value below, with its reason.
#
# A preflight cannot stop space disappearing afterwards. A write that still fails for want of
# space is recognised (out_of_space) and reported with the same code; the run is not
# committed, its own staging is removed as before, and nothing committed is touched.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged; the Full Audit launcher calls it as root on /var/lib/isedraf"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Free-space preflight (STORE-016, STORE-022): estimate, check, refuse - never delete."""
import errno
import os
import stat

MIB = 1024 * 1024

# The estimate's named values.
RUN_FLOOR = 8 * MIB
# A run is never estimated below this. The largest snapshot measured on the lab hosts was
# 482 KB (a Full Audit run, 2026-11-15); the floor is about sixteen times that, so a first run,
# which has no earlier snapshot to measure, still has room on a host with far more accounts,
# keys and mounts than the lab.
RUN_MARGIN = 4
# The next run may be larger than the last: accounts, keys, rules and mounts are added. Four
# times the largest recent snapshot of the same store.
RECENT_SNAPSHOTS = 3
# How many of the newest committed snapshots are measured: bounded work on a large store.
RECOVERY_RESERVE = 1 * MIB
# STORE-022: headroom kept free for one ledger recovery record, a new ledger segment and their
# directory entries, so a full disk never leaves the ledger unable to advance.

SPACE_ERRNOS = (errno.ENOSPC, errno.EDQUOT)
REASON = "INSUFFICIENT_SPACE"


class InsufficientSpace(Exception):
    """The filesystem holding the store has too little room for the run (STORE-022)."""

    def __init__(self, path, available, run_estimate):
        self.path = path
        self.available = available
        self.run_estimate = run_estimate
        self.required = run_estimate + RECOVERY_RESERVE
        super(InsufficientSpace, self).__init__(
            "%s: the filesystem holding %s has %s available; this run needs %s (%s estimated "
            "for the run, %s kept for a ledger recovery record)"
            % (REASON, path, mib(available), mib(self.required), mib(run_estimate),
               mib(RECOVERY_RESERVE)))


def mib(value):
    return "%.1f MiB" % (value / float(MIB))


def _existing(path):
    """The path itself, or its nearest existing parent (a first run has no store yet)."""
    while not os.path.lexists(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    return path


def snapshot_size(path):
    """Bytes of the regular files under one snapshot directory; links are never followed."""
    total = 0
    for top, dirs, files in os.walk(path, followlinks=False):
        for name in files:
            st = os.lstat(os.path.join(top, name))
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
    return total


def run_estimate(root):
    """RUN_MARGIN times the largest of the newest RECENT_SNAPSHOTS committed snapshots of this
    store, never below RUN_FLOOR. Reads directory metadata only, never evidence content."""
    snapshots = os.path.join(root, "snapshots")
    try:
        names = sorted(n for n in os.listdir(snapshots) if n.startswith("SDS-"))
    except OSError:
        names = []
    largest = 0
    for name in names[-RECENT_SNAPSHOTS:]:
        path = os.path.join(snapshots, name)
        if stat.S_ISDIR(os.lstat(path).st_mode):
            largest = max(largest, snapshot_size(path))
    return max(RUN_MARGIN * largest, RUN_FLOOR)


def available(root):
    """Bytes an unprivileged writer may still use on the filesystem holding root."""
    st = os.statvfs(_existing(root))
    return st.f_bavail * st.f_frsize


def preflight(root):
    """Raise InsufficientSpace when the run and the recovery reserve do not fit. Writes
    nothing; called before the store is prepared and before anything is collected."""
    estimate = run_estimate(root)
    free = available(root)
    if free < estimate + RECOVERY_RESERVE:
        raise InsufficientSpace(root, free, estimate)
    return free, estimate


def out_of_space(exc):
    """True when exc, or an exception it was raised from, is a write that found no space."""
    seen = 0
    while exc is not None and seen < 8:
        if isinstance(exc, OSError) and exc.errno in SPACE_ERRNOS:
            return True
        exc = exc.__cause__ or exc.__context__
        seen += 1
    return False
