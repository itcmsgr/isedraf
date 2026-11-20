# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The listing launcher inside the read-only list unit: what the system store holds.
# Implements: AUTH-035, AUTH-032, AUTH-022, AUTH-023, D-129
#
# `sudo isedraf list` (AUTH-035, D-129 point 12). Strictly read-only: the unit has the report
# unit's properties (AUTH-032), so the store is read-only (ProtectSystem=strict, no
# ReadWritePaths=), and this launcher, root inside the unit, does only this:
#
#   1. checks the fixed store as AUTH-022 states it, never touching it; a store that does not
#      exist yet is reported, never created (0); a deviating one is refused (67)
#   2. takes the whole-run lock on a read-only descriptor, so it never reads mid-commit (66)
#   3. reads the ledger, bounded and no-follow, as the report launcher does: ISEDRAF's own
#      integrity metadata (runs and the baseline approval), never host evidence
#   4. lists the names of evaluations/ and snapshots/ to show the evaluation identities and
#      to count snapshot directories the ledger does not record (SNAP-018)
#
# It opens no snapshot file and no evaluation artifact: no host evidence and no result is
# read or interpreted (AUTH-033 "no result interpreted"). It writes nothing, creates nothing,
# starts no reduced process and asks for no capability beyond the unit's. The rendering is
# summary.listing_text, the same as the user route.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="launcher (root inside the read-only list unit)"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""AUTH-035 list launcher: metadata of the system store, read-only."""
import os
import re
import signal
import sys

from isedraf import ids, stateroot, summary
from isedraf.exitcodes import OK, RUN_IN_PROGRESS, STATE_ROOT_UNUSABLE, USAGE_OR_ENGINE
from isedraf.evaluate import record
from isedraf.launcher import reportunit, store

SCOPES = ("newest", "all")
SDS_RE = re.compile(r"^SDS-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
NAMES_BOUND = 100000
# At most this many entries are read from evaluations/ or snapshots/: a bound on the work of a
# listing, far above any store the lab has measured.

INTERRUPTED = reportunit.INTERRUPTED
STOP_SIGNALS = reportunit.STOP_SIGNALS


def _names(path, pattern):
    """Entry names of one store directory matching an identifier pattern, sorted; absent is
    empty."""
    if not os.path.lexists(path):
        return []
    reportunit._directory(path, store.OWNER_UID, store.OWNER_GID)
    found = []
    with os.scandir(path) as entries:
        for entry in entries:
            if len(found) >= NAMES_BOUND:
                raise reportunit.Refused("%s holds more than %d entries" % (path, NAMES_BOUND))
            if pattern.match(entry.name):
                found.append(entry.name)
    return sorted(found)


def collect(root):
    """The same shape as isedraf.listing.collect, from metadata only. Under the lock."""
    # Every segment (STORE-010), read as the report launcher reads them; a torn tail is refused,
    # never recovered here (STORE-016: the next Full Audit recovers it).
    cores = (reportunit.verified_cores(reportunit.ledger_items(root))
             if os.path.lexists(os.path.join(root, "ledger")) else [])
    runs = [{"snapshot_id": reportunit._snapshot_id(c, "snapshot record"),
             "collected_at": c.get("occurred_at"), "state_root": c.get("state_root")}
            for c in cores if c.get("event") == reportunit.SNAPSHOT_COMMITTED]
    baselines = [{"revision": c.get("baseline_revision"),
                  "snapshot_id": reportunit._snapshot_id(c, "baseline record"),
                  "approved_at": c.get("occurred_at")}
                 for c in cores if c.get("event") == reportunit.BASELINE_APPROVED]
    known = set(r["snapshot_id"] for r in runs)
    unledgered = [n for n in _names(os.path.join(root, "snapshots"), SDS_RE) if n not in known]
    # Identities only: an evaluation's artifacts are not opened (no result is interpreted).
    evaluations = [{"evaluation_id": n, "identity_only": True}
                   for n in _names(os.path.join(root, "evaluations"), record.EVL_RE)]
    return {"runs": runs, "baselines": baselines, "evaluations": evaluations, "reports": [],
            "unledgered": len(unledgered)}


def run(scope, root=None, out=None, err=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    root = root or store.ROOT
    if scope not in SCOPES:
        err.write("isedraf: the list launcher was given no listing scope\n")
        return USAGE_OR_ENGINE
    out.write(summary.header("sudo isedraf list", stateroot.SYSTEM_PRODUCTION))
    if not os.path.lexists(root):
        out.write("No system evidence store at:\n  %s\nIt is never created at runtime.\n"
                  "Start with: sudo isedraf audit\n" % root)
        return OK
    try:
        store.check_root(root)
        if not os.path.lexists(os.path.join(root, stateroot.LOCK_NAME)):
            found = collect(root)          # no run has ever started: nothing to lock against
        else:
            with reportunit._ReadOnlyLock(root):
                found = collect(root)
    except store.Unusable as exc:
        err.write(summary.refusal("STATE_ROOT_UNUSABLE: %s" % exc, "Nothing was read or "
                                  "written."))
        return STATE_ROOT_UNUSABLE
    except stateroot.RunInProgress as exc:
        err.write(summary.refusal("RUN_IN_PROGRESS: %s" % exc, "Nothing was read or written.",
                                  "wait for the other ISEDRAF run to finish, then run sudo "
                                  "isedraf list again"))
        return RUN_IN_PROGRESS
    except (reportunit.Refused, OSError) as exc:
        err.write(summary.refusal("LIST_REFUSED: %s" % exc, "Nothing was written."))
        return USAGE_OR_ENGINE
    out.write(summary.listing_text(found, stateroot.SYSTEM_PRODUCTION, root,
                                   show_all=(scope == "all")))
    return OK


_stop = []


def main(argv):
    for signum in STOP_SIGNALS:
        signal.signal(signum, lambda s, _f: _stop.append(s))
    if len(argv) != 2 or not ids.ID_RE.match(argv[0] or "") or not argv[0].startswith("RUN-"):
        sys.stderr.write("isedraf: the list launcher takes a run identifier and a scope\n")
        return USAGE_OR_ENGINE
    code = run(argv[1])
    signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    return INTERRUPTED if _stop else code
