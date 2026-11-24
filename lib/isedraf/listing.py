# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: What one evidence store holds: committed runs, evaluations, the baseline, saved reports.
# Implements: D-129, SNAP-018, STORE-001
#
# v0.5 register item R1 (`isedraf list`, D-129 point 11). Read-only and bounded to metadata: the
# ledger (which runs and which baseline are committed), each evaluation's manifest (its run and
# result counts), the baseline pointer, and the names, sizes and times of saved reports. It
# never reads snapshot content or host evidence, never takes the run lock, never writes, never
# repairs, and never collects. A run is listed only when the ledger records it; a snapshot
# directory the ledger does not reference is counted separately as unledgered (SNAP-018) and is
# never shown as a run.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Read-only listing of one evidence store (v0.5 R1)."""
import json
import os
import stat

from isedraf import ledger

EVALUATIONS = "evaluations"
# The directory report --save writes (isedraf.report.REPORTS_DIRECTORY; a test holds them equal).
# Not imported: this module sits below the presentation layer.
REPORTS_DIRECTORY = "reports"
REPORT_EXTENSIONS = (".md", ".json", ".html")


class Unreadable(Exception):
    """The store's metadata cannot be read as committed metadata."""


def _evaluation(root, name):
    path = os.path.join(root, EVALUATIONS, name, "manifest.json")
    try:
        with open(path, "rb") as fh:
            manifest = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        return {"evaluation_id": name, "problem": "manifest unreadable: %s" % exc}
    if not isinstance(manifest, dict) or manifest.get("evaluation_id") != name:
        return {"evaluation_id": name, "problem": "the manifest names another evaluation"}
    return {"evaluation_id": name, "snapshot_id": manifest.get("snapshot_id"),
            "result_counts": manifest.get("result_counts") or {},
            "baseline_revision": manifest.get("baseline_revision")}


def _reports(root):
    found = []
    base = os.path.join(root, REPORTS_DIRECTORY)
    for top, dirs, files in os.walk(base, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            if not name.endswith(REPORT_EXTENSIONS):
                continue
            path = os.path.join(top, name)
            st = os.lstat(path)
            if stat.S_ISREG(st.st_mode):
                found.append({"path": os.path.abspath(path), "size": st.st_size,
                              "report_id": name.rsplit(".", 1)[0]})
    return found


def collect(root):
    """Everything the store holds, oldest first, from committed metadata only."""
    try:
        records = ledger.read_records(root)
    except (OSError, ValueError) as exc:
        raise Unreadable("the ledger cannot be read: %s" % exc)
    cores = [r.get("record_core") or {} for r in records]
    runs = [{"snapshot_id": c.get("snapshot_id"), "collected_at": c.get("occurred_at"),
             "state_root": c.get("state_root")}
            for c in cores if c.get("event") == ledger.EVENT_SNAPSHOT_COMMITTED]
    baselines = [{"revision": c.get("baseline_revision"), "snapshot_id": c.get("snapshot_id"),
                  "approved_at": c.get("occurred_at")}
                 for c in cores if c.get("event") == ledger.EVENT_BASELINE_APPROVED]
    try:
        names = sorted(n for n in os.listdir(os.path.join(root, EVALUATIONS))
                       if n.startswith("EVL-"))
    except OSError:
        names = []
    try:
        unledgered = len(ledger.unledgered_snapshots(root))
    except (OSError, ValueError):
        unledgered = 0
    return {"runs": runs, "baselines": baselines,
            "evaluations": [_evaluation(root, n) for n in names],
            "reports": _reports(root), "unledgered": unledgered}
