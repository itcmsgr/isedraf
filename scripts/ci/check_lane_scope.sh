#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Reconcile what a lane changed against what it was entitled to change.
# Implements: GOV-001
#
# From the pilot. tests/test_sudo_adversarial.py is the red-team lane's file and it ended
# up in the production lane's commit, because the coordinator copied it across to run it.
# Benign that time. The control exists for the time it is not, and because a manifest that
# can be violated without consequence is not a manifest.
#
# Run BEFORE integration. A lane returning green tests with an out-of-manifest change is a
# LANE_SCOPE_VIOLATION even when the edit is correct: the question is entitlement, not
# whether the change happens to work.
#
# usage: check_lane_scope.sh <lane> <base-sha> <head-sha>
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
LANE="${1:?usage: check_lane_scope.sh <lane> <base> <head>}"
BASE="${2:?}"; HEAD_SHA="${3:?}"

CHANGED="$(git diff --name-only "$BASE".."$HEAD_SHA")"
if [ -z "$CHANGED" ]; then
    echo "  FAIL  $LANE changed nothing between $BASE and $HEAD_SHA" >&2
    exit 1
fi

printf '%s\n' "$CHANGED" | python3 -c '
import json, sys
lane, root = sys.argv[1], sys.argv[2]
spec = json.load(open(root + "/scripts/ci/lane_manifests.json"))
if lane not in spec["lanes"]:
    print("  FAIL  %s has no manifest" % lane); raise SystemExit(1)
manifest = spec["lanes"][lane]
allowed = manifest["write"] + manifest.get("write_with_coordinator_review", [])
forbidden = spec["never_writable_by_any_worker"]
changed = [l.strip() for l in sys.stdin if l.strip()]
violations, reviewed = [], []
for path in changed:
    if any(path == f or path.startswith(f) for f in forbidden):
        violations.append((path, "FROZEN/SHARED - no worker may write this"))
        continue
    if any(path == a or path.startswith(a) for a in manifest["write"]):
        continue
    if any(path == a or path.startswith(a)
           for a in manifest.get("write_with_coordinator_review", [])):
        reviewed.append(path)
        continue
    violations.append((path, "outside the lane manifest"))
for path in reviewed:
    print("  REVIEW  %s (coordinator-reviewed path)" % path)
if violations:
    print("=== LANE_SCOPE_VIOLATION: %s ===" % lane)
    for path, why in violations:
        print("  FAIL  %s - %s" % (path, why))
    raise SystemExit(1)
print("  OK    %s: %d file(s) changed, all within the manifest" % (lane, len(changed)))
' "$LANE" "$ROOT"
