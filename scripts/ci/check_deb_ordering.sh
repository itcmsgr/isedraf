#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: DEBIAN/sha256sums must be ordered, not in filesystem order.
# Implements: NORM-037, D-86, GOV-002
#
# NORM-037 in the packaging rather than in the engine. `find` returns directory order,
# which is a property of the filesystem: the same 24 lines came out in a different
# sequence on btrfs and on ext4, so the .deb differed across machines while its payload
# was byte-identical. The engine has had a gate and an injection for unordered set-like
# fields since W1-A; the package build had neither.
#
# A single-machine reproducibility check cannot catch this, because one machine has one
# filesystem. Only the ordering itself is checkable locally.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,ar,tar,sort,mktemp"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
DIST="${1:-$ROOT/dist}/packages"
FAIL=0

echo "--- deb control ordering (NORM-037, D-86) ---"
found=0
for deb in "$DIST"/*.deb; do
    [ -e "$deb" ] || continue
    case "$deb" in *latest*) continue;; esac
    found=$((found + 1))
    T="$(mktemp -d)"
    ar p "$deb" control.tar.gz 2>/dev/null | tar xzO ./sha256sums > "$T/s" 2>/dev/null \
        || { echo "  FAIL  $(basename "$deb"): DEBIAN/sha256sums unreadable" >&2; FAIL=1; rm -rf "$T"; continue; }
    if [ ! -s "$T/s" ]; then
        echo "  FAIL  $(basename "$deb"): DEBIAN/sha256sums is empty" >&2; FAIL=1
    elif LC_ALL=C sort -c -k2 "$T/s" 2>/dev/null; then
        echo "  OK    $(basename "$deb"): $(wc -l < "$T/s" | tr -d ' ') sha256sums entries are ordered"
    else
        echo "  FAIL  $(basename "$deb"): DEBIAN/sha256sums is not sorted — it carries the" >&2
        echo "        builder's filesystem order into the package" >&2
        FAIL=1
    fi
    rm -rf "$T"
done

# Z-18: a gate that passes over an empty directory is not a gate.
if [ "$found" -eq 0 ]; then
    echo "  FAIL  no .deb found in $DIST — nothing was checked" >&2
    exit 1
fi
[ "$FAIL" -eq 0 ] || { echo "  deb control ordering gate FAILED" >&2; exit 1; }
