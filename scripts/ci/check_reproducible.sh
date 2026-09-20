#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Build twice from the same tree and require identical bytes.
# Implements: D-86, GOV-002, NORM-039
#
# A project whose thesis is canonical bytes shipped packages that were not canonical.
# Two builds of an identical tree produced three different artifacts, because `ar`
# wrote the current time and the BUILDER'S NUMERIC UID into every member header, and
# rpm wrote BUILDTIME from the clock. The uid was a disclosure leak as well: every
# downloaded .deb carried the build account's UID.
#
# Nothing claimed this was reproducible, so no documentation was false - but the
# two-file checksum design (SHA256SUMS.build vs SHA256SUMS) invites a reader to
# rebuild and compare, and that was impossible.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="rebuilds dist/ twice"
# meta:binaries="git,bash,sha256sum,sort,diff"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2

echo "--- reproducible build (D-86, NORM-039) ---"
A="$(mktemp)"; B="$(mktemp)"
trap 'rm -f "$A" "$B"' EXIT

bash packaging/build.sh >/dev/null 2>&1 || { echo "  FAIL  first build failed" >&2; exit 1; }
sort "$ROOT/dist/SHA256SUMS.build" > "$A"
bash packaging/build.sh >/dev/null 2>&1 || { echo "  FAIL  second build failed" >&2; exit 1; }
sort "$ROOT/dist/SHA256SUMS.build" > "$B"

# Z-18: a gate that passes over empty input is not a gate.
if [ ! -s "$A" ]; then
    echo "  FAIL  the build produced no artifacts to compare" >&2
    exit 1
fi

if cmp -s "$A" "$B"; then
    echo "  OK    $(wc -l < "$A" | tr -d ' ') artifacts identical across two builds of the same tree"
    exit 0
fi
echo "=== reproducible build gate FAILED ===" >&2
diff "$A" "$B" | sed 's/^/          /' >&2
echo "  The same source must produce the same bytes, or 'rebuild it yourself and" >&2
echo "  compare' is not something a user can actually do." >&2
exit 1
