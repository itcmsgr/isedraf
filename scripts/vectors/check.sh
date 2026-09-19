#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Regenerate the W1-A vectors into a temp dir and byte-compare with the committed ones.
# Implements: NORM-039, GOV-002
#
# It NEVER overwrites the committed vectors. Updating golden output is a deliberate review
# event, not a side effect of running the tests.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3,diff,mktemp"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
COMMITTED="test-vectors/w1a/v1"
# Z-18: this used to SKIP and exit 0 when the directory was missing, so deleting the
# corpus turned the release-blocking gate green. The corpus is committed; its absence is
# now a failure, which is the only reading under which NORM-039 means anything.
[ -d "$COMMITTED" ] || {
    echo "  FAIL  $COMMITTED is missing; the golden corpus is release-blocking (NORM-039)" >&2
    exit 1
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
python3 scripts/vectors/generate.py "$TMP" >/dev/null || { echo "  FAIL  generator errored" >&2; exit 1; }

if diff -r -q "$COMMITTED" "$TMP" >/dev/null 2>&1; then
    # Z-12: print the interpreter and the digest of the regenerated corpus. Every CI lane
    # then carries, in its own log, the evidence that it reproduced the SAME committed
    # bytes - which is how cross-lane identity is established without copying a result
    # from one interpreter into another.
    echo "  OK    W1-A vectors reproduce byte-for-byte" \
         "[python $(python3 -c 'import sys;print(".".join(map(str,sys.version_info[:3])))')" \
         "corpus $(sha256sum "$TMP/EXPECTED.sha256" | cut -c1-16)]"
else
    echo "  FAIL  regenerated vectors differ from the committed golden output" >&2
    diff -r "$COMMITTED" "$TMP" 2>&1 | head -20 | sed 's/^/        /' >&2
    echo "        Golden output is updated deliberately, never as a side effect." >&2
    exit 1
fi

python3 scripts/vectors/verify.py || exit 1
