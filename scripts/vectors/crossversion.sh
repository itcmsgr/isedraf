#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Byte determinism across every Python interpreter present (Z-12, NORM-039).
# Implements: NORM-039, NORM-035, D-12
#
# The requirement is not "the vectors pass on some Python". It is that the SAME semantic
# input and the SAME frozen rules produce the SAME canonical bytes on every supported
# runtime. Per-version expected output would not be a passing test; it would be the
# determinism claim failing quietly.
#
# Nothing is copied between interpreters: each regenerates the corpus into its own
# directory and the directories are byte-compared here.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3,diff,mktemp,sha256sum"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2

CANDIDATES="python3.9 python3.10 python3.11 python3.12 python3.13 python3.14 python3
/usr/bin/python3 /usr/bin/python3.9 /usr/bin/python3.12"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
seen=""; first=""; firstv=""; rc=0; n=0

for c in $CANDIDATES; do
    command -v "$c" >/dev/null 2>&1 || continue
    v="$("$c" -c 'import sys;print(".".join(map(str,sys.version_info[:3])))' 2>/dev/null)" || continue
    [ -n "$v" ] || continue
    case " $seen " in *" $v "*) continue;; esac     # one run per distinct version
    seen="$seen $v"; n=$((n+1))
    d="$TMP/$v"
    if ! "$c" scripts/vectors/generate.py "$d" >/dev/null 2>&1; then
        echo "  FAIL  python $v could not generate the corpus" >&2; rc=1; continue
    fi
    dig="$(sha256sum "$d/EXPECTED.sha256" | cut -d' ' -f1)"
    if [ -z "$first" ]; then
        first="$d"; firstv="$v"
        echo "  ref   python $v  corpus digest $dig"
    elif diff -r -q "$first" "$d" >/dev/null 2>&1; then
        echo "  OK    python $v  corpus digest $dig  == python $firstv"
    else
        echo "  FAIL  python $v produced DIFFERENT canonical bytes than python $firstv" >&2
        diff -r "$first" "$d" 2>&1 | head -10 | sed 's/^/        /' >&2
        rc=1
    fi
done

if [ "$n" -lt 2 ]; then
    # Stated, never assumed (GOV-001): on a single-interpreter host this proves nothing
    # about cross-version determinism. The CI matrix is where the requirement is met.
    echo "  SKIP  only $n Python interpreter present ($seen) — cross-version determinism"
    echo "        is NOT demonstrated here; NORM-039 is met by the CI matrix (KGG-010)."
    exit "$rc"
fi
[ "$rc" -eq 0 ] && echo "  OK    $n interpreters produce byte-identical canonical evidence"
exit "$rc"
