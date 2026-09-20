#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Verify per-set freeze manifests and expose the verdict to other gates.
# Implements: D-68, D-107, GOV-001, GOV-004
#
# The sole authority on whether a freeze set is valid. `--verified-sets` prints the name of
# every set that passes, so check-scope consumes a verdict instead of testing for a
# historical filename (finding X-01).
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,sha256sum,readlink"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
FREEZE_DIR="docs/architecture/freeze"
QUIET=0; [ "${1:-}" = "--verified-sets" ] && QUIET=1
FAIL=0
say() { [ "$QUIET" -eq 1 ] || echo "$*"; }
bad() { [ "$QUIET" -eq 1 ] || echo "  FAIL  $*" >&2; FAIL=1; }

shopt -s nullglob
sets=("$FREEZE_DIR"/*.sha256)
if [ "${#sets[@]}" -eq 0 ]; then
    # A candidate tree with no manifest is NOT frozen. Stated, not assumed.
    say "  OK    no freeze set declared (candidate phase; nothing is frozen)"
    exit 0
fi

for m in "${sets[@]}"; do
    name="$(basename "$m" .sha256)"; ok=1
    seen=""
    while read -r digest path; do
        [ -n "${digest:-}" ] || continue
        case "$path" in
            *..*)      bad "$name: path traversal in manifest: $path"; ok=0; continue;;
            /*)        bad "$name: absolute path in manifest: $path"; ok=0; continue;;
        esac
        case " $seen " in *" $path "*) bad "$name: duplicate manifest entry: $path"; ok=0; continue;; esac
        seen="$seen $path"
        [ -e "$path" ]  || { bad "$name: manifested file missing: $path"; ok=0; continue; }
        [ -L "$path" ]  && { bad "$name: manifested path is a symlink: $path"; ok=0; continue; }
        [ -f "$path" ]  || { bad "$name: manifested path is not a regular file: $path"; ok=0; continue; }
        git ls-files --error-unmatch "$path" >/dev/null 2>&1 \
            || { bad "$name: manifested file is not tracked by git: $path"; ok=0; continue; }
        actual="$(sha256sum "$path" | cut -d' ' -f1)"
        [ "$actual" = "$digest" ] || { bad "$name: digest mismatch: $path"; ok=0; }
    done < "$m"
    if [ "$ok" -eq 1 ]; then
        n=$(grep -c . "$m")
        if [ "$QUIET" -eq 1 ]; then echo "$name"; else echo "  OK    freeze set $name: $n artifacts verified"; fi
    else
        bad "$name: INVALID — a manifested artifact changed, is untracked, or is not a regular file."
        bad "$name: this invalidates the freeze and requires an explicit re-freeze (D-68, D-107)."
    fi
done
exit "$FAIL"
