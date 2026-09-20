#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Produce the exact tree a public repository would contain, and prove it.
# Implements: D-90, GOV-001, GOV-002
#
# The private engineering repository keeps the real development history, including two
# commits whose content and messages name live infrastructure. That history is NOT
# rewritten and NOT exported. The public repository begins from this tree as its initial
# commit, with no .git of its own.
#
# The release packages are built FROM THE EXPORT, not from the engineering tree. An
# artifact handed to a user must come from exactly the bytes that will be public —
# otherwise the thing that was tested and the thing that was published are two different
# things that merely look alike.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="the export directory only"
# meta:binaries="git,tar,rsync,sha256sum"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
OUT="${1:-$ROOT/dist/export}"
FAIL=0
bad() { echo "  FAIL  $*" >&2; FAIL=1; }

# Paths that exist in the engineering tree and must never reach the public one.
# Paths that exist in the engineering repository and must NEVER reach the public one.
#
# CLAUDE.md is the owner's decision, reversed on 2026-09-19 after it shipped once: it is
# the instruction file that governs how this repository is worked on, not documentation a
# user or contributor of the published project needs. It stays in the engineering
# repository, where it is authority, and out of the public one, where it is noise at best
# and an invitation to argue with the process at worst.
# Owner decision 2026-09-19. The published repository carries the SPECIFICATION - what the
# tool guarantees, what its evidence means, how state and delta are defined - and not the
# internal change control that produced it. A reader of a public project is served by
# "ISEDRAF assesses only state observable on the local operating system"; they are not
# served by 124 numbered internal decisions, a register of unresolved questions with
# deadlines, or the lane scoping that drove implementation order.
#
# The freeze set is split the same way: docs/architecture/freeze/W1A_CORE_PUBLIC.sha256
# holds the digests of the published subset, COPIED from the full set rather than
# recomputed, so both repositories verify the same bytes and neither gate is weakened.
#
# V0_1_IMPLEMENTATION_SCOPE.md was in this list and was taken out on evidence. It looked
# like lane planning; it is the document that DEFINES 54 requirement IDs, and 52 published
# files cite them - including lib/isedraf/identity.py, cli.py, inventory/model.py and the
# tests. Every `Implements: SCOPE-045` in the shipped source would have pointed at a
# document the reader cannot open. A specification that the published code cites is not
# internal change control.
# ONE AUTHORITY. The exclusions live in scripts/ci/release_surface.txt as `!path` lines
# and are read from there, so the export and the privacy gate cannot disagree about what
# is published. planning/ is added here because it is untracked and therefore has no
# entry in a file that describes tracked surfaces.
EXCLUDE_PREFIXES="planning/ $(sed -n 's/^!//p' "$ROOT/scripts/ci/release_surface.txt" | tr '\n' ' ')"

rm -rf "$OUT"; mkdir -p "$OUT"

# git archive of HEAD: only tracked, committed bytes. A working-tree copy would carry
# whatever happened to be lying around.
git archive --format=tar HEAD | tar -x -C "$OUT" || { echo "  FAIL  git archive" >&2; exit 1; }

for prefix in $EXCLUDE_PREFIXES; do
    if [ -e "$OUT/$prefix" ]; then
        rm -rf "${OUT:?}/$prefix"
        echo "  removed $prefix from the export"
    fi
done

# .git must not exist in the export. The public repository gets a fresh history.
[ -e "$OUT/.git" ] && bad "the export contains .git — the private history must not travel"

echo "  exported $(find "$OUT" -type f | wc -l) files to $OUT"

for forbidden in planning .git GITHUB_CONNECT.md CLAUDE.md \
                 DECISIONS_REGISTER.md OPEN_DECISIONS.md AMENDMENTS.md \
                 W1A_CORE.sha256; do
    found="$(find "$OUT" -name "$forbidden" -print -quit 2>/dev/null)"
    [ -n "$found" ] && bad "forbidden path in the export: ${found#$OUT/}"
done

# A temporary history, only so the gates below can run: they resolve the repository root
# from git, and an export with no history is not a repository. It is removed at the end.
( cd "$OUT" && git init -q && git add -A >/dev/null 2>&1 \
  && git -c user.email=contact@itcms.gr -c user.name="ISEDRAF release" \
        commit -q -m "release candidate" >/dev/null 2>&1 ) \
    || bad "could not stage the export for building"

# ---- the REAL gates, run against the EXPORT ------------------------------------------------
# The privacy gate is invoked rather than reimplemented. An open-coded grep here would be a
# second classification system that can disagree with the first: it already flagged the
# falsifiability harness, whose fixture exists precisely to prove the privacy gate fires.
if [ "$FAIL" -eq 0 ]; then
    ( cd "$OUT" && python3 "$ROOT/scripts/ci/check_privacy.py" --scope repository ) \
        || bad "the export failed the privacy gate"
    ( cd "$OUT" && python3 "$ROOT/scripts/ci/check_docs_truth.py" ) \
        || bad "the export failed the documentation truth gate"
    ( cd "$OUT" && bash "$ROOT/scripts/ci/check_freeze.sh" ) \
        || bad "the export failed freeze verification"
fi

if [ "$FAIL" -eq 0 ]; then
    ( cd "$OUT" && bash packaging/build.sh ) > "$OUT/../export-build.log" 2>&1 \
        || { bad "the release build FAILED from the exported tree"; tail -5 "$OUT/../export-build.log" >&2; }
    if [ -d "$OUT/dist/packages" ]; then
        bash scripts/ci/check_package_payload.sh "$OUT/dist" || bad "exported package payload rejected"
    fi
fi

# The export's own .git was created only to build; it must not be part of what is published.
rm -rf "${OUT:?}/.git"

[ "$FAIL" -eq 0 ] || { echo "  release export FAILED" >&2; exit 1; }
echo "  OK    export clean, packages built from it, payloads verified"
