#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Enforce canonical on-disk paths across every authority tier.
# Implements: D-99, D-49, D-105
#
# Round 3 finding T-07: the ledger path was repaired in four documents and left stale in
# two others - including the data map an auditor is told to rely on - while the repair
# document asserted the sweep had landed. Prose review is insufficient; this is the gate.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,grep"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
FAIL=0
fail() { echo "  FAIL  $*" >&2; FAIL=1; }

# Canonical: /var/lib/isedraf/ledger/segment-NNNNNN.jsonl  (D-99)
# Forbidden anywhere normative: the singular ledger.jsonl path.
scan() {
    for f in "$@"; do
        [ -f "$f" ] || continue
        case "$f" in *20_review/*|*00_nftban/*|*/bootstrap/*|*/prompts/*) continue;; esac
        if grep -nI 'ledger\.jsonl' "$f" | grep -qv 'paths:allow-legacy'; then
            grep -nI 'ledger\.jsonl' "$f" | grep -v 'paths:allow-legacy' | while read -r l; do
                echo "  FAIL  $f:${l%%:*}: singular 'ledger.jsonl'; canonical is ledger/segment-NNNNNN.jsonl (D-99)" >&2
            done
            FAIL=1
        fi
    done
}
# Enumerate with find, not git pathspecs: the gate must see authoritative files whether
# or not git tracks them, and must not depend on glob expansion quirks (T-07, T-20).
mapfile -t FILES < <(
    { find docs -name '*.md' -type f 2>/dev/null
      [ -f CLAUDE.md ] && echo CLAUDE.md
    } | sort -u
)
[ "${#FILES[@]}" -gt 0 ] || { echo "  FAIL  path gate enumerated no files - scope defect" >&2; exit 1; }
echo "  scope: ${#FILES[@]} files"
scan "${FILES[@]}"

[ "$FAIL" -eq 0 ] && echo "  OK    canonical paths consistent" || { echo "  path consistency FAILED" >&2; exit 1; }
