#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Enforce D-96 — no product implementation before architecture freeze.
# Implements: D-96, D-107, D-68, G-05
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

# D-107: implementation is authorized by a VERIFIED freeze set, not by a historical
# filename. check-freeze is the sole authority; this gate consumes its verdict (X-01).
VERIFIED="$(bash scripts/ci/check_freeze.sh --verified-sets 2>/dev/null)"
if [ -n "$VERIFIED" ]; then
    echo "  INFO  verified freeze set(s): $(echo $VERIFIED | tr '\n' ' ')— implementation of that scope permitted"
    # This used to `exit 0`, which switched off everything below it. D-96 is genuinely a
    # PRE-freeze rule and must stop applying here - but D-84 and D-17/D-86 are permanent
    # posture, and verifying a freeze set was silently disabling them too. Found the
    # moment W1A_CORE.sha256 was created, by the falsifiability harness, because the
    # D-84 and D-17/D-86 injections stopped firing (GOV-002 doing its job).
    PREFREEZE=0
else
    PREFREEZE=1
fi

if [ "$PREFREEZE" -eq 1 ]; then
    echo "=== D-96: pre-freeze bootstrap scope ==="

    # Product implementation paths must not exist before the freeze.
    for p in lib/isedraf bin/isedraf collectors rules schemas corpus; do
        [ -e "$p" ] && fail "$p exists before architecture freeze (D-96)"
    done

    # Only governance/documentation/CI tooling may ship.
    while IFS= read -r f; do
        case "$f" in
            scripts/ci/*|scripts/docs/*) ;;
            # NORM-039 golden vectors are release-blocking conformance artifacts, not
            # product implementation: they test the frozen spec and are permitted before
            # the freeze.
            scripts/vectors/*) ;;
            *) fail "$f: executable code outside scripts/ci and scripts/docs before freeze (D-96)" ;;
        esac
    done < <(git ls-files '*.py' '*.sh' | grep -v '^git-hooks/')
fi

# Everything below is PERMANENT posture and runs whether or not anything is frozen.

# D-84 posture, asserted from the very first commit.
if git grep -nIE '^[[:space:]]*(import|from)[[:space:]]+(socket|ssl|urllib|http|smtplib|ftplib|xmlrpc|sqlite3|dbm|shelve)\b' -- 'scripts/**/*.py' >/dev/null 2>&1; then
    fail "network/database import found in repository tooling (D-84)"
fi

# D-17/D-86: bytecode must never be committed.
git ls-files | grep -qE '\.pyc$|__pycache__/' && fail "committed bytecode (D-17, D-86)"

# Internal planning material must never be tracked.
git ls-files | grep -qE '^(planning|INIT)/' && fail "internal planning material is tracked (must stay local-only)"

[ "$FAIL" -eq 0 ] && echo "  OK    bootstrap scope clean" || echo "  bootstrap scope FAILED" >&2
exit "$FAIL"
