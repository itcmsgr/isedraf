#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Enforce canonical file identity — SPDX, copyright holder, meta:owner.
# Implements: D-62, D-90, L-01, L-03, L-04, L-05, L-07, L-11
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,grep,python3"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
HOLDER="Antonios Voulvoulis / ITCMS"
CONTACT="contact@itcms.gr"
FAIL=0
fail() { echo "  FAIL  $*" >&2; FAIL=1; }

echo "=== L-03/L-04/L-05: source file identity ==="
while IFS= read -r f; do
    [ -f "$f" ] || continue
    grep -q 'SPDX-License-Identifier: MPL-2.0' "$f" || fail "$f: missing SPDX-License-Identifier: MPL-2.0"
    if grep -q 'SPDX-FileCopyrightText' "$f"; then
        grep -qF "$HOLDER" "$f" || fail "$f: SPDX copyright does not carry canonical holder verbatim"
    fi
    # L-03: meta:owner, where present, must be EXACTLY the canonical value.
    if grep -q 'meta:owner=' "$f"; then
        if ! grep -qF "meta:owner=\"$HOLDER\"" "$f"; then
            fail "$f: meta:owner is not the canonical value \"$HOLDER\""
        fi
    fi
done < <(git ls-files '*.sh' '*.py')

echo "=== docs: SPDX comment header required ==="
while IFS= read -r f; do
    grep -q 'SPDX-License-Identifier: MPL-2.0' "$f" || fail "$f: missing SPDX header comment"
done < <(git ls-files 'docs/**/*.md' 'docs/*.md')

echo "=== L-11: declared contact must be canonical ==="
# Precise by design: prose may legitimately QUOTE a foreign address to document what
# must not be inherited (docs/development/HEADER_POLICY.md does exactly that). Only a
# DECLARATION is a violation - an SPDX copyright line or a meta:owner line.
# --untracked so a local run sees what CI sees; git grep alone searches only the index.
# -P only: combining -E and -P makes git grep error out, and a swallowed error is a
# gate that can never fail. Errors are therefore fatal here, not tolerated.
decl_hits=$(git grep -nI --untracked -P \
    '^[^[:alnum:]]*(SPDX-FileCopyrightText|meta:owner=).*@(?!itcms\.gr)' -- . ) ; rc=$?
if [ "$rc" -gt 1 ]; then
    fail "L-11 gate could not execute (git grep exit $rc) - refusing to report a pass"
elif [ -n "$decl_hits" ]; then
    while IFS= read -r line; do
        [ -n "$line" ] && fail "declares a non-canonical contact: ${line%%:*} (canonical: $CONTACT)"
    done <<< "$decl_hits"
fi

echo "=== HDR-001/HDR-002: one metadata grammar, no governance keys in docstrings ==="
while IFS= read -r f; do
    [ -f "$f" ] || continue
    # Governance metadata must use the meta: grammar, never a docstring field.
    if grep -qE '^\s*(Owner|Maintainer|Copyright-Owner|Stability):' "$f"; then
        fail "$f: governance key in prose/docstring; use the meta: grammar (HDR-002)"
    fi
    # Every eligible source file carries the canonical owner line.
    grep -q 'meta:owner=' "$f" || fail "$f: missing meta:owner (HDR-001)"
    grep -q 'meta:type=' "$f" || fail "$f: missing meta:type (HDR-001)"
done < <(git ls-files --untracked 'scripts/**/*.sh' 'scripts/**/*.py' 'collectors/*.sh' 'lib/**/*.py' 2>/dev/null)

echo "=== L-07: JSON must not carry a synthetic licence key ==="
while IFS= read -r f; do
    python3 - "$f" <<'PY' || FAIL=1
import json,sys
p=sys.argv[1]
try: d=json.load(open(p))
except Exception as e: print(f"  FAIL  {p}: invalid JSON: {e}"); sys.exit(1)
if isinstance(d,dict):
    bad=[k for k in d if k.lower() in ("_license","_owner","_copyright","_spdx")]
    if bad: print(f"  FAIL  {p}: synthetic licence key(s) {bad}; JSON is NON_HEADER_FORMAT (REUSE only)"); sys.exit(1)
PY
done < <(git ls-files '*.json')

[ "$FAIL" -eq 0 ] && echo "  OK    header identity clean" || echo "  header identity FAILED" >&2
exit "$FAIL"
