#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Falsify the falsification harness itself (Z-20).
# Implements: GOV-002, Z-20
#
# The injections prove the GATES can fail. Nothing proved the HARNESS could tell a
# rejection from a corpse. It could not: it read the gate's exit code, and a mutated tool
# that dies exits non-zero exactly like a gate that rejected. This file is the test of
# the test infrastructure, and it runs BEFORE the injections it certifies.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,bash,python3,mktemp"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
# shellcheck source=scripts/ci/falsifiable_lib.sh
. "$ROOT/scripts/ci/falsifiable_lib.sh"

RC=0
expect() {      # expect <required outcome> <what it proves> <inject args...>
    local want="$1" why="$2"; shift 2
    OUTCOMES=(); PASS=0; FAIL=0
    inject "$@" >/dev/null 2>&1
    local got="${OUTCOMES[0]%% *}"
    if [ "$got" = "$want" ]; then
        echo "  OK   $why -> $got"
    else
        echo "  FAIL $why: harness said $got, contract requires $want" >&2
        RC=1
    fi
}

echo "=== Z-20 harness self-test: a crash is not a detection ==="

# 1. The Z-20 case itself. The mutated GENERATOR dies before it can emit anything, so the
#    gate fails with no rejection evidence. The previous harness counted this as a firing
#    mutation - a mutation suite can otherwise score 100% while testing nothing at all.
expect MUTATION_TOOL_CRASHED "mutated tool dies before producing its artifact" \
  "selftest: crashing generator" \
  'bash scripts/vectors/check.sh' \
  'printf "\nraise SystemExit(3)\n" >> scripts/vectors/generate.py' \
  'NORM-035 requires the escape'

# 2. The mutation never applied: a stale anchor, the exact failure that left the Z-02
#    injection silently broken while the summary reported it firing.
expect HARNESS_ERROR "mutation command fails (stale anchor)" \
  "selftest: stale anchor" \
  'bash scripts/ci/check_headers.sh' \
  'python3 -c "raise AssertionError(\"mutation anchor miss\")"' \
  'meta:owner is not the canonical value'

# 3. The mutation ran, exited 0, and changed nothing.
expect HARNESS_ERROR "mutation succeeds but alters nothing" \
  "selftest: no-op mutation" \
  'bash scripts/ci/check_headers.sh' \
  'true' \
  'meta:owner is not the canonical value'

# 4. A real mutation the gate does not cover must be reported as uncovered, never as firing.
expect MUTATION_EXECUTED_BUT_NOT_DETECTED "gate accepts a mutation outside its scope" \
  "selftest: out-of-scope mutation" \
  'bash scripts/ci/check_paths.sh' \
  'printf "irrelevant\n" > selftest_probe.txt && git add -A' \
  'singular'

# 5. And the positive control: a real mutation, rejected, with the reason named.
expect MUTATION_EXECUTED_AND_DETECTED "real mutation rejected with its evidence" \
  "selftest: real mutation" \
  'bash scripts/ci/check_headers.sh' \
  'sed -i "/SPDX-License-Identifier/d" scripts/ci/check_bootstrap_scope.sh' \
  'missing SPDX-License-Identifier'

[ "$RC" -eq 0 ] && echo "  OK    harness distinguishes detection from crash, no-op and harness error"
exit "$RC"
