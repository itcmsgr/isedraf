#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The falsifiability harness CONTRACT — one injection, four distinguishable outcomes.
# Implements: GOV-002, Z-20
#
# Z-20. A mutation harness that reads only the gate's exit code cannot tell "the gate
# rejected the mutation" from "the mutated tool died". Both are non-zero. A suite that
# counts the second as a firing gate is measuring nothing, and its own failures are
# invisible - which is exactly how the Z-02 injection sat broken while the summary
# reported 25 firing.
#
# Every injection therefore declares the EVIDENCE its gate must print. A gate that fails
# without producing that evidence is not counted as firing.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,bash,tar,mktemp"
# =============================================================================

# Outcome vocabulary (Z-20). Exactly one is assigned per injection.
#   MUTATION_EXECUTED_AND_DETECTED   mutation applied, gate failed, gate named the reason  -> PASS
#   MUTATION_EXECUTED_BUT_NOT_DETECTED  mutation applied, gate passed                      -> FAIL
#   MUTATION_TOOL_CRASHED            gate failed but produced no rejection evidence        -> FAIL
#   HARNESS_ERROR                    the mutation never applied, or the copy failed        -> FAIL
PASS=0; FAIL=0
declare -a OUTCOMES=()

# A witness that the mutation actually landed, computed from the WORKING TREE rather than
# from git: after `git init && git add -A` every file is staged as added, so `git status`
# is never empty and can witness nothing. The index is deliberately left untouched here -
# staging files on the harness's own initiative would change what the gate under test sees.
_tree_digest() {
    find . -path ./.git -prune -o -type f -print0 2>/dev/null \
        | sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum
}

_record() {   # _record OUTCOME name detail
    OUTCOMES+=("$1 $2")
    case "$1" in
        MUTATION_EXECUTED_AND_DETECTED) echo "  OK   fires: $2"; PASS=$((PASS+1));;
        *) echo "  FAIL [$1] $2${3:+ — $3}" >&2; FAIL=$((FAIL+1));;
    esac
}

# inject <name> <gate> <mutate> <evidence-ERE> [tree|external]
#
# <evidence-ERE> is the text the GATE must print for the failure to count. It is the whole
# point: it is what distinguishes a rejection from a crash.
# <scope> defaults to "tree": the mutation must leave a visible change in the working tree.
# "external" is for the two commit-msg injections, whose subject is a file outside the repo;
# it must be declared, never inferred, so that "nothing changed" can never pass silently.
inject() {
    local name="$1" gate="$2" mutate="$3" evidence="${4:-}" scope="${5:-tree}"
    if [ -z "$evidence" ]; then
        _record HARNESS_ERROR "$name" "no evidence pattern declared (GOV-002)"; return
    fi
    local t log; t="$(mktemp -d)"; log="$(mktemp)"

    git ls-files -z | tar --null -T - -cf - 2>/dev/null | tar -xf - -C "$t" 2>/dev/null
    (
        cd "$t" || exit 70
        git init -q >/dev/null 2>&1 || exit 70
        git add -A >/dev/null 2>&1 || exit 70
        # The sandbox needs a real HEAD, not just an index. `packaging/build.sh` runs
        # `git archive HEAD`, and without a commit it died on that line, so NO injection
        # had ever reached a completed build: everything downstream of the tarball was
        # unreachable. The two package injections that existed were genuine - both are
        # caught during staging, before `git archive` - which is exactly why the hole
        # stayed invisible until an injection needed a finished artifact.
        # A fresh `git init` inherits no hooks, so nothing is bypassed here.
        git -c user.name=falsifiable -c user.email=falsifiable@invalid \
            commit -q -m "sandbox" >/dev/null 2>&1 || exit 70
        local before after
        before="$(_tree_digest)"
        eval "$mutate" >/dev/null 2>&1 || exit 71
        after="$(_tree_digest)"
        if [ "$scope" = "tree" ] && [ "$before" = "$after" ]; then
            exit 72
        fi
        eval "$gate" >"$log" 2>&1 || exit 1
        exit 0
    )
    local rc=$?
    local out; out="$(cat "$log" 2>/dev/null)"
    rm -rf "$t" "$log"

    case "$rc" in
        70) _record HARNESS_ERROR "$name" "could not build the disposable tree";;
        71) _record HARNESS_ERROR "$name" "the mutation command failed; the tree was never mutated";;
        72) _record HARNESS_ERROR "$name" "the mutation changed nothing in the tree";;
        0)  _record MUTATION_EXECUTED_BUT_NOT_DETECTED "$name" "the gate accepted the mutated tree";;
        *)  if printf '%s' "$out" | grep -qE "$evidence"; then
                _record MUTATION_EXECUTED_AND_DETECTED "$name"
            else
                _record MUTATION_TOOL_CRASHED "$name" \
                    "the gate failed WITHOUT printing its rejection evidence /$evidence/"
                # Always show what the gate actually said. This used to require
                # FALSIFIABLE_DEBUG=1, which meant a crash that happened only on a CI
                # runner was undiagnosable from the CI log - the one place it occurred.
                # A crash you cannot see is a crash you cannot fix.
                printf '%s\n' "$out" | tail -25 | sed 's/^/         | /' >&2
            fi;;
    esac
}

harness_summary() {
    echo "--- $PASS injections detected, $FAIL not counted as firing ---"
    [ "$FAIL" -eq 0 ]
}
