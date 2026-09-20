#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
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
#
# INVARIANT, owner decision 2026-09-19 (from the `ar -D`/`-U` finding):
#
#   local mutation works   !=   CI mutation proven
#
# For a RELEASE-CRITICAL gate, MUTATION_EXECUTED_AND_DETECTED on a workstation is not
# sufficient evidence. The injection must also be observed firing in the environment that
# BUILDS THE RELEASE, because the release environment is part of the proof.
#
# This was learned the hard way and twice in one afternoon. A reproducibility injection
# dropped `ar`'s deterministic flag and fired locally; on ubuntu-latest it passed silently,
# because whether plain `ar rc` is deterministic depends on how the local binutils was
# COMPILED. Forcing `U` also fired locally and also passed silently there. A green
# injection that proves nothing, on the exact machine that produces the artifacts.
#
# New release/build injections SHALL declare which of these they have:
#
#   MUTATION_EXECUTED_AND_DETECTED   observed firing locally
#   CI_EXECUTED_AND_DETECTED         observed firing in CI, on the release builder
#
# The harness is not redesigned here; `make check-falsifiable` runs in CI on every push and
# a non-firing injection fails that job, so the second observation exists for every
# injection that runs there. What this records is that it MUST exist, and that an
# environment-dependent mutation is not evidence until it has been seen to fire where the
# release is built.
#   HARNESS_ERROR                    the mutation never applied, or the copy failed        -> FAIL
PASS=0
SKIPPED=0; FAIL=0
declare -a OUTCOMES=()

# A witness that the mutation actually landed, computed from the WORKING TREE rather than
# from git: after `git init && git add -A` every file is staged as added, so `git status`
# is never empty and can witness nothing. The index is deliberately left untouched here -
# staging files on the harness's own initiative would change what the gate under test sees.
_tree_digest() {
    # Regular files AND symlinks. `-type f` alone excludes symlinks entirely, so adding
    # one changed nothing the harness could see and the injection that tests for a
    # symlink escaping the repository reported "the mutation changed nothing" - a blind
    # spot precisely where it matters, since a symlink is one of the ways restricted
    # content reaches a public artifact without ever being committed to it.
    #
    # The link is recorded as name -> target rather than followed: what changed is where
    # the path points, and following it would hash whatever happens to be outside.
    {
        find . -path ./.git -prune -o -type f -print0 2>/dev/null \
            | sort -z | xargs -0 sha256sum 2>/dev/null
        find . -path ./.git -prune -o -type l -printf '%p -> %l\n' 2>/dev/null | sort
    } | sha256sum
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
# <requires> (6th argument) names a path the injection's SUBJECT lives in. When it is
# absent, the injection is SKIPPED and said to be skipped - not counted as firing, and
# not counted as a failure either.
#
# This exists because the public repository publishes the specification and not the
# internal change control. Seven injections attack documents that are deliberately not
# published there: the decisions register, the master index, CLAUDE.md. In that checkout
# they mutated something the gate genuinely cannot see, and reported
# MUTATION_EXECUTED_BUT_NOT_DETECTED - technically accurate, and the wrong verdict.
#
# It cannot be used to hide a real failure: in the engineering repository every subject
# exists, so nothing skips, and a skip is printed with the path that caused it.
# Declared on the line BEFORE the injection it applies to. A sixth positional argument
# was the obvious design and the wrong one: several injections carry a heredoc or a
# trailing comment, so "the last argument" is not somewhere a tool can reliably append.
# This reads the same way and cannot land inside a heredoc.
next_requires() { NEXT_REQUIRES="$1"; }

inject() {
    # A malformed call used to die with "$3: unbound variable" and abort the whole run,
    # which is the worst possible failure for a harness: it stops reporting on everything
    # after it. Twice now an edit to this file dropped an argument line — once leaving an
    # orphaned evidence string that the NEXT injection swallowed as its gate.
    #
    # Z-20 already has the right vocabulary for "this experiment could not be performed".
    # A broken injection is a HARNESS_ERROR, reported and counted, and the run continues.
    if [ "$#" -lt 4 ]; then
        _record HARNESS_ERROR "${1:-<unnamed injection>}" \
            "malformed call: $# argument(s), expected at least 4 (name, gate, mutation, evidence)"
        return
    fi
    local name="$1" gate="$2" mutate="$3" evidence="${4:-}" scope="${5:-tree}"
    local requires="${NEXT_REQUIRES:-}"; NEXT_REQUIRES=""
    if [ -z "$evidence" ]; then
        _record HARNESS_ERROR "$name" "no evidence pattern declared (GOV-002)"; return
    fi
    if [ -n "$requires" ] && [ ! -e "$requires" ]; then
        SKIPPED=$((SKIPPED + 1))
        echo "  SKIP subject not present in this checkout: $requires — $name"
        return
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
    # Three separate numbers, never added together. An injection that was skipped did not
    # reach its target condition and did not falsify anything; reporting "84 injections"
    # when 77 executed and 7 were skipped invites the reader to treat a declared
    # non-applicable case as a negative control that passed. Z-20 exists to stop exactly
    # that conflation, and a summary line is where it would quietly happen.
    echo "--- falsification: $PASS executed and detected · ${SKIPPED:-0} declared skips"\
" (subject not present in this checkout) · $FAIL unexpected non-firing ---"
    [ "$FAIL" -eq 0 ]
}
