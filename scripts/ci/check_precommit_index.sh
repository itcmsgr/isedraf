#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Prove the pre-commit hook validates the content being COMMITTED, not the
#          working tree it happens to be run from.
# Implements: GOV-002, D-68, D-83
#
# IQ-029. The hook ran `make check` against the working tree. Stage an invalid file,
# repair only the working-tree copy, and the hook passed on the repaired copy while git
# recorded the invalid staged one: a passing hook behind bytes that never passed.
#
# The hook cannot be tested by running it here, because it runs `make check`, which runs
# this. So each case builds a throwaway repository whose `make check` fails exactly when
# payload.txt contains BAD, installs the hook under test in THAT repository, and makes real
# commits. The repository under test is never touched.
#
# usage: check_precommit_index.sh [hook-to-test]   (default: git-hooks/pre-commit)
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,bash,make,mktemp,grep"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"
HOOK="$(cd "$ROOT" && readlink -f "${1:-git-hooks/pre-commit}")"
echo "--- pre-commit validates the committed content (IQ-029) ---"
[ -f "$HOOK" ] || { echo "  FAIL  no hook at $HOOK"; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/isedraf-hooktest.XXXXXX")" || exit 1
trap 'rm -rf "$WORK"' EXIT
FAILS=0
ok()   { echo "  OK    $1"; }
bad()  { echo "  FAIL  $1"; FAILS=$((FAILS + 1)); }

# A repository shaped like this one where it matters to the hook: a freeze check, the three
# hooks in git-hooks/ and installed, and a `make check` that fails on BAD content.
newrepo() {
  local r="$WORK/$1"
  git init -q "$r" || return 1
  git -C "$r" config user.name "hook test"
  git -C "$r" config user.email "hooktest@example.invalid"
  git -C "$r" config commit.gpgsign false
  mkdir -p "$r/scripts/ci" "$r/git-hooks"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$r/scripts/ci/check_freeze.sh"
  printf 'check:\n\t@! grep -q BAD payload.txt\n' > "$r/Makefile"
  cp "$HOOK" "$r/git-hooks/pre-commit"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$r/git-hooks/pre-push"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$r/git-hooks/commit-msg"
  local hd; hd="$(git -C "$r" rev-parse --git-path hooks)"
  case "$hd" in /*) ;; *) hd="$r/$hd" ;; esac
  cp "$r"/git-hooks/* "$hd"/ && chmod 0755 "$hd"/*
  echo GOOD > "$r/payload.txt"
  git -C "$r" add -A
  echo "$r"
}

commit_in() { git -C "$1" commit -q -m "case" >/dev/null 2>&1; }
head_of()   { git -C "$1" rev-parse -q --verify HEAD 2>/dev/null || echo none; }

# 0. the first commit of a repository has no HEAD to build on, and must still be checked
r="$(newrepo first)" || exit 1
if commit_in "$r"; then ok "root commit: a valid first commit is accepted"
else bad "root commit: a valid first commit was refused"; fi

# 1. THE UNSAFE CASE. Invalid content staged, working-tree copy repaired.
r="$(newrepo unsafe)" && commit_in "$r"
before="$(head_of "$r")"
echo BAD > "$r/payload.txt"; git -C "$r" add payload.txt; echo GOOD > "$r/payload.txt"
if commit_in "$r"; then
  bad "staged BAD, tree repaired: the hook PASSED and git committed $(git -C "$r" show HEAD:payload.txt)"
elif [ "$(head_of "$r")" != "$before" ]; then
  bad "staged BAD, tree repaired: refused, yet HEAD moved"
else ok "staged BAD, tree repaired: refused, HEAD unchanged"; fi

# 2. THE BLOCKING CASE. Valid content staged, unrelated breakage in the tree only.
r="$(newrepo blocking)" && commit_in "$r"
echo GOOD2 > "$r/payload.txt"; git -C "$r" add payload.txt; echo BAD > "$r/payload.txt"
if commit_in "$r" && [ "$(git -C "$r" show HEAD:payload.txt)" = GOOD2 ]; then
  ok "staged GOOD, tree broken: accepted, and the staged content is what was committed"
else bad "staged GOOD, tree broken: refused for content that is not being committed"; fi

# 3. `commit -a` builds its own temporary index; the hook must validate THAT one.
r="$(newrepo all)" && commit_in "$r"
echo BAD > "$r/payload.txt"
if git -C "$r" commit -q -a -m "case" >/dev/null 2>&1; then
  bad "commit -a of BAD content: accepted"
else ok "commit -a of BAD content: refused"; fi

# 4. `commit <path>` commits the tree copy of <path> over a different staged one.
r="$(newrepo partial)" && commit_in "$r"
echo BAD > "$r/payload.txt"; git -C "$r" add payload.txt; echo GOOD3 > "$r/payload.txt"
if git -C "$r" commit -q -m "case" -- payload.txt >/dev/null 2>&1 \
   && [ "$(git -C "$r" show HEAD:payload.txt)" = GOOD3 ]; then
  ok "commit <path> of GOOD over staged BAD: accepted, GOOD committed"
else bad "commit <path> of GOOD over staged BAD: refused"; fi

# 5. the snapshot must not outlive the hook
left="$(git -C "$WORK/unsafe" worktree list | wc -l)"
if [ "$left" -eq 1 ]; then ok "no snapshot worktree left registered after the hook"
else bad "$((left - 1)) snapshot worktree(s) left registered after the hook"; fi

if [ "$FAILS" -ne 0 ]; then
  echo "=== pre-commit index gate FAILED: $FAILS case(s) ==="
  exit 1
fi
echo "  OK    pre-commit validates the committed content, in all 6 cases"
