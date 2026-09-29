# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Every contributed commit carries its author's DCO sign-off.
# Implements: D-91, D-92, D-93, GOV-002
#
# Owner decision 2026-09-29: the project adopts the Developer Certificate of Origin. A
# `Signed-off-by:` trailer is a personal legal statement, so this gate checks that it names
# the commit's AUTHOR - a sign-off by someone else certifies nothing about the author's
# right to contribute. It checks the commits a pull request adds and never rewrites or
# judges history: commits made before the policy are not in any pull request range.
#
#   check_dco.py BASE HEAD      every non-merge commit in BASE..HEAD
#   check_dco.py                the same, with BASE and HEAD from DCO_BASE / DCO_HEAD
#   check_dco.py --self-test    prove the check tells signed from unsigned commits
#
# `Assisted-by:` is a separate disclosure (D-93) and is not a sign-off.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a temporary repository under TMPDIR, self-test only"
# meta:binaries="git"
# =============================================================================
"""DCO: every non-merge commit in a range is signed off by its own author."""
import os
import re
import shutil
import subprocess
import sys
import tempfile

SHA = re.compile(r"^[0-9a-f]{7,64}$")
SIGNOFF = re.compile(r"^(?P<name>.+?)\s*<(?P<email>[^<>\s]+)>\s*$")


def git(*argv, cwd=None, env=None):
    return subprocess.run(["git"] + list(argv), cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True, check=True).stdout


def unsigned(base, head, cwd=None, env=None):
    """[(sha, subject, author)] for every non-merge commit without its author's sign-off."""
    bad = []
    for sha in git("rev-list", "--no-merges", "%s..%s" % (base, head), cwd=cwd, env=env).split():
        name, email, subject = git("log", "-1", "--format=%an%x00%ae%x00%s", sha,
                                   cwd=cwd, env=env).rstrip("\n").split("\x00")
        trailers = git("log", "-1", "--format=%(trailers:key=Signed-off-by,valueonly,unfold)",
                       sha, cwd=cwd, env=env).splitlines()
        ok = False
        for value in trailers:
            m = SIGNOFF.match(value.strip())
            if m and m.group("name").strip() == name.strip() \
                    and m.group("email").lower() == email.lower():
                ok = True
                break
        if not ok:
            bad.append((sha, subject, "%s <%s>" % (name, email)))
    return bad


def report(bad, base):
    for sha, subject, author in bad:
        print("  FAIL  %s %r by %s: no Signed-off-by matching the author" % (sha[:12], subject, author))
    print("  Sign off your own commits (Developer Certificate of Origin, see CONTRIBUTING.md):")
    print("    git commit --amend -s --no-edit        # the last commit")
    print("    git rebase --signoff %s    # every commit on the branch" % base[:12])
    print("  then push the branch again. Nobody may sign off on another person's behalf.")


def self_test():
    tmp = tempfile.mkdtemp(prefix="isedraf-dco-")
    # Run under a git hook, `git commit` exports GIT_AUTHOR_*, GIT_DIR and friends, and they
    # override -c user.name and cwd. The self-test repository must see none of them.
    clean = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    clean["GIT_CONFIG_NOSYSTEM"] = "1"
    try:
        def commit(msg, name="Ada Example", email="ada@example.test"):
            env = dict(clean, GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email,
                       GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email)
            git("commit", "-q", "--allow-empty", "--no-gpg-sign", "-m", msg, cwd=tmp, env=env)
            return git("rev-parse", "HEAD", cwd=tmp, env=clean).strip()
        git("init", "-q", cwd=tmp, env=clean)
        base = commit("root")
        good = commit("signed\n\nSigned-off-by: Ada Example <ada@example.test>")
        good_case = commit("signed, email case differs\n\nSigned-off-by: Ada Example <ADA@example.test>")
        none = commit("no sign-off\n\nAssisted-by: none")
        other = commit("signed by someone else\n\nSigned-off-by: Bob Other <bob@example.test>")
        body = commit("sign-off only in the body\n\nSigned-off-by: Ada Example <ada@example.test> said so")
        found = {sha for sha, _, _ in unsigned(base, "HEAD", cwd=tmp, env=clean)}
        expect = {none, other, body}
        if found != expect or good in found or good_case in found:
            print("  FAIL  DCO self-test: flagged %d commits, expected exactly the %d unsigned ones"
                  % (len(found), len(expect)))
            return 1
        print("  OK    DCO self-test: %d unsigned commits caught, %d signed commits accepted"
              % (len(expect), 2))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) == 3:
        base, head = argv[1], argv[2]
    elif len(argv) == 1:
        base, head = os.environ.get("DCO_BASE", ""), os.environ.get("DCO_HEAD", "")
    else:
        print("usage: check_dco.py BASE HEAD | --self-test", file=sys.stderr)
        return 64
    if not (SHA.match(base) and SHA.match(head)):
        print("  FAIL  DCO: BASE and HEAD must be commit SHAs, got %r and %r" % (base, head))
        return 64
    bad = unsigned(base, head)
    if bad:
        report(bad, base)
        return 1
    n = len(git("rev-list", "--no-merges", "%s..%s" % (base, head)).split())
    print("  OK    DCO: %d commit(s) signed off by their authors" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
