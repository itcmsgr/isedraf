#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Every tests/test_*.py is run by `make check-tests` or excluded with a reason.
# Implements: GOV-002, NORM-039
#
# Found 2026-10-09: tests/test_launcher_relay.py and tests/test_mounts_adversarial.py existed,
# passed, and were run by nothing in `make check` or CI - assurance that was not being given.
# This gate makes that state impossible to reach silently: a test file is either named in the
# check-tests recipe or listed in scripts/ci/test_exclusions.json with a non-empty reason, never
# both, and an exclusion that names no file is stale.
#
# meta:type="gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""Test inclusion: no test file is silently left out of `make check`."""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
EXCLUSIONS = ROOT / "scripts" / "ci" / "test_exclusions.json"
_RUN = re.compile(r"python3 (tests/test_[A-Za-z0-9_]+\.py)")


def recipe(makefile_text, target="check-tests"):
    """The recipe lines of one Makefile target."""
    lines, inside = [], False
    for line in makefile_text.splitlines():
        if line.startswith(target + ":"):
            inside = True
            continue
        if inside:
            if line.startswith("\t"):
                lines.append(line)
            elif line.strip() == "" or line.startswith("#"):
                continue
            else:
                break
    return lines


def check(test_files, makefile_text, exclusions):
    run = set(_RUN.findall("\n".join(recipe(makefile_text))))
    problems = []
    for path in sorted(test_files):
        reason = exclusions.get(path)
        if path in run and path in exclusions:
            problems.append("%s is both run by check-tests and excluded" % path)
        elif path not in run and not (isinstance(reason, str) and reason.strip()):
            problems.append("%s is run by nothing in `make check-tests` and is not excluded with a "
                            "reason in scripts/ci/test_exclusions.json" % path)
    for path in sorted(set(exclusions) - set(test_files)):
        problems.append("the exclusion of %s names no test file (stale)" % path)
    for path in sorted(run - set(test_files)):
        problems.append("check-tests runs %s, which does not exist" % path)
    return problems, run


def self_test():
    """The rule fires on each failure shape and stays silent on a clean set."""
    mk = "check-tests:\n\t@python3 tests/test_a.py\n\t@python3 tests/test_b.py\n\nother:\n\tpython3 tests/test_c.py\n"
    cases = [
        ({"tests/test_a.py", "tests/test_b.py"}, {}, False),
        ({"tests/test_a.py", "tests/test_b.py", "tests/test_c.py"}, {}, True),   # c only elsewhere
        ({"tests/test_a.py", "tests/test_b.py", "tests/test_c.py"},
         {"tests/test_c.py": "manual lab test"}, False),
        ({"tests/test_a.py", "tests/test_b.py", "tests/test_c.py"},
         {"tests/test_c.py": " "}, True),                                          # empty reason
        ({"tests/test_a.py", "tests/test_b.py"}, {"tests/test_a.py": "x"}, True),  # both
        ({"tests/test_a.py", "tests/test_b.py"}, {"tests/test_z.py": "x"}, True),  # stale
        ({"tests/test_a.py"}, {}, True),                                           # runs a missing file
    ]
    wrong = [i for i, (files, excl, bad) in enumerate(cases)
             if bool(check(files, mk, excl)[0]) != bad]
    return len(cases), wrong


def main():
    cases, wrong = self_test()
    if wrong:
        print("  FAIL  test inclusion self-test: case(s) %s judged wrongly" % wrong)
        return 1
    files = set(str(p.relative_to(ROOT)) for p in (ROOT / "tests").glob("test_*.py"))
    exclusions = json.loads(EXCLUSIONS.read_text(encoding="utf-8")).get("excluded", {})
    problems, run = check(files, MAKEFILE.read_text(encoding="utf-8"), exclusions)
    if problems:
        for problem in problems:
            print("  FAIL  %s" % problem)
        print("=== test inclusion gate FAILED ===")
        return 1
    print("  OK    test inclusion: %d test files, %d run by check-tests, %d excluded with a reason; "
          "self-test %d cases" % (len(files), len(run & files), len(exclusions), cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
