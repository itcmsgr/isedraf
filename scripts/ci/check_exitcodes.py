#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: lib/isedraf/exitcodes.json is the one source of exit codes, and nothing drifts from it.
# Implements: OUT-001, OUT-017, SCOPE-077, AUTH-023, AUTH-020, D-72
#
# OUT-001: exit codes are defined once in lib/isedraf/exitcodes.json, and code, documentation
# and tests are validated against it. This gate checks, in one place:
#   - the file itself: unique codes and names, every field present, precedence over its codes
#   - lib/isedraf/exitcodes.py: every constant is a reachable code of the same name, and every
#     reachable code has a constant
#   - SCOPE-077: the W1-A set 0, 2, 64, 70 is reachable; OUT-001's table: every code it lists
#   - the Full Audit launcher: its interruption status and 128 + each stop signal are listed
#     signal statuses (AUTH-020)
#   - bin/isedraf: every literal `exit N` is a reachable code
#   - each subcommand's codes are codes or signal statuses of the file
#   - README.md: every code in its exit table is reachable
#
# meta:type="gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""OUT-001: exit codes have one source."""
import copy
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "lib" / "isedraf" / "exitcodes.json"
W1A = {0, 2, 64, 70}
_HLD_ROW = re.compile(r"^\| `(\d+)` \|", re.M)
_README_ROW = re.compile(r"^\| (\d+) \|", re.M)
_SHELL_EXIT = re.compile(r"\bexit (\d+)\b")


def constants():
    sys.path.insert(0, str(ROOT / "lib"))
    from isedraf import exitcodes
    from isedraf.launcher import outer, reportunit, unit
    named = dict((k, v) for k, v in vars(exitcodes).items()
                 if k.isupper() and isinstance(v, int) and not isinstance(v, bool))
    interrupted = {outer.INTERRUPTED, unit.INTERRUPTED, reportunit.INTERRUPTED}
    stops = {128 + int(s) for s in outer.STOP_SIGNALS}
    return named, interrupted, stops


def check(data, named, interrupted, stops, hld, shell, readme):
    problems = []
    codes = data.get("codes") or []
    by_code = dict((c.get("code"), c) for c in codes)
    names = [c.get("name") for c in codes]
    if len(by_code) != len(codes) or len(set(names)) != len(names):
        problems.append("exitcodes.json repeats a code or a name")
    for c in codes:
        if set(c) != {"code", "name", "reachable", "source", "meaning"}:
            problems.append("code %r does not carry exactly code, name, reachable, source, meaning"
                            % c.get("code"))
    reachable = set(k for k, c in by_code.items() if c.get("reachable") is True)
    flat = []
    for p in data.get("precedence") or []:
        flat.extend(p if isinstance(p, list) else [p])
    if sorted(flat) != sorted(k for k in by_code if k < 64):
        problems.append("precedence does not order exactly the codes below 64")
    for name, value in sorted(named.items()):
        entry = by_code.get(value)
        if entry is None or entry.get("name") != name or value not in reachable:
            problems.append("exitcodes.py %s = %d is not a reachable code of that name" % (name, value))
    for value in sorted(reachable - set(named.values())):
        problems.append("reachable code %d has no constant in exitcodes.py" % value)
    for value in sorted(W1A - reachable):
        problems.append("SCOPE-077 code %d is not reachable" % value)
    for value in sorted(set(hld) - set(by_code)):
        problems.append("OUT-001 lists %d, which exitcodes.json does not define" % value)
    statuses = set(s.get("status") for s in (data.get("signal_statuses") or {}).get("statuses", []))
    for value in sorted((interrupted | stops) - statuses):
        problems.append("the launcher can return %d, which is not a listed signal status" % value)
    if statuses & set(by_code):
        problems.append("a signal status collides with an ISEDRAF code")
    for value in sorted(set(shell) - reachable):
        problems.append("bin/isedraf exits %d, which is not a reachable code" % value)
    for command, values in sorted((data.get("subcommands") or {}).items()):
        for value in values:
            if value not in reachable and value not in statuses:
                problems.append("%s lists %d, neither a reachable code nor a signal status"
                                % (command, value))
    for value in sorted(set(readme) - reachable):
        problems.append("README.md documents exit %d, which is not a reachable code" % value)
    return problems


def self_test(data):
    """Each failure shape fires and a consistent set passes, on a synthetic baseline derived
    from the file alone - never from the tree under check, so real drift is reported as drift."""
    statuses = [s["status"] for s in data["signal_statuses"]["statuses"]]
    named = dict((c["name"], c["code"]) for c in data["codes"] if c["reachable"])
    hld = [c["code"] for c in data["codes"] if c["code"] < 64]
    interrupted, stops = {143}, set(s for s in statuses if s < 255)

    def drop(code):
        d = copy.deepcopy(data)
        d["codes"] = [c for c in d["codes"] if c["code"] != code]
        return d

    def rename(code, name):
        d = copy.deepcopy(data)
        for c in d["codes"]:
            if c["code"] == code:
                c["name"] = name
        return d
    cases = [
        (data, named, [], [], False),
        (drop(66), named, [], [], True),                        # constant without a code
        (rename(67, "STATE_ROOT_UNWRITABLE"), named, [], [], True),
        (data, dict(named, NEW_CODE=71), [], [], True),         # code without the file
        (data, named, [99], [], True),                          # bin/isedraf drift
        (data, named, [], [3], True),                           # doc names an unreachable code
        (drop(70), named, [], [], True),                        # SCOPE-077 / constant
    ]
    wrong = [i for i, (d, n, s, r, bad) in enumerate(cases)
             if bool(check(d, n, interrupted, stops, hld, s, r)) != bad]
    return len(cases), wrong


def main():
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    named, interrupted, stops = constants()
    hld_text = (ROOT / "docs" / "architecture" / "ISEDRAF_HLD.md").read_text(encoding="utf-8")
    section = hld_text.split("## 8. Exit codes", 1)[1].split("\n## ", 1)[0]
    hld = [int(x) for x in _HLD_ROW.findall(section)]
    shell = [int(x) for x in _SHELL_EXIT.findall((ROOT / "bin" / "isedraf").read_text())]
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
    table = readme_text.split("| Exit | Meaning |", 1)
    readme = [int(x) for x in _README_ROW.findall(table[1].split("\n\n", 1)[0])] if len(table) == 2 else []
    cases, wrong = self_test(data)
    if wrong:
        print("  FAIL  exit-code self-test: case(s) %s judged wrongly" % wrong)
        return 1
    problems = check(data, named, interrupted, stops, hld, shell, readme)
    if problems:
        for p in problems:
            print("  FAIL  %s" % p)
        print("=== exit codes gate FAILED ===")
        return 1
    reachable = sorted(c["code"] for c in data["codes"] if c["reachable"])
    print("  OK    exit codes (OUT-001): %d defined, reachable %s, signal statuses %s; constants, "
          "OUT-001, SCOPE-077, launcher, bin/isedraf and README agree; self-test %d cases"
          % (len(data["codes"]), reachable,
             sorted(s["status"] for s in data["signal_statuses"]["statuses"]), cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
