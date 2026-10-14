#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Hold the fixed privileged operation registry to the Full Audit authority model.
# Implements: D-123, D-124, D-118, D-122, AUTH-025, AUTH-026, AUTH-027, AUTH-028
#
# What it refuses, before any privileged code exists:
#   - an operation identifier that is a command string rather than a declared contract;
#   - an operation that takes a caller input, a shell, or CAP_SYS_ADMIN;
#   - the supervisor acquisition mode admitted into coverage.py while nothing produces it;
#   - an IMPLEMENTED operation while the launcher it would run under does not exist;
#   - the authority document and the registry disagreeing;
#   - a supervisor code contract that differs from its registry entry in any mirrored field,
#     status included, or that has no registry entry;
#   - a supervisor module that imports anything but the standard library and
#     isedraf.supervisor (the supervisor is a privilege transport, not an intelligence layer);
#   - an IMPLEMENTED operation that the section it serves never requests by its exact
#     versioned identifier (AUTH-024: IMPLEMENTED means reachable in production);
#   - an admission record that breaks AUTH-025: more than one IMPLEMENTED operation that is not
#     validated, an unvalidated one that is not next_candidate, a next_candidate that is not the
#     first unvalidated operation in the frozen order, or a validated record that is not a
#     prefix of that order or names an operation that is not IMPLEMENTED;
#   - in release mode (--release), any IMPLEMENTED operation that is not validated, and in
#     every mode a release workflow that does not run release mode before it builds (AUTH-025);
#   - a capability candidate that is also excluded, CAP_KILL or CAP_SYS_ADMIN as a candidate, or
#     a capability named in lib/isedraf/launcher/ that is not a candidate (AUTH-011, AUTH-026);
#   - a capability measured not required (CAP_CHOWN) back among the candidates, or a measured
#     route capability that is not a candidate (AUTH-027);
#   - a REQUIRED set that differs from the measured route, or a launcher bounding set that is
#     not exactly the REQUIRED set (AUTH-028).
#
# Development tooling only: standard library plus the engine's own pure modules.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================

"""Fixed privileged operations: contract shape, invariants and the admission rule."""
import ast
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                                            universal_newlines=True).strip())
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import coverage   # noqa: E402
from isedraf.supervisor import contracts   # noqa: E402

SPEC = ROOT / "docs" / "architecture" / "FULL_AUDIT_AUTHORITY_MODEL.md"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-candidate.yml"
RELEASE_STEP = "python3 scripts/ci/check_privileged_operations.py --release"
REGISTRY = ROOT / "scripts" / "ci" / "privileged_operations.json"
LAUNCHER = ROOT / "lib" / "isedraf" / "launcher"
SUPERVISOR_PKG = ROOT / "lib" / "isedraf" / "supervisor"
FIELDS = {"operation_id", "purpose", "serves", "targets", "privilege_basis", "fixed_executable",
          "fixed_argv", "caller_inputs", "output_bound_bytes", "status", "env_policy",
          "cwd_policy", "stdin_policy", "timeout_seconds", "exit_status_policy"}
EXEC_POLICY = {"env_policy": "CLEAN_FIXED", "cwd_policy": "ROOT_DIR", "stdin_policy": "DEVNULL",
               "exit_status_policy": "ZERO_ONLY_SUCCEEDS"}
SHELLISH = re.compile(r"[;&|`$<>(){}\\*?!\s]")
SUPERVISOR = "SUPERVISOR_FIXED_OPERATION"


def vocabulary():
    text = SPEC.read_text(encoding="utf-8")
    match = re.search(r"```json full-audit-authority-vocabulary\n(.*?)\n```", text, re.S)
    if not match:
        sys.exit("FAIL  %s carries no full-audit-authority-vocabulary block" % SPEC)
    return json.loads(match.group(1))


def admission_record():
    """The owner-controlled admission block of AUTH-025, read from the frozen document."""
    text = SPEC.read_text(encoding="utf-8")
    match = re.search(r"```json full-audit-operation-admission\n(.*?)\n```", text, re.S)
    if not match:
        sys.exit("FAIL  %s carries no full-audit-operation-admission block" % SPEC)
    return json.loads(match.group(1))


def check(registry, vocab, modes, launcher_exists):
    problems = []
    pattern = re.compile(vocab["operation_id_pattern"])
    ops = registry.get("operations", [])
    ids = [o.get("operation_id") for o in ops]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        problems.append("operations are not sorted and unique by operation_id")
    for op in ops:
        oid = op.get("operation_id")
        if set(op) != FIELDS:
            problems.append("%s: fields %s, expected %s" % (oid, sorted(op), sorted(FIELDS)))
            continue
        if not isinstance(oid, str) or not pattern.match(oid):
            problems.append("%r is not a fixed operation identifier (AUTH-008); a command string "
                            "is never an operation_id" % (oid,))
        if op["caller_inputs"] != []:
            problems.append("%s takes caller inputs %r (AUTH-003)" % (oid, op["caller_inputs"]))
        if op["status"] not in vocab["operation_status"]:
            problems.append("%s status %r" % (oid, op["status"]))
        basis = op["privilege_basis"]
        if not isinstance(basis, str) or not basis or any(
                cap in basis for cap in vocab["forbidden_privilege_basis"]):
            problems.append("%s privilege basis %r is empty or forbidden" % (oid, basis))
        exe, argv = op["fixed_executable"], op["fixed_argv"]
        if exe is None:
            if argv != []:
                problems.append("%s has fixed_argv without a fixed_executable" % oid)
        elif not (isinstance(exe, str) and exe.startswith("/") and not SHELLISH.search(exe)):
            problems.append("%s fixed_executable %r is not a constant absolute path" % (oid, exe))
        if exe is not None and pathlib.PurePosixPath(exe).name in ("sh", "bash", "dash", "env"):
            problems.append("%s runs a shell or an interpreter launcher (AUTH-003)" % oid)
        if not isinstance(argv, list) or not all(
                isinstance(a, str) and a and not SHELLISH.search(a) for a in argv):
            problems.append("%s fixed_argv %r is not a list of constant arguments" % (oid, argv))
        bound = op["output_bound_bytes"]
        if not isinstance(bound, int) or not 0 < bound <= 16 * 1024 * 1024:
            problems.append("%s output bound %r is not a positive bound of at most 16 MiB"
                            % (oid, bound))
        if not op["targets"] or not isinstance(op["targets"], list):
            problems.append("%s declares no targets" % oid)
        for key, required in sorted(EXEC_POLICY.items()):
            want = required if exe is not None else "NOT_APPLICABLE"
            if op[key] not in vocab[key] or op[key] != want:
                problems.append("%s %s is %r; AUTH-014 requires %r" % (oid, key, op[key], want))
        timeout = op["timeout_seconds"]
        if not isinstance(timeout, int) or not 0 < timeout <= vocab["timeout_seconds_max"]:
            problems.append("%s timeout %r is not 1..%d seconds (AUTH-014)"
                            % (oid, timeout, vocab["timeout_seconds_max"]))
        if op["status"] == "IMPLEMENTED" and not launcher_exists:
            problems.append("%s is IMPLEMENTED but no launcher exists (design only, D-123)" % oid)

    implemented = [o for o in ops if o.get("status") == "IMPLEMENTED"]
    defined = set(vocab["acquisition_mode_defined"])
    for mode in modes:
        if mode not in defined:
            problems.append("coverage.MODES has %r, which the authority model does not define"
                            % mode)
    if SUPERVISOR in modes and not implemented:
        problems.append("coverage.MODES admits %s while no operation is IMPLEMENTED "
                        "(AUTH-007: a value is admitted only when a mechanism produces it)"
                        % SUPERVISOR)
    if implemented and SUPERVISOR not in modes:
        problems.append("operations are IMPLEMENTED but coverage.MODES does not admit %s"
                        % SUPERVISOR)
    output = set(vocab["supervisor_output_fields"])
    if output != {"operation_id", "status", "bytes", "stderr_bytes", "status_metadata"}:
        problems.append("supervisor output fields %s are not the AUTH-015 set" % sorted(output))
    for field in sorted(output & set(vocab["forbidden_output_fields"])):
        problems.append("supervisor output carries %r, which is engine semantics (AUTH-015)"
                        % field)
    if SUPERVISOR not in vocab["acquisition_mode_defined"]:
        problems.append("the authority model does not define %s" % SUPERVISOR)
    return problems


def check_code_contracts(registry, code):
    """Each supervisor contract equals its registry entry; IMPLEMENTED needs a contract."""
    problems = []
    entries = dict((o.get("operation_id"), o) for o in registry.get("operations", []))
    for oid, contract in sorted(code.items()):
        entry = entries.get(oid)
        if entry is None:
            problems.append("supervisor contract %s has no registry entry (AUTH-004)" % oid)
            continue
        for field in contracts.MIRRORED:
            if contract.get(field) != entry.get(field):
                problems.append("supervisor contract %s %s is %r; the registry has %r"
                                % (oid, field, contract.get(field), entry.get(field)))
        performer = contract.get("performer")
        if performer == contracts.PERFORM_READ_REGULAR_FILE:
            targets = contract.get("targets") or []
            if (contract.get("fixed_executable") is not None or len(targets) != 1
                    or not targets[0].startswith("/") or SHELLISH.search(targets[0])
                    or "<" in targets[0]):
                problems.append("supervisor contract %s reads a file but does not name exactly "
                                "one constant absolute target" % oid)
        elif performer == contracts.PERFORM_READ_FIXED_TREE:
            # AUTH-029: one root file and one directory, both constant absolute paths, no
            # executable, and bounds on each member and on the number of entries.
            paths = [contract.get("root_file"), contract.get("directory")]
            if (contract.get("fixed_executable") is not None or not all(
                    isinstance(p, str) and p.startswith("/") and not SHELLISH.search(p)
                    and "<" not in p for p in paths)
                    or not isinstance(contract.get("member_bound_bytes"), int)
                    or not 0 < contract["member_bound_bytes"] <= contract["output_bound_bytes"]
                    or not isinstance(contract.get("max_entries"), int)
                    or not 0 < contract["max_entries"] <= 4096):
                problems.append("supervisor contract %s reads a fixed tree but does not name a "
                                "constant root file and directory with member and entry bounds "
                                "(AUTH-029)" % oid)
        elif performer == contracts.PERFORM_FIXED_EXECUTABLE:
            if contract.get("fixed_executable") is None:
                problems.append("supervisor contract %s runs no fixed executable" % oid)
        else:
            problems.append("supervisor contract %s has unknown performer %r" % (oid, performer))
    for oid, entry in sorted(entries.items()):
        if entry.get("status") == "IMPLEMENTED" and oid not in code:
            problems.append("%s is IMPLEMENTED but the supervisor has no contract for it" % oid)
    return problems


def requested_by_section(operation_id, section):
    """True when the serving section's code names the exact identifier (AUTH-024 item 3)."""
    package = ROOT / "lib" / "isedraf" / section
    for path in sorted(package.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and node.value == operation_id:
                return True
    return False


def check_production_reachable(registry, requested=requested_by_section):
    """AUTH-024 for the IMPLEMENTED entries."""
    problems = []
    implemented = [o for o in registry.get("operations", []) if o.get("status") == "IMPLEMENTED"]
    for op in implemented:
        if not requested(op["operation_id"], op["serves"]):
            problems.append("%s is IMPLEMENTED but lib/isedraf/%s never requests it by its exact "
                            "identifier (AUTH-024: IMPLEMENTED means reachable in production)"
                            % (op["operation_id"], op["serves"]))
    return problems


def check_admission(registry, admission, release=False):
    """AUTH-025: one newly admitted operation at a time, validated by the owner in order."""
    problems = []
    order = admission.get("order", [])
    validated = admission.get("validated", [])
    candidate = admission.get("next_candidate")
    if set(admission) != {"order", "validated", "next_candidate"}:
        problems.append("the admission block has keys %s, expected order, validated and "
                        "next_candidate (AUTH-025)" % sorted(admission))
    status = dict((o.get("operation_id"), o.get("status"))
                  for o in registry.get("operations", []))
    if not order or len(set(order)) != len(order):
        problems.append("the admission order is empty or names an operation twice (AUTH-025)")
    for oid in order:
        if oid not in status:
            problems.append("%s is in the admission order but not registered (AUTH-025)" % oid)
        elif status[oid] == "DESIGN_OPEN":
            problems.append("%s is DESIGN_OPEN and cannot be in the admission order (AUTH-025)"
                            % oid)
    if validated != order[:len(validated)]:
        problems.append("validated %s is not a prefix of the admission order; operations are "
                        "validated in order (AUTH-025)" % validated)
    for oid in validated:
        if status.get(oid) != "IMPLEMENTED":
            problems.append("%s is recorded validated but is not IMPLEMENTED (AUTH-025)" % oid)
    first_unvalidated = next((o for o in order if o not in validated), None)
    if candidate != first_unvalidated:
        problems.append("next_candidate %s is not the first unvalidated operation in the order, "
                        "%s (AUTH-025)" % (candidate, first_unvalidated))
    # Every unvalidated IMPLEMENTED operation must be next_candidate, so at most one can be:
    # the "at most one" invariant is this rule, not a second check that could never fire alone.
    unvalidated = sorted(o for o, st in status.items()
                         if st == "IMPLEMENTED" and o not in validated)
    for oid in unvalidated:
        if oid != candidate:
            problems.append("%s is IMPLEMENTED out of turn; only next_candidate %s may be "
                            "IMPLEMENTED before it is validated (AUTH-025)" % (oid, candidate))
    if release:
        for oid in unvalidated:
            problems.append("release mode: %s is IMPLEMENTED but not validated; no release "
                            "includes it (AUTH-025)" % oid)
    return problems


def check_release_workflow(path=RELEASE_WORKFLOW):
    """The release build runs release mode first, so condition 9 is enforced, not remembered."""
    if not path.exists():
        return ["%s does not exist; release mode would never run (AUTH-025)" % path.name]
    lines = path.read_text(encoding="utf-8").splitlines()
    runs = [i for i, l in enumerate(lines) if l.strip() == "run: " + RELEASE_STEP]
    builds = [i for i, l in enumerate(lines) if l.strip() == "run: bash packaging/build.sh"]
    if not runs or not builds or min(runs) > min(builds):
        return ["%s does not run '%s' before it builds packages (AUTH-025)"
                % (path.name, RELEASE_STEP)]
    return []


def admission_self_test():
    """Fixed cases on every run, so weakening a rule fails here even on a clean registry."""
    order = ["a_v1", "b_v1", "c_v1"]

    def refused(statuses, validated, candidate, release=False):
        registry = {"operations": [{"operation_id": o, "status": st}
                                   for o, st in sorted(statuses.items())]}
        return bool(check_admission(registry, {"order": order, "validated": validated,
                                               "next_candidate": candidate}, release))
    I, P = "IMPLEMENTED", "PLANNED"
    cases = [
        ("the next candidate under validation", {"a_v1": I, "b_v1": I, "c_v1": P},
         ["a_v1"], "b_v1", False, False),
        ("an operation out of turn", {"a_v1": I, "b_v1": P, "c_v1": I},
         ["a_v1"], "b_v1", False, True),
        ("two operations under validation", {"a_v1": I, "b_v1": I, "c_v1": I},
         ["a_v1"], "b_v1", False, True),
        ("a next_candidate that is not the first unvalidated operation",
         {"a_v1": I, "b_v1": P, "c_v1": P}, ["a_v1"], "c_v1", False, True),
        ("a validated record out of order", {"a_v1": P, "b_v1": I, "c_v1": P},
         ["b_v1"], "a_v1", False, True),
        ("a validated operation that is not IMPLEMENTED", {"a_v1": I, "b_v1": P, "c_v1": P},
         ["a_v1", "b_v1"], "c_v1", False, True),
        ("a release with an unvalidated operation", {"a_v1": I, "b_v1": I, "c_v1": P},
         ["a_v1"], "b_v1", True, True),
        ("a release with every IMPLEMENTED operation validated",
         {"a_v1": I, "b_v1": P, "c_v1": P}, ["a_v1"], "b_v1", True, False),
    ]
    problems = []
    for name, statuses, validated, candidate, release, expected in cases:
        if refused(statuses, validated, candidate, release) != expected:
            problems.append("admission self-test: %s was %s (AUTH-025)"
                            % (name, "accepted" if expected else "refused"))
    return problems, len(cases), sum(1 for c in cases if c[5])


def check_capabilities(vocab, launcher):
    """AUTH-011, AUTH-026: candidate is not required is not granted; some are never candidates."""
    problems = []
    candidates = set(vocab.get("capability_candidates", []))
    excluded = set(vocab.get("capability_excluded", []))
    if not candidates or not excluded:
        problems.append("the authority vocabulary declares no capability candidates or exclusions")
    for cap in sorted(candidates & excluded):
        problems.append("%s is both a capability candidate and excluded (AUTH-026)" % cap)
    not_required = set(vocab.get("capability_measured_not_required", []))
    for cap in sorted(candidates & not_required):
        problems.append("%s is a candidate although it was measured not required (AUTH-027)" % cap)
    if "CAP_CHOWN" not in not_required:
        problems.append("CAP_CHOWN is not recorded as measured not required (AUTH-027)")
    for cap in sorted(set(vocab.get("capability_measured_route", [])) - candidates):
        problems.append("measured route capability %s is not a candidate (AUTH-027)" % cap)
    required = set(vocab.get("capability_required", []))
    if not required or required != set(vocab.get("capability_measured_route", [])):
        problems.append("the REQUIRED capability set is empty or not the measured route (AUTH-028)")
    if launcher.is_dir():
        from isedraf.launcher import outer
        bounding = set(outer.CAPABILITY_BOUNDING_SET.split())
        if bounding != required:
            problems.append("the launcher's CapabilityBoundingSet %s is not exactly the REQUIRED "
                            "set %s (AUTH-028)" % (sorted(bounding), sorted(required)))
    for cap in ("CAP_KILL", "CAP_SYS_ADMIN", "CAP_AUDIT_CONTROL"):
        if cap not in excluded:
            problems.append("%s is not excluded (AUTH-011, AUTH-012, AUTH-026)" % cap)
    if launcher.is_dir():
        for path in sorted(launcher.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                for cap in re.findall(r"CAP_[A-Z_]+", node.value):
                    if cap not in candidates:
                        problems.append("%s names %s, which is not a capability candidate "
                                        "(AUTH-011, AUTH-026)" % (path.relative_to(ROOT), cap))
    return problems


def supervisor_imports(package):
    """Imports in the supervisor package outside the standard library and itself."""
    problems = []
    stdlib = set(getattr(sys, "stdlib_module_names", ())) or None
    for path in sorted(package.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] if node.level == 0 else ["<relative>"]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if name == "isedraf.supervisor" or name.startswith("isedraf.supervisor."):
                    continue
                if top == "isedraf" or name == "<relative>" or (
                        stdlib is not None and top not in stdlib):
                    problems.append("%s imports %s: the supervisor imports only the standard "
                                    "library and isedraf.supervisor (AUTH-006)"
                                    % (path.relative_to(ROOT) if ROOT in path.parents
                                       else path, name))
    return problems


def main():
    release = sys.argv[1:] == ["--release"]
    if sys.argv[1:] and not release:
        sys.exit("usage: check_privileged_operations.py [--release]")
    vocab = vocabulary()
    admission = admission_record()
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    problems = check(registry, vocab, list(coverage.MODES), LAUNCHER.is_dir())
    problems += check_code_contracts(registry, contracts.CONTRACTS)
    problems += supervisor_imports(SUPERVISOR_PKG)
    problems += check_production_reachable(registry)
    self_test, cases, refusals = admission_self_test()
    problems += self_test
    problems += check_admission(registry, admission, release)
    problems += check_release_workflow()
    problems += check_capabilities(vocab, LAUNCHER)
    for p in problems:
        print("  FAIL  %s" % p)
    if problems:
        print("=== privileged operations gate FAILED ===")
        return 1
    ops = registry["operations"]
    print("  OK    privileged operations: %d fixed contracts, no caller inputs, no shell, no "
          "CAP_SYS_ADMIN; %s admitted only while an operation is implemented (%d implemented); "
          "%d supervisor contract(s) equal the registry; supervisor imports stdlib only"
          % (len(ops), SUPERVISOR, len([o for o in ops if o["status"] == "IMPLEMENTED"]),
             len(contracts.CONTRACTS)))
    print("  OK    admission (AUTH-025): validated %s; next candidate %s; %s; self-test %d cases, "
          "%d refused" % (", ".join(admission["validated"]) or "none", admission["next_candidate"],
                          "release mode: every IMPLEMENTED operation validated" if release
                          else "release workflow runs release mode before it builds",
                          cases, refusals))
    return 0


if __name__ == "__main__":
    sys.exit(main())
