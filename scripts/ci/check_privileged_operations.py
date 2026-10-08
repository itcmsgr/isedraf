#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Hold the fixed privileged operation registry to the Full Audit authority model.
# Implements: D-123, D-118, D-122
#
# What it refuses, before any privileged code exists:
#   - an operation identifier that is a command string rather than a declared contract;
#   - an operation that takes a caller input, a shell, or CAP_SYS_ADMIN;
#   - the supervisor acquisition mode admitted into coverage.py while nothing produces it;
#   - an IMPLEMENTED operation while the launcher it would run under does not exist;
#   - the authority document and the registry disagreeing.
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
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                                            universal_newlines=True).strip())
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import coverage   # noqa: E402

SPEC = ROOT / "docs" / "architecture" / "FULL_AUDIT_AUTHORITY_MODEL.md"
REGISTRY = ROOT / "scripts" / "ci" / "privileged_operations.json"
LAUNCHER = ROOT / "lib" / "isedraf" / "launcher"
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


def main():
    vocab = vocabulary()
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    problems = check(registry, vocab, list(coverage.MODES), LAUNCHER.is_dir())
    for p in problems:
        print("  FAIL  %s" % p)
    if problems:
        print("=== privileged operations gate FAILED ===")
        return 1
    ops = registry["operations"]
    print("  OK    privileged operations: %d fixed contracts, no caller inputs, no shell, no "
          "CAP_SYS_ADMIN; %s reserved until an operation is implemented (%d implemented)"
          % (len(ops), SUPERVISOR, len([o for o in ops if o["status"] == "IMPLEMENTED"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
