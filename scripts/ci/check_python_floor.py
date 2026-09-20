# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Hold the production package to the declared runtime Python floor.
# Implements: D-12, GOV-001, GOV-002
#
# The floor is worth nothing as a sentence. Without this gate, someone writes
# `subprocess.run(..., capture_output=True)` - Python 3.7+ - and EL8 breaks months later,
# on a customer's host, with no test having failed.
#
# The restriction applies ONLY to code that runs on a target host. scripts/ and tests/
# never do, and are deliberately left free to use a newer interpreter.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git"
# =============================================================================

"""Syntax is checked by the grammar itself; APIs by a named list with versions."""
import ast
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())

# Code that runs ON A TARGET HOST. Nothing else is constrained.
RUNTIME_PATHS = ["lib/isedraf", "scripts/compat"]
FLOOR = (3, 6)

# Library surface newer than the floor. ast.parse(feature_version=...) catches SYNTAX
# exactly; these are the APIs it cannot see, each with the version that introduced it.
NEWER_API = [
    (r"\bcapture_output\s*=", "subprocess capture_output=", "3.7"),
    (r"subprocess\.[a-z_]+\([^)]*\btext\s*=", "subprocess text=", "3.7"),
    (r"\bimport\s+dataclasses|\bfrom\s+dataclasses\b|@dataclass", "dataclasses", "3.7"),
    (r"\bfrom\s+__future__\s+import\s+annotations", "PEP 563 annotations", "3.7"),
    (r"\bimportlib\.metadata\b|\bfrom\s+importlib\s+import\s+metadata", "importlib.metadata", "3.8"),
    (r"\bcached_property\b", "functools.cached_property", "3.8"),
    (r"\btyping\.Protocol\b|\bfrom\s+typing\s+import\s+[^\n]*\bProtocol\b", "typing.Protocol", "3.8"),
    (r"\.removeprefix\(|\.removesuffix\(", "str.removeprefix/removesuffix", "3.9"),
    (r"\bimport\s+zoneinfo|\bfrom\s+zoneinfo\b", "zoneinfo", "3.9"),
    (r"\bimport\s+graphlib|\bfrom\s+graphlib\b", "graphlib", "3.9"),
    (r"\bmath\.lcm\b|\bmath\.nextafter\b", "math.lcm/nextafter", "3.9"),
    (r"\bint\.bit_count\b|\.bit_count\(\)", "int.bit_count", "3.10"),
    (r"\bzip\([^)]*\bstrict\s*=", "zip(strict=)", "3.10"),
    (r"\bimport\s+tomllib|\bfrom\s+tomllib\b", "tomllib", "3.11"),
    (r"\bdatetime\.UTC\b", "datetime.UTC", "3.11"),
    (r"\bExceptionGroup\b|\bexcept\*", "exception groups", "3.11"),
    (r"\bitertools\.batched\b", "itertools.batched", "3.12"),
    # PEP 585 / PEP 604 in annotations, which fail at runtime on 3.6, not merely in type
    # checking, because annotations are evaluated.
    (r":\s*(list|dict|tuple|set|frozenset|type)\[", "PEP 585 builtin generics", "3.9"),
    (r"->\s*(list|dict|tuple|set|frozenset|type)\[", "PEP 585 builtin generics", "3.9"),
    (r":\s*[A-Za-z_][A-Za-z0-9_.]*\s*\|\s*None\b", "PEP 604 unions", "3.10"),
]

failures = []
scanned = 0

for base in RUNTIME_PATHS:
    directory = ROOT / base
    if not directory.is_dir():
        failures.append("%s: declared runtime path does not exist" % base)
        continue
    for path in sorted(directory.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        scanned += 1
        src = path.read_text(encoding="utf-8")
        # Syntax, decided by the grammar rather than by a pattern list.
        try:
            ast.parse(src, filename=rel, feature_version=FLOOR)
        except SyntaxError as exc:
            failures.append("%s:%s: syntax is newer than Python %d.%d — %s"
                            % (rel, exc.lineno, FLOOR[0], FLOOR[1], exc.msg))
        except ValueError as exc:
            failures.append("%s: could not be parsed at the floor: %s" % (rel, exc))
        # APIs the grammar cannot see.
        for pattern, name, version in NEWER_API:
            for m in re.finditer(pattern, src):
                if "floor:allow" in src[src.rfind("\n", 0, m.start()) + 1:
                                       (src.find("\n", m.start()) + 1) or len(src)]:
                    continue
                line = src[:m.start()].count("\n") + 1
                failures.append("%s:%d: %s requires Python %s, the runtime floor is %d.%d"
                                % (rel, line, name, version, FLOOR[0], FLOOR[1]))

if scanned == 0:
    failures.append("the gate scanned no files — scope defect, refusing to report a pass")

if failures:
    print("=== production Python floor FAILED ===", file=sys.stderr)
    for f in sorted(set(failures)):
        print("  FAIL  %s" % f, file=sys.stderr)
    print("  Production code runs on target hosts and is held to Python %d.%d (D-12)."
          % FLOOR, file=sys.stderr)
    print("  scripts/ and tests/ are NOT constrained: they never run on a target host.",
          file=sys.stderr)
    sys.exit(1)
print("  OK    %d runtime files hold to the Python %d.%d floor (%s)"
      % (scanned, FLOOR[0], FLOOR[1], ", ".join(RUNTIME_PATHS)))
