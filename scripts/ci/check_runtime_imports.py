# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Every runtime import is on the explicit D-84 allowlist; anything else fails.
# Implements: D-84, GOV-002
#
# IQ-034. D-84 specifies an ALLOWLIST: runtime imports are restricted to an explicit list
# and anything else fails. What ran instead were two denylists - a grep of scripts/ for ten
# network and database modules, and the architecture gate's network markers. Under a
# denylist an unknown module is permitted; under D-84 it is refused. Those are different
# security models, and the repository implemented the weaker one while documenting the
# stronger.
#
#   allowlist absent, empty or malformed   FAIL (closed, never open)
#   import not on the allowlist            FAIL
#   forbidden module, even if allowlisted  FAIL
#   dynamic import (importlib, __import__) FAIL - it would bypass any list
#
# The permitted set is the file, never the running interpreter. Production code holds to a
# Python 3.6 floor (D-12) while CI runs something newer, so deriving "stdlib" from the
# interpreter at hand would silently permit modules the floor does not have.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================
"""usage: check_runtime_imports.py"""
import ast
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True).strip())
RUNTIME = ROOT / "lib" / "isedraf"
ALLOW = RUNTIME / "runtime-imports.allow"
FIRST_PARTY = "isedraf"
# D-84 and CLAUDE.md §2 Imports: refused whatever the allowlist says, so widening the list
# cannot quietly reopen a network or database path. Matched on the top-level name, and on
# the full dotted name for the one entry that is a submodule.
FORBIDDEN = {"socket", "ssl", "urllib", "http", "smtplib", "ftplib", "xmlrpc", "sqlite3",
             "dbm", "shelve", "asyncio", "importlib", "multiprocessing.connection"}
NAME = re.compile(r"^[a-z_][a-z0-9_]*$")

print("--- runtime import allowlist (D-84) ---")
FAIL = []


def bad(msg):
    FAIL.append(msg)
    print("  FAIL  %s" % msg)


def forbidden(dotted):
    parts = dotted.split(".")
    return any(".".join(parts[:i]) in FORBIDDEN for i in range(1, len(parts) + 1))


# --- 1. the allowlist: present, well-formed, sorted, unique, no forbidden entry ----------
allowed = []
if not ALLOW.is_file():
    bad("%s is missing: failing closed. D-84 permits nothing that is not listed"
        % ALLOW.relative_to(ROOT))
else:
    for n, raw in enumerate(ALLOW.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line != raw or not NAME.match(line):
            bad("%s:%d: malformed allowlist line %r - one top-level module name per line"
                % (ALLOW.relative_to(ROOT), n, raw))
            continue
        allowed.append(line)
    if not allowed and not FAIL:
        bad("%s lists no module: failing closed" % ALLOW.relative_to(ROOT))
    if allowed != sorted(allowed):
        bad("%s is not sorted, so an addition cannot be reviewed as one line"
            % ALLOW.relative_to(ROOT))
    for dup in sorted({m for m in allowed if allowed.count(m) > 1}):
        bad("%s lists %r more than once" % (ALLOW.relative_to(ROOT), dup))
    for m in allowed:
        if forbidden(m):
            bad("%s permits forbidden module %r (D-84); the allowlist cannot widen the "
                "network and database prohibition" % (ALLOW.relative_to(ROOT), m))
permitted = set(allowed)

# --- 2. every runtime import ------------------------------------------------------------
files = sorted(p for p in RUNTIME.rglob("*.py") if "__pycache__" not in p.parts)
used = set()
for path in files:
    rel = path.relative_to(ROOT)
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(rel))
    except (SyntaxError, UnicodeDecodeError) as exc:
        bad("%s cannot be parsed, so its imports cannot be checked: %s" % (rel, exc))
        continue
    for node in ast.walk(tree):
        # modules: what is imported. members: `from m import x` may name a submodule
        # (`from multiprocessing import connection`), so those are checked as forbidden too.
        modules, members = [], []
        if isinstance(node, ast.Import):
            modules = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules = [node.module]
            members = ["%s.%s" % (node.module, a.name) for a in node.names]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "__import__":
            bad("%s:%d: dynamic import via __import__ bypasses the allowlist"
                % (rel, node.lineno))
        for dotted in modules + members:
            top = dotted.split(".")[0]
            if top == FIRST_PARTY:
                continue
            if forbidden(dotted):
                bad("%s:%d: imports forbidden module %r (D-84)" % (rel, node.lineno, dotted))
            elif dotted in modules and top not in permitted:
                bad("%s:%d: imports %r, which is not in the D-84 allowlist"
                    % (rel, node.lineno, top))
            used.add(top)

unused = sorted(permitted - used)
if unused:
    print("  NOTE  allowlisted but not imported: %s. Permitted, not required; remove "
          "entries the runtime no longer needs." % ", ".join(unused))

if FAIL:
    print("=== runtime import allowlist FAILED ===")
    sys.exit(1)
print("  OK    %d runtime files: every import on the %d-module D-84 allowlist, none forbidden,"
      % (len(files), len(permitted)))
print("        no dynamic import")
