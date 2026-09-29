# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Where the code actually touches the world, from the AST rather than from names.
# Implements: GOV-001
#
# meta:type="analysis"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="docs/development/architecture/generated"
# meta:binaries="git,python3"
"""Filesystem, subprocess, network, clock and randomness, per module and function."""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as C                                          # noqa: E402

#: The artifacts this generator owns. The freshness gate reads this rather
#: than keeping a second list that could disagree with reality.
OUTPUTS = ('07_io_side_effects.csv',)

EFFECTS = {
    "FS_READ": ("open", "read", "listdir", "lstat", "stat", "fstat", "readlink",
                "scandir", "read_file", "read_lines", "read_file_lossless"),
    "FS_WRITE": ("write", "mkdir", "makedirs", "rename", "unlink", "remove", "rmdir",
                 "chmod", "symlink", "fsync", "mkstemp", "mkdtemp"),
    "SUBPROCESS": ("Popen", "run", "check_output", "call", "system", "execv", "execve"),
    "NETWORK": ("socket", "urlopen", "connect", "getaddrinfo", "create_connection",
                "HTTPConnection", "gethostbyname"),
    "CLOCK": ("time", "now", "utcnow", "monotonic", "perf_counter"),
    "RANDOM": ("random", "urandom", "choice", "shuffle", "token_bytes"),
    "ENVIRONMENT": ("environ", "getenv", "putenv"),
}

# `run` is subprocess only in hostio; elsewhere it is an ordinary method name, and
# `time`/`stat` collide with module names. Effects are attributed from attribute/callable
# usage, then the report is read by a human - this map is an instrument, not a verdict.
AMBIGUOUS = {"run", "time", "stat", "random", "write", "read", "call", "connect"}


def _out_dir():
    """Where to write. The gate points this at a temp dir and diffs."""
    target = os.path.join(C.ROOT, "docs/development/architecture/generated")
    for index, arg in enumerate(sys.argv):
        if arg == "--out" and index + 1 < len(sys.argv):
            target = sys.argv[index + 1]
    if not os.path.isdir(target):
        os.makedirs(target)
    return target


def main():
    rows = []
    for relative in C.python_files("lib", "scripts"):
        tree = C.parse(relative)
        module = C.module_name(relative)
        for function in C.functions(tree):
            names = C.called_names(function)
            for effect, markers in EFFECTS.items():
                hits = sorted(names & set(markers))
                if hits:
                    rows.append({
                        "module": module, "file": relative,
                        "function": function.name, "effect": effect,
                        "markers": " ".join(hits),
                        "ambiguous": "yes" if set(hits) <= AMBIGUOUS else "no",
                    })
    out = os.path.join(_out_dir(), "07_io_side_effects.csv")
    with open(out, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["module", "file", "function",
                                                    "effect", "markers", "ambiguous"])
        writer.writeheader()
        for row in sorted(rows, key=lambda r: (r["module"], r["function"], r["effect"])):
            writer.writerow(row)

    print("  %d effect sites recorded" % len(rows))
    print()
    print("  === host I/O inside lib/isedraf, by module ===")
    lib = [r for r in rows if r["file"].startswith("lib/") and r["ambiguous"] == "no"]
    by_module = {}
    for row in lib:
        by_module.setdefault(row["module"], set()).add(row["effect"])
    for module in sorted(by_module):
        print("    %-42s %s" % (module, " ".join(sorted(by_module[module]))))
    print()
    print("  === NETWORK anywhere in lib/isedraf ===")
    net = [r for r in rows if r["file"].startswith("lib/") and r["effect"] == "NETWORK"]
    print("    %s" % (net or "NONE"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
