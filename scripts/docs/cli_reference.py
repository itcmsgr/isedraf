#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Generate docs/reference/CLI.md from the command table (lib/isedraf/commands.py).
# Implements: D-129, D-89
#
# The command reference is the same text `isedraf --help` and `isedraf <command> --help`
# print, rendered from the same table, so the reference and the installed help cannot
# disagree (register item H6). Hand edits are lost on the next generate and fail `check`.
#
# meta:type="generator"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="docs/reference/CLI.md"
# meta:binaries="python3"
# =============================================================================
"""`generate` writes the page; `check` fails when the committed page is stale."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = ROOT / "docs" / "reference" / "CLI.md"
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import commands  # noqa: E402  (after the path insert, by design)

HEADER = """<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/commands.py
     Regenerate: python3 scripts/docs/cli_reference.py generate
     `make check` fails when this file and the command table disagree. -->

# Command reference

**GENERATED FILE — DO NOT EDIT MANUALLY**

This is the help the installed `isedraf` prints, rendered from the same command table. Exit
codes are defined once in `lib/isedraf/exitcodes.json`; their full meanings are in the README.
"""


def render():
    forms = ["`isedraf %s`" % " ".join(f) if f else "`isedraf`" for f in commands.help_forms()]
    parts = [HEADER, "## Start page\n",
             "`isedraf` with no arguments, and `isedraf help`:\n",
             "```text", commands.start_page().rstrip("\n"), "```\n",
             "## Help forms\n",
             "Accepted on the user route and, before anything else is checked, under sudo or "
             "root (the same answer, exit 0; they read no evidence, open no store and start "
             "nothing). `isedraf help` naming anything else exits 64 and lists the valid "
             "commands.\n",
             ", ".join(forms) + "\n",
             "## Overview\n", "```text", commands.overview().rstrip("\n"), "```\n"]
    for group in commands.GROUPS:
        members = [r for r in commands.COMMANDS if r["group"] == group]
        if not members:
            continue
        parts.append("## %s\n" % group)
        for record in members:
            parts.extend(["### `isedraf %s`\n" % commands.name(record), "```text",
                          commands.command_help(record).rstrip("\n"), "```\n"])
    return "\n".join(parts)


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    text = render()
    if action == "generate":
        TARGET.write_text(text)
        print("  generated %s" % TARGET.relative_to(ROOT))
        return 0
    if action == "check":
        current = TARGET.read_text() if TARGET.exists() else ""
        if current != text:
            print("=== docs/reference/CLI.md is stale ===")
            print("  run: python3 scripts/docs/cli_reference.py generate")
            return 1
        print("  OK    docs/reference/CLI.md renders the command table")
        return 0
    print("usage: cli_reference.py generate|check", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main())
