#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Generate packaging/completion/isedraf.bash from the command table and the packaged
#          native catalog.
# Implements: D-129
#
# Register item C1. The completion is static: every command, option and criterion ID is
# written into the file when it is generated, from lib/isedraf/commands.py (the table the
# parser and the help are built from) and lib/isedraf/catalog/native_controls.json (the
# catalog the same package installs). At Tab time it runs no isedraf, reads no evidence
# store and never offers a snapshot ID. `check` fails when the committed file is stale, so
# the completion cannot drift from the parser (register item H6).
#
# meta:type="generator"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="packaging/completion/isedraf.bash"
# meta:binaries="python3"
# =============================================================================
"""`generate` writes the completion file; `check` fails when it is stale."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = ROOT / "packaging" / "completion" / "isedraf.bash"
CATALOG = ROOT / "lib" / "isedraf" / "catalog" / "native_controls.json"
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import commands  # noqa: E402  (after the path insert, by design)

HEADER = """\
# shellcheck shell=bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Bash completion for isedraf. GENERATED FILE - DO NOT EDIT MANUALLY.
#          Source: lib/isedraf/commands.py and lib/isedraf/catalog/native_controls.json
#          Regenerate: python3 scripts/docs/bash_completion.py generate
# Implements: D-129
#
# Static: completes commands, each command's own options, the installed criterion IDs and,
# after `help`, command names. It runs no isedraf, reads no evidence store and never offers
# a snapshot ID. Only path options (--root, --profile, --source) complete file or directory
# names. It uses bash builtins only, so it also works when sourced without the
# bash-completion package.
#
# meta:type="completion"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="bash"
# =============================================================================
"""


def _form(record):
    return " ".join(record["path"])


def _reply(kind, top=()):
    """The bash lines that fill COMPREPLY for one completion kind."""
    if kind == commands.COMPLETE_COMMAND:
        return ['_isedraf_words "%s"' % " ".join(top)]
    if kind == commands.COMPLETE_DIR:
        return ['_isedraf_paths -d']
    if kind == commands.COMPLETE_FILE:
        return ['_isedraf_paths -f']
    if kind == commands.COMPLETE_CRITERION:
        return ['_isedraf_words "$_isedraf_criteria"']
    # COMPLETE_NONE and COMPLETE_SNAPSHOT: nothing is offered.
    return [':']


def render():
    ids = [c["criterion_id"] for c in json.loads(CATALOG.read_text())["criteria"]]
    top, groups = [], {}
    for record in commands.COMMANDS:
        first = record["path"][0]
        if first not in top:
            top.append(first)
        if len(record["path"]) > 1:
            groups.setdefault(first, []).append(record["path"][1])
    value_options = [(r, o) for r in commands.COMMANDS for o in r["options"] if o["metavar"]]

    out = [HEADER]
    out.append("_isedraf_criteria='%s'" % " ".join(ids))
    out.append("")
    out.append("_isedraf_words() {")
    out.append('    local w')
    out.append('    while IFS= read -r w; do COMPREPLY+=("$w"); done \\')
    out.append('        < <(compgen -W "$1" -- "${COMP_WORDS[COMP_CWORD]:-}")')
    out.append("}")
    out.append("")
    out.append("_isedraf_paths() {")
    out.append('    local w')
    out.append('    compopt -o filenames 2>/dev/null')
    out.append('    while IFS= read -r w; do COMPREPLY+=("$w"); done \\')
    out.append('        < <(compgen "$1" -- "${COMP_WORDS[COMP_CWORD]:-}")')
    out.append("}")
    out.append("")
    out.append("_isedraf() {")
    out.append('    local cur prev w form="" i=1 nargs=0')
    out.append('    COMPREPLY=()')
    out.append('    cur="${COMP_WORDS[COMP_CWORD]:-}"')
    out.append('    prev=""')
    out.append('    [ "$COMP_CWORD" -gt 0 ] && prev="${COMP_WORDS[COMP_CWORD-1]:-}"')
    out.append('    # The command form is read from the words before the cursor; an option that')
    out.append('    # takes a value consumes the next word.')
    out.append('    while [ "$i" -lt "$COMP_CWORD" ]; do')
    out.append('        w="${COMP_WORDS[i]:-}"')
    out.append('        case "$form" in')
    out.append('            "")')
    out.append('                case "$w" in -*) ;; *) form="$w" ;; esac ;;')
    for group, actions in groups.items():
        out.append('            %s)' % group)
        out.append('                case "$w" in -*) ;; *) form="%s $w" ;; esac ;;' % group)
    out.append('            *)')
    out.append('                case "$form:$w" in')
    if value_options:
        out.append('                    %s) i=$((i + 1)) ;;'
                   % "|".join('"%s:%s"' % (_form(r), o["flag"]) for r, o in value_options))
    out.append('                    *:-*) ;;')
    out.append('                    *) nargs=$((nargs + 1)) ;;')
    out.append('                esac ;;')
    out.append('        esac')
    out.append('        i=$((i + 1))')
    out.append('    done')
    if value_options:
        out.append('    case "$form:$prev" in')
        for r, o in value_options:
            out.append('        "%s:%s") %s; return 0 ;;'
                       % (_form(r), o["flag"], "; ".join(_reply(o["complete"]))))
        out.append('    esac')
    out.append('    case "$form" in')
    out.append('        "")')
    out.append('            case "$cur" in')
    out.append('                -*) _isedraf_words "--help --version" ;;')
    out.append('                *) _isedraf_words "%s" ;;' % " ".join(top))
    out.append('            esac ;;')
    for group, actions in groups.items():
        out.append('        %s)' % group)
        out.append('            _isedraf_words "%s --help" ;;' % " ".join(actions))
    for record in commands.COMMANDS:
        options = " ".join(["--help"] + [o["flag"] for o in record["options"]])
        out.append('        "%s")' % _form(record))
        out.append('            case "$cur" in')
        out.append('                -*) _isedraf_words "%s" ;;' % options)
        if record["arguments"]:
            out.append('                *)')
            out.append('                    if [ "$nargs" -eq 0 ]; then %s; fi ;;'
                       % "; ".join(_reply(record["arguments"][0]["complete"], top)))
        else:
            out.append('                *) _isedraf_words "%s" ;;' % options)
        out.append('            esac ;;')
    out.append('    esac')
    out.append('    return 0')
    out.append("}")
    out.append("")
    out.append("complete -F _isedraf isedraf")
    return "\n".join(out) + "\n"


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    text = render()
    if action == "generate":
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        TARGET.write_text(text)
        print("  generated %s" % TARGET.relative_to(ROOT))
        return 0
    if action == "check":
        current = TARGET.read_text() if TARGET.exists() else ""
        if current != text:
            print("=== packaging/completion/isedraf.bash is stale ===")
            print("  run: python3 scripts/docs/bash_completion.py generate")
            return 1
        print("  OK    bash completion renders the command table and the installed catalog")
        return 0
    print("usage: bash_completion.py generate|check", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main())
