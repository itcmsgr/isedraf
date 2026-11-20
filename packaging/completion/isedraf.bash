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

_isedraf_criteria='ISE-ACCOUNT-001 ISE-ACCOUNT-002 ISE-ACCOUNT-003 ISE-ACCOUNT-004 ISE-SSH-001 ISE-ACCOUNT-005 ISE-AUTH-001 ISE-SSH-002'

_isedraf_words() {
    local w
    while IFS= read -r w; do COMPREPLY+=("$w"); done \
        < <(compgen -W "$1" -- "${COMP_WORDS[COMP_CWORD]:-}")
}

_isedraf_paths() {
    local w
    compopt -o filenames 2>/dev/null
    while IFS= read -r w; do COMPREPLY+=("$w"); done \
        < <(compgen "$1" -- "${COMP_WORDS[COMP_CWORD]:-}")
}

_isedraf() {
    local cur prev w form="" i=1 nargs=0
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]:-}"
    prev=""
    [ "$COMP_CWORD" -gt 0 ] && prev="${COMP_WORDS[COMP_CWORD-1]:-}"
    # The command form is read from the words before the cursor; an option that
    # takes a value consumes the next word.
    while [ "$i" -lt "$COMP_CWORD" ]; do
        w="${COMP_WORDS[i]:-}"
        case "$form" in
            "")
                case "$w" in -*) ;; *) form="$w" ;; esac ;;
            baseline)
                case "$w" in -*) ;; *) form="baseline $w" ;; esac ;;
            *)
                case "$form:$w" in
                    "audit:--root"|"evaluate:--snapshot"|"report:--profile"|"identity:--source"|"inventory:--root") i=$((i + 1)) ;;
                    *:-*) ;;
                    *) nargs=$((nargs + 1)) ;;
                esac ;;
        esac
        i=$((i + 1))
    done
    case "$form:$prev" in
        "audit:--root") _isedraf_paths -d; return 0 ;;
        "evaluate:--snapshot") :; return 0 ;;
        "report:--profile") _isedraf_paths -f; return 0 ;;
        "identity:--source") _isedraf_paths -f; return 0 ;;
        "inventory:--root") _isedraf_paths -d; return 0 ;;
    esac
    case "$form" in
        "")
            case "$cur" in
                -*) _isedraf_words "--help --version" ;;
                *) _isedraf_words "help audit evaluate explain baseline list report identity inventory" ;;
            esac ;;
        baseline)
            _isedraf_words "approve --help" ;;
        "help")
            case "$cur" in
                -*) _isedraf_words "--help --all" ;;
                *)
                    if [ "$nargs" -eq 0 ]; then _isedraf_words "help audit evaluate explain baseline list report identity inventory"; fi ;;
            esac ;;
        "audit")
            case "$cur" in
                -*) _isedraf_words "--help --root" ;;
                *) _isedraf_words "--help --root" ;;
            esac ;;
        "evaluate")
            case "$cur" in
                -*) _isedraf_words "--help --snapshot" ;;
                *) _isedraf_words "--help --snapshot" ;;
            esac ;;
        "explain")
            case "$cur" in
                -*) _isedraf_words "--help" ;;
                *)
                    if [ "$nargs" -eq 0 ]; then _isedraf_words "$_isedraf_criteria"; fi ;;
            esac ;;
        "baseline approve")
            case "$cur" in
                -*) _isedraf_words "--help" ;;
                *)
                    if [ "$nargs" -eq 0 ]; then :; fi ;;
            esac ;;
        "list")
            case "$cur" in
                -*) _isedraf_words "--help --all" ;;
                *) _isedraf_words "--help --all" ;;
            esac ;;
        "report")
            case "$cur" in
                -*) _isedraf_words "--help --json --html --profile --save" ;;
                *) _isedraf_words "--help --json --html --profile --save" ;;
            esac ;;
        "identity")
            case "$cur" in
                -*) _isedraf_words "--help --source" ;;
                *) _isedraf_words "--help --source" ;;
            esac ;;
        "inventory")
            case "$cur" in
                -*) _isedraf_words "--help --json --root" ;;
                *) _isedraf_words "--help --json --root" ;;
            esac ;;
    esac
    return 0
}

complete -F _isedraf isedraf
