#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: One command-definition source: the table, the parser, the exit-code registry, the
#          root route and every example agree (register item H6).
# Implements: D-129, OUT-001, SCOPE-077, AUTH-019
#
# Checks, in one place:
#   - every table record has a handler in cli.py and every handler a record
#   - each record's exit codes equal its rows in lib/isedraf/exitcodes.json, every command
#     row there is named by a record, and every code has a plain-words meaning
#   - the forms the table says run under sudo are exactly the forms launcher/outer.py admits
#   - every `isedraf ...` example parses with the real parser and selects its own record;
#     every `sudo isedraf ...` example is an admitted root form
#   - groups, effects and completion kinds are from the table's vocabularies
#   - the help forms (AUTH-019 as amended for v0.5): every accepted form gives the same
#     answer on the user route (cli.main) and the root route (outer.answer_help), which
#     outer.main calls before any other check; no help form is an admitted root form; the
#     root refusal names exactly the sudo forms and bin/isedraf prints it line for line
#
# meta:type="gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""H6: the command table is the one source, and nothing drifts from it."""
import contextlib
import io
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

USAGE_ROW = "isedraf (usage error)"
KINDS = ("none", "file", "dir", "criterion", "snapshot", "command")


def root_forms(outer):
    """The invocations outer.main admits under root: `audit` and the three route constants."""
    import inspect
    source = inspect.getsource(outer.main)
    forms = (set(outer.REPORT_INVOCATIONS) | set(outer.LIST_INVOCATIONS)
             | {outer.EVALUATE_INVOCATION, outer.BASELINE_INVOCATION})
    if 'list(argv) != ["audit"]' in source:
        forms.add(("audit",))
    return forms


def check(table, handlers, registry, admitted, parse):
    problems = []
    paths = [r["path"] for r in table.COMMANDS]
    if len(set(paths)) != len(paths):
        problems.append("a command path is defined twice")
    for path in sorted(set(paths) ^ set(handlers)):
        problems.append("%r: a table record without a handler, or a handler without a record"
                        % (" ".join(path),))
    rows = registry.get("subcommands") or {}
    named = set()
    for r in table.COMMANDS:
        label = "isedraf %s" % " ".join(r["path"])
        if r["group"] not in table.GROUPS:
            problems.append("%s: unknown group %r" % (label, r["group"]))
        if r["effect"] not in table.EFFECTS:
            problems.append("%s: unknown effect %r" % (label, r["effect"]))
        for item in list(r["options"]) + list(r["arguments"]):
            if item["complete"] not in KINDS:
                problems.append("%s: unknown completion kind %r" % (label, item["complete"]))
        if any(a["required"] for a in r["arguments"]) and not r.get("missing"):
            problems.append("%s: takes an argument but has no missing-argument guidance (H7)"
                            % label)
        for key, codes in sorted(r["exits"].items()):
            named.add(key)
            if key not in rows:
                problems.append("%s: exit row %r is not in exitcodes.json" % (label, key))
            elif list(codes) != list(rows[key]):
                problems.append("%s: exit codes %s differ from exitcodes.json %r %s"
                                % (label, list(codes), key, rows[key]))
            for code in codes:
                if code not in table.EXIT_MEANINGS:
                    problems.append("%s: exit %d has no plain-words meaning" % (label, code))
        sudo_keys = set(k for k in r["exits"] if k.startswith("sudo "))
        if bool(sudo_keys) != bool(r["sudo_forms"] or r.get("root_help")):
            problems.append("%s: sudo exit rows and sudo forms disagree" % label)
        for example in r["examples"]:
            words = example.split()
            helps = set(commands_module().help_forms())
            for prefix in (["isedraf"], ["sudo", "isedraf"]):
                if words[:len(prefix)] == prefix and tuple(words[len(prefix):]) in helps:
                    break
            else:
                prefix = None
            if prefix is not None:
                if not r.get("root_help"):
                    problems.append("%s: example %r is a help form of another record"
                                    % (label, example))
                continue
            if words[:2] == ["sudo", "isedraf"]:
                if tuple(words[2:]) not in admitted:
                    problems.append("%s: example %r is not a form the root route admits"
                                    % (label, example))
                elif tuple(words[2:]) not in r["sudo_forms"]:
                    problems.append("%s: example %r belongs to another record" % (label, example))
            elif words[:1] == ["isedraf"]:
                selected = parse(words[1:])
                if selected is not r:
                    problems.append("%s: example %r does not parse to this command"
                                    % (label, example))
            else:
                problems.append("%s: example %r does not start with isedraf or sudo isedraf"
                                % (label, example))
    for key in sorted(set(rows) - named - {USAGE_ROW}):
        problems.append("exitcodes.json row %r is named by no command record" % key)
    declared = set(f for r in table.COMMANDS for f in r["sudo_forms"])
    for form in sorted(declared ^ admitted):
        problems.append("sudo form %r: the table and launcher/outer.py disagree"
                        % (" ".join(form),))
    return problems


def commands_module():
    from isedraf import commands
    return commands


# Near misses: each must be refused with 64 by both routes, never answered with 0.
HELP_PROBES = (("help", "no-such-command"), ("help", "--all", "audit"), ("help", "baseline", "x"),
               ("help", "--bogus"))


def check_help(table, user_route, root_route, outer_source, refusal, launcher_text, admitted):
    """The help forms: one answer on both routes, before admission, and the refusal text.
    user_route(argv) and root_route(argv) return (code, stdout, stderr)."""
    problems = []
    forms = table.help_forms()
    if len(set(forms)) != len(forms):
        problems.append("a help form is listed twice")
    for form in sorted(set(forms) & admitted):
        problems.append("help form %r is also an admitted root route" % (" ".join(form),))
    for form in list(forms) + list(HELP_PROBES):
        expected = table.answer(form)
        label = "isedraf %s" % " ".join(form) if form else "isedraf"
        if expected is None:
            problems.append("%s: not answered by the command definitions" % label)
            continue
        want = 64 if form in HELP_PROBES else 0
        if expected[0] != want:
            problems.append("%s: exits %d, expected %d" % (label, expected[0], want))
        for route, run in (("user route (cli.main)", user_route),
                           ("root route (outer.answer_help)", root_route)):
            got = run(form)
            if got != expected:
                problems.append("%s: the %s answers differently from commands.answer"
                                % (label, route))
    # outer.main answers help before any other check (AUTH-019 as amended for v0.5).
    first = outer_source.find("answer_help(argv)")
    for later in ("geteuid", "unsafe_install()", "OS_RELEASE", "GETENT"):
        at = outer_source.find(later)
        if first < 0 or (0 <= at < first):
            problems.append("outer.main does not answer the help forms before %s" % later)
    for form in [f for r in table.COMMANDS for f in r["sudo_forms"]]:
        if form[-1].startswith("--"):
            continue
        if "sudo isedraf %s " % " ".join(form) not in refusal:
            problems.append("the root refusal does not name `sudo isedraf %s`" % " ".join(form))
    for line in ("isedraf: " + refusal).splitlines():
        if '"%s"' % line not in launcher_text:
            problems.append("bin/isedraf does not print the refusal line %r" % line)
    return problems


def _parser_selects(cli):
    parser = cli.build_parser()

    def parse(argv):
        sink = io.StringIO()
        try:
            with contextlib.redirect_stderr(sink), contextlib.redirect_stdout(sink):
                args = parser.parse_args(argv)
        except SystemExit:
            return None
        return getattr(args, "record", None)
    return parse


# D-129 D1: every isedraf command shown in a shell block of the operator documents is a form the
# command table implements (parsed by the real parser, an admitted root form, or a help form).
DOCS = ("README.md", "docs/GETTING_STARTED.md", "docs/REPORT_GUIDE.md", "docs/EVIDENCE_MODEL.md",
        "docs/AUDITOR_GUIDE.md", "docs/SECURITY_AND_LIMITATIONS.md")


def doc_examples(texts):
    """(path, line number, words) of each isedraf command in a ```sh block. A trailing
    comment, a redirection or a pipe ends the command; a line holding a placeholder (<...>)
    is checked up to the placeholder's argument."""
    found = []
    for path, text in texts:
        inside = False
        for number, line in enumerate(text.splitlines(), 1):
            if line.startswith("```"):
                inside = line.strip() in ("```sh", "```bash", "```shell") and not inside
                continue
            if not inside:
                continue
            command = line.split("#", 1)[0]
            for stop in (">", "|", ";", "&&"):
                command = command.split(stop, 1)[0]
            words = command.split()
            if words[:1] == ["isedraf"] or words[:2] == ["sudo", "isedraf"]:
                found.append((path, number, [w for w in words if not w.startswith("<")]))
    return found


def check_docs(examples, helps, admitted, parse):
    problems = []
    for path, number, words in examples:
        sudo = words[:1] == ["sudo"]
        argv = tuple(words[2:] if sudo else words[1:])
        if argv in helps:
            continue
        if sudo:
            if argv not in admitted:
                problems.append("%s:%d: `%s` is not a form the root route admits"
                                % (path, number, " ".join(words)))
        elif parse(list(argv)) is None:
            problems.append("%s:%d: `%s` does not parse with the command table"
                            % (path, number, " ".join(words)))
    return problems


def _user_route(cli):
    def run(argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()
    return run


def _root_route(outer):
    import tempfile

    def run(argv):
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            code = outer.answer_help(list(argv), out.fileno(), err.fileno())
            texts = []
            for handle in (out, err):
                handle.seek(0)
                texts.append(handle.read().decode("utf-8"))
        return code, texts[0], texts[1]
    return run


def main():
    import inspect
    from isedraf import cli, commands
    from isedraf.launcher import outer
    registry = json.loads((ROOT / "lib" / "isedraf" / "exitcodes.json").read_text())
    admitted = root_forms(outer)
    problems = check(commands, set(cli.HANDLERS), registry, admitted, _parser_selects(cli))
    problems += check_help(commands, _user_route(cli), _root_route(outer),
                           inspect.getsource(outer.main), outer.REFUSAL,
                           (ROOT / "bin" / "isedraf").read_text(), admitted)
    examples = doc_examples([(p, (ROOT / p).read_text(encoding="utf-8")) for p in DOCS
                             if (ROOT / p).exists()])
    problems += check_docs(examples, set(commands.help_forms()), admitted, _parser_selects(cli))
    if problems:
        print("=== command table (H6): %d problem(s) ===" % len(problems))
        for p in problems:
            print("  FAIL  %s" % p)
        return 1
    print("  OK    command table (H6): %d command forms, each with a handler, its exit rows, "
          "parsing examples; %d root forms equal launcher/outer.py; %d help forms answered "
          "alike on both routes, before admission; %d documented commands are real forms"
          % (len(commands.COMMANDS), len(admitted), len(commands.help_forms()), len(examples)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
