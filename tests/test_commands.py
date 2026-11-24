# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: One command table: the parser, the help and the gate agree with it.
# Implements: D-129, SCOPE-077, OUT-001, AUTH-019
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""v0.5 register items H1, H3, H4, H5, H6, H7."""
import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import catalog, cli, commands, exitcodes                  # noqa: E402
from isedraf.launcher import outer                                     # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "check_commands", str(ROOT / "scripts" / "ci" / "check_commands.py"))
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def flat(text):
    """Help is word-wrapped; phrases are compared with whitespace normalized."""
    return " ".join(text.split())


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class Help(unittest.TestCase):
    """H4, H5: help is rendered from the table, exits 0 and names only implemented forms."""

    def test_overview_lists_every_command_by_group_developer_last(self):
        code, out, _ = run(["--help"])
        self.assertEqual(code, exitcodes.OK)
        positions = [out.index("\n%s:\n" % g) for g in commands.GROUPS]
        self.assertEqual(positions, sorted(positions))
        for record in commands.COMMANDS:
            self.assertIn("  %s " % commands.name(record), out)
        self.assertLess(out.index("audit "), out.index("identity "))
        self.assertIn("sudo isedraf audit", out)
        self.assertIn("explicit decision", out)

    def test_every_command_has_help_with_effect_privilege_writes_exits_examples(self):
        for record in commands.COMMANDS:
            code, out, _ = run(list(record["path"]) + ["--help"])
            self.assertEqual(code, exitcodes.OK, record["path"])
            self.assertEqual(out, commands.command_help(record))
            for heading in ("What it does", "Who runs it", "What it writes", "Exit codes:",
                            "Examples:"):
                self.assertIn(heading, out, (record["path"], heading))
            for option in record["options"]:
                self.assertIn(option["flag"], out)

    def test_baseline_help_separates_dev_and_full_audit_approval(self):
        out = flat(run(["baseline", "approve", "--help"])[1])
        self.assertIn("sudo isedraf baseline approve", out)
        self.assertIn("development (DEV) store", out)
        self.assertIn("never turns a personal-store run into production evidence", out)
        self.assertIn("takes no snapshot argument", out)

    def test_evaluate_help_says_zero_is_not_all_passed(self):
        out = flat(run(["evaluate", "--help"])[1])
        self.assertIn("does not mean every criterion passed", out)

    def test_examples_always_name_the_executable(self):
        for record in commands.COMMANDS:
            for example in record["examples"]:
                self.assertTrue(example in ("isedraf", "sudo isedraf")
                                or example.startswith(("isedraf ", "sudo isedraf ")), example)


class MissingArguments(unittest.TestCase):
    """H7: a missing argument gets guidance and a complete example; exit stays 64."""

    def test_explain_without_an_id_lists_the_installed_criteria(self):
        code, out, err = run(["explain"])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertEqual(out, "")
        registry, _raw = catalog.load()
        for criterion in registry["criteria"]:
            self.assertIn(criterion["criterion_id"], err)
        self.assertIn("isedraf explain ISE-ACCOUNT-001", err)
        err = flat(err)
        self.assertNotIn("the following arguments are required", err)

    def test_baseline_approve_without_a_snapshot_explains_both_contexts(self):
        code, _, err = run(["baseline", "approve"])
        err = flat(err)
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertIn("sudo isedraf baseline approve", err)
        self.assertIn("isedraf baseline approve SDS-ID", err)
        self.assertIn("Development (DEV) store", err)
        self.assertIn("System store", err)
        self.assertIn("personal store holds no baseline", err)
        self.assertIn("sudo does not turn a personal-store run into production evidence", err)

    def test_baseline_without_an_action_names_it(self):
        code, _, err = run(["baseline"])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertIn("isedraf baseline approve", err)



class StartPageAndHelp(unittest.TestCase):
    """H3, H4, Q1, Q2 (D-129): bare isedraf, isedraf help, help --all, help COMMAND."""

    def test_bare_isedraf_prints_the_start_page_and_exits_zero(self):
        code, out, err = run([])
        self.assertEqual((code, err), (exitcodes.OK, ""))
        self.assertEqual(out, commands.start_page())
        self.assertEqual(run(["help"]), (exitcodes.OK, out, ""))

    def test_the_start_page_holds_what_h3_requires(self):
        page = flat(commands.start_page())
        for phrase in ("Standard Audit", "Full Audit", "isedraf audit", "isedraf evaluate",
                       "isedraf report", "sudo isedraf audit",
                       "Approving a baseline is an explicit decision, never an automatic "
                       "next step", "isedraf help --all", "/usr/share/doc/isedraf/docs/"):
            self.assertIn(phrase, page)
        for line in commands.start_page().splitlines():
            self.assertLessEqual(len(line), commands.WIDTH, line)

    def test_help_all_is_the_grouped_overview(self):
        self.assertEqual(run(["help", "--all"]), (exitcodes.OK, commands.overview(), ""))
        self.assertEqual(run(["--help"]), (exitcodes.OK, commands.overview(), ""))
        self.assertIn("Getting started:", commands.overview())

    def test_help_command_is_that_commands_help(self):
        for record in commands.COMMANDS:
            code, out, err = run(["help"] + list(record["path"]))
            self.assertEqual((code, err), (exitcodes.OK, ""), record["path"])
            self.assertEqual(out, commands.command_help(record))
        code, out, _ = run(["help", "baseline"])
        self.assertEqual(out, commands.command_help(commands.find(("baseline", "approve"))))

    def test_help_for_an_unknown_command_exits_64_and_lists_the_valid_ones(self):
        code, out, err = run(["help", "prune"])
        self.assertEqual((code, out), (exitcodes.USAGE_OR_ENGINE, ""))
        self.assertIn("isedraf help: unknown command 'prune'.", err)
        for record in commands.COMMANDS:
            self.assertIn(commands.name(record), flat(err))

    def test_invalid_commands_and_arguments_keep_their_error_exits(self):
        for argv in (["prune"], ["audit", "--bogus"], ["help", "--all", "audit"]):
            self.assertEqual(run(argv)[0], exitcodes.USAGE_OR_ENGINE, argv)

    def test_the_version_is_the_installed_version(self):
        from isedraf import ENGINE_VERSION
        self.assertEqual(run(["--version"]), (exitcodes.OK, "isedraf %s\n" % ENGINE_VERSION, ""))

    def test_help_forms_collect_approve_and_write_nothing(self):
        # Q1: no collection, approval or evidence-store write. Each form runs in a fresh
        # process with an empty HOME and state directory; afterwards both are still empty.
        import os
        import subprocess
        import tempfile
        for form in commands.help_forms():
            with tempfile.TemporaryDirectory() as home:
                env = {"HOME": home, "XDG_STATE_HOME": os.path.join(home, "state"),
                       "PATH": "/usr/bin:/bin", "LC_ALL": "C",
                       "PYTHONPATH": str(ROOT / "lib")}
                done = subprocess.run(
                    [sys.executable, "-B", "-c",
                     "import sys; from isedraf.cli import main; sys.exit(main())"] + list(form),
                    env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=60)
                self.assertEqual(done.returncode, 0, (form, done.stderr))
                self.assertEqual(os.listdir(home), [], form)


class Gate(unittest.TestCase):
    """H6: the gate passes on the real table and refuses each kind of drift."""

    def setUp(self):
        self.registry = json.loads((ROOT / "lib" / "isedraf" / "exitcodes.json").read_text())
        self.admitted = gate.root_forms(outer)
        self.parse = gate._parser_selects(cli)

    def problems(self, table=commands, handlers=None, registry=None, admitted=None):
        return gate.check(table, set(cli.HANDLERS) if handlers is None else handlers,
                          self.registry if registry is None else registry,
                          self.admitted if admitted is None else admitted, self.parse)

    def mutated(self, index, **changes):
        class Table(object):
            pass
        table = Table()
        for attr in ("GROUPS", "EFFECTS", "EXIT_MEANINGS"):
            setattr(table, attr, getattr(commands, attr))
        records = [dict(r) for r in commands.COMMANDS]
        records[index].update(changes)
        table.COMMANDS = tuple(records)
        return table

    def test_the_real_table_passes(self):
        self.assertEqual(self.problems(), [])

    def test_root_forms_are_the_five_routes(self):
        # AUTH-035 (D-129 point 12) adds the read-only listing.
        self.assertEqual(self.admitted, {("audit",), ("report",), ("report", "--json"),
                                         ("report", "--html"), ("evaluate",),
                                         ("baseline", "approve"), ("list",),
                                         ("list", "--all")})

    def test_a_handler_without_a_record_is_refused(self):
        self.assertTrue(self.problems(handlers=set(cli.HANDLERS) | {("prune",)}))

    def test_exit_codes_that_differ_from_the_registry_are_refused(self):
        registry = copy.deepcopy(self.registry)
        registry["subcommands"]["isedraf explain"] = [0, 64]
        self.assertTrue(any("differ" in p for p in self.problems(registry=registry)))

    def test_an_unnamed_registry_row_is_refused(self):
        registry = copy.deepcopy(self.registry)
        registry["subcommands"]["isedraf prune"] = [0, 64]
        self.assertTrue(any("named by no command" in p for p in self.problems(registry=registry)))

    def test_a_sudo_form_the_root_route_does_not_admit_is_refused(self):
        self.assertTrue(any("disagree" in p
                            for p in self.problems(admitted=self.admitted | {("explain",)})))

    def test_an_example_that_does_not_parse_is_refused(self):
        index = [r["path"] for r in commands.COMMANDS].index(("report",))
        table = self.mutated(index, examples=("isedraf report --pdf",))
        self.assertTrue(any("does not parse" in p for p in self.problems(table=table)))

    def test_a_sudo_example_with_an_argument_is_refused(self):
        index = [r["path"] for r in commands.COMMANDS].index(("baseline", "approve"))
        table = self.mutated(index, examples=("sudo isedraf baseline approve SDS-x",))
        self.assertTrue(any("not a form the root route admits" in p
                            for p in self.problems(table=table)))

    def test_an_argument_without_guidance_is_refused(self):
        index = [r["path"] for r in commands.COMMANDS].index(("explain",))
        table = self.mutated(index, missing=None)
        self.assertTrue(any("guidance" in p for p in self.problems(table=table)))


class DocExamples(unittest.TestCase):
    """D1: every isedraf command in a guide's shell block is a real command form."""

    def check(self, text):
        examples = gate.doc_examples([("doc.md", text)])
        return gate.check_docs(examples, set(commands.help_forms()), gate.root_forms(outer),
                               gate._parser_selects(cli)), examples

    def test_real_forms_pass_comments_redirections_and_placeholders_aside(self):
        problems, examples = self.check(
            "```sh\nisedraf audit            # collect\nisedraf report --html > r.html\n"
            "sudo isedraf list --all\nisedraf baseline approve <SDS-id>\nisedraf\n```\n")
        self.assertEqual(problems, [])
        self.assertEqual(len(examples), 5)

    def test_an_invented_option_or_root_form_is_refused(self):
        problems, _ = self.check("```sh\nisedraf report --pdf\nsudo isedraf explain X\n```\n")
        self.assertEqual(len(problems), 2)

    def test_text_outside_shell_blocks_is_not_a_command(self):
        problems, examples = self.check("isedraf report --pdf\n```text\nisedraf frobnicate\n```\n")
        self.assertEqual((problems, examples), ([], []))


class HelpGate(unittest.TestCase):
    """AUTH-019 as amended for v0.5: one help answer on both routes, before admission."""

    def setUp(self):
        import inspect
        self.inputs = dict(table=commands, user_route=gate._user_route(cli),
                           root_route=gate._root_route(outer),
                           outer_source=inspect.getsource(outer.main),
                           refusal=outer.REFUSAL,
                           launcher_text=(ROOT / "bin" / "isedraf").read_text(),
                           admitted=gate.root_forms(outer))

    def problems(self, **changes):
        inputs = dict(self.inputs, **changes)
        return gate.check_help(**inputs)

    def test_the_real_routes_pass(self):
        self.assertEqual(self.problems(), [])

    def test_a_route_that_answers_differently_is_refused(self):
        real = self.inputs["root_route"]

        def drifted(argv):
            code, out, err = real(argv)
            return code, out.replace("Full Audit", "Full audit"), err
        self.assertTrue(any("answers differently" in p
                            for p in self.problems(root_route=drifted)))

    def test_help_after_the_privilege_check_is_refused(self):
        source = self.inputs["outer_source"].replace(
            "helped = answer_help(argv)", "os.geteuid()\n    helped = answer_help(argv)")
        self.assertTrue(any("before geteuid" in p for p in self.problems(outer_source=source)))

    def test_a_help_form_that_is_also_a_root_route_is_refused(self):
        admitted = self.inputs["admitted"] | {("--version",)}
        self.assertTrue(any("also an admitted root route" in p
                            for p in self.problems(admitted=admitted)))

    def test_a_refusal_that_omits_a_route_is_refused(self):
        refusal = outer.REFUSAL.replace("  sudo isedraf evaluate           its evaluation\n", "")
        self.assertTrue(any("does not name `sudo isedraf evaluate`" in p
                            for p in self.problems(refusal=refusal)))

    def test_a_launcher_fallback_that_drifts_is_refused(self):
        text = self.inputs["launcher_text"].replace("its baseline", "the baseline")
        self.assertTrue(any("bin/isedraf does not print" in p
                            for p in self.problems(launcher_text=text)))


if __name__ == "__main__":
    unittest.main(verbosity=0)
