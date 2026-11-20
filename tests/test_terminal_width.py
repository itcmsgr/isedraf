# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Every line of human terminal text fits 80 columns, on every command and case.
# Implements: D-129, SCOPE-077
#
# Owner rule 2026-11-20 (v0.5 terminal UX): human terminal text fits 80 columns; an identifier,
# path, digest, JSON pointer or code span is never split, and may pass 80 columns only alone on
# its line (summary.within_terminal). The Markdown, HTML and JSON reports follow their own formats
# and are excluded: for `isedraf report` only the messages around the document are checked.
#
# The coverage table below names every case. A command of the command table without a case, or
# a help form never run, fails the test, so a new command cannot skip the rule.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""v0.5 terminal rule: a coverage table of commands and cases, every line checked."""
import contextlib
import io
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import catalog, cli, commands, exitcodes, ledger, summary   # noqa: E402
from isedraf.launcher import evalunit, listunit, outer, reportunit, store, unit  # noqa: E402

HOST = {"etc/machine-id": "0123456789abcdef0123456789abcdef\n",
        "etc/passwd": "root:x:0:0:root:/root:/bin/sh\n"
                      "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        "etc/group": "root:x:0:\n"}
ANY = None           # exit code not asserted (the case is about the text)

# (name, state, argv, expected exit, the stdout is a report document)
# state: "empty" - no store; "runs" - two committed runs and an evaluation; "saved" - runs and two
# saved reports; "torn" - runs, then a torn ledger tail.
CASES = [
    ("start page", "empty", [], 0, False),
    ("help", "empty", ["help"], 0, False),
    ("help --all", "empty", ["help", "--all"], 0, False),
    ("--help", "empty", ["--help"], 0, False),
    ("--version", "empty", ["--version"], 0, False),
    ("help unknown", "empty", ["help", "prune"], 64, False),
    ("unknown command", "empty", ["prune"], 64, False),
    ("unknown option", "empty", ["audit", "--bogus"], 64, False),
    ("list, no store", "empty", ["list"], 0, False),
    ("report, no store", "empty", ["report"], 64, False),
    ("evaluate, no store", "empty", ["evaluate"], ANY, False),
    ("explain, missing argument", "empty", ["explain"], 64, False),
    ("explain, unknown", "empty", ["explain", "NOPE-1"], 64, False),
    ("baseline, missing action", "empty", ["baseline"], 64, False),
    ("baseline approve, missing argument", "empty", ["baseline", "approve"], 64, False),
    ("audit", "empty", ["audit", "--root", "{host}"], ANY, False),
    ("identity", "empty", ["identity", "--source", "{host}/etc/machine-id"], ANY, False),
    ("inventory", "empty", ["inventory", "--root", "{host}"], ANY, False),
    ("inventory --json", "empty", ["inventory", "--json", "--root", "{host}"], ANY, True),
    ("list", "runs", ["list"], 0, False),
    ("list --all", "runs", ["list", "--all"], 0, False),
    ("evaluate", "runs", ["evaluate"], 0, False),
    ("report (document)", "runs", ["report"], ANY, True),
    ("report --json (document)", "runs", ["report", "--json"], ANY, True),
    ("report --html (document)", "runs", ["report", "--html"], ANY, True),
    ("report --save", "runs", ["report", "--save"], ANY, False),
    ("baseline approve, DEV run", "runs", ["baseline", "approve", "{sid}"], ANY, False),
    ("baseline approve, again", "runs", ["baseline", "approve", "{sid}"], ANY, False),
    ("list --all, saved reports", "saved", ["list", "--all"], 0, False),
    ("list, saved reports", "saved", ["list"], 0, False),
    ("report, torn ledger", "torn", ["report"], 64, False),
    ("list, torn ledger", "torn", ["list"], 64, False),
    ("evaluate, torn ledger", "torn", ["evaluate"], 64, False),
    ("audit, recovers", "torn", ["audit", "--root", "{host}"], ANY, False),
]
for _record in catalog.load()[0]["criteria"]:
    CASES.append(("explain " + _record["criterion_id"], "empty",
                  ["explain", _record["criterion_id"]], 0, False))
for _record in commands.COMMANDS:
    CASES.append(("%s --help" % commands.name(_record), "empty",
                  list(_record["path"]) + ["--help"], 0, False))
    CASES.append(("help %s" % commands.name(_record), "empty",
                  ["help"] + list(_record["path"]), 0, False))


def offending(text):
    return [line for line in text.splitlines() if not summary.within_terminal(line)]


class UserRoute(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.host = os.path.join(self.base, "host")
        for rel, text in HOST.items():
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        # A deep store path, so every line naming it meets a path longer than one line.
        self.root = os.path.join(self.base, "a-deliberately-long-directory-name-for-paths", "store")
        patch = mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.root})
        patch.start()
        self.addCleanup(patch.stop)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def prepare(self, state):
        if state in ("runs", "torn", "saved"):
            self.run_cli(["audit", "--root", self.host])
            self.run_cli(["audit", "--root", self.host])
            self.run_cli(["evaluate"])
        if state == "saved":
            self.run_cli(["report", "--save"])
            self.run_cli(["report", "--html", "--save"])
        if state == "torn":
            segment = ledger.segment_path(self.root)
            with open(segment, "rb") as fh:
                data = fh.read()
            with open(segment, "ab") as fh:
                fh.write(data[-200:-163])

    def test_every_case_keeps_the_terminal_rule(self):
        failures = []
        for name, state, argv, want, document in CASES:
            shutil.rmtree(self.root, True)
            self.prepare(state)
            sid = (ledger.snapshot_records(self.root)[0]["snapshot_id"]
                   if state in ("runs", "saved") else "")
            argv = [a.replace("{host}", self.host).replace("{sid}", sid) for a in argv]
            code, out, err = self.run_cli(argv)
            if want is not ANY and code != want:
                failures.append("%s: exit %r, expected %r" % (name, code, want))
            for line in offending(err) + ([] if document else offending(out)):
                failures.append("%s: %d columns: %s" % (name, len(line), line))
        self.assertEqual(failures, [], "\n".join(failures))

    def test_long_host_values_move_to_their_own_lines(self):
        vendor = "QEMU / Ubuntu 24.04 PC v2 (i440FX + PIIX, arch_caps fix, 1996) with a longer tail"
        mount = "/srv/" + "very-long-mount-point-name/" * 4
        for line in ("  %-17s : %s" % ("vendor / product", vendor), "  %-17s : ext4" % mount):
            fitted = cli._fit(line)
            self.assertEqual(offending("\n".join(fitted)), [], fitted)
            words = lambda text: [w for w in text.split() if w != ":"]   # noqa: E731
            self.assertEqual(words(" ".join(fitted)), words(line))       # nothing lost or split
        self.assertIn("  " + mount, cli._fit("  %-17s : ext4" % mount))

    def test_the_coverage_table_names_every_command_and_help_form(self):
        covered = set()
        for _name, _state, argv, _want, _doc in CASES:
            words = tuple(a for a in argv if not a.startswith("-"))
            for record in commands.COMMANDS:
                if words[:len(record["path"])] == record["path"] or (
                        words[:1] == ("help",) and words[1:] == record["path"]):
                    covered.add(record["path"])
        self.assertEqual(covered, set(r["path"] for r in commands.COMMANDS))
        run = set(tuple(argv) for _n, _s, argv, _w, _d in CASES)
        self.assertTrue(set(f for f, _k in commands.HELP_FORMS) - {("-h",), ("help", "-h"),
                                                                   ("help", "--help")} <= run)


class RootRoute(unittest.TestCase):
    """The root route's text, from the functions that print it (the lab covers the rest)."""

    def assert_terminal(self, name, text):
        self.assertEqual(offending(text), [], name)

    def test_help_forms_and_refusals_of_the_outer_entry(self):
        for form in commands.help_forms():
            code, out, err = commands.answer(form)
            self.assert_terminal(" ".join(form) or "(bare)", out + err)
        for euid in (0, 1000):
            err = io.StringIO()
            with mock.patch.object(os, "geteuid", return_value=euid):
                outer.main(["identity"], err)
            self.assert_terminal("refusal euid %d" % euid, err.getvalue())
        for token in summary.PLAIN:
            self.assert_terminal(token, summary.explained(
                token, "a detail naming /var/lib/isedraf/ledger/segment-000001.jsonl and "
                "SDS-20261120T000000Z-0123456789abcdef (BASE-021)", "Nothing was written."))

    def test_the_system_store_launchers(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        host = os.path.join(base, "host")
        for rel, text in HOST.items():
            path = os.path.join(host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        root = os.path.join(base, "root")
        with mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": root}):
            for _ in range(2):
                cli.cmd_audit(type("A", (), {"root": host})(), out=io.StringIO(),
                              err=io.StringIO())
        uid, gid = os.getuid(), os.getgid()
        with mock.patch.object(store, "OWNER_UID", uid), mock.patch.object(store, "OWNER_GID",
                                                                            gid):
            for scope in ("newest", "all"):
                out, err = io.StringIO(), io.StringIO()
                listunit.run(scope, root, out, err)
                self.assert_terminal("sudo list " + scope, out.getvalue() + err.getvalue())
            out, err = io.StringIO(), io.StringIO()
            listunit.run("newest", root + "-absent", out, err)
            self.assert_terminal("sudo list, absent store", out.getvalue() + err.getvalue())
            segment = ledger.segment_path(root)
            with open(segment, "rb") as fh:
                data = fh.read()
            with open(segment, "ab") as fh:
                fh.write(data[-200:-163])
            for name, call in (
                    ("sudo list, torn", lambda e: listunit.run("newest", root, io.StringIO(), e)),
                    ("sudo report, torn", lambda e: reportunit.run("markdown", root, e,
                                                                   engine_uid=uid)),
                    ("sudo evaluate, torn", lambda e: evalunit.run(root, e, io.StringIO(),
                                                                   engine_uid=uid,
                                                                   state_root_class="DEV"))):
                err = io.StringIO()
                self.assertEqual(call(err), exitcodes.USAGE_OR_ENGINE, name)
                self.assert_terminal(name, err.getvalue())
        err = io.StringIO()
        with mock.patch.object(unit.space, "available", return_value=1024 * 1024):
            unit.run("RUN-20261120T000000Z-0123456789abcdef", root=base, err=err)
        self.assert_terminal("sudo audit, no space", err.getvalue())
        self.assert_terminal("recovered notice", summary.recovered_notice("segment-000001.jsonl"))
        self.assert_terminal("approval text", summary.approval_text(
            {"snapshot_id": "SDS-20261120T000000Z-0123456789abcdef",
             "profile": {"object": {"profile_id": "v0.4-default-1"}},
             "required_sections": ["host_identity", "accounts", "ssh", "loginpolicy"],
             "sections": {}}, "2026-11-20T00:00:00Z", "SYSTEM_PRODUCTION"))


if __name__ == "__main__":
    unittest.main(verbosity=0)
