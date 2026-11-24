# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The bash completion follows the command table and never reads evidence.
# Implements: D-129
#
# Each case runs a clean bash (no profile, no rc, no bash-completion package), sources the
# generated file, sets COMP_WORDS/COMP_CWORD as bash would, calls the function and reads
# COMPREPLY back.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3,bash"
# =============================================================================
"""v0.5 register item C1."""
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import commands                                            # noqa: E402

FILE = ROOT / "packaging" / "completion" / "isedraf.bash"
CATALOG = ROOT / "lib" / "isedraf" / "catalog" / "native_controls.json"
_spec = importlib.util.spec_from_file_location(
    "bash_completion", str(ROOT / "scripts" / "docs" / "bash_completion.py"))
generator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generator)

DRIVER = r'''
source "$1"; shift
COMP_WORDS=("$@")
COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
_isedraf
printf '%s\n' "${COMPREPLY[@]}"
'''


class Completion(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)
        # A store with a run in it, where a completion that read evidence would find it.
        runs = os.path.join(self.home, ".local", "state", "isedraf", "snapshots",
                            "SDS-20261113T101500Z-0123456789abcdef")
        os.makedirs(runs)

    def complete(self, *words):
        """Completions for `isedraf <words>`, the last word being the one under the cursor."""
        env = {"PATH": "/usr/bin:/bin", "HOME": self.home, "LC_ALL": "C"}
        done = subprocess.run(["bash", "--noprofile", "--norc", "-c", DRIVER, "driver",
                               str(FILE), "isedraf"] + list(words),
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env, cwd=self.home, timeout=20,
                              universal_newlines=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stderr, "")
        return [w for w in done.stdout.split("\n") if w]

    def test_the_file_is_the_generated_one(self):
        self.assertEqual(FILE.read_text(), generator.render())

    def test_top_level_offers_the_commands_of_the_table(self):
        top = []
        for record in commands.COMMANDS:
            if record["path"][0] not in top:
                top.append(record["path"][0])
        self.assertEqual(sorted(self.complete("")), sorted(top))
        self.assertEqual(sorted(self.complete("-")), ["--help", "--version"])
        self.assertEqual(self.complete("ev"), ["evaluate"])

    def test_each_command_offers_exactly_its_own_options(self):
        for record in commands.COMMANDS:
            expected = sorted(["--help"] + [o["flag"] for o in record["options"]])
            got = sorted(self.complete(*(list(record["path"]) + ["-"])))
            self.assertEqual(got, expected, record["path"])

    def test_options_are_not_shared_between_commands(self):
        self.assertNotIn("--json", self.complete("audit", "--"))
        self.assertNotIn("--root", self.complete("report", "--"))
        self.assertIn("--profile", self.complete("report", "--"))

    def test_the_baseline_group_offers_its_action(self):
        self.assertEqual(sorted(self.complete("baseline", "")), ["--help", "approve"])

    def test_help_offers_the_command_names_once(self):
        top = sorted(set(r["path"][0] for r in commands.COMMANDS))
        self.assertEqual(sorted(self.complete("help", "")), top)
        self.assertEqual(self.complete("help", "ev"), ["evaluate"])
        self.assertEqual(self.complete("help", "audit", ""), [])

    def test_explain_offers_the_installed_criterion_ids(self):
        ids = [c["criterion_id"] for c in json.loads(CATALOG.read_text())["criteria"]]
        self.assertEqual(sorted(self.complete("explain", "")), sorted(ids))
        self.assertEqual(sorted(self.complete("explain", "ISE-SSH")),
                         sorted(i for i in ids if i.startswith("ISE-SSH")))
        self.assertEqual(self.complete("explain", "ISE-ACCOUNT-001", ""), [])

    def test_no_snapshot_id_is_ever_offered(self):
        for words in (("baseline", "approve", ""), ("baseline", "approve", "SDS"),
                      ("evaluate", "--snapshot", ""), ("evaluate", "--snapshot", "SDS")):
            self.assertEqual(self.complete(*words), [], words)

    def test_path_options_complete_paths_and_consume_their_value(self):
        open(os.path.join(self.home, "profile.json"), "w").close()
        self.assertIn("profile.json", self.complete("report", "--profile", "pro"))
        self.assertEqual(self.complete("audit", "--root", ".lo"), [".local"])
        self.assertEqual(sorted(self.complete("report", "--profile", "x.json", "--h")),
                         ["--help", "--html"])

    def test_nothing_from_any_evidence_store_appears(self):
        seen = []
        for words in (("",), ("baseline", "approve", ""), ("explain", ""),
                      ("report", ""), ("evaluate", "")):
            seen.extend(self.complete(*words))
        self.assertFalse([w for w in seen if w.startswith("SDS-")], seen)

    def test_the_file_runs_nothing_and_names_no_store(self):
        text = FILE.read_text()
        code = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
        body = "\n".join(code)
        for forbidden in ("/var/lib/isedraf", ".local/state", "XDG_STATE_HOME",
                          "ISEDRAF_STATE_ROOT",
                          "isedraf ", "$(isedraf", "`isedraf"):
            hits = [line for line in code if forbidden in line
                    and line.strip() != "complete -F _isedraf isedraf"]
            self.assertEqual(hits, [], forbidden)
        self.assertIn("complete -F _isedraf isedraf", body)


if __name__ == "__main__":
    unittest.main(verbosity=0)
