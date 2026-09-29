# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The command surface tells the truth about how a run ended.
# Implements: SCOPE-077
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""GA track step 1: every exit the CLI can take is in the frozen W1-A exit set."""
import contextlib
import io
import os
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import cli, exitcodes                                    # noqa: E402


class UsageErrorsExitSixtyFour(unittest.TestCase):
    """SCOPE-077: usage errors are 64. argparse exits 2 on its own, and 2 is the frozen
    code for INCOMPLETE evidence, so a mistyped command read as "ran, evidence partial"."""

    def run_cli(self, argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            try:
                code = cli.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, err.getvalue()

    def test_an_unknown_command_is_a_usage_error(self):
        code, err = self.run_cli(["no-such-command"])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)
        self.assertIn("invalid choice", err)

    def test_an_unknown_option_is_a_usage_error(self):
        code, _ = self.run_cli(["inventory", "--no-such-option"])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)

    def test_no_command_is_a_usage_error(self):
        code, _ = self.run_cli([])
        self.assertEqual(code, exitcodes.USAGE_OR_ENGINE)

    def test_help_and_version_still_exit_zero(self):
        for argv in (["--help"], ["--version"]):
            code, _ = self.run_cli(argv)
            self.assertEqual(code, exitcodes.OK, argv)

    def test_every_exit_is_in_the_frozen_set(self):
        for argv in (["no-such-command"], ["inventory", "--bogus"], []):
            code, _ = self.run_cli(argv)
            self.assertIn(code, exitcodes.W1A_SET, argv)


if __name__ == "__main__":
    unittest.main(verbosity=0)
