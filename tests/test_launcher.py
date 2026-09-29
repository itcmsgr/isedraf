# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The launcher never writes bytecode next to the installed package.
# Implements: SCOPE-062, SCOPE-071
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="sh,python3"
# =============================================================================
"""RC1 rehearsal, 2026-09-28: `sudo isedraf audit` was refused with exit 70 as SCOPE-071
requires, but the interpreter it ran under could write to /usr/lib/isedraf and left 58
root-owned __pycache__ files there. No package owns them, so uninstall left the directory
behind on every distribution tested. A refused run must not change the host (SCOPE-062),
and bytecode is never written (D-86). The test gives the launcher a package directory it
CAN write to - root's position over /usr/lib - and requires that nothing appears in it."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


class LauncherWritesNoBytecode(unittest.TestCase):

    def setUp(self):
        self.prefix = pathlib.Path(tempfile.mkdtemp(prefix="isedraf-launcher-"))
        self.addCleanup(shutil.rmtree, str(self.prefix), True)
        (self.prefix / "bin").mkdir()
        shutil.copy2(str(ROOT / "bin" / "isedraf"), str(self.prefix / "bin" / "isedraf"))
        shutil.copytree(str(ROOT / "lib" / "isedraf"), str(self.prefix / "lib" / "isedraf"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX",
                                 "PYTHONPATH", "ISEDRAF_STATE_ROOT", "SUDO_USER")}

    def bytecode(self):
        return sorted(str(p.relative_to(self.prefix)) for p in self.prefix.rglob("*")
                      if p.name == "__pycache__" or p.suffix == ".pyc")

    def launch(self, *argv, **extra_env):
        env = dict(self.env, **extra_env)
        return subprocess.run(["sh", str(self.prefix / "bin" / "isedraf")] + list(argv),
                              env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60)

    def test_the_launcher_imports_the_package(self):
        # Guards the test itself: a launcher that never imported the package would
        # trivially write no bytecode.
        r = self.launch("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"isedraf ", r.stdout)

    def test_a_run_writes_no_bytecode_into_a_writable_package(self):
        self.launch("--help")
        self.assertEqual(self.bytecode(), [])

    def test_a_refused_privileged_run_writes_no_bytecode(self):
        r = self.launch("audit", SUDO_USER="someone")
        self.assertEqual(r.returncode, 70, r.stderr)
        self.assertEqual(self.bytecode(), [])


if __name__ == "__main__":
    unittest.main()
