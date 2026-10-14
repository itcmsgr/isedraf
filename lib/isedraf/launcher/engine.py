# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Start the reduced engine: a constant setpriv command, a fixed entry, fixed fds.
# Implements: AUTH-020, AUTH-011, AUTH-026, AUTH-027, EXEC-011
#
# Every element of the command is a constant of this module (AUTH-020): the `isedraf` user
# and group, no supplementary groups, empty inheritable, ambient and bounding sets (which
# leaves permitted and effective empty for a non-root uid), no-new-privileges, and the fixed
# engine entry under the install root. The environment is EXEC-011's and nothing else;
# stdin is /dev/null; the working directory is the run's staging; the supervisor channel is
# placed on descriptors 3 (engine -> supervisor) and 4 (supervisor -> engine). No path,
# argument, environment value or option comes from the operator, the engine or
# configuration. The engine's reduction is then proven by the engine itself
# (isedraf.fullaudit, ENGINE_NOT_REDUCED) and on the lab corpus (OD-06).
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="launcher (root inside the Full Audit unit)"
# meta:mutates="none"
# meta:binaries="setpriv,python3"
# =============================================================================
"""The reduced engine's constant command and its start."""
import os
import subprocess

SETPRIV = "/usr/bin/setpriv"
PYTHON = "/usr/bin/python3"
INSTALL_ROOT = "/usr/lib"
ENGINE_ACCOUNT = "isedraf"
ENTRY = ("import sys; sys.path.insert(0, %r); from isedraf.fullaudit import main; "
         "sys.exit(main())" % INSTALL_ROOT)
ARGV = (SETPRIV, "--reuid=" + ENGINE_ACCOUNT, "--regid=" + ENGINE_ACCOUNT, "--clear-groups",
        "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs",
        PYTHON, "-IB", "-c", ENTRY)
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

# EXEC-020, AUTH-027: a failed run's staging holds files the engine identity owns, which
# root cannot remove without a capability the route does not have. They are removed by the
# same reduced identity, from inside the staging, with the same constant reduction.
CLEAN_ENTRY = ("import os, shutil\n"
               "for name in os.listdir('.'):\n"
               "    if os.path.isdir(name) and not os.path.islink(name):\n"
               "        shutil.rmtree(name)\n"
               "    else:\n"
               "        os.unlink(name)\n")
CLEAN_ARGV = ARGV[:9] + ("-IB", "-c", CLEAN_ENTRY)
REQUEST_FD = 3
RESPONSE_FD = 4


def clean(staging):
    """Empty a staging as the reduced engine identity. Returns its exit code."""
    return subprocess.run(list(CLEAN_ARGV), cwd=staging, env=dict(ENVIRONMENT),
                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, close_fds=True, timeout=120,
                          shell=False).returncode


def start(staging, request_w, response_r):
    """Start the reduced engine in `staging` with the channel on fds 3 and 4."""
    def place():
        os.dup2(request_w, REQUEST_FD, inheritable=True)
        os.dup2(response_r, RESPONSE_FD, inheritable=True)

    return subprocess.Popen(list(ARGV), cwd=staging, env=dict(ENVIRONMENT),
                            stdin=subprocess.DEVNULL, close_fds=True,
                            pass_fds=(REQUEST_FD, RESPONSE_FD), preexec_fn=place,
                            shell=False)
