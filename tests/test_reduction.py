# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The engine proves its own reduction; the launcher starts it by a constant command.
# Implements: AUTH-020, AUTH-021, AUTH-027, AUTH-006
#
# v0.2 P5b-2. Unprivileged. The reduction rule is held against synthetic /proc/self/status
# texts; the real reduction through setpriv was measured on the lab corpus by the P5b spike
# and is proven again end to end in P6. The engine's bundle is built from fixtures, never
# from the machine running the test.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""v0.2 P5b-2: engine reduction self-check, constant engine command, staged bundle."""
import io
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, HERE)

from isedraf import audit, fullaudit, identity, snapshot           # noqa: E402

collect_real = audit.collect
from isedraf.launcher import engine, store                         # noqa: E402
import test_evidence_limits as fixtures                            # noqa: E402

PASSWD = "root:x:0:0:root:/root:/bin/sh\nisedraf:x:991:990::/:/usr/sbin/nologin\n"
ZERO = "0000000000000000"


def status(**change):
    fields = {"Uid": "991\t991\t991\t991", "Gid": "990\t990\t990\t990", "Groups": "",
              "CapInh": ZERO, "CapPrm": ZERO, "CapEff": ZERO, "CapBnd": ZERO,
              "CapAmb": ZERO, "NoNewPrivs": "1"}
    fields.update(change)
    return "Name:\tpython3\n" + "".join("%s:\t%s\n" % kv for kv in fields.items())


class TheEngineProvesItsReduction(unittest.TestCase):

    def test_a_reduced_engine_passes(self):
        self.assertEqual(fullaudit.reduction_problems(status(), PASSWD), [])

    def test_every_departure_is_named(self):
        for change in ({"Uid": "0\t0\t0\t0"}, {"Uid": "991\t0\t991\t991"},
                       {"Gid": "0\t0\t0\t0"}, {"Groups": "4 27"},
                       {"CapInh": "0000000000000001"}, {"CapPrm": "00000000000001c4"},
                       {"CapEff": "0000000000000004"}, {"CapBnd": "000001ffffffffff"},
                       {"CapAmb": "0000000000000080"}, {"NoNewPrivs": "0"},
                       {"Uid": "992\t992\t992\t992"}):
            self.assertTrue(fullaudit.reduction_problems(status(**change), PASSWD), change)

    def test_a_missing_field_is_not_a_reduction(self):
        text = "".join(l + "\n" for l in status().splitlines() if not l.startswith("CapBnd"))
        self.assertTrue(fullaudit.reduction_problems(text, PASSWD))

    def test_the_account_must_exist_exactly_once(self):
        self.assertTrue(fullaudit.reduction_problems(status(), "root:x:0:0::/:/bin/sh\n"))
        self.assertTrue(fullaudit.reduction_problems(status(), PASSWD + PASSWD.splitlines()[1]
                                                     + "\n"))

    def test_this_unprivileged_test_process_is_not_reduced(self):
        with open("/proc/self/status") as fh:
            self.assertTrue(fullaudit.reduction_problems(fh.read(), PASSWD))


class TheEngineCommandIsConstant(unittest.TestCase):

    def test_the_command_reduces_everything(self):
        self.assertEqual(engine.ARGV[:8], (
            "/usr/bin/setpriv", "--reuid=isedraf", "--regid=isedraf", "--clear-groups",
            "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs"))
        self.assertEqual(engine.ARGV[8:11], ("/usr/bin/python3", "-IB", "-c"))
        self.assertIn("from isedraf.fullaudit import main", engine.ARGV[11])
        self.assertEqual(len(engine.ARGV), 12)

    def test_every_executable_is_absolute_and_nothing_names_a_capability(self):
        self.assertTrue(engine.SETPRIV.startswith("/") and engine.PYTHON.startswith("/"))
        for arg in engine.ARGV:
            self.assertNotIn("CAP_", arg)

    def test_the_environment_is_exec011_only(self):
        self.assertEqual(engine.ENVIRONMENT,
                         {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})

    def test_start_takes_no_command_argument(self):
        import inspect
        self.assertEqual(list(inspect.signature(engine.start).parameters),
                         ["staging", "request_w", "response_r"])


class TheEngineSeesOnlyItsChannel(unittest.TestCase):

    def test_stdio_and_fds_3_and_4_cwd_and_environment(self):
        staging = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, staging, True)
        probe = ("import os, json; os.write(3, json.dumps({'fds': sorted(os.listdir("
                 "'/proc/self/fd')), 'stdin': os.readlink('/proc/self/fd/0'), 'cwd': os.getcwd(),"
                 " 'env': dict(os.environ), 'got': os.read(4, 64).decode()}).encode()); os.close(3)")
        req_r, req_w = os.pipe()
        resp_r, resp_w = os.pipe()
        with mock.patch.object(engine, "ARGV", (sys.executable, "-IB", "-c", probe)), \
                mock.patch.dict(os.environ, {"ISEDRAF_LEAK": "1"}):
            proc = engine.start(staging, req_w, resp_r)
        os.close(req_w)
        os.close(resp_r)
        os.write(resp_w, b"answer")
        os.close(resp_w)
        raw = b""
        while True:
            chunk = os.read(req_r, 65536)
            if not chunk:
                break
            raw += chunk
        os.close(req_r)
        self.assertEqual(proc.wait(timeout=30), 0)
        import json
        seen = json.loads(raw.decode())
        self.assertEqual(seen["got"], "answer")
        self.assertEqual(seen["stdin"], "/dev/null")
        self.assertEqual(os.path.realpath(seen["cwd"]), os.path.realpath(staging))
        self.assertEqual(seen["env"], engine.ENVIRONMENT)
        self.assertLessEqual(set(seen["fds"]), {"0", "1", "2", "3", "4", "5"})
        self.assertTrue({"3", "4"} <= set(seen["fds"]))


class TheCleanupIsReducedToo(unittest.TestCase):

    def test_the_cleanup_command_is_the_same_reduction(self):
        self.assertEqual(engine.CLEAN_ARGV[:9], engine.ARGV[:9])

    def test_the_cleanup_sees_only_the_exec011_environment(self):
        staging = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, staging, True)
        probe = ("import os, json; open('env.json', 'w').write(json.dumps(dict(os.environ)))")
        with mock.patch.object(engine, "CLEAN_ARGV", (sys.executable, "-IB", "-c", probe)), \
                mock.patch.dict(os.environ, {"ISEDRAF_LEAK": "1"}):
            self.assertEqual(engine.clean(staging), 0)
        import json
        with open(os.path.join(staging, "env.json")) as fh:
            self.assertEqual(json.load(fh), engine.ENVIRONMENT)


class TheEngineBuildsTheStagedBundle(fixtures.Host):

    def setUp(self):
        super().setUp()
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        _ts, _s, self.run_id, _e = snapshot.new_ids()
        self.staging = os.path.join(base, self.run_id)
        os.mkdir(self.staging, 0o700)
        os.chmod(self.staging, store.STAGING_MODE)
        cwd = os.getcwd()
        os.chdir(self.staging)
        self.addCleanup(os.chdir, cwd)
        collect, ident, limits = audit.collect, identity.collect, audit.evidence_limits
        host = self.host
        for target, name, value in (
                (audit, "collect", lambda root, channel=None, sandboxed=False: collect(host)),
                (identity, "collect", lambda path: ident(os.path.join(host, "etc/machine-id"))),
                (audit, "evidence_limits", lambda sections, root: limits(sections, host))):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_engine(self, problems):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(fullaudit, "reduction_problems", lambda *a: problems):
            code = fullaudit.run(out, err)
        return code, err.getvalue()

    def test_an_unreduced_engine_writes_nothing(self):
        code, err = self.run_engine(["CapBnd is not empty"])
        self.assertEqual(code, 64)
        self.assertIn("ENGINE_NOT_REDUCED", err)
        self.assertEqual(os.listdir(self.staging), [])

    def test_a_reduced_engine_stages_a_bundle_the_launcher_accepts(self):
        code, err = self.run_engine([])
        self.assertIn(code, (0, 2), err)
        with mock.patch.object(store, "OWNER_UID", os.getuid()), \
                mock.patch.object(store, "OWNER_GID", os.getgid()):
            envelope = store.check_staged(self.staging, os.getuid(), self.run_id)
        core = envelope["manifest_core"]
        self.assertEqual((core["run_mode"], core["state_root"]), ("FULL_AUDIT", "SYSTEM_PRODUCTION"))

    def test_the_engine_hands_its_channel_to_the_collectors(self):
        # AUTH-024: the Full Audit route is what makes read_shadow_v1 reachable.
        seen = []
        marker = object()
        with mock.patch.object(audit, "collect",
                               lambda root, channel=None, sandboxed=False: (seen.append((channel, sandboxed)),
                                                           collect_real(self.host))[1]):
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(fullaudit, "reduction_problems", lambda *a: []):
                fullaudit.run(out, err, channel=marker)
        self.assertEqual(seen, [(marker, True)])

    def test_outside_a_run_staging_the_engine_refuses(self):
        os.chdir(os.path.dirname(self.staging))
        code, err = self.run_engine([])
        self.assertEqual(code, 64)


if __name__ == "__main__":
    unittest.main()
