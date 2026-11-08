# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: `sudo isedraf evaluate` - the system-store evaluation route, without root.
# Implements: AUTH-033, AUTH-019, AUTH-022, AUTH-032, D-126, EVAL-005, EVAL-006, EVAL-007
#
# The root side (evalunit) runs in-process against a store built by a real audit, with the
# store owner patched to the test user; the reduced evaluator runs as a real subprocess,
# exactly as the unit starts it except for the setpriv reduction, which needs root.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================
"""AUTH-033: read as the report route does, evaluate reduced, promote under a closed contract."""
import fcntl
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.abspath(os.path.join(HERE, "..", "lib"))
sys.path.insert(0, LIB)

from isedraf import ENGINE_VERSION, canonical, cli, ledger, stateroot      # noqa: E402
from isedraf.evaluate import record, run as evaluate_run                  # noqa: E402
from isedraf.launcher import evalunit, outer, renderer, reportunit, store  # noqa: E402
from isedraf.supervisor import frame                                      # noqa: E402

HOST = {"etc/machine-id": "3f9a1c0b7d2e4a68b5c6d7e8f9a0b1c2\n",
        "etc/passwd": "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/a:/bin/sh\n",
        "etc/group": "root:x:0:\nalice:x:1000:\n",
        "etc/shadow": "root:*:19000:0:99999:7:::\nalice:!:19000::::::\n",
        "etc/nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\n",
        "proc/sys/kernel/hostname": "fixturehost\n"}
UID, GID = os.getuid(), os.getgid()
CLASS = stateroot.DEV            # the fixture store's class; the route's constant is patched


def evaluator_argv(log):
    """The reduced evaluator as the unit starts it, minus setpriv (which needs root). Its
    stderr - relayed to the operator in the unit - goes to `log` so a test can read it."""
    return [sys.executable, "-IB", "-c",
            "import sys; sys.path.insert(0, %r); sys.stderr = open(%r, 'w'); "
            "from isedraf.launcher import evalunit, evaluator; evalunit.CLASS = %r; "
            "evaluator.reduction_check = lambda: []; "
            "sys.exit(evaluator.main([]))" % (LIB, log, CLASS)]


def private_catalog(testcase):
    """The root side reads the catalog only from a root-owned file that is not group- or
    world-writable. A checkout made under umask 002 is group-writable, so the tests hand the
    root side a 0644 copy of the same bytes rather than depend on the developer's umask."""
    from isedraf import catalog
    from isedraf.launcher import evalunit
    base = tempfile.mkdtemp()
    testcase.addCleanup(shutil.rmtree, base, True)
    copy = os.path.join(base, "native_controls.json")
    shutil.copyfile(catalog.REGISTRY, copy)
    os.chmod(copy, 0o644)
    real = evalunit.read_catalog
    patch = mock.patch.object(evalunit, "read_catalog", lambda path=None: real(copy))
    patch.start()
    testcase.addCleanup(patch.stop)


class NoLeakedPipe(object):
    """Mixin: a route whose child exits early must not leak the pipe it was fed through."""

    def assertNoResourceWarning(self, call):
        import gc
        import warnings
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            result = call()
            gc.collect()
        leaks = [w for w in caught if issubclass(w.category, ResourceWarning)]
        self.assertEqual(leaks, [], [str(w.message) for w in leaks])
        return result


def fingerprint(root, under=("snapshots", "ledger")):
    out = []
    for top in under:
        for base, dirs, files in os.walk(os.path.join(root, top)):
            dirs.sort()
            for name in sorted(dirs + files):
                path = os.path.join(base, name)
                st = os.lstat(path)
                digest = ""
                if os.path.isfile(path):
                    with open(path, "rb") as fh:
                        digest = hashlib.sha256(fh.read()).hexdigest()
                out.append((os.path.relpath(path, root), st.st_mode, st.st_mtime_ns, digest))
    return out


class Route(NoLeakedPipe, unittest.TestCase):

    def setUp(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        host = os.path.join(base, "host")
        for rel, text in HOST.items():
            path = os.path.join(host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        self.root = os.path.join(base, "root")
        with mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.root}):
            code = cli.cmd_audit(type("A", (), {"root": host})(), out=io.StringIO(),
                                 err=io.StringIO())
        self.assertIn(code, (0, 2))
        for patch in (mock.patch.object(store, "OWNER_UID", UID),
                      mock.patch.object(store, "OWNER_GID", GID),
                      mock.patch.object(evalunit, "CLASS", CLASS)):
            patch.start()
            self.addCleanup(patch.stop)
        private_catalog(self)
        del evalunit._stop[:]

    def evaluate(self, argv=None):
        out, err = io.StringIO(), io.StringIO()
        log = os.path.join(os.path.dirname(self.root), "evaluator.log")
        code = evalunit.run(self.root, err, out, engine_uid=UID, argv=argv or evaluator_argv(log))
        reduced = ""
        if os.path.exists(log):
            with open(log) as fh:
                reduced = fh.read()
            os.unlink(log)
        return code, out.getvalue(), err.getvalue() + reduced

    def evaluations(self):
        base = os.path.join(self.root, "evaluations")
        return sorted(os.listdir(base)) if os.path.isdir(base) else []

    def committed(self):
        (name,) = self.evaluations()
        base = os.path.join(self.root, "evaluations", name)
        out = {}
        for n in sorted(os.listdir(base)):
            with open(os.path.join(base, n), "rb") as fh:
                out[n] = fh.read()
        return name, out

    def answer(self):
        """A genuine evaluator answer for the store, and the identity root expects."""
        items = reportunit.acquire(self.root, UID)
        catalog_bytes = evalunit.read_catalog()
        sid, the_key, evl_id = evalunit.expected_identity(items, catalog_bytes)
        evl, raw, _results = evaluate_run.build(self.root, CLASS, ENGINE_VERSION)
        self.assertEqual(evl, evl_id)
        return raw, sid, the_key, evl_id

    @staticmethod
    def encode(raw):
        return frame.encode([frame.item(frame.ENTRY, n.encode("ascii"), frame.READ_OK,
                                        {"mode": 0o100600, "uid": UID, "gid": GID,
                                         "size": len(b)}, b) for n, b in sorted(raw.items())])

    # -- the route ----------------------------------------------------------------------

    def test_the_outer_entry_runs_the_evaluation_unit_with_the_audit_properties(self):
        argv = outer.evaluate_unit_argv("RUN-20261102T000000Z-0123456789abcdef")
        self.assertTrue(argv[5].startswith("--unit=isedraf-evaluate-RUN-"))
        for prop in outer.PROPERTIES:
            self.assertIn(prop, argv)
        self.assertIn("ReadWritePaths=-/var/lib/isedraf", argv)
        self.assertEqual(argv[-1], "RUN-20261102T000000Z-0123456789abcdef")
        self.assertIn("isedraf.launcher.evalunit", argv[-2])
        with self.assertRaises(ValueError):
            outer.evaluate_unit_argv("/var/lib/isedraf")

    def test_the_evaluator_command_is_the_engine_reduction_and_a_fixed_entry(self):
        argv = evalunit.evaluate_argv()
        self.assertEqual(argv[:9], ["/usr/bin/setpriv", "--reuid=isedraf", "--regid=isedraf",
                                    "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
                                    "--bounding-set=-all", "--no-new-privs", "/usr/bin/python3"])
        self.assertIn("isedraf.launcher.evaluator", argv[-1])

    def test_an_evaluation_is_committed_root_owned_and_identical_to_the_user_route(self):
        before = fingerprint(self.root)
        code, out, err = self.evaluate()
        self.assertEqual(code, 0, err)
        self.assertIn("committed in the system store", out)
        self.assertIn("ISE-ACCOUNT-001", err)              # the reduced side's summary
        name, files = self.committed()
        raw, _sid, _key, evl_id = self.answer()
        self.assertEqual(name, evl_id)
        self.assertEqual(files, raw)                         # the same bytes as `isedraf evaluate`
        base = os.path.join(self.root, "evaluations", name)
        self.assertEqual(os.stat(base).st_mode & 0o777, 0o700)
        self.assertEqual({os.stat(os.path.join(base, n)).st_mode & 0o777 for n in files}, {0o600})
        self.assertEqual(fingerprint(self.root), before)   # snapshot and ledger untouched
        self.assertEqual(os.listdir(os.path.join(self.root, "tmp")), [])

    def test_a_second_evaluation_is_a_no_op(self):
        self.assertEqual(self.evaluate()[0], 0)
        first = self.committed()
        code, out, _err = self.evaluate()
        self.assertEqual(code, 0)
        self.assertIn("already committed, identical", out)
        self.assertEqual(self.committed(), first)

    def test_a_different_evaluation_under_the_same_identity_is_never_overwritten(self):
        self.assertEqual(self.evaluate()[0], 0)
        name, files = self.committed()
        path = os.path.join(self.root, "evaluations", name, "results.json")
        os.chmod(path, 0o600)
        with open(path, "ab") as fh:
            fh.write(b" ")
        code, _out, err = self.evaluate()
        self.assertEqual(code, 64)
        self.assertIn("never overwritten", err)

    def test_evidence_that_does_not_verify_writes_nothing(self):
        sid = ledger.read_records(self.root)[-1]["record_core"]["snapshot_id"]
        path = os.path.join(self.root, "snapshots", sid, "sections", "accounts.json")
        os.chmod(path, 0o600)
        with open(path, "ab") as fh:
            fh.write(b" ")
        code, _out, err = self.evaluate()
        self.assertEqual(code, 64)
        self.assertIn("EVIDENCE_VERIFICATION_FAILED", err)
        self.assertEqual(self.evaluations(), [])

    def test_a_held_lock_is_66_and_a_non_conforming_store_is_67(self):
        fd = os.open(os.path.join(self.root, stateroot.LOCK_NAME), os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(self.evaluate()[0], 66)
        os.close(fd)
        os.chmod(self.root, 0o755)
        self.assertEqual(self.evaluate()[0], 67)
        self.assertEqual(os.stat(self.root).st_mode & 0o777, 0o755)
        os.chmod(self.root, 0o700)
        self.assertEqual(self.evaluations(), [])

    def test_a_stop_before_the_first_write_promotes_nothing(self):
        evalunit._stop.append(15)
        self.assertEqual(self.evaluate()[0], evalunit.INTERRUPTED)
        self.assertEqual(self.evaluations(), [])

    def test_an_evaluator_that_is_not_reduced_refuses_and_nothing_is_written(self):
        # The test user is not the isedraf account with empty capability sets: the real
        # check, unpatched, must refuse (AUTH-020, as AUTH-033 requires).
        log = os.path.join(os.path.dirname(self.root), "unreduced.log")
        argv = [sys.executable, "-IB", "-c",
                "import sys; sys.path.insert(0, %r); sys.stderr = open(%r, 'w'); "
                "from isedraf.launcher import evaluator; sys.exit(evaluator.main([]))" % (LIB, log)]
        code, _out, _err = self.evaluate(argv=argv)
        self.assertEqual(code, 64)
        with open(log) as fh:
            self.assertIn("ENGINE_NOT_REDUCED", fh.read())
        self.assertEqual(self.evaluations(), [])

    def test_an_evaluator_that_fails_promotes_nothing(self):
        # Regression (2026-11-05): the pipe to an evaluator that exits early is closed.
        code, _out, _err = self.assertNoResourceWarning(
            lambda: self.evaluate(argv=[sys.executable, "-c", "import sys; sys.exit(64)"]))
        self.assertEqual(code, 64)
        self.assertEqual(self.evaluations(), [])

    # -- the closed promotion contract --------------------------------------------------

    def test_the_genuine_answer_is_accepted(self):
        raw, sid, the_key, evl_id = self.answer()
        self.assertEqual(evalunit.check_answer(self.encode(raw), sid, the_key, evl_id, CLASS), raw)

    def test_every_departure_from_the_contract_is_refused(self):
        raw, sid, the_key, evl_id = self.answer()

        def rewrite(name, change):
            obj = json.loads(raw[name].decode("utf-8"))
            change(obj)
            out = dict(raw, **{name: canonical.canonical_bytes(obj)})
            return out

        bad = {
            "an extra artifact": dict(raw, **{"notes.json": b"{}\n"}),
            "a missing artifact": dict((n, b) for n, b in raw.items() if n != "changes.json"),
            "a path as a name": dict(dict((n, b) for n, b in raw.items() if n != "results.json"),
                                     **{"../ledger/x": raw["results.json"]}),
            "a non-canonical artifact": dict(raw, **{"findings.json": raw["findings.json"] + b" "}),
            "another evaluation identity": rewrite(
                "results.json", lambda o: o.update(evaluation_id="EVL-20261102T000000Z-0000000000000000")),
            "another snapshot": rewrite("changes.json", lambda o: o.update(snapshot_id="SDS-x")),
            "another class": rewrite("findings.json", lambda o: o.update(state_root="DEV-X")),
            "an artifact its manifest does not bind": rewrite(
                "results.json", lambda o: o.update(results=[])),
            "another key": rewrite("manifest.json", lambda o: o["key"].update(engine_version="9")),
        }
        for label, answer in bad.items():
            with self.assertRaises(evalunit.Refused, msg=label):
                evalunit.check_answer(self.encode(answer), sid, the_key, evl_id, CLASS)

    def test_the_identity_is_computed_by_root_not_taken_from_the_answer(self):
        raw, sid, the_key, evl_id = self.answer()
        other = "EVL-20261102T000000Z-0123456789abcdef"
        with self.assertRaises(evalunit.Refused):
            evalunit.check_answer(self.encode(raw), sid, the_key, other, CLASS)

    # -- the report route shows the committed evaluation and never makes one -----------

    def report(self):
        items = reportunit.acquire(self.root, UID)
        items += reportunit.acquire_evaluation(self.root, items)
        out, err = io.StringIO(), io.StringIO()
        code = renderer.render("json", frame.encode(items), out, err)
        return code, out.getvalue(), err.getvalue(), items

    def test_the_report_route_shows_the_committed_evaluation(self):
        code, out, err, items = self.report()
        self.assertIn(code, (0, 2), err)
        self.assertEqual(json.loads(out)["native_results"]["status"], "NO_EVALUATION")
        self.assertEqual(self.evaluate()[0], 0)
        before = fingerprint(self.root, ("snapshots", "ledger", "evaluations"))
        code, out, err, items = self.report()
        self.assertIn(code, (0, 2), err)
        native = json.loads(out)["native_results"]
        first = [r for r in native["results"] if r["criterion_id"] == "ISE-ACCOUNT-001"][0]
        self.assertEqual((native["status"], first["result"]), ("EVALUATED", "PASS"))
        self.assertEqual(sum(1 for i in items if i["name"].startswith(b"evaluations/")), 4)
        self.assertEqual(fingerprint(self.root, ("snapshots", "ledger", "evaluations")), before)

    def test_the_renderer_refuses_an_evaluation_name_outside_the_contract(self):
        self.assertEqual(self.evaluate()[0], 0)
        _code, _out, _err, items = self.report()
        for it in items:
            if it["name"].endswith(b"/changes.json"):
                it["name"] = it["name"].replace(b"changes.json", b"../../ledger/x")
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(renderer.render("json", frame.encode(items), out, err), 64)
        self.assertIn("REPORT_REFUSED", err.getvalue())


if __name__ == "__main__":
    unittest.main()
