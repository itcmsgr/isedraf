# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Production tests for the W1-B identity vertical slice.
# Implements: IDENT-002, IDENT-003, IDENT-004, IDENT-005, NORM-039, NORM-042, PRIV-004,
#             SNAP-014, SNAP-018, SNAP-020, SNAP-021, SNAP-022, SNAP-023, SCOPE-071,
#             SCOPE-077, STORE-024, STORE-025
#
# The golden vectors are the ORACLE, never a runtime dependency: production code never
# reads them, and these tests compare production output against them byte for byte.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="temporary directories only"
# meta:binaries="git"
# =============================================================================

"""Unit, integration, golden-compatibility and independent-verification layers."""
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import ENGINE_VERSION, canonical, cli, identity, ledger, snapshot  # noqa: E402
from isedraf import stateroot, verify                                           # noqa: E402
from isedraf.exitcodes import INCOMPLETE, OK, PRIVILEGE_REFUSED                 # noqa: E402

VECTORS = ROOT / "test-vectors" / "w1a" / "v1"


def write_source(directory, data):
    path = os.path.join(directory, "machine-id")
    with open(path, "wb") as fh:
        fh.write(data)
    return path


class TestParser(unittest.TestCase):
    """IDENT-003 / IDENT-004, one row at a time."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def collect(self, data):
        return identity.collect(write_source(self.tmp, data))

    def test_valid(self):
        r = self.collect(b"7f8e9a0b1c2d3e4f5061728394a5b6c7")
        self.assertEqual(r.status, "COLLECTED")
        self.assertIsNone(r.reason)
        self.assertTrue(r.host_id.startswith("sha256:"))

    def test_optional_single_lf_normalizes_away(self):
        a = self.collect(b"7f8e9a0b1c2d3e4f5061728394a5b6c7")
        b = self.collect(b"7f8e9a0b1c2d3e4f5061728394a5b6c7\n")
        c = self.collect(b"7F8E9A0B1C2D3E4F5061728394A5B6C7\n")
        self.assertEqual(a.host_id, b.host_id)
        self.assertEqual(a.host_id, c.host_id)   # IDENT-003 lowercases
        self.assertEqual(a.state_canonical, c.state_canonical)

    def test_second_lf_is_rejected(self):
        self.assertEqual(self.collect(b"7f8e9a0b1c2d3e4f5061728394a5b6c7\n\n").reason,
                         "SYNTAX_REJECTED")

    def test_all_zero_rejected(self):
        r = self.collect(b"0" * 32 + b"\n")
        self.assertEqual((r.status, r.reason), ("ERROR", "SYNTAX_REJECTED"))

    def test_uninitialized_rejected(self):
        r = self.collect(b"uninitialized\n")
        self.assertEqual((r.status, r.reason), ("ERROR", "SYNTAX_REJECTED"))

    def test_over_long_is_source_unreadable_not_syntax(self):
        r = self.collect(b"7f8e9a0b1c2d3e4f5061728394a5b6c7\n" + b"x" * 5000)
        self.assertEqual((r.status, r.reason), ("ERROR", "SOURCE_UNREADABLE"))

    def test_non_utf8_is_syntax_rejected_not_base64(self):
        # NORM-042: IDENT-003's grammar decides; NORM-036 must not rescue these bytes.
        r = self.collect(b"7f8e9a0b1c2d3e4f5061728394a5b6\xff\xfe\n")
        self.assertEqual((r.status, r.reason), ("ERROR", "SYNTAX_REJECTED"))
        self.assertIsNone(r.state_canonical)

    def test_catch_all_row_5(self):
        """IDENT-004 row 5. An unanticipated failure becomes a named ERROR, never a pass."""
        import unittest.mock
        path = write_source(self.tmp, b"7f8e9a0b1c2d3e4f5061728394a5b6c7")
        with unittest.mock.patch.object(identity, "parse",
                                        side_effect=RuntimeError("unanticipated")):
            r = identity.collect(path)
        self.assertEqual((r.status, r.reason), ("ERROR", "INTERNAL_ERROR"))

    def test_missing_source(self):
        r = identity.collect(os.path.join(self.tmp, "absent"))
        self.assertEqual((r.status, r.reason), ("NOT_TESTED", "SOURCE_ABSENT"))

    def test_unreadable_source(self):
        path = write_source(self.tmp, b"7f8e9a0b1c2d3e4f5061728394a5b6c7")
        os.chmod(path, 0o000)
        if os.geteuid() == 0:                       # root ignores the mode
            self.skipTest("permission semantics are not observable as root")
        r = identity.collect(path)
        self.assertEqual((r.status, r.reason), ("ERROR", "SOURCE_UNREADABLE"))

    def test_directory_as_source(self):
        r = identity.collect(self.tmp)
        self.assertEqual((r.status, r.reason), ("ERROR", "SOURCE_UNREADABLE"))


class TestSnapId(unittest.TestCase):
    def test_engine_version_matches_the_version_file(self):
        self.assertEqual(ENGINE_VERSION, (ROOT / "VERSION").read_text().strip())

    def test_identifier_grammar(self):
        from isedraf import ids
        ts = ids.now_utc()
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        for prefix in ("SDS", "RUN", "EVT"):
            self.assertRegex(ids.new_id(prefix, ts), ids.ID_RE)

    def test_two_ids_differ(self):
        from isedraf import ids
        ts = ids.now_utc()
        self.assertNotEqual(ids.new_id("SDS", ts), ids.new_id("SDS", ts))


class TestHostIdRule(unittest.TestCase):
    """SNAP-023, at the point where the manifest is built."""

    def core(self, ident):
        return snapshot.manifest_core(ident, "SDS-20260918T142233Z-3f9a1c0b7d2e4a68",
                                      "RUN-20260918T142233Z-a1b2c3d4e5f60718",
                                      "2026-09-18T14:22:33Z", "DEV", ENGINE_VERSION)

    def test_collected_carries_the_string(self):
        ident = identity.Identity("COLLECTED", None, "7f8e9a0b1c2d3e4f5061728394a5b6c7")
        self.assertEqual(self.core(ident)["host_id"], ident.host_id)

    def test_non_collected_is_null_and_the_key_is_present(self):
        for status, reason in (("ERROR", "SYNTAX_REJECTED"),
                               ("NOT_TESTED", "SOURCE_ABSENT")):
            core = self.core(identity.Identity(status, reason))
            self.assertIn("host_id", core)
            self.assertIsNone(core["host_id"])

    def test_collected_without_host_id_is_refused_not_normalized(self):
        ident = identity.Identity("COLLECTED", None)     # no normalized value
        with self.assertRaises(ValueError):
            self.core(ident)

    def test_host_id_on_a_non_collected_section_is_refused(self):
        ident = identity.Identity("ERROR", "SYNTAX_REJECTED",
                                  "7f8e9a0b1c2d3e4f5061728394a5b6c7")
        ident.status = "ERROR"
        with self.assertRaises(ValueError):
            self.core(ident)


class TestStateRoot(unittest.TestCase):
    """PRIV-004 and SCOPE-071."""

    def test_root_is_refused(self):
        with self.assertRaises(stateroot.PrivilegeRefused):
            stateroot.resolve(environ={}, euid=0)

    def test_sudo_transition_is_refused(self):
        with self.assertRaises(stateroot.PrivilegeRefused):
            stateroot.resolve(environ={"SUDO_USER": "someone"}, euid=1000)

    def test_override_is_refused_under_sudo_even_unprivileged(self):
        with self.assertRaises(stateroot.PrivilegeRefused):
            stateroot.resolve(environ={"SUDO_USER": "someone",
                                       "ISEDRAF_STATE_ROOT": "/tmp/x"}, euid=1000)

    def test_w1_has_no_production_mode_and_says_so(self):
        """IQ-010. SCOPE-070 puts W1 under ISEDRAF_STATE_ROOT; Mode A owns the production
        root and is deferred by SCOPE-072. Falling back to it would offer a mode this
        slice cannot reach, and fail later with a bare permission error."""
        with self.assertRaises(stateroot.StateRootError) as caught:
            stateroot.resolve(environ={}, euid=1000)
        message = str(caught.exception)
        self.assertIn("SCOPE-070", message)
        self.assertIn("SCOPE-072", message)
        self.assertIn(stateroot.ENV_STATE_ROOT, message)

    def test_override_marks_dev(self):
        path, cls = stateroot.resolve(environ={"ISEDRAF_STATE_ROOT": "/tmp/x"}, euid=1000)
        self.assertEqual((path, cls), ("/tmp/x", stateroot.DEV))

    def test_relative_override_is_refused(self):
        with self.assertRaises(stateroot.StateRootError):
            stateroot.resolve(environ={"ISEDRAF_STATE_ROOT": "relative"}, euid=1000)


class TestEndToEnd(unittest.TestCase):
    """collect -> snapshot -> ledger -> verify -> render, through the real CLI path."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "state")
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        self._environ = dict(os.environ)
        os.environ["ISEDRAF_STATE_ROOT"] = self.root
        os.environ.pop("SUDO_USER", None)
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._environ)

    def run_cli(self, data=b"7f8e9a0b1c2d3e4f5061728394a5b6c7\n"):
        source = write_source(self.src, data) if data is not None \
            else os.path.join(self.src, "absent")
        out, err = io.StringIO(), io.StringIO()
        args = type("A", (), {"source": source})()
        code = cli.cmd_identity(args, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def test_collected_run(self):
        code, out, _ = self.run_cli()
        self.assertEqual(code, OK)
        self.assertIn("COLLECTED", out)
        self.assertIn("sha256:", out)
        self.assertEqual(verify.verify_store(self.root), [])

    def test_raw_machine_id_is_never_rendered(self):
        code, out, _ = self.run_cli()
        self.assertEqual(code, OK)
        self.assertNotIn("7f8e9a0b1c2d3e4f5061728394a5b6c7", out)

    def test_incomplete_run_still_commits_and_exits_2(self):
        code, out, _ = self.run_cli(None)
        self.assertEqual(code, INCOMPLETE)
        self.assertIn("NOT_TESTED", out)
        self.assertIn("SOURCE_ABSENT", out)
        snapshots = os.listdir(os.path.join(self.root, "snapshots"))
        self.assertEqual(len(snapshots), 1)
        self.assertFalse(os.path.exists(os.path.join(
            self.root, "snapshots", snapshots[0], "state")))
        self.assertEqual(verify.verify_store(self.root), [])

    def test_layout_and_permissions(self):
        self.run_cli()
        self.assertEqual(os.stat(self.root).st_mode & 0o777, 0o700)
        for name in stateroot.W1A_DIRECTORIES:
            self.assertEqual(os.stat(os.path.join(self.root, name)).st_mode & 0o777,
                             0o700)
        # STORE-025: W1-A creates ONLY these.
        for absent in ("baselines", "evaluations", "acceptances", "reports", "exports"):
            self.assertFalse(os.path.exists(os.path.join(self.root, absent)))
        snap = os.path.join(self.root, "snapshots",
                            os.listdir(os.path.join(self.root, "snapshots"))[0])
        self.assertEqual(os.stat(os.path.join(snap, "manifest.json")).st_mode & 0o777,
                         0o600)
        self.assertEqual(sorted(os.listdir(snap)),
                         ["manifest.json", "method", "state"])   # SNAP-021

    def test_every_artifact_carries_the_dev_marker(self):
        """PRIV-004: artifacts from a development state root are marked, always."""
        self.run_cli()
        base = os.path.join(self.root, "snapshots")
        snap = os.path.join(base, os.listdir(base)[0])
        with open(os.path.join(snap, "manifest.json"), "rb") as fh:
            envelope = json.load(fh)
        self.assertEqual(envelope["manifest_core"]["state_root"], stateroot.DEV)
        record = ledger.read_records(self.root)[0]
        self.assertEqual(record["record_core"]["state_root"], stateroot.DEV)

    def test_chaining_across_runs(self):
        for _ in range(3):
            self.assertEqual(self.run_cli()[0], OK)
        records = ledger.read_records(self.root)
        self.assertEqual([r["record_core"]["sequence"] for r in records], [1, 2, 3])
        self.assertEqual(records[0]["record_core"]["previous_record_hash"],
                         ledger.GENESIS_PREVIOUS)
        for a, b in zip(records, records[1:]):
            self.assertEqual(b["record_core"]["previous_record_hash"], a["record_hash"])
        self.assertEqual(verify.verify_store(self.root), [])

    def test_idle_runs_produce_identical_state(self):
        self.run_cli()
        self.run_cli()
        digests = set()
        base = os.path.join(self.root, "snapshots")
        for name in os.listdir(base):
            with open(os.path.join(base, name, "state", "host_identity.json"), "rb") as f:
                digests.add(f.read())
        self.assertEqual(len(digests), 1, "an unchanged host produced two state objects")

    def test_store_discontinuity_refuses(self):
        self.run_cli()
        base = os.path.join(self.root, "snapshots")
        original = os.path.join(base, os.listdir(base)[0])
        for suffix in ("aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"):
            shutil.copytree(original, os.path.join(
                base, "SDS-20260101T000000Z-" + suffix))
        code, _, err = self.run_cli()
        self.assertEqual(code, INCOMPLETE)          # SNAP-018 + SCOPE-077
        self.assertIn("STORE_DISCONTINUITY", err)

    def test_privileged_execution_is_refused(self):
        os.environ["SUDO_USER"] = "someone"
        code, _, err = self.run_cli()
        self.assertEqual(code, PRIVILEGE_REFUSED)
        self.assertIn("does not yet support privileged execution", err)

    def test_corrupted_evidence_is_reported_not_rendered_as_success(self):
        self.run_cli()
        base = os.path.join(self.root, "snapshots")
        snap = os.path.join(base, os.listdir(base)[0])
        state = os.path.join(snap, "state", "host_identity.json")
        os.chmod(state, 0o600)
        with open(state, "wb") as fh:
            fh.write(canonical.canonical_bytes({"host_id": "sha256:" + "a" * 64}))
        self.assertNotEqual(verify.verify_store(self.root), [])


class TestGoldenCompatibility(unittest.TestCase):
    """NORM-039. Production output must equal the certified expected bytes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def cases(self):
        for case in sorted(p for p in VECTORS.iterdir() if p.is_dir()):
            if case.name.startswith(("S1-", "D1-")):
                continue
            yield case

    def produce(self, case):
        """Run PRODUCTION code over the vector's input, using the vector's fixture."""
        fixture = json.loads((case / "input" / "fixture.json").read_text())
        source = case / "input" / "machine-id.bin"
        if source.exists():
            path = os.path.join(self.tmp, case.name)
            os.makedirs(path, exist_ok=True)
            path = os.path.join(path, "machine-id")
            with open(path, "wb") as fh:
                fh.write(source.read_bytes())
        else:
            path = os.path.join(self.tmp, "does-not-exist")
        ident = identity.collect(path)
        built = snapshot.build(ident, fixture["snapshot_id"], fixture["run_id"],
                               fixture["created_at"], fixture["state_root"],
                               fixture["engine_version"])
        core = {
            "ledger_schema_version": ledger.LEDGER_SCHEMA_VERSION,
            "sequence": 1,
            "event": ledger.EVENT_SNAPSHOT_COMMITTED,
            "event_id": fixture["event_id"],
            "occurred_at": fixture["occurred_at"],
            "previous_record_hash": ledger.GENESIS_PREVIOUS,
            "snapshot_id": fixture["snapshot_id"],
            "manifest_hash": built["manifest_hash"],
            "state_root": fixture["state_root"],
        }
        core_canonical = canonical.canonical_bytes(core)
        record_hash = canonical.rendered(
            canonical.hash_frame(canonical.DOMAIN_LEDGER_RECORD, core_canonical))
        return ident, built, core, core_canonical, record_hash

    def test_every_case_matches_the_certified_bytes(self):
        checked = 0
        for case in self.cases():
            ident, built, core, core_canonical, record_hash = self.produce(case)
            e = case / "expected"
            with self.subTest(case=case.name):
                self.assertEqual(ident.status, (e / "status.txt").read_text().strip())
                reason_file = e / "reason.txt"
                if ident.reason is None:
                    self.assertFalse(reason_file.exists())      # NORM-040
                else:
                    self.assertEqual(reason_file.read_bytes(),
                                     ident.reason.encode() + b"\n")
                if ident.collected:
                    self.assertEqual((e / "normalized-machine-id.bin").read_bytes(),
                                     ident.normalized.encode("ascii"))
                    self.assertEqual((e / "host-id.txt").read_text().strip(),
                                     ident.host_id)
                    self.assertEqual((e / "state.canonical").read_bytes(),
                                     ident.state_canonical)
                    self.assertEqual((e / "state.sha256").read_text().strip(),
                                     ident.state_hash)
                else:
                    self.assertFalse((e / "state.canonical").exists())
                self.assertEqual((e / "method.canonical").read_bytes(), built["method"])
                self.assertEqual((e / "manifest-core.canonical").read_bytes(),
                                 built["manifest_core_canonical"])
                self.assertEqual((e / "manifest-hash.txt").read_text().strip(),
                                 built["manifest_hash"])
                self.assertEqual((e / "manifest.json").read_bytes(), built["manifest"])
                self.assertEqual((e / "record-core.canonical").read_bytes(),
                                 core_canonical)
                self.assertEqual((e / "record-hash.txt").read_text().strip(), record_hash)
                self.assertEqual((e / "record.json").read_bytes(),
                                 canonical.canonical_bytes(
                                     {"record_core": core, "record_hash": record_hash}))
            checked += 1
        self.assertGreaterEqual(checked, 13)

    def test_production_artifacts_satisfy_the_independent_verifier(self):
        """The certified W1-A verifier, unmodified, applied to PRODUCTION output.

        The corpus is copied, one case's expected/ is rebuilt entirely from production
        code, EXPECTED.sha256 is regenerated so no checksum can be what passes it, and
        scripts/vectors/verify.py is pointed at the copy.
        """
        import hashlib
        work = os.path.join(self.tmp, "corpus")
        shutil.copytree(str(VECTORS), os.path.join(work, "w1a", "v1"))
        v = pathlib.Path(work) / "w1a" / "v1"
        for case in self.cases():
            ident, built, core, core_canonical, record_hash = self.produce(case)
            e = v / case.name / "expected"
            shutil.rmtree(str(e))
            e.mkdir(parents=True)
            (e / "status.txt").write_text(ident.status + "\n")
            if ident.reason is not None:
                (e / "reason.txt").write_text(ident.reason + "\n")
            if ident.collected:
                (e / "normalized-machine-id.bin").write_bytes(
                    ident.normalized.encode("ascii"))
                (e / "host-id.txt").write_text(ident.host_id + "\n")
                (e / "state.canonical").write_bytes(ident.state_canonical)
                (e / "state.sha256").write_text(ident.state_hash + "\n")
            (e / "method.canonical").write_bytes(built["method"])
            (e / "manifest-core.canonical").write_bytes(built["manifest_core_canonical"])
            (e / "manifest-hash.txt").write_text(built["manifest_hash"] + "\n")
            (e / "manifest.json").write_bytes(built["manifest"])
            (e / "record-core.canonical").write_bytes(core_canonical)
            (e / "record-hash.txt").write_text(record_hash + "\n")
            (e / "record.json").write_bytes(canonical.canonical_bytes(
                {"record_core": core, "record_hash": record_hash}))
        lines = ["%s  %s" % (hashlib.sha256(f.read_bytes()).hexdigest(),
                             f.relative_to(v))
                 for f in sorted(v.rglob("*"))
                 if f.is_file() and f.name != "EXPECTED.sha256"]
        (v / "EXPECTED.sha256").write_text("\n".join(sorted(lines)) + "\n")

        source = (ROOT / "scripts" / "vectors" / "verify.py").read_text()
        patched = source.replace('ROOT / "test-vectors"',
                                 'pathlib.Path("%s")' % work)
        self.assertNotEqual(patched, source, "verifier redirection anchor missing")
        script = os.path.join(self.tmp, "independent_verify.py")
        with open(script, "w") as fh:
            fh.write(patched)
        result = subprocess.run([sys.executable, script], cwd=str(ROOT),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0,
                         "independent verifier rejected production output:\n%s%s"
                         % (result.stdout, result.stderr))


class TestProbePortability(unittest.TestCase):
    """The compatibility probe must parse under the OLDEST interpreter it must report on.

    RHEL 8's default python3 is 3.6. A probe that needs 3.9 cannot tell us whether a host
    has 3.9 — it just crashes, and the tier goes unrecorded. This asserts the probe avoids
    syntax introduced after 3.6, which is checkable without having 3.6 installed.
    """

    def test_probe_avoids_post_3_6_syntax(self):
        import ast
        tree = ast.parse((ROOT / "scripts" / "compat" / "probe.py").read_text())
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, getattr(ast, "NamedExpr", ()),
                                     "walrus operator is 3.8+")
            self.assertNotIsInstance(node, getattr(ast, "Match", ()),
                                     "match statement is 3.10+")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.assertFalse(getattr(node.args, "posonlyargs", []),
                                 "positional-only parameters are 3.8+")

    def test_probe_spawns_no_subprocess(self):
        """It runs on production hosts. It reads files and executes nothing.

        Checked against the parsed CODE, not the raw text: the file's own header
        explains that it spawns no subprocess, and a substring search would match
        the explanation and call it a violation.
        """
        import ast
        tree = ast.parse((ROOT / "scripts" / "compat" / "probe.py").read_text())
        banned_modules = {"subprocess", "shutil", "socket", "urllib", "http"}
        banned_calls = {"system", "popen", "execv", "execve", "execvp", "spawnv"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name.split(".")[0], banned_modules)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn((node.module or "").split(".")[0], banned_modules)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, banned_calls)

    def test_probe_never_exports_an_identifier(self):
        """A portability record must not carry a host identifier off the host."""
        import ast
        source = (ROOT / "scripts" / "compat" / "probe.py").read_text()
        tree = ast.parse(source)
        keys = {n.value for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        self.assertIn("expected_status", keys)
        self.assertNotIn("host_id", keys)
        self.assertNotIn("machine_id_value", keys)
        self.assertNotIn("hashlib", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
