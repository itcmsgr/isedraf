# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The snapshot records its run mode, and the verifier holds authority to it.
# Implements: D-124, AUTH-017, AUTH-018, AUTH-009
#
# v0.2 P5a. The run mode is set by the route, pairs with the state-root class, enters the
# manifest hash and never the state hash. The verifier refuses a run mode that does not
# pair with its class, a supervisor acquisition outside FULL_AUDIT or under an identifier
# that is not IMPLEMENTED, and an operation_id on a current-identity source. A snapshot
# without the field (W1-A, GA 0.1.x) still verifies and is never read as FULL_AUDIT.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""v0.2 P5a: run mode in manifest_core, and the AUTH-017/AUTH-018 verifier rules."""
import ast
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, HERE)

from isedraf import canonical, cli, identity, snapshot, stateroot, verify   # noqa: E402
import test_evidence_limits as fixtures                                       # noqa: E402

# IQ-059: an operation that is registered and not IMPLEMENTED, taken from the registry at run
# time rather than named, so a later slice cannot silently invalidate the test.
UNIMPLEMENTED = sorted(o["operation_id"] for o in json.load(open(os.path.join(
    HERE, "..", "scripts", "ci", "privileged_operations.json")))["operations"]
    if o["status"] != "IMPLEMENTED")[0]

IDS = ("SDS-20261007T000000Z-" + "a" * 16, "RUN-20261007T000000Z-" + "b" * 16,
       "2026-10-07T00:00:00Z")


class Built(fixtures.Host):

    def build(self, state_root_class="DEV", run_mode=None):
        ident = identity.collect(os.path.join(self.host, "etc/machine-id"))
        return snapshot.build(ident, IDS[0], IDS[1], IDS[2], state_root_class, "0.0.0",
                              run_mode=run_mode)

    def test_the_run_mode_moves_the_manifest_hash_and_never_the_state_hash(self):
        without, standard = self.build(), self.build(run_mode=stateroot.STANDARD_AUDIT)
        section = lambda b: b["manifest_core"]["sections"][snapshot.SECTION]["state_hash"]
        self.assertEqual(section(without), section(standard))
        self.assertEqual(without["state"], standard["state"])
        self.assertNotEqual(without["manifest_hash"], standard["manifest_hash"])
        self.assertNotIn("run_mode", without["manifest_core"])
        self.assertEqual(standard["manifest_core"]["run_mode"], "STANDARD_AUDIT")

    def test_full_audit_is_refused_for_an_unprivileged_class(self):
        for klass in ("DEV", "USER_PRODUCTION"):
            with self.assertRaises(ValueError):
                self.build(klass, stateroot.FULL_AUDIT)

    def test_standard_audit_is_refused_for_the_system_class(self):
        with self.assertRaises(ValueError):
            self.build("SYSTEM_PRODUCTION", stateroot.STANDARD_AUDIT)

    def test_an_unknown_run_mode_is_refused(self):
        with self.assertRaises(ValueError):
            self.build("DEV", "ROOT")


class Committed(fixtures.Host):
    """A real `isedraf audit` commit, then single-field tampering with honest rehashing,
    so that the rule under test is the only thing that can fail."""

    def setUp(self):
        super().setUp()
        state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, state, True)
        self.root = os.path.join(state, "r")
        with mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.root}):
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
                cli.main(["audit", "--root", self.host])
        snaps = os.path.join(self.root, "snapshots")
        self.snap = os.path.join(snaps, sorted(os.listdir(snaps))[0])
        self.err = err.getvalue()

    def envelope(self):
        with open(os.path.join(self.snap, "manifest.json"), "rb") as fh:
            return json.loads(fh.read())

    def rewrite(self, core):
        core_hash = canonical.rendered(canonical.hash_frame(
            canonical.DOMAIN_SNAPSHOT_MANIFEST, canonical.canonical_bytes(core)))
        os.chmod(self.snap, 0o700)
        path = os.path.join(self.snap, "manifest.json")
        os.chmod(path, 0o600)
        with open(path, "wb") as fh:
            fh.write(canonical.canonical_bytes({"manifest_core": core,
                                                "manifest_hash": core_hash}))

    def rewrite_limits(self, change):
        path = os.path.join(self.snap, "coverage", "evidence_limits.json")
        os.chmod(path, 0o600)
        with open(path, "rb") as fh:
            limits = json.loads(fh.read())
        change(limits)
        data = canonical.canonical_bytes(limits)
        with open(path, "wb") as fh:
            fh.write(data)
        core = self.envelope()["manifest_core"]
        core["auxiliary_artifacts"]["coverage/evidence_limits.json"] = \
            snapshot.auxiliary_digest(data)
        self.rewrite(core)

    def auth(self, rule):
        return [p for p in verify.verify_snapshot(self.snap) if rule in p]

    def test_isedraf_audit_records_standard_audit_and_verifies(self):
        self.assertEqual(self.envelope()["manifest_core"]["run_mode"], "STANDARD_AUDIT")
        self.assertEqual(verify.verify_store(self.root), [], self.err)

    def test_a_snapshot_without_run_mode_verifies_and_is_not_full_audit(self):
        core = self.envelope()["manifest_core"]
        del core["run_mode"]
        self.rewrite(core)
        self.assertEqual(verify.verify_snapshot(self.snap), [])

    def test_full_audit_on_an_unprivileged_class_is_refused(self):
        core = self.envelope()["manifest_core"]
        core["run_mode"] = "FULL_AUDIT"
        self.rewrite(core)
        self.assertTrue(self.auth("AUTH-018"))

    def test_an_unknown_run_mode_is_refused(self):
        core = self.envelope()["manifest_core"]
        core["run_mode"] = "ROOT"
        self.rewrite(core)
        self.assertTrue(self.auth("AUTH-018"))

    def test_a_supervisor_source_in_a_standard_run_is_refused(self):
        def supervised(limits):
            limits["sources"][0]["acquisition_mode"] = "SUPERVISOR_FIXED_OPERATION"
            limits["sources"][0]["operation_id"] = "read_shadow_v1"
        self.rewrite_limits(supervised)
        problems = self.auth("AUTH-017")
        self.assertTrue([p for p in problems if "outside a FULL_AUDIT run" in p], problems)

    def test_a_supervisor_source_under_an_unimplemented_operation_is_refused(self):
        def supervised(limits):
            limits["sources"][0]["acquisition_mode"] = "SUPERVISOR_FIXED_OPERATION"
            limits["sources"][0]["operation_id"] = UNIMPLEMENTED
        self.rewrite_limits(supervised)
        problems = self.auth("AUTH-017")
        self.assertTrue([p for p in problems if "not an IMPLEMENTED operation" in p], problems)

    def test_an_operation_id_on_a_current_identity_source_is_refused(self):
        def tagged(limits):
            limits["sources"][0]["operation_id"] = "read_shadow_v1"
        self.rewrite_limits(tagged)
        self.assertTrue(self.auth("AUTH-017"))

    def test_the_untampered_limits_satisfy_the_coupling(self):
        self.assertEqual(self.auth("AUTH-017"), [])


class NoOperatorChoosesTheRunMode(unittest.TestCase):

    def test_the_command_line_has_no_run_mode_option(self):
        tree = ast.parse(pathlib.Path(cli.__file__).read_text(encoding="utf-8"))
        options = [a.value for node in ast.walk(tree)
                   if isinstance(node, ast.Call) and getattr(node.func, "attr", "")
                   == "add_argument"
                   for a in node.args if isinstance(a, ast.Constant)]
        self.assertTrue(options)
        for option in options:
            for word in ("mode", "full", "privilege", "supervisor", "operation"):
                self.assertNotIn(word, option.lower(), option)


if __name__ == "__main__":
    unittest.main()
