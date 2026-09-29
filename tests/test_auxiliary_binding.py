# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: D-115 — auxiliary bundle artifacts are bound, and are not host state.
# Implements: SCOPE-045, GOV-002
#
# The eight proofs the owner required. Seven attack the binding; the eighth proves the
# separation the binding must NOT destroy - a coverage change moves manifest_hash and
# leaves state_hash alone.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""D-115: bundle integrity over auxiliary artifacts, with host-state identity intact."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf import canonical, coverage, identity, snapshot, verify   # noqa: E402


def a_manifest(refused=False):
    entries = [coverage.source("accounts", "etc/passwd", coverage.COLLECTED,
                               coverage.READ_OK, coverage.OP_FILE_READ)]
    entries.append(coverage.source(
        "accounts", "etc/shadow",
        coverage.NOT_TESTED if refused else coverage.COLLECTED,
        coverage.PERMISSION_DENIED if refused else coverage.READ_OK,
        coverage.OP_FILE_READ))
    return coverage.manifest(entries, coverage.MODE_CURRENT_IDENTITY)


class Bundle(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        for name in ("snapshots", "tmp", "ledger"):
            os.makedirs(os.path.join(self.root, name), mode=0o700)
        self.host = self.host_root()

    def host_root(self):
        """A machine-id fixture. identity.collect takes the FILE path, not a root.

        identity.collect("/") is ERROR in a sandbox where /etc/machine-id is unreadable,
        which would make the state_hash comparison in proof 7 a None == None tautology -
        it would pass while proving nothing. A COLLECTED identity gives that proof a real
        hash to hold constant.
        """
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, "etc"))
        with open(os.path.join(root, "etc", "machine-id"), "w") as handle:
            handle.write("3f8a1c2b4d5e6f708192a3b4c5d6e7f8\n")
        return os.path.join(root, "etc", "machine-id")

    def commit(self, refused=False, coverage_manifest=True):
        ident = identity.collect(self.host)
        self.assertTrue(ident.collected,
                        "the fixture identity must be COLLECTED or proof 7 is vacuous")
        created, sds, run, _evt = snapshot.new_ids()
        built = snapshot.build(
            ident, sds, run, created, "DEV", "test",
            coverage_manifest=a_manifest(refused) if coverage_manifest else None)
        path = snapshot.commit(self.root, built, sds)
        return path, built

    def core(self, path):
        with open(os.path.join(path, "manifest.json"), "rb") as handle:
            return json.loads(handle.read())["manifest_core"]

    def rewrite(self, path, relative, data):
        with open(os.path.join(path, relative), "wb") as handle:
            handle.write(data)


class BoundAndVerified(Bundle):

    def test_a_clean_bundle_verifies(self):
        path, _ = self.commit()
        self.assertEqual(verify.verify_snapshot(path), [])

    def test_both_auxiliary_artifacts_are_declared(self):
        path, _ = self.commit()
        declared = self.core(path)["auxiliary_artifacts"]
        self.assertEqual(sorted(declared),
                         ["coverage/evidence_limits.json",
                          "method/host_identity.json"])

    def test_the_declaration_is_a_map_not_an_ordered_array(self):
        # NORM-037: an array-typed field in W1-A needs a declared total ordering. A map
        # has none to declare, because canonical_bytes sorts object keys.
        self.assertIsInstance(self.core(self.commit()[0])["auxiliary_artifacts"], dict)

    def test_the_registry_is_explicit_and_bounded(self):
        # Not a directory walk: snapshot identity must not depend on accidental files.
        # Still an exact list. The ten audit sections join it by owner decision of
        # 2026-09-27 (GA v0.1, D-115 extension); the amendment text is pending, and this
        # branch does not merge before it lands.
        self.assertEqual(sorted(snapshot.AUXILIARY_ARTIFACTS),
                         ["coverage/evidence_limits.json",
                          "method/host_identity.json",
                          "sections/accounts.json", "sections/authorizedkeys.json",
                          "sections/hostname.json", "sections/inventory.json",
                          "sections/loginpolicy.json", "sections/mounts.json",
                          "sections/nss.json", "sections/pam.json",
                          "sections/ssh.json", "sections/sudo.json"])

    def test_a_stray_file_in_the_bundle_does_not_enter_the_binding(self):
        path, _ = self.commit()
        self.rewrite(path, "coverage/.nfs-swap", b"junk")
        self.assertEqual(verify.verify_snapshot(path), [])


class TheEightProofs(Bundle):

    def assert_rejected(self, path, needle):
        problems = verify.verify_snapshot(path)
        self.assertTrue(problems, "verify_snapshot accepted the tampered bundle")
        self.assertTrue(any(needle in p for p in problems),
                        "rejected for the wrong reason: %r" % problems)

    # 1 -----------------------------------------------------------------------
    def test_mutating_evidence_limits_alone_fails_verification(self):
        path, _ = self.commit()
        self.rewrite(path, "coverage/evidence_limits.json", b'{"tampered":true}')
        self.assert_rejected(path, "does not match its binding")

    # 2 -----------------------------------------------------------------------
    def test_mutating_it_and_recomputing_its_own_digest_still_fails(self):
        """The reason a self-digest was never enough.

        An attacker who rewrites the artifact can also rewrite the coverage_digest inside
        it, and the object stays internally consistent. Membership of THIS snapshot is
        what manifest_core asserts, and that is what they cannot forge without breaking
        manifest_hash and the ledger chain above it.
        """
        path, _ = self.commit()
        forged = a_manifest(refused=True)
        forged["coverage_digest"] = coverage.coverage_digest(forged)
        self.rewrite(path, "coverage/evidence_limits.json",
                     canonical.canonical_bytes(forged))
        self.assert_rejected(path, "does not match its binding")

    # 3 -----------------------------------------------------------------------
    def test_substituting_a_valid_artifact_from_another_snapshot_fails(self):
        first, _ = self.commit()
        second, _ = self.commit(refused=True)
        with open(os.path.join(second, "coverage", "evidence_limits.json"), "rb") as fh:
            other = fh.read()
        self.assertEqual(verify.verify_snapshot(second), [])
        self.rewrite(first, "coverage/evidence_limits.json", other)
        self.assert_rejected(first, "does not match its binding")

    # 4 -----------------------------------------------------------------------
    def test_mutating_method_host_identity_fails(self):
        """The gap that predated R1.5-P. This file was in every bundle and unread."""
        path, _ = self.commit()
        self.rewrite(path, "method/host_identity.json", b'{"collector_id":"forged"}')
        self.assert_rejected(path, "does not match its binding")

    # 5 -----------------------------------------------------------------------
    def test_deleting_an_auxiliary_artifact_fails(self):
        path, _ = self.commit()
        os.unlink(os.path.join(path, "coverage", "evidence_limits.json"))
        self.assert_rejected(path, "missing or unreadable")

    # 6 -----------------------------------------------------------------------
    def test_editing_the_binding_without_rebuilding_the_chain_fails(self):
        path, _ = self.commit()
        with open(os.path.join(path, "manifest.json"), "rb") as handle:
            envelope = json.loads(handle.read())
        envelope["manifest_core"]["auxiliary_artifacts"][
            "coverage/evidence_limits.json"] = "sha256:" + "0" * 64
        self.rewrite(path, "manifest.json", canonical.canonical_bytes(envelope))
        self.assert_rejected(path, "manifest_hash does not match its preimage")

    def test_removing_the_entry_as_well_as_changing_the_file_still_fails(self):
        # Closing the obvious evasion: drop the binding AND the artifact stays present.
        path, _ = self.commit()
        with open(os.path.join(path, "manifest.json"), "rb") as handle:
            envelope = json.loads(handle.read())
        del envelope["manifest_core"]["auxiliary_artifacts"][
            "coverage/evidence_limits.json"]
        core = envelope["manifest_core"]
        envelope["manifest_hash"] = canonical.rendered(canonical.hash_frame(
            canonical.DOMAIN_SNAPSHOT_MANIFEST, canonical.canonical_bytes(core)))
        self.rewrite(path, "manifest.json", canonical.canonical_bytes(envelope))
        self.assert_rejected(path, "is in the bundle and is not bound")

    # 7 -----------------------------------------------------------------------
    def test_a_coverage_only_change_moves_the_bundle_and_not_the_host_state(self):
        """THE architectural proof. Same host, different visibility.

        state_hash identical, coverage_digest different, manifest_hash different. Binding
        the coverage artifact for integrity must not make a coverage change look like a
        host-state change, and this measures that rather than asserting it.
        """
        _, open_run = self.commit(refused=False)
        _, shut_run = self.commit(refused=True)
        open_core = open_run["manifest_core"]
        shut_core = shut_run["manifest_core"]
        self.assertEqual(open_core["sections"]["host_identity"]["state_hash"],
                         shut_core["sections"]["host_identity"]["state_hash"],
                         "host-state identity moved when only visibility changed")
        self.assertEqual(open_run["state"], shut_run["state"])
        self.assertNotEqual(open_run["coverage_digest"], shut_run["coverage_digest"])
        self.assertNotEqual(open_core["auxiliary_artifacts"],
                            shut_core["auxiliary_artifacts"])
        self.assertNotEqual(open_run["manifest_hash"], shut_run["manifest_hash"])

    # 8 -----------------------------------------------------------------------
    def test_the_three_identities_answer_three_questions(self):
        path, built = self.commit()
        core = self.core(path)
        state_hash = core["sections"]["host_identity"]["state_hash"]
        self.assertIsNotNone(state_hash)
        self.assertIsNotNone(built["coverage_digest"])
        self.assertIn("coverage/evidence_limits.json", core["auxiliary_artifacts"])
        auxiliary = core["auxiliary_artifacts"]["coverage/evidence_limits.json"]
        self.assertNotEqual(built["coverage_digest"], auxiliary)
        self.assertNotEqual(state_hash, auxiliary)
        self.assertNotEqual(state_hash, built["coverage_digest"])
        # Different domains, so a digest of one kind can never be mistaken for the other.
        self.assertNotEqual(canonical.DOMAIN_AUXILIARY_ARTIFACT, canonical.DOMAIN_STATE)


class CoverageDigestIsRetained(Bundle):
    """Owner ruling: the binding does not replace observation-capability identity."""

    def test_the_manifest_still_carries_its_own_digest(self):
        path, _ = self.commit()
        with open(os.path.join(path, "coverage", "evidence_limits.json"), "rb") as fh:
            body = json.loads(fh.read())
        self.assertEqual(body["coverage_digest"], coverage.coverage_digest(body))

    def test_a_snapshot_without_coverage_binds_only_method(self):
        path, _ = self.commit(coverage_manifest=False)
        self.assertEqual(sorted(self.core(path)["auxiliary_artifacts"]),
                         ["method/host_identity.json"])
        self.assertEqual(verify.verify_snapshot(path), [])


if __name__ == "__main__":
    unittest.main(verbosity=0)
