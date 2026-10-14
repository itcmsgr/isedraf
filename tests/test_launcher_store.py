# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The production store is validated, never repaired; promotion is mechanical.
# Implements: AUTH-021, AUTH-022, AUTH-023, AUTH-026, AUTH-027
#
# v0.2 P5b-1. Unprivileged: the store owner constants are replaced by this test's own uid,
# so every rule is exercised exactly as the launcher applies it, without root. What only
# root and the lab corpus can show (owner root, a second identity, the sandbox) is P6.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""v0.2 P5b-1: SYSTEM_PRODUCTION store conformance, staging, and promotion."""
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, HERE)

from isedraf import identity, ledger, snapshot, stateroot, verify      # noqa: E402
from isedraf.launcher import store                                     # noqa: E402
import test_evidence_limits as fixtures                                # noqa: E402

UID, GID = os.getuid(), os.getgid()


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


class Store(fixtures.Host):

    def setUp(self):
        super().setUp()
        for name, value in (("OWNER_UID", UID), ("OWNER_GID", GID)):
            patcher = mock.patch.object(store, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        self.root = os.path.join(base, "isedraf")

    def declare(self, m=0o700):
        os.mkdir(self.root)
        os.chmod(self.root, m)

    def built(self, run_id, state_root="SYSTEM_PRODUCTION", run_mode="FULL_AUDIT"):
        ident = identity.collect(os.path.join(self.host, "etc/machine-id"))
        created_at, snapshot_id, _r, _e = snapshot.new_ids()
        return snapshot.build(ident, snapshot_id, run_id, created_at, state_root, "0.0.0",
                              run_mode=run_mode)

    def staged(self, **kw):
        self.declare()
        store.prepare(self.root)
        _ts, _s, run_id, _e = snapshot.new_ids()
        staging = store.make_staging(self.root, run_id)
        snapshot.write_bundle(staging, self.built(run_id, **kw))
        return staging, run_id


class RootIsValidatedNeverRepaired(Store):

    def test_a_missing_root_is_unusable_and_not_created(self):
        with self.assertRaises(store.Unusable):
            store.check_root(self.root)
        self.assertFalse(os.path.lexists(self.root))

    def test_a_conforming_root_is_accepted(self):
        self.declare()
        store.check_root(self.root)

    def test_a_wrong_mode_is_unusable_and_left_as_it_was(self):
        self.declare(0o755)
        with self.assertRaises(store.Unusable):
            store.prepare(self.root)
        self.assertEqual(mode(self.root), 0o755)
        self.assertEqual(os.listdir(self.root), [])

    def test_a_link_is_unusable(self):
        target = self.root + "-target"
        os.mkdir(target, 0o700)
        self.addCleanup(shutil.rmtree, target, True)
        os.symlink(target, self.root)
        with self.assertRaises(store.Unusable):
            store.check_root(self.root)
        self.assertTrue(os.path.islink(self.root))

    def test_a_regular_file_is_unusable_and_untouched(self):
        with open(self.root, "w"):
            pass
        os.chmod(self.root, 0o600)
        with self.assertRaises(store.Unusable):
            store.check_root(self.root)
        self.assertEqual(mode(self.root), 0o600)

    def test_another_owner_is_unusable(self):
        self.declare()
        with mock.patch.object(store, "OWNER_UID", UID + 1):
            with self.assertRaises(store.Unusable):
                store.check_root(self.root)


class EntriesAreCreatedOrRefused(Store):

    def test_missing_entries_are_created_conforming(self):
        self.declare()
        store.prepare(self.root)
        for name in store.DIRECTORIES:
            self.assertEqual(mode(os.path.join(self.root, name)), 0o700)
        self.assertEqual(mode(os.path.join(self.root, stateroot.LOCK_NAME)), 0o600)

    def test_a_non_conforming_entry_is_refused_not_repaired(self):
        self.declare()
        os.mkdir(os.path.join(self.root, "snapshots"))
        os.chmod(os.path.join(self.root, "snapshots"), 0o755)
        with self.assertRaises(store.Unusable):
            store.prepare(self.root)
        self.assertEqual(mode(os.path.join(self.root, "snapshots")), 0o755)

    def test_a_linked_lock_is_refused(self):
        self.declare()
        os.symlink("/etc/passwd", os.path.join(self.root, stateroot.LOCK_NAME))
        with self.assertRaises(store.Unusable):
            store.prepare(self.root)


class StagingAndPromotion(Store):

    def test_the_staging_is_root_owned_and_open_under_a_closed_tmp(self):
        self.declare()
        store.prepare(self.root)
        _ts, _s, run_id, _e = snapshot.new_ids()
        staging = store.make_staging(self.root, run_id)
        self.assertEqual(mode(staging), 0o777)
        self.assertEqual(mode(os.path.dirname(staging)), 0o700)

    def test_a_run_id_is_never_a_path(self):
        self.declare()
        store.prepare(self.root)
        for bad in ("../snapshots", "RUN-x", "/tmp", "SDS-20261007T000000Z-" + "a" * 16):
            with self.assertRaises(ValueError):
                store.make_staging(self.root, bad)

    def test_a_valid_staging_is_promoted_and_ledgered(self):
        staging, run_id = self.staged()
        envelope = store.check_staged(staging, UID, run_id)
        final = store.promote(self.root, staging, envelope)
        self.assertFalse(os.path.lexists(staging))
        self.assertEqual(mode(final), 0o700)
        self.assertEqual(verify.verify_store(self.root), [])
        records = ledger.read_records(self.root)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["record_core"]["state_root"], "SYSTEM_PRODUCTION")

    def test_an_undeclared_file_is_refused(self):
        staging, run_id = self.staged()
        with open(os.path.join(staging, "notes.txt"), "w") as fh:
            fh.write("x")
        with self.assertRaises(store.PromotionRefused):
            store.check_staged(staging, UID, run_id)

    def test_a_link_in_the_staging_is_refused(self):
        staging, run_id = self.staged()
        os.symlink("/etc", os.path.join(staging, "coverage"))
        with self.assertRaises(store.PromotionRefused):
            store.check_staged(staging, UID, run_id)

    def test_a_hard_link_is_refused(self):
        staging, run_id = self.staged()
        os.link(os.path.join(staging, "manifest.json"), os.path.join(self.root, "extra"))
        with self.assertRaises(store.PromotionRefused):
            store.check_staged(staging, UID, run_id)

    def test_a_file_of_another_owner_is_refused(self):
        staging, run_id = self.staged()
        with self.assertRaises(store.PromotionRefused):
            store.check_staged(staging, UID + 1, run_id)

    def test_a_tampered_manifest_is_refused(self):
        staging, run_id = self.staged()
        path = os.path.join(staging, "manifest.json")
        with open(path) as fh:
            envelope = json.load(fh)
        envelope["manifest_core"]["engine_version"] = "9.9.9"
        with open(path, "w") as fh:
            fh.write(json.dumps(envelope))
        with self.assertRaises(store.PromotionRefused):
            store.check_staged(staging, UID, run_id)

    def test_a_standard_audit_snapshot_is_never_promoted_into_the_system_store(self):
        staging, run_id = self.staged(state_root="USER_PRODUCTION", run_mode="STANDARD_AUDIT")
        with self.assertRaises(store.PromotionRefused):
            store.check_staged(staging, UID, run_id)

    def test_a_snapshot_of_another_run_is_refused(self):
        staging, _run_id = self.staged()
        _ts, _s, other, _e = snapshot.new_ids()
        with self.assertRaises(store.PromotionRefused):
            store.check_staged(staging, UID, other)

    def test_an_existing_snapshot_is_never_replaced(self):
        staging, run_id = self.staged()
        envelope = store.check_staged(staging, UID, run_id)
        os.mkdir(os.path.join(self.root, "snapshots",
                              envelope["manifest_core"]["snapshot_id"]), 0o700)
        with self.assertRaises(store.PromotionRefused):
            store.promote(self.root, staging, envelope)
        self.assertTrue(os.path.isdir(staging))


if __name__ == "__main__":
    unittest.main()
