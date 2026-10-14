# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: read_sudoers_graph_v1 - the AUTH-029 frame, the fixed-surface performer, and the
#          engine that alone interprets what came back.
# Implements: AUTH-029, AUTH-015, AUTH-003, AUTH-006, AUTH-017, AUTH-024, IQ-046, IQ-057
#
# Unprivileged and fixture-only: the performer reads a temporary tree through the supervisor's
# HOST_ROOT test seam, and the engine is given a scripted channel. Nothing reads the host.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""AUTH-029: framing is facts only; the performer stays on its surface; the engine judges."""
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))

from isedraf import coverage, hostio                                   # noqa: E402
from isedraf.shared import bounded, result                             # noqa: E402
from isedraf.sudo import acquire                                       # noqa: E402
from isedraf.supervisor import contracts, frame, perform, protocol     # noqa: E402

REG = stat.S_IFREG | 0o440
DIR = stat.S_IFDIR | 0o750
LNK = stat.S_IFLNK | 0o777
META = {"mode": REG, "uid": 0, "gid": 0, "size": 4}
COLLECTION_STATUSES = ("COLLECTED", "PARTIAL", "NOT_TESTED", "ERROR")


def tree(root=b"root ALL=(ALL) ALL\n", listing=b"plain", entries=None,
         listing_outcome=frame.READ_OK):
    items = [frame.item(frame.ROOT, b"/etc/sudoers", frame.READ_OK,
                        dict(META, size=len(root)), root)]
    if listing_outcome == frame.READ_OK:
        items.append(frame.item(frame.LISTING, b"/etc/sudoers.d", frame.READ_OK,
                                dict(META, mode=DIR), listing))
    elif listing_outcome == frame.NOT_FOUND:
        items.append(frame.item(frame.LISTING, b"/etc/sudoers.d", frame.NOT_FOUND))
    else:
        items.append(frame.item(frame.LISTING, b"/etc/sudoers.d", listing_outcome,
                                dict(META, mode=DIR)))
    for entry in entries if entries is not None else [
            frame.item(frame.ENTRY, b"plain", frame.READ_OK, META, b"ops ALL=(ALL) ALL\n")]:
        items.append(entry)
    return frame.encode(items)


class Channel(object):
    def __init__(self, data=b"", status=protocol.COMPLETED, stderr=None):
        self.res = protocol.result(acquire.SUDOERS_OPERATION, status, data, stderr)
        self.requests = []

    def request(self, operation_id):
        self.requests.append(operation_id)
        return self.res


class TheFrameIsFactsOnly(unittest.TestCase):
    """AUTH-029: a strict codec; acquisition outcomes are not collection statuses."""

    def test_the_vocabulary_is_the_frozen_set_and_never_a_collection_status(self):
        text = open(os.path.join(HERE, "..", "docs", "architecture",
                                 "FULL_AUDIT_AUTHORITY_MODEL.md")).read()
        bullet = text[text.index("**Framing within `AUTH-015`**"):]
        bullet = bullet[:bullet.index("A\n  privileged-side")]
        frozen = tuple(re.findall(r"`([A-Z_]+)`", bullet.split("acquisition outcome in a field")[1]))
        self.assertEqual(frozen, frame.ACQUISITION_OUTCOMES)
        self.assertFalse(set(frame.ACQUISITION_OUTCOMES) & set(COLLECTION_STATUSES))

    def test_round_trip(self):
        data = tree()
        items = frame.decode(data, 1 << 20, 10)
        self.assertEqual(frame.encode(items), data)

    def refused(self, data, limit=1 << 20, max_items=10):
        with self.assertRaises(frame.FrameError):
            frame.decode(data, limit, max_items)

    def test_trailing_bytes_are_refused(self):
        self.refused(tree() + b"\0")

    def test_a_count_larger_than_the_items_is_refused(self):
        data = bytearray(tree())
        data[8:12] = (4).to_bytes(4, "big")
        self.refused(bytes(data))

    def test_a_count_smaller_than_the_items_is_refused(self):
        data = bytearray(tree())
        data[8:12] = (2).to_bytes(4, "big")
        self.refused(bytes(data))

    def test_an_unknown_acquisition_outcome_is_refused(self):
        data = bytearray(tree())
        data[13] = len(frame.ACQUISITION_OUTCOMES) + 1
        self.refused(bytes(data))

    def test_an_unknown_kind_is_refused(self):
        data = bytearray(tree())
        data[12] = 9
        self.refused(bytes(data))

    def test_a_length_past_the_end_is_refused(self):
        self.refused(tree()[:-3])

    def test_bad_magic_is_refused(self):
        self.refused(b"NOTAFRAM" + tree()[8:])

    def test_an_oversized_frame_is_refused(self):
        self.refused(tree(), limit=40)

    def test_too_many_items_are_refused(self):
        self.refused(tree(), max_items=2)

    def test_impossible_kind_and_outcome_combinations_are_refused(self):
        bad = [
            dict(kind=frame.ENTRY, name=b"x", acquisition_outcome=frame.SYMLINK,
                 lstat=dict(META, mode=LNK), content=b"policy"),          # link with content
            dict(kind=frame.ENTRY, name=b"x", acquisition_outcome=frame.SYMLINK,
                 lstat=META, content=b""),                               # link that is a file
            dict(kind=frame.ENTRY, name=b"x", acquisition_outcome=frame.NOT_FOUND,
                 lstat=META, content=b""),                               # absent with lstat
            dict(kind=frame.ENTRY, name=b"x", acquisition_outcome=frame.READ_OK,
                 lstat=None, content=b"x"),                              # read without lstat
            dict(kind=frame.LISTING, name=b"x", acquisition_outcome=frame.READ_OK,
                 lstat=META, content=b""),                               # listing not a dir
            dict(kind=frame.ENTRY, name=b"x", acquisition_outcome=frame.NON_REGULAR,
                 lstat=META, content=b""),                               # non-regular regular
            dict(kind=frame.ENTRY, name=b"x", acquisition_outcome=frame.TRUNCATED,
                 lstat=META, content=b"part"),                           # truncated content
            dict(kind=frame.ENTRY, name=b"a\0b", acquisition_outcome=frame.NOT_FOUND,
                 lstat=None, content=b""),                               # NUL in a name
        ]
        for record in bad:
            with self.assertRaises(frame.FrameError, msg=repr(record)):
                frame.item(record["kind"], record["name"], record["acquisition_outcome"],
                           record["lstat"], record["content"])

    def test_the_tree_shape_is_checked(self):
        items = frame.decode(tree(), 1 << 20, 10)
        frame.check_tree(items, b"/etc/sudoers", b"/etc/sudoers.d")
        for broken in (items[1:], [items[1], items[0]] + items[2:], items[:2],
                       items + [items[2]]):
            with self.assertRaises(frame.FrameError):
                frame.check_tree(broken, b"/etc/sudoers", b"/etc/sudoers.d")
        with self.assertRaises(frame.FrameError):
            frame.check_tree(items, b"/etc/other", b"/etc/sudoers.d")


class ThePerformerStaysOnItsSurface(unittest.TestCase):
    """AUTH-029 performer: lstat first, links and non-regular entries never opened."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        os.makedirs(os.path.join(self.root, "etc/sudoers.d"))
        self.write("etc/sudoers", "@includedir /etc/sudoers.d\n")
        self.write("etc/sudoers.d/plain", "ops ALL=(ALL) ALL\n")
        self.write("etc/sudoers.d/ignored.conf", "x ALL=(ALL) ALL\n")
        self.write("etc/elsewhere", "linked ALL=(ALL) NOPASSWD: ALL\n")
        os.symlink("/etc/elsewhere", os.path.join(self.root, "etc/sudoers.d/link"))
        os.makedirs(os.path.join(self.root, "etc/sudoers.d/subdir"))
        patcher = mock.patch.object(contracts, "HOST_ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, rel, text):
        with open(os.path.join(self.root, rel), "w") as handle:
            handle.write(text)

    def perform(self, **overrides):
        contract = dict(contracts.CONTRACTS[acquire.SUDOERS_OPERATION], **overrides)
        with mock.patch.dict(contracts.CONTRACTS, {acquire.SUDOERS_OPERATION: contract}):
            return perform.perform(acquire.SUDOERS_OPERATION)

    def tree(self, res):
        self.assertEqual(res["status"], protocol.COMPLETED, res)
        return frame.check_tree(frame.decode(res["bytes"], 1 << 22, 2000),
                                b"/etc/sudoers", b"/etc/sudoers.d")

    def outcomes(self, t):
        return dict((e["name"], e["acquisition_outcome"]) for e in t["entries"])

    def test_every_listed_entry_is_reported_with_its_own_outcome(self):
        t = self.tree(self.perform())
        self.assertEqual(t["root"]["acquisition_outcome"], frame.READ_OK)
        self.assertEqual(frame.listing_names(t["listing"]["content"]),
                         [b"ignored.conf", b"link", b"plain", b"subdir"])
        self.assertEqual(self.outcomes(t), {b"ignored.conf": frame.READ_OK,
                                            b"link": frame.SYMLINK, b"plain": frame.READ_OK,
                                            b"subdir": frame.NON_REGULAR})

    def test_a_symlink_is_never_opened(self):
        opened = []
        real = os.open
        with mock.patch.object(perform.os, "open",
                               lambda p, *a, **k: opened.append(p) or real(p, *a, **k)):
            t = self.tree(self.perform())
        self.assertNotIn(b"link", opened)
        self.assertNotIn(b"subdir", opened)
        link = [e for e in t["entries"] if e["name"] == b"link"][0]
        self.assertEqual(link["content"], b"")
        self.assertTrue(stat.S_ISLNK(link["lstat"]["mode"]))

    def test_an_entry_replaced_by_a_link_after_lstat_is_recorded_as_the_link(self):
        real, seen = os.stat, []

        def stale(name, *a, **k):
            if name == b"link" and not seen:
                # the lstat made before the swap said a regular file; every later one sees
                # the link the entry now is
                seen.append(name)
                return real(os.path.join(self.root, "etc/sudoers.d/plain"))
            return real(name, *a, **k)
        with mock.patch.object(perform.os, "stat", stale):
            t = self.tree(self.perform())
        self.assertEqual(self.outcomes(t)[b"link"], frame.SYMLINK)

    def test_no_filename_rule_is_applied_on_the_privileged_side(self):
        t = self.tree(self.perform())
        ignored = [e for e in t["entries"] if e["name"] == b"ignored.conf"][0]
        self.assertEqual(ignored["acquisition_outcome"], frame.READ_OK)

    def test_an_unreadable_entry_is_refused_not_absent(self):
        if os.geteuid() == 0:
            self.skipTest("root reads mode 000")
        path = os.path.join(self.root, "etc/sudoers.d/plain")
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, 0o644)
        self.assertEqual(self.outcomes(self.tree(self.perform()))[b"plain"],
                         frame.PERMISSION_DENIED)

    def test_a_missing_directory_is_not_found_and_carries_no_entries(self):
        shutil.rmtree(os.path.join(self.root, "etc/sudoers.d"))
        t = self.tree(self.perform())
        self.assertEqual(t["listing"]["acquisition_outcome"], frame.NOT_FOUND)
        self.assertEqual(t["entries"], [])

    def test_a_symlinked_directory_is_not_followed(self):
        shutil.rmtree(os.path.join(self.root, "etc/sudoers.d"))
        os.makedirs(os.path.join(self.root, "etc/real.d"))
        os.symlink("real.d", os.path.join(self.root, "etc/sudoers.d"))
        t = self.tree(self.perform())
        self.assertEqual(t["listing"]["acquisition_outcome"], frame.SYMLINK)
        self.assertEqual(t["entries"], [])

    def test_a_symlinked_root_file_is_not_followed(self):
        os.remove(os.path.join(self.root, "etc/sudoers"))
        os.symlink("elsewhere", os.path.join(self.root, "etc/sudoers"))
        t = self.tree(self.perform())
        self.assertEqual(t["root"]["acquisition_outcome"], frame.SYMLINK)
        self.assertEqual(t["root"]["content"], b"")

    def test_an_oversized_member_is_truncated_without_content(self):
        t = self.tree(self.perform(member_bound_bytes=5))
        plain = [e for e in t["entries"] if e["name"] == b"plain"][0]
        self.assertEqual((plain["acquisition_outcome"], plain["content"]),
                         (frame.TRUNCATED, b""))

    def test_too_many_entries_truncate_the_whole_operation(self):
        res = self.perform(max_entries=2)
        self.assertEqual((res["status"], res["bytes"]), (protocol.TRUNCATED, b""))

    def test_an_oversized_frame_truncates_the_whole_operation(self):
        res = self.perform(output_bound_bytes=64, member_bound_bytes=64)
        self.assertEqual((res["status"], res["bytes"]), (protocol.TRUNCATED, b""))


class TheEngineAloneInterprets(unittest.TestCase):
    """The collector builds the graph from the frame only, and decides every status."""

    def collect(self, channel):
        with mock.patch.object(hostio, "read_file_lossless",
                               side_effect=AssertionError("the engine read a file")), \
                mock.patch.object(bounded, "enumerate_paths",
                                  side_effect=AssertionError("the engine listed a directory")):
            return acquire.collect("/", channel=channel)

    def test_a_clean_surface_is_collected_and_names_the_operation(self):
        channel = Channel(tree(root=b"@includedir /etc/sudoers.d\n"))
        ev = self.collect(channel)
        self.assertEqual(channel.requests, [acquire.SUDOERS_OPERATION])
        self.assertEqual(ev.status, result.COLLECTED, ev.reason)
        self.assertEqual([r["source_path"] for r in ev.records], ["/etc/sudoers.d/plain"])
        for entry in ev.provenance["coverage"]:
            self.assertEqual((entry["acquisition_mode"], entry["operation_id"]),
                             (coverage.MODE_SUPERVISOR_FIXED_OPERATION,
                              acquire.SUDOERS_OPERATION), entry)
        meta = dict((f["requested_path"], f) for f in ev.provenance["files"])
        self.assertEqual(meta["/etc/sudoers.d/plain"]["mode_octal"], "0440")
        self.assertIsNone(meta["/etc/sudoers.d/plain"]["inode"])

    def test_a_symlinked_entry_is_observed_not_read_and_partial(self):
        link = frame.item(frame.ENTRY, b"link", frame.SYMLINK, dict(META, mode=LNK))
        plain = frame.item(frame.ENTRY, b"plain", frame.READ_OK, META, b"ops ALL=(ALL) ALL\n")
        ev = self.collect(Channel(tree(root=b"@includedir /etc/sudoers.d\n",
                                       listing=b"link\0plain", entries=[link, plain])))
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn("SYMLINK_NOT_FOLLOWED", ev.reason)
        self.assertIn("link", [e["name"] for e in ev.provenance["includedir_entries_observed"]])

    def test_an_include_outside_the_surface_is_not_tested_never_absent(self):
        ev = self.collect(Channel(tree(root=b"@includedir /etc/sudoers.d\n"
                                            b"@include /etc/sudoers.local\n"
                                            b"@includedir /etc/more.d\n")))
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn(acquire.OUTSIDE_SURFACE, ev.reason)
        outside = dict((c["source"], c) for c in ev.provenance["coverage"]
                       if (c["reason"] or "").startswith(acquire.OUTSIDE_SURFACE))
        self.assertEqual(sorted(outside), ["/etc/more.d", "/etc/sudoers.local"])
        for entry in outside.values():
            self.assertEqual(entry["status"], "NOT_TESTED")
            self.assertNotIn("operation_id", entry)       # no one acquired it
            self.assertFalse(entry["absence_claim_allowed"])

    def test_a_listing_that_could_not_be_made_is_never_empty(self):
        ev = self.collect(Channel(tree(root=b"@includedir /etc/sudoers.d\n", entries=[],
                                       listing_outcome=frame.PERMISSION_DENIED)))
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn("could not be listed", ev.reason)

    def test_a_missing_directory_keeps_its_ordinary_meaning(self):
        ev = self.collect(Channel(tree(root=b"@includedir /etc/sudoers.d\n", entries=[],
                                       listing_outcome=frame.NOT_FOUND)))
        self.assertNotIn("could not be listed", ev.reason or "")

    def test_a_non_regular_entry_is_partial(self):
        sub = frame.item(frame.ENTRY, b"subdir", frame.NON_REGULAR, dict(META, mode=DIR))
        ev = self.collect(Channel(tree(root=b"@includedir /etc/sudoers.d\n",
                                       listing=b"subdir", entries=[sub])))
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn("NON_REGULAR_ENTRY", ev.reason)

    def test_the_operation_failing_is_never_a_clean_section(self):
        for channel, status in ((Channel(status=protocol.REFUSED, stderr=b"NOT_ENABLED"),
                                 result.NOT_TESTED),
                                (Channel(status=protocol.TRUNCATED), result.NOT_TESTED),
                                (Channel(status=protocol.FAILED, stderr=b"TIMEOUT"),
                                 result.ERROR),
                                (Channel(tree() + b"\0"), result.ERROR)):
            ev = self.collect(channel)
            self.assertEqual(ev.status, status, ev.reason)
            self.assertEqual(ev.records, [])

    def test_the_standard_route_is_unchanged(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, "etc"))
        with open(os.path.join(root, "etc/sudoers"), "w") as handle:
            handle.write("root ALL=(ALL) ALL\n")
        ev = acquire.collect(root)
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertNotIn("operation_id", json.dumps(ev.provenance["coverage"]))


if __name__ == "__main__":
    unittest.main()
