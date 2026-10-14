# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: read_sshd_declared_config_v1 - the fixed surface from the frame, everything outside
#          it read by the engine as itself, never a discovered path to the supervisor.
# Implements: AUTH-030, AUTH-029, AUTH-003, AUTH-017, AUTH-024, IQ-046, IQ-060
#
# Unprivileged and fixture-only: the supervisor is a scripted channel, and every file outside
# the surface lives in a temporary directory. Nothing reads this machine's /etc/ssh.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""AUTH-030: a fixed privileged surface and a truthful mixed-authority graph."""
import os
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))

from isedraf import coverage, hostio                                   # noqa: E402
from isedraf.shared import result                                      # noqa: E402
from isedraf.ssh import acquire                                        # noqa: E402
from isedraf.supervisor import contracts, frame, perform, protocol     # noqa: E402

REG = {"mode": stat.S_IFREG | 0o600, "uid": 0, "gid": 0, "size": 1}
DIR = dict(REG, mode=stat.S_IFDIR | 0o755)
LNK = dict(REG, mode=stat.S_IFLNK | 0o777)


def entry(name, text=None, outcome=frame.READ_OK, lstat=None):
    data = b"" if text is None else text.encode()
    return frame.item(frame.ENTRY, name.encode(), outcome,
                      lstat or (REG if outcome != frame.NOT_FOUND else None), data)


def surface(root_text, entries, listing_outcome=frame.READ_OK):
    items = [frame.item(frame.ROOT, b"/etc/ssh/sshd_config", frame.READ_OK, REG,
                        root_text.encode())]
    if listing_outcome == frame.READ_OK:
        items.append(frame.item(frame.LISTING, b"/etc/ssh/sshd_config.d", frame.READ_OK, DIR,
                                b"\0".join(sorted(e["name"] for e in entries))))
    else:
        items.append(frame.item(frame.LISTING, b"/etc/ssh/sshd_config.d", listing_outcome,
                                None if listing_outcome == frame.NOT_FOUND else DIR))
    return frame.encode(items + sorted(entries, key=lambda e: e["name"]))


class Channel(object):
    """The supervisor, scripted. Full Audit also asks for the effective configuration
    (AUTH-031); by default that answer is a well-formed sshd -T output, so these tests
    stay about the declared dimension."""

    def __init__(self, data=b"", status=protocol.COMPLETED, stderr=None, effective=None):
        self.answers = {
            acquire.SSHD_OPERATION: protocol.result(acquire.SSHD_OPERATION, status, data,
                                                    stderr),
            acquire.EFFECTIVE_OPERATION: effective or protocol.result(
                acquire.EFFECTIVE_OPERATION, protocol.COMPLETED, b"port 22\n", b"",
                exit_code=0)}
        self.requests = []

    def request(self, operation_id):
        self.requests.append(operation_id)
        return self.answers[operation_id]


class FullAuditDeclaredConfig(unittest.TestCase):

    def setUp(self):
        self.outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.outside, True)

    def put(self, name, text, mode=0o644):
        path = os.path.join(self.outside, name)
        with open(path, "w") as handle:
            handle.write(text)
        os.chmod(path, mode)
        self.addCleanup(os.chmod, path, 0o644)
        return path

    def collect(self, channel):
        reads, real = [], hostio.read_file_lossless

        def guarded(path, *a, **k):
            if path.startswith("/etc/ssh"):
                raise AssertionError("the engine read the privileged surface itself: %s" % path)
            reads.append(path)
            return real(path, *a, **k)
        with mock.patch.object(hostio, "read_file_lossless", guarded):
            ev = acquire.collect("/", channel=channel)
        # The two fixed requests of the ssh section, and nothing else (AUTH-030, AUTH-031).
        self.assertEqual(channel.requests, [acquire.SSHD_OPERATION, acquire.EFFECTIVE_OPERATION])
        return ev, reads

    def cov(self, ev):
        return dict((c["source"], c) for c in ev.provenance["coverage"])

    def test_el9_shape_mixed_authority_is_collected_and_each_source_says_how(self):
        policy = self.put("opensshserver.config", "Ciphers aes256-ctr\n")
        ev, reads = self.collect(Channel(surface(
            "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n",
            [entry("50-redhat.conf", "Include %s\nX11Forwarding no\n" % policy),
             entry("50-cloud-init.conf", "PasswordAuthentication no\n")])))
        self.assertEqual(ev.status, result.COLLECTED, ev.reason)
        cov = self.cov(ev)
        for path in ("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/50-cloud-init.conf",
                     "/etc/ssh/sshd_config.d/50-redhat.conf"):
            self.assertEqual((cov[path]["acquisition_mode"], cov[path]["operation_id"]),
                             (coverage.MODE_SUPERVISOR_FIXED_OPERATION, acquire.SSHD_OPERATION))
        self.assertEqual(cov[policy]["status"], "COLLECTED")
        self.assertNotIn("operation_id", cov[policy])          # CURRENT_IDENTITY
        self.assertEqual(reads, [policy])
        keywords = [r.get("keyword") for r in ev.records if r.get("kind") == "DIRECTIVE"]
        self.assertIn("ciphers", keywords)

    def test_a_chain_outside_the_surface_stays_with_the_engine_at_every_hop(self):
        third = self.put("third.conf", "MaxAuthTries 3\n")
        second = self.put("second.conf", "Include %s\nLoginGraceTime 30\n" % third)
        first = self.put("first.conf", "Include %s\n" % second)
        ev, reads = self.collect(Channel(surface(
            "Include /etc/ssh/sshd_config.d/*.conf\n",
            [entry("10.conf", "Include %s\n" % first)])))
        self.assertEqual(ev.status, result.COLLECTED, ev.reason)
        self.assertEqual(reads, [first, second, third])
        for path in (first, second, third):
            self.assertNotIn("operation_id", self.cov(ev)[path])

    def test_an_unreadable_hop_in_the_chain_is_not_tested_and_partial(self):
        if os.geteuid() == 0:
            self.skipTest("root reads mode 000")
        hidden = self.put("hidden.conf", "MaxAuthTries 3\n", mode=0)
        first = self.put("first.conf", "Include %s\n" % hidden)
        ev, _reads = self.collect(Channel(surface(
            "Include /etc/ssh/sshd_config.d/*.conf\n",
            [entry("10.conf", "Include %s\n" % first)])))
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertEqual(self.cov(ev)[hidden]["status"], "NOT_TESTED")
        self.assertNotIn("operation_id", self.cov(ev)[hidden])

    def test_a_cycle_outside_the_surface_terminates(self):
        loop = os.path.join(self.outside, "loop.conf")
        self.put("loop.conf", "Include %s\nMaxSessions 4\n" % loop)
        ev, reads = self.collect(Channel(surface("Include %s\n" % loop, [])))
        self.assertLessEqual(reads.count(loop), 2)
        self.assertIn(ev.status, (result.PARTIAL, result.COLLECTED))

    def test_an_outside_file_including_back_into_the_surface_is_served_from_the_frame(self):
        back = self.put("back.conf", "Include /etc/ssh/sshd_config.d/20.conf\n")
        ev, reads = self.collect(Channel(surface(
            "Include %s\n" % back, [entry("20.conf", "UsePAM yes\n")])))
        self.assertEqual(ev.status, result.COLLECTED, ev.reason)
        self.assertEqual(reads, [back])          # 20.conf came from the frame, not a read
        self.assertEqual(self.cov(ev)["/etc/ssh/sshd_config.d/20.conf"]["operation_id"],
                         acquire.SSHD_OPERATION)

    def test_match_scope_and_order_are_kept_without_claiming_an_effective_value(self):
        ev, _reads = self.collect(Channel(surface(
            "PasswordAuthentication yes\nMatch User alice\n"
            "  Include /etc/ssh/sshd_config.d/*.conf\n",
            [entry("10.conf", "PasswordAuthentication no\n")])))
        directives = [r for r in ev.records if r.get("keyword") == "passwordauthentication"]
        self.assertEqual([(r["value"], r["scope"]) for r in directives],
                         [("yes", "GLOBAL"), ("no", "MATCH")])
        self.assertEqual(directives[1]["match_criteria"][0]["values"], ["alice"])
        self.assertLess(directives[0]["ordinal"], directives[1]["ordinal"])
        # The declared records claim no effective value; the only effective claim in the
        # section is the resolved dimension, and it is the global one (AUTH-031).
        self.assertEqual(set(r["kind"] for r in directives), {"DIRECTIVE"})
        self.assertEqual(ev.provenance["resolved"]["scope"], "GLOBAL_EFFECTIVE_SSHD_CONFIGURATION")
        self.assertEqual(ev.provenance["resolved"]["connection_context"]["status"], "NOT_TESTED")

    def test_the_glob_is_the_engines_and_only_matching_names_are_read(self):
        ev, _reads = self.collect(Channel(surface(
            "Include /etc/ssh/sshd_config.d/*.conf\n",
            [entry("10.conf", "UsePAM yes\n"), entry("README", "not policy\n")])))
        paths = [c for c in self.cov(ev)]
        self.assertIn("/etc/ssh/sshd_config.d/10.conf", paths)
        self.assertNotIn("/etc/ssh/sshd_config.d/README", paths)

    def test_a_symlinked_drop_in_is_not_followed_and_partial(self):
        ev, _reads = self.collect(Channel(surface(
            "Include /etc/ssh/sshd_config.d/*.conf\n",
            [entry("10.conf", outcome=frame.SYMLINK, lstat=LNK)])))
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn("SYMLINK_NOT_FOLLOWED", ev.reason)
        link = self.cov(ev)["/etc/ssh/sshd_config.d/10.conf"]
        self.assertEqual((link["status"], link["operation_id"]),
                         ("NOT_TESTED", acquire.SSHD_OPERATION))

    def test_a_drop_in_directory_that_could_not_be_listed_is_never_empty(self):
        ev, _reads = self.collect(Channel(surface(
            "Include /etc/ssh/sshd_config.d/*.conf\n", [],
            listing_outcome=frame.PERMISSION_DENIED)))
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertIn("could not be listed", ev.reason)

    def test_a_missing_drop_in_directory_keeps_its_ordinary_meaning(self):
        ev, _reads = self.collect(Channel(surface(
            "Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n", [],
            listing_outcome=frame.NOT_FOUND)))
        self.assertEqual(ev.status, result.COLLECTED, ev.reason)

    def test_the_operation_failing_is_never_a_clean_section(self):
        # The effective operation is refused too, so the status is the declared failure's.
        refused = protocol.result(acquire.EFFECTIVE_OPERATION, protocol.REFUSED,
                                  stderr=b"NOT_ENABLED")
        for channel, status in ((Channel(status=protocol.REFUSED, stderr=b"NOT_ENABLED",
                                         effective=refused), result.NOT_TESTED),
                                (Channel(status=protocol.TRUNCATED, effective=refused),
                                 result.NOT_TESTED),
                                (Channel(status=protocol.FAILED, stderr=b"TIMEOUT",
                                         effective=refused), result.ERROR),
                                (Channel(surface("UsePAM yes\n", []) + b"\0",
                                         effective=refused), result.ERROR)):
            ev, _reads = self.collect(channel)
            self.assertEqual(ev.status, status, ev.reason)
            self.assertEqual(ev.records, [])

    def test_the_standard_route_is_unchanged(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, "etc/ssh"))
        with open(os.path.join(root, "etc/ssh/sshd_config"), "w") as handle:
            handle.write("PermitRootLogin no\n")
        ev = acquire.collect(root)
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertNotIn("operation_id", repr(ev.provenance["coverage"]))


class TheContractIsDeclaredOnly(unittest.TestCase):
    """AUTH-030: the performer is the fixed-tree reader over /etc/ssh, never an executable."""

    def test_the_contract_runs_nothing_and_names_the_ssh_surface(self):
        contract = contracts.CONTRACTS[acquire.SSHD_OPERATION]
        self.assertEqual(contract["performer"], contracts.PERFORM_READ_FIXED_TREE)
        self.assertIsNone(contract["fixed_executable"])
        self.assertEqual((contract["root_file"], contract["directory"]),
                         (acquire.SURFACE_ROOT, acquire.SURFACE_DIRECTORY))

    def test_the_performer_reads_a_fixture_surface_and_follows_no_link(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, "etc/ssh/sshd_config.d"))
        for rel, text in (("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n"),
                          ("etc/ssh/sshd_config.d/50-redhat.conf", "UsePAM yes\n"),
                          ("etc/outside.conf", "X11Forwarding no\n")):
            with open(os.path.join(root, rel), "w") as handle:
                handle.write(text)
        os.symlink("/etc/outside.conf", os.path.join(root, "etc/ssh/sshd_config.d/60.conf"))
        with mock.patch.object(contracts, "HOST_ROOT", root):
            res = perform.perform(acquire.SSHD_OPERATION)
        tree = frame.check_tree(frame.decode(res["bytes"], 1 << 22, 2000),
                                b"/etc/ssh/sshd_config", b"/etc/ssh/sshd_config.d")
        outcomes = dict((e["name"], e["acquisition_outcome"]) for e in tree["entries"])
        self.assertEqual(outcomes, {b"50-redhat.conf": frame.READ_OK, b"60.conf": frame.SYMLINK})


if __name__ == "__main__":
    unittest.main()
