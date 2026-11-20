# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The compact header, the audit summary and readable refusals (v0.5 P1, P2, P3).
# Implements: D-129, SCOPE-077, OUT-001
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""v0.5 register items P1, P2, P3."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import ENGINE_VERSION, summary                          # noqa: E402
from isedraf.snapshot import SECTION_NAMES                           # noqa: E402
from isedraf.supervisor import contracts                             # noqa: E402

SNAP = "SDS-20261115T064500Z-0123456789abcdef"
WHEN = "2026-11-15T06:45:00Z"


def flat(text):
    return " ".join(text.split())


def sections(**statuses):
    out = {}
    for name in SECTION_NAMES:
        status = statuses.get(name, "COLLECTED")
        out[name] = {"collection_status": status,
                     "reason": None if status == "COLLECTED" else
                     "PERMISSION_DENIED: %s could not be read as this user." % name}
    return out


class Header(unittest.TestCase):

    def test_the_header_names_product_version_command_mode_snapshot_and_time(self):
        text = summary.header("isedraf audit", "USER_PRODUCTION", SNAP, WHEN)
        self.assertIn("ISEDRAF %s | isedraf audit" % ENGINE_VERSION, text)
        self.assertIn("Standard Audit, your personal evidence store", text)
        self.assertIn("snapshot %s, collected %s" % (SNAP, WHEN), text)

    def test_the_header_is_ascii_and_framed(self):
        text = summary.header("isedraf audit", "SYSTEM_PRODUCTION", SNAP, WHEN)
        text.encode("ascii")
        lines = text.splitlines()
        self.assertEqual(lines[0], lines[-1])
        self.assertEqual(set(lines[0]), {"-"})

    def test_a_command_without_evidence_names_no_mode_or_snapshot(self):
        self.assertEqual(len(summary.header("isedraf inventory").splitlines()), 3)


class AuditSummary(unittest.TestCase):

    def render(self, store="USER_PRODUCTION", identity=True, **statuses):
        found = sections(**statuses)
        status = "COLLECTED" if not statuses else "PARTIAL"
        return summary.audit_summary(found, SECTION_NAMES, status, store, "/home/u/.local/"
                                     "state/isedraf", identity, SNAP)

    def test_a_complete_run_says_so_and_shows_no_exit_2_note(self):
        text = self.render()
        self.assertIn("Committed: one run, complete.", text)
        self.assertIn("Coverage of %d areas: %d COLLECTED, 0 PARTIAL, 0 NOT_TESTED, 0 ERROR."
                      % (len(SECTION_NAMES), len(SECTION_NAMES)), text)
        self.assertNotIn("Exit 2", text)

    def test_an_incomplete_run_counts_explains_each_area_and_exit_2(self):
        text = self.render(accounts="PARTIAL", sudo="NOT_TESTED", mounts="ERROR")
        self.assertIn("incomplete", text)
        self.assertIn("1 PARTIAL, 1 NOT_TESTED, 1 ERROR", text)
        for name in ("accounts", "sudo", "mounts"):
            self.assertIn("%s could not be read as this user (PERMISSION_DENIED)" % name,
                          flat(text))
        self.assertIn("Exit 2 means the run was committed with incomplete areas. Without "
                      "root that is expected. It is not a security verdict.", flat(text))

    def test_full_audit_is_named_only_where_a_fixed_operation_reads_more(self):
        text = flat(self.render(accounts="PARTIAL", mounts="PARTIAL"))
        self.assertIn("Full Audit (sudo isedraf audit) reads /etc/shadow.", text)
        self.assertEqual(text.count("Full Audit ("), 1)
        self.assertIn("Full Audit runs on Debian 12, Ubuntu 24.04, Rocky Linux 9, AlmaLinux 9, "
                      "with systemd.", text)
        self.assertNotIn("..", text)

    def test_the_full_audit_hint_matches_the_registered_operations(self):
        # Three sections, served by the four registered fixed operations (AUTH-024).
        self.assertEqual(sorted(summary.FULL_AUDIT_READS), ["accounts", "ssh", "sudo"])
        self.assertEqual(len(contracts.CONTRACTS), 4)

    def test_where_it_is_and_the_next_commands(self):
        text = self.render()
        self.assertIn("Stored in your personal evidence store: /home/u/.local/state/isedraf",
                      text)
        self.assertIn("0700", text)
        self.assertIn("  isedraf evaluate", text)
        self.assertIn("  isedraf report", text)

    def test_the_system_store_names_sudo_commands_and_no_full_audit_hint(self):
        text = self.render(store="SYSTEM_PRODUCTION", accounts="PARTIAL")
        self.assertIn("  sudo isedraf evaluate", text)
        self.assertNotIn("Full Audit (sudo", text)

    def test_every_line_fits_the_terminal(self):
        text = self.render(accounts="PARTIAL", sudo="NOT_TESTED", ssh="PARTIAL")
        for line in text.splitlines():
            self.assertLessEqual(len(line), summary.WIDTH, line)


class FullAuditRoute(unittest.TestCase):
    """P4: the Full Audit route shows the same summary, naming the system store."""

    def test_the_engine_reports_collected_and_leaves_the_commit_to_the_launcher(self):
        found = sections(sudo="PARTIAL")
        text = summary.audit_summary(found, SECTION_NAMES, "PARTIAL", "SYSTEM_PRODUCTION",
                                     "/var/lib/isedraf", True, SNAP, committed=False)
        self.assertIn("Collected: one run, incomplete", text)
        self.assertNotIn("Committed:", text)
        self.assertIn("To be stored in the system evidence store: /var/lib/isedraf", text)
        self.assertIn("  sudo isedraf evaluate", text)
        self.assertIn("Exit 2 means the run was committed with incomplete areas. It is not a "
                      "security verdict.", flat(text))
        self.assertNotIn("Without root", text)


class Approval(unittest.TestCase):
    """P5: what is approved is shown before anything is written."""

    OBJ = {"snapshot_id": SNAP, "profile": {"object": {"profile_id": "v0.4-default-1"}},
           "required_sections": ["host_identity", "accounts", "ssh", "loginpolicy"],
           "sections": {"host_identity": {"collection_status": "COLLECTED"},
                        "accounts": {"collection_status": "COLLECTED"},
                        "ssh": {"collection_status": "COLLECTED"},
                        "loginpolicy": {"collection_status": "COLLECTED"}}}

    def test_the_approval_names_run_time_store_profile_sections_and_meaning(self):
        text = summary.approval_text(self.OBJ, WHEN, "SYSTEM_PRODUCTION")
        self.assertIn("Approving as the baseline: %s\n  collected: %s" % (SNAP, WHEN), text)
        self.assertIn("the system evidence store (SYSTEM_PRODUCTION)", text)
        self.assertIn("profile: v0.4-default-1", text)
        for name in self.OBJ["required_sections"]:
            self.assertIn("%s COLLECTED" % name, flat(text))
        self.assertIn("Approval records accepted state; it does not establish that the host is "
                      "secure.", flat(text))

    def test_the_user_route_shows_it_before_the_commit(self):
        from unittest import mock
        from isedraf.baseline import approve
        order = []
        with mock.patch.object(approve, "plan", return_value=("WRITE", self.OBJ, b"{}")), \
                mock.patch.object(approve, "commit",
                                  side_effect=lambda *a, **k: order.append("commit") or "A"):
            approve.approve("/nonexistent", "DEV", SNAP, None,
                            before_write=lambda obj: order.append("shown"))
        self.assertEqual(order, ["shown", "commit"])


class Refusal(unittest.TestCase):

    def test_a_refusal_says_what_failed_what_was_written_and_what_next(self):
        text = summary.refusal("STATE_ROOT_MODE: the store is 0755, it must be 0700",
                               "Nothing was collected or written.", "chmod 700 ~/x")
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("isedraf: STATE_ROOT_MODE"))
        self.assertIn("  Nothing was collected or written.", lines)
        self.assertEqual(lines[-1], "  next: chmod 700 ~/x")


if __name__ == "__main__":
    unittest.main(verbosity=0)
