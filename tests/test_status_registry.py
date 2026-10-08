# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The status registry is derived truth: every reachable surface has an entry,
#          and every entry names a surface that exists.
# Implements: D-89, D-123, GOV-007
#
# IQ-043 and IQ-035. users/groups, sudo, SSH, PAM and mounts were PLANNED while
# `isedraf audit` collected them, and four collected sections had no entry at all,
# because nothing compared a PLANNED entry with the code. These cases hold the
# comparison in both directions.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3,git"
# =============================================================================

"""Status registry truth: surfaces and sections derived from the code, both directions."""
import copy
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts", "docs"))

import current_state                                         # noqa: E402


def truth(capabilities):
    return current_state.registry_truth(
        capabilities, current_state.audit_sections(), current_state.cli_surfaces(),
        current_state.privileged_operations(), current_state.acquisition_modes())


class DerivedSurfaces(unittest.TestCase):

    def test_the_cli_surfaces_are_read_from_the_parser_source(self):
        surfaces = current_state.cli_surfaces()
        for expected in ("identity", "inventory", "inventory --json", "audit", "report",
                         "report --json", "report --html"):
            self.assertIn(expected, surfaces)

    def test_the_audit_sections_are_the_snapshot_sections(self):
        sections = current_state.audit_sections()
        self.assertIn("accounts", sections)
        self.assertIn("authorizedkeys", sections)


class TheRegistryIsTrue(unittest.TestCase):

    def setUp(self):
        self.caps = copy.deepcopy(current_state.REGISTRY["capabilities"])

    def test_the_committed_registry_holds(self):
        self.assertEqual(truth(self.caps), [])

    def test_a_collected_section_cannot_be_missing(self):
        name = [n for n, c in self.caps.items() if c.get("audit_section") == "accounts"]
        self.assertEqual(len(name), 1)
        del self.caps[name[0]]
        self.assertTrue([p for p in truth(self.caps) if "accounts" in p])

    def test_a_reachable_capability_cannot_be_planned(self):
        name = [n for n, c in self.caps.items() if c.get("audit_section") == "sudo"][0]
        self.caps[name]["status"] = "PLANNED"
        self.caps[name]["evidence"] = None
        self.assertTrue([p for p in truth(self.caps) if name in p])

    def test_a_public_surface_cannot_be_missing(self):
        for cap in self.caps.values():
            cap["reachable_from"] = [s for s in cap.get("reachable_from", [])
                                     if s != "report --html"]
        self.assertTrue([p for p in truth(self.caps) if "report --html" in p])

    def test_a_zombie_surface_is_refused(self):
        name = [n for n, c in self.caps.items() if c.get("audit_section") == "pam"][0]
        self.caps[name]["reachable_from"].append("frobnicate")
        self.assertTrue([p for p in truth(self.caps) if "frobnicate" in p])

    def test_a_zombie_section_is_refused(self):
        name = [n for n, c in self.caps.items() if c.get("audit_section") == "pam"][0]
        self.caps[name]["audit_section"] = "firewall"
        self.assertTrue([p for p in truth(self.caps) if "firewall" in p])

    def test_full_audit_gain_follows_the_operation_registry(self):
        name = [n for n, c in self.caps.items() if c.get("audit_section") == "accounts"][0]
        self.assertEqual(self.caps[name]["full_audit_gain"], "PLANNED_FIXED_OPERATION")
        self.caps[name]["full_audit_gain"] = "NONE"
        self.assertTrue([p for p in truth(self.caps) if name in p])

    def test_authority_is_only_a_frozen_value(self):
        name = [n for n, c in self.caps.items() if c.get("audit_section") == "nss"][0]
        self.caps[name]["authority"] = "ROOT"
        self.assertTrue([p for p in truth(self.caps) if name in p])

    def test_every_entry_carries_the_four_fields(self):
        for name, cap in self.caps.items():
            for field in current_state.TRUTH_FIELDS:
                self.assertIn(field, cap, name)


if __name__ == "__main__":
    unittest.main()
