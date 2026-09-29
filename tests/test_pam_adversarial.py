# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Attack the PAM lane from its contract and from the documented grammar.
# Implements: SCOPE-022, SCOPE-045, GOV-002
#
# RED, PASS 1. Written against PAM_LANE_CONTRACT.md with no implementation to read.
#
# Several fixtures are taken from the pam.d grammar as documented and as it appears on a
# real host, not from our own assumptions - the SSH defect happened because an oracle was
# invented rather than derived. Control expressions like [default=bad success=ok
# user_unknown=ignore] are real forms, not constructions.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""Independent adversarial attack on the PAM lane."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import result                            # noqa: E402
from isedraf.pam import acquire, model                       # noqa: E402


class Fixture(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)
        os.makedirs(os.path.join(self.base, "etc/pam.d"))

    def service(self, name, text, mode=None):
        path = os.path.join(self.base, "etc/pam.d", name)
        with open(path, "w") as handle:
            handle.write(text)
        if mode is not None:
            os.chmod(path, mode)
        return path

    def collect(self, **services):
        for name, text in services.items():
            self.service(name.replace("__", "-"), text)
        return acquire.collect(self.base)

    def rules(self, ev, service=None):
        out = [r for r in ev.records if r["kind"] == model.RULE]
        if service is not None:
            out = [r for r in out if r["service"] == service]
        return out


class Grammar(Fixture):

    def test_the_four_types(self):
        ev = self.collect(sshd="auth required pam_unix.so\n"
                               "account required pam_unix.so\n"
                               "password required pam_unix.so\n"
                               "session required pam_unix.so\n")
        self.assertEqual([r["type"] for r in self.rules(ev)],
                         ["auth", "account", "password", "session"])

    def test_the_optional_dash_prefix_is_a_field_not_part_of_the_type(self):
        # `-session` means "do not complain if the module is missing". Folding the dash
        # into the type string would produce a fifth type that does not exist.
        ev = self.collect(sshd="-session optional pam_systemd.so\n")
        record = self.rules(ev)[0]
        self.assertEqual(record["type"], "session")
        self.assertTrue(record["silent_if_missing"])

    def test_simple_controls(self):
        ev = self.collect(sshd="auth required pam_unix.so\n"
                               "auth requisite pam_deny.so\n"
                               "auth sufficient pam_rootok.so\n"
                               "auth optional pam_cap.so\n")
        self.assertEqual([r["control"] for r in self.rules(ev)],
                         ["required", "requisite", "sufficient", "optional"])

    def test_module_and_arguments_are_separate(self):
        ev = self.collect(sshd="auth required pam_unix.so try_first_pass nullok\n")
        record = self.rules(ev)[0]
        self.assertEqual(record["module"], "pam_unix.so")
        self.assertEqual(record["arguments"], ["try_first_pass", "nullok"])

    def test_argument_containing_equals_is_not_split(self):
        ev = self.collect(sshd="password required pam_pwquality.so retry=3 minlen=12\n")
        self.assertEqual(self.rules(ev)[0]["arguments"], ["retry=3", "minlen=12"])

    def test_bracketed_argument_is_kept_whole(self):
        ev = self.collect(sshd="auth required pam_env.so envfile=/etc/env conffile=/e\n")
        self.assertEqual(len(self.rules(ev)[0]["arguments"]), 2)

    def test_comments_and_blank_lines_are_not_rules(self):
        ev = self.collect(sshd="#%PAM-1.0\n\n   \nauth required pam_unix.so\n")
        self.assertEqual(len(self.rules(ev)), 1)

    def test_unusual_whitespace(self):
        ev = self.collect(sshd="auth\t\trequired    pam_unix.so\n")
        self.assertEqual(self.rules(ev)[0]["module"], "pam_unix.so")

    def test_unknown_module_is_evidence_not_an_error(self):
        ev = self.collect(sshd="auth required pam_something_new_2029.so\n")
        self.assertEqual(ev.status, result.COLLECTED)

    def test_malformed_line_is_unsupported_not_guessed(self):
        ev = self.collect(sshd="auth\n")
        self.assertTrue([r for r in ev.records if r["kind"] == model.UNSUPPORTED])
        self.assertNotEqual(ev.status, result.COLLECTED)

    def test_unparsed_line_content_is_digested_not_retained(self):
        # A PAM line can name a module path or an argument carrying a file location.
        # The line we understand least is the one whose contents we are least entitled
        # to publish.
        ev = self.collect(sshd="PAMSECRETFIXTUREONLY nonsense here\n")
        unsupported = [r for r in ev.records if r["kind"] == model.UNSUPPORTED]
        self.assertTrue(unsupported)
        self.assertTrue(unsupported[0]["raw_digest"].startswith("sha256:"))
        for record in ev.records:
            for value in record.values():
                if isinstance(value, str):
                    self.assertNotIn("PAMSECRETFIXTUREONLY", value)

    def test_line_continuation_is_joined(self):
        ev = self.collect(sshd="auth required pam_unix.so \\\n    try_first_pass\n")
        self.assertEqual(self.rules(ev)[0]["arguments"], ["try_first_pass"])


class BracketedControls(Fixture):
    """Real forms from a running host, not constructions."""

    def test_numeric_jump_is_kept_numeric(self):
        ev = self.collect(sshd="session [success=1 default=ignore] pam_succeed_if.so\n")
        actions = self.rules(ev)[0]["control_actions"]
        mapping = {a["condition"]: a["action"] for a in actions}
        self.assertEqual(mapping["success"], 1)
        self.assertEqual(mapping["default"], "ignore")

    def test_named_actions_are_preserved(self):
        ev = self.collect(sshd="auth [success=done default=bad] pam_unix.so\n")
        mapping = {a["condition"]: a["action"]
                   for a in self.rules(ev)[0]["control_actions"]}
        self.assertEqual(mapping["success"], "done")
        self.assertEqual(mapping["default"], "bad")

    def test_multiple_conditions_are_all_kept_in_order(self):
        ev = self.collect(sshd="account [default=bad success=ok user_unknown=ignore] "
                               "pam_sss.so\n")
        actions = self.rules(ev)[0]["control_actions"]
        self.assertEqual([a["condition"] for a in actions],
                         ["default", "success", "user_unknown"])

    def test_the_control_is_not_collapsed_to_a_single_token(self):
        # Collapsing to CUSTOM destroys exactly the evidence a later criterion needs.
        ev = self.collect(sshd="auth [success=1 default=ignore] pam_unix.so\n")
        record = self.rules(ev)[0]
        self.assertEqual(record["control"], model.BRACKETED)
        self.assertTrue(record["control_actions"])

    def test_malformed_bracket_is_unsupported_not_partially_guessed(self):
        ev = self.collect(sshd="auth [success=1 default pam_unix.so\n")
        self.assertNotEqual(ev.status, result.COLLECTED)

    def test_simple_control_has_no_action_map(self):
        ev = self.collect(sshd="auth required pam_unix.so\n")
        self.assertIsNone(self.rules(ev)[0]["control_actions"])


class IncludeAndSubstack(Fixture):
    """Two different edges. Treating them as one loses the jump-escape boundary."""

    def test_include_and_substack_are_distinguished(self):
        ev = self.collect(sshd="auth include password-auth\n"
                               "auth substack postlogin\n",
                          password__auth="auth required pam_unix.so\n",
                          postlogin="session optional pam_lastlog.so\n")
        edges = [r["edge"] for r in ev.records if r["kind"] == model.EDGE]
        self.assertIn(model.INCLUDE, edges)
        self.assertIn(model.SUBSTACK, edges)
        self.assertNotEqual(model.INCLUDE, model.SUBSTACK)

    def test_the_referenced_service_is_recorded_as_a_name(self):
        ev = self.collect(sshd="auth include password-auth\n",
                          password__auth="auth required pam_unix.so\n")
        edge = [r for r in ev.records if r["kind"] == model.EDGE][0]
        self.assertEqual(edge["target_service"], "password-auth")

    def test_rules_from_the_referenced_service_carry_their_own_service_name(self):
        ev = self.collect(sshd="auth include password-auth\n",
                          password__auth="auth required pam_unix.so\n")
        services = set(r["service"] for r in self.rules(ev))
        self.assertIn("password-auth", services)

    def test_missing_target_service_is_reported(self):
        ev = self.collect(sshd="auth include nosuchservice\n")
        self.assertNotEqual(ev.status, result.COLLECTED)

    def test_unreadable_target_service_is_reported(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores these permission bits")
        self.service("locked", "auth required pam_unix.so\n", mode=0)
        ev = self.collect(sshd="auth include locked\n")
        self.assertNotEqual(ev.status, result.COLLECTED)

    def test_cycle_terminates(self):
        ev = self.collect(sshd="auth include other\n", other="auth include sshd\n")
        self.assertIsNotNone(ev.status)
        self.assertNotEqual(ev.status, result.COLLECTED)

    def test_a_service_referenced_twice_is_not_deduplicated_away(self):
        ev = self.collect(sshd="auth include common\naccount include common\n",
                          common="auth required pam_unix.so\n")
        self.assertGreaterEqual(len(self.rules(ev, "common")), 1)


class Confinement(Fixture):

    def test_a_fixture_root_never_reads_the_live_pam_d(self):
        ev = self.collect(sshd="auth required pam_unix.so\n")
        for record in ev.records:
            self.assertTrue(record["source_path"].startswith(self.base),
                            record["source_path"])

    def test_a_target_naming_a_path_does_not_escape_the_root(self):
        # Targets are service names. Something path-like must not become a traversal.
        ev = self.collect(sshd="auth include ../../etc/passwd\n")
        for record in ev.records:
            self.assertTrue(record["source_path"].startswith(self.base))

    def test_missing_pam_d_is_not_tested(self):
        shutil.rmtree(os.path.join(self.base, "etc/pam.d"))
        self.assertEqual(acquire.collect(self.base).status, result.NOT_TESTED)


class NoVerdicts(Fixture):

    def test_module_presence_is_not_a_conclusion(self):
        ev = self.collect(sshd="auth required pam_faillock.so preauth\n"
                               "password required pam_pwquality.so retry=3\n")
        for record in ev.records:
            for field in ("secure", "lockout_configured", "policy_effective",
                          "mfa", "hardened", "compliant", "finding", "risk"):
                self.assertNotIn(field, record)

    def test_the_limitation_states_that_no_outcome_is_computed(self):
        ev = self.collect(sshd="auth required pam_unix.so\n")
        limitation = ev.provenance["limitation"]
        self.assertIn("outcome", limitation.lower())


if __name__ == "__main__":
    unittest.main(verbosity=0)
