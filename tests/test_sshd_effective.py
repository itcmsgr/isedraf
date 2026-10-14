# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: resolve_sshd_effective_config_v1 - the global effective configuration, fail closed,
#          raw bytes kept, repeated-directive order kept, Match never claimed resolved.
# Implements: AUTH-031, SCOPE-020, SCOPE-021, SCOPE-022, AUTH-017, IQ-061, IQ-064
#
# Unprivileged and fixture-only: the supervisor is a scripted channel. Nothing runs sshd and
# nothing reads this machine's /etc/ssh.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""AUTH-031: sshd -T as the global effective configuration, and nothing more."""
import base64
import hashlib
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, os.path.join(HERE, "..", "scripts", "ci"))
sys.path.insert(0, HERE)

from isedraf import coverage                                           # noqa: E402
from isedraf.report import sections as report_sections                 # noqa: E402
from isedraf.shared import result                                      # noqa: E402
from isedraf.ssh import acquire, model                                 # noqa: E402
from isedraf.supervisor import contracts, protocol                     # noqa: E402
import check_privileged_operations as gate                             # noqa: E402
import test_sshd_operation as declared                                 # noqa: E402

DECLARED_FRAME = declared.surface("PermitRootLogin no\n", [])
OUTPUT = (b"port 22\n"
          b"addressfamily any\n"
          b"listenaddress 127.0.0.1:22\n"
          b"listenaddress 0.0.0.0:22\n"
          b"permitrootlogin no\n"
          b"hostkey /etc/ssh/ssh_host_ed25519_key\n"
          b"acceptenv LANG LC_*\n")


class Channel(object):
    """The supervisor, scripted per identifier."""

    def __init__(self, effective, declared_res=None):
        self.answers = {
            acquire.SSHD_OPERATION: declared_res or protocol.result(
                acquire.SSHD_OPERATION, protocol.COMPLETED, DECLARED_FRAME),
            acquire.EFFECTIVE_OPERATION: effective}
        self.requests = []

    def request(self, operation_id):
        self.requests.append(operation_id)
        answer = self.answers[operation_id]
        if isinstance(answer, Exception):
            raise answer
        return answer


def ok(data=OUTPUT):
    return protocol.result(acquire.EFFECTIVE_OPERATION, protocol.COMPLETED, data, b"",
                           exit_code=0)


def failed(stderr=b"", exit_code=None):
    return protocol.result(acquire.EFFECTIVE_OPERATION, protocol.FAILED, stderr=stderr,
                           exit_code=exit_code)


def resolved(ev):
    return [r for r in ev.records if r.get("kind") == model.RESOLVED_SETTING]


class GlobalEffectiveConfiguration(unittest.TestCase):

    def collect(self, effective, declared_res=None):
        channel = Channel(effective, declared_res)
        ev = acquire.collect("/", channel=channel)
        # Two fixed identifiers, in order, and nothing else ever crosses the channel.
        self.assertEqual(channel.requests, [acquire.SSHD_OPERATION, acquire.EFFECTIVE_OPERATION])
        return ev

    def test_settings_are_records_in_output_order_with_values_exactly_as_printed(self):
        ev = self.collect(ok())
        self.assertEqual(ev.status, result.COLLECTED, ev.reason)
        rows = [(r["keyword"], r["value"], r["occurrence"]) for r in resolved(ev)]
        self.assertEqual(rows, [("port", "22", 0), ("addressfamily", "any", 0),
                                ("listenaddress", "127.0.0.1:22", 0),
                                ("listenaddress", "0.0.0.0:22", 1),
                                ("permitrootlogin", "no", 0),
                                ("hostkey", "/etc/ssh/ssh_host_ed25519_key", 0),
                                ("acceptenv", "LANG LC_*", 0)])
        self.assertEqual([r["ordinal"] for r in resolved(ev)], list(range(7)))
        # The declared dimension is still there, unchanged in kind.
        self.assertIn("DIRECTIVE", [r["kind"] for r in ev.records])

    def test_repeated_directive_order_is_state_never_sorted(self):
        """IQ-064: overlapping listen addresses bind first-come; order is meaning."""
        swapped = OUTPUT.replace(b"listenaddress 127.0.0.1:22\nlistenaddress 0.0.0.0:22\n",
                                 b"listenaddress 0.0.0.0:22\nlistenaddress 127.0.0.1:22\n")
        a = [(r["value"], r["occurrence"]) for r in resolved(self.collect(ok()))
             if r["keyword"] == "listenaddress"]
        b = [(r["value"], r["occurrence"]) for r in resolved(self.collect(ok(swapped)))
             if r["keyword"] == "listenaddress"]
        self.assertEqual(a, [("127.0.0.1:22", 0), ("0.0.0.0:22", 1)])
        self.assertEqual(b, [("0.0.0.0:22", 0), ("127.0.0.1:22", 1)])
        self.assertEqual(model.CLASSIFICATION["occurrence"], result.STATE)
        self.assertEqual(model.CLASSIFICATION["ordinal"], result.PROVENANCE)

    def test_the_raw_output_is_kept_byte_for_byte(self):
        data = OUTPUT + b"banner /etc/issue.\xff\n"
        ev = self.collect(ok(data))
        raw = ev.provenance["resolved"]["raw_stdout"]
        self.assertEqual(base64.b64decode(raw["base64"]), data)
        self.assertEqual(raw["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(raw["byte_count"], len(data))
        banner = [r for r in resolved(ev) if r["keyword"] == "banner"][0]
        self.assertEqual(os.fsencode(banner["value"]), b"/etc/issue.\xff")

    def test_match_is_never_claimed_resolved(self):
        ev = self.collect(ok())
        context = ev.provenance["resolved"]["connection_context"]
        self.assertEqual(context["status"], result.NOT_TESTED)
        self.assertIn("Match", context["reason"])
        self.assertIn("global effective configuration", ev.provenance["limitation"])
        self.assertIn("Match", ev.provenance["limitation"])
        self.assertEqual(ev.provenance["resolved"]["scope"], model.RESOLVED_SCOPE)
        self.assertIn("sshd -T -C", ev.provenance["not_collected"])
        self.assertNotIn("sshd -T", ev.provenance["not_collected"])

    def test_coverage_names_the_operation_and_the_command(self):
        ev = self.collect(ok())
        entry = [c for c in ev.provenance["coverage"] if c["source"] == acquire.EFFECTIVE_SOURCE][0]
        self.assertEqual((entry["operation"], entry["status"], entry["access_outcome"]),
                         (coverage.OP_COMMAND, result.COLLECTED, coverage.READ_OK))
        self.assertEqual((entry["acquisition_mode"], entry["operation_id"]),
                         (coverage.MODE_SUPERVISOR_FIXED_OPERATION, acquire.EFFECTIVE_OPERATION))

    # -- fail closed (AUTH-031, SCOPE-022) ---------------------------------------------------

    def assert_failed_closed(self, ev, status, *needles):
        self.assertEqual(resolved(ev), [])
        res = ev.provenance["resolved"]
        self.assertEqual(res["status"], status)
        for needle in needles:
            self.assertIn(needle, res["reason"])
        self.assertEqual(ev.status, result.PARTIAL)      # the declared dimension was observed
        self.assertIn("resolved", ev.reason)

    def test_a_nonzero_exit_is_error_with_exit_status_and_stderr_excerpt(self):
        ev = self.collect(failed(b"/etc/ssh/sshd_config line 3: Bad configuration option: X\n",
                                 exit_code=255))
        self.assert_failed_closed(ev, result.ERROR, "255", "Bad configuration option")

    def test_exit_zero_with_empty_stdout_is_error(self):
        self.assert_failed_closed(self.collect(ok(b"")), result.ERROR, "EMPTY_OUTPUT")

    def test_output_beyond_the_bound_is_error_and_nothing_is_parsed(self):
        ev = self.collect(protocol.result(acquire.EFFECTIVE_OPERATION, protocol.TRUNCATED))
        self.assert_failed_closed(ev, result.ERROR, "TRUNCATED")

    def test_a_timeout_is_error(self):
        self.assert_failed_closed(self.collect(failed(b"TIMEOUT")), result.ERROR, "TIMEOUT")

    def test_an_unparseable_line_fails_the_whole_output(self):
        ev = self.collect(ok(OUTPUT + b"Not A Setting\n"))
        self.assert_failed_closed(ev, result.ERROR, "UNPARSEABLE")
        raw = ev.provenance["resolved"]["raw_stdout"]
        self.assertEqual(base64.b64decode(raw["base64"]), OUTPUT + b"Not A Setting\n")

    def test_an_absent_tool_is_not_tested(self):
        self.assert_failed_closed(self.collect(failed(b"ENOENT")), result.NOT_TESTED,
                                  "TOOL_ABSENT")

    def test_an_untrusted_executable_is_not_tested(self):
        self.assert_failed_closed(self.collect(failed(b"UNTRUSTED_EXECUTABLE")),
                                  result.NOT_TESTED, "UNTRUSTED_EXECUTABLE")

    def test_a_refusal_is_not_tested(self):
        ev = self.collect(protocol.result(acquire.EFFECTIVE_OPERATION, protocol.REFUSED,
                                          stderr=b"NOT_ENABLED"))
        self.assert_failed_closed(ev, result.NOT_TESTED, "SUPERVISOR_REFUSED")

    def test_a_channel_failure_is_error(self):
        ev = self.collect(protocol.ProtocolError("closed"))
        self.assert_failed_closed(ev, result.ERROR, "SUPERVISOR_CHANNEL_FAILED")

    def test_stderr_excerpt_is_bounded_and_sanitized(self):
        ev = self.collect(failed(b"\x1b[31mbad\x00" + b"x" * 5000, exit_code=1))
        reason = ev.provenance["resolved"]["reason"]
        self.assertNotIn("\x1b", reason)
        self.assertNotIn("\x00", reason)
        self.assertLess(len(reason), 600)

    def test_declared_failure_with_resolved_success_is_partial(self):
        ev = self.collect(ok(), declared_res=protocol.result(
            acquire.SSHD_OPERATION, protocol.REFUSED, stderr=b"NOT_ENABLED"))
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertTrue(resolved(ev))
        self.assertIn("declared", ev.reason)

    # -- the standard route is untouched ----------------------------------------------------

    def test_the_standard_route_never_runs_sshd_and_keeps_its_shape(self):
        base = os.path.join(os.path.dirname(HERE), "tests", "fixtures")
        root = os.path.join(base, "w3", "debian12") if os.path.isdir(
            os.path.join(base, "w3", "debian12")) else "/nonexistent-isedraf-root"
        ev = acquire.collect(root)
        self.assertEqual(resolved(ev), [])
        self.assertNotIn("resolved", ev.provenance)
        self.assertEqual(ev.provenance["limitation"], model.LIMITATION)
        self.assertIn("sshd -T", ev.provenance["not_collected"])

    # -- the contract and the report ----------------------------------------------------------

    def test_the_contract_is_the_fixed_executable_with_argv_exactly_dash_T(self):
        c = contracts.CONTRACTS[acquire.EFFECTIVE_OPERATION]
        self.assertEqual((c["performer"], c["fixed_executable"], c["fixed_argv"]),
                         (contracts.PERFORM_FIXED_EXECUTABLE, "/usr/sbin/sshd", ["-T"]))
        with open(str(gate.REGISTRY)) as handle:
            registry = dict((o["operation_id"], o) for o in json.load(handle)["operations"])
        for field in contracts.MIRRORED:
            self.assertEqual(c[field], registry[acquire.EFFECTIVE_OPERATION][field], field)

    def test_the_report_names_it_global_and_says_match_is_not_resolved(self):
        ev = self.collect(ok())
        rows = dict(report_sections.summarize("ssh", {"evidence": {
            "records": ev.records, "provenance": ev.provenance}}))
        self.assertEqual(rows["Declared configuration"], "COLLECTED - 1 records")
        self.assertEqual(rows["Global effective configuration (sshd -T, global only)"],
                         "COLLECTED - 7 settings")
        self.assertTrue(rows["Match-dependent (connection-specific) values"].startswith(
            "NOT_TESTED - not resolved by this audit"))

    def test_the_report_of_a_declared_only_section_is_unchanged(self):
        rows = report_sections.summarize("ssh", {"evidence": {"records": [{"kind": "DIRECTIVE"}],
                                                              "provenance": {}}})
        self.assertEqual(rows, [("Records observed", 1)])


if __name__ == "__main__":
    unittest.main()
