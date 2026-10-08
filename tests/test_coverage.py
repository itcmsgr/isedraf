# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: R1.5-P — the boundary of what a collection could prove, end to end.
# Implements: SCOPE-022, SCOPE-045, GOV-002
#
# The eight proofs the owner required before this contract may freeze, plus the two that
# carry the most weight: the /etc/shadow case that measured the gap, and a visibility
# change that must not read as a host change.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""Evidence coverage: derived centrally, carried structurally, rendered from fields."""
import ast
import inspect
import re
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf import coverage                                   # noqa: E402
from isedraf.accounts import acquire as accounts_acquire       # noqa: E402
from isedraf.report import model as report_model               # noqa: E402

ALICE = "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"


class _Collectors(dict):
    """Schema 2 needs a collector identity per domain (ELIM-006)."""

    def __missing__(self, domain):
        return {"collector_id": "isedraf.test." + domain, "collector_version": "1",
                "parser_version": "1"}


def limits(sources, mode=None):
    """coverage.manifest under schema 2, for tests that predate collector identity."""
    return coverage.manifest(sources, mode, _Collectors())


def entry(**kw):
    kw.setdefault("domain", "d")
    kw.setdefault("name", "s")
    kw.setdefault("status", coverage.COLLECTED)
    kw.setdefault("outcome", coverage.READ_OK)
    kw.setdefault("operation", coverage.OP_FILE_READ)
    return coverage.source(**kw)


class Vocabulary(unittest.TestCase):

    def test_root_is_not_an_access_requirement(self):
        """root is a MECHANISM. Naming it as the requirement is how a tool learns to
        give exactly one piece of advice."""
        for name in coverage.ACCESS_REQUIREMENTS:
            self.assertNotIn("ROOT", name)
            self.assertNotIn("SUDO", name)

    def test_the_unspecified_class_exists_and_is_named_for_the_requirement(self):
        self.assertIn(coverage.ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED,
                      coverage.ACCESS_REQUIREMENTS)

    def test_every_requirement_is_distinct(self):
        self.assertEqual(len(set(coverage.ACCESS_REQUIREMENTS)),
                         len(coverage.ACCESS_REQUIREMENTS))


class CentralDerivation(unittest.TestCase):
    """Owner ruling 4: one rule, one place. A domain states facts and derives nothing."""

    def test_only_a_refusal_implies_an_access_requirement(self):
        for outcome in (coverage.NOT_FOUND, coverage.IO_ERROR,
                        coverage.NOT_SUPPORTED, coverage.READ_OK):
            got = entry(outcome=outcome, status=coverage.NOT_TESTED)
            self.assertFalse(got["privilege_limited"], outcome)
            self.assertEqual(got["required_access"], coverage.ACCESS_NONE, outcome)

    def test_an_unknown_operation_cannot_be_invented(self):
        with self.assertRaises(ValueError):
            entry(operation="GUESSED")

    def test_the_requirement_follows_the_operation(self):
        pairs = ((coverage.OP_FILE_READ, coverage.ACCESS_FILE_READ),
                 (coverage.OP_DIRECTORY_LIST, coverage.ACCESS_DIRECTORY_TRAVERSE),
                 (coverage.OP_COMMAND, coverage.ACCESS_COMMAND_QUERY),
                 (coverage.OP_KERNEL_INTERFACE, coverage.ACCESS_KERNEL_INTERFACE),
                 (coverage.OP_SERVICE_QUERY, coverage.ACCESS_SERVICE_QUERY))
        for operation, expected in pairs:
            got = entry(operation=operation, outcome=coverage.PERMISSION_DENIED,
                        status=coverage.NOT_TESTED)
            self.assertEqual(got["required_access"], expected)

    def test_absence_follows_the_universe_and_not_the_source_status(self):
        """CORRECTED (CQ-1). This asserted the conflation, not the rule.

        It required `status == COLLECTED`, so it demanded that a NOT_TESTED source with a
        COMPLETE universe be refused - which is the absent-/etc/fstab case, where zero
        records IS the fully established answer. A source status describes an acquisition
        operation; universe completeness describes whether the bounded universe was
        observed well enough to prove absence. Only the second decides this.

        S3 was corrected first and this authority was left contradicting it: for one
        source S3 answered ACTIVE_ONLY while this answered False.
        """
        for status in (coverage.COLLECTED, coverage.NOT_TESTED, coverage.PARTIAL,
                       coverage.ERROR):
            got = entry(status=status, universe=coverage.UNIVERSE_COMPLETE,
                        outcome=coverage.READ_OK)
            self.assertTrue(got["absence_claim_allowed"],
                            "a COMPLETE universe was refused because status was %s"
                            % status)
            got = entry(status=status, universe=coverage.UNIVERSE_INCOMPLETE,
                        outcome=coverage.READ_OK)
            self.assertFalse(got["absence_claim_allowed"],
                             "an INCOMPLETE universe was permitted at status %s" % status)

    def test_the_absent_and_refused_cases_differ_despite_one_status(self):
        absent = entry(status=coverage.NOT_TESTED, outcome=coverage.NOT_FOUND,
                       universe=coverage.UNIVERSE_COMPLETE)
        refused = entry(status=coverage.NOT_TESTED,
                        outcome=coverage.PERMISSION_DENIED,
                        universe=coverage.UNIVERSE_INCOMPLETE)
        self.assertTrue(absent["absence_claim_allowed"])
        self.assertFalse(refused["absence_claim_allowed"])
        self.assertEqual(absent["status"], refused["status"])

    def test_the_derivation_cannot_see_the_status_at_all(self):
        # The strongest form: the rule takes only the universe, so no future edit can
        # quietly reintroduce a status term without changing the signature.
        import inspect
        signature = inspect.signature(coverage.absence_claim_allowed)
        self.assertEqual(list(signature.parameters), ["universe"])

    def test_a_perfect_read_of_an_incomplete_universe_still_forbids_absence(self):
        # The authorized_keys shape: the file was read, and the SET is unknown.
        got = entry(status=coverage.COLLECTED, outcome=coverage.READ_OK,
                    universe=coverage.UNIVERSE_INCOMPLETE)
        self.assertFalse(got["absence_claim_allowed"])
        self.assertTrue(got["affects_completeness"])


class SixRequiredDistinctions(unittest.TestCase):
    """Each must survive as a field. None may be collapsed into the English reason."""

    def case(self, **kw):
        return entry(**kw)

    def test_source_absent(self):
        got = self.case(status=coverage.NOT_TESTED, outcome=coverage.NOT_FOUND)
        self.assertFalse(got["privilege_limited"])
        self.assertEqual(got["required_access"], coverage.ACCESS_NONE)

    def test_source_present_and_observed(self):
        got = self.case()
        self.assertFalse(got["affects_completeness"])
        self.assertTrue(got["absence_claim_allowed"])

    def test_source_present_and_privilege_limited(self):
        # A refused source bounds an INCOMPLETE universe: records may exist that were
        # never seen. Stating it is now the caller's job, which is the correction.
        got = self.case(status=coverage.NOT_TESTED,
                        outcome=coverage.PERMISSION_DENIED,
                        universe=coverage.UNIVERSE_INCOMPLETE)
        self.assertTrue(got["privilege_limited"])
        self.assertTrue(got["affects_completeness"])
        self.assertFalse(got["absence_claim_allowed"])

    def test_source_present_and_partially_observed(self):
        got = self.case(status=coverage.PARTIAL, outcome=coverage.READ_OK,
                        universe=coverage.UNIVERSE_INCOMPLETE)
        self.assertFalse(got["privilege_limited"])
        self.assertTrue(got["affects_completeness"])
        self.assertFalse(got["absence_claim_allowed"])

    def test_source_unavailable_for_a_non_privilege_reason(self):
        for outcome in (coverage.IO_ERROR, coverage.NOT_SUPPORTED):
            got = self.case(status=coverage.ERROR, outcome=outcome)
            self.assertFalse(got["privilege_limited"], outcome)
            self.assertEqual(got["required_access"], coverage.ACCESS_NONE)

    def test_additional_authority_needed_but_class_unknown(self):
        # Representable WITHOUT claiming root: the operation is one this vocabulary has
        # no narrower class for, and the honest answer is that we do not know which.
        got = coverage.source("d", "s", coverage.NOT_TESTED,
                              coverage.PERMISSION_DENIED,
                              coverage.OP_SERVICE_QUERY)
        self.assertEqual(got["required_access"], coverage.ACCESS_SERVICE_QUERY)
        self.assertEqual(
            coverage.required_access("UNMAPPED_FUTURE_OPERATION",
                                     coverage.PERMISSION_DENIED),
            coverage.ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED)


class RootIsNotCompleteness(unittest.TestCase):
    """Proved structurally rather than by exercising a mode production cannot reach.

    An earlier version proved this by building a manifest in MODE_ELEVATED and checking
    the report said the right thing. That mode was a fiction - SCOPE-071 refuses
    privileged execution, so no collection path could emit it - and a proof that depends
    on a value only tests can produce proves something about the tests.

    The stronger proof is that COMPLETENESS IS NOT A FUNCTION OF THE MODE at all: the
    counts are computed from source outcomes alone, so no mode, present or future, can
    make an incomplete collection report as complete.
    """

    def incomplete(self):
        return limits(
            [entry(name="a"),
             entry(name="b", status=coverage.NOT_TESTED,
                   outcome=coverage.NOT_FOUND)], coverage.MODE_CURRENT_IDENTITY)

    def test_completeness_is_computed_from_outcomes_not_from_the_mode(self):
        tree = ast.parse(inspect.getsource(coverage.manifest))
        body = inspect.getsource(coverage.manifest)
        counted = body[body.index('"requested_sources"'):body.index('"sources": ordered')]
        self.assertNotIn("acquisition_mode", counted,
                         "a completeness count read the acquisition mode")
        self.assertTrue(tree)

    def test_an_incomplete_run_stays_incomplete(self):
        got = self.incomplete()
        self.assertEqual(got["requested_sources"], 2)
        self.assertEqual(got["complete_sources"], 1)
        self.assertTrue(got["limitations"])

    def test_the_manifest_has_no_field_that_could_say_a_mode_means_complete(self):
        blob = json.dumps(self.incomplete())
        for word in ("full", "COMPLETE_HOST", "all_evidence", "everything",
                     "ELEVATED", "ROOT"):
            self.assertNotIn(word, blob)

    def test_the_report_says_no_mode_makes_it_complete(self):
        lines = report_model._coverage_limitations(self.incomplete())
        self.assertTrue(any("No acquisition mode makes it complete" in line
                            for line in lines))

    def test_a_complete_run_carries_no_limitation(self):
        got = limits([entry(name="a")], coverage.MODE_CURRENT_IDENTITY)
        self.assertEqual(got["limitations"], [])
        self.assertEqual(report_model._coverage_limitations(got), [])


class NoUnproducibleMode(unittest.TestCase):
    """Ruling D: nothing may be frozen that production cannot emit."""

    def test_only_one_mode_exists(self):
        self.assertEqual(coverage.MODES, (coverage.MODE_CURRENT_IDENTITY,))

    def test_an_elevated_mode_is_not_in_the_vocabulary(self):
        self.assertFalse(hasattr(coverage, "MODE_ELEVATED"))
        for mode in coverage.MODES:
            self.assertNotIn("ELEVATED", mode)
            self.assertNotIn("ROOT", mode)
            self.assertNotIn("PRIVILEGED", mode)

    def test_no_production_module_can_emit_a_mode_outside_the_vocabulary(self):
        import subprocess
        out = subprocess.check_output(
            ["git", "grep", "-hn", "MODE_", "--", "lib/"], universal_newlines=True)
        for line in out.splitlines():
            # A token that STARTS with MODE_; NSS_MODE_NOT_ASSERTED (IQ-036) is an account
            # reason code in another namespace, not a coverage mode.
            for token in re.findall(r"(?<![A-Za-z0-9_])MODE_[A-Z_]+", line):
                self.assertIn(token, ("MODE_CURRENT_IDENTITY", "MODES"),
                              "production names %s, which is not producible" % token)

    def test_an_invented_mode_is_refused(self):
        for bad in ("ELEVATED", "ROOT", "PRIVILEGED", "UNPRIVILEGED"):
            with self.assertRaises(ValueError):
                limits([], bad)


class ObservationCapability(unittest.TestCase):
    """Same host facts, different visibility. THE R3 foundation."""

    def runs(self):
        before = limits(
            [entry(domain="accounts", name="etc/passwd"),
             entry(domain="accounts", name="etc/shadow",
                   status=coverage.NOT_TESTED,
                   outcome=coverage.PERMISSION_DENIED)],
            coverage.MODE_CURRENT_IDENTITY)
        after = limits(
            [entry(domain="accounts", name="etc/passwd"),
             entry(domain="accounts", name="etc/shadow")],
            coverage.MODE_CURRENT_IDENTITY)
        return before, after

    def test_the_coverage_digest_changes_when_visibility_changes(self):
        before, after = self.runs()
        self.assertNotEqual(before["coverage_digest"], after["coverage_digest"])

    def test_the_change_is_classified_as_visibility_not_as_host_state(self):
        before, after = self.runs()
        delta = coverage.compare(before, after)
        self.assertTrue(delta["coverage_changed"])
        self.assertEqual([c["change"] for c in delta["changes"]],
                         ["VISIBILITY_INCREASED"])
        self.assertEqual(delta["host_state_delta"],
                         "NOT_ESTABLISHED_BY_COVERAGE_COMPARISON")

    def test_no_change_word_in_a_coverage_comparison_says_the_host_changed(self):
        before, after = self.runs()
        blob = json.dumps(coverage.compare(before, after))
        for word in ("ADDED", "REMOVED", "HOST_CHANGED", "DRIFT"):
            self.assertNotIn(word, blob.replace(
                "NOT_ESTABLISHED_BY_COVERAGE_COMPARISON", ""))

    def test_the_outcome_alone_changes_the_digest(self):
        """Two runs with the SAME status and different reasons for it.

        The first version of this class changed status and outcome together, so status
        alone separated the runs and a digest that ignored the access outcome passed. A
        falsification injection that deleted the outcome from the digest frame went
        undetected, which is how the gap was found rather than argued about.
        """
        absent = limits(
            [entry(name="s", status=coverage.NOT_TESTED,
                   outcome=coverage.NOT_FOUND)], coverage.MODE_CURRENT_IDENTITY)
        refused = limits(
            [entry(name="s", status=coverage.NOT_TESTED,
                   outcome=coverage.PERMISSION_DENIED)], coverage.MODE_CURRENT_IDENTITY)
        self.assertNotEqual(absent["coverage_digest"], refused["coverage_digest"],
                            "a source that is absent and one that is refused produced "
                            "the same observation-capability identity")

    def test_identical_visibility_yields_an_identical_digest(self):
        # Otherwise every run would look like a visibility change.
        first = limits([entry(name="a")], coverage.MODE_CURRENT_IDENTITY)
        second = limits([entry(name="a")], coverage.MODE_CURRENT_IDENTITY)
        self.assertEqual(first["coverage_digest"], second["coverage_digest"])

    def test_the_digest_ignores_host_facts_and_watches_only_coverage(self):
        # A reason string is for people and must not move the identity that R3 compares.
        plain = limits([entry(name="a")], coverage.MODE_CURRENT_IDENTITY)
        annotated = limits(
            [entry(name="a", reason="a sentence that changed")],
            coverage.MODE_CURRENT_IDENTITY)
        self.assertEqual(plain["coverage_digest"], annotated["coverage_digest"])


class TheShadowProof(unittest.TestCase):
    """The measured case that opened R1.5-P, now answered without prose."""

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)
        os.makedirs(os.path.join(self.base, "etc"))
        self.write("etc/passwd", ALICE)
        self.write("etc/group", "alice:x:1000:\n")

    def write(self, relative, text, mode=None):
        path = os.path.join(self.base, relative)
        with open(path, "w") as handle:
            handle.write(text)
        if mode is not None:
            os.chmod(path, mode)
        return path

    def refused(self):
        path = self.write("etc/shadow", "alice:!:19000:0:99999:7:::\n")
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, 0o600)
        evidence = accounts_acquire.collect(self.base)
        return [s for s in evidence["coverage"] if s["source"] == "etc/shadow"][0]

    def test_a_machine_learns_it_was_access_without_reading_english(self):
        got = self.refused()
        self.assertEqual(got["access_outcome"], coverage.PERMISSION_DENIED)
        self.assertTrue(got["privilege_limited"])

    def test_a_machine_learns_what_access_would_be_needed(self):
        self.assertEqual(self.refused()["required_access"],
                         coverage.ACCESS_FILE_READ)

    def test_a_machine_learns_the_gap_affects_completeness(self):
        self.assertTrue(self.refused()["affects_completeness"])

    def test_a_machine_learns_absence_claims_are_forbidden(self):
        self.assertFalse(self.refused()["absence_claim_allowed"])

    def test_the_frozen_collection_status_is_unchanged(self):
        # SCOPE-022 decides the status. R1.5-P adds context and invents no new status.
        self.assertEqual(self.refused()["status"], coverage.NOT_TESTED)

    def test_an_absent_shadow_invents_no_privilege_requirement(self):
        evidence = accounts_acquire.collect(self.base)
        got = [s for s in evidence["coverage"] if s["source"] == "etc/shadow"][0]
        self.assertEqual(got["access_outcome"], coverage.NOT_FOUND)
        self.assertFalse(got["privilege_limited"])
        self.assertEqual(got["required_access"], coverage.ACCESS_NONE)

    def test_the_account_facts_are_unchanged_by_the_retrofit(self):
        """Backward compatibility: strip R1.5-P and the domain evidence is what it was."""
        evidence = accounts_acquire.collect(self.base)
        stripped = dict(evidence)
        stripped.pop("coverage")
        stripped["sources"] = {k: {"status": v["status"], "reason": v["reason"]}
                               for k, v in evidence["sources"].items()}
        self.assertEqual(stripped["local_accounts"][0]["name"], "alice")
        self.assertEqual(stripped["sources"]["etc/passwd"]["status"],
                         coverage.COLLECTED)
        self.assertNotIn("access_outcome", json.dumps(stripped))


class RendererReadsFieldsNotProse(unittest.TestCase):

    def test_the_renderer_never_inspects_a_reason_string(self):
        tree = ast.parse(inspect.getsource(report_model._coverage_limitations))
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                key = getattr(node.slice, "value", None)
                self.assertNotEqual(key, "reason",
                                    "the renderer read the English reason")
        source = inspect.getsource(report_model._coverage_limitations)
        for pattern in ('"permission denied"', "'permission denied'",
                        ".lower()", "in reason"):
            self.assertNotIn(pattern, source)

    def test_the_report_carries_the_manifest_rather_than_recomputing_it(self):
        source = inspect.getsource(report_model.build)
        self.assertIn('"evidence_limits": coverage_manifest', source)

    def test_no_manifest_and_an_empty_manifest_are_distinguishable(self):
        self.assertEqual(report_model._coverage_limitations(None), [])
        empty = limits([], coverage.MODE_CURRENT_IDENTITY)
        self.assertEqual(empty["requested_sources"], 0)


class Purity(unittest.TestCase):

    def test_coverage_senses_nothing_about_its_environment(self):
        tree = ast.parse(inspect.getsource(coverage))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("open", "geteuid", "getuid", "environ", "getcwd", "listdir",
                          "stat", "Popen", "check_output", "socket", "time"):
            self.assertNotIn(forbidden, names + attrs,
                             "coverage used %r; acquisition mode is passed IN"
                             % forbidden)

    def test_the_acquisition_mode_cannot_be_invented(self):
        with self.assertRaises(ValueError):
            limits([], "ROOT")


class ThreeAxes(unittest.TestCase):
    """Frozen: what happened, what would be needed, and how it was attempted."""

    def test_the_three_axes_are_three_fields(self):
        got = coverage.source("d", "s", coverage.NOT_TESTED,
                              coverage.PERMISSION_DENIED, coverage.OP_FILE_READ)
        self.assertEqual(got["access_outcome"], coverage.PERMISSION_DENIED)
        self.assertEqual(got["required_access"], coverage.ACCESS_FILE_READ)
        manifest = limits([got], coverage.MODE_CURRENT_IDENTITY)
        self.assertEqual(manifest["acquisition_modes"],
                         [coverage.MODE_CURRENT_IDENTITY])
        self.assertEqual(manifest["sources"][0]["acquisition_mode"],
                         coverage.MODE_CURRENT_IDENTITY)

    def test_one_outcome_can_carry_different_requirements(self):
        # Same thing happened; different access would obtain the evidence.
        a = coverage.source("d", "s", coverage.NOT_TESTED,
                            coverage.PERMISSION_DENIED, coverage.OP_FILE_READ)
        b = coverage.source("d", "s", coverage.NOT_TESTED,
                            coverage.PERMISSION_DENIED, coverage.OP_DIRECTORY_LIST)
        self.assertEqual(a["access_outcome"], b["access_outcome"])
        self.assertNotEqual(a["required_access"], b["required_access"])

    def test_one_requirement_can_follow_from_different_outcomes(self):
        denied = coverage.source("d", "s", coverage.NOT_TESTED,
                                 coverage.PERMISSION_DENIED, coverage.OP_FILE_READ)
        absent = coverage.source("d", "s", coverage.NOT_TESTED,
                                 coverage.NOT_FOUND, coverage.OP_FILE_READ)
        self.assertNotEqual(denied["required_access"], absent["required_access"])
        self.assertEqual(absent["required_access"], coverage.ACCESS_NONE)


class NotSupportedStaysOutOfHostio(unittest.TestCase):
    """Ruling C. hostio answers for the layer it can observe, and no further."""

    def test_hostio_does_not_define_a_capability_vocabulary(self):
        from isedraf import hostio
        self.assertFalse(hasattr(hostio, "NOT_SUPPORTED"))
        for name in dir(hostio):
            self.assertNotIn("SUPPORTED", name)

    def test_hostio_outcomes_are_file_operation_outcomes_only(self):
        from isedraf import hostio
        self.assertEqual(
            sorted([hostio.NOT_FOUND, hostio.PERMISSION_DENIED,
                    hostio.IO_ERROR, hostio.READ_OK]),
            sorted(["NOT_FOUND", "PERMISSION_DENIED", "IO_ERROR", "READ_OK"]))

    def test_not_supported_never_implies_an_authority_problem(self):
        got = coverage.source("d", "s", coverage.NOT_TESTED,
                              coverage.NOT_SUPPORTED, coverage.OP_COMMAND,
                              universe=coverage.UNIVERSE_INCOMPLETE)
        self.assertFalse(got["privilege_limited"])
        self.assertEqual(got["required_access"], coverage.ACCESS_NONE)
        self.assertFalse(got["absence_claim_allowed"])


class InventoryRetrofit(unittest.TestCase):
    """Ruling B. One evidence bundle, one visibility model."""

    def inventory(self):
        from isedraf import inventory
        return inventory.collect("/")

    def test_every_subdomain_carries_a_coverage_entry(self):
        from isedraf.inventory import model as inventory_model
        got = self.inventory()
        named = set(c["source"] for c in got["coverage"])
        self.assertEqual(named, set(inventory_model.SUBDOMAINS))

    def test_every_entry_uses_the_shared_vocabulary(self):
        for record in self.inventory()["coverage"]:
            self.assertIn(record["access_outcome"], coverage.OUTCOMES)
            self.assertIn(record["operation"], coverage.OPERATIONS)
            self.assertIn(record["required_access"], coverage.ACCESS_REQUIREMENTS)

    def test_a_command_failure_does_not_become_a_privilege_limitation(self):
        """THE ruling-B invariant. A nonzero exit is not a refusal.

        hostio.run returns ERROR for a nonzero exit, a timeout and an OSError alike and
        cannot tell a refusal from any of them, so the conservative classification must
        never reach ACCESS_COMMAND_QUERY on its own.
        """
        from isedraf import inventory
        blocks = {"network": {"collection_status": coverage.ERROR,
                              "reason": "ERROR", "access_outcome": None,
                              "operation": None}}
        got = inventory._coverage(blocks)[0]
        self.assertEqual(got["access_outcome"], coverage.IO_ERROR)
        self.assertFalse(got["privilege_limited"])
        self.assertEqual(got["required_access"], coverage.ACCESS_NONE)
        self.assertNotEqual(got["required_access"], coverage.ACCESS_COMMAND_QUERY)

    def test_a_missing_tool_is_unsupported_not_unauthorised(self):
        from isedraf import inventory
        blocks = {"network": {"collection_status": coverage.NOT_TESTED,
                              "reason": "NOT_TESTED", "access_outcome": None,
                              "operation": None}}
        got = inventory._coverage(blocks)[0]
        self.assertEqual(got["access_outcome"], coverage.NOT_SUPPORTED)
        self.assertFalse(got["privilege_limited"])

    def test_a_collector_that_established_a_refusal_is_believed(self):
        from isedraf import inventory
        blocks = {"host": {"collection_status": coverage.NOT_TESTED,
                           "reason": "denied",
                           "access_outcome": coverage.PERMISSION_DENIED,
                           "operation": coverage.OP_FILE_READ}}
        got = inventory._coverage(blocks)[0]
        self.assertTrue(got["privilege_limited"])
        self.assertEqual(got["required_access"], coverage.ACCESS_FILE_READ)

    def test_the_inventory_never_invents_a_refusal_on_a_live_host(self):
        # Nothing on an ordinary unprivileged run may claim authority was the obstacle
        # unless a collector determined it.
        for record in self.inventory()["coverage"]:
            if record["privilege_limited"]:
                self.assertEqual(record["access_outcome"],
                                 coverage.PERMISSION_DENIED)

    def test_the_inventory_facts_are_unchanged_by_the_retrofit(self):
        got = self.inventory()
        for block in got["subdomains"].values():
            for key in ("collection_status", "reason", "method", "state_dimension",
                        "data"):
                self.assertIn(key, block)


class ProvenanceKeysDoNotCollide(unittest.TestCase):
    """CQ-3. One key name must not mean two shapes.

    R1.5-P producers put a LIST of structured acquisition entries under `coverage`; S3
    used the same key for a scalar completeness string. Mounts is the first module that
    produces both, so a combined provenance would have carried one name with two
    meanings - and a renderer reading it would get whichever the producer happened to be.
    """

    def domains(self):
        from isedraf import inventory
        from isedraf.accounts import acquire as accounts
        import os, shutil, tempfile
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        os.makedirs(os.path.join(base, "etc"))
        with open(os.path.join(base, "etc", "passwd"), "w") as handle:
            handle.write("alice:x:1000:1000:A:/home/alice:/bin/sh\n")
        with open(os.path.join(base, "etc", "group"), "w") as handle:
            handle.write("alice:x:1000:\n")
        return [("accounts", accounts.collect(base)),
                ("inventory", inventory.collect(base))]

    def test_every_r15p_producer_keeps_coverage_a_list(self):
        for name, evidence in self.domains():
            entries = evidence["coverage"]
            self.assertIsInstance(entries, list, "%s made coverage a scalar" % name)
            for entry in entries:
                self.assertIsInstance(entry, dict)
                self.assertIn("access_outcome", entry)

    def test_s3_no_longer_claims_the_same_key(self):
        from isedraf.shared import compare, result

        class Trivial(compare.Comparator):
            name = "trivial"

            def identity(self, record):
                return record.get("k")

            def compare_pair(self, declared, active):
                return compare.EQUIVALENT

        evidence = compare.compare(
            result.Evidence(result.COLLECTED, records=[]),
            result.Evidence(result.COLLECTED, records=[]), Trivial(),
            declared_universe_complete=True, active_universe_complete=True)
        self.assertNotIn("coverage", evidence.provenance)
        self.assertIsInstance(evidence.provenance["comparison_input_coverage"], str)

    def test_the_three_comparison_axes_have_distinct_names(self):
        from isedraf.shared import compare, result

        class Trivial(compare.Comparator):
            name = "trivial"

            def identity(self, record):
                return record.get("k")

            def compare_pair(self, declared, active):
                return compare.EQUIVALENT

        provenance = compare.compare(
            result.Evidence(result.COLLECTED, records=[]),
            result.Evidence(result.COLLECTED, records=[]), Trivial(),
            declared_universe_complete=True,
            active_universe_complete=True).provenance
        for key in ("comparison_input_coverage", "pairing", "comparability"):
            self.assertIn(key, provenance)
        self.assertEqual(len({provenance["comparison_input_coverage"],
                              provenance["pairing"],
                              provenance["comparability"]}), 3)


if __name__ == "__main__":
    unittest.main(verbosity=0)
