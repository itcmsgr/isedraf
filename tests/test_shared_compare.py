# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: S3 — directional absence, preserved multiplicity, adapter-owned equivalence.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, GOV-002
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================

"""S3 — declared vs active comparison."""
import ast
import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import compare, result                 # noqa: E402


def cmp_(declared, active, comparator, declared_complete, active_complete,
         applicable=True):
    """IQ-020: every call states both universe-completeness answers.

    Spelled out at each call site rather than derived from status, because deriving it
    is exactly the conflation this correction removed. Where a test's two answers happen
    to match its two statuses, that is a fact about that test and not a rule.
    """
    return compare.compare(declared, active, comparator, applicable,
                           declared_universe_complete=declared_complete,
                           active_universe_complete=active_complete)


class Simple(compare.Comparator):
    name = "simple"

    def identity(self, record):
        return record["k"]

    def compare_pair(self, declared, active):
        return (compare.EQUIVALENT if declared["v"] == active["v"]
                else compare.DIFFERENT)


class Ordered(Simple):
    name = "ordered"
    order_sensitive = True


def side(status, records, reason=None):
    if status != result.COLLECTED and reason is None:
        reason = "incomplete for test purposes"
    return result.Evidence(status, records=records, reason=reason)


def rel(ev, identity):
    return [i["relationship"] for i in ev.records if i["identity"] == identity]


class BothComplete(unittest.TestCase):

    def test_exact_match(self):
        ev = cmp_(side(result.COLLECTED, [{"k": "A", "v": 1}]),
                             side(result.COLLECTED, [{"k": "A", "v": 1}]), Simple(), True, True)
        self.assertEqual(rel(ev, "A"), [compare.MATCHED])
        self.assertEqual(ev.provenance["comparison_input_coverage"], compare.COMPLETE)
        self.assertEqual(ev.status, result.COLLECTED)

    def test_modified(self):
        ev = cmp_(side(result.COLLECTED, [{"k": "A", "v": 1}]),
                             side(result.COLLECTED, [{"k": "A", "v": 2}]), Simple(), True, True)
        self.assertEqual(rel(ev, "A"), [compare.MODIFIED])

    def test_declared_only_is_provable(self):
        ev = cmp_(side(result.COLLECTED, [{"k": "A", "v": 1}]),
                             side(result.COLLECTED, []), Simple(), True, True)
        self.assertEqual(rel(ev, "A"), [compare.DECLARED_ONLY])
        self.assertEqual(ev.provenance["comparison_input_coverage"], compare.COMPLETE)

    def test_active_only_is_provable(self):
        ev = cmp_(side(result.COLLECTED, []),
                             side(result.COLLECTED, [{"k": "A", "v": 1}]), Simple(), True, True)
        self.assertEqual(rel(ev, "A"), [compare.ACTIVE_ONLY])


class DirectionalAbsence(unittest.TestCase):
    """An incomplete side blocks absence claims AGAINST that side only."""

    def test_partial_active_forbids_declared_only_but_allows_active_only(self):
        ev = cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1}, {"k": "B", "v": 2}]),
            side(result.PARTIAL, [{"k": "A", "v": 1}, {"k": "C", "v": 3}]), Simple(), True, False)
        self.assertEqual(rel(ev, "A"), [compare.MATCHED])
        # B might be in the part of the active side we could not read.
        self.assertEqual(rel(ev, "B"), [compare.COUNTERPART_UNKNOWN])
        # C is proven undeclared, because the declared side IS complete.
        self.assertEqual(rel(ev, "C"), [compare.ACTIVE_ONLY])
        self.assertEqual(ev.provenance["comparison_input_coverage"], compare.PARTIAL)

    def test_partial_declared_forbids_active_only_but_allows_declared_only(self):
        ev = cmp_(
            side(result.PARTIAL, [{"k": "A", "v": 1}, {"k": "B", "v": 2}]),
            side(result.COLLECTED, [{"k": "A", "v": 1}, {"k": "C", "v": 3}]), Simple(), False, True)
        self.assertEqual(rel(ev, "B"), [compare.DECLARED_ONLY])
        self.assertEqual(rel(ev, "C"), [compare.COUNTERPART_UNKNOWN])

    def test_both_partial_keeps_positive_matches(self):
        ev = cmp_(
            side(result.PARTIAL, [{"k": "A", "v": 1}, {"k": "B", "v": 2}]),
            side(result.PARTIAL, [{"k": "A", "v": 1}, {"k": "C", "v": 3}]), Simple(), False, False)
        self.assertEqual(rel(ev, "A"), [compare.MATCHED])
        self.assertEqual(rel(ev, "B"), [compare.COUNTERPART_UNKNOWN])
        self.assertEqual(rel(ev, "C"), [compare.COUNTERPART_UNKNOWN])
        self.assertEqual(ev.provenance["comparison_input_coverage"], compare.PARTIAL)

    def test_a_partial_side_does_not_collapse_the_whole_comparison(self):
        # The refinement: positive evidence honestly obtained is not thrown away.
        ev = cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1}]),
            side(result.PARTIAL, [{"k": "A", "v": 1}]), Simple(), True, False)
        self.assertNotEqual(ev.provenance["comparison_input_coverage"], compare.NOT_COMPARABLE)
        self.assertEqual(rel(ev, "A"), [compare.MATCHED])

    def test_not_tested_side_behaves_like_incomplete(self):
        ev = cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1}]),
            side(result.NOT_TESTED, []), Simple(), True, False)
        self.assertEqual(rel(ev, "A"), [compare.COUNTERPART_UNKNOWN])

    def test_each_item_records_which_directions_were_assertable(self):
        ev = cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1}]),
            side(result.PARTIAL, []), Simple(), True, False)
        item = ev.records[0]
        self.assertTrue(item["absence_assertable"]["declared_side"])
        self.assertFalse(item["absence_assertable"]["active_side"])
        self.assertIn("counterpart source is incomplete", item["reason"])


class NoUsableEvidence(unittest.TestCase):

    def test_both_sides_unusable_is_not_comparable(self):
        ev = cmp_(side(result.NOT_TESTED, []), side(result.NOT_TESTED, []),
                             Simple(), False, False)
        self.assertEqual(ev.provenance["comparison_input_coverage"], compare.NOT_COMPARABLE)
        self.assertIn("NOT_COMPARABLE", ev.reason)

    def test_not_applicable_is_not_a_synonym_for_missing_evidence(self):
        ev = cmp_(side(result.COLLECTED, [{"k": "A", "v": 1}]),
                             side(result.COLLECTED, []), Simple(), True, True, applicable=False)
        self.assertEqual(ev.provenance["comparison_input_coverage"], compare.NOT_APPLICABLE)
        self.assertNotEqual(ev.provenance["comparison_input_coverage"], compare.NOT_COMPARABLE)

    def test_both_empty_and_complete_is_a_complete_comparison(self):
        ev = cmp_(side(result.COLLECTED, []), side(result.COLLECTED, []),
                             Simple(), True, True)
        self.assertEqual(ev.provenance["comparison_input_coverage"], compare.COMPLETE)
        self.assertEqual(ev.records, [])


class Multiplicity(unittest.TestCase):
    """A dict keyed by identity would make duplicates disappear."""

    def test_duplicates_are_all_retained_and_none_is_paired_by_position(self):
        """CORRECTED — this test was CERTIFYING the IQ-019 defect.

        It asserted `[MATCHED, MATCHED]` for two declarations against two active records
        under one identity. Those two verdicts were decided by the order two unrelated
        sources happened to enumerate their lines in; nothing in the evidence said record
        1 corresponded to record 1. A green test was locking in a confident answer built
        from list position.

        What it was RIGHT about is kept and strengthened: every record is retained.
        """
        declared = [{"k": "A", "v": 1}, {"k": "A", "v": 2}]
        active = [{"k": "A", "v": 1}, {"k": "A", "v": 2}]
        ev = cmp_(side(result.COLLECTED, declared),
                             side(result.COLLECTED, active), Simple(), True, True)
        self.assertEqual(rel(ev, "A"), [compare.AMBIGUOUS] * 4)
        self.assertEqual(len(ev.records), 4, "a record was dropped")

    def test_the_result_does_not_depend_on_enumeration_order(self):
        def run(declared, active):
            ev = cmp_(side(result.COLLECTED, declared),
                                 side(result.COLLECTED, active), Simple(), True, True)
            return sorted(r["relationship"] for r in ev.records)
        forward = run([{"k": "A", "v": 1}, {"k": "A", "v": 2}],
                      [{"k": "A", "v": 1}, {"k": "A", "v": 2}])
        reversed_ = run([{"k": "A", "v": 2}, {"k": "A", "v": 1}],
                        [{"k": "A", "v": 1}, {"k": "A", "v": 2}])
        self.assertEqual(forward, reversed_)

    def test_multiplicity_on_either_side_alone_is_enough(self):
        for declared, active in (
                ([{"k": "A", "v": 1}, {"k": "A", "v": 2}], [{"k": "A", "v": 1}]),
                ([{"k": "A", "v": 1}], [{"k": "A", "v": 1}, {"k": "A", "v": 2}])):
            ev = cmp_(side(result.COLLECTED, declared),
                                 side(result.COLLECTED, active), Simple(), True, True)
            self.assertEqual(set(rel(ev, "A")), {compare.AMBIGUOUS})

    def test_a_unique_group_is_still_compared(self):
        # Otherwise AMBIGUOUS would be a constant rather than a finding.
        ev = cmp_(side(result.COLLECTED, [{"k": "A", "v": 1}]),
                             side(result.COLLECTED, [{"k": "A", "v": 1}]), Simple(), True, True)
        self.assertEqual(rel(ev, "A"), [compare.MATCHED])

    def test_duplicate_counts_differing_is_ambiguous_not_a_guess(self):
        ev = cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1}, {"k": "A", "v": 2}]),
            side(result.COLLECTED, [{"k": "A", "v": 1}]), Simple(), True, True)
        relationships = rel(ev, "A")
        self.assertIn(compare.AMBIGUOUS, relationships)
        # Never silently DECLARED_ONLY: which of the two is missing is unknowable.
        self.assertNotIn(compare.DECLARED_ONLY, relationships)

    def test_ambiguity_explains_itself(self):
        ev = cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1}, {"k": "A", "v": 2}]),
            side(result.COLLECTED, [{"k": "A", "v": 1}]), Simple(), True, True)
        item = [i for i in ev.records if i["relationship"] == compare.AMBIGUOUS][0]
        self.assertIn("no deterministic pairing", item["reason"])

    def test_ambiguity_does_not_degrade_acquisition_coverage(self):
        """CORRECTED. This asserted `coverage == PARTIAL` and was wrong.

        Two files acquired perfectly, whose records cannot be paired, are COMPLETE
        acquisition evidence about an ambiguous situation. Reporting PARTIAL blamed the
        acquisition for a limit belonging to the pairing, and would send an operator
        looking for evidence they already have. Pairing determinacy is its own axis.
        """
        ev = cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1}, {"k": "A", "v": 2}]),
            side(result.COLLECTED, [{"k": "A", "v": 1}]), Simple(), True, True)
        self.assertEqual(ev.provenance["comparison_input_coverage"], compare.COMPLETE)
        self.assertEqual(ev.provenance["pairing"], compare.AMBIGUOUS_PAIRING)
        self.assertEqual(ev.provenance["ambiguous_records"], 3)


class Ordering(unittest.TestCase):
    """The adapter decides whether order carries meaning."""

    RECORDS_A = [{"k": "A", "v": 1}, {"k": "B", "v": 2}]
    RECORDS_B = [{"k": "B", "v": 2}, {"k": "A", "v": 1}]

    def test_order_insensitive_reorder_is_equivalent(self):
        ev = cmp_(side(result.COLLECTED, self.RECORDS_A),
                             side(result.COLLECTED, self.RECORDS_B), Simple(), True, True)
        self.assertEqual(sorted(i["relationship"] for i in ev.records),
                         [compare.MATCHED, compare.MATCHED])

    def test_order_sensitive_reorder_is_a_difference(self):
        # Audit rules are why this exists: the same rules in a different order are a
        # different policy, and a set comparison would call an inverted policy unchanged.
        ev = cmp_(side(result.COLLECTED, self.RECORDS_A),
                             side(result.COLLECTED, self.RECORDS_B), Ordered(), True, True)
        self.assertTrue(all(i["relationship"] == compare.MODIFIED for i in ev.records))

    def test_order_sensitive_identical_sequences_match(self):
        ev = cmp_(side(result.COLLECTED, self.RECORDS_A),
                             side(result.COLLECTED, list(self.RECORDS_A)), Ordered(), True, True)
        self.assertTrue(all(i["relationship"] == compare.MATCHED for i in ev.records))

    def test_order_sensitive_records_position(self):
        ev = cmp_(side(result.COLLECTED, self.RECORDS_A),
                             side(result.COLLECTED, self.RECORDS_A), Ordered(), True, True)
        self.assertEqual([i["position"] for i in ev.records], [0, 1])

    def test_engine_does_not_sort_the_input(self):
        tree = ast.parse(inspect.getsource(compare))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        self.assertNotIn("sorted", names)
        self.assertNotIn("sort", attrs)


class AdapterOwnsEquivalence(unittest.TestCase):

    def test_same_semantics_written_differently_can_be_equal(self):
        class Lenient(compare.Comparator):
            name = "lenient"

            def identity(self, record):
                return record["k"].lower()

            def compare_pair(self, declared, active):
                return (compare.EQUIVALENT
                        if str(declared["v"]).strip().lower()
                        == str(active["v"]).strip().lower()
                        else compare.DIFFERENT)

        ev = cmp_(side(result.COLLECTED, [{"k": "Opt", "v": " YES "}]),
                             side(result.COLLECTED, [{"k": "opt", "v": "yes"}]),
                             Lenient(), True, True)
        self.assertEqual(ev.records[0]["relationship"], compare.MATCHED)

    def test_engine_never_uses_python_equality_on_records(self):
        class NeverEqual(Simple):
            name = "never"

            def compare_pair(self, declared, active):
                return compare.DIFFERENT

        ev = cmp_(side(result.COLLECTED, [{"k": "A", "v": 1}]),
                             side(result.COLLECTED, [{"k": "A", "v": 1}]), NeverEqual(), True, True)
        # Identical dicts, and the adapter still decides.
        self.assertEqual(ev.records[0]["relationship"], compare.MODIFIED)


class ComparatorProvenance(unittest.TestCase):
    """A comparison-semantics change must not look like a host change."""

    def test_semantics_change_changes_the_digest(self):
        class V1(Simple):
            name = "same"

        class V2(Simple):
            name = "same"
            order_sensitive = True

        a = cmp_(side(result.COLLECTED, []), side(result.COLLECTED, []), V1(), True, True)
        b = cmp_(side(result.COLLECTED, []), side(result.COLLECTED, []), V2(), True, True)
        self.assertNotEqual(a.provenance["comparator_digest"],
                            b.provenance["comparator_digest"])

    def test_digest_is_stable(self):
        a = cmp_(side(result.COLLECTED, []), side(result.COLLECTED, []),
                            Simple(), True, True)
        b = cmp_(side(result.COLLECTED, [{"k": "A", "v": 1}]),
                            side(result.COLLECTED, [{"k": "A", "v": 1}]), Simple(), True, True)
        self.assertEqual(a.provenance["comparator_digest"],
                         b.provenance["comparator_digest"])

    def test_provenance_answers_how_the_comparison_was_made(self):
        ev = cmp_(side(result.COLLECTED, [{"k": "A", "v": 1}]),
                             side(result.PARTIAL, []), Simple(), True, False)
        for field in ("comparator", "version", "comparator_digest", "comparison_input_coverage",
                      "declared_status", "active_status", "declared_universe_complete",
                      "active_universe_complete", "relationship_counts"):
            self.assertIn(field, ev.provenance)

    def test_items_carry_source_references(self):
        ev = cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1, "source_path": "/d",
                                     "source_line": 7}]),
            side(result.COLLECTED, []), Simple(), True, True)
        self.assertEqual(ev.records[0]["declared"]["source_line"], 7)
        self.assertEqual(ev.records[0]["declared"]["source_path"], "/d")


class PureComparisonLayer(unittest.TestCase):
    """S3 reads nothing, runs nothing, parses nothing."""

    def test_no_io_of_any_kind(self):
        tree = ast.parse(inspect.getsource(compare))
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("open", "lstat", "listdir", "Popen", "system", "socket",
                          "urlopen", "read_file", "read_file_lossless"):
            self.assertNotIn(forbidden, names + attrs, forbidden)

    def test_imports_no_domain_and_no_acquisition(self):
        tree = ast.parse(inspect.getsource(compare))
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                modules.append(node.module or "")
            elif isinstance(node, ast.Import):
                modules.extend(a.name for a in node.names)
        for module in modules:
            for forbidden in ("ssh", "sudo", "pam", "audit", "mounts", "services",
                              "firewall", "report", "inventory", "accounts", "_exec",
                              "bounded", "filemeta", "include_graph"):
                self.assertNotIn(forbidden, module, module)


class TriStateEquivalence(unittest.TestCase):
    """S3's four uncertainty classes, kept apart.

        absence uncertainty        COUNTERPART_UNKNOWN
        equivalence uncertainty    EQUIVALENCE_UNKNOWN
        pairing ambiguity          AMBIGUOUS
        unusable sources           NOT_COMPARABLE

    The mounts lane found that the first two were collapsed: a boolean `equal()` forced a
    pair whose equivalence could not be decided into MODIFIED, a confident claim of
    mismatch manufactured from missing evidence.
    """

    class Verdict(compare.Comparator):
        name = "verdict"

        def __init__(self, verdict):
            self.verdict = verdict

        def identity(self, record):
            return record["k"]

        def compare_pair(self, declared, active):
            return self.verdict

    def one(self, verdict, declared_status=result.COLLECTED,
            active_status=result.COLLECTED):
        # These fixtures use a COLLECTED source to mean a complete universe and a
        # non-COLLECTED one to mean incomplete. Stated, not inherited.
        return cmp_(side(declared_status, [{"k": "A", "v": 1}]),
                    side(active_status, [{"k": "A", "v": 2}]),
                    self.Verdict(verdict),
                    declared_status == result.COLLECTED,
                    active_status == result.COLLECTED)

    def test_equivalent_is_matched(self):
        self.assertEqual(self.one(compare.EQUIVALENT).records[0]["relationship"],
                         compare.MATCHED)

    def test_different_is_modified(self):
        self.assertEqual(self.one(compare.DIFFERENT).records[0]["relationship"],
                         compare.MODIFIED)

    def test_undecidable_is_its_own_relationship(self):
        self.assertEqual(self.one(compare.UNKNOWN).records[0]["relationship"],
                         compare.EQUIVALENCE_UNKNOWN)

    def test_unknown_is_not_matched(self):
        self.assertNotEqual(self.one(compare.UNKNOWN).records[0]["relationship"],
                            compare.MATCHED)

    def test_unknown_is_not_modified(self):
        self.assertNotEqual(self.one(compare.UNKNOWN).records[0]["relationship"],
                            compare.MODIFIED)

    def test_unknown_is_not_counterpart_unknown(self):
        """The distinction the whole amendment exists for."""
        self.assertNotEqual(self.one(compare.UNKNOWN).records[0]["relationship"],
                            compare.COUNTERPART_UNKNOWN)

    def test_unknown_is_not_ambiguous(self):
        self.assertNotEqual(self.one(compare.UNKNOWN).records[0]["relationship"],
                            compare.AMBIGUOUS)

    def test_the_reason_says_which_uncertainty_it_is(self):
        reason = self.one(compare.UNKNOWN).records[0]["reason"]
        self.assertIn("counterpart was found", reason)
        self.assertIn("semantically equivalent", reason)

    def test_a_bool_is_refused_rather_than_coerced(self):
        # True would silently become DIFFERENT under any `if` the engine wrote.
        for bad in (True, False, None, "MAYBE", 1):
            with self.assertRaises(ValueError):
                self.one(bad)

    def test_there_is_no_boolean_contract_left(self):
        self.assertFalse(hasattr(compare.Comparator, "equal"))


class CompletenessIsNotComparability(unittest.TestCase):
    """FROZEN: EVIDENCE COMPLETENESS != SEMANTIC COMPARABILITY."""

    def evidence(self, verdict):
        return cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1}]),
            side(result.COLLECTED, [{"k": "A", "v": 2}]),
            TriStateEquivalence.Verdict(verdict), True, True)

    def test_both_sides_complete_and_undecidable_keeps_coverage_complete(self):
        ev = self.evidence(compare.UNKNOWN)
        self.assertEqual(ev.provenance["comparison_input_coverage"], compare.COMPLETE)
        self.assertEqual(ev.status, result.COLLECTED)

    def test_but_comparability_says_so_on_its_own_axis(self):
        ev = self.evidence(compare.UNKNOWN)
        self.assertEqual(ev.provenance["comparability"],
                         compare.PARTIALLY_COMPARABLE)
        self.assertEqual(ev.provenance["undecidable_pairs"], 1)

    def test_a_decidable_comparison_is_fully_comparable(self):
        ev = self.evidence(compare.EQUIVALENT)
        self.assertEqual(ev.provenance["comparability"], compare.FULLY_COMPARABLE)
        self.assertEqual(ev.provenance["undecidable_pairs"], 0)

    def test_degrading_coverage_would_blame_the_wrong_thing(self):
        # An operator told the acquisition was PARTIAL would go looking for evidence
        # they already have. The two axes send them to different problems.
        ev = self.evidence(compare.UNKNOWN)
        self.assertNotEqual(ev.provenance["comparison_input_coverage"], compare.PARTIAL)
        self.assertIsNone(ev.reason)


class UncertaintyClassesStaySeparate(unittest.TestCase):

    def test_an_incomplete_counterpart_still_yields_counterpart_unknown(self):
        ev = cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1}]),
            side(result.PARTIAL, [], reason="partial"),
            TriStateEquivalence.Verdict(compare.UNKNOWN), True, False)
        self.assertEqual(ev.records[0]["relationship"], compare.COUNTERPART_UNKNOWN)

    def test_multiplicity_still_yields_ambiguous(self):
        ev = cmp_(
            side(result.COLLECTED, [{"k": "A", "v": 1}, {"k": "A", "v": 2}]),
            side(result.COLLECTED, [{"k": "A", "v": 3}]),
            TriStateEquivalence.Verdict(compare.UNKNOWN), True, True)
        kinds = set(r["relationship"] for r in ev.records)
        self.assertIn(compare.AMBIGUOUS, kinds)

    def test_directional_absence_is_unchanged(self):
        ev = cmp_(
            side(result.COLLECTED, []),
            side(result.PARTIAL, [{"k": "B", "v": 1}], reason="partial"),
            TriStateEquivalence.Verdict(compare.UNKNOWN), True, False)
        self.assertEqual(ev.records[0]["relationship"], compare.ACTIVE_ONLY)


class ContractProvenance(unittest.TestCase):

    def test_the_comparator_digest_records_the_equivalence_contract(self):
        identity = TriStateEquivalence.Verdict(compare.EQUIVALENT).semantic_identity()
        self.assertEqual(identity["semantics"]["equivalence_contract"], "TRI_STATE_V1")

    def test_the_pairing_contract_is_in_the_digest_too(self):
        """It was not asserted, and an injection removing it went undetected.

        Both contracts decide what a comparison MEANS, so both must move the digest that
        claims a comparison is unchanged.
        """
        identity = TriStateEquivalence.Verdict(compare.EQUIVALENT).semantic_identity()
        self.assertEqual(identity["semantics"]["pairing_contract"], "UNIQUE_ONLY_V1")

    def test_changing_the_pairing_contract_changes_the_digest(self):
        class Other(TriStateEquivalence.Verdict):
            pairing_contract = "POSITIONAL_V0"
        new = TriStateEquivalence.Verdict(compare.EQUIVALENT).semantic_identity()
        old = Other(compare.EQUIVALENT).semantic_identity()
        self.assertNotEqual(new["comparator_digest"], old["comparator_digest"])

    def test_the_provenance_schema_contract_is_in_the_digest(self):
        """Found by a mis-retargeted injection going undetected.

        Three contracts decide what a comparison MEANS or what SHAPE it reports in, and
        all three must move the digest that claims a comparison is unchanged. This one
        was added with the CQ-3 rename and was not asserted.
        """
        identity = TriStateEquivalence.Verdict(compare.EQUIVALENT).semantic_identity()
        self.assertEqual(identity["semantics"]["provenance_contract"],
                         "COMPARISON_INPUT_COVERAGE_V1")

    def test_changing_the_provenance_contract_changes_the_digest(self):
        class Old(TriStateEquivalence.Verdict):
            provenance_contract = "COVERAGE_KEY_V0"
        self.assertNotEqual(
            TriStateEquivalence.Verdict(compare.EQUIVALENT
                                        ).semantic_identity()["comparator_digest"],
            Old(compare.EQUIVALENT).semantic_identity()["comparator_digest"])

    def test_changing_the_contract_changes_the_digest(self):
        # A comparison whose semantics changed must not look like a host that did not.
        class Old(TriStateEquivalence.Verdict):
            equivalence_contract = "BOOLEAN_V0"
        new = TriStateEquivalence.Verdict(compare.EQUIVALENT).semantic_identity()
        old = Old(compare.EQUIVALENT).semantic_identity()
        self.assertNotEqual(new["comparator_digest"], old["comparator_digest"])


class SourceStatusIsNotUniverseCompleteness(unittest.TestCase):
    """IQ-020. A source status is a property of an OPERATION; universe completeness is a
    property of a bounded EVIDENCE UNIVERSE. S3 used to derive the second from the first.

        /etc/fstab absent            NOT_TESTED   universe COMPLETE
        /etc/fstab permission denied NOT_TESTED   universe INCOMPLETE

    Identical status, opposite absence semantics. The mounts lane could not implement
    owner ruling D until these came apart.
    """

    def unmatched(self, declared_status, declared_complete):
        """A declared side with no records, against one observed active record."""
        return cmp_(side(declared_status, [], reason="none"),
                    side(result.COLLECTED, [{"k": "/x", "v": 1}]),
                    Simple(), declared_complete, True)

    def test_absent_source_with_a_complete_universe_permits_the_absence_claim(self):
        ev = self.unmatched(result.NOT_TESTED, True)
        self.assertEqual(ev.records[0]["relationship"], compare.ACTIVE_ONLY)

    def test_refused_source_with_an_incomplete_universe_does_not(self):
        ev = self.unmatched(result.NOT_TESTED, False)
        self.assertEqual(ev.records[0]["relationship"], compare.COUNTERPART_UNKNOWN)

    def test_the_same_status_yields_opposite_results(self):
        """The orthogonality proof: status held constant, completeness varied."""
        complete = self.unmatched(result.NOT_TESTED, True)
        incomplete = self.unmatched(result.NOT_TESTED, False)
        self.assertNotEqual(complete.records[0]["relationship"],
                            incomplete.records[0]["relationship"])

    def test_a_fully_read_source_may_still_bound_an_incomplete_universe(self):
        """COLLECTED does not imply complete either.

        A collector that reads one source perfectly while its requested universe spans
        several is the mirror case, and a rule keyed on status would get it wrong in the
        dangerous direction - asserting an absence it has not established.
        """
        ev = self.unmatched(result.COLLECTED, False)
        self.assertEqual(ev.records[0]["relationship"], compare.COUNTERPART_UNKNOWN)

    def test_completeness_must_be_stated_and_has_no_default(self):
        # A default is how the old conflation would survive a rename.
        with self.assertRaises(TypeError):
            compare.compare(side(result.COLLECTED, []),
                            side(result.COLLECTED, []), Simple())

    def test_acquisition_coverage_still_follows_the_sources(self):
        # The axes stay apart in both directions: a complete universe over a NOT_TESTED
        # source is still an incompletely ACQUIRED comparison.
        ev = self.unmatched(result.NOT_TESTED, True)
        self.assertEqual(ev.provenance["comparison_input_coverage"], compare.PARTIAL)
        self.assertTrue(ev.provenance["declared_universe_complete"])

    def test_the_completeness_contract_is_in_the_digest(self):
        identity = Simple().semantic_identity()
        self.assertEqual(identity["semantics"]["completeness_contract"],
                         "EXPLICIT_BOUNDED_UNIVERSE_V1")

    def test_changing_the_completeness_contract_changes_the_digest(self):
        class Old(Simple):
            completeness_contract = "STATUS_IS_COMPLETENESS_V0"
        self.assertNotEqual(Simple().semantic_identity()["comparator_digest"],
                            Old().semantic_identity()["comparator_digest"])


if __name__ == "__main__":
    unittest.main(verbosity=0)
