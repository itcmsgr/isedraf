# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Compare two already-normalized sides. Read nothing, parse nothing, run nothing.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, GOV-001
#
# THIS IS NOT THE DELTA MODEL. Two different axes are easy to conflate and must not be:
#
#   DELTA      baseline snapshot vs a later snapshot        an axis of TIME
#              ADDED / REMOVED / MODIFIED
#
#   S3         a declared source vs an active source        an axis of SOURCE
#              DECLARED_ONLY / ACTIVE_ONLY / MATCHED
#
# A rule that is written in /etc/audit/rules.d but absent from the running kernel was
# never "removed" - nothing happened over time. It was declared and is not active, which
# is a statement about two sources observed in the same instant. Borrowing ADDED/REMOVED
# here would tell an operator a change occurred when none did. MODIFIED and
# NOT_COMPARABLE are reused because they mean the same thing on both axes.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Declared-versus-active comparison over normalized evidence."""

from . import result

# --- per-item relationship ----------------------------------------------------------------
MATCHED = "MATCHED"
MODIFIED = "MODIFIED"                      # same identity, different content
EQUIVALENCE_UNKNOWN = "EQUIVALENCE_UNKNOWN"
# A counterpart pair EXISTS and the available evidence cannot establish whether the two
# are semantically equivalent.
#
# The first real consumer of this comparator - mounts - showed that the previous boolean
# contract could not say this. `equal()` returned True or False, so a pair whose
# equivalence was undecidable became MODIFIED: a confident claim of mismatch produced by
# the absence of evidence. On an ordinary host every fstab line declares UUID= while every
# active mount reports a kernel device path, so that was not an edge case, it was every
# row.
#
# It is NOT COUNTERPART_UNKNOWN. That one means "we cannot prove nothing corresponds to
# this record, because the other side is incomplete" - uncertainty about ABSENCE. This
# means "we found the counterpart and cannot judge it" - uncertainty about EQUIVALENCE.
# Collapsing them would lose exactly the distinction that makes either useful.
DECLARED_ONLY = "DECLARED_ONLY"            # PROVEN absent from a complete active side
ACTIVE_ONLY = "ACTIVE_ONLY"                # PROVEN absent from a complete declared side
COUNTERPART_UNKNOWN = "COUNTERPART_UNKNOWN"
# Observed on one side, not found on the other, and the other side is INCOMPLETE. This is
# not absence. The record may sit in the part that could not be read, and calling it
# DECLARED_ONLY would be an accusation manufactured from a gap in our own reading.
AMBIGUOUS = "AMBIGUOUS"
# The identity is duplicated and the counts differ, so no deterministic pairing exists.
# Guessing first-wins or last-wins would invent a relationship the evidence cannot support.

RELATIONSHIPS = (MATCHED, MODIFIED, EQUIVALENCE_UNKNOWN,
                 DECLARED_ONLY, ACTIVE_ONLY, COUNTERPART_UNKNOWN,
                 AMBIGUOUS)

# --- overall coverage ----------------------------------------------------------------------
# NOT_COMPARABLE is the frozen vocabulary for "incomplete, and therefore not a result".
# NOT_APPLICABLE is the existing state-dimension value and means the domain genuinely does
# not apply here - never "we have no evidence", which is what NOT_COMPARABLE is for.
# --- the verdict a domain returns for ONE candidate pair ---------------------------
EQUIVALENT = "EQUIVALENT"
DIFFERENT = "DIFFERENT"
UNKNOWN = "UNKNOWN"
EQUIVALENCE = (EQUIVALENT, DIFFERENT, UNKNOWN)

_RELATIONSHIP_OF = {EQUIVALENT: MATCHED, DIFFERENT: MODIFIED,
                    UNKNOWN: EQUIVALENCE_UNKNOWN}

# UNKNOWN is a NAMED value, never False, None or a raised exception. A sentinel that
# doubles as falsity is a sentinel something will eventually treat as falsity.

# --- the comparability axis, distinct from coverage --------------------------------
FULLY_COMPARABLE = "FULLY_COMPARABLE"
PARTIALLY_COMPARABLE = "PARTIALLY_COMPARABLE"

# --- the pairing axis, distinct from both ------------------------------------------
DETERMINISTIC_PAIRING = "DETERMINISTIC"
AMBIGUOUS_PAIRING = "AMBIGUOUS_PAIRING"

COMPLETE = "COMPLETE"
PARTIAL = "PARTIAL"
NOT_COMPARABLE = "NOT_COMPARABLE"
NOT_APPLICABLE = "NOT_APPLICABLE"


class Comparator(object):
    """A domain's rules for identity, equivalence and ordering.

    The engine never decides that equality means `==`, string equality, dict equality or
    set membership. An sshd option, an audit rule, a mount entry and a service state are
    four different equivalence problems, and a generic comparator that assumed one of them
    would be silently wrong about the other three.
    """

    name = "comparator"
    version = 1

    #: When true the two sides are compared POSITIONALLY and reordering is a difference.
    #: Audit rules are the reason this exists: the same rules in a different order are a
    #: different policy, and a set comparison would call an inverted policy unchanged.
    order_sensitive = False

    #: Fields that define the comparison contract, for the identity digest.
    #: `equivalence_contract` is listed so that moving from the boolean contract to the
    #: tri-state one CHANGES every comparator digest. A comparison whose semantics changed
    #: must not be able to look like a host that did not.
    SEMANTIC_FIELDS = ("name", "version", "order_sensitive", "equivalence_contract",
                       "pairing_contract", "completeness_contract",
                       "provenance_contract")

    #: The pair-verdict contract this comparator speaks.
    equivalence_contract = "TRI_STATE_V1"

    #: How candidate groups are paired. Listed in SEMANTIC_FIELDS so that IQ-019's change
    #: of pairing semantics cannot look like a host that did not change.
    pairing_contract = "UNIQUE_ONLY_V1"

    #: The provenance schema this comparator emits. Bound into the digest so a consumer
    #: that learned the old key cannot be handed the new shape under an identity claiming
    #: nothing changed.
    provenance_contract = "COMPARISON_INPUT_COVERAGE_V1"

    #: Where directional absence gets its completeness from. A comparison generated when
    #: completeness meant "status == COLLECTED" must not share a semantic identity with
    #: one generated from an explicitly bounded universe.
    completeness_contract = "EXPLICIT_BOUNDED_UNIVERSE_V1"

    def identity(self, record):
        """The key under which a declared and an active record refer to the same thing."""
        raise NotImplementedError

    def compare_pair(self, declared, active):
        """EQUIVALENT, DIFFERENT or UNKNOWN for one candidate pair.

        UNKNOWN is a first-class answer, not a failure. A domain returns it when a
        correspondence exists and the evidence in hand cannot settle equivalence - an
        fstab `UUID=` against a kernel device path, a declared mount option set against
        the kernel's expanded one. Manufacturing EQUIVALENT to produce a tidier report,
        or DIFFERENT because equality could not be shown, are the two failures this
        return type exists to prevent.

        There is deliberately no `equal()` returning a bool. One spelling per concept.
        """
        raise NotImplementedError

    def semantic_identity(self):
        """A stable identity for the COMPARISON CONTRACT.

        The S1 lesson: a comparator whose semantics change must not later look like a host
        that changed. Derived from the declared semantic fields so it cannot drift from
        the behaviour it describes.
        """
        fields = {}
        for field in self.SEMANTIC_FIELDS:
            value = getattr(self, field, None)
            fields[field] = list(value) if isinstance(value, tuple) else value
        from .. import canonical
        import hashlib
        return {"comparator": self.name, "version": self.version,
                "semantics": fields,
                "comparator_digest": "sha256:" + hashlib.sha256(
                    canonical.canonical_bytes(fields)).hexdigest()}


def compare(declared, active, comparator, applicable=True, *,
            declared_universe_complete, active_universe_complete):
    """Compare two Evidence objects. Performs no I/O of any kind.

    FROZEN, DIRECTIONAL:

        Absence on side X may be asserted only when side X is COMPLETE over the
        relevant comparison domain.

    IQ-020. The two completeness arguments are MANDATORY and have no default, because a
    default is how the old conflation would survive. This used to read

        declared_complete = declared.status == result.COLLECTED

    which answers a different question. A source STATUS is a property of an acquisition
    operation; UNIVERSE COMPLETENESS is a property of a bounded evidence universe, and
    the two come apart in both directions:

        /etc/fstab absent            status NOT_TESTED   universe COMPLETE
                                     - zero declarations, and that is fully established
        /etc/fstab permission denied status NOT_TESTED   universe INCOMPLETE
                                     - declarations may exist that were not seen
        a source read in full        status COLLECTED    universe INCOMPLETE
                                     - possible whenever one source does not cover the
                                       whole requested universe

    Identical status, opposite absence semantics. Making the caller state it is the
    point: every consumer must answer the question rather than inherit an accidental
    answer from an unrelated field.

    The directions are independent. A complete declared side proves ACTIVE_ONLY even while
    the active side is partial, because the question "is this active record declared
    anywhere?" is answered by the complete side. The mirror case holds. Collapsing the
    whole comparison to NOT_COMPARABLE because one side is PARTIAL throws away positive
    evidence that was honestly obtained.
    """
    if not applicable:
        return _evidence(NOT_APPLICABLE, [], comparator, declared, active,
                         "NOT_APPLICABLE: the domain does not apply on this host.")

    declared_complete = bool(declared_universe_complete)
    active_complete = bool(active_universe_complete)

    if not declared.records and not active.records and not (
            declared_complete and active_complete):
        return _evidence(NOT_COMPARABLE, [], comparator, declared, active,
                         "NOT_COMPARABLE: neither side produced trustworthy normalized "
                         "records. declared=%s active=%s"
                         % (declared.status, active.status))

    if comparator.order_sensitive:
        items = _positional(declared, active, comparator,
                            declared_complete, active_complete)
    else:
        items = _by_identity(declared, active, comparator,
                             declared_complete, active_complete)

    # THREE AXES, and coverage is only the first of them:
    #
    #   acquisition completeness   did we obtain the evidence?
    #   pairing determinacy        could the records be paired at all?
    #   semantic comparability     could the pairs be judged?
    #
    # Coverage therefore depends on the SOURCES alone. Two perfectly acquired files whose
    # records cannot be paired - two fstab lines for one target against two stacked
    # mounts - are complete acquisition evidence about an ambiguous situation, and
    # reporting PARTIAL would send an operator looking for evidence they already have.
    # COUNTERPART_UNKNOWN cannot arise when both sides are complete, so it needs no
    # separate term here.
    acquired = (declared.status == result.COLLECTED
                and active.status == result.COLLECTED)
    if acquired:
        coverage, reason = COMPLETE, None
    else:
        unresolved = len([i for i in items
                          if i["relationship"] == COUNTERPART_UNKNOWN])
        coverage = PARTIAL
        reason = (
            "PARTIAL_COMPARISON: declared=%s active=%s. %d relationship(s) could not be "
            "resolved; absence was asserted only against a complete side."
            % (declared.status, active.status, unresolved))
    return _evidence(coverage, items, comparator, declared, active, reason,
                     declared_complete, active_complete)


def _by_identity(declared, active, comparator, declared_complete, active_complete):
    """Group both sides by semantic identity, preserving multiplicity.

    A dict keyed by identity would make a duplicated declaration disappear and decide,
    by insertion order, which one survived. Duplicates are exactly the anomaly a
    comparison should surface, so both sides keep lists.
    """
    d_groups, d_order = _group(declared.records, comparator)
    a_groups, _ = _group(active.records, comparator)
    items = []

    for key in d_order:
        d_list = d_groups[key]
        a_list = a_groups.get(key, [])
        items.extend(_pair(key, d_list, a_list, comparator,
                           declared_complete, active_complete))

    for key, a_list in a_groups.items():
        if key in d_groups:
            continue
        for index, active_record in enumerate(a_list):
            items.append(_item(
                key, None, active_record,
                # Only a COMPLETE declared side proves an active record is undeclared.
                ACTIVE_ONLY if declared_complete else COUNTERPART_UNKNOWN,
                declared_complete, active_complete,
                active_index=index))
    return items


def _pair(key, d_list, a_list, comparator, declared_complete, active_complete):
    """Pair one identity's records, or refuse to.

    IQ-019. The previous version paired the first min(len(d), len(a)) records BY LIST
    POSITION and marked only the leftovers ambiguous, while its docstring claimed it
    never guessed. With two declarations and two active records under one identity it
    produced two confident verdicts decided by the order two unrelated sources happened
    to enumerate their lines in - and with 2x1 it produced a MATCHED, the most
    reassuring output this comparator has, from an arbitrary choice.

    The rule now: multiplicity on EITHER side means no deterministic pairing exists, so
    every record in the group is AMBIGUOUS. Every input record is preserved. There is no
    zip, no sort-then-zip, no first-wins, no last-wins, and no use of source ordinal as
    though coincident position were evidence.

    A future adapter may supply an authoritative pairing contract. None is authorized,
    and inventing one here to rescue a domain would be the same defect wearing a
    different hat.
    """
    items = []
    if len(d_list) > 1 or len(a_list) > 1:
        for index, record in enumerate(d_list):
            items.append(_item(key, record, None, AMBIGUOUS, declared_complete,
                               active_complete, declared_index=index))
        for index, record in enumerate(a_list):
            items.append(_item(key, None, record, AMBIGUOUS, declared_complete,
                               active_complete, active_index=index))
        return items

    if d_list and a_list:
        items.append(_item(key, d_list[0], a_list[0],
                           _relationship(comparator, d_list[0], a_list[0]),
                           declared_complete, active_complete,
                           declared_index=0, active_index=0))
        return items

    for index, record in enumerate(d_list):
        items.append(_item(key, record, None,
                           DECLARED_ONLY if active_complete else COUNTERPART_UNKNOWN,
                           declared_complete, active_complete, declared_index=index))
    for index, record in enumerate(a_list):
        items.append(_item(key, None, record,
                           ACTIVE_ONLY if declared_complete else COUNTERPART_UNKNOWN,
                           declared_complete, active_complete, active_index=index))
    return items


def _positional(declared, active, comparator, declared_complete, active_complete):
    """Order-sensitive comparison. Nothing is sorted and nothing is grouped."""
    items = []
    for index in range(max(len(declared.records), len(active.records))):
        d = declared.records[index] if index < len(declared.records) else None
        a = active.records[index] if index < len(active.records) else None
        if d is not None and a is not None:
            key = comparator.identity(d)
            if key != comparator.identity(a):
                # Different things at the same position: an ordering difference, which
                # is what an order-sensitive comparison exists to detect. Not an
                # equivalence question at all, so the tri-state is not consulted.
                relationship = MODIFIED
            else:
                relationship = _relationship(comparator, d, a)
        elif d is not None:
            key = comparator.identity(d)
            relationship = DECLARED_ONLY if active_complete else COUNTERPART_UNKNOWN
        else:
            key = comparator.identity(a)
            relationship = ACTIVE_ONLY if declared_complete else COUNTERPART_UNKNOWN
        items.append(_item(key, d, a, relationship, declared_complete, active_complete,
                           position=index))
    return items


def _group(records, comparator):
    groups, order = {}, []
    for record in records:
        key = comparator.identity(record)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(record)
    return groups, order


def _relationship(comparator, declared, active):
    """The domain's tri-state verdict, mapped onto a pair relationship.

    The verdict is validated rather than trusted: a comparator that returned True, None or
    a typo would otherwise silently become DIFFERENT under any `if` the engine wrote, and
    the whole point of this contract is that a wrong answer cannot be produced by accident.
    """
    verdict = comparator.compare_pair(declared, active)
    if verdict not in _RELATIONSHIP_OF:
        raise ValueError(
            "%s.compare_pair returned %r; the contract is EQUIVALENT, DIFFERENT or "
            "UNKNOWN" % (type(comparator).__name__, verdict))
    return _RELATIONSHIP_OF[verdict]


def _item(key, declared_record, active_record, relationship,
          declared_complete, active_complete, **where):
    """One relationship, carrying enough provenance to explain itself.

    A report saying "declared but not active" must be able to show the operator which
    declaration, from which source and line, and why the engine was entitled to call it
    absent rather than unknown.
    """
    item = {
        "identity": key,
        "relationship": relationship,
        "declared": _reference(declared_record),
        "active": _reference(active_record),
        "absence_assertable": {"declared_side": declared_complete,
                               "active_side": active_complete},
    }
    if relationship == COUNTERPART_UNKNOWN:
        item["reason"] = (
            "the counterpart source is incomplete, so this record's absence from it "
            "cannot be asserted")
    elif relationship == AMBIGUOUS:
        item["reason"] = (
            "this identity appears more than once and the counts differ, so no "
            "deterministic pairing exists")
    elif relationship == EQUIVALENCE_UNKNOWN:
        item["reason"] = (
            "a counterpart was found, and the available evidence cannot establish "
            "whether the two are semantically equivalent")
    item.update(where)
    return item


def _reference(record):
    """A pointer back into the source evidence, never a copy of the whole record."""
    if record is None:
        return None
    return {key: record.get(key)
            for key in ("source_path", "source_line", "ordinal", "path", "key")
            if record.get(key) is not None} or {"present": True}


def _evidence(coverage, items, comparator, declared, active, reason,
              declared_complete=None, active_complete=None):
    status = {COMPLETE: result.COLLECTED, PARTIAL: result.PARTIAL,
              NOT_COMPARABLE: result.NOT_TESTED,
              NOT_APPLICABLE: result.NOT_TESTED}[coverage]
    counts = {}
    for item in items:
        counts[item["relationship"]] = counts.get(item["relationship"], 0) + 1
    provenance = dict(comparator.semantic_identity())
    undecidable = counts.get(EQUIVALENCE_UNKNOWN, 0)
    ambiguous = counts.get(AMBIGUOUS, 0)
    provenance.update({
        # CQ-3. This key was `coverage`, which is ALSO the R1.5-P key for a LIST of
        # structured acquisition entries. Mounts is the first module that produces both,
        # and a combined provenance would have had one name meaning a string in one place
        # and a list in another - a collision waiting for a renderer or a snapshot
        # consumer to read the wrong one. R1.5-P keeps `coverage`; the S3 scalar is
        # renamed, because it is the newer and narrower concept.
        #
        # It names what it actually is after IQ-020: how completely the evidence
        # universes ENTERING this comparison were acquired. Not semantic comparability,
        # not pairing determinacy, and not the R1.5-P collection.
        "comparison_input_coverage": coverage,
        # The SECOND axis, reported beside coverage and never folded into it. Coverage
        # answers "did we obtain the evidence"; comparability answers "could we judge
        # what we obtained". A run can be COMPLETE on the first and PARTIAL on the
        # second, and a reader who sees only one of them will draw the wrong conclusion
        # about which problem to go and solve.
        "comparability": (FULLY_COMPARABLE if not undecidable
                          else PARTIALLY_COMPARABLE),
        "undecidable_pairs": undecidable,
        # The pairing axis. Complete sources may still admit no deterministic pairing.
        "pairing": DETERMINISTIC_PAIRING if not ambiguous else AMBIGUOUS_PAIRING,
        "ambiguous_records": ambiguous,
        "declared_status": declared.status,
        "active_status": active.status,
        "declared_universe_complete": declared_complete,
        "active_universe_complete": active_complete,
        "relationship_counts": counts,
    })
    return result.Evidence(status, records=items, reason=reason,
                           source="declared+active", provenance=provenance)
