# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: What the collection could observe, why not, and what would be needed instead.
# Implements: SCOPE-022, SCOPE-045, GOV-001
#
# R1.5-P. The single authority for acquisition coverage, and the reason it is single.
#
# hostio has always distinguished NOT_FOUND from PERMISSION_DENIED from IO_ERROR. Two of
# five domains consumed that distinction; the rest dropped it, and accounts/acquire.py
# computed `detail = PERMISSION_DENIED` for /etc/shadow and then serialised only `status`
# and `reason`. The answer survived as an English sentence. A consumer that wanted to know
# whether privilege caused a gap had to parse prose.
#
# THE DERIVED FIELDS ARE DERIVED HERE, AND NOWHERE ELSE.
#
# A domain states FACTS about its acquisition: what it tried, what came back, and whether
# its own source universe was complete. It does not author `privilege_limited` and it does
# not author `absence_claim_allowed`. Owner ruling: if a value is derivable from canonical
# structured fields, an independently authored copy is a second truth waiting to
# contradict the first - and the one that gets it wrong will be the one a criterion reads.
#
# Pure: takes structured facts, returns structured facts. No filesystem, no environment,
# no clock, no network. Acquisition mode is passed IN, never sensed here.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Evidence coverage: the boundary of what a collection was capable of proving."""

from . import canonical
from .status import COLLECTED, ERROR, NOT_TESTED, PARTIAL      # noqa: F401

SCHEMA_VERSION = 1

# --- what the collection tried ----------------------------------------------------------
# The OPERATION is a fact about what was attempted, not a judgement. It is what lets the
# access requirement be derived rather than declared: a refused file read needs file-read
# authority, and no domain has to decide that for itself.
OP_FILE_READ = "FILE_READ"
OP_FILE_METADATA = "FILE_METADATA"
OP_DIRECTORY_LIST = "DIRECTORY_LIST"
OP_COMMAND = "COMMAND"
OP_KERNEL_INTERFACE = "KERNEL_INTERFACE"
OP_SERVICE_QUERY = "SERVICE_QUERY"
OPERATIONS = (OP_FILE_READ, OP_FILE_METADATA, OP_DIRECTORY_LIST, OP_COMMAND,
              OP_KERNEL_INTERFACE, OP_SERVICE_QUERY)

# --- what came back ----------------------------------------------------------------------
# hostio's vocabulary, re-exported so a consumer of coverage never has to import the I/O
# layer to read a coverage record.
READ_OK = "READ_OK"
NOT_FOUND = "NOT_FOUND"
PERMISSION_DENIED = "PERMISSION_DENIED"
IO_ERROR = "IO_ERROR"
NOT_SUPPORTED = "NOT_SUPPORTED"
# The source exists as a concept and this build cannot read it: no parser, no tool, a
# kernel feature that is not present. NOT a privilege problem, and deliberately distinct
# from IO_ERROR so that "we could not" and "we do not know how" stay separable.
TRUNCATED = "TRUNCATED"
# The source is larger than the read bound and was NOT read as complete evidence (owner
# invariant 2026-09-24: truncated input is never COLLECTED-complete).
OUTCOMES = (READ_OK, NOT_FOUND, PERMISSION_DENIED, IO_ERROR, NOT_SUPPORTED, TRUNCATED)

# --- what additional access the EVIDENCE would need --------------------------------------
# These describe the requirement, never the mechanism. Access may be granted by a file
# ACL, a group, a sudo policy, a capability, a helper or root, and which of those an
# operator should use is a decision about their host. ISEDRAF does not guess it, and
# `root` is deliberately absent from this vocabulary: root is a mechanism, and naming a
# mechanism as the requirement is how "run it as root" becomes the only advice a tool
# knows how to give.
ACCESS_NONE = "ACCESS_NONE"
ACCESS_FILE_READ = "ACCESS_FILE_READ"
ACCESS_DIRECTORY_TRAVERSE = "ACCESS_DIRECTORY_TRAVERSE"
ACCESS_COMMAND_QUERY = "ACCESS_COMMAND_QUERY"
ACCESS_KERNEL_INTERFACE = "ACCESS_KERNEL_INTERFACE"
ACCESS_SERVICE_QUERY = "ACCESS_SERVICE_QUERY"

ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED = "ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED"
# We know the collection identity lacked sufficient authority. We cannot honestly say
# which narrower evidence-access class would be enough.
#
# OWNER RULING: this class is for that case ONLY. It must never be used for an I/O error,
# an unsupported source, a missing tool, or an unexplained failure - none of which is
# known to be a privilege problem, and all of which would be quietly converted into
# "ask your administrator for more access" by a vocabulary that let them in.

ACCESS_REQUIREMENTS = (ACCESS_NONE, ACCESS_FILE_READ, ACCESS_DIRECTORY_TRAVERSE,
                       ACCESS_COMMAND_QUERY, ACCESS_KERNEL_INTERFACE,
                       ACCESS_SERVICE_QUERY, ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED)

_BY_OPERATION = {
    OP_FILE_READ: ACCESS_FILE_READ,
    OP_FILE_METADATA: ACCESS_FILE_READ,
    OP_DIRECTORY_LIST: ACCESS_DIRECTORY_TRAVERSE,
    OP_COMMAND: ACCESS_COMMAND_QUERY,
    OP_KERNEL_INTERFACE: ACCESS_KERNEL_INTERFACE,
    OP_SERVICE_QUERY: ACCESS_SERVICE_QUERY,
}

# --- how complete the source's own universe was -------------------------------------------
UNIVERSE_COMPLETE = "COMPLETE"
UNIVERSE_INCOMPLETE = "INCOMPLETE"
UNIVERSE_NOT_APPLICABLE = "NOT_APPLICABLE"

# --- the acquisition context ---------------------------------------------------------------
# THIRD AXIS. Owner ruling: what happened, what would be needed, and how the acquisition
# was attempted are three questions, and a single privilege field cannot answer them.
#
#     access_outcome    PERMISSION_DENIED        what happened
#     required_access   ACCESS_FILE_READ         what would obtain the evidence
#     acquisition_mode  CURRENT_IDENTITY         how it was attempted
#
MODE_CURRENT_IDENTITY = "CURRENT_IDENTITY"
# The only mode R1.5 can produce. ISEDRAF attempted the acquisition as whatever identity
# it was already running as, and elevated nothing.
#
# There is deliberately no ELEVATED value. An earlier draft had one, and it was a fiction
# twice over: SCOPE-071 refuses privileged execution so no collection path could emit it,
# and - the subtler half - a process that HAPPENS to run as uid 0 has not performed
# elevation. Execution identity and "ISEDRAF elevated an acquisition operation" are
# different provenance facts, and an enum that conflated them would have frozen the
# confusion into the schema.
#
# Future modes - a privileged helper, an operator-approved elevated operation - are
# CONTRACTED DIRECTION and are admitted when a mechanism exists to produce them. Reserving
# the semantics now would mean tests could produce a value production cannot.
MODES = (MODE_CURRENT_IDENTITY,)

# Passed in, never sensed here: a pure module that read the process's euid would produce a
# different answer depending on where it ran.


def required_access(operation, outcome):
    """What the EVIDENCE would need. Derived, never declared by a domain.

    Only a refusal implies an access requirement. An absent source needs no authority to
    stay absent, an I/O error is a statement about a device, and an unsupported source is
    a statement about this build - reporting any of them as "needs more privilege" would
    send an operator to grant access that changes nothing.
    """
    if outcome != PERMISSION_DENIED:
        return ACCESS_NONE
    return _BY_OPERATION.get(operation, ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED)


def privilege_limited(outcome):
    """True only when the collection identity was the obstacle."""
    return outcome == PERMISSION_DENIED


def absence_claim_allowed(universe):
    """THE central rule: does the BOUNDED UNIVERSE support an absence claim?

    CQ-1. This used to read `status == COLLECTED and universe is complete`, and the
    status term was the non-conforming half. A source status describes an acquisition
    OPERATION; universe completeness describes whether the bounded evidence universe was
    observed well enough to prove absence. They come apart, and the case that exposed it
    is ordinary:

        /etc/fstab absent            NOT_TESTED / NOT_FOUND          universe COMPLETE
            - there are no fstab declarations, and that is fully established
        /etc/fstab permission denied NOT_TESTED / PERMISSION_DENIED  universe INCOMPLETE
            - declarations may exist that were never seen

    Identical status, opposite answers. The frozen R1.5-P text already said the right
    thing - "an existing but unreadable source cannot support an absence claim, and
    neither can a partially observed one" - and an absent source is neither of those.
    S3 was corrected first (IQ-020) and this authority was left contradicting it: for the
    same source S3 answered ACTIVE_ONLY while this answered False.

    There is ONE meaning of "can this bounded universe support an absence claim", and the
    universe is the authority. Criteria consume it; no domain authors it.
    """
    return universe in (UNIVERSE_COMPLETE, UNIVERSE_NOT_APPLICABLE)


def source(domain, name, status, outcome, operation, reason=None,
           universe=UNIVERSE_COMPLETE, note=None):
    """One acquisition attempt, with every derivable field derived here.

    A caller supplies facts: which source, what it tried, what came back, whether its own
    universe was complete. Everything a consumer needs in order to reason about coverage
    is computed from those, in this function, once.
    """
    if outcome not in OUTCOMES:
        raise ValueError("unknown access outcome %r" % (outcome,))
    if operation not in OPERATIONS:
        raise ValueError("unknown operation %r" % (operation,))
    if universe not in (UNIVERSE_COMPLETE, UNIVERSE_INCOMPLETE,
                        UNIVERSE_NOT_APPLICABLE):
        raise ValueError("unknown universe state %r" % (universe,))
    return {
        "domain": domain,
        "source": name,
        "operation": operation,
        "status": status,
        "reason": reason,
        "access_outcome": outcome,
        "source_universe": universe,
        # --- derived, centrally -------------------------------------------------------
        "privilege_limited": privilege_limited(outcome),
        "required_access": required_access(operation, outcome),
        "affects_completeness": status != COLLECTED or universe == UNIVERSE_INCOMPLETE,
        "absence_claim_allowed": absence_claim_allowed(universe),
        "note": note,
    }


def manifest(sources, acquisition_mode):
    """The Evidence Limits Manifest: the boundary of what this run could prove.

    Counts are over the EXPLICIT REQUESTED UNIVERSE - the sources this collection set out
    to acquire - and never over "Linux security". A percentage computed against anything
    else has no defensible denominator, so none is produced here.
    """
    if acquisition_mode not in MODES:
        raise ValueError("unknown acquisition mode %r" % (acquisition_mode,))
    ordered = sorted(sources, key=lambda s: (s["domain"], s["source"]))
    limitations = [s for s in ordered if s["affects_completeness"]]
    body = {
        "schema_version": SCHEMA_VERSION,
        "acquisition_mode": acquisition_mode,
        "requested_sources": len(ordered),
        "complete_sources": len([s for s in ordered
                                 if not s["affects_completeness"]]),
        "partial_sources": len([s for s in ordered if s["status"] == PARTIAL]),
        "privilege_limited_sources": len([s for s in ordered
                                          if s["privilege_limited"]]),
        "other_unavailable_sources": len([s for s in limitations
                                          if not s["privilege_limited"]
                                          and s["status"] != PARTIAL]),
        "required_access": sorted(set(s["required_access"] for s in ordered
                                      if s["required_access"] != ACCESS_NONE)),
        "sources": ordered,
        "limitations": limitations,
    }
    # ROOT IS NOT COMPLETENESS, and the schema enforces it rather than asserting it: the
    # counts above are computed from source outcomes alone and the mode is not an input to
    # any of them. There is no field here that could express "complete because of how we
    # ran", in any mode, present or future.
    body["coverage_digest"] = coverage_digest(body)
    return body


def coverage_digest(body):
    """A deterministic identity for what this run could OBSERVE, not for what it found.

    Computed over the coverage facts alone - domain, source, operation, status, outcome,
    universe - and deliberately not over any host fact. That is the whole point: two runs
    of an unchanged host that differ only in what the collector was allowed to read must
    produce different coverage digests and identical host state, so a later comparison can
    say "visibility changed" instead of "the host changed".
    """
    facts = [{"domain": s["domain"], "source": s["source"],
              "operation": s["operation"], "status": s["status"],
              "access_outcome": s["access_outcome"],
              "source_universe": s["source_universe"]}
             for s in sorted(body["sources"],
                             key=lambda s: (s["domain"], s["source"]))]
    frame = {"schema_version": SCHEMA_VERSION,
             "acquisition_mode": body["acquisition_mode"], "sources": facts}
    return canonical.rendered(canonical.hash_frame(
        DOMAIN_COVERAGE, canonical.canonical_bytes(frame)))


DOMAIN_COVERAGE = "ISEDRAF:EVIDENCE-COVERAGE:V1"


def compare(before, after):
    """Did the collector's VISIBILITY change between two runs?

    Answers one question and refuses the other. A change here is never a host-state
    change: gaining permission to read /etc/shadow makes previously invisible facts
    visible, and reporting those as newly created host state is the observation capability
    masquerading as drift.
    """
    changed = []
    index = dict(((s["domain"], s["source"]), s) for s in before["sources"])
    for entry in after["sources"]:
        key = (entry["domain"], entry["source"])
        was = index.get(key)
        if was is None:
            changed.append({"domain": key[0], "source": key[1],
                            "change": "SOURCE_ADDED_TO_REQUESTED_UNIVERSE"})
            continue
        if (was["status"], was["access_outcome"]) != (entry["status"],
                                                      entry["access_outcome"]):
            changed.append({
                "domain": key[0], "source": key[1],
                "change": ("VISIBILITY_INCREASED"
                           if was["affects_completeness"]
                           and not entry["affects_completeness"]
                           else "VISIBILITY_DECREASED"
                           if entry["affects_completeness"]
                           and not was["affects_completeness"]
                           else "VISIBILITY_CHANGED"),
                "before": {"status": was["status"],
                           "access_outcome": was["access_outcome"]},
                "after": {"status": entry["status"],
                          "access_outcome": entry["access_outcome"]},
            })
    return {
        "coverage_changed": bool(changed)
                            or before["coverage_digest"] != after["coverage_digest"],
        "before_coverage_digest": before["coverage_digest"],
        "after_coverage_digest": after["coverage_digest"],
        "changes": changed,
        "host_state_delta": "NOT_ESTABLISHED_BY_COVERAGE_COMPARISON",
        # Stated as a field so it cannot be forgotten. A coverage comparison establishes
        # what the collector could see. Whether the HOST changed is a different question
        # over different evidence, and a consumer reading this object gets told so.
    }
