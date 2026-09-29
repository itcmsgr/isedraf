# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Acquire declared fstab and active mount evidence, and compare them honestly.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, GOV-001
#
# /proc/self/mountinfo is the active source. /proc/mounts was measured against it: same
# line count, and it LOSES mount ID, parent ID and the root field. It is NOT a fallback -
# a comparison whose identity silently degraded is worse than one that reports it could
# not run. findmnt is never invoked.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Declared and active mount evidence, with source status and universe kept apart."""
import os

from .. import coverage, hostio, hostpath
from ..shared import compare, result
from . import model, sources

FSTAB = "/etc/fstab"
MOUNTINFO = "/proc/self/mountinfo"
NAMESPACE = "/proc/self/ns/mnt"


def declared_path(root):
    """The fstab path for a collection root. PURE - no I/O, no host state.

    Ruling F requires path logic to be exercisable at collection_root="/" without
    performing acquisition, and an inline call inside a collector cannot be. Separating
    it is what makes the production root testable at all, which is the defect class that
    reached frozen code in authorized_keys.
    """
    return hostpath.under(root, FSTAB)


def active_path(root):
    """The mountinfo path for a collection root. PURE."""
    return hostpath.under(root, MOUNTINFO)


def namespace_path(root):
    """The namespace-link path for a collection root. PURE."""
    return hostpath.under(root, NAMESPACE)


def _contained(root, path):
    """Resolved-target containment. hostpath owns the arithmetic; the caller resolves.

    SHARED_ABSTRACTION_CANDIDATE, consumer_count = 2 (authorizedkeys, mounts). hostpath is
    pure and cannot see a symlinked /etc, fstab or mountinfo. realpath is a CHECK, never
    identity: the recorded path stays lexical. This does NOT prove race-free acquisition.
    """
    return hostpath.contains(os.path.realpath(root), os.path.realpath(path))


def _source_space(root):
    """RULING E. Fixture evidence is never described as this process's namespace."""
    return (model.SOURCE_LIVE_NAMESPACE if os.path.normpath(root) == os.sep
            else model.SOURCE_FIXTURE_OFFLINE)


def _side(name, path, status, outcome, reason, universe_complete, records, malformed,
          provenance):
    # The coverage entry names the PATH ACTUALLY READ, not the logical source. Naming the
    # logical one made a fixture run's evidence say "/proc/self/mountinfo", which reads as
    # the live kernel file and is exactly the misattribution ruling E forbids.
    entry = coverage.source(
        "mounts", path, status, outcome, coverage.OP_FILE_READ, reason=reason,
        universe=(coverage.UNIVERSE_COMPLETE if universe_complete
                  else coverage.UNIVERSE_INCOMPLETE))
    provenance = dict(provenance)
    provenance["coverage"] = [entry] + list(provenance.pop("extra_coverage", []))
    provenance["universe_complete"] = universe_complete
    provenance["malformed_count"] = malformed
    evidence = result.Evidence(status, records=records, reason=reason, source=path,
                               provenance=provenance)
    return evidence


def collect_declared(root="/"):
    """/etc/fstab under the collection root.

    RULING D: source status and universe completeness are separate. An absent file fully
    establishes that THIS source contributes zero declarations, so the FSTAB_DECLARATIONS
    universe is COMPLETE while the source is honestly NOT_TESTED.
    """
    path = declared_path(root)
    # NOT "source": FSTAB. That field held the LOGICAL path - /etc/fstab,
    # /proc/self/mountinfo - while the bytes came from under a collection root, so a
    # reader walking the evidence for the sources it read was handed the live paths.
    # The same misattribution ruling E forbids, one field over from where it was fixed
    # in the coverage entry. The path actually read is Evidence.source and the coverage
    # entry; this names WHICH source it is, and is not a path.
    base = {"scope": model.DECLARED_SCOPE, "dimension": model.DECLARED,
            "source_name": "fstab",
            "universe_note": (
                "The universe is the declarations in /etc/fstab. It excludes systemd "
                "mount units, generator output and transient mounts, whose absence is "
                "never claimed."),
            "resolution": "SOURCE_SPECIFICATIONS_ARE_NOT_RESOLVED"}

    if not _contained(root, path):
        return _side(FSTAB, path, result.NOT_TESTED, coverage.NOT_SUPPORTED,
                     "SOURCE_OUTSIDE_COLLECTION_ROOT: %s resolves outside the collection "
                     "root and was not read." % FSTAB, False, [], 0, base)

    outcome = hostio.read_file_lossless(path)
    if not outcome.ok:
        if outcome.detail == hostio.NOT_FOUND:
            return _side(FSTAB, path, result.NOT_TESTED, hostio.NOT_FOUND,
                         "SOURCE_ABSENT: %s does not exist, so this host declares no "
                         "fstab entries. Declarations from other mechanisms are outside "
                         "this universe and are not claimed absent." % FSTAB,
                         True, [], 0, base)
        status = (result.NOT_TESTED if outcome.detail == hostio.PERMISSION_DENIED
                  else result.ERROR)
        return _side(FSTAB, path, status, outcome.detail,
                     "SOURCE_UNREADABLE: %s exists and could not be read, so "
                     "declarations may exist that were not observed." % FSTAB,
                     False, [], 0, base)

    records, malformed = sources.parse_fstab(outcome.value, path)
    status = result.PARTIAL if malformed else result.COLLECTED
    reason = (None if not malformed else
              "MALFORMED_RECORDS: %d fstab line(s) did not parse and are retained; "
              "declarations may exist that were not understood." % malformed)
    return _side(FSTAB, path, status, outcome.detail, reason, not malformed,
                 records, malformed, base)


def collect_active(root="/"):
    """Active mounts, from the source space the collection root selects."""
    space = _source_space(root)
    path = active_path(root)
    namespace, namespace_entry = _namespace(root, space)
    base = {"scope": model.ACTIVE_SCOPE, "dimension": model.ACTIVE,
            "source_name": "mountinfo",
            "source_space": space, "mount_namespace": namespace,
            "extra_coverage": [namespace_entry],
            "namespace_boundary": (
                "Active mounts from one mount namespace. The collector cannot prove it "
                "shares the initial namespace, so mounts outside the observed one are "
                "neither seen nor claimed absent. An evidence boundary, not a privilege "
                "limitation: no acquisition method here establishes that additional "
                "authority would reveal other namespaces.")}

    if not _contained(root, path):
        return _side(MOUNTINFO, path, result.NOT_TESTED, coverage.NOT_SUPPORTED,
                     "SOURCE_OUTSIDE_COLLECTION_ROOT: %s resolves outside the collection "
                     "root and was not read." % MOUNTINFO, False, [], 0, base)

    outcome = hostio.read_file_lossless(path)
    if not outcome.ok:
        status = (result.NOT_TESTED if outcome.detail in (hostio.NOT_FOUND,
                                                          hostio.PERMISSION_DENIED)
                  else result.ERROR)
        reason = ("SOURCE_ABSENT: %s is not present, so no active mount evidence was "
                  "obtained. No fallback to another mount table is attempted, because "
                  "one would silently lose mount identity and topology." % MOUNTINFO
                  if outcome.detail == hostio.NOT_FOUND
                  else "SOURCE_UNREADABLE: %s could not be read." % MOUNTINFO)
        return _side(MOUNTINFO, path, status, outcome.detail, reason, False, [], 0, base)

    records, malformed = sources.parse_mountinfo(outcome.value, path)
    status = result.PARTIAL if malformed else result.COLLECTED
    reason = (None if not malformed else
              "MALFORMED_RECORDS: %d mountinfo line(s) did not parse and are retained. "
              "Active mounts may exist that were not understood, so absence against the "
              "active side is not claimed." % malformed)
    # A malformed active record makes the ACTIVE universe incomplete. Dropping one - or
    # keeping it while calling the universe complete - would manufacture a false
    # DECLARED_ONLY, which is the worse direction.
    return _side(MOUNTINFO, path, status, outcome.detail, reason, not malformed,
                 records, malformed, base)


def _namespace(root, space):
    """Which namespace was observed, where that question applies."""
    if space != model.SOURCE_LIVE_NAMESPACE:
        return None, coverage.source(
            "mounts", namespace_path(root), result.NOT_TESTED, coverage.NOT_SUPPORTED,
            coverage.OP_FILE_METADATA,
            reason="NOT_APPLICABLE: the active evidence is fixture or offline, so it has "
                   "no relationship to this process's mount namespace.",
            universe=coverage.UNIVERSE_NOT_APPLICABLE)
    path = namespace_path(root)
    observed, outcome = None, coverage.READ_OK
    try:
        observed = os.readlink(path)
    except OSError as error:
        errno = getattr(error, "errno", None)
        outcome = (coverage.NOT_FOUND if errno == 2
                   else coverage.PERMISSION_DENIED if errno == 13
                   else coverage.IO_ERROR)
    return observed, coverage.source(
        "mounts", path,
        result.COLLECTED if observed else result.NOT_TESTED, outcome,
        coverage.OP_FILE_METADATA,
        reason=(None if observed else
                "SOURCE_UNREADABLE: the namespace identity could not be established. The "
                "active evidence is still one namespace's view."),
        universe=(coverage.UNIVERSE_COMPLETE if observed
                  else coverage.UNIVERSE_INCOMPLETE))


def compare_declared_active(declared, active):
    """S3 with the mounts adapter, told each side's universe completeness explicitly."""
    return compare.compare(
        declared, active, model.MountComparator(),
        declared_universe_complete=declared.provenance.get("universe_complete", False),
        active_universe_complete=active.provenance.get("universe_complete", False))


def collect(root="/"):
    declared = collect_declared(root)
    active = collect_active(root)
    comparison = compare_declared_active(declared, active)
    status, reason = _combined(declared, active)
    return result.Evidence(
        status, records=comparison.records, reason=reason, source=root,
        provenance={
            "scope": "%s + %s" % (model.DECLARED_SCOPE, model.ACTIVE_SCOPE),
            "active_source_space": active.provenance.get("source_space"),
            "limitation": model.LIMITATION,
            "not_collected": list(model.NOT_COLLECTED),
            # ONE artifact, ONE coverage entry per source. Each side still describes
            # itself when used standalone - collect_declared() and collect_active() carry
            # their own coverage - but an EMBEDDED side does not, because the aggregate
            # below already holds its entries. Carrying both put every entry in the
            # object twice, and a consumer summing privilege-limited sources by walking
            # would have double-counted them.
            "declared": _embedded(declared.provenance, declared.records),
            "active": _embedded(active.provenance, active.records),
            "comparison": comparison.provenance,
            # CQ-3: the R1.5-P LIST, alongside S3's scalar under its own name. Mounts is
            # the first module carrying both, so this is where the rename is proved.
            "coverage": (list(declared.provenance.get("coverage", []))
                         + list(active.provenance.get("coverage", []))),
            "coverage_is_domain_aggregate": True,
            "comparison_input_coverage":
                comparison.provenance.get("comparison_input_coverage"),
            "pairing": comparison.provenance.get("pairing"),
            "comparability": comparison.provenance.get("comparability"),
        })


def _embedded(provenance, records):
    """A side's provenance and its PARSED RECORDS, inside the combined artifact.

    The records are carried because the comparison items above hold only
    _reference() pointers - source_path, source_line, ordinal - and a pointer whose
    referent is absent from the artifact points nowhere. Without this, a reader had
    the engine's interpretation and none of the evidence it interpreted: no
    options_raw, so the contract's verbatim-retention rule held only in memory, and
    an artifact could not be inspected without ISEDRAF.

    The interpretive layer stays at Evidence.records; this is the factual layer.
    Both are present, and they are not merged.
    """
    embedded = dict(provenance)
    embedded.pop("coverage", None)
    embedded["coverage_in"] = "domain aggregate at provenance.coverage"
    embedded["records"] = list(records)
    return embedded


def _combined(declared, active):
    if declared.status == result.COLLECTED and active.status == result.COLLECTED:
        return result.COLLECTED, None
    parts = [e.reason for e in (declared, active) if e.reason]
    if declared.status == result.NOT_TESTED and active.status == result.NOT_TESTED:
        return result.NOT_TESTED, " ".join(parts) or "NOT_TESTED: no mount evidence."
    return result.PARTIAL, " ".join(parts) or "PARTIAL: mount evidence is incomplete."
