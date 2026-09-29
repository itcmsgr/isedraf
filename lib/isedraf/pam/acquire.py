# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Read /etc/pam.d, follow include and substack edges, keep the edges distinct.
# Implements: SCOPE-022, SCOPE-045, GOV-001
#
# ROOTED-PATH QUESTION, ANSWERED: PAM does NOT need it.
#
# sudo and SSH both take an absolute filesystem path from a directive and must map it
# beneath the collection root. PAM does not: `include password-auth` names a SERVICE, and
# a service is resolved by joining the pam.d directory with the name. The pam.d directory
# is already rooted, so no absolute path ever appears to be rebased.
#
# The code looks similar - a name becomes a path - but the operation is different: one
# maps an absolute path under a root, the other joins a name to a known directory. Same
# shape, different abstraction. Consumer count stays at 2.
#
# A target containing path separators is REFUSED rather than joined, because a service
# name is not a path and treating it as one would be the traversal this refuses to have.
#
# S5 enumerates the directory; S4 records metadata. Traversal of the edge graph is done
# here rather than through S2, because a PAM edge is not a file include: the target is a
# service name resolved in one known directory, there is no glob, and the two edge kinds
# mean different things. S2's adapter contract is about include DIRECTIVES naming paths.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Declared PAM stack across service files and their include/substack edges."""
import os

from .. import coverage, hostio
from ..shared import bounded, filemeta, result
from . import model, sources

PAM_D = "etc/pam.d"
MAX_DEPTH = 16


class Services(bounded.Universe):
    """One level, files only. Every service file in pam.d is a root of interest."""

    name = "pam.d"
    max_depth = 1
    include_files = True
    include_directories = False


def collect(root="/"):
    directory = os.path.join(root, PAM_D)
    _coverage = []          # R1.5-P acquisition context, one entry per service file
    listing = bounded.enumerate_paths(directory, Services())
    if listing.status == result.NOT_TESTED:
        return result.Evidence(result.NOT_TESTED, records=[], source=directory,
                               reason=listing.reason,
                               provenance=_provenance(directory, [], [], 0,
                                                  _coverage))

    records, files, events = [], [], []
    ordinal = 0
    visited = set()
    in_progress = []

    def load(service, depth, referenced_by):
        """Parse one service, then follow its edges.

        Two different questions, and an earlier version answered only one of them.
        `in_progress` is the chain currently being expanded and detects a CYCLE, which is
        a broken configuration. `visited` is everything already parsed and detects a
        service reached a second time from elsewhere, which is ordinary - two stacks
        commonly include the same common-auth. Treating both as "already loaded" made a
        cycle indistinguishable from a diamond, and reported a broken stack as complete.

        S2 makes exactly this distinction. The mistake was failing to carry it across.
        """
        nonlocal ordinal
        if depth > MAX_DEPTH:
            events.append({"event": "DEPTH_LIMIT", "service": service,
                           "detail": "edge depth exceeded %d" % MAX_DEPTH})
            return
        if service in in_progress:
            events.append({"event": "CYCLE", "service": service,
                           "referenced_by": referenced_by,
                           "chain": list(in_progress) + [service],
                           "detail": "this service is already being expanded"})
            return
        if service in visited:
            events.append({"event": "ALREADY_LOADED", "service": service,
                           "referenced_by": referenced_by})
            return
        if os.sep in service or service in ("", ".", ".."):
            # A service name is not a path. Joining one that contains separators would
            # be a traversal out of pam.d.
            events.append({"event": "INVALID_SERVICE_NAME", "service": service,
                           "referenced_by": referenced_by,
                           "detail": "a PAM target names a service, not a path"})
            return
        visited.add(service)
        path = os.path.join(directory, service)
        outcome = hostio.read_file_lossless(path)
        files.append(filemeta.observe(path).records[0])
        if not outcome.ok:
            events.append({"event": "MISSING_SERVICE"
                           if outcome.detail == hostio.NOT_FOUND
                           else "UNREADABLE_SERVICE",
                           "service": service, "referenced_by": referenced_by,
                           "detail": outcome.reason,
                           "access_outcome": outcome.detail})
            _coverage.append(coverage.source(
                "pam", path,
                result.NOT_TESTED if outcome.detail == hostio.NOT_FOUND
                else result.ERROR if outcome.detail == hostio.IO_ERROR
                else result.NOT_TESTED,
                outcome.detail, coverage.OP_FILE_READ, reason=outcome.reason,
                universe=coverage.UNIVERSE_INCOMPLETE))
            return
        _coverage.append(coverage.source(
            "pam", path, result.COLLECTED, outcome.detail, coverage.OP_FILE_READ))
        parsed, bad = sources.parse(outcome.value, service, path, ordinal, depth)
        ordinal += len(parsed)
        records.extend(parsed)
        _count[0] += bad
        in_progress.append(service)
        try:
            for record in parsed:
                if record["kind"] == model.EDGE:
                    load(record["target_service"], depth + 1, service)
        finally:
            in_progress.pop()

    _count = [0]
    for entry in listing.records:
        if entry["name"] is None:
            events.append({"event": "UNDECODABLE_SERVICE_NAME",
                           "name_bytes_hex": entry["name_bytes_hex"]})
            continue
        load(entry["name"], 0, None)

    status, reason = _status(events, records, _count[0], listing)
    return result.Evidence(status, records=records, reason=reason, source=directory,
                           provenance=_provenance(directory, files, events,
                                                  _count[0], _coverage))


def _status(events, records, malformed, listing):
    problems = []
    blocking = [e for e in events
                if e["event"] in ("MISSING_SERVICE", "UNREADABLE_SERVICE",
                                  "DEPTH_LIMIT", "INVALID_SERVICE_NAME",
                                  "UNDECODABLE_SERVICE_NAME", "CYCLE")]
    if blocking:
        problems.append(
            "INCOMPLETE_STACK: %d edge target(s) did not resolve (%s). The stack read "
            "here is not the whole stack."
            % (len(blocking), ", ".join(sorted(set(e["event"] for e in blocking)))))
    if listing.status != result.COLLECTED:
        problems.append(listing.reason)
    if malformed:
        if records and malformed == len(records):
            return result.ERROR, (
                "UNPARSEABLE: no line in the PAM configuration could be read as a rule.")
        problems.append(
            "MALFORMED_RECORDS: %d of %d lines could not be read as PAM rules and are "
            "retained as UNSUPPORTED records." % (malformed, len(records)))
    if problems:
        return result.PARTIAL, " ".join(problems)
    return result.COLLECTED, None


def _provenance(directory, files, events, malformed, coverage_entries=None):
    return {"scope": "DECLARED_PAM_STACK",
            "limitation": model.LIMITATION,
            "not_collected": list(model.NOT_COLLECTED),
            "edge_semantics": model.EDGE_SEMANTICS,
            "pam_d": directory,
            "edge_events": events,
            "files": files,
            "coverage": coverage_entries or [],
            "malformed_count": malformed}
