# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Resolve the sudoers include graph and collect declared policy from it.
# Implements: SCOPE-022, SCOPE-045, GOV-001
#
# The first real consumer of the Batch 1 primitives.
#
#   S2  include_graph   #include and #includedir, via a sudoers adapter
#   S4  filemeta        ownership and mode of every policy file, lstat only
#   S5  bounded         the includedir listing, with sudoers' own eligibility rule
#
# The division that matters is the one S2 and S5 were corrected to support: the primitive
# observes, the domain decides what the observation means. S5 reports every directory
# entry it saw; `model.includedir_eligible` decides which of them sudoers considers, so a
# .bak file in sudoers.d is recorded as observed and excluded from policy rather than
# parsed as if the host applied it.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Sudoers acquisition: include graph, file metadata, declared policy records."""
import os

from .. import coverage, hostpath, textbytes
from ..shared import bounded, filemeta, include_graph, result
from . import model, sources

SUDOERS = "etc/sudoers"


class SudoersIncludes(include_graph.Adapter):
    """`#include FILE` and `#includedir DIR`, with sudoers' own directory rules.

    sudo's own parser treats these as directives despite the leading `#`, which is a
    genuine grammar quirk rather than a comment convention - a generic include engine
    that skipped `#` lines would follow none of them.
    """

    name = "sudoers"

    #: An empty /etc/sudoers.d is the default state of most Linux hosts, so NO_MATCH must
    #: not make the evidence incomplete - otherwise nearly every host reports PARTIAL and
    #: the status stops carrying information. A named #include that is missing is a
    #: different matter: the administrator wrote a path that is not there.
    COMPLETENESS = dict(include_graph.Adapter.COMPLETENESS)
    COMPLETENESS[include_graph.NO_MATCH] = False
    COMPLETENESS[include_graph.DUPLICATE_INCLUDE] = False

    def __init__(self, root):
        self.root = root
        self.observed_entries = []
        self.excluded_entries = []
        self.unlisted_directories = []

    def _rebase(self, target, parent):
        """Resolve an include target INSIDE the root this collection was given.

        Found by the adversarial lane on first contact, and it is the dangerous class:
        sudoers include paths are absolute on a real host, so `#include /etc/extra` under
        a fixture root resolved against the LIVE filesystem. A fixture run would have read
        the machine executing the test and reported it as the machine under test - the
        exact fallthrough the account contract froze against and the architecture
        assertions forbid.

        The branch is sudoers grammar and stays here; the mapping is shared (hostpath,
        consumer #1 of 3). With root="/" both arms are the identity, so production
        behaviour is unchanged.
        """
        if os.path.isabs(target):
            return hostpath.under(self.root, target)
        return hostpath.beneath(
            self.root, os.path.join(os.path.dirname(parent), target))

    def directives(self, text, path):
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if line.startswith("#includedir") or line.startswith("@includedir"):
                target = line.split(None, 1)[1].strip() if " " in line else ""
                yield number, line, self._directory(target, path), bool(target)
            elif line.startswith("#include") or line.startswith("@include"):
                target = line.split(None, 1)[1].strip() if " " in line else ""
                yield number, line, ([self._rebase(target, path)]
                                     if target else []), bool(target)

    def _directory(self, target, parent):
        """S5 lists the directory; sudoers semantics decide what counts.

        This is the boundary the pilot exists to test. The enumerator must not substitute
        its generic universe for the domain's: sudo ignores any filename containing '.'
        or ending in '~', and a file it ignores is not policy this host applies.
        """
        if not target:
            return []
        directory = self._rebase(target, parent)

        class SudoersDirectory(bounded.Universe):
            name = "sudoers.d"
            max_depth = 1
            include_files = True
            include_directories = False

        listing = bounded.enumerate_paths(directory, SudoersDirectory())
        events = set(a.get("event") for a in listing.anomalies)
        if listing.status != result.COLLECTED and bounded.ROOT_MISSING not in events:
            # IQ-046 (1): an absent includedir is ordinary, but one that exists and could
            # not be listed (or listed only in part) is policy that was never seen. It must
            # not read as an empty directory, which the include graph treats as harmless.
            # Only a listdir refusal is known to be a privilege limit; any other failure is
            # recorded without claiming one.
            self.unlisted_directories.append({
                "path": directory,
                "access_outcome": (coverage.PERMISSION_DENIED
                                   if bounded.ENTRY_UNREADABLE in events
                                   else coverage.IO_ERROR),
                "reason": listing.reason or "SOURCE_UNREADABLE: %s could not be listed."
                          % directory})
        eligible = []
        for entry in listing.records:
            name = entry["name"]
            self.observed_entries.append({"path": entry["path"], "name": name,
                                          "name_encoding": entry["name_encoding"]})
            if name is None:
                # An undecodable filename cannot be matched against sudoers' rule with
                # any confidence, so it is recorded and excluded rather than guessed at.
                self.excluded_entries.append({"name_bytes_hex": entry["name_bytes_hex"],
                                              "reason": "UNDECODABLE_FILENAME"})
                continue
            if model.includedir_eligible(name):
                eligible.append(entry["path"])
            else:
                self.excluded_entries.append(
                    {"name": name, "reason": "IGNORED_BY_SUDOERS_FILENAME_RULE"})
        return eligible

    def sort_expansion(self, paths):
        """sudo reads an includedir in sorted order, and S2 preserves whatever order the
        adapter returns. Byte ordering keeps it identical on every host."""
        return sorted(paths,
                      key=lambda p: textbytes.original_bytes(os.path.basename(p)))


def collect(root="/"):
    """Declared sudo policy from the whole include graph, in source order."""
    adapter = SudoersIncludes(root)
    graph = include_graph.resolve(os.path.join(root, SUDOERS), adapter)

    if not graph.records or not graph.records[0]["readable"]:
        return result.Evidence(
            graph.status, records=[], reason=graph.reason,
            source=os.path.join(root, SUDOERS),
            provenance=_provenance(adapter, graph, [], 0))

    records, malformed, ordinal, files = [], 0, 0, []
    for node in graph.records:
        files.append(filemeta.observe(node["path"]).records[0])
        if not node["readable"]:
            continue
        parsed, bad = sources.parse(node["text"], node["path"], ordinal)
        records.extend(parsed)
        malformed += bad
        ordinal += len(parsed)

    status, reason = _status(graph, records, malformed, adapter.unlisted_directories)
    return result.Evidence(status, records=records, reason=reason,
                           source=os.path.join(root, SUDOERS),
                           provenance=_provenance(adapter, graph, files, malformed))


def _status(graph, records, malformed, unlisted=()):
    """The include graph, the includedir listings and the parse all constrain completeness."""
    problems = []
    if graph.status != result.COLLECTED:
        problems.append(graph.reason)
    if unlisted:
        problems.append(
            "INCOMPLETE_INCLUDE_GRAPH: %d includedir(s) could not be listed (%s); sudo "
            "policy they may contain was not observed." % (
                len(unlisted), ", ".join(u["path"] for u in unlisted)))
    if malformed:
        if records and malformed == len(records):
            return result.ERROR, (
                "UNPARSEABLE: no line in the sudo policy could be read as a known "
                "construct; no trustworthy normalized interpretation can be produced.")
        problems.append(
            "MALFORMED_RECORDS: %d of %d policy lines did not match a known sudoers "
            "construct and are retained as UNSUPPORTED records." % (malformed,
                                                                   len(records)))
    if problems:
        return result.PARTIAL, " ".join(problems)
    return result.COLLECTED, None


def _provenance(adapter, graph, files, malformed):
    return {
        "scope": "DECLARED_LOCAL_SUDO_POLICY",
        "limitation": model.LIMITATION,
        "not_collected": list(model.NOT_COLLECTED),
        "include_events": graph.anomalies,
        "include_status": graph.status,
        "files": files,
        "coverage": _coverage("sudo", graph) + _listing_coverage(
            "sudo", adapter.unlisted_directories),
        "includedir_entries_observed": adapter.observed_entries,
        "includedir_entries_excluded": adapter.excluded_entries,
        "malformed_count": malformed,
    }


def _listing_coverage(domain, unlisted):
    """One entry per includedir that could not be listed (IQ-046 (1))."""
    return [coverage.source(domain, u["path"], result.NOT_TESTED, u["access_outcome"],
                            coverage.OP_DIRECTORY_LIST, reason=u["reason"],
                            universe=coverage.UNIVERSE_INCOMPLETE)
            for u in unlisted]


def _coverage(domain, graph):
    """R1.5-P acquisition context, one entry per file the include graph reached.

    The graph already knew which nodes were refused and which were simply absent; it
    recorded the distinction as an event label and dropped the machine answer. Nothing
    about the declared configuration changes here.
    """
    out = []
    for node in graph.records:
        outcome = node.get("access_outcome") or (
            coverage.READ_OK if node.get("readable") else coverage.NOT_FOUND)
        out.append(coverage.source(
            domain, node["path"],
            result.COLLECTED if node.get("readable") else (
                result.NOT_TESTED if outcome == coverage.NOT_FOUND
                else result.ERROR if outcome == coverage.IO_ERROR
                else result.NOT_TESTED),
            outcome, coverage.OP_FILE_READ,
            universe=(coverage.UNIVERSE_COMPLETE if node.get("readable")
                      else coverage.UNIVERSE_INCOMPLETE)))
    return out
