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
# Full Audit (AUTH-029): given the supervisor channel, the engine reads nothing under
# /etc/sudoers* itself. read_sudoers_graph_v1 returns the root file, the listing of
# /etc/sudoers.d and each entry in one AUTH-029 frame, and the include graph is resolved from
# that frame only: an include outside the fixed surface is NOT_TESTED, a symlinked or
# non-regular entry is observed and not read, and either makes the section PARTIAL.
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

from .. import coverage, fixedop, hostio, hostpath, textbytes
from ..shared import bounded, filemeta, include_graph, result
from ..supervisor import frame, protocol
from . import model, sources

SUDOERS = "etc/sudoers"
SUDOERS_OPERATION = "read_sudoers_graph_v1"
SURFACE_ROOT = "/etc/sudoers"
SURFACE_DIRECTORY = "/etc/sudoers.d"
# The contract's bounds (lib/isedraf/supervisor/contracts.py, mirrored by the registry gate).
FRAME_LIMIT = 4194304
FRAME_ITEMS = 2 + 1024
# An acquisition outcome is not a collection status (AUTH-029); this maps it onto the
# engine's access-outcome vocabulary, and the engine alone decides what it means.
_ACCESS = {frame.READ_OK: coverage.READ_OK, frame.NOT_FOUND: coverage.NOT_FOUND,
           frame.PERMISSION_DENIED: coverage.PERMISSION_DENIED,
           frame.TRUNCATED: coverage.TRUNCATED, frame.IO_ERROR: coverage.IO_ERROR,
           frame.SYMLINK: coverage.NOT_SUPPORTED, frame.NON_REGULAR: coverage.NOT_SUPPORTED}
OUTSIDE_SURFACE = "OUTSIDE_OPERATION_SURFACE"


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

    def __init__(self, root, tree=None):
        self.root = root
        self.tree = tree
        self.outside_surface = []
        self.non_regular = []
        self.observed_entries = []
        self.excluded_entries = []
        self.unlisted_directories = []
        self.unfollowed_symlinks = []

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
        if self.tree is not None:
            return self._supervised_directory(directory)

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
            if entry.get("is_symlink") and not self._live():
                # IQ-057, AUTH-029: a symlink is observed as a symlink and never dereferenced
                # in a fixture - its target may be on the machine running the collection, and
                # a relative one is not followed either, so that Full Audit and fixtures read
                # exactly the same surface.
                self.unfollowed_symlinks.append(entry["path"])
                continue
            if model.includedir_eligible(name):
                eligible.append(entry["path"])
            else:
                self.excluded_entries.append(
                    {"name": name, "reason": "IGNORED_BY_SUDOERS_FILENAME_RULE"})
        return eligible

    def _supervised_directory(self, directory):
        """The includedir from the AUTH-029 frame: never listed by the engine itself."""
        if directory != SURFACE_DIRECTORY:
            self.outside_surface.append(directory)
            return []
        listing = self.tree["listing"]
        outcome = listing["acquisition_outcome"]
        if outcome == frame.NOT_FOUND:
            return []
        if outcome != frame.READ_OK:
            # IQ-046 (1): a listing the supervisor could not make is policy never seen,
            # not an empty directory.
            self.unlisted_directories.append({
                "path": directory, "access_outcome": _ACCESS[outcome],
                "operation_id": SUDOERS_OPERATION,
                "reason": "SOURCE_UNREADABLE: %s could not be listed (%s)."
                          % (directory, outcome)})
            return []
        eligible = []
        for entry in self.tree["entries"]:
            name = os.fsdecode(entry["name"])
            path = os.path.join(directory, name)
            decodable = not textbytes.has_surrogates(name)
            self.observed_entries.append({"path": path if decodable else None,
                                          "name": name if decodable else None,
                                          "name_encoding": textbytes.encoding_of(name)})
            outcome = entry["acquisition_outcome"]
            if outcome == frame.SYMLINK:
                self.unfollowed_symlinks.append(path)
                continue
            if outcome == frame.NON_REGULAR:
                self.non_regular.append(path)
                continue
            if not decodable:
                self.excluded_entries.append({"name_bytes_hex": textbytes.hex_of(name),
                                              "reason": "UNDECODABLE_FILENAME"})
                continue
            if model.includedir_eligible(name):
                eligible.append(path)
            else:
                self.excluded_entries.append(
                    {"name": name, "reason": "IGNORED_BY_SUDOERS_FILENAME_RULE"})
        return eligible

    def _live(self):
        return os.path.normpath(self.root) == os.sep

    def sort_expansion(self, paths):
        """sudo reads an includedir in sorted order, and S2 preserves whatever order the
        adapter returns. Byte ordering keeps it identical on every host."""
        return sorted(paths,
                      key=lambda p: textbytes.original_bytes(os.path.basename(p)))


class _FromFrame(object):
    """The read function the include graph uses in Full Audit: bytes only from the frame."""

    def __init__(self, tree):
        self.items = {SURFACE_ROOT: tree["root"]}
        for entry in tree["entries"]:
            self.items[os.path.join(SURFACE_DIRECTORY, os.fsdecode(entry["name"]))] = entry
        self.listed = tree["listing"]["acquisition_outcome"] == frame.READ_OK
        self.outside = []

    def expand(self, target):
        """What an include target names, from the frame - never from this machine's disk.

        A path the frame holds is itself. A path in the listed directory that the complete
        listing does not hold is absent there. Anything else is outside the surface, and is
        handed to the read, which records it as not read rather than as absent."""
        if target in self.items:
            return [target]
        if os.path.dirname(target) == SURFACE_DIRECTORY and self.listed:
            return []
        return [target]

    def metadata(self, path):
        item = self.items.get(path)
        return None if item is None else item["lstat"]

    def __call__(self, path):
        item = self.items.get(path)
        if item is None:
            self.outside.append(path)
            return hostio.Outcome(ok=False, reason=OUTSIDE_SURFACE, source=path,
                                  detail=coverage.NOT_SUPPORTED)
        outcome = item["acquisition_outcome"]
        if outcome == frame.READ_OK:
            return hostio.Outcome(value=item["content"].decode("utf-8", "surrogateescape"),
                                  source=path, detail=hostio.READ_OK)
        return hostio.Outcome(ok=False, reason="SOURCE_UNREADABLE", source=path,
                              detail=_ACCESS[outcome])


def _acquire_tree(channel):
    """The decoded AUTH-029 tree, or (None, status, reason) for an operation that failed."""
    try:
        res = channel.request(SUDOERS_OPERATION)
    except (protocol.ProtocolError, OSError) as exc:
        return None, result.ERROR, ("SUPERVISOR_CHANNEL_FAILED: %s could not be requested "
                                    "from the supervisor (%s)." % (SUDOERS_OPERATION,
                                                                    type(exc).__name__))
    if res["status"] == protocol.REFUSED:
        return None, result.NOT_TESTED, ("SUPERVISOR_REFUSED: %s was refused by the "
                                         "supervisor; no sudo policy was observed."
                                         % SUDOERS_OPERATION)
    if res["status"] == protocol.TRUNCATED:
        return None, result.NOT_TESTED, ("SOURCE_TRUNCATED: the sudo policy surface exceeds "
                                         "%s's bounds and was not observed as complete "
                                         "evidence." % SUDOERS_OPERATION)
    if res["status"] != protocol.COMPLETED:
        return None, result.ERROR, ("SUPERVISOR_FAILED: %s did not complete (%s)." % (
            SUDOERS_OPERATION, (res["stderr_bytes"] or b"").decode("ascii", "replace")))
    try:
        tree = frame.check_tree(frame.decode(res["bytes"], FRAME_LIMIT, FRAME_ITEMS),
                                SURFACE_ROOT.encode("ascii"),
                                SURFACE_DIRECTORY.encode("ascii"))
    except frame.FrameError as exc:
        return None, result.ERROR, ("SUPERVISOR_FRAME_INVALID: %s returned a frame that is "
                                    "not what AUTH-029 allows (%s)." % (SUDOERS_OPERATION, exc))
    return tree, None, None


def collect(root="/", channel=None):
    """Declared sudo policy from the whole include graph, in source order.

    `channel` is the Full Audit supervisor channel, given only by the reduced engine; the
    surface is then acquired by read_sudoers_graph_v1 (AUTH-029) and nothing under
    /etc/sudoers* is read by the engine itself.
    """
    if channel is not None:
        return _collect_supervised(channel)
    adapter = SudoersIncludes(root)
    graph = include_graph.resolve(os.path.join(root, SUDOERS), adapter)
    return _evidence(root, adapter, graph,
                     lambda path: filemeta.observe(path).records[0])


def _collect_supervised(channel):
    tree, status, reason = _acquire_tree(channel)
    if tree is None:
        entry = coverage.source("sudo", SURFACE_ROOT, status,
                                coverage.IO_ERROR if status == result.ERROR
                                else coverage.NOT_SUPPORTED, coverage.OP_FILE_READ,
                                reason=reason, universe=coverage.UNIVERSE_INCOMPLETE,
                                operation_id=SUDOERS_OPERATION)
        return result.Evidence(status, records=[], reason=reason, source=SURFACE_ROOT,
                               provenance={"scope": "DECLARED_LOCAL_SUDO_POLICY",
                                           "limitation": model.LIMITATION,
                                           "not_collected": list(model.NOT_COLLECTED),
                                           "coverage": [entry]})
    adapter = SudoersIncludes("/", tree=tree)
    read = _FromFrame(tree)
    graph = include_graph.resolve(SURFACE_ROOT, adapter, read=read, expand=read.expand)
    adapter.outside_surface.extend(read.outside)
    return _evidence("/", adapter, graph,
                     lambda path: filemeta.from_lstat(path, read.metadata(path)),
                     operation_id=SUDOERS_OPERATION)


def _evidence(root, adapter, graph, meta, operation_id=None):
    if not graph.records or not graph.records[0]["readable"]:
        return result.Evidence(
            graph.status, records=[], reason=graph.reason,
            source=os.path.join(root, SUDOERS),
            provenance=_provenance(adapter, graph, [], 0, operation_id))

    records, malformed, ordinal, files = [], 0, 0, []
    for node in graph.records:
        files.append(meta(node["path"]))
        if not node["readable"]:
            continue
        parsed, bad = sources.parse(node["text"], node["path"], ordinal)
        records.extend(parsed)
        malformed += bad
        ordinal += len(parsed)

    status, reason = _status(graph, records, malformed, adapter.unlisted_directories,
                             adapter.unfollowed_symlinks, adapter.outside_surface,
                             adapter.non_regular)
    return result.Evidence(status, records=records, reason=reason,
                           source=os.path.join(root, SUDOERS),
                           provenance=_provenance(adapter, graph, files, malformed,
                                                  operation_id))


def _status(graph, records, malformed, unlisted=(), unfollowed=(), outside=(),
            non_regular=()):
    """The include graph, the includedir listings and the parse all constrain completeness."""
    problems = []
    if graph.status != result.COLLECTED:
        problems.append(graph.reason)
    if unlisted:
        problems.append(
            "INCOMPLETE_INCLUDE_GRAPH: %d includedir(s) could not be listed (%s); sudo "
            "policy they may contain was not observed." % (
                len(unlisted), ", ".join(u["path"] for u in unlisted)))
    if unfollowed:
        problems.append(
            "SYMLINK_NOT_FOLLOWED: %d includedir entr%s %s a symlink and %s not "
            "dereferenced (%s); policy behind %s was not observed." % (
                len(unfollowed), "y" if len(unfollowed) == 1 else "ies",
                "is" if len(unfollowed) == 1 else "are",
                "was" if len(unfollowed) == 1 else "were", ", ".join(unfollowed),
                "it" if len(unfollowed) == 1 else "them"))
    if outside:
        problems.append(
            "%s: %d include target(s) lie outside %s's fixed surface (%s) and were not "
            "read; policy they may contain was not observed and is not claimed absent." % (
                OUTSIDE_SURFACE, len(outside), SUDOERS_OPERATION, ", ".join(outside)))
    if non_regular:
        problems.append(
            "NON_REGULAR_ENTRY: %d includedir entr%s not a regular file and %s not read "
            "(%s)." % (len(non_regular), "y is" if len(non_regular) == 1 else "ies are",
                       "was" if len(non_regular) == 1 else "were", ", ".join(non_regular)))
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


def _provenance(adapter, graph, files, malformed, operation_id=None):
    return {
        "scope": "DECLARED_LOCAL_SUDO_POLICY",
        "limitation": model.LIMITATION,
        "not_collected": list(model.NOT_COLLECTED),
        "include_events": graph.anomalies,
        "include_status": graph.status,
        "files": files,
        "coverage": _coverage("sudo", graph, operation_id, adapter.outside_surface)
                    + _listing_coverage("sudo", adapter.unlisted_directories)
                    + _symlink_coverage("sudo", adapter.unfollowed_symlinks, operation_id)
                    + _non_regular_coverage("sudo", adapter.non_regular, operation_id)
                    + _outside_coverage("sudo", adapter.outside_surface, graph),
        "includedir_entries_observed": adapter.observed_entries,
        "includedir_entries_excluded": adapter.excluded_entries,
        "malformed_count": malformed,
    }


def _symlink_coverage(domain, unfollowed, operation_id=None):
    """One entry per includedir symlink observed and not dereferenced (IQ-057, AUTH-029)."""
    return [coverage.source(domain, path, result.NOT_TESTED, coverage.NOT_SUPPORTED,
                            coverage.OP_FILE_METADATA,
                            reason="SYMLINK_NOT_FOLLOWED: %s is a symlink; it was observed "
                                   "and not dereferenced, so the policy behind it was not "
                                   "observed." % path,
                            universe=coverage.UNIVERSE_INCOMPLETE, operation_id=operation_id)
            for path in unfollowed]


def _non_regular_coverage(domain, paths, operation_id=None):
    """One entry per includedir entry that is neither a regular file nor a link."""
    return [coverage.source(domain, path, result.NOT_TESTED, coverage.NOT_SUPPORTED,
                            coverage.OP_FILE_METADATA,
                            reason="NON_REGULAR_ENTRY: %s is not a regular file and was not "
                                   "read." % path,
                            universe=coverage.UNIVERSE_INCOMPLETE, operation_id=operation_id)
            for path in paths]


def _outside_coverage(domain, outside, graph):
    """An includedir outside the surface; an include FILE outside it is a graph node already.

    Not acquired by the supervisor, and not read by the engine either, so it names no
    operation: claiming one would say an acquisition happened that did not."""
    nodes = set(node["path"] for node in graph.records)
    return [coverage.source(domain, path, result.NOT_TESTED, coverage.NOT_SUPPORTED,
                            coverage.OP_DIRECTORY_LIST,
                            reason="%s: %s is outside %s's fixed surface and was not "
                                   "listed." % (OUTSIDE_SURFACE, path, SUDOERS_OPERATION),
                            universe=coverage.UNIVERSE_INCOMPLETE)
            for path in outside if path not in nodes]


def _listing_coverage(domain, unlisted):
    """One entry per includedir that could not be listed (IQ-046 (1))."""
    return [coverage.source(domain, u["path"], result.NOT_TESTED, u["access_outcome"],
                            coverage.OP_DIRECTORY_LIST, reason=u["reason"],
                            universe=coverage.UNIVERSE_INCOMPLETE,
                            operation_id=u.get("operation_id"))
            for u in unlisted]


def _coverage(domain, graph, operation_id=None, outside=()):
    """R1.5-P acquisition context, one entry per file the include graph reached.

    The graph already knew which nodes were refused and which were simply absent; it
    recorded the distinction as an event label and dropped the machine answer. Nothing
    about the declared configuration changes here.
    """
    out = []
    for node in graph.records:
        outcome = node.get("access_outcome") or (
            coverage.READ_OK if node.get("readable") else coverage.NOT_FOUND)
        beyond = node["path"] in outside
        out.append(coverage.source(
            domain, node["path"],
            result.COLLECTED if node.get("readable") else (
                result.NOT_TESTED if outcome == coverage.NOT_FOUND
                else result.ERROR if outcome == coverage.IO_ERROR
                else result.NOT_TESTED),
            outcome, coverage.OP_FILE_READ,
            reason=("%s: %s is outside %s's fixed surface and was not read." % (
                OUTSIDE_SURFACE, node["path"], SUDOERS_OPERATION) if beyond else None),
            universe=(coverage.UNIVERSE_COMPLETE if node.get("readable")
                      else coverage.UNIVERSE_INCOMPLETE),
            # The supervisor acquired every node except one outside its surface, which no
            # one read: that node names no operation.
            operation_id=None if beyond else operation_id))
    return out
