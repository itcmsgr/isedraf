# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Resolve the sshd_config include graph and collect declared configuration.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, GOV-001
#
# S2 for the include graph, S4 for file metadata. The domain owns the grammar and the
# scope, because neither is a shared concept.
#
# SHARED_ABSTRACTION_CANDIDATE RESOLVED - consumer_count = 3, extracted to isedraf.hostpath:
#
#   an absolute include path + a collection root that is not "/"
#       -> lexically map the path beneath the root
#   root "/" -> identity
#   never realpath, never a live-host fallback
#
# PAM was not the third consumer: `include password-auth` names a SERVICE resolved inside
# an already-rooted directory, which is a different operation that happens to look alike.
# authorized_keys is, because an account home is a host-absolute path and a declared
# AuthorizedKeysFile is either absolute or relative to that home.
#
# What stays here is the GRAMMAR - whether an Include target is absolute at all, and how
# a relative one is anchored. sshd anchors it to the including file's directory; a future
# consumer anchors it somewhere else. The anchor is domain knowledge; the mapping is not.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Declared sshd configuration across the include graph."""
import os

from .. import coverage, hostpath, textbytes
from ..shared import filemeta, include_graph, result
from . import model, sources

SSHD_CONFIG = "etc/ssh/sshd_config"


class SshdIncludes(include_graph.Adapter):
    """`Include` directives, with sshd's ordering and an empty drop-in tolerated."""

    name = "sshd_config"

    #: An empty sshd_config.d is the default state of most hosts. A glob matching nothing
    #: must not make the evidence incomplete, or nearly every host reports PARTIAL and
    #: the status stops meaning anything. A named file that is absent is different.
    COMPLETENESS = dict(include_graph.Adapter.COMPLETENESS)
    COMPLETENESS[include_graph.NO_MATCH] = False
    COMPLETENESS[include_graph.DUPLICATE_INCLUDE] = False

    def __init__(self, root):
        self.root = root

    def _rebase(self, target, parent):
        """Resolve inside the collection root. See the module header: consumer #2."""
        if os.path.isabs(target):
            return hostpath.under(self.root, target)
        return hostpath.beneath(
            self.root, os.path.join(os.path.dirname(parent), target))

    def directives(self, text, path):
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if parts[0].lower() != "include":
                continue
            if len(parts) < 2 or not parts[1].strip():
                yield number, line, [], False
                continue
            # One Include may name several whitespace-separated patterns.
            targets = [self._rebase(t, path) for t in parts[1].split()]
            yield number, line, targets, True

    def sort_expansion(self, paths):
        return sorted(paths,
                      key=lambda p: textbytes.original_bytes(os.path.basename(p)))


def collect(root="/"):
    adapter = SshdIncludes(root)
    graph = include_graph.resolve(os.path.join(root, SSHD_CONFIG), adapter)

    if not graph.records or not graph.records[0]["readable"]:
        return result.Evidence(
            graph.status, records=[], reason=graph.reason,
            source=os.path.join(root, SSHD_CONFIG),
            provenance=_provenance(graph, [], 0))

    records, malformed, ordinal, match_index, files = [], 0, 0, 0, []
    # The scope active at each line of each file, so an included file can be parsed under
    # the scope of the Include directive that pulled it in. S2 yields parents before
    # children in expansion order, so a parent's map always exists when its child is
    # reached. Restoration needs no bookkeeping: a child's scope changes live entirely
    # inside the child's own parse and never travel back to the parent.
    scope_maps = {}
    for node in graph.records:
        files.append(filemeta.observe(node["path"]).records[0])
        if not node["readable"]:
            continue
        entry = sources.GLOBAL_SCOPE
        if node["parent"] is not None and node.get("directive"):
            parent_map = scope_maps.get(node["parent"], {})
            entry = parent_map.get(node["directive"]["line"], sources.GLOBAL_SCOPE)
        parsed, bad, match_index, scope_at_line = sources.parse(
            node["text"], node["path"], ordinal, match_index, entry)
        scope_maps[node["path"]] = scope_at_line
        records.extend(parsed)
        malformed += bad
        ordinal += len(parsed)

    status, reason = _status(graph, records, malformed)
    return result.Evidence(status, records=records, reason=reason,
                           source=os.path.join(root, SSHD_CONFIG),
                           provenance=_provenance(graph, files, malformed))


def _status(graph, records, malformed):
    problems = []
    if graph.status != result.COLLECTED:
        problems.append(graph.reason)
    if malformed:
        if records and malformed == len(records):
            return result.ERROR, (
                "UNPARSEABLE: no line in the sshd configuration could be read as a "
                "directive; no trustworthy normalized interpretation can be produced.")
        problems.append(
            "MALFORMED_RECORDS: %d of %d configuration lines could not be read as "
            "directives and are retained as UNSUPPORTED records."
            % (malformed, len(records)))
    if problems:
        return result.PARTIAL, " ".join(problems)
    return result.COLLECTED, None


def _provenance(graph, files, malformed):
    return {"scope": "DECLARED_SSHD_CONFIGURATION",
            "dimension": model.DECLARED,
            "limitation": model.LIMITATION,
            "not_collected": list(model.NOT_COLLECTED),
            "duplicate_policy": model.DUPLICATE_POLICY,
            "include_events": graph.anomalies,
            "include_status": graph.status,
            "files": files,
            "coverage": _coverage("ssh", graph),
            "malformed_count": malformed}


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
