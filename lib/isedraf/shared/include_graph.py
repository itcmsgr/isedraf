# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Resolve a configuration include graph without deciding what an include means.
# Implements: SCOPE-022, SCOPE-045, GOV-001
#
# sshd_config has `Include`, sudoers has `#include` and `#includedir`, PAM has `include`
# and `substack`, and a dozen `*.d` families have their own ordering rules. The syntaxes
# are not interchangeable. The SHAPE is: a directive in one file pulls in more files, with
# an order, a globbing rule, a depth limit and a cycle risk.
#
# So this is an engine plus a per-domain ADAPTER, not one parser pretending every include
# means the same thing. The engine owns traversal, ordering, cycles, limits and
# provenance. The adapter owns "is this line a directive, and which targets does it name".
#
# The failure modes are why this is shared rather than written five times. A missed include
# is a missed rule: an sshd_config whose `Include /etc/ssh/sshd_config.d/*.conf` was not
# followed reports PermitRootLogin as whatever the main file said, confidently and wrongly.
# Every one of those failures is recorded here and affects completeness, so no consumer can
# inherit a silently truncated view of its own configuration.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""A generic include-graph resolver driven by a domain adapter."""
import os

from .. import hostio as _exec
from . import result

# --- node source kinds -------------------------------------------------------------------
ROOT = "ROOT"
INCLUDED = "INCLUDED"

# --- what the engine OBSERVED, with no opinion about what it means -----------------------
# The engine discovers and records. It does not decide that any of these means the
# evidence is incomplete, because that answer is domain-specific and the engine has no
# domain. A wildcard matching zero files is a perfectly ordinary state for an empty
# `conf.d`; a literal include naming a file that is not there is usually a broken
# configuration; and which of those a given format considers normal is the format's
# business, not this module's.
NO_MATCH = "NO_MATCH"                       # a glob expanded to nothing
MISSING_TARGET = "MISSING_TARGET"           # a literal path that does not exist
UNREADABLE_TARGET = "UNREADABLE_TARGET"     # exists, could not be read
UNSUPPORTED_DIRECTIVE = "UNSUPPORTED_DIRECTIVE"
DUPLICATE_INCLUDE = "DUPLICATE_INCLUDE"     # same file reached through two parents
CYCLE = "CYCLE"
DEPTH_LIMIT = "DEPTH_LIMIT"
NODE_LIMIT = "NODE_LIMIT"

EVENTS = (NO_MATCH, MISSING_TARGET, UNREADABLE_TARGET, UNSUPPORTED_DIRECTIVE,
          DUPLICATE_INCLUDE, CYCLE, DEPTH_LIMIT, NODE_LIMIT)

DEFAULT_MAX_DEPTH = 16
DEFAULT_MAX_NODES = 256


class Adapter(object):
    """What one domain's include syntax looks like.

    `directives(text, path)` yields (line_number, directive_text, targets, supported).
    `targets` are strings exactly as written; the engine resolves them against the parent
    directory and expands globs. `supported=False` marks a directive the adapter
    recognized as an include form it cannot handle, which is recorded rather than dropped.

    Sorting is the adapter's call, not the engine's: sshd sorts glob matches lexically,
    sudoers `#includedir` has its own rule about which filenames are eligible. The engine
    preserves whatever order the adapter returns.
    """

    name = "adapter"

    def directives(self, text, path):
        raise NotImplementedError

    def sort_expansion(self, paths):
        """Order for one directive's glob expansion. Default: as the filesystem gave it,
        then sorted, because readdir order is not deterministic and an unstable graph
        would produce an unstable digest."""
        return sorted(paths)

    #: Whether each observed event means this domain's evidence is incomplete.
    #:
    #: These are DEFAULTS, not truths, and they live on the adapter rather than in the
    #: engine so that a domain can disagree without the engine knowing any domain exists.
    #: An earlier version of this module forced PARTIAL for every event, which quietly
    #: encoded one format's opinion - that a wildcard matching nothing is a problem - into
    #: a primitive five formats were going to share.
    #:
    #: NO_MATCH and DUPLICATE_INCLUDE default to harmless: an empty drop-in directory is
    #: an ordinary configuration, and a file included twice is a structural fact whose
    #: meaning depends on whether the format applies declarations once or twice. The rest
    #: default to completeness-affecting, because stopping early or failing to read a
    #: named file means there is configuration we did not see.
    COMPLETENESS = {
        NO_MATCH: False,
        DUPLICATE_INCLUDE: False,
        MISSING_TARGET: True,
        UNREADABLE_TARGET: True,
        UNSUPPORTED_DIRECTIVE: True,
        CYCLE: True,
        DEPTH_LIMIT: True,
        NODE_LIMIT: True,
    }

    def affects_completeness(self, event):
        """Does this observed event mean the domain's evidence is incomplete?

        Override per domain. The engine calls this and never second-guesses the answer.
        """
        return self.COMPLETENESS.get(event["event"], True)


def resolve(root_path, adapter, read=None, max_depth=DEFAULT_MAX_DEPTH,
            max_nodes=DEFAULT_MAX_NODES, expand=None):
    """Walk the include graph from `root_path`.

    Returns Evidence whose records are nodes in EXPANSION ORDER - the order a
    configuration parser would encounter them, which for most of these formats is the
    order that decides which declaration wins. Nothing is sorted afterwards.
    """
    read = read or _exec.read_file_lossless
    expand = expand or _default_expand

    nodes, anomalies = [], []
    # `visiting` is the current path down the graph, for cycle detection. `seen` is every
    # node already emitted, for duplicate detection. They answer different questions: a
    # diamond where two parents include the same file is a duplicate and legal; a file
    # that includes itself through any path is a cycle and is not.
    state = {"count": 0, "truncated": False}

    def walk(path, depth, parent, directive, visiting):
        if state["count"] >= max_nodes:
            state["truncated"] = True
            anomalies.append(result.anomaly(
                result.ANOMALY_LIMIT,
                "include graph exceeded %d nodes; traversal stopped" % max_nodes,
                source_path=path, parent=parent, event=NODE_LIMIT))
            return
        if depth > max_depth:
            anomalies.append(result.anomaly(
                result.ANOMALY_UNSUPPORTED,
                "include depth exceeded %d" % max_depth,
                source_path=path, parent=parent, event=DEPTH_LIMIT))
            return
        real = _identity(path)
        if real in visiting:
            # Terminate, keep what was already collected, and say so. Recursion is bounded
            # by this check plus max_depth, so a hostile or accidental loop cannot exhaust
            # the stack.
            anomalies.append(result.anomaly(
                result.ANOMALY_CYCLE,
                "include cycle: %s is already being expanded" % path,
                source_path=path, parent=parent, event=CYCLE))
            return

        outcome = read(path)
        ordinal = state["count"]
        state["count"] += 1
        node = {"path": path, "source_kind": ROOT if parent is None else INCLUDED,
                "parent": parent, "directive": directive, "ordinal": ordinal,
                "depth": depth, "text": None, "readable": bool(outcome.ok),
                # R1.5-P: the reason a node is unreadable is a fact about the collection
                # identity, not decoration. MISSING_TARGET vs UNREADABLE_TARGET already
                # split absent from refused for the EVENT; this keeps the machine answer
                # on the node, where a domain building coverage can reach it.
                "access_outcome": outcome.detail}
        if not outcome.ok:
            kind = (MISSING_TARGET if outcome.detail == _exec.NOT_FOUND
                    else UNREADABLE_TARGET)
            node["event"] = kind
            anomalies.append(result.anomaly(
                result.ANOMALY_MISSING if kind == MISSING_TARGET
                else result.ANOMALY_UNREADABLE,
                "%s: %s" % (path, outcome.reason),
                source_path=path, parent=parent, event=kind))
            nodes.append(node)
            return
        node["text"] = outcome.value
        nodes.append(node)

        for line_no, directive_text, targets, supported in adapter.directives(
                outcome.value, path):
            if not supported:
                anomalies.append(result.anomaly(
                    result.ANOMALY_UNSUPPORTED,
                    "unsupported include form: %s" % directive_text,
                    source_path=path, source_line=line_no,
                    event=UNSUPPORTED_DIRECTIVE))
                continue
            for target in targets:
                resolved = target if os.path.isabs(target) else os.path.join(
                    os.path.dirname(path), target)
                matches = expand(resolved)
                if not matches:
                    # A glob that matched nothing and a literal path that is absent are
                    # DIFFERENT observations, and conflating them was the defect: an empty
                    # drop-in directory is ordinary, a named file that vanished is not.
                    # Both are recorded; neither is judged here.
                    glob = _has_glob(resolved)
                    anomalies.append(result.anomaly(
                        result.ANOMALY_MISSING,
                        ("include pattern matched nothing: %s" if glob
                         else "include target does not exist: %s") % target,
                        source_path=path, source_line=line_no,
                        event=NO_MATCH if glob else MISSING_TARGET))
                    continue
                for expansion_ordinal, match in enumerate(
                        adapter.sort_expansion(matches)):
                    walk(match, depth + 1, path,
                         {"text": directive_text, "line": line_no,
                          "expansion_ordinal": expansion_ordinal},
                         visiting | {real})

    walk(root_path, 0, None, None, frozenset())

    # Duplicate inclusion: the same file reached through two different parents. Legal, and
    # worth reporting, because in most of these formats it means the declarations are
    # applied twice.
    first_seen = {}
    for node in nodes:
        ident = _identity(node["path"])
        if ident in first_seen:
            node["duplicate_of"] = first_seen[ident]
            anomalies.append(result.anomaly(
                result.ANOMALY_DUPLICATE,
                "%s is included more than once" % node["path"],
                source_path=node["path"], parent=node["parent"],
                first_ordinal=first_seen[ident], event=DUPLICATE_INCLUDE))
        else:
            first_seen[ident] = node["ordinal"]

    status, reason = _status(nodes, anomalies, adapter)
    return result.Evidence(
        status, records=nodes, reason=reason, source=root_path, anomalies=anomalies,
        provenance={"adapter": adapter.name, "max_depth": max_depth,
                    "max_nodes": max_nodes, "node_count": len(nodes),
                    "truncated": state["truncated"]})


def _status(nodes, anomalies, adapter):
    """SCOPE-022, applied to a graph rather than a file.

    The root is the engine's call: a root that does not exist is not an incomplete graph,
    it is the absence of the source, and that is NOT_TESTED in every format.

    Everything else is the ADAPTER's call. The engine asks whether each recorded event
    affects this domain's completeness and counts the answers; it does not hold an opinion
    of its own.
    """
    if not nodes:
        return result.NOT_TESTED, "SOURCE_ABSENT: the include root produced no nodes."
    root = nodes[0]
    if not root["readable"]:
        if root.get("event") == MISSING_TARGET:
            return result.NOT_TESTED, ("SOURCE_ABSENT: %s does not exist."
                                       % root["path"])
        return result.NOT_TESTED, ("SOURCE_UNREADABLE: %s could not be read."
                                   % root["path"])
    blocking = [a for a in anomalies
                if a.get("event") and adapter.affects_completeness(a)]
    if blocking:
        kinds = sorted(set(a["event"] for a in blocking))
        return result.PARTIAL, (
            "INCOMPLETE_INCLUDE_GRAPH: %d include target(s) did not resolve (%s). The "
            "configuration read here is not the whole configuration."
            % (len(blocking), ", ".join(kinds)))
    return result.COLLECTED, None


def _identity(path):
    """Identity for cycle and duplicate detection, WITHOUT following symlinks.

    os.path.realpath() would resolve symlinks and could therefore consult a target outside
    a fixture root. normpath is lexical: it collapses `a/../b` without touching the
    filesystem, which keeps a fixture hermetic.
    """
    return os.path.normpath(path)


def _default_expand(pattern):
    """Expand one include target to concrete paths.

    Globbing is lexical plus one directory listing; no symlink is followed to decide
    membership. A plain path that exists returns itself, and a plain path that does not
    returns nothing, so the caller can tell "matched nothing" from "is a file".
    """
    if not _has_glob(pattern):
        return [pattern] if os.path.lexists(pattern) else []
    directory, name = os.path.split(pattern)
    try:
        entries = os.listdir(directory or ".")
    except OSError:
        return []
    import fnmatch
    return [os.path.join(directory, e) for e in entries if fnmatch.fnmatch(e, name)]


def _has_glob(pattern):
    return any(ch in pattern for ch in "*?[")
