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
# Full Audit (AUTH-030): given the supervisor channel, read_sshd_declared_config_v1 returns
# the fixed surface - /etc/ssh/sshd_config, the listing of /etc/ssh/sshd_config.d and each
# entry - in one AUTH-029 frame. The engine applies sshd's grammar to it: globs over the
# drop-in directory match the frame's listing, a symlinked or non-regular match is recorded
# and not read. An include outside the surface - at any depth of the chain - is expanded and
# read by the engine itself and recorded CURRENT_IDENTITY, or is NOT_TESTED; no discovered
# path is ever sent to the supervisor. This is declared configuration only: sshd never runs.
#
# SHARED_ABSTRACTION_CANDIDATE, consumer_count = 2 (sudo, ssh): the frame-backed reader and
# the tree acquisition. Extracted at the third consumer, as hostpath was.
#
# Full Audit also asks for resolve_sshd_effective_config_v1 (AUTH-031): the supervisor runs
# the fixed /usr/sbin/sshd -T and returns its stdout unparsed. It is the GLOBAL effective
# configuration - Match blocks are applied only with -C, which this operation never has - so
# the connection context is recorded NOT_TESTED and the limitation says so (SCOPE-020). It
# fails closed: only exit 0 with a non-empty stdout of well-formed lines yields settings;
# anything else is ERROR or NOT_TESTED by the SCOPE-022 table and nothing is derived. The
# stdout is kept byte-for-byte in provenance; each setting keeps its position among the
# lines with the same keyword, because the order of a repeated directive is meaning (IQ-064).
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Declared sshd configuration across the include graph, and in Full Audit the global
effective configuration from sshd -T."""
import base64
import hashlib
import os
import re

import fnmatch

from .. import coverage, hostio, hostpath, textbytes
from ..shared import filemeta, include_graph, result
from ..supervisor import frame, protocol
from . import model, sources

SSHD_CONFIG = "etc/ssh/sshd_config"
SSHD_OPERATION = "read_sshd_declared_config_v1"
EFFECTIVE_OPERATION = "resolve_sshd_effective_config_v1"
EFFECTIVE_SOURCE = "sshd -T"
# One `sshd -T` line: a lower-case keyword, then nothing or one space and the value as printed.
_SETTING = re.compile(r"\A([a-z0-9]+)(?: (.*))?\Z", re.S)
STDERR_EXCERPT = 240
SURFACE_ROOT = "/etc/ssh/sshd_config"
SURFACE_DIRECTORY = "/etc/ssh/sshd_config.d"
FRAME_LIMIT = 4194304
FRAME_ITEMS = 2 + 1024
_ACCESS = {frame.READ_OK: coverage.READ_OK, frame.NOT_FOUND: coverage.NOT_FOUND,
           frame.PERMISSION_DENIED: coverage.PERMISSION_DENIED,
           frame.TRUNCATED: coverage.TRUNCATED, frame.IO_ERROR: coverage.IO_ERROR,
           frame.SYMLINK: coverage.NOT_SUPPORTED, frame.NON_REGULAR: coverage.NOT_SUPPORTED}


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


class _Surface(object):
    """Full Audit's read and expansion: the fixed surface from the frame, everything else
    by the engine as itself (AUTH-030). Never a discovered path to the supervisor."""

    def __init__(self, tree):
        self.items = {SURFACE_ROOT: tree["root"]}
        self.names = []
        for entry in tree["entries"]:
            name = os.fsdecode(entry["name"])
            self.names.append(name)
            self.items[os.path.join(SURFACE_DIRECTORY, name)] = entry
        self.listing = tree["listing"]["acquisition_outcome"]
        self.own = set()            # read by the engine itself: CURRENT_IDENTITY
        self.unfollowed, self.non_regular, self.unlisted = [], [], []

    def _inside(self, path):
        return path == SURFACE_ROOT or os.path.dirname(path) == SURFACE_DIRECTORY

    def expand(self, pattern):
        if not self._inside(pattern):
            # Outside the surface the engine expands the pattern itself, as sshd would.
            return include_graph._default_expand(pattern)
        if pattern in self.items:
            return [pattern]
        if os.path.dirname(pattern) != SURFACE_DIRECTORY:
            return []
        if self.listing == frame.NOT_FOUND:
            return []
        if self.listing != frame.READ_OK:
            # IQ-046 (1): a directory the supervisor could not list is never an empty one.
            if pattern not in self.unlisted:
                self.unlisted.append(pattern)
            return []
        name = os.path.basename(pattern)
        return [os.path.join(SURFACE_DIRECTORY, n) for n in self.names
                if fnmatch.fnmatchcase(n, name)]

    def metadata(self, path):
        item = self.items.get(path)
        return None if item is None else item["lstat"]

    def __call__(self, path):
        item = self.items.get(path)
        if item is None:
            if self._inside(path):
                return hostio.Outcome(ok=False, reason="SOURCE_ABSENT", source=path,
                                      detail=coverage.NOT_FOUND)
            self.own.add(path)
            return hostio.read_file_lossless(path)
        outcome = item["acquisition_outcome"]
        if outcome == frame.READ_OK:
            return hostio.Outcome(value=item["content"].decode("utf-8", "surrogateescape"),
                                  source=path, detail=hostio.READ_OK)
        if outcome == frame.SYMLINK and path not in self.unfollowed:
            self.unfollowed.append(path)
        if outcome == frame.NON_REGULAR and path not in self.non_regular:
            self.non_regular.append(path)
        return hostio.Outcome(ok=False, reason="SOURCE_UNREADABLE", source=path,
                              detail=_ACCESS[outcome])


def _acquire_tree(channel):
    """The decoded AUTH-029 frame of the fixed surface, or (None, status, reason)."""
    try:
        res = channel.request(SSHD_OPERATION)
    except (protocol.ProtocolError, OSError) as exc:
        return None, result.ERROR, ("SUPERVISOR_CHANNEL_FAILED: %s could not be requested "
                                    "from the supervisor (%s)." % (SSHD_OPERATION,
                                                                    type(exc).__name__))
    if res["status"] == protocol.REFUSED:
        return None, result.NOT_TESTED, ("SUPERVISOR_REFUSED: %s was refused by the "
                                         "supervisor; no sshd configuration was observed."
                                         % SSHD_OPERATION)
    if res["status"] == protocol.TRUNCATED:
        return None, result.NOT_TESTED, ("SOURCE_TRUNCATED: the sshd configuration surface "
                                         "exceeds %s's bounds and was not observed as "
                                         "complete evidence." % SSHD_OPERATION)
    if res["status"] != protocol.COMPLETED:
        return None, result.ERROR, ("SUPERVISOR_FAILED: %s did not complete (%s)." % (
            SSHD_OPERATION, (res["stderr_bytes"] or b"").decode("ascii", "replace")))
    try:
        tree = frame.check_tree(frame.decode(res["bytes"], FRAME_LIMIT, FRAME_ITEMS),
                                SURFACE_ROOT.encode("ascii"),
                                SURFACE_DIRECTORY.encode("ascii"))
    except frame.FrameError as exc:
        return None, result.ERROR, ("SUPERVISOR_FRAME_INVALID: %s returned a frame that is "
                                    "not what AUTH-029 allows (%s)." % (SSHD_OPERATION, exc))
    return tree, None, None


def collect(root="/", channel=None):
    """Declared sshd configuration. `channel` is the Full Audit supervisor channel, given
    only by the reduced engine (AUTH-030); with it, the supervisor also runs the fixed
    sshd -T for the global effective configuration (AUTH-031). The standard route never
    runs sshd."""
    if channel is not None:
        return _with_effective(_collect_supervised(channel), _resolve_effective(channel))
    adapter = SshdIncludes(root)
    graph = include_graph.resolve(os.path.join(root, SSHD_CONFIG), adapter)
    return _evidence(root, graph, lambda path: filemeta.observe(path).records[0])


def _collect_supervised(channel):
    tree, status, reason = _acquire_tree(channel)
    if tree is None:
        entry = coverage.source("ssh", SURFACE_ROOT, status,
                                coverage.IO_ERROR if status == result.ERROR
                                else coverage.NOT_SUPPORTED, coverage.OP_FILE_READ,
                                reason=reason, universe=coverage.UNIVERSE_INCOMPLETE,
                                operation_id=SSHD_OPERATION)
        return result.Evidence(status, records=[], reason=reason, source=SURFACE_ROOT,
                               provenance={"scope": "DECLARED_SSHD_CONFIGURATION",
                                           "dimension": model.DECLARED,
                                           "limitation": model.LIMITATION,
                                           "not_collected": list(model.NOT_COLLECTED),
                                           "coverage": [entry]})
    surface = _Surface(tree)
    graph = include_graph.resolve(SURFACE_ROOT, SshdIncludes("/"), read=surface,
                                  expand=surface.expand)

    def meta(path):
        if path in surface.own:
            return filemeta.observe(path).records[0]
        return filemeta.from_lstat(path, surface.metadata(path))
    return _evidence("/", graph, meta, surface)


def _evidence(root, graph, meta, surface=None):
    if not graph.records or not graph.records[0]["readable"]:
        return result.Evidence(
            graph.status, records=[], reason=graph.reason,
            source=os.path.join(root, SSHD_CONFIG),
            provenance=_provenance(graph, [], 0, surface))

    records, malformed, ordinal, match_index, files = [], 0, 0, 0, []
    # The scope active at each line of each file, so an included file can be parsed under
    # the scope of the Include directive that pulled it in. S2 yields parents before
    # children in expansion order, so a parent's map always exists when its child is
    # reached. Restoration needs no bookkeeping: a child's scope changes live entirely
    # inside the child's own parse and never travel back to the parent.
    scope_maps = {}
    for node in graph.records:
        files.append(meta(node["path"]))
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

    status, reason = _status(graph, records, malformed, surface)
    return result.Evidence(status, records=records, reason=reason,
                           source=os.path.join(root, SSHD_CONFIG),
                           provenance=_provenance(graph, files, malformed, surface))


def _status(graph, records, malformed, surface=None):
    problems = []
    if graph.status != result.COLLECTED:
        problems.append(graph.reason)
    if surface is not None:
        if surface.unlisted:
            problems.append(
                "INCOMPLETE_INCLUDE_GRAPH: %s could not be listed, so the drop-ins %s "
                "names were not observed (%s)." % (SURFACE_DIRECTORY, ", ".join(
                    surface.unlisted), surface.listing))
        if surface.unfollowed:
            problems.append(
                "SYMLINK_NOT_FOLLOWED: %s %s a symlink in the privileged surface and %s "
                "not dereferenced; policy behind it was not observed." % (
                    ", ".join(surface.unfollowed),
                    "is" if len(surface.unfollowed) == 1 else "are",
                    "was" if len(surface.unfollowed) == 1 else "were"))
        if surface.non_regular:
            problems.append(
                "NON_REGULAR_ENTRY: %s %s not a regular file and %s not read." % (
                    ", ".join(surface.non_regular),
                    "is" if len(surface.non_regular) == 1 else "are",
                    "was" if len(surface.non_regular) == 1 else "were"))
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


def _provenance(graph, files, malformed, surface=None):
    return {"scope": "DECLARED_SSHD_CONFIGURATION",
            "dimension": model.DECLARED,
            "limitation": model.LIMITATION,
            "not_collected": list(model.NOT_COLLECTED),
            "duplicate_policy": model.DUPLICATE_POLICY,
            "include_events": graph.anomalies,
            "include_status": graph.status,
            "files": files,
            "coverage": _coverage("ssh", graph, surface)
                        + _unlisted_coverage("ssh", surface),
            "malformed_count": malformed}


def _unlisted_coverage(domain, surface):
    if surface is None or not surface.unlisted:
        return []
    return [coverage.source(domain, SURFACE_DIRECTORY, result.NOT_TESTED,
                            _ACCESS.get(surface.listing, coverage.IO_ERROR),
                            coverage.OP_DIRECTORY_LIST,
                            reason="SOURCE_UNREADABLE: %s could not be listed (%s); the "
                                   "drop-ins it holds were not observed." % (
                                       SURFACE_DIRECTORY, surface.listing),
                            universe=coverage.UNIVERSE_INCOMPLETE,
                            operation_id=SSHD_OPERATION)]


def _coverage(domain, graph, surface=None):
    """R1.5-P acquisition context, one entry per file the include graph reached.

    The graph already knew which nodes were refused and which were simply absent; it
    recorded the distinction as an event label and dropped the machine answer. Nothing
    about the declared configuration changes here.
    """
    out = []
    for node in graph.records:
        outcome = node.get("access_outcome") or (
            coverage.READ_OK if node.get("readable") else coverage.NOT_FOUND)
        # AUTH-030: a node of the fixed surface names the operation that acquired it; a node
        # the engine read as itself names none and is CURRENT_IDENTITY.
        supervised = surface is not None and node["path"] not in surface.own
        reason = None
        if surface is not None and node["path"] in surface.unfollowed:
            reason = ("SYMLINK_NOT_FOLLOWED: %s is a symlink in the privileged surface; it "
                      "was observed and not dereferenced." % node["path"])
        elif surface is not None and node["path"] in surface.non_regular:
            reason = "NON_REGULAR_ENTRY: %s is not a regular file and was not read." % (
                node["path"])
        out.append(coverage.source(
            domain, node["path"],
            result.COLLECTED if node.get("readable") else (
                result.NOT_TESTED if outcome in (coverage.NOT_FOUND, coverage.NOT_SUPPORTED)
                else result.ERROR if outcome == coverage.IO_ERROR
                else result.NOT_TESTED),
            outcome, coverage.OP_FILE_READ, reason=reason,
            universe=(coverage.UNIVERSE_COMPLETE if node.get("readable")
                      else coverage.UNIVERSE_INCOMPLETE),
            operation_id=SSHD_OPERATION if supervised else None))
    return out


# --- resolve_sshd_effective_config_v1 (AUTH-031) ----------------------------------------------

def _excerpt(data):
    """A bounded, printable rendering of supervisor or sshd stderr (SCOPE-022)."""
    text = (data or b"").decode("ascii", "replace")
    text = "".join(c if " " <= c <= "~" else " " for c in text)
    text = " ".join(text.split())
    return text[:STDERR_EXCERPT] + ("..." if len(text) > STDERR_EXCERPT else "")


def _parse_effective(data):
    """(records, None) for well-formed output, or ([], line_number) at the first bad line."""
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    records, seen = [], {}
    for ordinal, raw in enumerate(lines):
        match = _SETTING.match(raw.decode("utf-8", "surrogateescape"))
        if match is None:
            return [], ordinal + 1
        keyword = match.group(1)
        records.append({"kind": model.RESOLVED_SETTING, "keyword": keyword,
                        "value": match.group(2) if match.group(2) is not None else "",
                        "occurrence": seen.get(keyword, 0), "ordinal": ordinal})
        seen[keyword] = seen.get(keyword, 0) + 1
    return records, None


def _failure_of(res):
    """(status, access_outcome, reason) for a FAILED result, by the SCOPE-022 table."""
    token = res["stderr_bytes"] or b""
    exit_code = res["status_metadata"]["exit_code"]
    if exit_code is not None:
        return result.ERROR, coverage.IO_ERROR, (
            "TOOL_FAILED: sshd -T exited with status %d (stderr: %s); nothing of its output "
            "is used." % (exit_code, _excerpt(token) or "empty"))
    if token == b"ENOENT":
        return result.NOT_TESTED, coverage.NOT_FOUND, (
            "TOOL_ABSENT: /usr/sbin/sshd is not present; no effective configuration was "
            "observed.")
    if token in (b"NOT_REGULAR", b"UNTRUSTED_EXECUTABLE"):
        return result.NOT_TESTED, coverage.NOT_SUPPORTED, (
            "UNTRUSTED_EXECUTABLE: the supervisor did not run /usr/sbin/sshd (%s); no "
            "effective configuration was observed." % token.decode("ascii"))
    if token == b"TIMEOUT":
        return result.ERROR, coverage.IO_ERROR, (
            "TOOL_FAILED: sshd -T did not finish within the operation's timeout (TIMEOUT); "
            "nothing of its output is used.")
    return result.ERROR, coverage.IO_ERROR, (
        "TOOL_FAILED: sshd -T could not be run (%s); nothing of its output is used."
        % (_excerpt(token) or "no detail"))


def _resolve_effective(channel):
    """The resolved dimension: records, status, reason, coverage entry and provenance."""
    block = {"operation_id": EFFECTIVE_OPERATION, "scope": model.RESOLVED_SCOPE,
             "dimension": model.RESOLVED, "exit_code": None, "raw_stdout": None,
             "stderr_excerpt": None,
             "connection_context": {"status": result.NOT_TESTED,
                                    "reason": model.CONNECTION_CONTEXT_REASON}}
    records = []
    try:
        res = channel.request(EFFECTIVE_OPERATION)
    except (protocol.ProtocolError, OSError) as exc:
        status, outcome, reason = result.ERROR, coverage.IO_ERROR, (
            "SUPERVISOR_CHANNEL_FAILED: %s could not be requested from the supervisor (%s)."
            % (EFFECTIVE_OPERATION, type(exc).__name__))
    else:
        block["exit_code"] = res["status_metadata"]["exit_code"]
        if res["status"] == protocol.REFUSED:
            status, outcome, reason = result.NOT_TESTED, coverage.NOT_SUPPORTED, (
                "SUPERVISOR_REFUSED: %s was refused by the supervisor (%s); no effective "
                "configuration was observed." % (EFFECTIVE_OPERATION,
                                                 _excerpt(res["stderr_bytes"]) or "no detail"))
        elif res["status"] == protocol.TRUNCATED:
            status, outcome, reason = result.ERROR, coverage.TRUNCATED, (
                "OUTPUT_TRUNCATED: sshd -T printed more than the operation's bound; nothing of "
                "its output is used.")
        elif res["status"] != protocol.COMPLETED:
            status, outcome, reason = _failure_of(res)
        else:
            data = res["bytes"]
            block["raw_stdout"] = {"base64": base64.b64encode(data).decode("ascii"),
                                   "sha256": hashlib.sha256(data).hexdigest(),
                                   "byte_count": len(data)}
            block["stderr_excerpt"] = _excerpt(res["stderr_bytes"]) or None
            records, bad_line = _parse_effective(data)
            if not data:
                status, outcome, reason = result.ERROR, coverage.READ_OK, (
                    "EMPTY_OUTPUT: sshd -T exited 0 and printed nothing; no effective "
                    "configuration is claimed.")
            elif bad_line is not None:
                status, outcome, reason = result.ERROR, coverage.READ_OK, (
                    "UNPARSEABLE: line %d of the sshd -T output is not a lower-case keyword "
                    "with a value; no setting is derived from the output." % bad_line)
            else:
                status, outcome, reason = result.COLLECTED, coverage.READ_OK, None
    if status != result.COLLECTED:
        records = []
    block["status"], block["reason"] = status, reason
    entry = coverage.source("ssh", EFFECTIVE_SOURCE, status, outcome, coverage.OP_COMMAND,
                            reason=reason,
                            universe=(coverage.UNIVERSE_COMPLETE if status == result.COLLECTED
                                      else coverage.UNIVERSE_INCOMPLETE),
                            operation_id=EFFECTIVE_OPERATION)
    return records, status, reason, entry, block


def _with_effective(declared, effective):
    """One ssh section with both dimensions; its status derives from both (AUTH-016)."""
    records, status, reason, entry, block = effective
    statuses = (declared.status, status)
    if all(s == result.COLLECTED for s in statuses):
        combined = result.COLLECTED
    elif any(s in (result.COLLECTED, result.PARTIAL) for s in statuses):
        combined = result.PARTIAL
    else:
        combined = result.ERROR if result.ERROR in statuses else result.NOT_TESTED
    reasons = []
    if declared.status != result.COLLECTED and declared.reason:
        reasons.append("declared: %s" % declared.reason)
    if status != result.COLLECTED:
        reasons.append("resolved: %s" % reason)
    provenance = dict(declared.provenance)
    # The declared dimension's own outcome, computed above from the declared evidence; it
    # travels in the section, which the manifest binds, and never in host state.
    provenance["declared"] = {"status": declared.status, "reason": declared.reason}
    provenance.update({"scope": model.SUPERVISED_SCOPE,
                       "dimension": model.SUPERVISED_DIMENSION,
                       "limitation": model.SUPERVISED_LIMITATION,
                       "not_collected": list(model.SUPERVISED_NOT_COLLECTED),
                       "resolved": block,
                       "coverage": list(provenance.get("coverage") or []) + [entry]})
    return result.Evidence(combined, records=list(declared.records) + records,
                           reason=" ".join(reasons) or None, source=declared.source,
                           provenance=provenance)
