# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Enumerate a bounded, explicitly requested set of paths. Never crawl a host.
# Implements: SCOPE-022, SCOPE-045, GOV-001
#
# FROZEN INVARIANT:
#
#   Completeness means complete over the explicitly requested enumeration universe,
#   not complete over the filesystem.
#
# That distinction is the whole design. A caller asking for `*.conf` at depth 1 under
# /etc/ssh/sshd_config.d has asked a precise question, and the honest answer is COLLECTED
# even though the filesystem contains millions of other paths. Reporting PARTIAL because
# deeper directories exist would make every bounded question permanently incomplete, and
# an operator who sees PARTIAL on every run stops reading the word.
#
# So the engine records events and the CALLER decides which ones invalidate its universe -
# the same separation S2 needed after an earlier version forced PARTIAL for every include
# event. The two cases that must never be conflated:
#
#   requested boundary obeyed     depth 1 was asked for; depth 2 exists   -> complete
#   safety limit reached          the cap fired; entries were not seen    -> incomplete
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Bounded, deterministic, non-following directory enumeration."""
import errno
import fnmatch
import os
import stat

from .. import textbytes
from . import result

# --- what the engine observed, with no opinion -------------------------------------------
ROOT_MISSING = "ROOT_MISSING"
ROOT_UNREADABLE = "ROOT_UNREADABLE"
ENTRY_UNREADABLE = "ENTRY_UNREADABLE"
ENTRY_DISAPPEARED = "ENTRY_DISAPPEARED"
IO_ERROR = "IO_ERROR"
LIMIT_REACHED = "LIMIT_REACHED"             # safety cap: entries were NOT seen
DEPTH_BOUNDARY = "DEPTH_BOUNDARY"           # requested boundary: obeyed as asked
FILESYSTEM_BOUNDARY = "FILESYSTEM_BOUNDARY"
SYMLINK_SKIPPED = "SYMLINK_SKIPPED"

EVENTS = (ROOT_MISSING, ROOT_UNREADABLE, ENTRY_UNREADABLE, ENTRY_DISAPPEARED, IO_ERROR,
          LIMIT_REACHED, DEPTH_BOUNDARY, FILESYSTEM_BOUNDARY, SYMLINK_SKIPPED)


class Universe(object):
    """The enumeration the caller is asking for, and what would invalidate it."""

    name = "universe"

    #: How deep to descend. 0 means the root's own entries only. This is a statement
    #: about the QUESTION, not a safety device.
    max_depth = 1

    #: A hard cap on entries examined. This IS a safety device: reaching it means the
    #: answer is short because we stopped, not because the filesystem was.
    max_entries = 10000

    #: fnmatch pattern applied to the entry NAME. None means every name.
    pattern = None

    include_files = True
    include_directories = False

    #: Off by default and deliberately hard to turn on. A symlink in a config directory
    #: pointing at / would otherwise turn a bounded question into a filesystem crawl.
    follow_symlinks = False

    #: Off by default. Crossing into another filesystem is usually not what a question
    #: about /etc meant.
    cross_filesystems = False

    #: Defaults, not truths, and they live here rather than in the engine.
    #:
    #: DEPTH_BOUNDARY and FILESYSTEM_BOUNDARY are the caller's own instructions being
    #: obeyed, so they do not make the answer incomplete. SYMLINK_SKIPPED likewise.
    #: LIMIT_REACHED does, because the cap firing means eligible entries exist that were
    #: never examined. A read failure does, because something inside the universe could
    #: not be seen.
    COMPLETENESS = {
        DEPTH_BOUNDARY: False,
        FILESYSTEM_BOUNDARY: False,
        SYMLINK_SKIPPED: False,
        LIMIT_REACHED: True,
        ENTRY_UNREADABLE: True,
        ENTRY_DISAPPEARED: True,
        IO_ERROR: True,
    }

    def affects_completeness(self, event):
        return self.COMPLETENESS.get(event["event"], True)

    def eligible(self, name, entry_type):
        if self.pattern is not None and not fnmatch.fnmatch(name, self.pattern):
            return False
        if entry_type == "DIRECTORY":
            return self.include_directories
        return self.include_files


def enumerate_paths(root, universe=None):
    """Enumerate `root` under `universe`. Returns Evidence; records are entries.

    Ordering is by the raw filename BYTES, so it is identical on every host regardless of
    locale, and two names that differ only in undecodable bytes never collide.
    """
    universe = universe or Universe()
    entries, anomalies = [], []
    state = {"examined": 0, "capped": False}

    try:
        root_info = os.lstat(root)
    except OSError as exc:
        event = ROOT_MISSING if exc.errno == errno.ENOENT else ROOT_UNREADABLE
        reason = ("SOURCE_ABSENT: %s does not exist." % root
                  if event == ROOT_MISSING
                  else "SOURCE_UNREADABLE: %s could not be listed." % root)
        return result.Evidence(
            result.NOT_TESTED, records=[], reason=reason, source=root,
            anomalies=[result.anomaly(result.ANOMALY_MISSING, reason,
                                      source_path=root, event=event)],
            provenance=_provenance(universe, state))

    root_device = root_info.st_dev

    def descend(directory, depth):
        if state["capped"]:
            return
        try:
            names = os.listdir(directory)
        except OSError as exc:
            kind = (ENTRY_UNREADABLE
                    if exc.errno in (errno.EACCES, errno.EPERM) else IO_ERROR)
            anomalies.append(result.anomaly(
                result.ANOMALY_UNREADABLE,
                "%s could not be listed: %s" % (
                    directory, errno.errorcode.get(exc.errno, exc.errno)),
                source_path=directory, event=kind))
            return

        for name in _ordered(names):
            if state["examined"] >= universe.max_entries:
                # The cap fired. Eligible entries exist that were never examined, and
                # saying so is the difference between a short answer and a wrong one.
                if not state["capped"]:
                    state["capped"] = True
                    anomalies.append(result.anomaly(
                        result.ANOMALY_LIMIT,
                        "enumeration stopped at the %d-entry safety cap; eligible "
                        "entries were not examined" % universe.max_entries,
                        source_path=directory, event=LIMIT_REACHED))
                return
            state["examined"] += 1
            path = os.path.join(directory, name)
            try:
                info = os.lstat(path)
            except OSError as exc:
                event = (ENTRY_DISAPPEARED if exc.errno == errno.ENOENT
                         else ENTRY_UNREADABLE
                         if exc.errno in (errno.EACCES, errno.EPERM) else IO_ERROR)
                anomalies.append(result.anomaly(
                    result.ANOMALY_UNREADABLE,
                    "%s could not be examined" % path,
                    source_path=path, event=event))
                continue

            entry_type = _type(info.st_mode)
            is_link = stat.S_ISLNK(info.st_mode)
            if is_link and not universe.follow_symlinks:
                # Observed as a directory entry, not as permission to walk the target.
                anomalies.append(result.anomaly(
                    result.ANOMALY_UNSUPPORTED,
                    "%s is a symlink and was not followed" % path,
                    source_path=path, event=SYMLINK_SKIPPED))

            if universe.eligible(name, entry_type):
                entries.append(_entry(path, name, info, entry_type, depth, is_link))

            if entry_type == "DIRECTORY" and not is_link:
                if not universe.cross_filesystems and info.st_dev != root_device:
                    anomalies.append(result.anomaly(
                        result.ANOMALY_UNSUPPORTED,
                        "%s is on another filesystem and was not entered" % path,
                        source_path=path, event=FILESYSTEM_BOUNDARY))
                    continue
                if depth + 1 > universe.max_depth:
                    # The caller's own boundary, obeyed. Recorded so the reader knows the
                    # question had an edge, not so the answer is called incomplete.
                    anomalies.append(result.anomaly(
                        result.ANOMALY_LIMIT,
                        "%s is below the requested depth of %d and was not entered"
                        % (path, universe.max_depth),
                        source_path=path, event=DEPTH_BOUNDARY))
                    continue
                descend(path, depth + 1)

    descend(root, 1)
    status, reason = _status(anomalies, universe, root)
    return result.Evidence(status, records=entries, reason=reason, source=root,
                           anomalies=anomalies, provenance=_provenance(universe, state))


def _ordered(names):
    """Deterministic, locale-independent, and safe for undecodable bytes.

    sorted() on str uses code-point order, which for surrogate-escaped bytes is not the
    byte order and differs from what every other tool sees. Sorting on the encoded bytes
    gives one answer everywhere, and it cannot make two distinct byte names compare equal.
    """
    return sorted(names, key=textbytes.original_bytes)


def _entry(path, name, info, entry_type, depth, is_link):
    decodable = not textbytes.has_surrogates(name)
    return {
        "path": path if decodable else None,
        "name": name if decodable else None,
        # Lossless identity for names that are not valid UTF-8. Same rule as an account
        # name: a replacement character is a DIFFERENT name, and two undecodable names
        # must never collapse into one.
        "name_bytes_hex": textbytes.hex_of(name),
        "name_encoding": textbytes.encoding_of(name),
        "entry_type": entry_type,
        "is_symlink": is_link,
        "depth": depth,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "size": info.st_size,
    }


def _type(mode):
    if stat.S_ISDIR(mode):
        return "DIRECTORY"
    if stat.S_ISREG(mode):
        return "REGULAR"
    if stat.S_ISLNK(mode):
        return "SYMLINK"
    return "OTHER"


def _status(anomalies, universe, root):
    blocking = [a for a in anomalies
                if a.get("event") and universe.affects_completeness(a)]
    if not blocking:
        return result.COLLECTED, None
    kinds = sorted(set(a["event"] for a in blocking))
    return result.PARTIAL, (
        "INCOMPLETE_ENUMERATION: %d event(s) prevented complete enumeration of the "
        "requested universe under %s (%s). Entries collected before that point are "
        "retained." % (len(blocking), root, ", ".join(kinds)))


def _provenance(universe, state):
    return {"universe": universe.name, "max_depth": universe.max_depth,
            "max_entries": universe.max_entries, "pattern": universe.pattern,
            "follow_symlinks": universe.follow_symlinks,
            "cross_filesystems": universe.cross_filesystems,
            "entries_examined": state["examined"],
            "safety_cap_reached": state["capped"],
            "ordering": "filename bytes, ascending"}
