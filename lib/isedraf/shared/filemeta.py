# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Observe the filesystem object AT a path, and never the one it points to.
# Implements: SCOPE-022, SCOPE-045, GOV-001
#
# FROZEN INVARIANT:
#
#   Path metadata describes the filesystem object actually observed at the requested
#   path. It does not imply anything about the object a symlink may resolve to, unless
#   target observation was separately requested and successfully collected.
#
# That is why every observation here is lstat(2) and never stat(2). A collector that
# followed /etc/sudoers to wherever it pointed and reported the target's owner and mode as
# though they were the requested object's would be describing a different file than the
# one it was asked about - and would do it confidently, which is worse than failing.
#
# This module reports facts. `uid 0, mode 0600` is an observation; whether that is correct
# for a given file is a criterion, and criteria live elsewhere.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""lstat-based metadata for explicitly requested paths, with honest digest coherence."""
import errno
import hashlib
import os
import stat

from . import result

# --- file type, straight from st_mode -----------------------------------------------------
REGULAR = "REGULAR"
DIRECTORY = "DIRECTORY"
SYMLINK = "SYMLINK"
FIFO = "FIFO"
SOCKET = "SOCKET"
BLOCK_DEVICE = "BLOCK_DEVICE"
CHAR_DEVICE = "CHAR_DEVICE"
OTHER = "OTHER"

_TYPES = ((stat.S_ISREG, REGULAR), (stat.S_ISDIR, DIRECTORY), (stat.S_ISLNK, SYMLINK),
          (stat.S_ISFIFO, FIFO), (stat.S_ISSOCK, SOCKET), (stat.S_ISBLK, BLOCK_DEVICE),
          (stat.S_ISCHR, CHAR_DEVICE))

# --- digest outcomes, kept SEPARATE from the metadata status ------------------------------
# Metadata succeeding and content failing is an ordinary, expected combination: /etc/shadow
# is lstat-able by anyone and readable by nobody. Collapsing the two into one status would
# either throw away the metadata or claim a coherent observation that never happened.
DIGEST_NOT_REQUESTED = "NOT_REQUESTED"
DIGEST_COLLECTED = "COLLECTED"
DIGEST_NOT_APPLICABLE = "NOT_APPLICABLE"      # not a regular file
DIGEST_UNREADABLE = "UNREADABLE"
DIGEST_OBJECT_CHANGED = "OBJECT_CHANGED"      # the path stopped naming what we lstat-ed


def observe(path, digest=False, limit=64 * 1024 * 1024):
    """Observe the object at `path`. Never follows a symlink.

    `path` is kept exactly as requested, lexically. The record answers "what is at this
    path", which is the question a configuration audit asks - not "what is at the end of
    this chain of links", which is a different question and needs its own request.
    """
    record = {"requested_path": path, "exists": None, "file_type": None,
              "uid": None, "gid": None, "mode": None, "mode_octal": None,
              "permission_bits": None, "setuid": None, "setgid": None, "sticky": None,
              "size": None, "is_symlink": None, "symlink_target_text": None,
              "device": None, "inode": None, "nlink": None,
              "digest_status": DIGEST_NOT_REQUESTED, "digest": None,
              "digest_reason": None}

    try:
        info = os.lstat(path)
    except OSError as exc:
        record["exists"] = False
        if exc.errno == errno.ENOENT:
            return result.Evidence(
                result.NOT_TESTED, records=[record], source=path,
                reason="SOURCE_ABSENT: %s does not exist." % path,
                provenance=_provenance(digest))
        if exc.errno in (errno.EACCES, errno.EPERM):
            # SCOPE-022: privilege denial is NOT_TESTED. Being unable to lstat a path
            # usually means a parent directory is not searchable, which is a statement
            # about who is asking.
            return result.Evidence(
                result.NOT_TESTED, records=[record], source=path,
                reason="SOURCE_UNREADABLE: %s could not be examined: permission denied."
                       % path,
                provenance=_provenance(digest))
        return result.Evidence(
            result.ERROR, records=[record], source=path,
            reason="SOURCE_UNREADABLE: %s could not be examined." % path,
            provenance=_provenance(digest))

    mode = info.st_mode
    record.update({
        "exists": True,
        "file_type": _file_type(mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
        # The raw bits AND a rendering. A criterion needs the bits; a report needs the
        # rendering; neither should have to derive the other and risk disagreeing.
        "mode": stat.S_IMODE(mode),
        "mode_octal": "%04o" % stat.S_IMODE(mode),
        "permission_bits": stat.S_IMODE(mode) & 0o777,
        "setuid": bool(mode & stat.S_ISUID),
        "setgid": bool(mode & stat.S_ISGID),
        "sticky": bool(mode & stat.S_ISVTX),
        "size": info.st_size,
        "is_symlink": stat.S_ISLNK(mode),
        "device": info.st_dev,
        "inode": info.st_ino,
        "nlink": info.st_nlink,
    })

    if record["is_symlink"]:
        try:
            # The target TEXT, read lexically. It is not resolved, not joined against the
            # parent, and emphatically not followed: an absolute target naming a real path
            # on the machine running a fixture test must not be visited.
            record["symlink_target_text"] = os.readlink(path)
        except OSError:
            record["symlink_target_text"] = None

    if digest:
        _add_digest(record, path, info, limit)

    status, reason = _status(record, digest)
    return result.Evidence(status, records=[record], source=path, reason=reason,
                           provenance=_provenance(digest))


def _add_digest(record, path, before, limit):
    """Digest the content, and refuse to claim it belongs to the metadata unless it does.

    lstat and open are two operations. Between them the path can be replaced - that is
    the ordinary shape of a config rewrite, not an exotic attack. Combining metadata from
    one inode with content from another and presenting it as one observation would be a
    quiet lie.

    So the object is opened WITHOUT following symlinks, and the open file descriptor is
    fstat-ed. If the descriptor's identity differs from what was lstat-ed, the path stopped
    naming the same object and the digest is refused rather than attached.
    """
    if not stat.S_ISREG(before.st_mode):
        record["digest_status"] = DIGEST_NOT_APPLICABLE
        record["digest_reason"] = ("a digest is defined for regular files; this is %s"
                                   % record["file_type"])
        return
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except OSError as exc:
        record["digest_status"] = DIGEST_UNREADABLE
        record["digest_reason"] = ("content could not be opened: %s"
                                   % errno.errorcode.get(exc.errno, exc.errno))
        return
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            record["digest_status"] = DIGEST_OBJECT_CHANGED
            record["digest_reason"] = (
                "the path stopped naming the object whose metadata was observed; "
                "metadata and content would not describe one file")
            return
        digest = hashlib.sha256()
        total = 0
        while total < limit:
            chunk = os.read(fd, min(65536, limit - total))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        if (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            # The object we held open was rewritten in place while we read it.
            record["digest_status"] = DIGEST_OBJECT_CHANGED
            record["digest_reason"] = ("the object changed while it was being read; the "
                                       "digest would not describe a coherent state")
            return
        record["digest"] = "sha256:" + digest.hexdigest()
        record["digest_status"] = DIGEST_COLLECTED
        record["digest_bytes"] = total
    except OSError as exc:
        record["digest_status"] = DIGEST_UNREADABLE
        record["digest_reason"] = ("content could not be read: %s"
                                   % errno.errorcode.get(exc.errno, exc.errno))
    finally:
        os.close(fd)


def _status(record, digest):
    """Metadata is the observation. A failed digest makes it PARTIAL, never worthless."""
    if not digest or record["digest_status"] in (DIGEST_COLLECTED,
                                                 DIGEST_NOT_REQUESTED):
        return result.COLLECTED, None
    if record["digest_status"] == DIGEST_NOT_APPLICABLE:
        # Asking for a digest of a directory is a caller mistake, not incomplete evidence
        # about the host. The metadata is complete and the reason says why there is no
        # digest.
        return result.COLLECTED, None
    return result.PARTIAL, (
        "METADATA_COLLECTED_DIGEST_NOT_COLLECTED: %s (%s). The metadata below describes "
        "the object that was observed; no content digest is claimed for it."
        % (record["digest_reason"], record["digest_status"]))


def _file_type(mode):
    for predicate, name in _TYPES:
        if predicate(mode):
            return name
    return OTHER


def _provenance(digest):
    return {"method": "lstat(2)", "follows_symlinks": False,
            "digest_requested": bool(digest)}


# --- SCOPE-045 ---------------------------------------------------------------------------
# Ownership and mode are configuration: a file becoming world-readable is a real event.
# Size, inode and device are observations that change for ordinary reasons. Timestamps are
# deliberately NOT collected here - they are the sort of field that looks harmless and then
# turns into an invented creation date, which is exactly the inference EVID-020 forbids.
CLASSIFICATION = {
    "requested_path": result.PROVENANCE,
    "exists": result.STATE,
    "file_type": result.STATE,
    "uid": result.STATE,
    "gid": result.STATE,
    "mode": result.STATE,
    "mode_octal": result.DERIVED,
    "permission_bits": result.DERIVED,
    "setuid": result.STATE,
    "setgid": result.STATE,
    "sticky": result.STATE,
    "is_symlink": result.STATE,
    "symlink_target_text": result.STATE,
    "size": result.OBSERVATION,
    "nlink": result.OBSERVATION,
    "device": result.OBSERVATION,
    "inode": result.OBSERVATION,
    "digest": result.STATE,
    "digest_status": result.PROVENANCE,
    "digest_reason": result.PROVENANCE,
    "digest_bytes": result.OBSERVATION,
}
