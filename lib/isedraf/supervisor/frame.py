# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The fixed binary framing of several raw acquisitions inside one AUTH-015 `bytes`.
# Implements: AUTH-029, AUTH-015, AUTH-003, AUTH-006
#
# AUTH-029 (framing within AUTH-015): one registered operation's opaque `bytes` may carry
# several raw acquisitions. Each item holds only acquisition facts - its kind, its raw name,
# a low-level acquisition_outcome, its raw lstat metadata, and its raw bytes where the
# contract permits reading them. An acquisition outcome is NOT a collection status: nothing
# here can carry COLLECTED, PARTIAL, NOT_TESTED or ERROR, or any judgment about what the
# bytes mean. Decoding is strict; interpretation happens only in the engine.
#
#   frame  = MAGIC (8 bytes) | count (u32) | item * count          nothing after the last item
#   item   = kind (u8) | acquisition_outcome (u8) | name length (u16) | name
#            | has_lstat (u8) [ | mode (u32) | uid (u32) | gid (u32) | size (u64) ]
#            | content length (u32) | content
#
# Pure: no I/O. Used by both sides; it imports only the standard library.
#
# =============================================================================
"""AUTH-029 framing: raw acquisitions and their acquisition outcomes, nothing else."""
import stat
import struct

MAGIC = b"ISDAF\x001\x00"

ROOT = "ROOT"
LISTING = "LISTING"
ENTRY = "ENTRY"
KINDS = (ROOT, LISTING, ENTRY)

# The closed set frozen by AUTH-029. Not the collection-status vocabulary.
READ_OK = "READ_OK"
NOT_FOUND = "NOT_FOUND"
PERMISSION_DENIED = "PERMISSION_DENIED"
SYMLINK = "SYMLINK"
NON_REGULAR = "NON_REGULAR"
TRUNCATED = "TRUNCATED"
IO_ERROR = "IO_ERROR"
ACQUISITION_OUTCOMES = (READ_OK, NOT_FOUND, PERMISSION_DENIED, SYMLINK, NON_REGULAR,
                        TRUNCATED, IO_ERROR)

NAME_LIMIT = 4096
HEAD = struct.Struct(">8sI")
ITEM = struct.Struct(">BBH")
FLAG = struct.Struct(">B")
LSTAT = struct.Struct(">IIIQ")
LENGTH = struct.Struct(">I")
LSTAT_FIELDS = ("mode", "uid", "gid", "size")


class FrameError(ValueError):
    """A frame, or an item, that is not exactly what AUTH-029 allows."""


def item(kind, name, acquisition_outcome, lstat=None, content=b""):
    """One acquisition, checked against what its kind and outcome may carry."""
    record = {"kind": kind, "name": name, "acquisition_outcome": acquisition_outcome,
              "lstat": None if lstat is None else dict(lstat), "content": content}
    _check(record)
    return record


def _check(record):
    kind, name, outcome = record["kind"], record["name"], record["acquisition_outcome"]
    lstat, content = record["lstat"], record["content"]
    if kind not in KINDS:
        raise FrameError("unknown kind %r" % (kind,))
    if outcome not in ACQUISITION_OUTCOMES:
        raise FrameError("unknown acquisition_outcome %r" % (outcome,))
    if not isinstance(name, bytes) or not 0 < len(name) <= NAME_LIMIT or b"\0" in name:
        raise FrameError("an item name is raw bytes, 1 to %d long, with no NUL" % NAME_LIMIT)
    if not isinstance(content, bytes):
        raise FrameError("item content is raw bytes")
    if lstat is not None:
        if sorted(lstat) != sorted(LSTAT_FIELDS) or not all(
                isinstance(lstat[f], int) and lstat[f] >= 0 for f in LSTAT_FIELDS):
            raise FrameError("lstat metadata is exactly mode, uid, gid and size")
    # Only a completed read carries bytes. A link, a non-regular object, a refusal or a
    # truncated read carries none: anything else would be content the contract did not read.
    if content and outcome != READ_OK:
        raise FrameError("%s %s carries content" % (kind, outcome))
    if outcome == NOT_FOUND and lstat is not None:
        raise FrameError("NOT_FOUND carries lstat metadata")
    if outcome in (READ_OK, SYMLINK, NON_REGULAR) and lstat is None:
        raise FrameError("%s %s carries no lstat metadata" % (kind, outcome))
    if lstat is not None:
        mode = lstat["mode"]
        if outcome == SYMLINK and not stat.S_ISLNK(mode):
            raise FrameError("SYMLINK whose lstat is not a link")
        if outcome == READ_OK:
            wanted = stat.S_ISDIR if kind == LISTING else stat.S_ISREG
            if not wanted(mode):
                raise FrameError("%s READ_OK whose lstat is not a %s" % (
                    kind, "directory" if kind == LISTING else "regular file"))
        if outcome == NON_REGULAR:
            regular = stat.S_ISDIR(mode) if kind == LISTING else stat.S_ISREG(mode)
            if regular or stat.S_ISLNK(mode):
                raise FrameError("NON_REGULAR whose lstat is %s" % (
                    "a link" if stat.S_ISLNK(mode) else "what the kind expects"))


def encode(items):
    out = [HEAD.pack(MAGIC, len(items))]
    for record in items:
        _check(record)
        out.append(ITEM.pack(KINDS.index(record["kind"]) + 1,
                             ACQUISITION_OUTCOMES.index(record["acquisition_outcome"]) + 1,
                             len(record["name"])))
        out.append(record["name"])
        if record["lstat"] is None:
            out.append(FLAG.pack(0))
        else:
            out.append(FLAG.pack(1))
            out.append(LSTAT.pack(*[record["lstat"][f] for f in LSTAT_FIELDS]))
        out.append(LENGTH.pack(len(record["content"])))
        out.append(record["content"])
    return b"".join(out)


def decode(data, limit, max_items):
    """Every item, or FrameError. Strict: no trailing byte, no unknown code, no excess."""
    if not isinstance(data, bytes):
        raise FrameError("a frame is bytes")
    if len(data) > limit:
        raise FrameError("frame of %d bytes exceeds the %d-byte bound" % (len(data), limit))
    view, at = memoryview(data), 0

    def take(n):
        nonlocal at
        if n < 0 or at + n > len(data):
            raise FrameError("a length runs past the end of the frame")
        chunk = bytes(view[at:at + n])
        at += n
        return chunk

    magic, count = HEAD.unpack(take(HEAD.size))
    if magic != MAGIC:
        raise FrameError("not an AUTH-029 frame")
    if count > max_items:
        raise FrameError("%d items exceed the %d-item bound" % (count, max_items))
    items = []
    for _ in range(count):
        kind_code, outcome_code, name_length = ITEM.unpack(take(ITEM.size))
        if not 1 <= kind_code <= len(KINDS):
            raise FrameError("unknown kind code %d" % kind_code)
        if not 1 <= outcome_code <= len(ACQUISITION_OUTCOMES):
            raise FrameError("unknown acquisition_outcome code %d" % outcome_code)
        name = take(name_length)
        (flag,) = FLAG.unpack(take(FLAG.size))
        if flag not in (0, 1):
            raise FrameError("lstat flag %d is neither 0 nor 1" % flag)
        lstat = (dict(zip(LSTAT_FIELDS, LSTAT.unpack(take(LSTAT.size)))) if flag else None)
        (content_length,) = LENGTH.unpack(take(LENGTH.size))
        if content_length > limit:
            raise FrameError("an item of %d bytes exceeds the bound" % content_length)
        record = {"kind": KINDS[kind_code - 1],
                  "acquisition_outcome": ACQUISITION_OUTCOMES[outcome_code - 1],
                  "name": name, "lstat": lstat, "content": take(content_length)}
        _check(record)
        items.append(record)
    if at != len(data):
        raise FrameError("%d trailing bytes after the last item" % (len(data) - at))
    return items


def listing_names(content):
    """The names a LISTING item carries: NUL-separated raw bytes, which no filename holds."""
    return content.split(b"\0") if content else []


def check_tree(items, root_name, directory_name):
    """The AUTH-029 shape of one fixed-surface result: the root file, then the listing, then
    exactly one entry for every listed name, in the listing's byte order. A fact check of
    the frame, never a judgment of what the files mean."""
    if len(items) < 2 or items[0]["kind"] != ROOT or items[1]["kind"] != LISTING:
        raise FrameError("a tree frame starts with its ROOT item and then its LISTING item")
    if items[0]["name"] != root_name or items[1]["name"] != directory_name:
        raise FrameError("the ROOT or LISTING item names another path")
    entries = items[2:]
    if [e for e in entries if e["kind"] != ENTRY]:
        raise FrameError("only ENTRY items follow the LISTING item")
    listing = items[1]
    names = (listing_names(listing["content"])
             if listing["acquisition_outcome"] == READ_OK else [])
    if names != sorted(names) or len(set(names)) != len(names):
        raise FrameError("the listing is not sorted and unique by bytes")
    for name in names:
        if b"/" in name or name in (b".", b".."):
            raise FrameError("a listed name is not a single directory entry")
    if [e["name"] for e in entries] != names:
        raise FrameError("the ENTRY items are not exactly the listed names, in order")
    return {"root": items[0], "listing": listing, "entries": entries}
