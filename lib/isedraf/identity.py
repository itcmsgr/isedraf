# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: host_identity collection, parsing, normalization and host_id derivation.
# Implements: IDENT-002, IDENT-003, IDENT-004, IDENT-005, IDENT-006, NORM-042, SNAP-022
#
# The collector collects and the engine interprets: this module reads bytes and applies
# the frozen grammar. It renders nothing and decides no policy.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""IDENT-003's one frozen parser, and IDENT-004's total ordered decision list."""
import errno
import os

from . import canonical

SOURCE_PATH = "/etc/machine-id"
SOURCE_ID = "file:/etc/machine-id"          # IDENT-006: per field, never per section
IDENTITY_SCHEME = "machine-id-sha256-v1"    # IDENT-005: provenance, not state
READ_BOUND = 4096                           # IDENT-003: at most exactly 4096 bytes
COLLECTOR_ID = "host_identity"
COLLECTOR_VERSION = 1
PARSER_VERSION = 1
CLASSIFICATION_TABLE_VERSION = 1

_HEX = frozenset("0123456789abcdefABCDEF")
_REJECTED_VALUES = ("0" * 32, "uninitialized")


class Identity(object):
    """One host_identity collection outcome. Carries no rendering and no policy."""

    __slots__ = ("status", "reason", "normalized", "host_id", "state",
                 "state_canonical", "state_hash")

    def __init__(self, status, reason, normalized=None):
        self.status = status
        self.reason = reason
        self.normalized = normalized
        self.host_id = None
        self.state = None
        self.state_canonical = None
        self.state_hash = None
        if normalized is not None:
            self.host_id = canonical.rendered(
                canonical.hash_frame(canonical.DOMAIN_HOST_ID,
                                     normalized.encode("utf-8")))
            self.state = {"host_id": self.host_id}      # IDENT-002: nothing else
            self.state_canonical = canonical.canonical_bytes(self.state)
            self.state_hash = canonical.rendered(
                canonical.hash_frame(canonical.DOMAIN_STATE, self.state_canonical))

    @property
    def collected(self):
        return self.status == "COLLECTED"


def read_source(path=SOURCE_PATH):
    """Bounded read. Returns (raw_bytes, None) or (None, IDENT-004 reason).

    IDENT-004 row 1 is ENOENT specifically; every other I/O error is row 2, including
    EACCES and a read longer than the frozen bound. The bound is read as BOUND+1 bytes so
    that "longer than the bound" is observable rather than silently truncated.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None, "SOURCE_ABSENT"        # row 1
        return None, "SOURCE_UNREADABLE"        # row 2: EACCES, EISDIR, ELOOP, ...
    try:
        raw = os.read(fd, READ_BOUND + 1)
    except OSError:
        return None, "SOURCE_UNREADABLE"        # row 2
    finally:
        os.close(fd)
    if len(raw) > READ_BOUND:
        return None, "SOURCE_UNREADABLE"        # row 2: over-long read
    return raw, None


def parse(raw):
    """IDENT-003's grammar. Returns (normalized, None) or (None, reason).

    NORM-042: this grammar decides acceptance FIRST. A byte sequence it rejects is
    SYNTAX_REJECTED whether it failed on encoding or on shape, and SHALL NEVER become
    NORM-036 tagged-base64 material inside identity state.
    """
    body = raw[:-1] if raw.endswith(b"\n") else raw     # the one optional trailing LF
    if b"\n" in body or b"\r" in body:
        return None, "SYNTAX_REJECTED"
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError:
        return None, "SYNTAX_REJECTED"                  # NORM-042, not NORM-036
    if len(text) != 32 or any(c not in _HEX for c in text):
        return None, "SYNTAX_REJECTED"
    text = text.lower()                                 # IDENT-003 normalization
    if text in _REJECTED_VALUES:
        return None, "SYNTAX_REJECTED"
    return text, None


def collect(path=SOURCE_PATH):
    """IDENT-004, evaluated top-down; the first matching row wins."""
    try:
        raw, reason = read_source(path)
        if reason == "SOURCE_ABSENT":
            return Identity("NOT_TESTED", reason)               # row 1
        if reason is not None:
            return Identity("ERROR", reason)                    # row 2
        normalized, reason = parse(raw)
        if reason is not None:
            return Identity("ERROR", reason)                    # row 3
        return Identity("COLLECTED", None, normalized)          # row 4
    except Exception:                                           # row 5: the catch-all
        # In a trust tool an unhandled failure becomes a named ERROR, never a silent pass.
        return Identity("ERROR", "INTERNAL_ERROR")


def method_object():
    """SNAP-021 freezes this object verbatim. PROVENANCE, outside the state hash."""
    return {
        "classification_table_version": CLASSIFICATION_TABLE_VERSION,
        "collector_id": COLLECTOR_ID,
        "collector_version": COLLECTOR_VERSION,
        "identity_scheme": IDENTITY_SCHEME,
        "parser_version": PARSER_VERSION,
        "source_id": SOURCE_ID,
    }
