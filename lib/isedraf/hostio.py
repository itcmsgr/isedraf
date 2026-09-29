# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The only way inventory collectors touch the filesystem or run a command.
# Implements: EXEC-016, D-71, D-84, SCOPE-022
#
# Collectors collect; the engine interprets. Nothing here parses meaning — it reads bytes
# and returns them, or says why it could not.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="discovered at runtime, fixed argv only"
# =============================================================================

"""Bounded reads and fixed-argv execution. No shell, ever.

Moved out of inventory/ by ARCH-01. Reading a file and running a fixed argv are not
inventory concepts: accounts, the shared include graph and every future domain need them
too, and reaching them through `isedraf.inventory` executed all nine inventory collectors
as a side effect of importing a helper. This module depends on nothing but the standard
library, which is what makes it safe to sit underneath everything.

It is also the single place host I/O happens outside a domain, which is what makes the
ARCH-01 side-effect map meaningful rather than a list of everywhere os.open appears.
"""
import errno
import os
import stat
import subprocess

# A fixed PATH, not the caller's: a collector that resolves a binary through an inherited
# PATH is a collector an attacker can redirect.
SEARCH_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
ENVIRONMENT = {"LC_ALL": "C", "LANG": "C", "PATH": ":".join(SEARCH_DIRS)}
OUTPUT_LIMIT = 1024 * 1024
DEFAULT_TIMEOUT = 5

# Why a read produced nothing, at errno granularity. `reason` keeps the frozen SCOPE-022
# vocabulary; this says which kind of failure it was, so a caller can tell a refusal from
# a broken disk. Refusal is a statement about privilege; an I/O error is a statement about
# the source. Reporting both as "unreadable" loses the only detail that decides between
# NOT_TESTED and ERROR.
NOT_FOUND = "NOT_FOUND"
PERMISSION_DENIED = "PERMISSION_DENIED"
IO_ERROR = "IO_ERROR"
READ_OK = "READ_OK"
# The source is larger than the bound. Owner invariant (2026-09-24): truncated input is
# NEVER complete evidence. What was read up to the bound is not returned as a value,
# because a caller that parsed it would report the first MiB of /etc/passwd as the whole
# file - which hid a UID-0 account placed after it.
TRUNCATED = "TRUNCATED"


class Outcome(object):
    """What a read or a command produced, and why if it produced nothing.

    `reason` uses the frozen SCOPE-022 vocabulary so a caller never has to guess whether
    absence meant "not installed" or "refused".
    """

    __slots__ = ("value", "ok", "reason", "source", "detail")

    def __init__(self, value=None, ok=True, reason=None, source=None, detail=None):
        self.value = value
        self.ok = ok
        self.reason = reason
        self.source = source
        # ADDITIVE, and deliberately separate from `reason`.
        #
        # SCOPE-022 decides collection status from a table, and two of its rows need a
        # distinction `reason` does not carry: "privilege or MAC denial -> NOT_TESTED"
        # and "present and failed -> ERROR" are different answers, but EACCES and EIO
        # both arrive here as SOURCE_UNREADABLE. A caller that must apply that table -
        # /etc/shadow is the obvious one, since it is root-readable by design - cannot
        # do it from `reason` alone.
        #
        # `reason` is left exactly as it was so that no existing caller changes
        # behaviour. identity.py does not use this reader at all: IDENT-004 freezes
        # ENOENT as row 1 and every other I/O error, EACCES included, as row 2, and that
        # frozen collapse is intentional rather than an oversight to be corrected here.
        self.detail = detail

    def __bool__(self):
        return self.ok

    __nonzero__ = __bool__          # Python 2 name; harmless and costs nothing


def which(name):
    """Resolve a binary against the FIXED search path. Returns None if absent."""
    if os.path.isabs(name):
        return name if os.path.exists(name) else None
    for directory in SEARCH_DIRS:
        candidate = os.path.join(directory, name)
        if os.path.exists(candidate):
            return candidate
    return None


def _read_bytes(path, limit):
    """(bytes, None) or (None, Outcome). One open, at most `limit` bytes, never silent.

    Reads up to `limit` bytes and then asks for ONE more: if the file has it, the read is
    TRUNCATED and no value is returned. Absence, refusal, I/O failure and truncation are
    four different answers, and all four are reported.
    """
    try:
        # O_NONBLOCK: opening a FIFO with no writer would otherwise block forever
        # (hardening red team F10). The type is checked before anything is read.
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None, Outcome(ok=False, reason="SOURCE_ABSENT", source=path,
                                 detail=NOT_FOUND)
        if exc.errno in (errno.EACCES, errno.EPERM):
            return None, Outcome(ok=False, reason="SOURCE_UNREADABLE", source=path,
                                 detail=PERMISSION_DENIED)
        return None, Outcome(ok=False, reason="SOURCE_UNREADABLE", source=path,
                             detail=IO_ERROR)
    try:
        mode = os.fstat(fd).st_mode
        if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
            return None, Outcome(ok=False, reason="SOURCE_NOT_REGULAR", source=path,
                                 detail=IO_ERROR)
        chunks, total = [], 0
        while total < limit:
            chunk = os.read(fd, min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total >= limit and os.read(fd, 1):
            return None, Outcome(ok=False, reason="SOURCE_TRUNCATED", source=path,
                                 detail=TRUNCATED)
        return b"".join(chunks), None
    except OSError:
        return None, Outcome(ok=False, reason="SOURCE_UNREADABLE", source=path,
                             detail=IO_ERROR)
    finally:
        os.close(fd)


def read_file(path, limit=OUTPUT_LIMIT):
    """Bounded read. Absence, refusal and truncation are different answers, all reported."""
    data, failure = _read_bytes(path, limit)
    if failure is not None:
        return failure
    return Outcome(value=data.decode("utf-8", "replace"), source=path, detail=READ_OK)


def read_file_lossless(path, limit=OUTPUT_LIMIT):
    """Like read_file, but the bytes survive the round trip.

    `read_file` decodes with errors="replace", which turns any byte that is not valid
    UTF-8 into U+FFFD. For a CPU model string that is a cosmetic dent. For an IDENTIFIER
    it is a correctness defect: an account named b"jos\xe9" becomes 'jos\ufffd', and the
    tool would then measure, hash, baseline and report an identifier the host does not
    have. Two different undecodable names collapse to the same replacement character, so
    a delta could not even tell them apart.

    surrogateescape maps each undecodable byte to a lone surrogate and maps it back
    exactly, so `value.encode("utf-8", "surrogateescape")` returns the original bytes.
    Those surrogates cannot appear in canonical JSON (NORM-035), which is deliberate: a
    caller must decide explicitly how to represent an undecodable identifier rather than
    letting one slip into canonical state.

    The file is opened ONCE. It used to be read by read_file and then opened and read a
    second time, so the two reads could see different files.
    """
    data, failure = _read_bytes(path, limit)
    if failure is not None:
        return failure
    return Outcome(value=data.decode("utf-8", "surrogateescape"), source=path,
                   detail=READ_OK)


def read_lines(path):
    outcome = read_file(path)
    if not outcome.ok:
        return outcome
    return Outcome(value=outcome.value.splitlines(), source=path)


def run(argv, timeout=DEFAULT_TIMEOUT):
    """Fixed argv, no shell, clean environment, bounded output, closed stdin.

    argv[0] is resolved against SEARCH_DIRS, so a collector cannot be redirected by an
    inherited PATH, and a missing tool is NOT_TESTED rather than an exception.
    """
    binary = which(argv[0])
    if binary is None:
        return Outcome(ok=False, reason="NOT_TESTED", source=argv[0])
    full = [binary] + list(argv[1:])
    try:
        proc = subprocess.Popen(full, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, env=dict(ENVIRONMENT),
                                close_fds=True)
    except OSError:
        return Outcome(ok=False, reason="ERROR", source=binary)
    try:
        out, _err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return Outcome(ok=False, reason="ERROR", source=binary)
    if proc.returncode != 0:
        # SCOPE-022: a tool that is present and failed is an ERROR, never NOT_TESTED.
        return Outcome(ok=False, reason="ERROR", source=binary)
    return Outcome(value=out[:OUTPUT_LIMIT].decode("utf-8", "replace"), source=binary)
