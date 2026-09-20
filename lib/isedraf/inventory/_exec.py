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

"""Bounded reads and fixed-argv execution. No shell, ever."""
import errno
import os
import subprocess

# A fixed PATH, not the caller's: a collector that resolves a binary through an inherited
# PATH is a collector an attacker can redirect.
SEARCH_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
ENVIRONMENT = {"LC_ALL": "C", "LANG": "C", "PATH": ":".join(SEARCH_DIRS)}
OUTPUT_LIMIT = 1024 * 1024
DEFAULT_TIMEOUT = 5


class Outcome(object):
    """What a read or a command produced, and why if it produced nothing.

    `reason` uses the frozen SCOPE-022 vocabulary so a caller never has to guess whether
    absence meant "not installed" or "refused".
    """

    __slots__ = ("value", "ok", "reason", "source")

    def __init__(self, value=None, ok=True, reason=None, source=None):
        self.value = value
        self.ok = ok
        self.reason = reason
        self.source = source

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


def read_file(path, limit=OUTPUT_LIMIT):
    """Bounded read. Absence and refusal are different answers, and both are reported."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return Outcome(ok=False, reason="SOURCE_ABSENT", source=path)
        if exc.errno in (errno.EACCES, errno.EPERM):
            return Outcome(ok=False, reason="SOURCE_UNREADABLE", source=path)
        return Outcome(ok=False, reason="SOURCE_UNREADABLE", source=path)
    try:
        # A single os.read() on a /proc file returns only what the kernel generated for
        # that call - typically one page. Reading /proc/cpuinfo once truncated a 6-core
        # host to 2 logical CPUs, silently and plausibly, which is the worst kind of
        # wrong. Read until EOF, still bounded.
        chunks, total = [], 0
        while total < limit:
            chunk = os.read(fd, min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
    except OSError:
        return Outcome(ok=False, reason="SOURCE_UNREADABLE", source=path)
    finally:
        os.close(fd)
    return Outcome(value=data.decode("utf-8", "replace"), source=path)


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
