# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Perform one enabled fixed operation and return its AUTH-015 result.
# Implements: D-123, AUTH-003, AUTH-006, AUTH-014, AUTH-015, AUTH-029
#
# Three performers, all mechanical:
#
#   read_regular_file   open the one contract target with O_NOFOLLOW and O_NONBLOCK, refuse
#                       anything that is not a regular file, read at most the bound plus
#                       one byte, stop at the timeout.
#   read_fixed_tree     AUTH-029: one root file, one directory's listing, and each entry of
#                       it - lstat through the directory descriptor, never following a link,
#                       opening only regular entries, with O_NOFOLLOW; framed by frame.py
#                       with one acquisition_outcome per item and no interpretation.
#   fixed_executable    run the contract's absolute executable with its constant argv, the
#                       CLEAN_FIXED environment, cwd /, stdin /dev/null; read stdout up to the
#                       bound and stderr up to STDERR_LIMIT; kill it at the timeout or when
#                       stdout passes the bound; only exit 0 succeeds.
#
# Neither looks at what it read. A result never says what the bytes mean.
#
# Limits stated rather than hidden:
# - O_NOFOLLOW protects the final path component. The directories above a target are
#   root-owned on every supported distribution, and a process that can replace them can
#   already replace the target.
# - The executable's owner and mode are checked before it runs; a root process able to swap
#   it between the check and the exec is outside what this check can stop.
# - The file timeout is checked between bounded reads. A read blocked inside the kernel is
#   not interrupted; the systemd unit's own runtime limit bounds the whole run (D-27).
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="supervisor (root in FULL_AUDIT, fixed operations only)"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""The two mechanical performers and the dispatch from identifier to result."""
import errno
import os
import stat
import subprocess

from isedraf.supervisor import contracts
from isedraf.supervisor import frame
from isedraf.supervisor import protocol

CHUNK = 65536
# How long one idle pass waits for the child before reading its pipes again.
POLL_SECONDS = 0.01


def _elapsed():
    return os.times().elapsed


def _errname(exc):
    return errno.errorcode.get(exc.errno, "OSERROR").encode("ascii")


def _target(path):
    return os.path.join(contracts.HOST_ROOT, path.lstrip("/"))


def read_regular_file(operation_id, contract):
    path = _target(contract["targets"][0])
    bound = contract["output_bound_bytes"]
    deadline = _elapsed() + contract["timeout_seconds"]
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
                     | os.O_NOCTTY)
    except OSError as exc:
        return protocol.result(operation_id, protocol.FAILED, stderr=_errname(exc))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return protocol.result(operation_id, protocol.FAILED, stderr=b"NOT_REGULAR")
        chunks, total = [], 0
        while True:
            if _elapsed() > deadline:
                return protocol.result(operation_id, protocol.FAILED, stderr=b"TIMEOUT")
            chunk = os.read(fd, min(CHUNK, bound + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > bound:
                return protocol.result(operation_id, protocol.TRUNCATED)
        return protocol.result(operation_id, protocol.COMPLETED, b"".join(chunks))
    except OSError as exc:
        return protocol.result(operation_id, protocol.FAILED, stderr=_errname(exc))
    finally:
        os.close(fd)


_ERRNO_OUTCOME = {errno.ENOENT: frame.NOT_FOUND, errno.EACCES: frame.PERMISSION_DENIED,
                  errno.EPERM: frame.PERMISSION_DENIED, errno.ELOOP: frame.SYMLINK,
                  errno.ENOTDIR: frame.NON_REGULAR}


def _lstat_fields(info):
    return {"mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid,
            "size": info.st_size}


def _lstat_or_none(name, dir_fd=None):
    try:
        return _lstat_fields(os.stat(name, dir_fd=dir_fd, follow_symlinks=False))
    except OSError:
        return None


def _failure(kind, name, exc, path, dir_fd=None):
    """One item for an acquisition that raised: the errno's outcome, never a judgment."""
    outcome = _ERRNO_OUTCOME.get(exc.errno, frame.IO_ERROR)
    if outcome == frame.NOT_FOUND:
        return frame.item(kind, name, outcome)
    meta = _lstat_or_none(path, dir_fd)
    if outcome in (frame.SYMLINK, frame.NON_REGULAR):
        # ELOOP and ENOTDIR say only that the open was refused for the object's type (a
        # link with O_DIRECTORY gives ENOTDIR, not ELOOP); the lstat says which type it is.
        if meta is None:
            outcome = frame.IO_ERROR
        elif stat.S_ISLNK(meta["mode"]):
            outcome = frame.SYMLINK
        elif (stat.S_ISDIR(meta["mode"]) if kind == frame.LISTING
              else stat.S_ISREG(meta["mode"])):
            outcome = frame.IO_ERROR
        else:
            outcome = frame.NON_REGULAR
    return frame.item(kind, name, outcome, meta)


def _read_bounded(fd, limit, deadline):
    """At most `limit` bytes, or None when there were more."""
    chunks, total = [], 0
    while True:
        if _elapsed() > deadline:
            raise TimeoutError()
        chunk = os.read(fd, min(CHUNK, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            return None


def _read_file_item(kind, name, path, member_limit, deadline, dir_fd=None):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
                     | os.O_NOCTTY, dir_fd=dir_fd)
    except OSError as exc:
        return _failure(kind, name, exc, path, dir_fd)
    try:
        info = os.fstat(fd)
        meta = _lstat_fields(info)
        if not stat.S_ISREG(info.st_mode):
            return frame.item(kind, name, frame.NON_REGULAR, meta)
        try:
            data = _read_bounded(fd, member_limit, deadline)
        except OSError:
            return frame.item(kind, name, frame.IO_ERROR, meta)
        if data is None:
            return frame.item(kind, name, frame.TRUNCATED, meta)
        return frame.item(kind, name, frame.READ_OK, meta, data)
    finally:
        os.close(fd)


def read_fixed_tree(operation_id, contract):
    """AUTH-029: the root file, the directory's listing, each listed entry; nothing else."""
    bound = contract["output_bound_bytes"]
    member_limit = contract["member_bound_bytes"]
    deadline = _elapsed() + contract["timeout_seconds"]
    root_name = contract["root_file"].encode("ascii")
    directory_name = contract["directory"].encode("ascii")
    try:
        items = [_read_file_item(frame.ROOT, root_name, _target(contract["root_file"]),
                                 member_limit, deadline)]
        directory = _target(contract["directory"])
        try:
            dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                             | os.O_CLOEXEC)
        except OSError as exc:
            items.append(_failure(frame.LISTING, directory_name, exc, directory))
            return _framed(operation_id, items, bound)
        try:
            try:
                names = sorted(os.fsencode(n) for n in os.listdir(dir_fd))
            except OSError as exc:
                outcome = (frame.PERMISSION_DENIED if exc.errno in (errno.EACCES, errno.EPERM)
                           else frame.IO_ERROR)
                items.append(frame.item(frame.LISTING, directory_name, outcome,
                                        _lstat_fields(os.fstat(dir_fd))))
                return _framed(operation_id, items, bound)
            if len(names) > contract["max_entries"]:
                return protocol.result(operation_id, protocol.TRUNCATED)
            items.append(frame.item(frame.LISTING, directory_name, frame.READ_OK,
                                    _lstat_fields(os.fstat(dir_fd)), b"\0".join(names)))
            for name in names:
                if _elapsed() > deadline:
                    raise TimeoutError()
                items.append(_entry_item(name, dir_fd, member_limit, deadline))
        finally:
            os.close(dir_fd)
    except TimeoutError:
        return protocol.result(operation_id, protocol.FAILED, stderr=b"TIMEOUT")
    return _framed(operation_id, items, bound)


def _entry_item(name, dir_fd, member_limit, deadline):
    """lstat first, without following: a link or a non-regular entry is never opened."""
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as exc:
        return _failure(frame.ENTRY, name, exc, name, dir_fd)
    if stat.S_ISLNK(info.st_mode):
        return frame.item(frame.ENTRY, name, frame.SYMLINK, _lstat_fields(info))
    if not stat.S_ISREG(info.st_mode):
        return frame.item(frame.ENTRY, name, frame.NON_REGULAR, _lstat_fields(info))
    # Opened relative to the directory with O_NOFOLLOW: an entry replaced by a link since the
    # lstat fails with ELOOP and is recorded as the link it now is.
    return _read_file_item(frame.ENTRY, name, name, member_limit, deadline, dir_fd)


def _framed(operation_id, items, bound):
    data = frame.encode(items)
    if len(data) > bound:
        return protocol.result(operation_id, protocol.TRUNCATED)
    return protocol.result(operation_id, protocol.COMPLETED, data)


def _trusted_executable(path):
    try:
        st = os.stat(path)
    except OSError as exc:
        return _errname(exc)
    if not stat.S_ISREG(st.st_mode):
        return b"NOT_REGULAR"
    if st.st_uid != contracts.EXECUTABLE_OWNER_UID or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return b"UNTRUSTED_EXECUTABLE"
    return None


def fixed_executable(operation_id, contract):
    exe = contract["fixed_executable"]
    refused = _trusted_executable(exe)
    if refused is not None:
        return protocol.result(operation_id, protocol.FAILED, stderr=refused)
    bound = contract["output_bound_bytes"]
    deadline = _elapsed() + contract["timeout_seconds"]
    try:
        proc = subprocess.Popen([exe] + list(contract["fixed_argv"]), shell=False,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=dict(contracts.EXEC_ENVIRONMENT),
                                cwd=contracts.EXEC_CWD, close_fds=True)
    except OSError as exc:
        return protocol.result(operation_id, protocol.FAILED, stderr=_errname(exc))
    out, err = bytearray(), bytearray()
    open_fds = {proc.stdout.fileno(): out, proc.stderr.fileno(): err}
    for fd in open_fds:
        os.set_blocking(fd, False)
    stopped = None
    try:
        while open_fds and stopped is None:
            progressed = False
            for fd, buf in list(open_fds.items()):
                try:
                    chunk = os.read(fd, CHUNK)
                except BlockingIOError:
                    continue
                if not chunk:
                    del open_fds[fd]
                    continue
                progressed = True
                if buf is out:
                    out.extend(chunk)
                    if len(out) > bound:
                        stopped = protocol.TRUNCATED
                        break
                elif len(err) < protocol.STDERR_LIMIT:
                    err.extend(chunk[:protocol.STDERR_LIMIT - len(err)])
            if stopped is None and _elapsed() > deadline:
                stopped = protocol.FAILED
            if stopped is None and not progressed:
                try:
                    proc.wait(timeout=POLL_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
        if stopped is None:
            try:
                proc.wait(timeout=max(deadline - _elapsed(), 0))
            except subprocess.TimeoutExpired:
                stopped = protocol.FAILED
        if stopped is not None:
            proc.kill()
            proc.wait()
    finally:
        proc.stdout.close()
        proc.stderr.close()
    if stopped == protocol.TRUNCATED:
        return protocol.result(operation_id, protocol.TRUNCATED, stderr=bytes(err))
    if stopped == protocol.FAILED:
        # Stopped at the timeout: no exit status was observed.
        return protocol.result(operation_id, protocol.FAILED, stderr=bytes(err))
    if proc.returncode != 0:
        # ZERO_ONLY_SUCCEEDS: any other exit is a failed operation, with its exit code.
        return protocol.result(operation_id, protocol.FAILED, stderr=bytes(err),
                               exit_code=proc.returncode)
    return protocol.result(operation_id, protocol.COMPLETED, bytes(out), bytes(err),
                           exit_code=0)


def perform(operation_id):
    """The AUTH-015 result for one requested identifier. Never raises for a caller input."""
    if not isinstance(operation_id, str) or not protocol.OPERATION_ID.match(operation_id):
        return protocol.result(None, protocol.REFUSED, stderr=b"MALFORMED_REQUEST")
    if operation_id not in contracts.CONTRACTS:
        return protocol.result(operation_id, protocol.REFUSED, stderr=b"UNKNOWN_OPERATION")
    contract = contracts.enabled(operation_id)
    if contract is None:
        return protocol.result(operation_id, protocol.REFUSED, stderr=b"NOT_ENABLED")
    performer = PERFORMERS[contract["performer"]]
    return performer(operation_id, contract)


PERFORMERS = {contracts.PERFORM_READ_REGULAR_FILE: read_regular_file,
              contracts.PERFORM_READ_FIXED_TREE: read_fixed_tree,
              contracts.PERFORM_FIXED_EXECUTABLE: fixed_executable}
