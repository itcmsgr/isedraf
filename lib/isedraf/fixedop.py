# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The engine's side of a fixed operation: ask for an identifier, check the answer.
# Implements: D-123, AUTH-004, AUTH-006, AUTH-015, AUTH-016
#
# The engine holds no privilege. It sends an operation identifier and receives bounded bytes
# and a supervisor status; it never sends a path, an argument or an environment, because the
# protocol has no place for one. The answer is decoded strictly (protocol.decode_response).
#
# The mapping from a supervisor status onto the collection vocabulary is the engine's
# (AUTH-015) and lives here, once. It gives the access outcome of the one source the
# operation read. It never gives a section status: a COMPLETED operation does not make its
# section COLLECTED if another required source is missing (AUTH-016). The section derives its
# status from all of its sources, as it does for sources it read itself.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Engine-side fixed operation requests and the supervisor-status mapping."""
import os

from isedraf import coverage
from isedraf.supervisor import protocol

# The supervisor's one-token details for an operation that runs no executable.
_FILE_DETAIL = {b"ENOENT": coverage.NOT_FOUND,
                b"EACCES": coverage.PERMISSION_DENIED,
                b"EPERM": coverage.PERMISSION_DENIED}


def _read_exact(fd, size):
    data = bytearray()
    while len(data) < size:
        chunk = os.read(fd, min(65536, size - len(data)))
        if not chunk:
            raise protocol.ProtocolError("the supervisor closed the channel mid-frame")
        data.extend(chunk)
    return bytes(data)


class Channel:
    """Two descriptors to the supervisor: one to write requests, one to read results."""

    def __init__(self, request_fd, response_fd):
        self.request_fd = request_fd
        self.response_fd = response_fd

    def request(self, operation_id):
        """The validated AUTH-015 result for one identifier. Raises ProtocolError."""
        frame = protocol.encode_request(operation_id)
        view = memoryview(frame)
        while view:
            view = view[os.write(self.request_fd, view):]
        (size,) = protocol.HEADER.unpack(_read_exact(self.response_fd, protocol.HEADER.size))
        if size > protocol.RESPONSE_LIMIT:
            raise protocol.ProtocolError("response frame of %d bytes exceeds the limit" % size)
        return protocol.decode_response(_read_exact(self.response_fd, size), operation_id)


def access_outcome(res, runs_executable=False):
    """The coverage access outcome of the source one operation read."""
    status = res["status"]
    if status == protocol.COMPLETED:
        return coverage.READ_OK
    if status == protocol.TRUNCATED:
        return coverage.TRUNCATED
    if status == protocol.REFUSED:
        return coverage.NOT_SUPPORTED
    if runs_executable:
        return coverage.IO_ERROR
    return _FILE_DETAIL.get(res["stderr_bytes"], coverage.IO_ERROR)
