# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Answer the engine's requests over two file descriptors, one result per request.
# Implements: D-123, AUTH-003, AUTH-015
#
# The loop reads one request line, performs it and writes one framed result, until the
# engine closes its end. A request that is not exactly one identifier line is answered
# REFUSED and ends the loop: the supervisor does not try to resynchronise with a caller that
# has sent something the protocol has no place for.
#
# Nothing here starts the supervisor or the engine. The Full Audit route (systemd-run unit,
# the isedraf identity, the reduced engine) is later work (v0.2 P5) and is what will call
# serve().
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="supervisor (root in FULL_AUDIT, fixed operations only)"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""The supervisor's request loop."""
import os

from isedraf.supervisor import perform
from isedraf.supervisor import protocol


def _read_request(fd):
    """One raw request line, b"" at end of input, or the oversized prefix that was read."""
    line = bytearray()
    while len(line) <= protocol.REQUEST_LIMIT:
        byte = os.read(fd, 1)
        if not byte:
            return bytes(line)
        line.extend(byte)
        if byte == b"\n":
            return bytes(line)
    return bytes(line)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def serve(request_fd, response_fd):
    """Answer requests until end of input or a malformed request. Returns requests answered."""
    answered = 0
    while True:
        line = _read_request(request_fd)
        if not line:
            return answered
        operation_id = protocol.decode_request(line)
        if operation_id is None:
            res = protocol.result(None, protocol.REFUSED, stderr=b"MALFORMED_REQUEST")
            _write_all(response_fd, protocol.encode_response(res))
            return answered + 1
        _write_all(response_fd, protocol.encode_response(perform.perform(operation_id)))
        answered += 1
