# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The wire format between the engine and the supervisor, both directions.
# Implements: D-123, AUTH-003, AUTH-008, AUTH-015
#
# A request is one operation identifier and a newline, nothing else. There is no field for a
# path, an argument, an environment variable or an option, so no caller can supply one
# (AUTH-003): the supervisor refuses any request that is not exactly a registered-shape
# identifier.
#
# A response is a 4-byte big-endian length and a JSON object with exactly the five AUTH-015
# fields. JSON is the frame, not content: `bytes` and `stderr_bytes` are base64 and are never
# interpreted by the supervisor. The engine decodes a response strictly and refuses an extra
# field, an unknown status or a byte count that does not match.
#
# For an operation that runs no executable, `stderr_bytes` carries the supervisor's own
# one-token detail for a failure (an errno name such as ENOENT, or NOT_REGULAR, TIMEOUT,
# UNKNOWN_OPERATION) and `exit_code` is null. For a fixed executable it carries the
# executable's own bounded stderr, and `exit_code` its exit status, or null when the
# supervisor stopped it.
#
# Pure: no I/O. Used by both sides; it imports only the standard library.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Engine <-> supervisor framing: an identifier in, five fields out."""
import base64
import binascii
import json
import re
import struct

OPERATION_ID = re.compile(r"\A[a-z][a-z0-9_]*_v[1-9][0-9]*\Z")
REQUEST_LIMIT = 128

COMPLETED = "COMPLETED"
FAILED = "FAILED"
REFUSED = "REFUSED"
TRUNCATED = "TRUNCATED"
STATUSES = (COMPLETED, FAILED, REFUSED, TRUNCATED)

FIELDS = ("operation_id", "status", "bytes", "stderr_bytes", "status_metadata")
METADATA = ("byte_count", "exit_code")

# The largest contract bound the registry gate admits, and the supervisor's own stderr bound.
BYTES_LIMIT = 16 * 1024 * 1024
STDERR_LIMIT = 64 * 1024
HEADER = struct.Struct(">I")
RESPONSE_LIMIT = (BYTES_LIMIT + STDERR_LIMIT) * 4 // 3 + 4096


class ProtocolError(ValueError):
    """A frame that is not exactly what the protocol allows."""


def encode_request(operation_id):
    if not isinstance(operation_id, str) or not OPERATION_ID.match(operation_id):
        raise ProtocolError("not an operation identifier: %r" % (operation_id,))
    return operation_id.encode("ascii") + b"\n"


def decode_request(line):
    """The identifier, or None for anything that is not exactly one identifier line."""
    if not isinstance(line, bytes) or len(line) > REQUEST_LIMIT or not line.endswith(b"\n"):
        return None
    try:
        text = line[:-1].decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if OPERATION_ID.match(text) else None


def result(operation_id, status, data=b"", stderr=None, exit_code=None):
    """One AUTH-015 result. The only shape the supervisor ever returns."""
    if status not in STATUSES:
        raise ProtocolError("unknown supervisor status %r" % (status,))
    return {"operation_id": operation_id, "status": status, "bytes": bytes(data),
            "stderr_bytes": None if stderr is None else bytes(stderr[:STDERR_LIMIT]),
            "status_metadata": {"exit_code": exit_code, "byte_count": len(data)}}


def encode_response(res):
    body = {"operation_id": res["operation_id"], "status": res["status"],
            "bytes": base64.b64encode(res["bytes"]).decode("ascii"),
            "stderr_bytes": (None if res["stderr_bytes"] is None
                             else base64.b64encode(res["stderr_bytes"]).decode("ascii")),
            "status_metadata": dict(res["status_metadata"])}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    return HEADER.pack(len(raw)) + raw


def _b64(value, limit, name):
    if not isinstance(value, str):
        raise ProtocolError("%s is not base64 text" % name)
    try:
        data = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise ProtocolError("%s is not base64" % name)
    if len(data) > limit:
        raise ProtocolError("%s exceeds %d bytes" % (name, limit))
    return data


def decode_response(raw, requested):
    """Validate one response body for the identifier that was requested. Strict."""
    try:
        body = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("response is not JSON")
    if not isinstance(body, dict) or sorted(body) != sorted(FIELDS):
        raise ProtocolError("response fields are not exactly %s" % (FIELDS,))
    if body["operation_id"] != requested:
        raise ProtocolError("response is for %r, not %r" % (body["operation_id"], requested))
    if body["status"] not in STATUSES:
        raise ProtocolError("unknown supervisor status %r" % (body["status"],))
    meta = body["status_metadata"]
    if not isinstance(meta, dict) or sorted(meta) != sorted(METADATA):
        raise ProtocolError("status_metadata is not exactly %s" % (METADATA,))
    exit_code = meta["exit_code"]
    if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
        raise ProtocolError("exit_code is not an integer or null")
    data = _b64(body["bytes"], BYTES_LIMIT, "bytes")
    stderr = (None if body["stderr_bytes"] is None
              else _b64(body["stderr_bytes"], STDERR_LIMIT, "stderr_bytes"))
    count = meta["byte_count"]
    if not isinstance(count, int) or isinstance(count, bool) or count != len(data):
        raise ProtocolError("byte_count does not match the bytes returned")
    if body["status"] != COMPLETED and data:
        raise ProtocolError("a %s result carries bytes" % body["status"])
    return result(requested, body["status"], data, stderr, exit_code)
