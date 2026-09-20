# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Canonical serialization and hash framing — the production implementation.
# Implements: NORM-034, NORM-035, NORM-038, NORM-042
#
# This is PRODUCTION code. scripts/vectors/generate.py is the reference generator that
# certified the contract; it is not imported here and never will be. The golden vectors
# are the oracle, not a runtime dependency.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Canonical bytes and HASH_FRAME_V1, implemented from the frozen requirements."""
import hashlib

# NORM-038: the four W1-A domains. Mutually non-prefixing, asserted by the D1 vector.
DOMAIN_HOST_ID = "ISEDRAF:HOST-ID:V1"
DOMAIN_STATE = "ISEDRAF:STATE:V1"
DOMAIN_SNAPSHOT_MANIFEST = "ISEDRAF:SNAPSHOT-MANIFEST:V1"
DOMAIN_LEDGER_RECORD = "ISEDRAF:LEDGER-RECORD:V1"

_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}
_INT64_MIN = -(2 ** 63)
_INT64_MAX = 2 ** 63 - 1


class CanonicalError(ValueError):
    """A value cannot be canonically serialized. NORM-034 names the error."""


def _escape(s):
    """NORM-035's escape alphabet, written out rather than delegated to json."""
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif cp in _SHORT:
            out.append(_SHORT[cp])
        elif cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F or cp in (0x2028, 0x2029):
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if not (_INT64_MIN <= v <= _INT64_MAX):
            raise CanonicalError("INTEGER_OUT_OF_RANGE")
        return str(v)
    if isinstance(v, str):
        return _escape(v)
    if isinstance(v, list):
        # NORM-035: arrays are order-preserving; ordering set-like data is normalization's
        # job (NORM-037), never the serializer's. W1-A declares no array-typed field.
        return "[" + ",".join(_serialize(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v)                       # sorted by Unicode code point
        if len(set(keys)) != len(keys):
            raise CanonicalError("duplicate key")
        for k in keys:
            if not isinstance(k, str):
                raise CanonicalError("non-string key")
        return "{" + ",".join(_escape(k) + ":" + _serialize(v[k]) for k in keys) + "}"
    if isinstance(v, float):
        raise CanonicalError("floats are not representable in canonical form")
    raise CanonicalError("unsupported type %r" % type(v).__name__)


def canonical_bytes(value):
    """UTF-8 canonical form with exactly one trailing LF, and the LF IS hashed."""
    return _serialize(value).encode("utf-8") + b"\n"


def hash_frame(domain, *components):
    """HASH_FRAME_V1(domain, c1..cn) = SHA-256(ASCII(domain) || uint64_be(len) || c ...).

    Components are raw bytes. Where a component is a hash it is the raw 32-byte digest,
    never the rendered "sha256:" string.
    """
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    for c in components:
        h.update(len(c).to_bytes(8, "big"))
        h.update(c)
    return h.digest()


def rendered(digest):
    """The on-disk rendering of a digest. Never the preimage form."""
    return "sha256:" + digest.hex()
