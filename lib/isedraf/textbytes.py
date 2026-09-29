# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: One definition of "this text did not decode", used everywhere it matters.
# Implements: SCOPE-045, NORM-035
#
# ARCH-01 found three copies of the same expression - in accounts/sources.py,
# shared/bounded.py and shared/keyvalue.py - each deciding independently what an
# undecodable identifier is. The logic was identical in all three, which is precisely why
# it was worth consolidating: three copies of a rule do not drift on the day they are
# written, they drift on the day one of them is fixed.
#
# The rule matters more than its size. An account name, a filename and a configuration
# key that are not valid UTF-8 must all be treated the same way: the text is not repaired,
# the bytes are preserved exactly, and a replacement character - which is a DIFFERENT
# identifier - never takes the original's place.
#
# Pure: takes text, returns facts. No filesystem, no subprocess, no network.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Undecodable-byte handling for identifiers read off a Linux host."""

UTF8 = "UTF8"
UNDECODABLE = "UNDECODABLE"


def has_surrogates(text):
    """True when `text` carries bytes that did not decode as UTF-8.

    Readers use errors="surrogateescape", which maps each undecodable byte to a lone
    surrogate and maps it back exactly. Those surrogates cannot appear in canonical JSON
    (NORM-035), which is deliberate: a caller must decide explicitly how to represent an
    undecodable identifier rather than letting one slip into canonical state.
    """
    if text is None:
        return False
    return any(0xD800 <= ord(character) <= 0xDFFF for character in text)


def original_bytes(text):
    """The exact bytes the host held, recovered from a surrogateescape decode."""
    return text.encode("utf-8", "surrogateescape")


def hex_of(text):
    """Lossless, canonically representable identity for any identifier."""
    return "".join("%02x" % byte for byte in bytearray(original_bytes(text)))


def encoding_of(text):
    return UNDECODABLE if has_surrogates(text) else UTF8
