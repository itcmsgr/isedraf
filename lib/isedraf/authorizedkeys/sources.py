# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Parse authorized-keys lines. Text in, records out. Nothing is read or decided.
# Implements: SCOPE-045, NORM-035, NORM-037
#
# PURE. No filesystem, no environment, no clock, no network. The architecture gate
# enforces it and a test asserts it independently, because a parser that can reach the
# host is a parser whose output depends on where it ran.
#
# The one structural decision worth stating: whether a line begins with OPTIONS is not
# guessed from punctuation. The wire format names its own algorithm inside the
# base64 blob, so a candidate type is accepted when the blob AGREES with it. That makes
# the split self-validating and independent of any list of key types this project would
# otherwise have to maintain and would otherwise fall behind on - a key type invented
# after this code was written still parses, and is recorded with the type the file gives.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""The authorized-keys line grammar, and the retention decisions it carries."""
import base64
import binascii
import hashlib
import struct

from .. import textbytes
from ..shared.result import NOT_RETAINED, RETAIN_VALUE
from . import model


STRUCTURE_KEY_ONLY = "KEY_ONLY"
STRUCTURE_OPTIONS_AND_KEY = "OPTIONS_AND_KEY"
STRUCTURE_UNDETERMINED = "UNDETERMINED"
# The third is the honest one. See _line.


def parse(text, source=None, start_ordinal=0, option_policy=None):
    """Parse one authorized-keys file's text into records.

    Returns (records, malformed_count). Every non-blank, non-comment line produces a
    record: a line that did not parse is EVIDENCE that the file contains something
    unparseable, and dropping it would report a cleaner file than the host has.
    """
    policy = model.OPTION_VALUE_POLICY if option_policy is None else option_policy
    records, malformed = [], 0
    ordinal = start_ordinal
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        record = _line(line, policy)
        record["source_path"] = source
        record["source_line"] = number
        record["ordinal"] = ordinal
        ordinal += 1
        if record["parse_status"] != model.PARSE_OK:
            malformed += 1
        records.append(record)
    _mark_duplicates(records)
    return records, malformed


def fingerprint(blob):
    """OpenSSH's fingerprint basis, over the decoded blob.

    SHA-256, base64, padding stripped. Verified against `ssh-keygen -lf` rather than
    asserted from memory - the test that does so is an executable oracle, and a scheme
    nobody checked is a scheme that is probably subtly wrong.
    """
    digest = hashlib.sha256(blob).digest()
    return model.DIGEST_SHA256 + ":" + base64.b64encode(digest).decode("ascii").rstrip("=")


# --- line structure ---------------------------------------------------------------------

def _line(line, policy):
    """Decide whether the line begins with options, and never guess when it cannot.

    A line that PARSES is unambiguous: the blob names its own algorithm, so the field
    before it is either a key type that agrees or an option list. A line that does not
    parse is a different matter. `no-pty ssh-rsa <broken>` and `ssh-rsa <broken> comment`
    have the same shape, and the only thing that would separate them is a list of key
    types - which is exactly the list this parser refuses to maintain, because it would
    silently mislabel every key type invented after it was written.

    So when nothing decodes and the first field could be either, the line is recorded as
    carrying no readable key and NOTHING about its structure is claimed. An option list
    reported from a guess is worse evidence than an acknowledged unknown.
    """
    first, rest = _split_unquoted(line)
    record = _empty()

    # No options: the first field is a key type and the material after it agrees.
    key = _key_fields(first, rest)
    if key is not None:
        record["options"] = []
        record["structure"] = STRUCTURE_KEY_ONLY
        return _fill(record, key, policy)

    # Options then key, where the key material decodes.
    if rest is not None:
        second, tail = _split_unquoted(rest)
        key = _key_fields(second, tail)
        if key is not None:
            options, ok = _options(first, policy)
            record["options"] = options
            record["structure"] = STRUCTURE_OPTIONS_AND_KEY
            if not ok:
                record["parse_status"] = model.PARSE_MALFORMED_OPTIONS
                return record
            return _fill(record, key, policy)

    # Nothing decoded. The first field is an option list only when it carries a character
    # a key type cannot: '=', '"' or ','.
    if _is_certainly_options(first):
        options, ok = _options(first, policy)
        record["options"] = options
        record["structure"] = STRUCTURE_OPTIONS_AND_KEY
        if not ok:
            record["parse_status"] = model.PARSE_MALFORMED_OPTIONS
            return record
        second, tail = _split_unquoted(rest) if rest is not None else (None, None)
        record["key_type"] = second or None
        record["parse_status"] = (
            model.PARSE_MALFORMED_BASE64 if tail
            else model.PARSE_OPTIONS_ONLY if second is None
            else model.PARSE_NO_KEY_MATERIAL)
        return record

    record["structure"] = STRUCTURE_UNDETERMINED
    record["parse_status"] = (model.PARSE_MALFORMED_BASE64 if rest
                              else model.PARSE_NO_KEY_MATERIAL)
    return record


def _is_certainly_options(field):
    """Only these characters settle it. A key type may contain none of them."""
    return any(character in field for character in ('=', '"', ','))


def _key_fields(candidate, rest):
    """(type, blob, blob_type, comment) when `candidate` really names a key."""
    if not candidate or rest is None:
        return None
    material, comment = _split_unquoted(rest)
    if not material:
        return None
    blob = _decode(material)
    if blob is None:
        return None
    blob_type = _blob_type(blob)
    if blob_type is None:
        # Valid base64 that decodes to something with no algorithm string where the wire
        # format puts one. It is not a key, and it is not "malformed base64" either - the
        # base64 was fine. Reported as itself rather than as the nearest existing status.
        if _is_certainly_options(candidate):
            return None
        return candidate, blob, None, comment
    if blob_type != candidate and _is_certainly_options(candidate):
        return None
    return candidate, blob, blob_type, comment


def _decode(material):
    try:
        return base64.b64decode(material.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


def _blob_type(blob):
    """The algorithm name the wire format carries inside itself."""
    if len(blob) < 4:
        return None
    try:
        length = struct.unpack(">I", blob[:4])[0]
    except struct.error:
        return None
    if length == 0 or length > 64 or len(blob) < 4 + length:
        return None
    try:
        return blob[4:4 + length].decode("ascii")
    except UnicodeDecodeError:
        return None


def _fill(record, key, policy):
    key_type, blob, blob_type, comment = key
    record["key_type"] = key_type
    record["key_fingerprint"] = None if blob_type is None else fingerprint(blob)
    record["key_digest_algorithm"] = model.DIGEST_SHA256
    record["key_bits_source"] = None
    record["blob_type_agreement"] = (
        model.BLOB_TYPE_MATCHES if blob_type == key_type
        else model.BLOB_TYPE_UNREADABLE if blob_type is None
        else model.BLOB_TYPE_MISMATCH)
    record["blob_type"] = blob_type
    record["comment_present"] = bool(comment and comment.strip())
    record["comment_retention"] = model.COMMENT_POLICY
    # A line whose text and blob disagree about the algorithm is NOT an OK line.
    # `ssh-rsa <ed25519 blob>` reported as OK is an RSA key the host does not have and
    # that sshd would reject; the disagreement is the evidence, so it is the status.
    record["parse_status"] = (
        model.PARSE_NOT_A_KEY_BLOB if blob_type is None
        else model.PARSE_OK if blob_type == key_type
        else model.PARSE_KEY_TYPE_MISMATCH)
    return record


def _empty():
    return {
        "kind": "AUTHORIZED_KEY",
        "key_type": None,
        "key_fingerprint": None,
        "key_digest_algorithm": None,
        "blob_type": None,
        "blob_type_agreement": None,
        "options": [],
        "comment_present": False,
        "comment_retention": model.COMMENT_POLICY,
        "parse_status": model.PARSE_OK,
        "structure": None,
        "duplicate_of": None,
    }


# --- whitespace and quoting ---------------------------------------------------------------

def _split_unquoted(text):
    """Split at the first whitespace that is not inside a double-quoted value.

    An option value may contain spaces AND commas: `command="sleep 1, then exit"` is one
    option with one value. Splitting on whitespace or on commas without tracking the
    quote state is the classic break in this grammar, and it turns one restriction into
    two mangled ones.
    """
    quoted, escaped = False, False
    for index, character in enumerate(text):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quoted:
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
            continue
        if not quoted and character in " \t":
            return text[:index], text[index:].lstrip(" \t")
    return text, None


def _options(text, policy):
    """The comma-separated option list, with each value's retention decided here."""
    options, ok = [], True
    for name, value, present, well_formed in _split_options(text):
        if not well_formed:
            ok = False
        entry = {"name": name.lower(), "name_raw": name, "value_present": present}
        if not present:
            entry["value_retention"] = RETAIN_VALUE
            entry["value"] = None
            # A flag has no value to protect. Recording RETAIN_VALUE rather than
            # NOT_RETAINED keeps "nothing was withheld" distinguishable from "something
            # was withheld", which a null value alone would not say.
        else:
            decision = policy.get(name.lower(), model.DEFAULT_OPTION_VALUE_POLICY)
            entry["value_retention"] = decision
            entry["value"] = value if decision == RETAIN_VALUE else None
        options.append(entry)
    return options, ok


def _split_options(text):
    """Yield (name, value, value_present, well_formed) for each comma-separated option."""
    out = []
    field, quoted, escaped = [], False, False
    for character in text:
        if escaped:
            field.append(character)
            escaped = False
            continue
        if character == "\\" and quoted:
            escaped = True
            field.append(character)
            continue
        if character == '"':
            quoted = not quoted
            field.append(character)
            continue
        if character == "," and not quoted:
            out.append("".join(field))
            field = []
            continue
        field.append(character)
    out.append("".join(field))
    unterminated = quoted
    parsed = []
    for item in out:
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            name, _, value = item.partition("=")
            stripped, well_formed = _unquote(value)
            parsed.append((name, stripped, True, well_formed and not unterminated))
        else:
            parsed.append((item, None, False, not unterminated))
    return parsed


def _unquote(value):
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1].replace('\\"', '"'), True
    if value.startswith('"') or value.endswith('"'):
        return value, False
    return value, True


# --- duplicates ---------------------------------------------------------------------------

def _mark_duplicates(records):
    """A repeated key is a fact about the file, not a record to drop.

    Identity is the fingerprint alone. The same key listed twice with DIFFERENT options
    is still the same key appearing twice, and the options stay on their own records - a
    later layer can decide what that means, and this one must not decide it for them.
    """
    seen = {}
    for record in records:
        finger = record.get("key_fingerprint")
        if not finger:
            continue
        if finger in seen:
            record["duplicate_of"] = seen[finger]
        else:
            seen[finger] = record["ordinal"]


def undecodable(text):
    """True when the line carries bytes that did not decode. One definition, shared."""
    return textbytes.has_surrogates(text)


_ = NOT_RETAINED     # re-exported vocabulary; referenced so the import is not cosmetic
