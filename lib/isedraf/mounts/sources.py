# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Parse fstab and mountinfo. Text in, records out. Nothing is read or resolved.
# Implements: SCOPE-045, NORM-035, NORM-037
#
# PURE. No filesystem, no environment, no clock, no network.
#
# Two grammars that look alike and are not. fstab is positional fields written by a
# person, where the last two are OPTIONAL - a four-field line is valid. mountinfo is a
# kernel record whose optional-field count VARIES, terminated by a single "-". Every entry
# on the development host carried exactly one optional field, which is exactly why the
# count may not be assumed.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""The fstab and mountinfo grammars, parsed and never resolved."""

from .. import textbytes
from . import model

_ESCAPES = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}


def unescape(text):
    """fstab(5) and proc(5) octal escapes, and nothing else.

    Only the four sequences both formats produce are decoded. A general backslash-octal
    decoder would turn a literal `\\123` into something the host does not have.
    """
    if "\\" not in text:
        return text, False
    out, index, changed = [], 0, False
    while index < len(text):
        if text[index] == "\\" and text[index + 1:index + 4] in _ESCAPES:
            out.append(_ESCAPES[text[index + 1:index + 4]])
            index += 4
            changed = True
        else:
            out.append(text[index])
            index += 1
    return "".join(out), changed


def _text_or_bytes(record, field, raw):
    """The lossless doctrine: text when representable, exact bytes when not.

    UNDECODABLE != REPLACEMENT-DECODED. Two different byte paths must never collapse
    onto one U+FFFD string, because a comparison would then call them the same mount.
    """
    value, escaped = unescape(raw)
    if textbytes.has_surrogates(value):
        record[field] = None
        record[field + "_bytes_hex"] = textbytes.hex_of(value)
        record[field + "_encoding"] = textbytes.UNDECODABLE
        return None, escaped
    record[field] = value
    record[field + "_encoding"] = textbytes.UTF8
    return value, escaped


def parse_fstab(text, source=None):
    """Returns (records, malformed_count). A line that does not parse is RETAINED."""
    records, malformed, ordinal = [], 0, 0
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        record = _fstab_line(line)
        record["source_path"] = source
        record["source_line"] = number
        record["ordinal"] = ordinal
        ordinal += 1
        if record["parse_status"] != model.PARSE_OK:
            malformed += 1
        records.append(record)
    return records, malformed


def _fstab_line(line):
    record = {
        "kind": "FSTAB_ENTRY",
        "source_spec": None, "source_spec_tag": None, "source_spec_value": None,
        "target": None, "fstype": None, "options_raw": None, "options": [],
        "dump": 0, "pass": 0, "dump_declared": False, "pass_declared": False,
        "target_escaped": False, "parse_status": model.PARSE_OK, "field_count": 0,
    }
    fields = line.split()
    record["field_count"] = len(fields)
    if len(fields) < 4 or len(fields) > 6:
        record["parse_status"] = model.PARSE_FIELD_COUNT
        if len(fields) >= 2:
            record["source_spec"] = fields[0]
            _text_or_bytes(record, "target", fields[1])
        return record

    record["source_spec"] = fields[0]
    spec, _ = unescape(fields[0])
    record["source_spec_tag"], record["source_spec_value"] = _tag(spec)
    _, record["target_escaped"] = _text_or_bytes(record, "target", fields[1])
    record["fstype"] = fields[2]
    record["options_raw"] = fields[3]
    record["options"] = [o for o in fields[3].split(",") if o]
    # fstab(5): an omitted field 5 or 6 MEANS 0. The semantic value is 0 either way, and
    # whether it was written stays recorded, so "wrote 0" and "wrote nothing" remain
    # distinguishable at the raw evidence layer.
    for index, name in ((4, "dump"), (5, "pass")):
        if index >= len(fields):
            continue
        record[name + "_declared"] = True
        try:
            record[name] = int(fields[index])
        except ValueError:
            record["parse_status"] = model.PARSE_MALFORMED_NUMERIC
            record[name + "_raw"] = fields[index]
    return record


def _tag(spec):
    """How the source was WRITTEN. Never what device it names."""
    for tag in (model.SOURCE_TAG_UUID, model.SOURCE_TAG_LABEL,
                model.SOURCE_TAG_PARTUUID, model.SOURCE_TAG_PARTLABEL,
                model.SOURCE_TAG_ID, model.SOURCE_TAG_PATH):
        if spec.startswith(tag + "="):
            return tag, spec[len(tag) + 1:]
    return model.SOURCE_TAG_NONE, spec


def parse_mountinfo(text, source=None):
    """Returns (records, malformed_count).

    A malformed line is RETAINED. Dropping one denies that an active mount exists, which
    manufactures a false DECLARED_ONLY - the worse direction, and the reason the caller
    must also mark the active universe incomplete.
    """
    records, malformed, ordinal = [], 0, 0
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.rstrip("\r")
        if not line.strip():
            continue
        record = _mountinfo_line(line)
        record["source_path"] = source
        record["source_line"] = number
        record["ordinal"] = ordinal
        ordinal += 1
        if record["parse_status"] != model.PARSE_OK:
            malformed += 1
        records.append(record)
    return records, malformed


def _mountinfo_line(line):
    record = {
        "kind": "ACTIVE_MOUNT",
        "mount_id": None, "parent_mount_id": None,
        "major_minor": None, "major": None, "minor": None,
        "root": None, "mount_point": None,
        "mount_options_raw": None, "mount_options": [],
        "optional_fields": [], "unknown_optional_fields": [],
        "fstype": None, "mount_source": None,
        "super_options_raw": None, "super_options": [],
        "parse_status": model.PARSE_OK, "raw_line_bytes_hex": None,
    }
    fields = line.split(" ")
    separator = _separator(fields)
    if separator is None or len(fields) < separator + 4:
        record["parse_status"] = model.PARSE_MALFORMED_RECORD
        record["raw_line_bytes_hex"] = textbytes.hex_of(line)
        return record

    for index, name in ((0, "mount_id"), (1, "parent_mount_id")):
        try:
            record[name] = int(fields[index])
        except ValueError:
            record["parse_status"] = model.PARSE_MALFORMED_NUMERIC
            record[name + "_raw"] = fields[index]

    record["major_minor"] = fields[2]
    if ":" in fields[2]:
        record["major"], _, record["minor"] = fields[2].partition(":")

    _text_or_bytes(record, "root", fields[3])
    _text_or_bytes(record, "mount_point", fields[4])
    record["mount_options_raw"] = fields[5]
    record["mount_options"] = [o for o in fields[5].split(",") if o]

    for field in fields[6:separator]:
        name, _, value = field.partition(":")
        entry = {"name": name, "value": value or None, "raw": field}
        record["optional_fields"].append(entry)
        if name not in model.KNOWN_OPTIONAL:
            # Retained and NOT fatal: an unfamiliar optional field must not destroy an
            # otherwise usable record, or the next kernel silently loses evidence.
            record["unknown_optional_fields"].append(entry)

    record["fstype"] = fields[separator + 1]
    _text_or_bytes(record, "mount_source", fields[separator + 2])
    record["super_options_raw"] = fields[separator + 3]
    record["super_options"] = [o for o in fields[separator + 3].split(",") if o]
    return record


def _separator(fields):
    """The first "-" at or after the optional-field position.

    proc(5) puts six fields before the optional block, so the separator cannot appear
    earlier than index 6. Scanning LEFT TO RIGHT from there finds the real separator even
    when a later field - the mount source - is itself "-", which `mount -t tmpfs - /mnt`
    produces. Searching from the right reads every field after it as the wrong thing.
    """
    for index in range(6, len(fields)):
        if fields[index] == "-":
            return index
    return None
