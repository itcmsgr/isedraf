# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Pure parsers for the three local account files. No filesystem, no policy.
# Implements: SCOPE-022, SCOPE-045, IDENT-060, NORM-035
#
# These functions take TEXT and return records. They do not open files, do not know
# whether /etc/shadow was refused, and cannot consult the host they run on. That
# separation is what makes the fixtures deterministic: a parser test cannot pass or fail
# because of the permissions of the machine running it.
#
# They also do not interpret. A shell of /usr/sbin/nologin is recorded as the string
# "/usr/sbin/nologin" and nothing else - not "inactive", not "service account". A UID of
# 0 is recorded as 0, not "root", because the name and the UID are two separate
# observations and a host may legitimately carry several UID 0 entries under different
# names. That is precisely the fact an assurance tool must be able to REPORT, and it
# cannot report it if the parser has already decided which one is "the" root account.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Pure text -> records parsers for passwd, group and shadow."""
import re

from .. import textbytes
from . import model

# crypt(3): $id$[params$]salt$digest. Only the id is extracted; everything after it is
# discarded before this function returns. See `_password_state`.
_CRYPT = re.compile(r"^\$([0-9a-zA-Z-]+)\$")

# IDENT-060: integers and explicit named states only. The empty string is a distinct
# observation from a zero and from an absent field, and it is kept distinct.
_INT = re.compile(r"^-?[0-9]+$")

# glibc 2.43's files backend, measured with getent against synthetic files:
#   - a line ends at "\n" only; "\f", "\v", "\r", "\x1c", U+2028 stay inside a field
#   - a NUL byte ends the line
#   - leading C-locale whitespace is skipped before the name; then "#" is a comment
#   - an id is strtoul/strtol text: blanks, one sign, digits, and nothing after
# C isspace() in the C locale is exactly these six bytes. Python's str.isspace() is
# Unicode-aware, so "\xa0#evil:x:0:0" looked like a comment to the parser while glibc
# returns it as a UID-0 account.
_C_SPACE = " \t\n\v\f\r"
UID_MAX = 2 ** 32 - 1


class ParsedSource(object):
    """What one source file contained, including what was wrong with it.

    `records` are in file order. Nothing is de-duplicated and nothing is dropped:
    a malformed line becomes a record carrying its anomalies, not a silent omission,
    because "we read 40 accounts" and "we read 41 lines and one made no sense" are
    different statements about the same host.
    """

    __slots__ = ("records", "anomalies", "line_count", "malformed_count", "directives",
                 "directive_keys")

    def __init__(self, records, anomalies, line_count, malformed_count, directives=None,
                 directive_keys=None):
        self.records = records
        self.anomalies = anomalies
        self.line_count = line_count
        self.malformed_count = malformed_count
        # compat directives: retained, never records (W1-D §9 clarification).
        self.directives = [] if directives is None else directives
        # line -> exact bytes (hex) of each directive's name field. IN MEMORY ONLY: it lets
        # the topology refer to the local record with the same name without copying text
        # (red team pass 6, P6-3). Never serialized, never part of a directive record.
        self.directive_keys = {} if directive_keys is None else directive_keys

    @property
    def well_formed(self):
        return self.malformed_count == 0


def identifier(raw):
    """Represent an identifier without ever substituting one for another.

    Returns (name, encoding, bytes_hex, non_ascii). When the bytes are not valid UTF-8
    the name is None and the exact bytes are preserved in hex, because a replacement
    character is a different identifier and canonical state must not contain one.

    `non_ascii` is the half of IDENT-070 that the frozen text actually determines: a name
    containing code points outside ASCII. It needs no external table and no Unicode
    version, so it is reproducible across every supported interpreter. The CONFUSABLE
    half is NOT computed here - see IQ-012.
    """
    if raw == "":
        return None, None, None, None
    if textbytes.has_surrogates(raw):
        return None, model.NAME_UNDECODABLE, textbytes.hex_of(raw), True
    return (raw, model.NAME_UTF8, textbytes.hex_of(raw),
            any(ord(character) > 127 for character in raw))


def _anomaly(kind, detail, line_number):
    return {"anomaly": kind, "detail": detail, "line": line_number}


def _significant_lines(text, entry_comments=False):
    """Yield (line_number, line, uncertain, commented) for lines that carry a record.

    Blank lines and `#` comments are skipped. They are not anomalies: every real
    /etc/group on a Debian system has a trailing newline, and treating that as malformed
    would make every host permanently PARTIAL.

    `entry_comments` is for /etc/group. glibc's getgrent skips a `#` line, but its
    initgroups/getgrouplist path does not: "#wheel:x:10:alice" gives alice gid 10
    (measured, final re-check R3-1). A `#` line holding a ":" is therefore yielded with
    `commented` set, so the parser keeps it as an untrusted record and the source cannot
    claim complete evidence. A comment without ":" cannot be a group entry to glibc.
    """
    segments = text.split("\n")
    last = len(segments)
    for number, raw in enumerate(segments, start=1):
        line = raw.split("\x00", 1)[0].lstrip(_C_SPACE)
        commented = line.startswith("#")
        if not line or (commented and not (entry_comments and ":" in line)):
            continue
        # glibc shifts a line left over its leading blanks WITHOUT its terminator when the
        # line has no "\n" of its own (the last line of the file) or holds a NUL, and the
        # last characters are then read twice: " alice:...:/bin/sh" at end of file becomes
        # shell "/bin/shh" (measured). What glibc makes of such a line cannot be stated
        # exactly, so it is untrusted rather than guessed (differential harness, N1).
        uncertain = raw[:1] in _C_SPACE and raw[:1] != "" and (
            "\x00" in raw or (number == last and not text.endswith("\n")))
        yield number, line, uncertain, commented


def _glibc_number(value, signed):
    """(int, None) for a value glibc reads exactly; (None, why) otherwise.

    Leading zeros are stripped before int(): "0"*5000+"0" is 0 to glibc, and Python 3.11+
    refuses int() on a string over 4300 digits. An unsigned id with a sign of "-", or above
    UID_MAX, is one glibc wraps or clamps (measured: "-1" and "4294967296" both become
    4294967295); ISEDRAF does not state a value glibc had to invent.
    """
    # A linear scan, not a regex: "0*([0-9]+)$" backtracked quadratically on a long run of
    # zeros followed by a non-digit (hardening re-check N5: 64k zeros took 18 s).
    i = 0
    while i < len(value) and value[i] in _C_SPACE:
        i += 1
    sign = ""
    if i < len(value) and value[i] in "+-":
        sign = value[i]
        i += 1
    body = value[i:]
    if body == "" or not all("0" <= c <= "9" for c in body):
        return None, "empty" if value == "" else "not a number glibc accepts"
    digits = body.lstrip("0") or "0"
    if len(digits) > 19:
        return None, "outside the range glibc stores exactly"
    number = int(digits)
    if signed:
        # Shadow fields: glibc 2.43 stores -1, 0 and 0..2**31-1 exactly; every other
        # negative becomes -1 and larger values wrap or become -1 (hardening red team F4).
        number = -number if sign == "-" else number
        if number == -1 or 0 <= number <= 2 ** 31 - 1:
            return number, None
        return None, "a value glibc transforms rather than stores"
    # uid/gid: strtoul. "-0" is 0 (red team F3: a UID-0 account lost its uid); any other
    # sign of "-", or a value above UID_MAX, is wrapped or clamped by glibc.
    if (sign == "-" and number != 0) or number > UID_MAX:
        return None, "a value glibc wraps or clamps rather than stores"
    return number, None


def _exact(value):
    """A field as text, or "hex:<bytes>" when it is not UTF-8 (red team pass 8, N4).

    Read losslessly, a Latin-1 gecos or home holds bytes canonical serialization cannot
    carry. A field never contains ":", so the hex form cannot collide with a real value;
    members use the same form.
    """
    return "hex:" + textbytes.hex_of(value) if textbytes.has_surrogates(value) else value


def _untrusted(rec, anomalies, kind, detail, line_number):
    """Mark `rec` malformed with one anomaly; return 1 if it was not malformed before."""
    anomalies.append(_anomaly(kind, detail, line_number))
    rec["anomalies"].append(kind)
    newly = 0 if rec["malformed"] else 1
    rec["malformed"] = True
    return newly


def _empty_name(rec, parts, anomalies, line_number):
    """An empty name is never trustworthy identity (final re-check R3-2).

    glibc returns ":x:0:0:..." as an account and getspnam("") joins it to ":hash:...",
    while ISEDRAF has no identifier for it. The record is kept, counted malformed, and
    the source is PARTIAL rather than silently different.
    """
    if parts[0] != "":
        return 0
    return _untrusted(rec, anomalies, model.ANOMALY_MALFORMED_RECORD,
                      "the name field is empty", line_number)


_DIRECTIVE = re.compile(r"^([+-])(@?)([^:@\s]*)$")
# The name a directive may carry: the conventional account-name charset, with one optional
# trailing "$" for Samba machine accounts ("host01$"). "alice$6$salt$..." - a shadow line
# missing its first colon - is not a name, and its text is a hash (red team pass 2, #6).
_DIRECTIVE_NAME = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]*\$?$")


def _uncertain_directive(directive, anomalies, line_number):
    """A directive on a line glibc reads without its terminator is not stated exactly.

    The same rule as a record (differential harness, N1): glibc re-reads the tail of a
    blank-prefixed line that has no "\n" of its own, so what it makes of it is unknown.
    """
    anomalies.append(_anomaly(model.ANOMALY_MALFORMED_DIRECTIVE,
                              "leading blanks on a line glibc reads without its terminator",
                              line_number))
    if model.ANOMALY_MALFORMED_DIRECTIVE not in directive["anomalies"]:
        directive["anomalies"].append(model.ANOMALY_MALFORMED_DIRECTIVE)
    directive["malformed"] = True


def _int_value(value):
    """The integer an _INT string denotes, or None when it cannot be stated exactly.

    Leading zeros are stripped BEFORE int(): glibc's strtol reads "0"*4300+"5" as 5, while
    Python 3.11+ (and 3.7-3.10 patch releases) refuse int() on a string over 4300 digits
    (red team pass 6, P6-1). More than 19 significant digits is outside int64 whatever its
    value, and the range is checked exactly.
    """
    negative = value.startswith("-")
    digits = value.lstrip("-").lstrip("0")
    if len(digits) > 19:
        return None
    number = int(digits or "0")
    number = -number if negative else number
    return number if -2 ** 63 <= number < 2 ** 63 else None


def _in_int64(value):
    """True when an integer string fits a signed 64-bit value, without a long int()."""
    return _int_value(value) is not None


def _shape(value):
    """What an override field looks like, without keeping what it says."""
    if value == "":
        return "EMPTY"
    return "INTEGER" if _INT.match(value) else "OTHER"


def _directive(line, number, field_count, netgroups, anomalies, numeric=(),
               keep_override_text=True):
    """A compat directive, or None when the line is not one.

    W1-D §9 clarification (owner, 2026-09-24). A name field beginning with "+" or "-" is
    an NSS inclusion or exclusion directive for the NIS map, never an account: `+` is
    "every entry of the map", and parsing it as an account named "+" put a directive into
    identity state. The line alone decides; nsswitch.conf is never consulted here (§2).

    Leading blanks do not hide a directive: glibc skips them, so "\t+alice" is a directive
    and would otherwise have become an account named "\t+alice" (red team F5). They are
    kept as an anomaly, and the directive counts as malformed.

    Valid: "+", "+NAME", "-NAME", and "+@NG"/"-@NG" where `netgroups` (passwd, shadow),
    either bare or carrying the source's field count. Anything else starting with "+" or
    "-" is a MALFORMED directive: retained with its anomaly, and counted as malformed.

    Redaction outranks "verbatim" (W1-D §7). The password field is classified by
    _password_state. Override TEXT is kept only for a valid directive in a file whose
    override fields cannot carry a credential (passwd, group); for shadow, and for every
    malformed directive, only each field's shape is kept (red team F6: a hash placed in a
    shadow override field was retained verbatim).
    """
    # Leading C-locale blanks were already skipped by _significant_lines, as glibc skips
    # them, so "\t+alice" arrives here as "+alice": a directive, and not a malformed one
    # (owner ruling on RT-F5, 2026-09-27, superseding the pass-1 "leading blanks" rule).
    if line[:1] not in ("+", "-"):
        return None
    parts = line.split(":")
    problems = []
    match = _DIRECTIVE.match(parts[0])
    at, raw_name = (match.group(2), match.group(3)) if match else ("", "")
    if not match:
        problems.append("name field is not +, +NAME, -NAME or +/-@NETGROUP")
    elif at and not netgroups:
        problems.append("a netgroup directive is not defined for this file")
    elif at and not raw_name:
        problems.append("a netgroup directive names no netgroup")
    elif line[0] == "-" and not raw_name:
        problems.append("a bare \"-\" is not a defined directive")
    elif raw_name and not _DIRECTIVE_NAME.match(raw_name):
        problems.append("the directive names something that is not a valid account or "
                        "netgroup name")
    if len(parts) not in (1, field_count):
        problems.append("expected 1 or %d fields, found %d" % (field_count, len(parts)))
    overrides = parts[2:]
    # Numeric override positions must be empty or integers: glibc discards a directive
    # whose uid/gid override is not a number, and a hash placed there was kept verbatim
    # while the line was labelled valid (red team pass 3, F1). `numeric` is "all" for
    # shadow, whose override fields are all ageing values.
    positions = range(len(overrides)) if numeric == "all" else numeric
    if any(i < len(overrides) and _shape(overrides[i]) == "OTHER" for i in positions):
        problems.append("a numeric override field is neither empty nor an integer")
    elif any(i < len(overrides) and _shape(overrides[i]) == "INTEGER"
             and not _in_int64(overrides[i]) for i in positions):
        # A value canonical bytes cannot carry crashed collect() (red team pass 5, H2);
        # glibc wraps it. Outside int64 it is not a value this lane can state exactly.
        problems.append("a numeric override field is outside the 64-bit integer range")
    for problem in problems:
        anomalies.append(_anomaly(model.ANOMALY_MALFORMED_DIRECTIVE, problem, number))
    # A malformed directive keeps no field TEXT at all - not its name either - because a
    # line that failed to parse may have put a credential into any field.
    name, _encoding, name_hex, _non_ascii = identifier(raw_name if not problems else "")
    # glibc ignores the overrides of an EXCLUDE line, so none of their text is kept
    # (red team pass 8, L2).
    keep_text = not problems and keep_override_text and line[:1] == "+"
    if keep_text:
        # Read losslessly, an override may hold bytes that are not UTF-8; they are kept
        # exactly, as "hex:<bytes>", never as text canonical bytes cannot carry (pass 7, F5).
        overrides = ["hex:" + textbytes.hex_of(v) if textbytes.has_surrogates(v) else v
                     for v in overrides]
    # The target comes from the name field itself, not from the match: a malformed
    # "-@bad ng" is still a netgroup directive (red team pass 4, L3).
    field = parts[0][1:]
    return {
        "_key_hex": textbytes.hex_of(field.lstrip("@")) if field else None,
        "line": number,
        "kind": model.DIRECTIVE_INCLUDE if line[0] == "+" else model.DIRECTIVE_EXCLUDE,
        "target": (model.DIRECTIVE_NETGROUP if field.startswith("@") else
                   model.DIRECTIVE_NAME if field else model.DIRECTIVE_ALL),
        "name": name,
        "name_bytes_hex": name_hex,
        "name_length": len(parts[0]) - 1,
        "field_count": len(parts),
        "password_field_state": _password_state(parts[1]) if len(parts) > 1 else None,
        "override_fields": overrides if keep_text else None,
        "override_shape": [_shape(v) for v in overrides],
        # Owner ruling M2 (2026-09-24): a VALID shadow directive's ageing fields were
        # checked to be empty or integers above, so they carry no text a hash could hide
        # in. glibc applies them (max_days 3 vs 99999), so their canonical values are
        # kept: an integer as an int, so "03" and "3" are one value, and an empty field as
        # "" because the all-empty form clears fields the bare form leaves alone.
        "ageing_values": ([_int_value(v) if v != "" else "" for v in overrides]
                          if numeric == "all" and not problems else None),
        "malformed": bool(problems),
        "anomalies": [model.ANOMALY_MALFORMED_DIRECTIVE] if problems else [],
    }


def _numeric(value, field, line_number, anomalies):
    """(int or None, trustworthy). A number glibc would not store exactly is recorded as an
    anomaly and never coerced to a default; the caller counts its record as malformed."""
    number, why = _glibc_number(value, signed=False)
    if why is not None:
        anomalies.append(_anomaly(model.ANOMALY_NON_NUMERIC_ID,
                                  "%s is %s" % (field, why), line_number))
        return None, False
    return number, True


def _duplicates(records, name_key, id_key, anomalies):
    """Record collisions. Deliberately does NOT resolve them.

    A dict keyed by username would make a duplicated account disappear, and which of the
    two survived would depend on file order. Two accounts sharing a UID, or one name
    appearing twice, is the anomaly itself - the thing a host assurance tool exists to
    surface - so both sides are kept and the collision is named.

    Named by LINE and LENGTH, never by text (owner ruling N3, 2026-09-26). A name field
    can hold a password hash when a line is missing its first colon, and no pattern can
    tell a name from a secret, so no name text is copied into a diagnostic - valid names
    included: the records themselves, at the lines given, are the evidence.
    """
    seen_names, seen_ids = {}, {}
    for rec in records:
        # Collisions are decided on the exact bytes: two identical undecodable names both
        # decode to None and were never reported (hardening red team F5).
        key = rec.get("name_bytes_hex") if name_key == "name" else rec.get(name_key)
        if key is not None:
            if key in seen_names:
                first = seen_names[key]
                anomalies.append(_anomaly(
                    model.ANOMALY_DUPLICATE_NAME,
                    "the same %s (%d bytes) appears at lines %d and %d"
                    % (name_key, len(key) // 2 if name_key == "name" else len(key),
                       first["line"], rec["line"]), rec["line"]))
            else:
                seen_names[key] = rec
        ident = rec.get(id_key) if id_key else None
        if ident is not None:
            if ident in seen_ids:
                first = seen_ids[ident]
                anomalies.append(_anomaly(
                    model.ANOMALY_DUPLICATE_ID,
                    "%s %d is shared by the records at lines %d and %d"
                    % (id_key, ident, first["line"], rec["line"]), rec["line"]))
            else:
                seen_ids[ident] = rec
    return anomalies

def parse_passwd(text):
    """name:password:uid:gid:gecos:home:shell

    The second field is a legacy password placeholder, almost always `x`. It is NOT read
    as a credential here: a host that genuinely carries a hash in /etc/passwd is handled
    by the same redaction rule as shadow, in `_password_state`.
    """
    records, anomalies, directives, keys = [], [], [], {}
    malformed = 0
    for number, line, uncertain, _commented in _significant_lines(text):
        directive = _directive(line, number, 7, True, anomalies, numeric=(0, 1))
        if directive is not None:
            keys[number] = directive.pop("_key_hex")
            if uncertain:
                _uncertain_directive(directive, anomalies, number)
            directives.append(directive)
            malformed += 1 if directive["malformed"] else 0
            continue
        parts = line.split(":")
        rec = {"line": number, "malformed": False, "anomalies": []}
        if uncertain:
            malformed += 1
            rec["malformed"] = True
            anomalies.append(_anomaly(model.ANOMALY_MALFORMED_RECORD,
                                      "leading blanks on a line glibc reads without its "
                                      "terminator", number))
            rec["anomalies"].append(model.ANOMALY_MALFORMED_RECORD)
        if len(parts) != 7:
            malformed += 0 if rec["malformed"] else 1
            rec["malformed"] = True
            anomalies.append(_anomaly(model.ANOMALY_FIELD_COUNT,
                                      "expected 7 fields, found %d" % len(parts), number))
            rec["anomalies"].append(model.ANOMALY_FIELD_COUNT)
            # Keep whatever is legible. A truncated line still tells us a name existed.
            parts = (parts + [""] * 7)[:7]
        local = []
        uid, uid_ok = _numeric(parts[2], "uid", number, local)
        gid, gid_ok = _numeric(parts[3], "gid", number, local)
        if local:
            # glibc drops a line whose uid or gid it cannot read, so the record is not
            # trustworthy identity: counted malformed, forcing PARTIAL. This line used to
            # read "malformed += 0 if ... else 0", which counted nothing (red team pass 2).
            if not rec["malformed"]:
                malformed += 1
                rec["malformed"] = True
            anomalies.extend(local)
            rec["anomalies"].extend(a["anomaly"] for a in local)
        malformed += _empty_name(rec, parts, anomalies, number)
        name, encoding, name_hex, non_ascii = identifier(parts[0])
        rec.update({
            "name": name,
            "name_encoding": encoding,
            "name_bytes_hex": name_hex,
            "name_non_ascii": non_ascii,
            "uid": uid,
            "primary_gid": gid,
            "gecos": _exact(parts[4]),
            "home": _exact(parts[5]) if parts[5] != "" else None,
            "shell": _exact(parts[6]) if parts[6] != "" else None,
            "passwd_field_state": _password_state(parts[1]),
        })
        records.append(rec)
    _duplicates(records, "name", "uid", anomalies)
    return ParsedSource(records, anomalies, len(records) + len(directives), malformed,
                        directives, directive_keys=keys)


def parse_group(text):
    """name:password:gid:member,member,...

    `members` is the EXPLICIT supplementary list only. Primary membership lives in the
    passwd GID relationship and is deliberately not joined here: a user whose primary
    group is `staff` does not appear in the `staff` line of /etc/group, and a model that
    silently merged the two would lose which of the two sources said so.
    """
    records, anomalies, directives, keys = [], [], [], {}
    malformed = 0
    for number, line, uncertain, commented in _significant_lines(text, entry_comments=True):
        # glibc ignores every group override, so none of their text is kept (pass 7, F7).
        directive = _directive(line, number, 4, False, anomalies, numeric=(0,),
                               keep_override_text=False)
        if directive is not None:
            keys[number] = directive.pop("_key_hex")
            if uncertain:
                _uncertain_directive(directive, anomalies, number)
            directives.append(directive)
            malformed += 1 if directive["malformed"] else 0
            continue
        parts = line.split(":")
        rec = {"line": number, "malformed": False, "anomalies": []}
        if commented:
            malformed += _untrusted(rec, anomalies, model.ANOMALY_MALFORMED_RECORD,
                                    "a commented line glibc's initgroups still reads as a "
                                    "group entry", number)
        if uncertain:
            malformed += _untrusted(rec, anomalies, model.ANOMALY_MALFORMED_RECORD,
                                    "leading blanks on a line glibc reads without its "
                                    "terminator", number)
        if len(parts) != 4:
            malformed += 0 if rec["malformed"] else 1
            rec["malformed"] = True
            anomalies.append(_anomaly(model.ANOMALY_FIELD_COUNT,
                                      "expected 4 fields, found %d" % len(parts), number))
            rec["anomalies"].append(model.ANOMALY_FIELD_COUNT)
            parts = (parts + [""] * 4)[:4]
        local = []
        gid, _gid_ok = _numeric(parts[2], "gid", number, local)
        if local:
            # glibc drops a group line whose gid it cannot read: not trustworthy identity.
            if not rec["malformed"]:
                malformed += 1
                rec["malformed"] = True
            anomalies.extend(local)
            rec["anomalies"].extend(a["anomaly"] for a in local)
        # glibc strips leading C-locale blanks from each member, keeps trailing ones, and
        # drops a member left empty (hardening red team F2: " alice" made false orphans
        # and a wrong wheel membership). An undecodable member is written "hex:<bytes>":
        # a lone surrogate cannot be serialized canonically, and ":" cannot occur in a
        # member name, so the form is unambiguous (red team F5).
        members = []
        for m in parts[3].split(","):
            m = m.lstrip(_C_SPACE)
            if m == "":
                continue
            members.append("hex:" + textbytes.hex_of(m) if textbytes.has_surrogates(m) else m)
        malformed += _empty_name(rec, parts, anomalies, number)
        name, encoding, name_hex, non_ascii = identifier(parts[0])
        rec.update({
            "name": name,
            "name_encoding": encoding,
            "name_bytes_hex": name_hex,
            "name_non_ascii": non_ascii,
            "gid": gid,
            "explicit_members": members,
            "group_password_field_state": _password_state(parts[1]),
        })
        records.append(rec)
    _duplicates(records, "name", "gid", anomalies)
    return ParsedSource(records, anomalies, len(records) + len(directives), malformed,
                        directives, directive_keys=keys)


def parse_shadow(text):
    """name:password:lastchg:min:max:warn:inactive:expire:reserved

    IDENT-060: integers and explicit named states only. `''` and `-1` are DIFFERENT
    observations - one says the field was never set, the other says it was set to the
    sentinel - and both are different from 99999. None of them is turned into a date
    here, and none is turned into a judgement.
    """
    fields = ("last_change_days", "min_days", "max_days", "warn_days",
              "inactive_days", "expire_days")
    records, anomalies, directives, keys = [], [], [], {}
    malformed = 0
    for number, line, uncertain, _commented in _significant_lines(text):
        directive = _directive(line, number, 9, True, anomalies, numeric="all",
                               keep_override_text=False)
        if directive is not None:
            keys[number] = directive.pop("_key_hex")
            if uncertain:
                _uncertain_directive(directive, anomalies, number)
            directives.append(directive)
            malformed += 1 if directive["malformed"] else 0
            continue
        parts = line.split(":")
        rec = {"line": number, "malformed": False, "anomalies": []}
        if uncertain:
            malformed += 1
            rec["malformed"] = True
            anomalies.append(_anomaly(model.ANOMALY_MALFORMED_RECORD,
                                      "leading blanks on a line glibc reads without its "
                                      "terminator", number))
            rec["anomalies"].append(model.ANOMALY_MALFORMED_RECORD)
        if len(parts) != 9:
            malformed += 0 if rec["malformed"] else 1
            rec["malformed"] = True
            anomalies.append(_anomaly(model.ANOMALY_FIELD_COUNT,
                                      "expected 9 fields, found %d" % len(parts), number))
            rec["anomalies"].append(model.ANOMALY_FIELD_COUNT)
            parts = (parts + [""] * 9)[:9]
        ageing = {}
        for offset, field in enumerate(fields, start=2):
            raw = parts[offset]
            value, why = (None, None) if raw == "" else _glibc_number(raw, signed=True)
            if raw == "":
                ageing[field] = None
                ageing[field + "_source"] = "UNSPECIFIED"
            elif why is None:
                # strtol forms glibc reads: " 3" and "+3" are 3; "-1" stays the sentinel.
                ageing[field] = value
                ageing[field + "_source"] = "OBSERVED"
            else:
                ageing[field] = None
                ageing[field + "_source"] = "MALFORMED"
                anomalies.append(_anomaly(model.ANOMALY_MALFORMED_RECORD,
                                          "%s is %s" % (field, why), number))
                rec["anomalies"].append(model.ANOMALY_MALFORMED_RECORD)
                # glibc rejects the whole line ("5x" measured): never trustworthy.
                if not rec["malformed"]:
                    malformed += 1
                    rec["malformed"] = True
        # Field 9 (reserved) is parsed by glibc as a number, and a line whose field 9 is
        # anything else - including the "\r" a CRLF edit leaves - is rejected. An account
        # with an active hash was reported locked from such a line (red team F1).
        if parts[8] != "":
            _value, why = _glibc_number(parts[8], signed=True)
            if why is not None:
                anomalies.append(_anomaly(model.ANOMALY_MALFORMED_RECORD,
                                          "the reserved field is %s" % why, number))
                rec["anomalies"].append(model.ANOMALY_MALFORMED_RECORD)
                if not rec["malformed"]:
                    malformed += 1
                    rec["malformed"] = True
        malformed += _empty_name(rec, parts, anomalies, number)
        rec["name"], rec["name_encoding"], rec["name_bytes_hex"], rec["name_non_ascii"] \
            = identifier(parts[0])
        rec["password_state"] = _password_state(parts[1])
        rec.update(ageing)
        records.append(rec)
    _duplicates(records, "name", None, anomalies)
    return ParsedSource(records, anomalies, len(records) + len(directives), malformed,
                        directives, directive_keys=keys)


def _password_state(raw):
    """Classify a crypt field WITHOUT retaining it.

    This function is the redaction boundary. Everything it is given may be a credential
    verifier; everything it returns is a small closed vocabulary plus, at most, the
    algorithm identifier. The salt and the digest are never returned, never stored and
    never rendered, so no caller can leak them by accident - there is nothing to leak.
    Reading a hash to describe it is not a reason to keep it.
    """
    lock = model.LOCK_PREFIX_ABSENT
    body = raw
    if body.startswith("!"):
        lock = model.LOCK_PREFIX_PRESENT
        body = body.lstrip("!")
    scheme = None
    if body == "":
        content = model.CONTENT_EMPTY
    elif body == "*":
        content = model.CONTENT_DISABLED_TOKEN
    else:
        match = _CRYPT.match(body)
        if match:
            content = model.CONTENT_HASH_PRESENT
            # A NORMALIZED identifier from a closed table, never the raw `$id$` token.
            # `$6$` says SHA-512 and `$1$` says MD5, which is a legitimate security fact a
            # later criterion needs - it is metadata about the verifier, not the verifier,
            # and authenticates nobody. But an UNRECOGNIZED id is an arbitrary string
            # lifted out of the credential field, and publishing it verbatim would leak
            # exactly the material this boundary exists to contain. Owner ruling: bounded
            # vocabulary only.
            scheme = model.HASH_SCHEMES.get(match.group(1),
                                            model.HASH_SCHEME_OTHER)
        else:
            content = model.CONTENT_OTHER
    return {"lock_prefix": lock, "content": content, "hash_scheme": scheme}
