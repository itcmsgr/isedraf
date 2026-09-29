# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: A pure sudoers grammar parser. Text in, records out.
# Implements: SCOPE-022, SCOPE-045
#
# WHY THIS IS NOT S1.
#
# S1 parses key/value configuration and it is good at it. Sudoers is not that grammar.
# A user specification is `who where=(runas) tags: commands`, with comma lists at three
# levels, negation at four, and tags that apply from where they appear onward. Forcing
# that through a delimiter-and-profile model would mean inventing a key for something
# that has no key, and the result would be key/value-shaped evidence that a later
# consumer has to re-parse - which is how one grammar becomes three parsers.
#
# `Defaults env_keep += "A B"` does resemble a key/value assignment, and S1 could parse
# that one line. It is the only part that does, it arrives inside a comma list that S1
# has no concept of, and splitting the file between two parsers to reuse a primitive for
# one construct would cost more than it saves. Recorded as a deliberate non-use.
#
# S2, S4 and S5 ARE used, in acquire.py, because include resolution, file metadata and
# bounded enumeration are genuinely the same problems here as everywhere else.
#
# Pure: no filesystem, no subprocess, no network. Tested by inspection of this source.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Pure sudoers grammar: text -> policy records."""
import hashlib
import re

from .. import textbytes
from . import model

_ALIAS = re.compile(r"^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\s+(\S+)\s*=\s*(.*)$")
_DEFAULTS = re.compile(r"^Defaults(?:([:>@!])(\S+))?\s+(.*)$")
_SPEC = re.compile(r"^(.+?)\s+([^\s=]+)\s*=\s*(.*)$")
_OPTION = re.compile(r"^(!?)([A-Za-z_][A-Za-z0-9_]*)\s*(\+=|-=|=)?\s*(.*)$")


def parse(text, source=None, start_ordinal=0):
    """One sudoers file. Returns (records, malformed_count).

    Records carry their source path and line. Nothing is resolved: an alias reference is
    recorded as written, because whether it resolves is a later layer's question and an
    invented empty membership would hide a broken policy.
    """
    records, malformed = [], 0
    ordinal = start_ordinal
    for line_number, line, continued in _logical_lines(text):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            # `#include` and `#includedir` are directives, not comments. They are handled
            # by the include adapter in acquire.py; here they are simply not records.
            continue
        record = _line(stripped, source, line_number, ordinal, continued)
        if record["kind"] == model.UNSUPPORTED:
            malformed += 1
        records.append(record)
        ordinal += 1
    return records, malformed


def _logical_lines(text):
    physical = text.splitlines()
    index = 0
    while index < len(physical):
        start = index + 1
        line = physical[index]
        continued = False
        while line.endswith("\\") and index + 1 < len(physical):
            line = line[:-1] + " " + physical[index + 1].strip()
            index += 1
            continued = True
        index += 1
        yield start, line.rstrip("\\"), continued


def _base(kind, source, line_number, ordinal, continued):
    return {"kind": kind, "source_path": source, "source_line": line_number,
            "ordinal": ordinal, "continued": continued}


def _line(text, source, line_number, ordinal, continued):
    record = _base(model.UNSUPPORTED, source, line_number, ordinal, continued)

    match = _ALIAS.match(text)
    if match:
        record["kind"] = model.ALIAS
        record["alias_type"] = model.ALIAS_TYPES[match.group(1)]
        record["name"] = match.group(2)
        record["members"] = [_negatable(m) for m in _split(match.group(3))]
        return record

    match = _DEFAULTS.match(text)
    if match:
        sigil, scope, body = match.group(1), match.group(2), match.group(3)
        record["kind"] = model.DEFAULTS
        record["scope_type"] = (model.SCOPE_SIGILS[sigil] if sigil
                                else model.SCOPE_GLOBAL)
        record["scope"] = scope
        record["options"] = [o for o in (_option(part) for part in _split(body)) if o]
        return record

    match = _SPEC.match(text)
    if match:
        principals, host, rest = match.group(1), match.group(2), match.group(3)
        runas_users, runas_groups, commands = _runas_and_commands(rest)
        record["kind"] = model.SPEC
        record["principals"] = [_principal(p) for p in _split(principals)]
        record["host"] = _negatable(host)
        record["runas_users"] = runas_users
        record["runas_groups"] = runas_groups
        record["commands"] = commands
        return record

    # Unparsed. The content is DIGESTED rather than retained: a sudoers line names
    # commands, hosts and arguments, and a line we could not understand is exactly the
    # one whose contents we are least entitled to publish.
    record["raw_digest"] = "sha256:" + hashlib.sha256(
        textbytes.original_bytes(text)).hexdigest()
    record["reason"] = "line does not match any known sudoers construct"
    return record


def _runas_and_commands(rest):
    """`(runas)` is optional. Absent means sudo would default to root - that default is
    RESOLUTION, so the parser records that the source did not specify it."""
    runas_users = runas_groups = None
    rest = rest.strip()
    if rest.startswith("("):
        close = rest.find(")")
        if close != -1:
            inside = rest[1:close]
            rest = rest[close + 1:].strip()
            users, _, groups = inside.partition(":")
            runas_users = [_negatable(u) for u in _split(users)] if users.strip() else []
            runas_groups = ([_negatable(g) for g in _split(groups)]
                            if groups.strip() else None)
    return runas_users, runas_groups, _commands(rest)


def _commands(text):
    """Tags apply from where they appear ONWARD, which is why they accumulate."""
    commands, active = [], []
    for part in _split(text):
        while True:
            tag_match = re.match(r"^([A-Z_]+)\s*:\s*(.*)$", part)
            if tag_match and tag_match.group(1) in model.TAGS:
                active.append(tag_match.group(1))
                part = tag_match.group(2).strip()
                continue
            break
        if not part:
            continue
        item = _negatable(part)
        commands.append({"command": item["value"], "negated": item["negated"],
                         "tags": list(active)})
    return commands


def _option(text):
    match = _OPTION.match(text.strip())
    if not match:
        return None
    negated, name, operator, value = match.groups()
    return {"name": name, "operator": operator or None,
            "value": _unquote(value.strip()) if value.strip() else None,
            "negated": negated == "!"}


def _principal(text):
    item = _negatable(text)
    value, kind = item["value"], model.USER
    if value == "ALL":
        kind = model.ALL
    elif value.startswith("%:"):
        kind, value = model.NONUNIX_GROUP, value[2:]
    elif value.startswith("%#"):
        kind, value = model.GROUP_ID, value[2:]
    elif value.startswith("%"):
        kind, value = model.GROUP, value[1:]
    elif value.startswith("+"):
        kind, value = model.NETGROUP, value[1:]
    elif value.startswith("#"):
        kind, value = model.USER_ID, value[1:]
    elif value.isupper() and value.replace("_", "").isalnum():
        # Convention, not proof: sudoers aliases are upper-case by requirement, but an
        # upper-case name may simply be a user. Recorded as a reference, never resolved.
        kind = model.ALIAS_REFERENCE
    return {"value": value, "kind": kind, "negated": item["negated"]}


def _negatable(text):
    """A dropped `!` inverts a policy. It is stripped from the value and kept as a fact."""
    text = text.strip()
    negated = False
    while text.startswith("!"):
        negated = not negated
        text = text[1:].strip()
    return {"value": text, "negated": negated}


def _split(text):
    """Comma-separated, respecting quotes and parentheses."""
    parts, current, depth, quote = [], [], 0, None
    for character in text:
        if quote:
            current.append(character)
            if character == quote:
                quote = None
            continue
        if character in "\"'":
            quote = character
            current.append(character)
        elif character == "(":
            depth += 1
            current.append(character)
        elif character == ")":
            depth -= 1
            current.append(character)
        elif character == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


def _unquote(text):
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text
