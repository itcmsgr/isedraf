# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Parse /etc/nsswitch.conf into ordered services with their action clauses.
# Implements: IDENT-040, CMP-020, SCOPE-022
#
# NSS_HOSTNAME_LANE_CONTRACT.md §2. Order is the query order and an action clause changes
# resolver behaviour, so a database line is an ordered list of services, each carrying the
# actions that follow it - never a set of provider names. What this parser cannot fully
# interpret is kept verbatim and marked UNSUPPORTED, never normalized into something it
# is not.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""nsswitch.conf(5) parser. Pure: text in, records out."""
import re

from .. import textbytes
from . import model


class ParsedNsswitch(object):
    """Records in file order, and what was wrong with the file."""

    __slots__ = ("records", "anomalies")

    def __init__(self, records, anomalies):
        self.records = records
        self.anomalies = anomalies


# glibc splits nsswitch.conf on "\n" only and treats these as whitespace inside a line.
# str.splitlines() also breaks on \f, \v, \r and more, which hid "sss" in
# "passwd: files\fsss" and made that topology hash like plain "files" (red team F1).
_WHITESPACE = " \t\f\v\r"
# Blanks are ASCII only: Python's \s is Unicode, and glibc rejects "[\x1cX=Y]" and
# "[X\xa0=Y]" (red team pass 2, #3). "!" must be followed directly by the STATUS:
# glibc 2.43 rejects "[! X=Y]" and accepts "[ !X=Y]" and "[!X =Y]".
# The ACTION ends at a blank or the end of the bracket: glibc reads it up to blank, "="
# or "]", so "[X=return!Y=return]" is one invalid action, not two pairs (pass 3, F3).
_PAIR = re.compile(r"[ \t\f\v\r]*(!?)([A-Za-z]+)[ \t\f\v\r]*=[ \t\f\v\r]*([A-Za-z]+)"
                   r"(?=[ \t\f\v\r]|$)")


def _anomaly(kind, detail, line):
    return {"anomaly": kind, "detail": detail, "line": line}


def _tokens(text):
    """Split a service list into words and whole bracket groups, in order.

    Returns (tokens, problem). A bracket group may hold several STATUS=ACTION pairs and
    spaces, so it is one token. An unclosed bracket is reported, not repaired.
    """
    tokens, word, i, problem = [], "", 0, None
    while i < len(text):
        c = text[i]
        if c == "[":
            if word:
                tokens.append(word)
                word = ""
            end = text.find("]", i)
            if end < 0:
                # Keep reading the words after it: an unclosed bracket must not hide the
                # services that follow (red team pass 2, #4). Iteratively: recursing once
                # per unclosed bracket raised RecursionError on ~1000 of them (pass 3, F5).
                problem = "an action bracket is never closed"
                i += 1
                continue
            tokens.append(text[i:end + 1])
            i = end + 1
            continue
        if c in _WHITESPACE:
            if word:
                tokens.append(word)
                word = ""
        else:
            word += c
        i += 1
    if word:
        tokens.append(word)
    return tokens, problem


def _actions(bracket):
    """[STATUS=ACTION ...] -> (actions, problems). Keywords are case-insensitive.

    Blanks around "!", "=" and the brackets are accepted: glibc treats
    "[ NOTFOUND = return ]" exactly as "[NOTFOUND=return]", and "[! NOTFOUND=return]" is
    negated (red team F11). Anything the pair grammar does not consume is unsupported.
    """
    actions, problems = [], []
    body = bracket[1:-1]
    if not body.strip(_WHITESPACE):
        return actions, ["an empty action bracket"]
    pos = 0
    while pos < len(body):
        if not body[pos:].strip(_WHITESPACE):
            break
        m = _PAIR.match(body, pos)
        if not m:
            problems.append("action text %r is not STATUS=ACTION" % body[pos:].strip())
            break
        negated, status, action = m.group(1) == "!", m.group(2).lower(), m.group(3).lower()
        if status not in model.STATUSES or action not in model.ACTIONS:
            problems.append("action %r does not use a documented STATUS and ACTION"
                            % m.group(0).strip())
        else:
            actions.append({"negated": negated, "status": status, "action": action})
        pos = m.end()
    return actions, problems


def _text(value):
    """A string that is safe for canonical bytes: itself, or None plus its exact bytes."""
    if textbytes.has_surrogates(value):
        return None, textbytes.hex_of(value)
    return value, None


def parse_nsswitch(text):
    records, anomalies = [], []
    for number, line in enumerate(text.split("\n"), start=1):
        unsupported = []
        if "\x00" in line:
            # glibc stops reading a line at NUL (red team pass 2, #12).
            line = line.split("\x00", 1)[0]
            unsupported.append("a NUL byte ends the line for glibc")
        content = line.split("#", 1)[0].strip(_WHITESPACE)
        if not content:
            continue
        database, sep, rest = content.partition(":")
        if not sep or any(c in database.strip(_WHITESPACE) for c in _WHITESPACE):
            # glibc honours "passwd files" (red team F3) and "passwd sss x:y", whose colon
            # comes after the service (pass 2, #4). The database name ends at the first
            # ASCII blank; str.split() would also split on "\x1c", which glibc does not.
            first = content
            for c in _WHITESPACE:
                first = first.replace(c, " ")
            head, _, _ = first.partition(" ")
            database, rest = content[:len(head)], content[len(head):]
            unsupported.append("no colon after the database name")
        database = database.strip(_WHITESPACE)
        # glibc skips the whole run of blanks and colons after the database name, so
        # "passwd::sss" is sss, not a service called ":sss" (pass 3, F4).
        rest = rest.lstrip(_WHITESPACE + ":")
        if not database or any(c in database for c in _WHITESPACE):
            anomalies.append(_anomaly(model.ANOMALY_NO_DATABASE,
                                      "no database name on line %d" % number, number))
            continue
        if textbytes.has_surrogates(content):
            unsupported.append("the line is not valid UTF-8")
        tokens, problem = _tokens(rest)
        if problem:
            unsupported.append(problem)
        entries, previous_bracket = [], False
        for token in tokens:
            if token.startswith("["):
                actions, problems = _actions(token)
                unsupported.extend(problems)
                if not entries:
                    unsupported.append("an action bracket precedes every service")
                elif previous_bracket:
                    # glibc stops parsing at a second consecutive bracket; merging it into
                    # the first made two behaviours share a digest (red team F2).
                    unsupported.append("a second action bracket follows the first")
                else:
                    entries[-1]["actions"].extend(actions)
                previous_bracket = True
                continue
            previous_bracket = False
            service, service_hex = _text(token)
            entry = {"service": service,
                     "class": model.classify(service) if service else model.UNKNOWN,
                     "actions": []}
            if service_hex:
                entry["service_bytes_hex"] = service_hex
            entries.append(entry)
        if not entries:
            unsupported.append("no service is listed")
        for reason in unsupported:
            anomalies.append(_anomaly(model.ANOMALY_UNSUPPORTED, reason, number))
        db_text, db_hex = _text(database)
        raw_text, raw_hex = _text(content)
        record = {
            "database": db_text,
            "line": number,
            "raw": raw_text,
            "entries": entries,
            "semantics": model.UNSUPPORTED if unsupported else model.KNOWN,
            "unsupported": unsupported,
        }
        if db_hex:
            record["database_bytes_hex"] = db_hex
        if raw_hex:
            record["raw_bytes_hex"] = raw_hex
        records.append(record)
    seen = {}
    for rec in records:
        key = rec["database"]
        if key is None:
            continue
        if key in seen:
            anomalies.append(_anomaly(
                model.ANOMALY_DUPLICATE,
                "%r is declared at lines %d and %d; which one glibc honours is not "
                "asserted" % (key, seen[key], rec["line"]), rec["line"]))
        else:
            seen[key] = rec["line"]
    return ParsedNsswitch(records, anomalies)
