# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Parse key/value configuration without deciding what the configuration means.
# Implements: SCOPE-022, SCOPE-045, GOV-001
#
# login.defs, pwquality.conf, faillock.conf, limits.conf, journald.conf, resolved.conf and
# a dozen others are all "key value" and no two agree on what that means. The delimiter is
# `=` or whitespace or both. `#` may start a comment anywhere or only at the start of a
# line. Quotes may be literal or stripped. A trailing backslash may continue a line or be
# part of the value. A repeated key may mean last-wins, first-wins, or accumulate.
#
# So the profile carries the grammar and the PARSER PRESERVES DECLARATIONS. It does not
# compute an effective value, and it does not collapse duplicates - that is resolution, it
# is domain semantics, and doing it here would destroy the evidence a later resolver needs
# to explain itself.
#
#   PermitRootLogin yes
#   PermitRootLogin no
#
# Both declarations are recorded, in order, with their line numbers. Whichever one a domain
# decides wins, the report can then show the operator the other one and where it lives.
# A parser that returned {"PermitRootLogin": "no"} has thrown that away.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""A key/value parsing framework driven by a per-format profile."""
import re

from .. import textbytes
from . import result

# --- what a repeated key MEANS, recorded and never applied here --------------------------
# The profile declares it so a later resolver knows which rule to apply and the report can
# say which rule it applied. The parser itself keeps every declaration regardless.
LAST_WINS = "LAST_WINS"
FIRST_WINS = "FIRST_WINS"
ACCUMULATE = "ACCUMULATE"
DUPLICATE_UNSPECIFIED = "DUPLICATE_UNSPECIFIED"

# --- what an empty value MEANS, likewise recorded ----------------------------------------
EMPTY_IS_VALUE = "EMPTY_IS_VALUE"        # `Key=` sets it to the empty string
EMPTY_IS_UNSET = "EMPTY_IS_UNSET"        # `Key=` resets it to the built-in default
EMPTY_UNSPECIFIED = "EMPTY_UNSPECIFIED"

# --- anomalies this parser can produce ----------------------------------------------------
NO_DELIMITER = "NO_DELIMITER"
UNTERMINATED_CONTINUATION = "UNTERMINATED_CONTINUATION"
UNDECODABLE_LINE = "UNDECODABLE_LINE"
DUPLICATE_KEY = "DUPLICATE_KEY"


class Profile(object):
    """One format's grammar. Every field is a statement about syntax, not about security."""

    name = "profile"

    #: Characters that separate key from value. Whitespace is expressed as None, meaning
    #: "split on the first run of whitespace", which is how sshd_config and login.defs work.
    delimiters = ("=",)
    whitespace_delimited = False

    #: A line whose first non-blank character is one of these is a comment.
    comment_markers = ("#",)
    #: Whether a marker part-way through a line starts a comment. Getting this wrong
    #: truncates values silently and plausibly: cipher suite names and URL fragments both
    #: carry characters a comment marker would cut at, so a parser that treats `#` as
    #: inline in a format that does not would turn `pattern = a#b` into `a` and report it
    #: with complete confidence.
    inline_comments = False

    #: A trailing backslash continues onto the next line.
    allow_continuation = False

    #: Keys compared case-insensitively. sshd_config is case-insensitive for keywords;
    #: login.defs is not. `key` keeps the normalized form, `key_raw` keeps what was written.
    case_insensitive_keys = False

    #: Strip one layer of matching quotes from the value.
    strip_quotes = False

    #: `[section]` headers, as in some *.conf families.
    section_pattern = None

    duplicate_policy = DUPLICATE_UNSPECIFIED
    empty_value_policy = EMPTY_UNSPECIFIED

    #: Bumped by the domain when the grammar's MEANING changes in a way the digest below
    #: cannot see - a change to retention() or normalize_key(), for instance.
    version = 1

    #: The grammar fields that decide how bytes become declarations. Everything listed
    #: here feeds the identity digest.
    GRAMMAR_FIELDS = ("delimiters", "whitespace_delimited", "comment_markers",
                      "inline_comments", "allow_continuation", "case_insensitive_keys",
                      "strip_quotes", "section_pattern", "duplicate_policy",
                      "empty_value_policy", "version")

    def grammar_identity(self):
        """A stable identity for the CONTRACT that produced a set of declarations.

        Without this, a grammar change is indistinguishable from a host change. Two
        profiles sharing a name but differing in `inline_comments` turn the same bytes
        into different values, and a baseline comparing the two would report configuration
        drift on a host where nothing moved. The engine already refuses to let a collector
        version change masquerade as drift; this is the same rule one level down.

        The digest is derived from the grammar FIELDS rather than hand-maintained, so it
        cannot drift from the behaviour it describes: editing the grammar changes the
        digest whether or not anyone remembered to bump `version`.
        """
        fields = {}
        for name in self.GRAMMAR_FIELDS:
            value = getattr(self, name, None)
            fields[name] = list(value) if isinstance(value, tuple) else value
        return {"profile": self.name, "version": self.version,
                "grammar_digest": _digest(fields), "grammar": fields}

    def retention(self, key):
        """Retention policy for this key's value. Default: keep it.

        A format with credentials in it - a repository URL, a bind password - overrides
        this per key so the value never reaches a record in the first place. Scrubbing
        after the fact is the wrong order.
        """
        del key
        return result.RETAIN_VALUE

    def normalize_key(self, key):
        return key.lower() if self.case_insensitive_keys else key


def parse(text, profile, source=None):
    """Text plus a grammar in; declarations out, in file order.

    Nothing is resolved, nothing is de-duplicated, nothing is sorted. Every declaration
    the file made is a record, and a line that could not be understood is a record too,
    carrying its anomaly rather than vanishing.
    """
    records, anomalies = [], []
    section = None
    ordinal = 0
    malformed = 0

    for line_number, raw_line, continued in _logical_lines(text, profile, anomalies):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(m) for m in profile.comment_markers):
            continue

        if profile.section_pattern is not None:
            match = re.match(profile.section_pattern, stripped)
            if match:
                section = match.group(1)
                continue

        body = _strip_inline_comment(stripped, profile)
        key_raw, value_raw, found = _split(body, profile)
        record = {"ordinal": ordinal, "source_line": line_number, "source_path": source,
                  "section": section, "continued": continued, "anomalies": []}
        ordinal += 1

        if not found:
            # A line with no delimiter is not a declaration. It is retained so the reader
            # can see there was something there, and it is counted.
            malformed += 1
            record.update({"key": None, "key_raw": key_raw, "value": None,
                           "retention": None, "malformed": True})
            record["anomalies"].append(NO_DELIMITER)
            anomalies.append(result.anomaly(
                result.ANOMALY_MALFORMED, "line has no %s delimiter"
                % ("whitespace" if profile.whitespace_delimited else "key/value"),
                source_path=source, source_line=line_number))
            records.append(record)
            continue

        if textbytes.has_surrogates(key_raw) or textbytes.has_surrogates(value_raw):
            # Same rule as an account name: a value that is not valid UTF-8 is not quietly
            # turned into one. The caller sees that it could not be decoded.
            record["anomalies"].append(UNDECODABLE_LINE)
            anomalies.append(result.anomaly(
                result.ANOMALY_MALFORMED, "line is not valid UTF-8",
                source_path=source, source_line=line_number))

        value = _dequote(value_raw, profile)
        stored, retention = result.retained(value, profile.retention(
            profile.normalize_key(key_raw)))
        record.update({"key": profile.normalize_key(key_raw), "key_raw": key_raw,
                       "value": stored, "retention": retention, "malformed": False,
                       "empty": value == ""})
        records.append(record)

    _mark_duplicates(records, anomalies, source)
    status, reason = _status(records, malformed, source)
    return result.Evidence(
        status, records=records, reason=reason, source=source, anomalies=anomalies,
        provenance=dict(profile.grammar_identity(),
                        declaration_count=len(records),
                        malformed_count=malformed))


def _logical_lines(text, profile, anomalies):
    """Yield (line_number, text, continued). Continuations are joined if the profile says so."""
    physical = text.splitlines()
    index = 0
    while index < len(physical):
        start = index + 1
        line = physical[index]
        continued = False
        if profile.allow_continuation:
            while line.endswith("\\") and index + 1 < len(physical):
                line = line[:-1] + physical[index + 1]
                index += 1
                continued = True
            if line.endswith("\\"):
                # The file ended mid-continuation. Recorded, not silently accepted: the
                # value we hold is not the value the author wrote.
                anomalies.append(result.anomaly(
                    result.ANOMALY_MALFORMED,
                    "file ends with an unterminated line continuation",
                    source_line=start))
                line = line[:-1]
        index += 1
        yield start, line, continued


def _strip_inline_comment(line, profile):
    if not profile.inline_comments:
        return line
    cut = len(line)
    for marker in profile.comment_markers:
        found = line.find(marker)
        if found != -1:
            cut = min(cut, found)
    return line[:cut].rstrip()


def _split(body, profile):
    """Return (key, value, found). `found` is False when there is no delimiter at all."""
    if profile.whitespace_delimited:
        parts = body.split(None, 1)
        if len(parts) == 2:
            return parts[0], parts[1].strip(), True
        # A bare keyword with no value. Whether that is legal is the domain's business;
        # syntactically the delimiter is absent.
        return body, None, False
    best = None
    for delimiter in profile.delimiters:
        found = body.find(delimiter)
        if found != -1 and (best is None or found < best[1]):
            best = (delimiter, found)
    if best is None:
        return body, None, False
    delimiter, position = best
    return (body[:position].strip(), body[position + len(delimiter):].strip(), True)


def _dequote(value, profile):
    if value is None or not profile.strip_quotes or len(value) < 2:
        return value
    if value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _mark_duplicates(records, anomalies, source):
    """Record repetition. Deliberately does NOT resolve it.

    Which declaration wins is the domain's rule, applied later by a resolver that can
    explain itself. Collapsing here would leave that resolver nothing to explain.
    """
    first = {}
    for record in records:
        key = record.get("key")
        if key is None:
            continue
        scoped = (record.get("section"), key)
        if scoped in first:
            record["duplicate_of"] = first[scoped]
            record["anomalies"].append(DUPLICATE_KEY)
            anomalies.append(result.anomaly(
                result.ANOMALY_DUPLICATE,
                "%s is declared more than once" % key,
                source_path=source, source_line=record["source_line"],
                first_line=first[scoped]))
        else:
            first[scoped] = record["source_line"]


def _status(records, malformed, source):
    """SCOPE-022. Same boundary the account contract froze.

    An unknown key is EVIDENCE, not a parser error: a format gains options over time and a
    collector that errored on an option it had not heard of would fail on every host newer
    than itself. Only a line that is not a declaration at all counts as malformed.
    """
    if not records:
        return result.COLLECTED, None
    if malformed and malformed == len(records):
        return result.ERROR, (
            "UNPARSEABLE: no line in %s could be read as a declaration; no trustworthy "
            "normalized interpretation can be produced." % (source or "the source"))
    if malformed:
        return result.PARTIAL, (
            "MALFORMED_RECORDS: %d of %d lines in %s could not be read as declarations "
            "and are retained as anomalies."
            % (malformed, len(records), source or "the source"))
    return result.COLLECTED, None


def _digest(fields):
    """Deterministic across every supported interpreter.

    Reuses the project's canonical serializer rather than inventing a second deterministic
    encoding - NORM-035 already froze the byte-level answer, and two encodings would be
    two things to keep in agreement.
    """
    from .. import canonical
    import hashlib
    return "sha256:" + hashlib.sha256(
        canonical.canonical_bytes(fields)).hexdigest()
