# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: A pure sshd_config parser. Text plus an entry scope in, records out.
# Implements: SCOPE-022, SCOPE-045
#
# WHY THIS IS NOT S1.
#
# sshd accepts BOTH `Keyword value` and `Keyword=value`, and an S1 profile is either
# whitespace-delimited or delimiter-based, not both. A whitespace profile turns `Port=22`
# into the keyword `port=22` with no value; a `=` profile turns `Port 22` into a line with
# no delimiter. Either way the evidence is wrong and carries a digest proving which wrong
# grammar produced it.
#
# That is not an S1 defect. S1 expresses key/value formats correctly and sshd_config is
# not quite one - the same finding sudoers and limits.conf produced, from a different
# direction. Reported as a deliberate non-use.
#
# The second reason is Match. S1 returns a flat list of declarations and has no concept
# of a block, and scope is the thing this domain exists to preserve.
#
# Pure: no filesystem, no subprocess, no network.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""The sshd_config grammar, with Match scope preserved."""
import hashlib
import re

from .. import textbytes
from . import model

_SPLIT = re.compile(r"^(\S+?)(?:\s*=\s*|\s+)(.*)$")


GLOBAL_SCOPE = (model.GLOBAL, None, None)


def parse(text, source=None, start_ordinal=0, match_index_base=0,
          entry_scope=GLOBAL_SCOPE):
    """One sshd_config file, parsed under the scope it was entered with.

    Returns (records, malformed_count, next_match_index, scope_at_line).

    CORRECTED, SSH_INCLUDE_MATCH_CONTEXT_001. An earlier version started every file in
    GLOBAL scope, on the assumption that an included file cannot inherit a Match block.
    That is not OpenSSH behaviour, and the assumption was wrong in the dangerous
    direction: it reported conditional configuration as unconditional.

    sshd_config(5) states that Include may appear inside a Match block to perform
    conditional inclusion, and OpenSSH's parser saves the containing Match-active state,
    parses the included file under it, and restores it afterwards so the include cannot
    clobber the containing file. Verified against OpenSSH 10.2p1 with `sshd -T -C`:

        Match User alice / Include child ; child: PermitTTY no
            user=alice -> permittty no      the child inherited the Match
            user=bob   -> permittty yes     it did not apply

        Match User alice / Include child / AllowTcpForwarding no
        child contains its own `Match Group nosuchgroup`
            user=alice -> allowtcpforwarding no    parent scope restored on return
            user=bob   -> allowtcpforwarding yes   child's Match did not clobber it

    `scope_at_line` lets the caller give each included file the scope that was active at
    the Include directive, and restoration is structural: a child's scope changes live in
    the child's own parse and never travel back.
    """
    records, malformed = [], 0
    ordinal = start_ordinal
    match_index = match_index_base
    current_scope, current_criteria, current_index = entry_scope
    scope_at_line = {}

    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            # sshd has no inline comments. A '#' mid-line is part of the value, and
            # truncating there would silently change a cipher or key exchange list.
            continue
        base = {"source_path": source, "source_line": line_number, "ordinal": ordinal}
        ordinal += 1
        # Recorded BEFORE this line is interpreted, so an Include carries the scope it
        # was written in rather than any scope it goes on to establish.
        scope_at_line[line_number] = (current_scope, current_criteria, current_index)

        keyword_raw, value, ok = _split(line)
        if not ok:
            malformed += 1
            records.append(dict(base, kind=model.UNSUPPORTED,
                                raw_digest=_digest(line),
                                reason="line is not a keyword with a value"))
            continue

        if keyword_raw.lower() == "match":
            criteria = _criteria(value)
            if criteria is None:
                malformed += 1
                records.append(dict(base, kind=model.UNSUPPORTED,
                                    raw_digest=_digest(line),
                                    reason="Match block has no usable criteria"))
                continue
            current_scope = model.MATCH_SCOPE
            current_criteria = criteria
            current_index = match_index
            records.append(dict(base, kind=model.MATCH, criteria=criteria,
                                match_index=match_index))
            match_index += 1
            continue

        records.append(dict(base, kind=model.DIRECTIVE,
                            keyword=keyword_raw.lower(), keyword_raw=keyword_raw,
                            value=_unquote(value),
                            scope=current_scope,
                            match_index=current_index,
                            match_criteria=current_criteria))
    return records, malformed, match_index, scope_at_line


def _split(line):
    """`Keyword value` or `Keyword=value`. Returns (keyword, value, ok)."""
    match = _SPLIT.match(line)
    if not match:
        return line, None, False
    keyword, value = match.group(1), match.group(2).strip()
    keyword = keyword.rstrip("=")
    if not keyword or not value:
        return keyword or line, None, False
    return keyword, value, True


def _criteria(text):
    """`Match User a,b Address 10.0.0.0/8`, or `Match all`.

    Returns a list of {keyword, values, negated} or None when nothing usable is present.
    """
    tokens = text.split()
    criteria, index = [], 0
    while index < len(tokens):
        keyword = tokens[index].lower()
        if keyword in model.CRITERIA_WITHOUT_VALUE:
            criteria.append({"keyword": keyword, "values": [], "negated": False})
            index += 1
            continue
        if index + 1 >= len(tokens):
            break
        raw = tokens[index + 1]
        negated = raw.startswith("!")
        values = [v for v in (raw[1:] if negated else raw).split(",") if v]
        criteria.append({"keyword": keyword, "values": values, "negated": negated})
        index += 2
    return criteria or None


def _unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _digest(text):
    """An unparsed sshd_config line may carry a banner path, a key file or an address.
    It is the line we understand least, so its content is digested rather than kept."""
    return "sha256:" + hashlib.sha256(
        textbytes.original_bytes(text)).hexdigest()
