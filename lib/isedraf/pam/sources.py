# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: A pure pam.d grammar parser. Text in, rules out.
# Implements: SCOPE-022, SCOPE-045
#
# WHY THIS IS NOT S1. A PAM line is `type control module [args]` - four positional
# elements where the third is the value-bearing one and the second may itself be a
# bracketed expression containing `=` signs. There is no key and no delimiter, and a
# key/value profile would take `auth required pam_unix.so try_first_pass` and find
# whatever the profile's delimiter happened to hit first.
#
# The fourth domain to decline S1, for the fourth distinct reason. That consistency is
# the evidence the boundary is real.
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

"""The pam.d positional grammar, including bracketed control expressions."""
import hashlib

from .. import textbytes
from . import model


def parse(text, service, source=None, start_ordinal=0, depth=0):
    """One pam.d service file. Returns (records, malformed_count)."""
    records, malformed = [], 0
    ordinal = start_ordinal
    for line_number, line in _logical_lines(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        base = {"service": service, "source_path": source,
                "source_line": line_number, "ordinal": ordinal, "depth": depth}
        ordinal += 1
        record = _rule(stripped, base)
        if record["kind"] == model.UNSUPPORTED:
            malformed += 1
        records.append(record)
    return records, malformed


def _logical_lines(text):
    physical = text.splitlines()
    index = 0
    while index < len(physical):
        start = index + 1
        line = physical[index]
        while line.endswith("\\") and index + 1 < len(physical):
            line = line[:-1] + " " + physical[index + 1].strip()
            index += 1
        index += 1
        yield start, line.rstrip("\\")


def _rule(text, base):
    tokens = text.split()
    if len(tokens) < 2:
        return dict(base, kind=model.UNSUPPORTED, raw_digest=_digest(text),
                    reason="line has too few fields to be a PAM rule")

    raw_type = tokens[0]
    silent = raw_type.startswith("-")
    rule_type = raw_type[1:] if silent else raw_type
    if rule_type.lower() not in model.TYPES:
        return dict(base, kind=model.UNSUPPORTED, raw_digest=_digest(text),
                    reason="first field is not a PAM rule type")

    rest = text.split(None, 1)[1].strip()
    control, actions, rest, ok = _control(rest)
    if not ok:
        return dict(base, kind=model.UNSUPPORTED, raw_digest=_digest(text),
                    reason="control field could not be parsed")

    remainder = rest.split()
    if control in (model.INCLUDE, model.SUBSTACK):
        if not remainder:
            return dict(base, kind=model.UNSUPPORTED, raw_digest=_digest(text),
                        reason="%s names no target service" % control)
        return dict(base, kind=model.EDGE, type=rule_type.lower(),
                    silent_if_missing=silent, edge=control,
                    target_service=remainder[0])

    if not remainder:
        return dict(base, kind=model.UNSUPPORTED, raw_digest=_digest(text),
                    reason="rule names no module")
    return dict(base, kind=model.RULE, type=rule_type.lower(),
                silent_if_missing=silent, control=control,
                control_actions=actions, module=remainder[0],
                arguments=remainder[1:])


def _control(text):
    """Simple keyword or bracketed expression. Returns (control, actions, rest, ok)."""
    if text.startswith("["):
        close = text.find("]")
        if close == -1:
            return None, None, text, False
        inside = text[1:close]
        actions = []
        for token in inside.split():
            if "=" not in token:
                # A bracketed control is a list of condition=action pairs. A bare token
                # inside one is not a form PAM defines, and guessing which half is
                # missing would invent a rule the host does not have.
                return None, None, text, False
            condition, _, action = token.partition("=")
            # A numeric action is a JUMP - skip this many rules - and stays numeric,
            # because "1" and "ignore" are different kinds of thing.
            actions.append({"condition": condition,
                            "action": int(action) if action.lstrip("-").isdigit()
                            else action})
        if not actions:
            return None, None, text, False
        return model.BRACKETED, actions, text[close + 1:].strip(), True

    parts = text.split(None, 1)
    control = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ""
    if control not in model.SIMPLE_CONTROLS + (model.INCLUDE, model.SUBSTACK):
        return None, None, text, False
    return control, None, rest, True


def _digest(text):
    """An unparsed PAM line may name a module path or arguments carrying a file location.
    It is the line we understand least, so its content is digested rather than kept."""
    return "sha256:" + hashlib.sha256(
        textbytes.original_bytes(text)).hexdigest()
