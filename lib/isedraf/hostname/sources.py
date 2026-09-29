# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Parse /etc/hostname and compare it with the kernel hostname, exactly.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022
#
# NSS_HOSTNAME_LANE_CONTRACT.md §6 and hostname(5). One trailing newline is stripped and
# recorded; every other character is kept. The comparison is exact, and the two
# transformations systemd documents on apply - "?" template substitution and invalid-
# character filtering - are named NOT_COMPARABLE rather than compared into a false
# DIFFERENT.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Hostname parser and comparison. Pure: text in, facts out."""
from .. import textbytes
from . import model


def parse_hostname_file(text):
    """The declared name, with what hostname(5) permits skipped and nothing else changed."""
    trailing = text.endswith("\n")
    lines = text.split("\n")
    if trailing:
        lines = lines[:-1]
    names = [(n, line) for n, line in enumerate(lines, start=1)
             if line != "" and not line.startswith("#")]
    anomalies = []
    if not names:
        return {"state": model.EMPTY, "value": None, "trailing_newline": trailing,
                "anomalies": anomalies}
    if len(names) > 1:
        anomalies.append({"anomaly": model.ANOMALY_MULTIPLE,
                          "detail": "%d names at lines %s" % (
                              len(names), ", ".join(str(n) for n, _ in names)),
                          "line": names[1][0]})
        # Retained, as MALFORMED promises: every candidate line, exactly (pass 2, #11).
        return {"state": model.MALFORMED, "value": None, "trailing_newline": trailing,
                "anomalies": anomalies,
                "lines": [line if not textbytes.has_surrogates(line) else None
                          for _, line in names],
                "lines_bytes_hex": [textbytes.hex_of(line) for _, line in names]}
    number, value = names[0]
    if textbytes.has_surrogates(value):
        anomalies.append({"anomaly": model.ANOMALY_UNDECODABLE,
                          "detail": "the name is not valid UTF-8", "line": number})
        # The exact bytes are the evidence; a replacement character would be another name.
        return {"state": model.MALFORMED, "value": None, "trailing_newline": trailing,
                "anomalies": anomalies, "value_bytes_hex": textbytes.hex_of(value)}
    if value != value.strip():
        anomalies.append({"anomaly": model.ANOMALY_WHITESPACE,
                          "detail": "the name carries surrounding whitespace, which "
                                    "hostname(5) does not define", "line": number})
    return {"state": model.PRESENT, "value": value, "trailing_newline": trailing,
            "anomalies": anomalies}


def parse_kernel_hostname(text):
    """(value, value_bytes_hex). One trailing newline is not the name.

    An undecodable name is kept as its exact bytes and never replaced: a surrogate cannot
    be serialized canonically, and a substitute character would be a different name
    (red team F8).
    """
    value = text[:-1] if text.endswith("\n") else text
    if textbytes.has_surrogates(value):
        return None, textbytes.hex_of(value)
    return value, None


def _valid_dns_name(value):
    """hostname(5): a valid DNS domain name, at most 64 characters (the kernel's limit).

    Only the shape hostname(5) names is tested: non-empty labels that neither begin nor end
    with a hyphen. A name outside it is cleaned when applied, and the cleaning is not
    emulated, so such a name is not compared (red team F10).
    """
    if len(value) > model.KERNEL_NAME_LIMIT:
        return False
    return all(label and not label.startswith("-") and not label.endswith("-")
               for label in value.split("."))


def compare(declared, active):
    """(relation, reason). Exact, with every uncomparable case named."""
    if active.get("value") is None:
        return model.NOT_COMPARABLE, "the active hostname could not be read or decoded"
    state = declared.get("state")
    if state == model.ABSENT:
        return model.NOT_COMPARABLE, "the declared hostname file is absent"
    if state == model.EMPTY:
        return model.NOT_COMPARABLE, "the declared hostname file names no host"
    if state == model.MALFORMED:
        return model.NOT_COMPARABLE, "the declared hostname file is malformed"
    if state != model.PRESENT:
        # Unreadable, a directory, outside the root: never a crash (red team F7).
        return model.NOT_COMPARABLE, "the declared hostname could not be read"
    value = declared["value"]
    if declared.get("anomalies"):
        return model.NOT_COMPARABLE, ("the declared name carries whitespace, and how it "
                                      "is applied is not defined")
    if model.TEMPLATE_CHARACTER in value:
        return model.NOT_COMPARABLE, ("the declared name is a template: \"?\" is "
                                      "substituted from machine-id(5) when applied, and "
                                      "that substitution is not emulated")
    if any(c not in model.APPLIED_UNCHANGED for c in value):
        return model.NOT_COMPARABLE, ("the declared name contains characters hostname(5) "
                                      "says are filtered out when applied, and that "
                                      "filtering is not emulated")
    if not _valid_dns_name(value):
        return model.NOT_COMPARABLE, ("the declared name is not a valid DNS name of at most "
                                      "%d characters, and hostname(5) says such a name is "
                                      "cleaned when applied; that cleaning is not emulated"
                                      % model.KERNEL_NAME_LIMIT)
    return (model.EQUAL if value == active["value"] else model.DIFFERENT), None
