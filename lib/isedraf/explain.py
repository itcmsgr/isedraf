# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Render one native criterion record - `isedraf explain` and the generated page.
# Implements: D-77, D-80, D-111, EVAL-001, EVAL-009
#
# Pure: a record in, lines out. The CLI prints them; scripts/docs/criteria_pages.py writes
# the same lines as the generated documentation page, so the two can never say different
# things (EVAL-009: one record, every surface). No state root, no evidence, no evaluation.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""EVAL-009: explaining a criterion is rendering its record."""
from isedraf.summary import wrap


LIFECYCLE = "EXPERIMENTAL"          # D-80: every control in the prototype
NO_HISTORY = "not available: baseline and delta are v0.4"


def _items(value):
    return value if isinstance(value, list) else [value]


def lines(c):
    """The explanation of one criterion record, as a list of text lines.

    v0.5 terminal rule (owner, 2026-11-20): every line fits 80 columns; prose wraps, and an
    artifact path, a JSON pointer or a command is never split - a pointer gets its own line."""
    sem = c["evaluation_semantics"]
    out = ["%s  (version %d, %s)" % (c["criterion_id"], c["version"], LIFECYCLE), "",
           "Purpose"] + wrap("  ", c["purpose"], 2) + ["", "Why it matters"]
    out += wrap("  ", c["rationale"], 2) + [""]
    out += wrap("Check type      ", c["check_type"], 16)
    out += wrap("Severity        ", "%s (default_severity; a FAIL finding takes it unchanged)"
                % c["default_severity"], 16)
    out += wrap("Applicability   ", c["applicability"], 16) + ["", "Facts required"]
    for f in _items(c["facts_required"]):
        out += wrap("  - ", f, 4)
    out += ["", "Dimensions"]
    for name in ("declared", "resolved", "active"):
        if isinstance(c["dimensions"], dict) and name in c["dimensions"]:
            out += wrap("  %-9s " % name, c["dimensions"][name], 12)
    out += ["", "How it is evaluated"] + wrap("  Input: ", sem["input"], 4)
    out.append("  Evidence is sufficient when:")
    for s in sem["evidence_sufficient_when"]:
        out += wrap("    - ", s, 6)
    out.append("  Results:")
    for rule in sem["rules"]:
        out += wrap("    %-14s " % rule["result"], rule["when"], 19)
    out += wrap("  Never produced: ", ", ".join(sem.get("never_produced", [])), 4)
    out += wrap("  ", sem["determinism"], 2)
    out += ["", "Limitations - what a result does not establish"]
    for s in _items(c["limitations"]):
        out += wrap("  - ", s, 4)
    out += ["", "Evidence pointers"]
    for p in c["evidence_pointers"]:
        out.append("  - %s" % p["artifact"])
        out.append("      %s" % p["pointer"])
        out += wrap("      ", p["role"], 6)
    if c.get("manual_verification"):
        out += ["", "Manual verification (read-only)"] + wrap("  ", c["manual_verification"], 2)
    if c.get("remediation_guidance"):
        out += ["", "Remediation guidance (illustrative; ISEDRAF changes nothing)"]
        out += wrap("  ", c["remediation_guidance"], 2)
    out += ["", "Baseline state  " + NO_HISTORY, "Delta           " + NO_HISTORY]
    return out
