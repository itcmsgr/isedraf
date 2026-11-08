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

LIFECYCLE = "EXPERIMENTAL"          # D-80: every control in the prototype
NO_HISTORY = "not available: baseline and delta are v0.4"


def _items(value):
    return value if isinstance(value, list) else [value]


def lines(c):
    """The explanation of one criterion record, as a list of text lines."""
    sem = c["evaluation_semantics"]
    out = ["%s  (version %d, %s)" % (c["criterion_id"], c["version"], LIFECYCLE), "",
           "Purpose", "  " + c["purpose"], "",
           "Why it matters", "  " + c["rationale"], "",
           "Check type      %s" % c["check_type"],
           "Severity        %s (default_severity; a FAIL finding takes it unchanged)"
           % c["default_severity"],
           "Applicability   %s" % c["applicability"], "",
           "Facts required"]
    out += ["  - " + f for f in _items(c["facts_required"])]
    out += ["", "Dimensions"]
    for name in ("declared", "resolved", "active"):
        if isinstance(c["dimensions"], dict) and name in c["dimensions"]:
            out.append("  %-9s %s" % (name, c["dimensions"][name]))
    out += ["", "How it is evaluated", "  Input: " + sem["input"], "  Evidence is sufficient when:"]
    out += ["    - " + s for s in sem["evidence_sufficient_when"]]
    out.append("  Results:")
    for rule in sem["rules"]:
        out.append("    %-14s %s" % (rule["result"], rule["when"]))
    out.append("  Never produced: " + ", ".join(sem.get("never_produced", [])))
    out.append("  " + sem["determinism"])
    out += ["", "Limitations - what a result does not establish"]
    out += ["  - " + s for s in _items(c["limitations"])]
    out += ["", "Evidence pointers"]
    out += ["  %s  %s  (%s)" % (p["artifact"], p["pointer"], p["role"])
            for p in c["evidence_pointers"]]
    if c.get("manual_verification"):
        out += ["", "Manual verification (read-only)", "  " + c["manual_verification"]]
    if c.get("remediation_guidance"):
        out += ["", "Remediation guidance (illustrative; ISEDRAF changes nothing)",
                "  " + c["remediation_guidance"]]
    out += ["", "Baseline state  " + NO_HISTORY, "Delta           " + NO_HISTORY]
    return out
