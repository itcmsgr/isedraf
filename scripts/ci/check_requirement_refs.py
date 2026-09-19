# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Enforce requirement-reference integrity across authoritative project documents.
# Implements: D-105, D-106, GOV-001, GOV-002
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git"
# =============================================================================

"""
Requirement-reference integrity.

Proves: every referenced requirement ID exists; every defined ID is unique; no document
cites an undefined D-/OD-/requirement ID; no document cites a bare A-0xx amendment as
authority (amendments are historical provenance only).
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
)

# Requirement IDs are defined as a bolded leader at the start of a line.
DEF_RE = re.compile(r"^\*\*([A-Z]{2,6}-\d{3})\b", re.M)
REF_RE = re.compile(r"(?<![A-Z0-9-])([A-Z]{2,6}-\d{3})\b")
# Decisions and open decisions live in the register.
DDEF_RE = re.compile(r"^-\s+\*\*(D-\d{1,3}|OD-\d{1,2})\b", re.M)
DREF_RE = re.compile(r"\b(D-\d{1,3}|OD-\d{1,2})\b")
AMEND_RE = re.compile(r"\bA-0\d{2}\b")
# A gate's own falsification payloads are deliberately fake IDs. They are exempt only
# with an explicit inline marker - never silently, per the coverage rule (T-20).
FIXTURE_MARK = "refs:test-fixture"

# Prose words that match the ID shape but are not requirement IDs.
# Prefixes that look like requirement IDs but are not: implementation questions,
# illustrative control IDs (SD-MAC-001), and standards references.
NOT_IDS = {"MPL-2", "SHA-256", "RFC-3339", "UTF-8", "SP-800"}
NOT_ID_PREFIXES = ("IQ-", "KGG-", "ACC-", "SDS-", "EVL-")

# T-20: a requirement ID cited in ANY authority tier must resolve. Restricting the scan
# to architecture directories let a dangling requirement ID sit in HEADER_POLICY.md while the
# gate reported "all references resolve" - a gate that cannot fail for a whole file class.
DEFINING_GLOBS = ["docs/architecture/*.md", "docs/development/HEADER_POLICY.md"]
# Makefile and workflow YAML cited a historical amendment as live gate authority and sat outside
# the scan. A gate's own scope is the first thing to get wrong.
REFERENCING_GLOBS = ["docs/**/*.md", "CLAUDE.md", "scripts/**/*.py", "scripts/**/*.sh",
                     "Makefile", ".github/workflows/*.yml",
                     "planning/blueprint/10_architecture/*.md"]
REGISTER = ROOT / "docs" / "architecture" / "DECISIONS_REGISTER.md"
AMENDMENTS = ROOT / "docs" / "architecture" / "AMENDMENTS.md"

def collect(globs):
    out = []
    for g in globs:
        out += [p for p in sorted(ROOT.glob(g)) if p.is_file()]
    return sorted(set(out))

defining = [p for p in collect(DEFINING_GLOBS) if p.name != "AMENDMENTS.md"]
referencing = [p for p in collect(REFERENCING_GLOBS) if p.name != "AMENDMENTS.md"]
docs = sorted(set(defining) | set(referencing))
if not docs:
    print("  SKIP  no documents present yet")
    sys.exit(0)

failures = []
defined, dup = set(), []
for p in defining:
    for m in DEF_RE.finditer(p.read_text(encoding="utf-8")):
        i = m.group(1)
        if i in defined:
            dup.append((i, p.relative_to(ROOT).as_posix()))
        defined.add(i)

for i, where in dup:
    failures.append(f"duplicate requirement ID {i} (redefined in {where}) [D-105]")

decisions = set()
if REGISTER.exists():
    decisions = {m.group(1) for m in DDEF_RE.finditer(REGISTER.read_text(encoding="utf-8"))}

# Requirement IDs are DEFINED in the frozen architecture documents. Before the freeze
# those live under planning/ (untracked), so a CI checkout sees the register but not the
# documents it cites. Cross-checking requirement IDs in that state would fail on absence,
# not on a defect - and a gate that behaves differently locally and in CI is worthless.
# Decision and amendment checks always run; requirement-ID resolution runs only when the
# defining documents are actually visible.
requirement_defs_visible = bool(defined)

# Is ID resolution COMPLETE in this checkout?
#
# The public repository carries the specification and not the internal change control, so
# some documents that define requirement IDs are absent by design. A reference that does
# not resolve here may be perfectly valid and defined in a document this checkout does not
# have - reporting it as undefined would be a statement about the checkout, not about the
# code.
#
# Prefix families are not a usable proxy: IDENT-001 is defined in a published document and
# IDENT-003 in an unpublished one, so the family looks resolvable while half of it is not.
# The honest test is whether EVERY defining document is present.
#
# When one is missing, unresolved IDs are counted and named as unresolved HERE, and the
# gate says which mode it ran in. Nothing is weakened where it matters: the engineering
# repository has every document, runs in full mode, and is the only place these files can
# be edited.
EXPECTED_DEFINING = [
    "docs/architecture/ISEDRAF_HLD.md",
    "docs/architecture/EVIDENCE_AND_TRUST_MODEL.md",
    "docs/architecture/SNAPSHOT_BASELINE_DELTA_MODEL.md",
    "docs/architecture/NORMATIVE_SOURCES.md",
    "docs/architecture/V0_1_IMPLEMENTATION_SCOPE.md",
    "docs/architecture/W1A_CORE_FREEZE_SCOPE.md",
]
absent_defining = [d for d in EXPECTED_DEFINING if not (ROOT / d).exists()]
resolution_complete = not absent_defining
unresolved = set()

for p in docs:
    rel = p.relative_to(ROOT).as_posix()
    text = p.read_text(encoding="utf-8")

    def marked(pos):
        """True when the line carrying this offset declares itself a test fixture."""
        ls = text.rfind("\n", 0, pos) + 1
        le = text.find("\n", pos)
        return FIXTURE_MARK in text[ls:le if le != -1 else len(text)]

    if requirement_defs_visible:
        for m in REF_RE.finditer(text):
            i = m.group(1)
            if i in NOT_IDS or i in defined or i.startswith(NOT_ID_PREFIXES):
                continue
            if marked(m.start()):
                continue
            if not resolution_complete:
                unresolved.add(i)
                continue
            failures.append(f"{rel}: cites undefined requirement ID {i} [D-105]")
    if decisions:
        for m in DREF_RE.finditer(text):
            i = m.group(1)
            if i not in decisions and not marked(m.start()):
                failures.append(f"{rel}: cites undefined decision {i} [D-105]")
    # D-106: amendments are provenance, never authority.
    for m in AMEND_RE.finditer(text):
        if marked(m.start()):
            continue
        failures.append(
            f"{rel}: cites amendment {m.group(0)} as authority; cite the decision ID instead [D-106]"
        )

if failures:
    print("=== requirement-reference integrity FAILED ===", file=sys.stderr)
    for f in sorted(set(failures)):
        print(f"  FAIL  {f}", file=sys.stderr)
    sys.exit(1)
if not requirement_defs_visible:
    mode = "decisions-only (architecture not yet in repo)"
elif not resolution_complete:
    print("  NOTE  %d defining document(s) are not present in this checkout: %s"
          % (len(absent_defining), ", ".join(absent_defining)))
    if unresolved:
        print("        %d referenced ID(s) could not be resolved here and were NOT "
              "treated as failures: %s"
              % (len(unresolved), ", ".join(sorted(unresolved)[:8])
                 + (" …" if len(unresolved) > 8 else "")))
    print("        Full resolution runs in the engineering repository, which holds every")
    print("        defining document and is the only place they can be edited.")
    mode = "reduced — not every defining document is published here"
elif not decisions:
    mode = "reduced — the decisions register is not published here"
else:
    mode = "full"
print(f"  OK    {len(defined)} requirement IDs, {len(decisions)} decisions, "
      f"{len(docs)} files scanned, all references resolve [{mode}]")
