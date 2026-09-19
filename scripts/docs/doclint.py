# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Lint documentation for forbidden claims, competitive framing, status labels and links.
# Implements: D-87, D-88, D-89, C-01, C-05, C-06, C-07, C-08, C-13
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git"
# =============================================================================

"""
Documentation lint: forbidden claims, competitive framing, status labels, wiki-only
content and internal links.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
)

# Q-13: authoritative architecture and governance documents may NOT carry a file-wide
# forbidden-claim exemption - that disables the gate exactly where the claims live.
# Only documents whose PURPOSE is to enumerate the forbidden terms are exempt.
EXEMPT_PATHS = ()
EXEMPT_BY_PURPOSE = (
    "docs/development/HEADER_POLICY.md",
    "docs/development/DOCUMENTATION_POLICY.md",
    "docs/development/LLM_PROTOCOL.md",
    "docs/development/CI_INVENTORY.md",
    "docs/STYLE_GUIDE.md",
)
EXEMPT_MARKER = "doclint:exempt-forbidden-terms"

# Always an overclaim, in any context.
FORBIDDEN = [
    "revolutionary", "world-leading", "military-grade", "100% secure", "fully compliant",
    "zero-trust certified", "tamper-proof", "non-repudiable", "host unchanged",
    "read-only guaranteed", "better than", "category-defining", "enterprise-ready",
]

# Q-13: `immutable` and `append-only` have legitimate SCOPED meanings ("audit immutable
# mode", "append-only within a segment"). What is forbidden is the UNSCOPED security
# overclaim. Phrase-level, so the honest uses survive and the dishonest ones do not.
OVERCLAIM_RE = re.compile(
    r"\bhost\s+is\s+immutable\b"
    r"|\bevidence\s+is\s+immutable\b"
    r"|\bimmutable\s+against\s+root\b"
    r"|\bguaranteed\s+unchanged\b"
    r"|\bcannot\s+be\s+(modified|altered|tampered)\s+by\s+root\b"
    r"|\bproves?\s+the\s+host\s+is\s+(secure|uncompromised)\b",
    re.I,
)
# "replaces"/"beats" only matter as competitive framing, checked separately.
COMPETITIVE = re.compile(
    r"\bISEDRAF\s+vs\b"
    r"|\bvs\.?\s+(OpenSCAP|ComplianceAsCode|Lynis|osquery|Wazuh|AIDE|NFTBAN|NFTBan)\b"
    r"|\breplacement for\b"
    r"|\bISEDRAF\s+(replaces|beats|destroys)\b",
    re.I,
)
FENCE_RE = re.compile(r"```.*?```", re.S)
NEGATION_RE = re.compile(r"\b(not|never|no|isn't|is not|does not|doesn't)\b[^.]*$", re.I)

VALID_STATUS = {
    "IMPLEMENTED", "EXPERIMENTAL", "PLANNED", "FUTURE", "OUT_OF_SCOPE", "STUB",
    # Architecture-phase statuses.
    "FROZEN", "APPROVED", "PLANNING",
}

# A term inside backticks or quotes is a MENTION, not a use: a policy document must be
# able to name what it forbids. A term preceded by a negation is likewise not a claim.
MENTION_RE = re.compile(r"[`\"\u201c\u201d']")
NEG_NEAR = re.compile(
    r"\b(never|not|no|forbidden|forbids?|prohibit\w*|avoid|SHALL NOT|SHALL NEVER|"
    r"instead of|rather than|does not|cannot|refus\w+|reject\w*|unsoftened|limitation)\b",
    re.I,
)


def _is_claim(text: str, start: int, end: int) -> bool:
    """True when an occurrence is an assertion rather than a mention or a negation."""
    lead = text[max(0, start - 120):start]
    tail = text[end:end + 60]
    if MENTION_RE.search(text[max(0, start - 2):start]) or MENTION_RE.search(tail[:2]):
        return False
    if NEG_NEAR.search(lead) or NEG_NEAR.search(tail):
        return False
    return True
STATUS_RE = re.compile(r"^Status:\s*(.+?)\s*$", re.M)

failures = []


def check(path: pathlib.Path) -> None:
    rel = path.relative_to(ROOT).as_posix()
    if EXEMPT_PATHS and rel.startswith(EXEMPT_PATHS):
        return
    raw = path.read_text(encoding="utf-8")
    # A file-wide marker is honoured ONLY for documents whose purpose is to enumerate
    # the forbidden terms. Anywhere else it is itself a defect (Q-13).
    exempt = EXEMPT_MARKER in raw and rel in EXEMPT_BY_PURPOSE
    if EXEMPT_MARKER in raw and rel not in EXEMPT_BY_PURPOSE:
        failures.append(
            f"{rel}: file-wide forbidden-claim exemption is not permitted here; "
            f"use an inline <!-- doclint:quote --> span instead (Q-13)"
        )
    # Fenced code blocks hold examples and templates, not project claims.
    text = FENCE_RE.sub(lambda m: "\n" * m.group(0).count("\n"), raw)

    if not exempt:
        low = text.lower()
        for term in FORBIDDEN:
            for m in re.finditer(re.escape(term), text, re.I):
                if _is_claim(text, m.start(), m.end()):
                    failures.append(f"{rel}: forbidden claim {term!r} (C-05)")
                    break
        for m in OVERCLAIM_RE.finditer(text):
            if _is_claim(text, m.start(), m.end()):
                failures.append(f"{rel}: unscoped security overclaim {m.group(0)!r} (C-05)")
        for m in COMPETITIVE.finditer(text):
            lead = text[max(0, m.start() - 70):m.start()].lower()
            # "not developed as a replacement for X" is coexistence, not a claim.
            if NEGATION_RE.search(lead):
                continue
            failures.append(f"{rel}: competitive framing {m.group(0)!r} (C-06)")

    # T-27: architecture documents declare status EXTERNALLY, via membership in
    # FROZEN_MANIFEST.sha256. A status string inside the bytes would mean the reviewed
    # bytes and the frozen bytes differ, so none is required or permitted there.
    if rel.startswith("docs/architecture/") and re.search(r"^Status:", text, re.M):
        failures.append(
            f"{rel}: architecture documents declare status externally via "
            f"FROZEN_MANIFEST.sha256, not with a Status: line (T-27)"
        )

    # C-08: a declared status must be a known value.
    for m in STATUS_RE.finditer(text):
        value = m.group(1).split()[0].strip("*`.,")
        if value not in VALID_STATUS:
            failures.append(f"{rel}: unknown Status {value!r} (C-08)")

    # C-07: a STUB carries headings and the status line only.
    if re.search(r"^Status:\s*STUB\s*$", text, re.M):
        body = [
            ln for ln in text.splitlines()
            if ln.strip()
            and not ln.startswith(("#", "<!--", "-->", "Status:", "Implements:"))
        ]
        if body:
            failures.append(f"{rel}: STUB document contains behavioural prose (C-07)")

    # C-01: internal links resolve.
    for m in re.finditer(r"\[[^\]]*\]\(([^)#]+?)(?:#[^)]*)?\)", raw):
        target = m.group(1).strip()
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        if not (path.parent / target).resolve().exists():
            failures.append(f"{rel}: broken internal link -> {target} (C-01)")


# Authoritative input during the architecture phase lives under planning/ (untracked);
# after the freeze it lives under docs/architecture/. The lint SHALL NOT depend on git
# visibility to reach authoritative documents (Q-13).
for p in sorted(ROOT.glob("docs/**/*.md")):
    check(p)

for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md",
             "CODE_OF_CONDUCT.md", "CHANGELOG.md", "AI_ASSISTED_DEVELOPMENT.md"):
    p = ROOT / name
    if p.exists():
        check(p)

# C-13: no GitHub wiki content.
if (ROOT / "wiki").exists():
    failures.append("wiki/: a GitHub Wiki surface is present; /docs is canonical (D-87, C-13)")

if failures:
    print("=== doc lint FAILED ===", file=sys.stderr)
    for f in failures:
        print(f"  FAIL  {f}", file=sys.stderr)
    sys.exit(1)
print("  OK    doc lint clean")
