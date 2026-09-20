# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The README's claims about the project must match the project.
# Implements: C-01, D-88, D-89, D-90, GOV-002
#
# The README says of itself: "Every mark above is backed by a control that runs, or by a
# file in this repository." On the day the repository went public, four of its four badges
# were wrong:
#
#   version    said 0.0.0-pre while VERSION said 0.1.0-alpha1
#   status     said prototype while the status registry said TECHNICAL_PREVIEW_CANDIDATE
#   platforms  named three distributions; eleven had been measured
#   platforms  linked to a file that has never existed
#
# And the status line still read "Private pre-release development ... not yet a public
# release" in a repository anyone could read.
#
# A badge is a claim. Nothing checked them, so they aged while everything around them was
# gated. This checks them against the files they claim to come from.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================

"""usage: check_public_claims.py"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True).strip())
README = ROOT / "README.md"
REGISTRY = json.loads((ROOT / "scripts" / "ci" / "project_status.json").read_text())
VERSION = (ROOT / "VERSION").read_text().strip()
FAIL = []


def bad(msg):
    FAIL.append(msg)
    print("  FAIL  %s" % msg)


# Written as a plain literal and escaped here, not spelled out with backslashes inside a
# pattern. The privacy gate classifies domains by matching text against an allowlist, and
# "img\.shields\.io" is not the same string as "img.shields.io" — a regex-escaped host
# reads as an unclassified domain on the publication surface.
BADGE = re.escape("img.shields.io")

print("--- public claims (C-01, D-88, D-90) ---")
text = README.read_text(encoding="utf-8")

# --- 1. the version badge names the version this repository actually is ------------
# The badge service escapes a literal '-' as '--', so 0.1.0-alpha1 is written 0.1.0--alpha1.
m = re.search(BADGE + r"/badge/version-([^-\s)]+(?:--[^-\s)]+)*)-", text)
if not m:
    bad("README has no version badge to check")
else:
    shown = m.group(1).replace("--", "\x00").replace("-", " ").replace("\x00", "-")
    if shown != VERSION:
        bad("the version badge says %r; VERSION says %r" % (shown, VERSION))

# --- 2. the status badge does not contradict the status registry -------------------
STAGE_WORDS = {
    "TECHNICAL_PREVIEW_CANDIDATE": ("technical", "preview"),
    "TECHNICAL_PREVIEW": ("technical", "preview"),
    "PROTOTYPE": ("prototype",),
}
stage = REGISTRY["project_stage"]
m = re.search(BADGE + r"/badge/status-([^-\s)]+(?:--[^-\s)]+)*)-", text)
if not m:
    bad("README has no status badge to check")
else:
    shown = m.group(1).replace("--", "-").replace("%20", " ").lower()
    expected = STAGE_WORDS.get(stage)
    if expected is None:
        bad("the status registry stage %r has no README wording defined here" % stage)
    elif not any(w in shown for w in expected):
        bad("the status badge says %r; the status registry says %r" % (shown, stage))

# --- 3. no claim that this is private or unpublished -------------------------------
# The repository is public. Text written while it was private does not become harmless
# by being out of date; it tells a reader something false about what they are looking at.
STALE_PRIVACY = [
    (r"Private pre-release development", "says the project is private"),
    (r"is not yet a public release", "says there is no public release of the source"),
    (r"\bnot yet public\b", "says the project is not public"),
    (r"needs a public repository", "describes a blocker that no longer exists"),
]
for n, line in enumerate(text.splitlines(), 1):
    for pattern, why in STALE_PRIVACY:
        if re.search(pattern, line, re.I):
            bad("README:%d %s, but the source is published: %r"
                % (n, why, line.strip()[:70]))

# --- 4. the platform badge does not understate what was measured -------------------
measured = REGISTRY["platforms"]["distributions_measured"]
m = re.search(BADGE + r"/badge/platforms-([^)\s]+)", text)
if m:
    shown = m.group(1)
    named = sum(1 for d in measured if d.split()[0].lower() in shown.lower())
    if named and named < len(measured) and "%C2%B7" in shown:
        # It names some but not all, as a list. A partial list reads as the whole set.
        bad("the platform badge names %d distributions as a list; %d were measured. "
            "A partial list reads as the complete set." % (named, len(measured)))

# --- 5. no platform claim the measured record does not support (D-112) ---------------
# Platform breadth drifts upward on its own. The collectors have no architecture branches,
# which is a reason to EXPECT a platform to work and is not evidence that it does - and the
# gap between those two is where "supports ARM" gets written by someone who is not lying.
#
# The status registry records what was measured. This refuses any public text that claims
# more, with the same claim-context rule the licensing gate uses: a NEGATION is not a claim,
# because "ARM64 has not been tested" must stay sayable.
OVERCLAIM = [
    (r"\ball Linux (?:distribution|distro|system)s?\b", "every Linux distribution"),
    (r"\bevery Linux (?:distribution|distro|system)\b", "every Linux distribution"),
    (r"\bany Linux (?:distribution|distro|system)\b", "any Linux distribution"),
    (r"\buniversal(?:ly)? (?:supported|compatible)\b", "universal support"),
]
ARCH_CLAIM = re.compile(r"\b(ARM64|AArch64|aarch64|armhf|ARMv\d|Raspberry Pi)\b")
DISTRO_CLAIM = re.compile(r"\b(SLES|Amazon Linux|Alpine|Arch Linux|Gentoo|Oracle Linux|Fedora)\b")
SUPPORT = re.compile(r"\b(support(?:s|ed|ing)?|certified|validated|proven|works? on|"
                     r"runs? on|compatible|ready)\b", re.I)
NEG = re.compile(r"\b(no|not|never|without|zero|none|untested|not tested|NOT_TESTED|"
                 r"planned|future|target(?:ed|s)?|intend(?:ed|s)?|would|cannot|has not|"
                 r"have not|yet)\b", re.I)

measured_arch = set(a.lower() for a in REGISTRY["platforms"]["architectures_measured"])
measured_distro = REGISTRY["platforms"]["distributions_measured"]
docs = [r for r in subprocess.check_output(
    ["git", "ls-files", "*.md"], cwd=str(ROOT), text=True).split()
    if not r.startswith(("planning/", "docs/architecture/ISEDRAF_PRODUCT_HLD",
                         "docs/reference/PLATFORM_COMPATIBILITY", "docs/roadmap/"))]
# Negation is a property of the SECTION, not only of the line. The README's "Not yet
# claimed" list is a series of bare items - `all Linux distributions`, `ARM64
# certification` - under a heading that negates every one of them. Reading line by line,
# the gate flagged the list of things the project explicitly does NOT claim, which is the
# precise inverse of its purpose and exactly the noise that teaches people to skip a gate.
HEADING = re.compile(r"^#{1,6}\s+(.*)$")
NEG_SECTION = re.compile(r"\b(not|never|no|without|out[ _-]?of[ _-]?scope|planned|future|"
                         r"untested|deliberately absent|may not|forbidden|prohibited)\b", re.I)

for rel in docs:
    text_doc = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    section_negated = False
    for n, line in enumerate(text_doc.splitlines(), 1):
        h = HEADING.match(line)
        if h:
            section_negated = bool(NEG_SECTION.search(h.group(1)))
        if section_negated or NEG.search(line):
            continue
        for pattern, label in OVERCLAIM:
            if re.search(pattern, line, re.I):
                bad("%s:%d claims %s. Support is a matrix — architecture, distribution, "
                    "version, collector capability and DEMONSTRATED VALIDATION (D-112). "
                    "Line: %r" % (rel, n, label, line.strip()[:70]))
        if SUPPORT.search(line):
            m = ARCH_CLAIM.search(line)
            if m and not any(a in ("aarch64", "arm64") for a in measured_arch):
                bad("%s:%d claims support for %s, and architectures_measured is %r — no "
                    "ARM campaign has produced evidence (D-112). Line: %r"
                    % (rel, n, m.group(0),
                       REGISTRY["platforms"]["architectures_measured"],
                       line.strip()[:70]))
            d = DISTRO_CLAIM.search(line)
            if d and not any(d.group(0).lower() in x.lower() for x in measured_distro):
                bad("%s:%d claims support for %s, which is not in distributions_measured "
                    "(D-112). Line: %r" % (rel, n, d.group(0), line.strip()[:70]))

# --- 5b. every identity surface says the same thing ------------------------------------
# Five surfaces described the same product five different ways and nothing compared them.
# They legitimately differ in length and case - a banner, a subtitle, a package Summary
# and a 131-character About field are different formats - so each form is declared
# separately and each surface is held to its own form. What is not allowed is substance
# drifting apart, which is how "Evidence Bridge" and "Evidence Engine" both became true.
IDENT = REGISTRY.get("identity")
if not IDENT:
    bad("the status registry declares no canonical identity")
else:
    noun = IDENT["noun"]
    # The noun belongs in the LONG form. The README subtitle is deliberately different -
    # "…State Delta & Verifiable Evidence" - because a subtitle describes the product to a
    # reader rather than restating its formal descriptor. Requiring the noun in both was my
    # assumption, not the decision: D-113 declares the forms separately and on purpose.
    if noun not in IDENT["header"]:
        bad("the declared noun %r is absent from the header form" % noun)
    for retired in IDENT.get("retired_descriptors", []):
        for form in ("header", "tagline", "short", "about"):
            if retired in IDENT[form]:
                bad("the declared %s form still carries the retired descriptor %r"
                    % (form, retired))

    # README subtitle
    m = re.search(r"^\*\*(.+?)\*\*$", text, re.M)
    if not m:
        bad("README has no bold subtitle line to check")
    elif m.group(1) != IDENT["tagline"]:
        bad("the README subtitle is %r; the registry declares %r"
            % (m.group(1), IDENT["tagline"]))

    # package Summary / Description, as the build actually sets it
    build = (ROOT / "packaging" / "build.sh").read_text(encoding="utf-8")
    m = re.search(r'^DESCRIPTION="(.+?)"$', build, re.M)
    if not m:
        bad("packaging/build.sh sets no DESCRIPTION")
    elif m.group(1) != IDENT["short"]:
        bad("the package description is %r; the registry declares %r"
            % (m.group(1), IDENT["short"]))

    # CLI --help
    cli = (ROOT / "lib" / "isedraf" / "cli.py").read_text(encoding="utf-8")
    m = re.search(r'description="(.+?)"\)', cli)
    if not m:
        bad("the CLI declares no description")
    elif m.group(1).rstrip(".") != IDENT["short"].rstrip("."):
        bad("the CLI description is %r; the registry declares %r"
            % (m.group(1), IDENT["short"]))

    # PRODUCT-DESCRIPTOR-001 (D-113): a retired descriptor on any public claim surface.
    # Historical records may keep it — falsifying the record of what a thing was once
    # called is worse than an inconsistent string — and the exemption is exactly the two
    # files that exist to record history.
    HISTORICAL = {"docs/architecture/AMENDMENTS.md",
                  "docs/architecture/DECISIONS_REGISTER.md"}
    GATE_SELF = {"scripts/ci/project_status.json", "scripts/ci/check_public_claims.py",
                 "scripts/ci/falsifiable.sh"}
    # PRODUCT-DESCRIPTOR-001 governs PUBLIC claim surfaces. CLAUDE.md is tracked here and
    # deliberately excluded from the public export, so it is not one. It is reported as a
    # NOTE rather than exempted silently: the descriptor should still be consistent, and
    # the file is owner-only, so the inconsistency needs to stay visible to a human.
    NOT_PUBLISHED = {"CLAUDE.md"}
    for retired in IDENT.get("retired_descriptors", []):
        for rel in subprocess.check_output(
                ["git", "ls-files"], cwd=str(ROOT), text=True).split():
            if rel in HISTORICAL or rel in GATE_SELF:
                continue
            f = ROOT / rel
            if not f.is_file():
                continue
            try:
                body = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if retired in body:
                n = body[:body.index(retired)].count("\n") + 1
                if rel in NOT_PUBLISHED:
                    print("  NOTE  %s:%d still uses %r. Not a public claim surface — it "
                          "is excluded from the export — but owner-only, so it cannot be "
                          "corrected here." % (rel, n, retired))
                    continue
                bad("%s:%d uses the RETIRED product descriptor %r "
                    "(PRODUCT-DESCRIPTOR-001, D-113). The canonical noun is %r."
                    % (rel, n, retired, IDENT["noun"]))

    # the file-header banner, which is also inside a FROZEN artifact
    hp = ROOT / "docs" / "development" / "HEADER_POLICY.md"
    if hp.exists() and IDENT["noun"] not in hp.read_text(encoding="utf-8"):
        bad("HEADER_POLICY.md does not carry the declared noun %r. That file is inside "
            "the freeze sets, so the registry and the frozen policy disagreeing means one "
            "of them changed without an amendment." % IDENT["noun"])

# --- 6. the three-mode invariant is stated where it is normative (D-112) --------------
# A mapping may never alter native evidence. If the sentence that says so disappears from
# the HLD, nothing else in the repository asserts it.
hld = ROOT / "docs" / "architecture" / "ISEDRAF_PRODUCT_HLD.md"
if not hld.exists():
    bad("the consolidated product HLD is missing: %s" % hld.relative_to(ROOT))
else:
    h = hld.read_text(encoding="utf-8")
    for needed, why in (
            ("NEITHER B NOR C CAN CHANGE A", "the mode invariant"),
            ("DEMONSTRATED VALIDATION", "the platform-matrix rule"),
            ("mapped evidence", "the mapping-is-not-compliance distinction")):
        if needed not in h:
            bad("the product HLD no longer states %s (%r missing)" % (why, needed))

if FAIL:
    print("=== public claims gate FAILED ===")
    print("  A badge is a claim. Fix the claim, or the thing it claims.")
    sys.exit(1)
print("  OK    public claims: badges, publication state, platform matrix and the\n        three-mode invariant all consistent with the measured record")
