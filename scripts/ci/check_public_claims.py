# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
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

if FAIL:
    print("=== public claims gate FAILED ===")
    print("  A badge is a claim. Fix the claim, or the thing it claims.")
    sys.exit(1)
print("  OK    public claims: version, status, platform and publication state consistent")
