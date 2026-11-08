# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Generate docs/reference/criteria/<criterion_id>.md from the one registry.
# Implements: D-111, D-125, EVAL-002, EVAL-009
#
# EVAL-009: a generated page per criterion renders the same record `isedraf explain`
# renders, through the same function (lib/isedraf/explain.py), and is never edited by
# hand. check_native_catalog.py fails when a page is stale, missing, or has no criterion.
#
# meta:type="generator"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="docs/reference/criteria/"
# meta:binaries="git"
# =============================================================================
"""`generate` writes the pages; `check` fails when they and the registry disagree."""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
sys.path.insert(0, str(ROOT / "lib"))
from isedraf import catalog, explain        # noqa: E402

TARGET_DIR = ROOT / "docs" / "reference" / "criteria"
BANNER = "GENERATED FILE — DO NOT EDIT MANUALLY"


def page(record):
    header = [
        "<!--", "SPDX-License-Identifier: MPL-2.0",
        "SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS", "-->",
        "<!-- %s." % BANNER,
        "     Source: lib/isedraf/catalog/native_controls.json",
        "     Regenerate: python3 scripts/docs/criteria_pages.py generate",
        "     `make check` fails when this page and the registry disagree. -->", "",
        "# %s" % record["criterion_id"], "",
        "**%s**" % BANNER, "",
        "This page renders the registry record, exactly as `isedraf explain %s` does. The "
        "record is the only description of the criterion." % record["criterion_id"], "",
        "```text"]
    return "\n".join(header + explain.lines(record) + ["```", ""])


def expected():
    registry, _raw = catalog.load()
    return dict((TARGET_DIR / ("%s.md" % c["criterion_id"]), page(c))
                for c in registry["criteria"])


def problems():
    want = expected()
    out = []
    for path, text in sorted(want.items()):
        if not path.exists():
            out.append("%s is missing" % path.relative_to(ROOT))
        elif path.read_text(encoding="utf-8") != text:
            out.append("%s is stale" % path.relative_to(ROOT))
    if TARGET_DIR.exists():
        for path in sorted(TARGET_DIR.glob("*.md")):
            if path not in want:
                out.append("%s names no admitted criterion" % path.relative_to(ROOT))
    return out


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    if action == "generate":
        TARGET_DIR.mkdir(parents=True, exist_ok=True)
        for path, text in sorted(expected().items()):
            path.write_text(text, encoding="utf-8")
            print("  generated %s" % path.relative_to(ROOT))
        return 0
    found = problems()
    for p in found:
        print("  FAIL  %s" % p)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
