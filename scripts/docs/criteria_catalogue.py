# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Generate docs/reference/NATIVE_CRITERIA.csv, the native criteria catalogue.
# Implements: D-130, D-111, D-125, EVAL-002
#
# D-130 (owner, 2026-11-21): one row per criterion the release delivers, generated from the one
# registry (lib/isedraf/catalog/native_controls.json) and never edited by hand. UTF-8 without a
# byte-order mark, RFC 4180 quoting, CRLF line ends, one line per cell, lists joined with " | ".
# `check` fails when the file is stale, when its IDs, row count or any cell disagree with the
# registry, or when a cell would run as a spreadsheet formula (it starts with = + - @, a tab or a
# carriage return). Such a cell is refused, never escaped: the catalogue states the registry's
# text exactly or not at all.
#
# meta:type="generator"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="docs/reference/NATIVE_CRITERIA.csv"
# meta:binaries="git"
# =============================================================================
"""`generate` writes the catalogue; `check` fails when it and the registry disagree."""
import csv
import io
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
sys.path.insert(0, str(ROOT / "lib"))
from isedraf import catalog        # noqa: E402

TARGET = ROOT / "docs" / "reference" / "NATIVE_CRITERIA.csv"
JOIN = " | "
FORMULA_LEADS = ("=", "+", "-", "@", "\t", "\r")

# (column, how the registry record gives it). The order is the file's column order.
COLUMNS = (
    ("criterion_id", lambda c: c["criterion_id"]),
    ("family", lambda c: c["criterion_id"].split("-")[1]),
    ("title", lambda c: c["title"]),
    ("description", lambda c: c["purpose"]),
    ("lifecycle", lambda c: c["lifecycle"]),
    ("criterion_version", lambda c: str(c["version"])),
    ("introduced_in_release", lambda c: c["introduced_in"]),
    ("default_severity", lambda c: c["default_severity"]),
    ("check_type", lambda c: c["check_type"]),
    ("evidence_sections", lambda c: JOIN.join(sorted(set(
        p["artifact"] for p in c["evidence_pointers"] if p["artifact"].startswith("sections/"))))),
    ("collection_requirements", lambda c: JOIN.join(
        ["%s: %s" % (c["minimum_run"]["route"], c["minimum_run"]["reason"]),
         "the route is necessary, not sufficient; evidence is sufficient when:"]
        + list(c["evaluation_semantics"]["evidence_sufficient_when"]))),
    ("applicability", lambda c: c["applicability"]),
    ("result_meanings", lambda c: JOIN.join(
        ["%s: %s" % (r["result"], r["when"]) for r in c["evaluation_semantics"]["rules"]]
        + ["never produced: %s" % ", ".join(c["evaluation_semantics"].get("never_produced", []))
           ])),
    ("limitations", lambda c: JOIN.join(
        c["limitations"] if isinstance(c["limitations"], list) else [c["limitations"]])),
    ("documentation", lambda c: "isedraf explain %s%sdocs/reference/criteria/%s.md"
     % (c["criterion_id"], JOIN, c["criterion_id"])),
)


def one_line(text):
    """A cell is one line: line breaks inside registry text become single spaces."""
    return " ".join(str(text).split())


def rows(registry):
    return [[one_line(get(c)) for _name, get in COLUMNS] for c in registry["criteria"]]


def render(registry):
    out = io.StringIO()
    writer = csv.writer(out, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow([name for name, _get in COLUMNS])
    writer.writerows(rows(registry))
    return out.getvalue()


def problems():
    registry, _raw = catalog.load()
    out = []
    want = render(registry)
    for row in rows(registry):
        for (name, _get), cell in zip(COLUMNS, row):
            if cell.startswith(FORMULA_LEADS):
                out.append("%s: column %s starts with %r, which a spreadsheet runs as a formula; "
                           "change the registry text" % (row[0], name, cell[:1]))
    if not TARGET.exists():
        return out + ["%s is missing" % TARGET.relative_to(ROOT)]
    data = TARGET.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        out.append("%s starts with a byte-order mark (D-130: UTF-8 without one)"
                   % TARGET.relative_to(ROOT))
    text = data.decode("utf-8")
    if text != want:
        out.append("%s is stale or edited by hand; run: python3 scripts/docs/criteria_catalogue.py "
                   "generate" % TARGET.relative_to(ROOT))
    parsed = list(csv.reader(io.StringIO(text, newline="")))
    ids = [r[0] for r in parsed[1:] if r]
    admitted = [c["criterion_id"] for c in registry["criteria"]]
    if ids != admitted:
        out.append("the catalogue lists %d criteria %s; the registry admits %d %s"
                   % (len(ids), ids, len(admitted), admitted))
    return out


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    if action == "generate":
        registry, _raw = catalog.load()
        TARGET.write_bytes(render(registry).encode("utf-8"))
        print("  generated %s" % TARGET.relative_to(ROOT))
        return 0
    found = problems()
    for p in found:
        print("  FAIL  %s" % p)
    if not found:
        print("  OK    %s: fresh, consistent with the registry, no formula cell"
              % TARGET.relative_to(ROOT))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
