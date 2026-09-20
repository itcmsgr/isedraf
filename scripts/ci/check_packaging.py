# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Catch packaging-metadata defects without needing a builder for every distro.
# Implements: D-86, GOV-002, EXEC-016
#
# Both checks here exist because a real defect got past a green local build:
#
#   BuildRequires   `BuildRequires: coreutils` made the RPM unsatisfiable on a
#                   Debian/Ubuntu builder, whose rpm database has never heard of a
#                   package by that name. It resolved on a Fedora workstation, so it
#                   passed locally and broke on the runner the release actually uses.
#                   Nothing here is compiled, so the correct number of build
#                   dependencies is zero.
#
#   changelog date  rpmbuild WARNS about a bogus weekday and carries on. A warning
#                   in a build log nobody reads is not a control. 2026-09-18 was a
#                   Friday and the spec said Thursday.
#
# Text-only: no rpm, no dpkg, no builder. It therefore runs inside `make check`, on any
# machine, before a commit rather than after a release.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================

"""usage: check_packaging.py"""
import datetime
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True).strip())
SPEC = ROOT / "packaging" / "rpm" / "isedraf.spec.in"
CONTROL = ROOT / "packaging" / "deb" / "control.in"
FAIL = []

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
CHANGELOG = re.compile(r"^\* (\w{3}) (\w{3}) (\d{1,2}) (\d{4}) ")


def bad(msg):
    FAIL.append(msg)
    print("  FAIL  %s" % msg)


print("--- packaging metadata (D-86, EXEC-016) ---")

if not SPEC.exists():
    bad("the rpm spec template is missing: %s" % SPEC)
else:
    text = SPEC.read_text(encoding="utf-8")

    # --- 1. no build dependencies -------------------------------------------------
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith("BuildRequires:"):
            bad("%s:%d declares a build dependency (%s). Nothing is compiled, and a "
                "BuildRequires that cannot be resolved on the release builder breaks "
                "the RPM for every release."
                % (SPEC.relative_to(ROOT), n, line.split(":", 1)[1].strip()))

    # --- 2. every changelog entry states the real weekday -------------------------
    entries = 0
    for n, line in enumerate(text.splitlines(), 1):
        m = CHANGELOG.match(line)
        if not m:
            continue
        entries += 1
        weekday, month, day, year = m.groups()
        if month not in MONTHS:
            bad("%s:%d has an unrecognised month %r"
                % (SPEC.relative_to(ROOT), n, month))
            continue
        actual = datetime.date(int(year), MONTHS[month], int(day)).strftime("%a")
        if actual != weekday:
            bad("%s:%d says %s for %s %s %s, which was a %s. rpmbuild only warns "
                "about this, and a warning in a build log nobody reads is not a "
                "control." % (SPEC.relative_to(ROOT), n, weekday, month, day, year,
                              actual))
    if entries == 0:
        # Z-18: a gate that passes over an empty input is not a gate.
        bad("%s has no %%changelog entries to check" % SPEC.relative_to(ROOT))

    # --- 3. the architecture claim the whole design rests on ----------------------
    if "BuildArch:      noarch" not in text and "BuildArch: noarch" not in text:
        bad("%s does not declare BuildArch: noarch" % SPEC.relative_to(ROOT))

if not CONTROL.exists():
    bad("the deb control template is missing: %s" % CONTROL)
elif "Architecture: all" not in CONTROL.read_text(encoding="utf-8"):
    bad("%s does not declare Architecture: all" % CONTROL.relative_to(ROOT))

if FAIL:
    print("=== packaging metadata gate FAILED ===")
    print("  A package that builds on the author's distribution is not a package.")
    sys.exit(1)
print("  OK    packaging metadata: no build dependencies, %d changelog date(s) correct, "
       "architecture declared" % entries)
