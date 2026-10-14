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

# --- 4. the version a package installs is the version it stamps into evidence ---------
# SNAP-020: ENGINE_VERSION is "the VERSION file verbatim" and goes into every snapshot
# manifest as provenance. A VERSION bump without the constant built a package that
# installed as one version and recorded another (GA lifecycle proof, 2026-09-28).
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
engine = re.search(r'^ENGINE_VERSION = "([^"]*)"', (ROOT / "lib" / "isedraf" / "__init__.py")
                   .read_text(encoding="utf-8"), re.M)
if not engine or engine.group(1) != version:
    bad("VERSION is %s but ENGINE_VERSION in lib/isedraf/__init__.py is %s; a package "
        "would install as one version and record the other in its evidence (SNAP-020)"
        % (version, engine.group(1) if engine else "missing"))

# --- 5. the state root is declared, never repaired (AUTH-027, AUTH-026, D-60) ------------
# The package declares /var/lib/isedraf as an empty root:root 0700 payload directory and the
# isedraf account through sysusers. No maintainer script or scriptlet may create, change or
# remove the state root: that would move StateDirectory='s silent repair into packaging.
BUILD = ROOT / "packaging" / "build.sh"
POSTINST = ROOT / "packaging" / "deb" / "postinst"
SYSUSERS = ROOT / "packaging" / "sysusers" / "isedraf.conf"
MUTATION = re.compile(r"\b(mkdir|chmod|chown|chgrp|rm|rmdir|install|mv|ln|setfacl|"
                      r"useradd|userdel|groupadd|groupdel|adduser|deluser)\b")
build_text = BUILD.read_text(encoding="utf-8") if BUILD.exists() else ""
# AUTH-027 refined 2026-10-08: dpkg replaces an existing file or dangling symlink with a
# payload directory, so the deb never carries the state root as payload.
staging_lines = [l.split("#", 1)[0] for l in build_text.splitlines()
                 if l.strip().startswith(("install", "mkdir"))]
if [l for l in staging_lines if "/var/lib/isedraf" in l]:
    bad("packaging/build.sh stages /var/lib/isedraf as payload (AUTH-027)")
if "-C \"$DEBROOT\" usr var" in build_text:
    bad("packaging/build.sh ships var/ in the deb data archive (AUTH-027)")
GHOST = "%ghost %dir %attr(0700,root,root) /var/lib/isedraf"
# AUTH-027 as refined 2026-10-08: the ONE maintainer-script line allowed to name the state
# root. It creates the root only when nothing exists at the path and never touches an object.
RPM_CREATE_IF_ABSENT = ("if [ ! -e /var/lib/isedraf ] && [ ! -L /var/lib/isedraf ]; then "
                        "mkdir -m 0700 /var/lib/isedraf || :; fi")
if SPEC.exists():
    spec_lines = [l.strip() for l in SPEC.read_text(encoding="utf-8").splitlines()]
    if GHOST not in spec_lines:
        bad("the rpm spec does not declare %s (AUTH-027: never payload truth)" % GHOST)
    if [l for l in spec_lines if "/var/lib/isedraf" in l and l.startswith("%dir")]:
        bad("the rpm spec declares /var/lib/isedraf as payload; rpm repairs payload "
            "directories on reinstall (AUTH-027)")
    if [l for l in spec_lines if l.startswith("install") and "/var/lib/isedraf" in l]:
        bad("the rpm %install stages /var/lib/isedraf as payload (AUTH-027)")
if not SYSUSERS.exists() or not re.search(r"^u isedraf - ", SYSUSERS.read_text(
        encoding="utf-8"), re.M):
    bad("packaging/sysusers/isedraf.conf does not declare the isedraf account (D-60)")
scripts = []
if POSTINST.exists():
    scripts.append(("packaging/deb/postinst", POSTINST.read_text(encoding="utf-8")))
if SPEC.exists():
    spec_text = SPEC.read_text(encoding="utf-8")
    for section in re.findall(r"^%(?:pre|post|preun|postun|pretrans|posttrans)\b.*?(?=^%\w)",
                              spec_text, re.M | re.S):
        scripts.append(("rpm scriptlet", section))
allowed = {}
for label, body in scripts:
    for n, line in enumerate(body.splitlines(), 1):
        code = line.split("#", 1)[0]
        if code.strip() == RPM_CREATE_IF_ABSENT:
            allowed[label] = allowed.get(label, 0) + 1
            continue
        if MUTATION.search(code) or "/var/lib/isedraf" in code:
            bad("%s:%d mutates files or accounts (%s); only systemd-sysusers may run "
                "(AUTH-026, AUTH-027, D-60)" % (label, n, code.strip()))

for label in ("packaging/deb/postinst", "rpm scriptlet"):
    if allowed.get(label, 0) != 1:
        bad("%s must create the state root exactly once, only when absent (found %d "
            "create-if-absent lines; AUTH-027)" % (label, allowed.get(label, 0)))

if FAIL:
    print("=== packaging metadata gate FAILED ===")
    print("  A package that builds on the author's distribution is not a package.")
    sys.exit(1)
print("  OK    packaging metadata: no build dependencies, %d changelog date(s) correct, "
       "architecture declared, VERSION matches ENGINE_VERSION" % entries)
