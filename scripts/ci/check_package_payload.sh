#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Inspect what is INSIDE the built packages, not what we meant to put there.
# Implements: D-86, D-90, GOV-002, EXEC-016
#
# A clean source tree is not a correct package. The DEB staged the payload to
# /usr/isedraf instead of /usr/lib/isedraf, where the launcher looks: it built, it
# installed, and the command did nothing. Nothing in the source tree was wrong.
#
# This unpacks each artifact and checks the bytes a user actually receives.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,ar,tar,rpm,python3,mktemp"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
DIST="${1:-$ROOT/dist}/packages"
FAIL=0
bad() { echo "  FAIL  $*" >&2; FAIL=1; }
ok()  { echo "  OK    $*"; }

[ -d "$DIST" ] || { echo "  FAIL  no built packages at $DIST — run packaging/build.sh" >&2; exit 1; }

# A gate that passes when there is nothing to inspect is not a gate. The build creates
# dist/packages before it stages anything, so a build that dies half way leaves an empty
# directory — and an earlier version of this script walked it, matched no glob, and
# reported success. Count first, judge second.
shopt -s nullglob
count_deb=("$DIST"/*.deb); count_rpm=("$DIST"/*.rpm); count_tgz=("$DIST"/*.tar.gz)
[ "${#count_deb[@]}" -gt 0 ] || bad "no .deb in $DIST — the build produced nothing to verify"
[ "${#count_tgz[@]}" -gt 0 ] || bad "no source tarball in $DIST"
if command -v rpmbuild >/dev/null 2>&1 && [ "${#count_rpm[@]}" -eq 0 ]; then
    bad "rpmbuild is available but no .rpm was produced"
fi
# The deb is assembled from $STAGE by packaging/build.sh; the rpm is assembled by the
# spec's own %install section from the source tarball. Two implementations of "what goes
# in the package" WILL drift - and they had: the rpm shipped two documents where the deb
# shipped four, so an EL user received half the documentation a Debian user did. Nothing
# in either tree was wrong. Comparing the two payloads against each other is the only
# thing that catches it.
DEB="$(find "$DIST" -maxdepth 1 -name '*.deb' ! -name '*latest*' | head -1)"
RPM="$(find "$DIST" -maxdepth 1 -name '*.rpm' ! -name '*latest*' | head -1)"
if [ -n "$DEB" ] && [ -n "$RPM" ] && command -v rpm >/dev/null 2>&1; then
    D="$(mktemp -d)"
    ar p "$DEB" data.tar.gz 2>/dev/null | tar tz 2>/dev/null \
        | grep 'usr/share/doc/isedraf/.' | sed 's|.*/||' | sort -u > "$D/deb"
    rpm -qlp "$RPM" 2>/dev/null \
        | grep 'usr/share/doc/isedraf/.' | sed 's|.*/||' | sort -u > "$D/rpm"
    if cmp -s "$D/deb" "$D/rpm"; then
        ok "deb and rpm ship the same $(wc -l < "$D/deb" | tr -d ' ') documentation files"
    else
        bad "deb and rpm ship DIFFERENT documentation:"
        diff "$D/deb" "$D/rpm" | sed 's/^/          /' >&2
    fi
    rm -rf "$D"
fi

[ "$FAIL" -eq 0 ] || { echo "  package payload gate FAILED" >&2; exit 1; }

# Anything here in a payload means a private or generated artifact escaped the build.
#
# The disposable-lab compatibility records under docs/compatibility/records/ are NOT on
# this list: they are the evidence behind the published platform claims, they describe
# machines that were destroyed after each campaign, and the privacy audit classified them
# as safe. A gate that forbids the evidence for a claim it also requires teaches people to
# disable it.
# CLAUDE.md, CONTRIBUTING.md and the development docs are PUBLIC by owner decision and
# ship in the git repository and the source tarball. They must not reach the RUNTIME
# payload: a package installs what the tool needs to run plus the documentation a user
# was meant to read, and contributor guardrails are neither. Verified, not assumed -
# they are absent today and this keeps them absent.
FORBIDDEN_PAYLOAD_DOCS='(^|/)(CLAUDE|CONTRIBUTING|CODE_OF_CONDUCT|AI_ASSISTED_DEVELOPMENT|CHANGELOG)\.md$'
FORBIDDEN_PATHS='(^|/)planning/|(^|/)\.git/|GITHUB_CONNECT|isedraf-w1c|\.pyc$|__pycache__|(^|/)usr/isedraf/|(^|/)dist/|id_ed25519|id_rsa|\.ssh/'
REQUIRED='usr/bin/isedraf usr/lib/isedraf/cli.py usr/lib/isedraf/identity.py usr/lib/isedraf/inventory/collectors.py usr/lib/isedraf/report/model.py'

check_listing() {   # check_listing <label> <file-with-one-path-per-line>
    local label="$1" listing="$2" missing=""
    for required in $REQUIRED; do
        grep -qE "(^|/)${required}$" "$listing" || missing="$missing $required"
    done
    [ -z "$missing" ] || bad "$label: missing from payload:$missing"
    if grep -qE "$FORBIDDEN_PATHS" "$listing"; then
        bad "$label: forbidden content in payload:"
        grep -E "$FORBIDDEN_PATHS" "$listing" | sed 's/^/          /' >&2
    fi
    if grep -qE "$FORBIDDEN_PAYLOAD_DOCS" "$listing"; then
        bad "$label: development documentation in the runtime payload:"
        grep -E "$FORBIDDEN_PAYLOAD_DOCS" "$listing" | sed 's/^/          /' >&2
    fi
    # The launcher resolves <prefix>/lib/isedraf from its own location.
    grep -qE "(^|/)usr/isedraf/" "$listing" \
        && bad "$label: payload installs to /usr/isedraf; the launcher looks in /usr/lib/isedraf"
    [ "$FAIL" -eq 0 ] && ok "$label: layout correct, no forbidden content"
}

# ---- DEB --------------------------------------------------------------------------------
for deb in "$DIST"/*.deb; do
    [ -e "$deb" ] || continue
    case "$deb" in *latest*) continue;; esac
    T="$(mktemp -d)"
    ar p "$deb" data.tar.gz 2>/dev/null | tar tz > "$T/list" 2>/dev/null \
        || { bad "$(basename "$deb"): data.tar.gz unreadable"; rm -rf "$T"; continue; }
    check_listing "deb $(basename "$deb")" "$T/list"
    ar p "$deb" control.tar.gz 2>/dev/null | tar xzO ./control > "$T/control" 2>/dev/null
    grep -q "^Architecture: all$" "$T/control" \
        || bad "deb: Architecture is not 'all'; the payload has nothing architecture-specific"
    grep -q "^Depends: python3" "$T/control" || bad "deb: no python3 dependency declared"
    rm -rf "$T"
done

# ---- RPM --------------------------------------------------------------------------------
if command -v rpm >/dev/null 2>&1; then
    for pkg in "$DIST"/*.rpm; do
        [ -e "$pkg" ] || continue
        case "$pkg" in *latest*) continue;; esac
        T="$(mktemp -d)"
        rpm -qlp "$pkg" 2>/dev/null | sed 's|^/||' > "$T/list"
        check_listing "rpm $(basename "$pkg")" "$T/list"
        arch="$(rpm -qp --queryformat '%{ARCH}' "$pkg" 2>/dev/null)"
        [ "$arch" = "noarch" ] || bad "rpm: BuildArch is '$arch', expected noarch"
        # RPM's generator re-adds this on its own, and it breaks EL8, which ships no
        # /usr/bin/python3 and runs ISEDRAF on its vendor interpreter.
        if rpm -qp --requires "$pkg" 2>/dev/null | grep -qx "/usr/bin/python3"; then
            bad "rpm: an unconditional /usr/bin/python3 requirement reappeared — it would"
            bad "      force a runtime onto EL8 hosts that already have a working one"
        else
            ok "rpm: no unconditional /usr/bin/python3 requirement"
        fi
        rm -rf "$T"
    done
fi

# ---- source tarball ----------------------------------------------------------------------
for tgz in "$DIST"/*.tar.gz; do
    [ -e "$tgz" ] || continue
    case "$tgz" in *latest*) continue;; esac
    T="$(mktemp -d)"
    tar tzf "$tgz" > "$T/list" 2>/dev/null || { bad "tarball unreadable"; rm -rf "$T"; continue; }
    if grep -qE "$FORBIDDEN_PATHS" "$T/list"; then
        bad "tarball: forbidden content:"
        grep -E "$FORBIDDEN_PATHS" "$T/list" | sed 's/^/          /' >&2
    else
        ok "tarball $(basename "$tgz"): no forbidden content"
    fi
    rm -rf "$T"
done

[ "$FAIL" -eq 0 ] || { echo "  package payload gate FAILED" >&2; exit 1; }
echo "  OK    package payloads verified"
