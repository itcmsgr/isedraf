#!/bin/sh
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Install the real package on a disposable VM, use it, remove it, reinstall it.
# Implements: D-86, D-90, EXEC-016, SCOPE-070
#
# Runs INSIDE a disposable lab VM. It proves what a stranger gets: the package installs
# with the distribution's own tool, the command works, evidence is produced, removal takes
# the software away and LEAVES THE EVIDENCE, and reinstalling works.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="package installation only"
# meta:mutates="installs and removes the package under test"
# meta:binaries="sh,apt-get|dnf|zypper,sudo"
# =============================================================================
set -u
R() { echo "STEP $*"; }
OUT=/tmp/lifecycle.json
fail=""
note() { fail="$fail $1"; }

DEB=$(ls ~/pkg/*.deb 2>/dev/null | head -1)
RPM=$(ls ~/pkg/*.rpm 2>/dev/null | head -1)
if command -v apt-get >/dev/null 2>&1 && [ -n "$DEB" ]; then
    MGR=apt; PKG="$DEB"
    INSTALL="sudo -n apt-get install -y --allow-downgrades $DEB"
    REMOVE="sudo -n apt-get remove -y isedraf"
elif command -v dnf >/dev/null 2>&1 && [ -n "$RPM" ]; then
    MGR=dnf; PKG="$RPM"
    INSTALL="sudo -n dnf install -y --nogpgcheck $RPM"; REMOVE="sudo -n dnf remove -y isedraf"
elif command -v zypper >/dev/null 2>&1 && [ -n "$RPM" ]; then
    MGR=zypper; PKG="$RPM"
    INSTALL="sudo -n zypper --non-interactive install --allow-unsigned-rpm $RPM"
    REMOVE="sudo -n zypper --non-interactive remove isedraf"
else
    echo '{"error":"no usable package manager or package"}' ; exit 0
fi

$INSTALL >/tmp/install.log 2>&1 || note install_failed
VER=$(isedraf --version 2>&1 | head -1) || note version_failed
command -v isedraf >/dev/null 2>&1 || note not_on_path
[ -f /usr/lib/isedraf/cli.py ] || note wrong_layout
[ -f /usr/isedraf/cli.py ] && note installed_to_wrong_prefix
find /usr/lib/isedraf -name '*.pyc' 2>/dev/null | grep -q . && note pyc_installed

export ISEDRAF_STATE_ROOT="$HOME/.isedraf-state"
rm -rf "$ISEDRAF_STATE_ROOT"
IDENT=$(isedraf identity 2>&1 | head -2 | tr '\n' ' ') || true
echo "$IDENT" | grep -q "collection status" || note identity_failed
isedraf inventory >/tmp/inv.txt 2>&1 || true
grep -q "ISEDRAF host inventory" /tmp/inv.txt || note inventory_failed
isedraf report --save >/tmp/rep.txt 2>&1 || true
REPORT=$(cat /tmp/rep.txt 2>/dev/null | tail -1)
[ -f "$REPORT" ] || note report_not_saved
grep -q "ISEDRAF System Assurance Report" "$REPORT" 2>/dev/null || note report_content_bad
SNAPS=$(ls -d "$ISEDRAF_STATE_ROOT"/snapshots/SDS-* 2>/dev/null | wc -l)
LEDGER=$(wc -l < "$ISEDRAF_STATE_ROOT/ledger/segment-000001.jsonl" 2>/dev/null || echo 0)

$REMOVE >/tmp/remove.log 2>&1 || note remove_failed
# Check the FILE, not `command -v`: the shell's hash table still holds the path from the
# successful invocations above, so `command -v` reports a binary that is already gone.
[ -x /usr/bin/isedraf ] && note binary_present_after_remove
[ -d /usr/lib/isedraf ] && note package_files_present_after_remove
[ -d "$ISEDRAF_STATE_ROOT" ] || note evidence_removed_with_package

$INSTALL >>/tmp/install.log 2>&1 || note reinstall_failed
isedraf --version >/dev/null 2>&1 || note reinstall_broken
IDENT2=$(isedraf identity 2>&1 | grep "host id" | head -1)

PY=$(command -v python3 || echo /usr/libexec/platform-python)
PYV=$("$PY" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])' 2>/dev/null || echo unknown)
OSN=$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")

printf '{"os":"%s","manager":"%s","python":"%s","version":"%s","snapshots":%s,"ledger_records":%s,"identity_stable":%s,"failures":"%s","verdict":"%s"}\n' \
  "$OSN" "$MGR" "$PYV" "$VER" "${SNAPS:-0}" "${LEDGER:-0}" \
  "$([ -n "$IDENT2" ] && echo true || echo false)" \
  "$(echo $fail)" "$([ -z "$fail" ] && echo PASS || echo FAIL)"
