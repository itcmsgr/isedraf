#!/bin/sh
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: GA v0.1 lifecycle proof on a disposable VM: install, audit, report, reboot,
#          upgrade, remove, reinstall - and the evidence survives every step.
# Implements: D-86, D-90, EXEC-016, SCOPE-070, D-116, D-117, STORE-026
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

# Usage, inside the VM, with packages in ~/pkg/old and ~/pkg/new:
#   package_lifecycle.sh phase1      install OLD, audit, HTML report, verify
#   (reboot the VM from outside)
#   package_lifecycle.sh phase2      audit after reboot, upgrade to NEW, audit + report,
#                                    remove (evidence stays), reinstall, audit
# Each phase prints one JSON line. The evidence store is the default USER_PRODUCTION one:
# no ISEDRAF_STATE_ROOT and no XDG_STATE_HOME, exactly what an operator gets.
PHASE="${1:-}"
case "$PHASE" in phase1|phase2) ;; *) echo '{"error":"usage: phase1|phase2"}'; exit 64;; esac
unset ISEDRAF_STATE_ROOT XDG_STATE_HOME
STORE="$HOME/.local/state/isedraf"
# Phase 1's reference values must survive the reboot. They were kept in /tmp, which Debian
# and Ubuntu clear at boot, so phase 2 compared against nothing (GA proof, 2026-09-28).
REF="$HOME/.isedraf-lifecycle"
mkdir -p "$REF"
fail=""
note() { fail="$fail $1"; }

pick() {   # pick <dir>: the package this host's manager installs
    if command -v apt-get >/dev/null 2>&1; then ls "$1"/*.deb 2>/dev/null | head -1
    else ls "$1"/*.rpm 2>/dev/null | head -1; fi
}
install_pkg() {
    if command -v apt-get >/dev/null 2>&1; then sudo -n apt-get install -y --allow-downgrades "$1"
    elif command -v dnf >/dev/null 2>&1; then sudo -n dnf install -y --nogpgcheck "$1"
    else sudo -n zypper --non-interactive install --allow-unsigned-rpm "$1"; fi
}
remove_pkg() {
    if command -v apt-get >/dev/null 2>&1; then sudo -n apt-get remove -y isedraf
    elif command -v dnf >/dev/null 2>&1; then sudo -n dnf remove -y isedraf
    else sudo -n zypper --non-interactive remove isedraf; fi
}
audit_once() {   # audit_once <tag>: 0 or 2 is a completed run; anything else is a failure
    isedraf audit >"/tmp/audit-$1.txt" 2>&1; rc=$?
    case "$rc" in 0|2) ;; *) note "audit_$1_rc_$rc";; esac
}
report_once() {   # report_once <tag>: saved HTML, verified committed evidence
    path=$(isedraf report --html --save 2>/dev/null | tail -1)
    [ -f "$path" ] || note "report_$1_not_saved"
    html=$(cat "$path" 2>/dev/null)
    case "$html" in *"PRIVILEGE LEVEL: UNPRIVILEGED"*) ;; *) note "report_$1_banner";; esac
    json=$(isedraf report --json 2>/dev/null)
    case "$json" in *'"verified": true'*) ;; *) note "report_$1_not_verified";; esac
    case "$json" in *'"state_root_class": "USER_PRODUCTION"'*) ;; *) note "report_$1_class";; esac
}
snapshot_digest() {   # every committed snapshot, byte for byte
    (cd "$STORE/snapshots" 2>/dev/null && find . -type f -print0 | sort -z \
        | xargs -0 sha256sum 2>/dev/null | sha256sum | cut -c1-16)
}
ledger_records() { wc -l < "$STORE/ledger/segment-000001.jsonl" 2>/dev/null || echo 0; }
host_id() { isedraf report --json 2>/dev/null | sed -n 's/.*"host_id": "\(sha256:[0-9a-f]*\)".*/\1/p' | head -1; }

if [ "$PHASE" = phase1 ]; then
    OLD=$(pick ~/pkg/old); [ -n "$OLD" ] || { echo '{"error":"no old package"}'; exit 0; }
    rm -rf "$STORE"
    install_pkg "$OLD" >/tmp/install-old.log 2>&1 || note install_old_failed
    [ -f /usr/lib/isedraf/cli.py ] || note wrong_layout
    [ -n "$(find /usr/lib/isedraf -name '*.pyc' 2>/dev/null)" ] && note pyc_installed
    audit_once first
    report_once first
    MODE=$(stat -c %a "$STORE" 2>/dev/null)
    [ "$MODE" = 700 ] || note "store_mode_$MODE"
    host_id > "$REF/host-id"
    snapshot_digest > "$REF/snapshots"
    printf '{"phase":"phase1","version":"%s","ledger_records":%s,"failures":"%s","verdict":"%s"}\n' \
      "$(isedraf --version 2>&1 | head -1)" "$(ledger_records)" "$(echo $fail)" \
      "$([ -z "$fail" ] && echo PASS || echo FAIL)"
    exit 0
fi

# phase2 - after the reboot
NEW=$(pick ~/pkg/new); [ -n "$NEW" ] || { echo '{"error":"no new package"}'; exit 0; }
# A missing or empty reference would compare equal to an empty result and pass silently.
[ -s "$REF/snapshots" ] && [ -s "$REF/host-id" ] || note phase1_reference_missing
[ "$(snapshot_digest)" = "$(cat "$REF/snapshots" 2>/dev/null)" ] || note evidence_changed_across_reboot
audit_once after_reboot
BEFORE_UPGRADE=$(snapshot_digest)
install_pkg "$NEW" >/tmp/install-new.log 2>&1 || note upgrade_failed
[ "$(snapshot_digest)" = "$BEFORE_UPGRADE" ] || note evidence_changed_by_upgrade
audit_once after_upgrade
report_once after_upgrade
[ "$(host_id)" = "$(cat "$REF/host-id" 2>/dev/null)" ] || note host_id_changed
RECORDS=$(ledger_records)
[ "$RECORDS" -ge 3 ] 2>/dev/null || note "ledger_records_$RECORDS"
BEFORE_REMOVE=$(snapshot_digest)
remove_pkg >/tmp/remove.log 2>&1 || note remove_failed
# The FILE, not `command -v`: the shell's hash table still holds the old path.
[ -x /usr/bin/isedraf ] && note binary_present_after_remove
[ -d /usr/lib/isedraf ] && note package_files_present_after_remove
[ -d "$STORE" ] || note evidence_removed_with_package
[ "$(snapshot_digest)" = "$BEFORE_REMOVE" ] || note evidence_changed_by_remove
install_pkg "$NEW" >/tmp/reinstall.log 2>&1 || note reinstall_failed
audit_once after_reinstall
[ "$(ledger_records)" -gt "$RECORDS" ] 2>/dev/null || note ledger_not_continued

PY=$(command -v python3 || echo /usr/libexec/platform-python)
PYV=$("$PY" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])' 2>/dev/null || echo unknown)
OSN=$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")
printf '{"phase":"phase2","os":"%s","python":"%s","version":"%s","ledger_records":%s,"failures":"%s","verdict":"%s"}\n' \
  "$OSN" "$PYV" "$(isedraf --version 2>&1 | head -1)" "$(ledger_records)" "$(echo $fail)" \
  "$([ -z "$fail" ] && echo PASS || echo FAIL)"
