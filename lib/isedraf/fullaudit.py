# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The reduced engine of a Full Audit run: prove its reduction, then build the bundle.
# Implements: AUTH-006, AUTH-018, AUTH-020, AUTH-021, AUTH-027
#
# The launcher starts this entry through setpriv as the `isedraf` account, with the run's
# staging directory as working directory and the supervisor channel on descriptors 3 and 4
# (AUTH-020). Before it collects anything it reads its own /proc/self/status and refuses
# with ENGINE_NOT_REDUCED unless its uid and gid are the isedraf account's, it has no
# supplementary group, all five capability sets are empty and no-new-privileges is set.
#
# It then collects, parses and normalizes exactly as `isedraf audit` does, and writes the
# bundle into its working directory with the shared snapshot.write_bundle: run mode
# FULL_AUDIT, class SYSTEM_PRODUCTION, run_id the name of the staging the launcher created.
# It never renames, promotes or ledgers anything; the launcher does (AUTH-021).
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged (the reduced isedraf account, no capability)"
# meta:mutates="state-root only"
# meta:binaries=""
# =============================================================================
"""Full Audit reduced engine: reduction self-check and the staged bundle."""
import os
import sys

from isedraf import audit, fixedop, hostio, identity, ids, snapshot, stateroot
from isedraf.accounts import sources
from isedraf.cli import ENGINE_VERSION
from isedraf.exitcodes import INCOMPLETE, OK, USAGE_OR_ENGINE

STATUS = "/proc/self/status"
PASSWD = "/etc/passwd"
ENGINE_ACCOUNT = "isedraf"
CAPABILITY_SETS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")


def reduction_problems(status_text, passwd_text, account=ENGINE_ACCOUNT):
    """Why this process is not the reduced engine of AUTH-020; empty when it is."""
    fields = {}
    for line in status_text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.split()
    problems = []
    uid, gid = fields.get("Uid", []), fields.get("Gid", [])
    for name, values in (("uid", uid), ("gid", gid)):
        if len(values) != 4 or len(set(values)) != 1 or values[0] == "0":
            problems.append("%s is %s, not one non-root identity" % (name, " ".join(values)))
    if fields.get("Groups"):
        problems.append("supplementary groups %s" % " ".join(fields["Groups"]))
    for key in CAPABILITY_SETS:
        values = fields.get(key)
        try:
            empty = len(values) == 1 and int(values[0], 16) == 0
        except (TypeError, ValueError):
            empty = False
        if not empty:
            problems.append("%s is not empty" % key)
    if fields.get("NoNewPrivs") != ["1"]:
        problems.append("no-new-privileges is not set")
    accounts = [r for r in sources.parse_passwd(passwd_text).records
                if not r.get("malformed") and r.get("name") == account]
    if len(accounts) != 1:
        problems.append("the %s account is not defined exactly once" % account)
    elif uid and gid and (str(accounts[0]["uid"]), str(accounts[0]["primary_gid"])) != (
            uid[0], gid[0]):
        problems.append("uid/gid %s/%s are not the %s account's" % (uid[0], gid[0], account))
    return problems


def run(out=None, err=None, channel=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    with open(STATUS) as fh:
        status_text = fh.read()
    passwd = hostio.read_file(PASSWD)
    problems = reduction_problems(status_text, passwd.value if passwd.ok else "")
    if problems:
        err.write("isedraf: ENGINE_NOT_REDUCED: %s\n" % "; ".join(problems))
        return USAGE_OR_ENGINE
    run_id = os.path.basename(os.getcwd())
    if not ids.ID_RE.match(run_id) or not run_id.startswith("RUN-"):
        err.write("isedraf: the engine is not in a run staging directory\n")
        return USAGE_OR_ENGINE
    sections, run_status = audit.collect("/", channel=channel, sandboxed=True)
    ident = identity.collect(identity.SOURCE_PATH)
    created_at, snapshot_id, _run, _event = snapshot.new_ids()
    built = snapshot.build(ident, snapshot_id, run_id, created_at,
                           stateroot.SYSTEM_PRODUCTION, ENGINE_VERSION,
                           coverage_manifest=audit.evidence_limits(sections, "/"),
                           sections=sections, run_mode=stateroot.FULL_AUDIT)
    previous = os.umask(0o077)
    try:
        snapshot.write_bundle(".", built)
    finally:
        os.umask(previous)
    out.write("  audit             : %s\n" % run_status)
    for name in audit.SECTIONS:
        out.write("    %-15s %s\n" % (name, sections[name]["collection_status"]))
    complete = ident.collected and run_status == "COLLECTED"
    return OK if complete else INCOMPLETE


def main():
    """The launcher's fixed entry. AUTH-020: the supervisor channel is on fds 3 (requests)
    and 4 (answers); closing both when the run ends lets the supervisor's loop finish."""
    try:
        return run(channel=fixedop.Channel(3, 4))
    finally:
        for fd in (3, 4):
            try:
                os.close(fd)
            except OSError:
                pass
