# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The isedraf command line — `isedraf identity`.
# Implements: SCOPE-070, SCOPE-071, SCOPE-077, SNAP-014, SNAP-018, IDENT-001, EXPL-002
#
# The renderer is the LAST stage and never feeds anything back: no rendered string is
# hashed, stored or compared. Canonical state is produced upstream and read-only here.
#
# meta:type="cli"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="state-root only"
# meta:binaries=""
# =============================================================================

"""`isedraf identity` and `isedraf inventory`."""
import argparse
import json
import sys

from . import (ENGINE_VERSION, identity, inventory, ledger, report, snapshot,
               stateroot, verify)
from .exitcodes import INCOMPLETE, OK, PRIVILEGE_REFUSED, USAGE_OR_ENGINE

# SNAP-022's vocabulary, rendered for an operator. The token is the evidence; this text
# is only the explanation, and it never becomes state.
_REASON_TEXT = {
    "SOURCE_ABSENT": "%s does not exist" % identity.SOURCE_PATH,
    "SOURCE_UNREADABLE": "%s could not be read" % identity.SOURCE_PATH,
    "SYNTAX_REJECTED": "%s did not match the frozen machine-id grammar"
                       % identity.SOURCE_PATH,
    "INTEGER_OUT_OF_RANGE": "a normalized integer was out of range",
    "INTERNAL_ERROR": "an unanticipated failure occurred during collection",
}


def _render(ident, snapshot_id, state_root_class, root, out):
    out.write("ISEDRAF host identity\n")
    out.write("  collection status : %s\n" % ident.status)
    if ident.collected:
        # The host_id is a digest of the normalized source. The raw machine-id is NEVER
        # rendered: it is a stable hardware-adjacent identifier and printing it by default
        # would export exactly what the derivation exists to avoid.
        out.write("  host id           : %s\n" % ident.host_id)
    else:
        out.write("  reason            : %s\n" % ident.reason)
        out.write("                      %s\n"
                  % _REASON_TEXT.get(ident.reason, "see the frozen reason vocabulary"))
        out.write("  host id           : not derived\n")
    out.write("  snapshot          : %s\n" % snapshot_id)
    out.write("  evidence root     : %s (%s)\n" % (root, state_root_class))
    if state_root_class == stateroot.DEV:
        out.write("  note              : development state root; these artifacts are\n")
        out.write("                      marked DEV and are not production evidence\n")
    if not ident.collected:
        out.write("\nThe snapshot was still committed. A record of what could not be\n")
        out.write("collected is evidence; it is not a failure to report it.\n")


def cmd_identity(args, out=None, err=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        root, state_root_class = stateroot.resolve()
    except stateroot.PrivilegeRefused as exc:
        err.write("isedraf: %s (SCOPE-071)\n" % exc)
        return PRIVILEGE_REFUSED
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE

    try:
        stateroot.prepare(root)
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE

    try:
        with stateroot.RunLock(root):
            orphans = ledger.unledgered_snapshots(root)
            if len(orphans) > 1:
                # SNAP-018: more than one unledgered directory is store discontinuity,
                # which is NOT a crash artifact and is not silently recovered.
                err.write("isedraf: STORE_DISCONTINUITY — %d snapshots are not in the "
                          "ledger (SNAP-018)\n" % len(orphans))
                return INCOMPLETE

            ident = identity.collect(args.source)
            created_at, snapshot_id, run_id, event_id = snapshot.new_ids()
            built = snapshot.build(ident, snapshot_id, run_id, created_at,
                                   state_root_class, ENGINE_VERSION)
            snapshot.commit(root, built, snapshot_id)
            core, _core_canonical, record_hash = ledger.build_record(
                root, snapshot_id, built["manifest_hash"], event_id, created_at,
                state_root_class)
            ledger.append(root, core, record_hash)

            problems = verify.verify_store(root)
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE
    except Exception as exc:                          # pragma: no cover - engine failure
        err.write("isedraf: engine error: %s\n" % exc)
        return USAGE_OR_ENGINE

    if problems:
        # The engine wrote evidence it cannot itself verify. That is an engine failure and
        # is reported as one; it is never reported as a successful collection.
        err.write("isedraf: committed evidence failed verification:\n")
        for p in problems:
            err.write("  %s\n" % p)
        return USAGE_OR_ENGINE

    _render(ident, snapshot_id, state_root_class, root, out)
    return OK if ident.collected else INCOMPLETE


_STATUS_NOTE = {
    "NOT_TESTED": "not observable here",
    "PARTIAL": "partly observable",
    "ERROR": "observation failed",
}


def _render_inventory(inv, out):
    d = inv["subdomains"]

    def field(block, name):
        return (d[block].get("data") or {}).get(name)

    out.write("ISEDRAF host inventory\n")
    out.write("  collection        : %s\n" % inv["collection_status"])
    out.write("\nPLATFORM\n")
    out.write("  hostname          : %s\n" % (field("host", "hostname") or "-"))
    out.write("  fqdn              : %s\n"
              % (field("host", "fqdn") or "not resolvable locally"))
    out.write("  os                : %s\n" % (field("platform", "pretty_name") or "-"))
    out.write("  kernel            : %s\n" % (field("platform", "kernel_release") or "-"))
    out.write("  architecture      : %s\n" % (field("platform", "architecture") or "-"))
    out.write("  init              : %s\n" % (field("platform", "init_system") or "-"))
    virt = field("machine", "virtualized")
    out.write("  machine           : %s%s\n" % (
        {True: "virtual", False: "physical", None: "unknown"}[virt],
        " (%s)" % field("machine", "hypervisor") if field("machine", "hypervisor") else ""))
    out.write("  vendor / product  : %s / %s\n" % (field("machine", "vendor") or "-",
                                                    field("machine", "product") or "-"))
    out.write("\nCOMPUTE\n")
    out.write("  cpu               : %s\n" % (field("compute", "cpu_model") or "-"))
    out.write("  sockets / cores   : %s / %s   logical: %s\n" % (
        field("compute", "sockets") or "-", field("compute", "cores_per_socket") or "-",
        field("compute", "logical_cpus") or "-"))
    for label, key in (("memory", "total_bytes"), ("swap", "swap_total_bytes")):
        value = field("memory", key)
        out.write("  %-17s : %s\n" % (label,
                  "%.1f GiB" % (value / (1024.0 ** 3)) if value else "-"))

    out.write("\nSTORAGE\n")
    for dev in field("storage", "devices") or []:
        out.write("  %-17s : %s, %s\n" % (
            dev["name"], "%.1f GB" % (dev["size_bytes"] / 1e9) if dev["size_bytes"] else "?",
            dev["type"]))
    for fs in (field("storage", "filesystems") or [])[:8]:
        out.write("  %-17s : %s%s\n" % (fs["mount_point"], fs["fstype"],
                                         " (read-only)" if fs["read_only"] else ""))

    out.write("\nNETWORK\n")
    for iface in field("network", "interfaces") or []:
        if iface["loopback"]:
            continue
        out.write("  %-17s : %s, mtu %s\n" % (iface["name"], iface["state"], iface["mtu"]))
    for a in field("network", "ipv4") or []:
        if not a["loopback"]:
            out.write("  ipv4              : %s/%s on %s\n"
                      % (a["address"], a["prefix_length"], a["interface"]))
    for a in field("network", "ipv6_stable") or []:
        if a["classification"] != "LOOPBACK":
            out.write("  ipv6              : %s/%s on %s  [%s]\n"
                      % (a["address"], a["prefix_length"], a["interface"],
                         a["classification"]))
    volatile = field("network", "ipv6_volatile") or []
    if volatile:
        out.write("  ipv6 (temporary)  : %d address(es), rotate by design (RFC 4941)\n"
                  % len(volatile))
    for r in field("network", "default_routes") or []:
        out.write("  default route     : %s via %s (%s)\n"
                  % (r["family"], r["gateway"], r["interface"]))
    servers = field("dns", "servers") or []
    out.write("  dns               : %s\n" % (", ".join(servers) or "-"))

    out.write("\nTIME\n")
    out.write("  timezone          : %s\n" % (field("time", "timezone") or "-"))
    out.write("  ntp provider      : %s\n" % (field("time", "provider") or "none detected"))
    enabled, synced = field("time", "ntp_enabled"), field("time", "synchronized")
    out.write("  ntp enabled       : %s\n" % {True: "yes", False: "no", None: "unknown"}[enabled])
    out.write("  synchronized      : %s\n" % {True: "yes", False: "NO", None: "unknown"}[synced])
    if synced is False:
        # REC-005: this is not cosmetic. Event times collected now cannot be trusted
        # for ordering, and the qualifier exists so nobody has to remember that later.
        out.write("                      CLOCK_UNSYNCHRONIZED — event times observed on\n")
        out.write("                      this host carry no ordering guarantee (REC-005)\n")
    if field("time", "source"):
        out.write("  current source    : %s (stratum %s)\n"
                  % (field("time", "source"), field("time", "stratum")))

    incomplete = [(n, b["collection_status"]) for n, b in sorted(d.items())
                  if b["collection_status"] != "COLLECTED"]
    if incomplete:
        out.write("\nNOT FULLY COLLECTED\n")
        for name, status in incomplete:
            out.write("  %-17s : %s — %s\n"
                      % (name, status, _STATUS_NOTE.get(status, status)))
        out.write("\nAn incomplete observation is reported as incomplete. It is never\n")
        out.write("rendered as an empty success.\n")


def cmd_inventory(args, out=None, err=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        inv = inventory.collect(root=getattr(args, "root", "/"))
    except Exception as exc:                          # pragma: no cover - engine failure
        err.write("isedraf: engine error: %s\n" % exc)
        return USAGE_OR_ENGINE
    if getattr(args, "json", False):
        json.dump(inv, out, indent=2, sort_keys=True)
        out.write("\n")
    else:
        _render_inventory(inv, out)
    return OK if inv["collection_status"] == "COLLECTED" else INCOMPLETE


def cmd_report(args, out=None, err=None):
    """Render a report from evidence that already exists. Never collects identity.

    Rendering must not change what is being reported on, so this reads the committed
    snapshot and ledger rather than running a new collection.
    """
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        root, _class = stateroot.resolve()
    except stateroot.PrivilegeRefused as exc:
        err.write("isedraf: %s (SCOPE-071)\n" % exc)
        return PRIVILEGE_REFUSED
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE
    try:
        assessment = report.profile.load(getattr(args, "profile", None))
    except report.ProfileError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE
    try:
        inv = inventory.collect()
        model_obj = report.build(root, inv, assessment=assessment)
        rendered = (report.render.to_json(model_obj) if getattr(args, "json", False)
                    else report.render.to_markdown(model_obj))
    except Exception as exc:                          # pragma: no cover - engine failure
        err.write("isedraf: engine error: %s\n" % exc)
        return USAGE_OR_ENGINE

    if getattr(args, "save", False):
        path = report.write(root, model_obj, rendered,
                            "json" if getattr(args, "json", False) else "md")
        out.write("%s\n" % path)
    else:
        out.write(rendered)
    return OK if model_obj["report"]["status"] == "COMPLETE" else INCOMPLETE


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="isedraf",
        description="Linux host assurance, approved baseline, state delta and evidence.")
    parser.add_argument("--version", action="version",
                        version="isedraf %s" % ENGINE_VERSION)
    sub = parser.add_subparsers(dest="command")
    p_identity = sub.add_parser("identity", help="collect host identity and snapshot it")
    p_identity.add_argument("--source", default=identity.SOURCE_PATH,
                            help="identity source path (testing; default %(default)s)")
    p_identity.set_defaults(func=cmd_identity)
    p_inventory = sub.add_parser("inventory",
                                 help="collect and show the host inventory")
    p_inventory.add_argument("--json", action="store_true",
                             help="emit the normalized inventory object")
    p_inventory.add_argument("--root", default="/",
                             help="filesystem root (testing; default %(default)s)")
    p_inventory.set_defaults(func=cmd_inventory)
    p_report = sub.add_parser("report", help="render a system assurance report")
    p_report.add_argument("--json", action="store_true",
                          help="emit the machine-readable report model")
    p_report.add_argument("--profile", default=None,
                          help="optional assessment profile file (JSON). Personal\n"
                               "details belong in a file, not in argv, which lands\n"
                               "in shell history and every process listing")
    p_report.add_argument("--save", action="store_true",
                          help="write the report under <state root>/reports/")
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return USAGE_OR_ENGINE
    return args.func(args)
