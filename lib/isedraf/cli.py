# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The isedraf command line — `isedraf identity`.
# Implements: SCOPE-070, SCOPE-071, SCOPE-077, SNAP-014, SNAP-018, IDENT-001, EXPL-002,
#             BASE-002, BASE-007, BASE-008
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
import os
import sys

from . import (ENGINE_VERSION, identity, inventory, ledger, report, snapshot,
               stateroot, verify)
from . import audit as audit_mod
from . import catalog, explain as explain_mod
from .baseline import approve as baseline_approve
from .baseline import revision as baseline_revision
from .evaluate import run as evaluate_run
from .exitcodes import (APPROVAL_REFUSED, INCOMPLETE, OK, PRIVILEGE_REFUSED, RUN_IN_PROGRESS,
                        STATE_ROOT_UNUSABLE, TOOL_INTEGRITY_FAILURE, USAGE_OR_ENGINE)

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
    if state_root_class in (stateroot.DEV, stateroot.USER_PRODUCTION):
        # GA v0.1 (D-117): stated on every run, never implied.
        out.write("  privilege level   : UNPRIVILEGED - evidence that needs root is\n")
        out.write("                      NOT_TESTED, never assumed\n")
    if not ident.collected:
        out.write("\nThe snapshot was still committed. A record of what could not be\n")
        out.write("collected is evidence; it is not a failure to report it.\n")


def _refused(exc, err):
    """SCOPE-071's message verbatim (frozen); it already says what to do."""
    err.write("isedraf: %s\n" % exc)


def cmd_identity(args, out=None, err=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    done = _commit_run(args.source, None, err)
    if isinstance(done, int):
        return done
    ident, snapshot_id, state_root_class, root = done
    _render(ident, snapshot_id, state_root_class, root, out)
    return OK if ident.collected else INCOMPLETE


def _commit_run(identity_source, audit_root, err):
    """Collect, build, commit and ledger one run; verify the store afterwards.

    Returns (ident, snapshot_id, state_root_class, root, sections, run_status) or an exit
    code. `audit_root` None is an identity-only run; otherwise every audit section is
    collected there once and travels in the same bundle (D-115), committed by the same
    atomic rename and ledger append (D-50) - there is no second commit mechanism.
    """
    try:
        root, state_root_class = stateroot.resolve()
    except stateroot.PrivilegeRefused as exc:
        _refused(exc, err)
        return PRIVILEGE_REFUSED
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE

    if state_root_class == stateroot.USER_PRODUCTION:
        # STORE-026/027, before anything is created or collected: the root must be the
        # invoking user's own 0700 directory, on storage whose commit semantics hold.
        # A refusal never falls back to another class or root.
        try:
            stateroot.check_user_root(root, os.geteuid())
        except stateroot.StateRootError as exc:
            err.write("isedraf: %s\n" % exc)
            return STATE_ROOT_UNUSABLE
        existing = root
        while not os.path.exists(existing) and os.path.dirname(existing) != existing:
            existing = os.path.dirname(existing)
        suitable, reason = stateroot.storage_suitability(existing)
        if not suitable:
            err.write("isedraf: %s\n" % reason)
            return STATE_ROOT_UNUSABLE

    try:
        stateroot.prepare(root)
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return STATE_ROOT_UNUSABLE

    try:
        with stateroot.RunLock(root):
            orphans = ledger.unledgered_snapshots(root)
            if len(orphans) > 1:
                # SNAP-018: more than one unledgered directory is store discontinuity,
                # which is NOT a crash artifact and is not silently recovered.
                err.write("isedraf: STORE_DISCONTINUITY — %d snapshots are not in the "
                          "ledger (SNAP-018)\n" % len(orphans))
                return INCOMPLETE

            ident = identity.collect(identity_source)
            sections, run_status = (audit_mod.collect(audit_root) if audit_root is not None
                                    else (None, None))
            created_at, snapshot_id, run_id, event_id = snapshot.new_ids()
            limits = (audit_mod.evidence_limits(sections, audit_root)
                      if audit_root is not None else None)
            built = snapshot.build(ident, snapshot_id, run_id, created_at,
                                   state_root_class, ENGINE_VERSION,
                                   coverage_manifest=limits, sections=sections,
                                   run_mode=stateroot.RUN_MODE_OF_CLASS[state_root_class])
            snapshot.commit(root, built, snapshot_id)
            core, _core_canonical, record_hash = ledger.build_record(
                root, snapshot_id, built["manifest_hash"], event_id, created_at,
                state_root_class)
            ledger.append(root, core, record_hash)

            problems = verify.verify_store(root)
    except stateroot.RunInProgress as exc:
        # AUTH-023: 66, and nothing was collected or written.
        err.write("isedraf: %s\n" % exc)
        return RUN_IN_PROGRESS
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return STATE_ROOT_UNUSABLE
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

    if audit_root is None:
        return ident, snapshot_id, state_root_class, root
    return ident, snapshot_id, state_root_class, root, sections, run_status


def cmd_audit(args, out=None, err=None):
    """Every built collector once, one committed run, then the report of that run."""
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    root = getattr(args, "root", "/")
    source = (identity.SOURCE_PATH if root in ("", "/")
              else os.path.join(root, identity.SOURCE_PATH.lstrip("/")))
    done = _commit_run(source, root, err)
    if isinstance(done, int):
        return done
    ident, snapshot_id, state_root_class, evidence_root, sections, run_status = done
    _render(ident, snapshot_id, state_root_class, evidence_root, out)
    out.write("  audit             : %s\n" % run_status)
    for name in audit_mod.SECTIONS:
        s = sections[name]
        out.write("    %-15s %s\n" % (name, s["collection_status"]))
    out.write("\nRender it with: isedraf report\n")
    complete = ident.collected and run_status == "COLLECTED"
    return OK if complete else INCOMPLETE


def cmd_evaluate(args, out=None, err=None):
    """EVAL-001: verify one committed snapshot, evaluate it, commit one evaluation.

    Never collects. The exit code says whether the evaluation completed (EVAL-007): a
    FAIL or a NOT_EVALUATED result is an assurance result, and still exits 0.
    """
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        root, state_root_class = stateroot.resolve()
    except stateroot.PrivilegeRefused as exc:
        _refused(exc, err)
        return PRIVILEGE_REFUSED
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE
    if state_root_class == stateroot.USER_PRODUCTION:
        try:
            stateroot.check_user_root(root, os.geteuid())
        except stateroot.StateRootError as exc:
            err.write("isedraf: %s\n" % exc)
            return STATE_ROOT_UNUSABLE
    if not os.path.isdir(os.path.join(root, "ledger")):
        err.write("isedraf: there is no committed run to evaluate in %s; run `isedraf audit` "
                  "first\n" % root)
        return USAGE_OR_ENGINE
    try:
        with stateroot.RunLock(root):
            evl_id, raw, results = evaluate_run.build(
                root, state_root_class, ENGINE_VERSION, snapshot_id=args.snapshot)
            path, created = evaluate_run.commit(root, evl_id, raw)
    except stateroot.RunInProgress as exc:
        err.write("isedraf: %s\n" % exc)
        return RUN_IN_PROGRESS
    except evaluate_run.EvaluationRefused as exc:
        err.write("isedraf: evaluation refused, nothing was written: %s\n" % exc)
        return USAGE_OR_ENGINE
    except baseline_revision.IntegrityFailure as exc:
        # BASE-008 (D-127): the baseline in force does not verify. Never re-read silently.
        err.write("isedraf: baseline integrity failure, nothing was written: %s\n" % exc)
        return TOOL_INTEGRITY_FAILURE
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return STATE_ROOT_UNUSABLE
    except Exception as exc:                          # pragma: no cover - engine failure
        err.write("isedraf: engine error: %s\n" % exc)
        return USAGE_OR_ENGINE
    out.write("ISEDRAF native evaluation\n")
    out.write("  evaluation        : %s%s\n" % (evl_id, "" if created else
                                                 " (already committed, identical)"))
    out.write("  evaluated snapshot: %s\n" % json.loads(raw["results.json"])["snapshot_id"])
    out.write("  evidence root     : %s (%s)\n" % (root, state_root_class))
    if state_root_class == stateroot.DEV:
        out.write("  note              : development state root; this evaluation is marked\n")
        out.write("                      DEV and is not production evidence\n")
    for r in results:
        out.write("  %-17s : %s  %s\n" % (r["criterion_id"], r["result"], r["reason_code"]))
        out.write("                      %s\n" % r["reason"])
        for o in r["observations"]:
            out.write("                      observed: %s\n" % report.render.observation_text(o))
    _render_changes(json.loads(raw["changes.json"]), out)
    out.write("\nScope: each result covers only the evidence its criterion names;\n")
    out.write("run `isedraf explain <criterion>` for what a result does not establish.\n")
    return OK


def _render_changes(changes, out):
    """The comparison, as committed in changes.json. Rendering only; nothing is decided here."""
    if changes.get("baseline_revision") is None:
        if changes.get("unledgered_revision"):
            out.write("  baseline          : none in force; %s has no ledger record (an "
                      "interrupted approval) and is not used\n" % changes["unledgered_revision"])
        return
    out.write("  baseline          : %s (approved %s), %s\n"
              % (changes["baseline_revision"], changes["approved_snapshot_id"],
                 changes["applicability"]))
    if changes.get("reason"):
        out.write("                      %s\n" % changes["reason"])
    for name, summary in sorted(changes.get("sections", {}).items()):
        out.write("  %-17s : %s%s\n" % (name, summary["result"],
                                          " (collection method changed)"
                                          if summary.get("method_changed") else ""))
    for row in changes.get("changes", []):
        if row["primitive"] == baseline_revision.MODIFIED:
            out.write("  change            : %s MODIFIED, %s\n"
                      % (row["section"], row["interpretation"]))
        else:
            out.write("  not comparable    : %s - %s\n" % (row["section"], row["reason"]))


def cmd_baseline_approve(args, out=None, err=None):
    """BASE-002/007 (D-127): approve one committed DEV snapshot as BL-000001. Explicit only.

    Exit 0 approved (or an interrupted approval of the same snapshot completed); 65 refused
    with a named reason, nothing written; 5 when completing an interrupted approval whose
    recorded baseline does not verify; 64 usage or evidence that does not verify; 66 lock
    held; 67 state root unusable; 70 root or sudo.
    """
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        root, state_root_class = stateroot.resolve()
    except stateroot.PrivilegeRefused as exc:
        _refused(exc, err)
        return PRIVILEGE_REFUSED
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE
    if state_root_class == stateroot.USER_PRODUCTION:
        try:
            stateroot.check_user_root(root, os.geteuid())
        except stateroot.StateRootError as exc:
            err.write("isedraf: %s\n" % exc)
            return STATE_ROOT_UNUSABLE
    if not os.path.isdir(os.path.join(root, "ledger")):
        err.write("isedraf: there is no committed run in %s; run `isedraf audit` first\n"
                  % root)
        return USAGE_OR_ENGINE
    try:
        with stateroot.RunLock(root):
            outcome, obj = baseline_approve.approve(
                root, state_root_class, args.snapshot_id,
                lambda sid: evaluate_run.verified_run(root, sid))
    except stateroot.RunInProgress as exc:
        err.write("isedraf: %s\n" % exc)
        return RUN_IN_PROGRESS
    except baseline_revision.ApprovalRefused as exc:
        err.write("isedraf: approval refused, nothing was written: %s\n" % exc)
        return APPROVAL_REFUSED
    except evaluate_run.EvaluationRefused as exc:
        err.write("isedraf: approval refused, nothing was written: %s\n" % exc)
        return USAGE_OR_ENGINE
    except baseline_revision.IntegrityFailure as exc:
        err.write("isedraf: baseline integrity failure, nothing was written: %s\n" % exc)
        return TOOL_INTEGRITY_FAILURE
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return STATE_ROOT_UNUSABLE
    except Exception as exc:                          # pragma: no cover - engine failure
        err.write("isedraf: engine error: %s\n" % exc)
        return USAGE_OR_ENGINE
    out.write("ISEDRAF baseline\n")
    out.write("  revision          : %s%s\n" % (obj["revision_id"], "" if outcome ==
              baseline_approve.APPROVED else " (an interrupted approval was completed)"))
    out.write("  approved snapshot : %s\n" % obj["snapshot_id"])
    out.write("  profile           : %s\n" % obj["profile"]["object"]["profile_id"])
    out.write("  sections          : %s\n" % ", ".join(obj["tracked_sections"]))
    out.write("  evidence root     : %s (%s)\n" % (root, state_root_class))
    out.write("  note              : a DEV baseline; it is not a production baseline and\n")
    out.write("                      is never exported as evidence. Approved means\n")
    out.write("                      accepted, not secure.\n")
    return OK


def cmd_explain(args, out=None, err=None):
    """EVAL-009: render one criterion record. No state root, no evidence, no evaluation."""
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        stateroot.check_unprivileged()
    except stateroot.PrivilegeRefused as exc:
        _refused(exc, err)
        return PRIVILEGE_REFUSED
    try:
        registry, _raw = catalog.load()
    except catalog.CatalogError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE
    record = catalog.criterion(registry, args.criterion_id)
    if record is None:
        err.write("isedraf: %s is not an admitted criterion; admitted: %s\n"
                  % (args.criterion_id, ", ".join(c["criterion_id"]
                                                 for c in registry["criteria"]) or "none"))
        return USAGE_OR_ENGINE
    out.write("\n".join(explain_mod.lines(record)) + "\n")
    return OK


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
        # D-114: the observations, not an invented class. `queue_rotational` is
        # printed as a queue property because that is what it is.
        rot = dev.get("queue_rotational")
        rot_text = "rotational" if rot is True else (
            "non-rotational" if rot is False else "rotational unknown")
        out.write("  %-17s : %s, %s, %s\n" % (
            dev["name"], "%.1f GB" % (dev["size_bytes"] / 1e9) if dev["size_bytes"] else "?",
            dev.get("kernel_subsystem") or "subsystem unknown", rot_text))
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
        _refused(exc, err)
        return PRIVILEGE_REFUSED
    except stateroot.StateRootError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE
    try:
        assessment = report.profile.load(getattr(args, "profile", None))
    except report.ProfileError as exc:
        err.write("isedraf: %s\n" % exc)
        return USAGE_OR_ENGINE
    committed = report.committed_run(root)
    if committed is None:
        err.write("isedraf: no committed audit run in %s; run `isedraf audit` first. "
                  "A report renders committed evidence and never collects.\n" % root)
        return USAGE_OR_ENGINE
    try:
        model_obj = report.build(root, committed["sections"]["inventory"]["evidence"],
                                 assessment=assessment,
                                 audit_sections=committed["sections"],
                                 audit_digests=committed["digests"],
                                 coverage_manifest=committed.get("evidence_limits"),
                                 snapshot_id=committed["snapshot_id"])
        if getattr(args, "json", False):
            rendered, extension = report.render.to_json(model_obj), "json"
        elif getattr(args, "html", False):
            rendered, extension = report.render.to_html(model_obj), "html"
        else:
            rendered, extension = report.render.to_markdown(model_obj), "md"
    except Exception as exc:                          # pragma: no cover - engine failure
        err.write("isedraf: engine error: %s\n" % exc)
        return USAGE_OR_ENGINE

    if getattr(args, "save", False):
        path = report.write(root, model_obj, rendered, extension)
        out.write("%s\n" % path)
    else:
        out.write(rendered)
    return OK if model_obj["report"]["status"] == "COMPLETE" else INCOMPLETE


class _Parser(argparse.ArgumentParser):
    """argparse, but a usage error exits 64 (SCOPE-077).

    argparse exits 2 on its own, and 2 is the frozen code for committed-but-incomplete
    evidence: a mistyped command read as "the run happened and the evidence is partial".
    Subparsers inherit this class.
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(USAGE_OR_ENGINE, "%s: error: %s\n" % (self.prog, message))


def main(argv=None):
    parser = _Parser(
        prog="isedraf",
        description="Linux host evidence and assurance tool")
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
    p_audit = sub.add_parser("audit", help="run every built collector once and commit "
                                           "the evidence as one run")
    p_audit.add_argument("--root", default="/",
                         help="filesystem root (testing; default %(default)s)")
    p_audit.set_defaults(func=cmd_audit)
    p_report = sub.add_parser("report", help="render the report of the latest committed "
                                             "audit run (never collects)")
    p_report.add_argument("--json", action="store_true",
                          help="emit the machine-readable report model")
    p_report.add_argument("--html", action="store_true",
                          help="emit the static HTML report (Report 0.1)")
    p_report.add_argument("--profile", default=None,
                          help="optional assessment profile file (JSON). Personal\n"
                               "details belong in a file, not in argv, which lands\n"
                               "in shell history and every process listing")
    p_report.add_argument("--save", action="store_true",
                          help="write the report under <state root>/reports/")
    p_report.set_defaults(func=cmd_report)
    p_evaluate = sub.add_parser("evaluate", help="evaluate the latest committed audit run "
                                                 "against the native criteria (never collects)")
    p_evaluate.add_argument("--snapshot", default=None,
                            help="a committed snapshot ID (default: the latest committed run)")
    p_evaluate.set_defaults(func=cmd_evaluate)
    p_baseline = sub.add_parser("baseline", help="approve a committed DEV run as the baseline; "
                                                 "a Full Audit run is approved with "
                                                 "`sudo isedraf baseline approve`")
    b_sub = p_baseline.add_subparsers(dest="baseline_command")
    p_approve = b_sub.add_parser("approve", help="approve one committed snapshot, explicitly")
    p_approve.add_argument("snapshot_id", help="the SDS-... identifier to approve")
    p_approve.set_defaults(func=cmd_baseline_approve)
    p_explain = sub.add_parser("explain", help="explain a native criterion (reads no evidence)")
    p_explain.add_argument("criterion_id", help="for example ISE-ACCOUNT-001")
    p_explain.set_defaults(func=cmd_explain)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return USAGE_OR_ENGINE
    return args.func(args)
