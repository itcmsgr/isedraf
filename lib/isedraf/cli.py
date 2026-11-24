# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The isedraf command line — `isedraf identity`.
# Implements: SCOPE-070, SCOPE-071, SCOPE-077, SNAP-014, SNAP-018, IDENT-001, EXPL-002, D-129,
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
from . import catalog, commands, explain as explain_mod, listing, space, summary
from .baseline import approve as baseline_approve
from .baseline import revision as baseline_revision
from .evaluate import run as evaluate_run
from .exitcodes import (APPROVAL_REFUSED, INCOMPLETE, INSUFFICIENT_SPACE, OK, PRIVILEGE_REFUSED,
                        RUN_IN_PROGRESS, STATE_ROOT_UNUSABLE, TOOL_INTEGRITY_FAILURE,
                        USAGE_OR_ENGINE)

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


def _fit(line):
    """One `  label : value` line within the terminal rule: when it would pass 80 columns, the
    label stands on its line and the value follows, indented, wrapped by words (an identifier,
    path or digest is one word and stays whole)."""
    if summary.within_terminal(line):
        return [line]
    label, sep, value = line.partition(" : ")
    if not sep:
        return summary.wrap("  ", line.strip(), 4)
    head = label.rstrip() + " :"
    return ([head] if len(head) <= summary.TERMINAL else [label.rstrip()]) + summary.wrap(
        "    ", value, 4)


class _Fitted(object):
    """A text stream that passes every complete line through _fit (host-supplied values such as
    a CPU model, a vendor string or a mount point have no length bound)."""

    def __init__(self, out):
        self.out, self.pending = out, ""

    def write(self, text):
        self.pending += text
        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            self.out.write("\n".join(_fit(line)) + "\n")

    def close(self):
        if self.pending:
            self.out.write("\n".join(_fit(self.pending)))
            self.pending = ""


def _field(out, label, value):
    """`  label : value`, within the terminal rule (_fit)."""
    out.write("\n".join(_fit("  %-17s : %s" % (label, value))) + "\n")


def _render(ident, snapshot_id, state_root_class, root, out):
    out.write("ISEDRAF host identity\n")
    out.write("  collection status : %s\n" % ident.status)
    if ident.collected:
        # The host_id is a digest of the normalized source. The raw machine-id is NEVER
        # rendered: it is a stable hardware-adjacent identifier and printing it by default
        # would export exactly what the derivation exists to avoid.
        _field(out, "host id", ident.host_id)
    else:
        out.write("  reason            : %s\n" % ident.reason)
        out.write("                      %s\n"
                  % _REASON_TEXT.get(ident.reason, "see the frozen reason vocabulary"))
        out.write("  host id           : not derived\n")
    _field(out, "snapshot", snapshot_id)
    _field(out, "evidence root", root)                 # a path: never joined to other text
    _field(out, "evidence class", state_root_class)
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


# v0.5 P3: what a refused or failed run wrote, in one wording each.
NOTHING_COLLECTED = "Nothing was collected or written."
NOT_COMMITTED = ("No run was committed; evidence committed earlier is unchanged.")
AGAIN_LATER = "wait for the other ISEDRAF run to finish, then run the same command again"
NEVER_DELETES = "ISEDRAF never deletes evidence to make room."


def _recover_ledger(root, state_root_class, err):
    """STORE-016 (v0.5), under the caller's lock, before anything is collected or written: a
    torn tail of the newest ledger segment is kept and sealed by a new segment. Returns None to
    go on, or the exit code of a refusal (nothing was collected or written)."""
    occurred_at, _sid, _run, event_id = snapshot.new_ids()
    try:
        core = ledger.recover(root, state_root_class, occurred_at, event_id)
    except ledger.IntegrityFailure as exc:
        err.write(summary.refusal("%s; the ledger is not recovered or changed" % exc,
                                  NOTHING_COLLECTED))
        return USAGE_OR_ENGINE
    except OSError as exc:
        if space.out_of_space(exc):
            err.write(summary.refusal("%s: the ledger recovery found no space (%s)"
                                      % (space.REASON, exc), NOTHING_COLLECTED + " " +
                                      NEVER_DELETES, "free space on that filesystem, then run "
                                      "the command again"))
            return INSUFFICIENT_SPACE
        raise
    if core is not None:
        err.write(summary.recovered_notice(core["damaged_segment"]))
    return None


def _refuse_unrecovered(root, err):
    """STORE-016 (v0.5): report, list and evaluate never recover the ledger; an unrecovered
    torn tail or a ledger that does not verify is refused (64), nothing is written, and the
    command that recovers it is named. Returns None to go on, or the exit code."""
    try:
        torn = ledger.torn_tail(root)
    except (ledger.IntegrityFailure, OSError) as exc:
        err.write(summary.refusal(str(exc), "Nothing was written."))
        return USAGE_OR_ENGINE
    if torn is None:
        return None
    err.write(summary.refusal(
        "%s: %s ends in an incomplete record that is not yet recovered (STORE-016)"
        % (ledger.TORN_TAIL, torn["segment"]), "Nothing was written.",
        "isedraf audit (it recovers the ledger first, keeping the damaged bytes)"))
    return USAGE_OR_ENGINE


def _identity_lines(ident, state_root_class, out):
    """The host identity part of an audit, in the audit summary's compact form."""
    # 80 columns (rc2 acceptance): the host id, a 71-character hash, is never split; it gets
    # its own indented line.
    lines = []
    if ident.collected:
        lines += ["host identity: %s, host id" % ident.status, "  %s" % ident.host_id]
    else:
        lines += summary.wrap("host identity: ", "%s, %s (%s); host id not derived" % (
            ident.status, _REASON_TEXT.get(ident.reason, "see the frozen reason vocabulary"),
            ident.reason), 2)
    if state_root_class == stateroot.DEV:
        lines += summary.wrap("note: ", "development state root; these artifacts are marked DEV "
                              "and are not production evidence", 2)
    if state_root_class in (stateroot.DEV, stateroot.USER_PRODUCTION):
        lines += summary.wrap("privilege level: ", "UNPRIVILEGED - evidence that needs root is "
                              "NOT_TESTED, never assumed", 2)
    out.write("\n".join(lines) + "\n")


def _refused(exc, err):
    """SCOPE-071's message verbatim (frozen); it already says what to do."""
    err.write("isedraf: %s\n" % exc)


def cmd_identity(args, out=None, err=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    done = _commit_run(args.source, None, err)
    if isinstance(done, int):
        return done
    ident, snapshot_id, state_root_class, root, created_at = done
    out.write(summary.header("isedraf identity", state_root_class, snapshot_id, created_at))
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
        err.write(summary.refusal(str(exc), NOTHING_COLLECTED))
        return USAGE_OR_ENGINE

    if state_root_class == stateroot.USER_PRODUCTION:
        # STORE-026/027, before anything is created or collected: the root must be the
        # invoking user's own 0700 directory, on storage whose commit semantics hold.
        # A refusal never falls back to another class or root.
        try:
            stateroot.check_user_root(root, os.geteuid())
        except stateroot.StateRootError as exc:
            err.write(summary.refusal(str(exc), NOTHING_COLLECTED))
            return STATE_ROOT_UNUSABLE
        existing = root
        while not os.path.exists(existing) and os.path.dirname(existing) != existing:
            existing = os.path.dirname(existing)
        suitable, reason = stateroot.storage_suitability(existing)
        if not suitable:
            err.write(summary.refusal(reason, NOTHING_COLLECTED))
            return STATE_ROOT_UNUSABLE

    # STORE-016, STORE-022 (D-129 Q4): room for the run and a recovery record, checked before
    # the store is prepared and before anything is collected. Never deletes anything.
    try:
        space.preflight(root)
    except space.InsufficientSpace as exc:
        err.write(summary.refusal(str(exc), NOTHING_COLLECTED + " " + NEVER_DELETES,
                                  "free space on that filesystem, then run the command again"))
        return INSUFFICIENT_SPACE

    try:
        stateroot.prepare(root)
    except stateroot.StateRootError as exc:
        err.write(summary.refusal(str(exc), NOTHING_COLLECTED))
        return STATE_ROOT_UNUSABLE

    try:
        with stateroot.RunLock(root):
            refused = _recover_ledger(root, state_root_class, err)
            if refused is not None:
                return refused
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
        err.write(summary.refusal(str(exc), NOTHING_COLLECTED, AGAIN_LATER))
        return RUN_IN_PROGRESS
    except Exception as exc:                          # store and engine failures
        if space.out_of_space(exc):
            # The preflight cannot stop space disappearing during the run.
            err.write(summary.refusal("%s: the filesystem filled during the run (%s)"
                                      % (space.REASON, exc), NOT_COMMITTED + " " + NEVER_DELETES,
                                      "free space on that filesystem, then run the command again"))
            return INSUFFICIENT_SPACE
        if isinstance(exc, stateroot.StateRootError):
            err.write(summary.refusal(str(exc), NOT_COMMITTED))
            return STATE_ROOT_UNUSABLE
        err.write(summary.refusal("engine error: %s" % exc, NOT_COMMITTED))
        return USAGE_OR_ENGINE

    if problems:
        # The engine wrote evidence it cannot itself verify. That is an engine failure and
        # is reported as one; it is never reported as a successful collection.
        err.write("isedraf: committed evidence failed verification:\n")
        for p in problems:
            err.write("  %s\n" % p)
        return USAGE_OR_ENGINE

    if audit_root is None:
        return ident, snapshot_id, state_root_class, root, created_at
    return ident, snapshot_id, state_root_class, root, sections, run_status, created_at


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
    ident, snapshot_id, state_root_class, evidence_root, sections, run_status, created_at = done
    out.write(summary.header("isedraf audit", state_root_class, snapshot_id, created_at))
    _identity_lines(ident, state_root_class, out)
    out.write("\n")
    out.write(summary.audit_summary(sections, audit_mod.SECTIONS, run_status, state_root_class,
                                    evidence_root, ident.collected, snapshot_id))
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
        err.write(summary.refusal("there is no committed run to evaluate in %s" % root,
                                  "Nothing was written.", "isedraf audit"))
        return USAGE_OR_ENGINE
    try:
        with stateroot.RunLock(root):
            evl_id, raw, results = evaluate_run.build(
                root, state_root_class, ENGINE_VERSION, snapshot_id=args.snapshot)
            path, created = evaluate_run.commit(root, evl_id, raw)
    except stateroot.RunInProgress as exc:
        err.write(summary.refusal(str(exc), "Nothing was written.", AGAIN_LATER))
        return RUN_IN_PROGRESS
    except evaluate_run.EvaluationRefused as exc:
        err.write(summary.refusal("evaluation refused: %s" % exc, "Nothing was written.",
                                  "isedraf audit (it recovers the ledger first)"
                                  if ledger.TORN_TAIL in str(exc) else None))
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
    out.write(summary.header("isedraf evaluate", state_root_class,
                             json.loads(raw["results.json"])["snapshot_id"]))
    _field(out, "evaluation", evl_id)
    if not created:
        _field(out, "", "(already committed, identical)")
    _field(out, "evaluated snapshot", json.loads(raw["results.json"])["snapshot_id"])
    _field(out, "evidence root", root)
    _field(out, "evidence class", state_root_class)
    if state_root_class == stateroot.DEV:
        out.write("  note              : development state root; this evaluation is marked\n")
        out.write("                      DEV and is not production evidence\n")
    for r in results:
        out.write("  %-17s : %s  %s\n" % (r["criterion_id"], r["result"], r["reason_code"]))
        out.write("\n".join(summary.wrap(" " * 22, r["reason"], 22)) + "\n")
        for o in r["observations"]:
            out.write("\n".join(summary.wrap(" " * 22 + "observed: ",
                                              report.render.observation_text(o), 32)) + "\n")
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
    for name, result in sorted(changes.get("sections", {}).items()):
        out.write("  %-17s : %s%s\n" % (name, result["result"],
                                          " (collection method changed)"
                                          if result.get("method_changed") else ""))
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
            refused = _recover_ledger(root, state_root_class, err)
            if refused is not None:
                return refused

            def show(obj):
                # v0.5 P5: what is approved, before anything is written.
                collected = dict((r.get("snapshot_id"), r.get("occurred_at"))
                                 for r in ledger.snapshot_records(root)).get(obj["snapshot_id"])
                out.write(summary.header("isedraf baseline approve", state_root_class,
                                         obj["snapshot_id"], collected))
                out.write(summary.approval_text(obj, collected, state_root_class))
            outcome, obj = baseline_approve.approve(
                root, state_root_class, args.snapshot_id,
                lambda sid: evaluate_run.verified_run(root, sid), before_write=show)
    except stateroot.RunInProgress as exc:
        err.write(summary.refusal(str(exc), "Nothing was written.", AGAIN_LATER))
        return RUN_IN_PROGRESS
    except baseline_revision.ApprovalRefused as exc:
        err.write(summary.explained(exc.token, exc.detail, "Approval refused; nothing was "
                                    "written."))
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
    out.write("\nApproved: %s for %s%s, in %s.\n" % (
        obj["revision_id"], obj["snapshot_id"], "" if outcome == baseline_approve.APPROVED
        else " (an interrupted approval was completed)", root))
    out.write("A DEV baseline is not a production baseline and is never exported as evidence.\n"
              "Next: isedraf evaluate  (compares the latest run with this baseline)\n")
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
        err.write(summary.refusal(
            "%s is not an admitted criterion; admitted: %s" % (args.criterion_id, ", ".join(
                c["criterion_id"] for c in registry["criteria"]) or "none"),
            "Nothing was read from any evidence store.", "isedraf explain ISE-ACCOUNT-001"))
        return USAGE_OR_ENGINE
    out.write("\n".join(explain_mod.lines(record)) + "\n")
    return OK


_STATUS_NOTE = {
    "NOT_TESTED": "not observable here",
    "PARTIAL": "partly observable",
    "ERROR": "observation failed",
}


def _render_inventory(inv, out):
    out = _Fitted(out)
    d = inv["subdomains"]

    def field(block, name):
        return (d[block].get("data") or {}).get(name)

    out.write(summary.header("isedraf inventory"))
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
    refused = _refuse_unrecovered(root, err)
    if refused is not None:
        return refused
    committed = report.committed_run(root)
    if committed is None:
        err.write(summary.refusal("no committed audit run in %s; a report renders committed "
                                  "evidence and never collects" % root, "Nothing was written.",
                                  "isedraf audit"))
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
        path = os.path.abspath(report.write(root, model_obj, rendered, extension))
        # v0.5 R2: the exact absolute path on stdout (one line, for scripts), and how to view it
        # on stderr. The file is private: 0600 in the 0700 store.
        out.write("%s\n" % path)
        err.write("Saved, readable only by you. %s\n  %s\n"
                  % ("Open it in a browser, or with xdg-open:" if extension == "html"
                     else "View it with less:", path))
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
        # v0.5 terminal rule: no argparse usage block (its choice list is one long word); the
        # error, the valid commands and where to look, wrapped at 80 columns.
        lines = summary.wrap("%s: error: " % self.prog, message, 2)
        lines += summary.wrap("  commands: ", ", ".join(commands.name(r) for r in
                                                       commands.COMMANDS), 12)
        lines.append("  more: isedraf help --all, or isedraf help COMMAND")
        self.exit(USAGE_OR_ENGINE, "\n".join(lines) + "\n")


# D-129 (register items H4, H5, H6, H7): the parser is built from the command table in
# commands.py; this map binds each command form to its handler, and the option defaults the
# handlers expect. Nothing about a command's interface is written anywhere else.
def cmd_help(args):
    """`isedraf help`: main() answers every help form through commands.answer before the
    parser runs; this handler gives the same answer if the parser is ever reached."""
    argv = ["help"] + (["--all"] if args.all else []) + ([args.topic] if args.topic else [])
    code, text, problem = commands.answer(argv)
    sys.stdout.write(text)
    sys.stderr.write(problem)
    return code


def cmd_list(args, out=None, err=None):
    """v0.5 R1 (D-129 point 11): what the store holds, from committed metadata only. Reads
    no snapshot content, takes no lock, writes nothing, collects nothing."""
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        root, state_root_class = stateroot.resolve()
    except stateroot.PrivilegeRefused as exc:
        _refused(exc, err)
        return PRIVILEGE_REFUSED
    except stateroot.StateRootError as exc:
        err.write(summary.refusal(str(exc), "Nothing was read or written."))
        return USAGE_OR_ENGINE
    out.write(summary.header("isedraf list", state_root_class))
    if not os.path.isdir(root):
        out.write("\n".join(summary.wrap("", "No evidence store yet at %s." % root, 2))
                  + "\nStart with: isedraf audit\n")
        return OK
    if state_root_class == stateroot.USER_PRODUCTION:
        try:
            stateroot.check_user_root(root, os.geteuid())
        except stateroot.StateRootError as exc:
            err.write(summary.refusal(str(exc), "Nothing was read or written."))
            return STATE_ROOT_UNUSABLE
    refused = _refuse_unrecovered(root, err)
    if refused is not None:
        return refused
    try:
        found = listing.collect(root)
    except (listing.Unreadable, OSError) as exc:
        err.write(summary.refusal(str(exc), "Nothing was written."))
        return USAGE_OR_ENGINE
    out.write(summary.listing_text(found, state_root_class, root,
                                   show_all=getattr(args, "all", False)))
    return OK


HANDLERS = {
    ("help",): cmd_help,
    ("list",): cmd_list,
    ("audit",): cmd_audit,
    ("evaluate",): cmd_evaluate,
    ("explain",): cmd_explain,
    ("baseline", "approve"): cmd_baseline_approve,
    ("report",): cmd_report,
    ("identity",): cmd_identity,
    ("inventory",): cmd_inventory,
}
DEFAULTS = {
    ("audit", "--root"): "/",
    ("inventory", "--root"): "/",
    ("identity", "--source"): identity.SOURCE_PATH,
}


class _PrintAndExit(argparse.Action):
    """--help rendered from the command table, exit 0 (SCOPE-077: help is not an error)."""

    def __init__(self, option_strings, dest, text="", **kwargs):
        self.text = text
        super(_PrintAndExit, self).__init__(option_strings, dest, nargs=0,
                                            default=argparse.SUPPRESS, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        sys.stdout.write(self.text)
        parser.exit(OK)


def build_parser():
    parser = _Parser(prog=commands.PROG, add_help=False)
    parser.add_argument("--help", "-h", action=_PrintAndExit, text=commands.overview())
    parser.add_argument("--version", action=_PrintAndExit, text=commands.version_text())
    sub = parser.add_subparsers(dest="command")
    groups = {}
    for record in commands.COMMANDS:
        words = record["path"]
        holder = sub
        for depth, word in enumerate(words[:-1]):
            key = words[:depth + 1]
            if key not in groups:
                p_group = holder.add_parser(word, add_help=False)
                p_group.add_argument("--help", "-h", action=_PrintAndExit,
                                     text=commands.command_help(record))
                p_group.set_defaults(group_path=key)
                groups[key] = p_group.add_subparsers(dest="%s_command" % word)
            holder = groups[key]
        leaf = holder.add_parser(words[-1], add_help=False)
        leaf.add_argument("--help", "-h", action=_PrintAndExit,
                          text=commands.command_help(record))
        for option in record["options"]:
            if option["metavar"]:
                leaf.add_argument(option["flag"], metavar=option["metavar"],
                                  default=DEFAULTS.get((words[-1], option["flag"])))
            else:
                leaf.add_argument(option["flag"], action="store_true")
        for argument in record["arguments"]:
            # nargs="?": a missing argument gets guidance (H7), not only argparse's message.
            leaf.add_argument(argument["name"], nargs="?", default=None,
                              metavar=argument["metavar"])
        leaf.set_defaults(func=HANDLERS[words], record=record)
    return parser


def _missing(record, err):
    extra = ()
    if record["path"] == ("explain",):
        try:
            registry, _raw = catalog.load()
            ids = [c["criterion_id"] for c in registry["criteria"]]
            extra = ("Installed criteria: %s" % (", ".join(ids) or "none"),)
        except catalog.CatalogError as exc:
            extra = ("The installed catalog could not be read: %s" % exc,)
    err.write(commands.missing_help(record, extra))
    return USAGE_OR_ENGINE


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    # D-129 (H1, H3, H4; Q1, Q2): the help forms and the version are answered first, by the
    # same function the root route uses. Bare `isedraf` is the start page, exit 0; it collects,
    # approves and writes nothing. `isedraf help <unknown>` exits 64.
    helped = commands.answer(argv)
    if helped is not None:
        code, text, problem = helped
        sys.stdout.write(text)
        sys.stderr.write(problem)
        return code
    parser = build_parser()
    args = parser.parse_args(argv)
    record = getattr(args, "record", None)
    if record is None:
        if getattr(args, "group_path", None):
            # `isedraf baseline` without its action.
            members = [r for r in commands.COMMANDS
                       if r["path"][:len(args.group_path)] == args.group_path]
            sys.stderr.write("isedraf %s: name the action: %s\n"
                             % (" ".join(args.group_path),
                                ", ".join("isedraf %s" % commands.name(r) for r in members)))
        else:
            sys.stderr.write(commands.overview())
        return USAGE_OR_ENGINE
    for argument in record["arguments"]:
        if argument["required"] and getattr(args, argument["name"], None) is None:
            return _missing(record, sys.stderr)
    return args.func(args)
