# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: `sudo isedraf baseline approve`, the reduced side: verify, decide, build.
# Implements: D-128, AUTH-034, AUTH-020, BASE-011, BASE-012, BASE-013, BASE-021, BASE-026
#
# Runs as the isedraf account with no capability (the AUTH-020 reduction, checked here as
# the evaluator checks it). It receives one bounded frame on stdin - the ledger, the latest
# committed run, the baseline state and, when it is another run, the approved snapshot -
# holds no path or descriptor into the store, verifies all of it, and runs the same
# approval plan as `isedraf baseline approve` (baseline/approve.plan). It answers with one
# bounded frame of exactly two items on stdout: the action and the revision artifact's
# bytes. It writes nothing; the root side re-derives the action and checks the artifact
# before it writes (AUTH-034).
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="the isedraf account, no capability (AUTH-020)"
# meta:mutates="a private temporary directory, removed before it exits"
# meta:binaries=""
# =============================================================================
"""AUTH-034: the reduced side of system-store baseline approval."""
import os
import secrets
import shutil
import sys

from isedraf import fullaudit, verify
from isedraf.baseline import approve, revision
from isedraf.evaluate import run as evaluate_run
from isedraf.exitcodes import (APPROVAL_REFUSED, OK, TOOL_INTEGRITY_FAILURE,
                               USAGE_OR_ENGINE)
from isedraf.launcher import baselineunit, renderer, reportunit
from isedraf.supervisor import frame

TMP = renderer.TMP


def answer_items(action, raw):
    """The two answer items: the action and the artifact."""
    meta = {"mode": 0o100600, "uid": os.getuid(), "gid": os.getgid()}
    return [frame.item(frame.ENTRY, baselineunit.ACTION_NAME.encode("ascii"), frame.READ_OK,
                       dict(meta, size=len(action)), action.encode("ascii")),
            frame.item(frame.ENTRY, baselineunit.ARTIFACT_NAME.encode("ascii"), frame.READ_OK,
                       dict(meta, size=len(raw)), raw)]


def decide(data, out, err, state_root_class=None):
    state_root_class = state_root_class or baselineunit.CLASS
    try:
        items = frame.decode(data, reportunit.FRAME_LIMIT, reportunit.BASELINE_FRAME_ITEMS)
    except frame.FrameError as exc:
        err.write("isedraf: APPROVAL_REFUSED: the evidence frame is invalid (%s); nothing was "
                  "written.\n" % exc)
        return USAGE_OR_ENGINE
    base = os.path.join(TMP, "isedraf-approve-" + secrets.token_hex(16))
    os.mkdir(base, 0o700)
    try:
        try:
            sid = renderer.layout(items, base)
        except (renderer.FrameRefused, OSError, UnicodeError) as exc:
            err.write("isedraf: APPROVAL_REFUSED: %s; nothing was written.\n" % exc)
            return USAGE_OR_ENGINE
        try:
            problems = list(verify.verify_store(base)) + renderer.bound_to_ledger(base, sid)
        except (OSError, ValueError, KeyError, TypeError, reportunit.Refused) as exc:
            problems = ["the evidence could not be verified (%s)" % type(exc).__name__]
        if problems:
            err.write("isedraf: EVIDENCE_VERIFICATION_FAILED: %s; nothing was written.\n"
                      % "; ".join(problems))
            return USAGE_OR_ENGINE
        try:
            action, obj, raw = approve.plan(
                base, state_root_class, sid, lambda s: evaluate_run.verified_run(base, s),
                complete_recorded=True)
        except revision.ApprovalRefused as exc:
            err.write("isedraf: approval refused, nothing was written: %s\n" % exc)
            return APPROVAL_REFUSED
        except revision.IntegrityFailure as exc:
            err.write("isedraf: baseline integrity failure, nothing was written: %s\n" % exc)
            return TOOL_INTEGRITY_FAILURE
        except evaluate_run.EvaluationRefused as exc:
            err.write("isedraf: APPROVAL_REFUSED: %s; nothing was written.\n" % exc)
            return USAGE_OR_ENGINE
        out.write(frame.encode(answer_items(action, raw)))
        out.flush()
        err.write("ISEDRAF baseline (system store)\n")
        err.write("  approved snapshot : %s\n" % obj["snapshot_id"])
        err.write("  profile           : %s\n" % obj["profile"]["object"]["profile_id"])
        err.write("  sections          : %s\n" % ", ".join(obj["tracked_sections"]))
        return OK
    finally:
        shutil.rmtree(base, ignore_errors=True)


def reduction_check():
    """AUTH-020's own check, reused, as the evaluator uses it (AUTH-033)."""
    return fullaudit.current_reduction_problems()


def main(argv):
    if argv:
        sys.stderr.write("isedraf: the approver takes no argument\n")
        return USAGE_OR_ENGINE
    problems = reduction_check()
    if problems:
        sys.stderr.write("isedraf: ENGINE_NOT_REDUCED: %s; nothing was approved.\n"
                         % "; ".join(problems))
        return USAGE_OR_ENGINE
    data = sys.stdin.buffer.read(reportunit.FRAME_LIMIT + 1)
    if len(data) > reportunit.FRAME_LIMIT:
        sys.stderr.write("isedraf: APPROVAL_REFUSED: the evidence exceeds its bound\n")
        return USAGE_OR_ENGINE
    return decide(data, sys.stdout.buffer, sys.stderr)
