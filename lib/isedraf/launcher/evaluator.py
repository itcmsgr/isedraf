# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The reduced evaluator of `sudo isedraf evaluate` (AUTH-033).
# Implements: AUTH-033, AUTH-020, EVAL-001, EVAL-003, EVAL-004, EVAL-005, EVAL-006
#
# Runs as the isedraf account with every capability set empty and no-new-privileges (the
# AUTH-020 reduction). It receives one frame on stdin - the ledger, the latest committed
# snapshot's files and the catalog bytes - and holds no path or descriptor into the store.
# It lays the bytes out in a 0700 directory in the unit's private temporary space, verifies
# them as the report route does, evaluates with the same code as `isedraf evaluate`
# (evaluate.run.build), and writes exactly one frame of the four artifacts on stdout. The
# operator's summary goes to stderr. It reads no live host file and starts no collector.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged (isedraf account, AUTH-020 reduction)"
# meta:mutates="a private directory in the unit's temporary space, removed before exit"
# meta:binaries=""
# =============================================================================
"""AUTH-033: the reduced side of system-store evaluation."""
import json
import os
import secrets
import shutil
import sys

from isedraf import ENGINE_VERSION, fullaudit, verify
from isedraf.evaluate import run as evaluate_run
from isedraf.exitcodes import OK, USAGE_OR_ENGINE
from isedraf.launcher import evalunit, renderer, reportunit
from isedraf.supervisor import frame

TMP = renderer.TMP


def _split(items):
    """(catalog bytes, the evidence items). Exactly one catalog item."""
    name = evalunit.CATALOG_NAME.encode("ascii")
    catalogs = [i for i in items if i["name"] == name]
    if len(catalogs) != 1 or catalogs[0]["acquisition_outcome"] != frame.READ_OK:
        raise renderer.FrameRefused("the frame does not carry exactly one catalog")
    return catalogs[0]["content"], [i for i in items if i["name"] != name]


def evaluate(data, out, err, state_root_class=None):
    state_root_class = state_root_class or evalunit.CLASS
    try:
        items = frame.decode(data, reportunit.FRAME_LIMIT, evalunit.FRAME_ITEMS)
        catalog_bytes, evidence = _split(items)
    except (frame.FrameError, renderer.FrameRefused) as exc:
        err.write("isedraf: EVALUATION_REFUSED: the evidence frame is invalid (%s); nothing was "
                  "written.\n" % exc)
        return USAGE_OR_ENGINE
    base = os.path.join(TMP, "isedraf-evaluate-" + secrets.token_hex(16))
    os.mkdir(base, 0o700)
    try:
        try:
            sid = renderer.layout(evidence, base)
            catalog_path = os.path.join(base, "catalog.json")
            fd = os.open(catalog_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(catalog_bytes)
        except (renderer.FrameRefused, OSError, UnicodeError) as exc:
            err.write("isedraf: EVALUATION_REFUSED: %s; nothing was written.\n" % exc)
            return USAGE_OR_ENGINE
        try:
            problems = list(verify.verify_store(base)) + renderer.bound_to_ledger(base, sid)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            problems = ["the evidence could not be verified (%s)" % type(exc).__name__]
        if problems:
            err.write("isedraf: EVIDENCE_VERIFICATION_FAILED: %s; nothing was written.\n"
                      % "; ".join(problems))
            return USAGE_OR_ENGINE
        try:
            evl_id, raw, results = evaluate_run.build(base, state_root_class, ENGINE_VERSION,
                                                      registry_path=catalog_path)
        except evaluate_run.EvaluationRefused as exc:
            err.write("isedraf: EVALUATION_REFUSED: %s; nothing was written.\n" % exc)
            return USAGE_OR_ENGINE
        answer = frame.encode([frame.item(frame.ENTRY, name.encode("ascii"), frame.READ_OK,
                                          {"mode": 0o100600, "uid": os.getuid(),
                                           "gid": os.getgid(), "size": len(raw[name])},
                                          raw[name])
                               for name in sorted(raw)])
        out.write(answer)
        out.flush()
        err.write("ISEDRAF native evaluation (system store)\n")
        err.write("  evaluated snapshot: %s\n" % json.loads(raw["results.json"])["snapshot_id"])
        for r in results:
            err.write("  %-17s : %s  %s\n" % (r["criterion_id"], r["result"], r["reason_code"]))
            err.write("                      %s\n" % r["reason"])
        return OK
    finally:
        shutil.rmtree(base, ignore_errors=True)


def reduction_check():
    """AUTH-020's own check, reused: the evaluator refuses unless it IS the reduced identity
    (the isedraf account, every capability set empty, no-new-privileges). The lab measurement
    of 2026-11-02 found a unit without CAP_SETPCAP leaving the bounding set non-empty; this
    check is what turns that into a refusal instead of an unnoticed partial reduction."""
    return fullaudit.current_reduction_problems()


def main(argv):
    if argv:
        sys.stderr.write("isedraf: the evaluator takes no argument\n")
        return USAGE_OR_ENGINE
    problems = reduction_check()
    if problems:
        sys.stderr.write("isedraf: ENGINE_NOT_REDUCED: %s; nothing was evaluated.\n"
                         % "; ".join(problems))
        return USAGE_OR_ENGINE
    data = sys.stdin.buffer.read(reportunit.FRAME_LIMIT + 1)
    if len(data) > reportunit.FRAME_LIMIT:
        sys.stderr.write("isedraf: EVALUATION_REFUSED: the evidence exceeds its bound\n")
        return USAGE_OR_ENGINE
    return evaluate(data, sys.stdout.buffer, sys.stderr)
