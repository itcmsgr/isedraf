# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The reduced renderer of `sudo isedraf report`: verify the frame, then render.
# Implements: AUTH-032, AUTH-020, D-50, STORE-024
#
# Runs as the isedraf identity with no capability and no-new-privileges (the engine
# reduction). Its whole input is one frame on stdin: the ledger and the files of one
# committed snapshot, read by the root side (reportunit). It accepts exactly those names,
# lays the bytes out in its unit-private temporary directory (PrivateTmp, mode 0700,
# removed before it exits), and renders nothing unless the existing verification holds:
# the ledger chain, the snapshot's manifest and every file hash, and the last ledger
# record bound to that manifest. Then the existing report code renders it. It has no path
# into the store and sends nothing back but the report on stdout.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged (isedraf identity, no capability)"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""AUTH-032 reduced renderer."""
import json
import os
import re
import secrets
import shutil
import sys

from isedraf import ids, report, verify
from isedraf.exitcodes import INCOMPLETE, OK, USAGE_OR_ENGINE
from isedraf.launcher import reportunit, store
from isedraf.supervisor import frame

PRODUCTION_ROOT = "/var/lib/isedraf"
# The unit's PrivateTmp=yes makes this private to the run; the directory is created
# exclusively, 0700, under a random name.
TMP = "/tmp"
SCOPE = ("the ledger chain and the reported snapshot (its manifest, every file it lists and its "
         "ledger record); other snapshots in the store are not re-verified by this report")
_SNAPSHOT_NAME = re.compile(r"\Asnapshots/(SDS-[^/]+)/(.+)\Z")


class FrameRefused(Exception):
    pass


def layout(items, base):
    """Write the accepted items under `base` as a store would hold them. Returns the snapshot id."""
    ledger_name = reportunit.LEDGER_NAME
    sid, seen = None, set()
    for it in items:
        if it["kind"] != frame.ENTRY or it["acquisition_outcome"] != frame.READ_OK:
            raise FrameRefused("an item that is not a completed read")
        try:
            name = it["name"].decode("ascii", "strict")
        except UnicodeDecodeError:
            name = None
        if name is None or name in seen:
            raise FrameRefused("an item name that is not a single ASCII name")
        seen.add(name)
        if name == ledger_name:
            rel = name
        else:
            match = _SNAPSHOT_NAME.match(name)
            if not match or match.group(2) not in store.BUNDLE_FILES or not ids.ID_RE.match(
                    match.group(1)) or (sid is not None and match.group(1) != sid):
                raise FrameRefused("an item %r that AUTH-032 does not read" % name)
            sid, rel = match.group(1), name
        path = os.path.join(base, rel)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(it["content"])
    if ledger_name not in seen or sid is None or "snapshots/%s/manifest.json" % sid not in seen:
        raise FrameRefused("the frame lacks the ledger or the snapshot manifest")
    return sid


def bound_to_ledger(base, sid):
    """The last ledger record names this snapshot and its manifest hash (D-50)."""
    with open(os.path.join(base, reportunit.LEDGER_NAME), "rb") as fh:
        lines = [l for l in fh.read().split(b"\n") if l.strip()]
    core = json.loads(lines[-1].decode("utf-8"))["record_core"]
    with open(os.path.join(base, "snapshots", sid, "manifest.json"), "rb") as fh:
        envelope = json.loads(fh.read().decode("utf-8"))
    problems = []
    if core.get("snapshot_id") != sid:
        problems.append("the last ledger record names another snapshot")
    if core.get("manifest_hash") != envelope.get("manifest_hash"):
        problems.append("the last ledger record does not bind this manifest")
    return problems


def render(fmt, data, out, err):
    try:
        items = frame.decode(data, reportunit.FRAME_LIMIT, reportunit.FRAME_ITEMS)
    except frame.FrameError as exc:
        err.write("isedraf: REPORT_REFUSED: the evidence frame is invalid (%s); no report was "
                  "rendered.\n" % exc)
        return USAGE_OR_ENGINE
    base = os.path.join(TMP, "isedraf-report-" + secrets.token_hex(16))
    os.mkdir(base, 0o700)
    try:
        try:
            sid = layout(items, base)
        except (FrameRefused, OSError, UnicodeError) as exc:
            err.write("isedraf: REPORT_REFUSED: %s; no report was rendered.\n" % exc)
            return USAGE_OR_ENGINE
        try:
            problems = list(verify.verify_store(base)) + bound_to_ledger(base, sid)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            problems = ["the evidence could not be verified (%s)" % type(exc).__name__]
        if problems:
            err.write("isedraf: EVIDENCE_VERIFICATION_FAILED: %s; no report was rendered.\n"
                      % "; ".join(problems))
            return USAGE_OR_ENGINE
        committed = report.committed_run(base)
        if committed is None:
            err.write("isedraf: the latest committed Full Audit run has no audit sections; no "
                      "report was rendered.\n")
            return USAGE_OR_ENGINE
        model_obj = report.build(base, committed["sections"]["inventory"]["evidence"],
                                 audit_sections=committed["sections"],
                                 audit_digests=committed["digests"],
                                 coverage_manifest=committed.get("evidence_limits"))
        model_obj["identity_evidence"]["evidence_root"] = PRODUCTION_ROOT
        model_obj["identity_evidence"]["verification"]["scope"] = SCOPE
        if fmt == "json":
            rendered = report.render.to_json(model_obj)
        elif fmt == "html":
            rendered = report.render.to_html(model_obj)
        else:
            rendered = report.render.to_markdown(model_obj)
        out.write(rendered)
        return OK if model_obj["report"]["status"] == "COMPLETE" else INCOMPLETE
    finally:
        shutil.rmtree(base, ignore_errors=True)


def main(argv):
    if len(argv) != 1 or argv[0] not in reportunit.FORMATS:
        sys.stderr.write("isedraf: the renderer takes one report format\n")
        return USAGE_OR_ENGINE
    data = sys.stdin.buffer.read(reportunit.FRAME_LIMIT + 1)
    if len(data) > reportunit.FRAME_LIMIT:
        sys.stderr.write("isedraf: REPORT_REFUSED: the evidence exceeds its bound\n")
        return USAGE_OR_ENGINE
    return render(argv[0], data, sys.stdout, sys.stderr)
