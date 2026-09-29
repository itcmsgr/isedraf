# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Collect the declared and active hostname and the relation between them.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022
#
# NSS_HOSTNAME_LANE_CONTRACT.md §1, §6. Two files, read under the collection root. No
# hostname(1), hostnamectl, D-Bus or resolver is consulted, and a fixture root never falls
# through to the live /proc (mounts ruling E): an absent fixture file is absent.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Hostname declared-vs-active collector."""
import os
import stat

from .. import coverage, hostio, hostpath
from . import model, sources


def _unread(outcome, relative):
    if outcome.detail == hostio.NOT_FOUND:
        return model.NOT_TESTED, "SOURCE_ABSENT: /%s does not exist." % relative
    if outcome.detail == hostio.PERMISSION_DENIED:
        return model.NOT_TESTED, ("SOURCE_UNREADABLE: /%s could not be read: permission "
                                  "denied." % relative)
    return model.ERROR, "SOURCE_UNREADABLE: /%s exists but could not be read." % relative


_OUTSIDE = ("SOURCE_OUTSIDE_COLLECTION_ROOT: /%s resolves outside the collection root and "
            "was not read.")


def _contained(root, path):
    """Resolved-target containment, as mounts and authorized_keys do it (red team F9)."""
    return hostpath.contains(os.path.realpath(root), os.path.realpath(path))


def _not_regular(path):
    """True for an existing FIFO, device or directory: a read would block or misreport
    (red team pass 2, #13). Absence is left for the read to report."""
    try:
        return not stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False


_NOT_REGULAR = "SOURCE_NOT_REGULAR: /%s is not a regular file and was not read."


def _declared(root):
    path = os.path.join(root, model.DECLARED_SOURCE)
    side = {"source": "/" + model.DECLARED_SOURCE}
    if not _contained(root, path):
        side.update({"status": model.NOT_TESTED, "reason": _OUTSIDE % model.DECLARED_SOURCE,
                     "value": None, "state": None, "trailing_newline": None,
                     "anomalies": []})
        return side, coverage.NOT_SUPPORTED
    if _not_regular(path):
        side.update({"status": model.ERROR, "reason": _NOT_REGULAR % model.DECLARED_SOURCE,
                     "value": None, "state": None, "trailing_newline": None,
                     "anomalies": []})
        return side, coverage.NOT_SUPPORTED
    outcome = hostio.read_file_lossless(path)
    if not outcome.ok:
        status, reason = _unread(outcome, model.DECLARED_SOURCE)
        side.update({"status": status, "reason": reason, "value": None,
                     "state": (model.ABSENT if outcome.detail == hostio.NOT_FOUND
                               else None),
                     "trailing_newline": None, "anomalies": []})
        return side, outcome.detail
    parsed = sources.parse_hostname_file(outcome.value)
    side.update(parsed)
    if parsed["state"] == model.MALFORMED:
        side.update({"status": model.PARTIAL,
                     "reason": "MALFORMED: " + "; ".join(a["detail"]
                                                         for a in parsed["anomalies"])})
    else:
        side.update({"status": model.COLLECTED, "reason": None})
    return side, outcome.detail


def _active(root):
    path = os.path.join(root, model.ACTIVE_SOURCE)
    side = {"source": "/" + model.ACTIVE_SOURCE}
    if not _contained(root, path):
        side.update({"status": model.NOT_TESTED, "reason": _OUTSIDE % model.ACTIVE_SOURCE,
                     "value": None})
        return side, coverage.NOT_SUPPORTED
    if _not_regular(path):
        side.update({"status": model.ERROR, "reason": _NOT_REGULAR % model.ACTIVE_SOURCE,
                     "value": None})
        return side, coverage.NOT_SUPPORTED
    outcome = hostio.read_file_lossless(path)
    if not outcome.ok:
        status, reason = _unread(outcome, model.ACTIVE_SOURCE)
        side.update({"status": status, "reason": reason, "value": None})
        return side, outcome.detail
    value, value_hex = sources.parse_kernel_hostname(outcome.value)
    side.update({"status": model.COLLECTED, "reason": None, "value": value})
    if value_hex is not None:
        # Every byte was read and kept, so the evidence is complete (pass 2, #11); it is
        # only not text.
        side["value_bytes_hex"] = value_hex
    return side, outcome.detail


def _same_file(root):
    try:
        return os.path.samefile(os.path.join(root, model.DECLARED_SOURCE),
                                os.path.join(root, model.ACTIVE_SOURCE))
    except OSError:
        return False


def collect(root="/"):
    """`root` is joined, never escaped and never defaulted."""
    declared, declared_detail = _declared(root)
    active, active_detail = _active(root)
    relation, reason = sources.compare(declared, active)
    if relation == model.EQUAL and _same_file(root):
        # A declared file that IS the active interface is equal by construction: the
        # comparison would compare one file with itself (red team pass 3, F10).
        relation, reason = model.NOT_COMPARABLE, ("the declared file and the active "
                                                  "interface are the same file")
    return {
        "declared": declared,
        "active": active,
        "relation": relation,
        "relation_reason": reason,
        "coverage": [
            coverage.source("hostname", model.DECLARED_SOURCE, declared["status"],
                            declared_detail, coverage.OP_FILE_READ,
                            reason=declared["reason"],
                            universe=(coverage.UNIVERSE_COMPLETE
                                      if declared["status"] == model.COLLECTED
                                      else coverage.UNIVERSE_INCOMPLETE)),
            coverage.source("hostname", model.ACTIVE_SOURCE, active["status"],
                            active_detail, coverage.OP_KERNEL_INTERFACE,
                            reason=active["reason"],
                            universe=(coverage.UNIVERSE_COMPLETE
                                      if active["status"] == model.COLLECTED
                                      else coverage.UNIVERSE_INCOMPLETE)),
        ],
    }
