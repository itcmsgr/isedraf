# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Collect the NSS topology, and the identity-scope evidence derived from it.
# Implements: IDENT-040, IDENT-041, CMP-020, SCOPE-022, SCOPE-045
#
# NSS_HOSTNAME_LANE_CONTRACT.md §1, §4. The configuration FILE is read; no NSS function,
# resolver or directory is ever consulted, because a lookup through NSS would make the
# evidence depend on the topology it describes, and for the identity databases it IS the
# enumeration IDENT-040 forbids.
#
# This lane produces evidence and emits no comparison finding. The comparison engine
# (W1-C) is required to emit COLLECTION_SCOPE_CHANGED / COLLECTION_METHOD_CHANGED; this
# module only establishes the canonical evidence it will need.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""NSS topology collector."""
import hashlib
import os
import stat

from .. import canonical, coverage, hostio, hostpath
from . import model, sources


def _topology(records):
    """The canonical identity topology: what an NSS source set IS, and nothing else.

    Line numbers, comments and spacing are presentation, so they are excluded and a
    reformatted file keeps its digest. Order and actions are semantics, so they are kept
    and either one moves the digest. An UNSUPPORTED line carries its raw text as well: the
    part this lane could not interpret must still move the digest when it changes.
    """
    out = []
    for rec in records:
        if rec["database"] not in model.IDENTITY_DATABASES:
            continue
        item = {"database": rec["database"], "entries": rec["entries"],
                "semantics": rec["semantics"]}
        if rec["semantics"] == model.UNSUPPORTED:
            item["raw"] = rec["raw"]
            if "raw_bytes_hex" in rec:
                item["raw_bytes_hex"] = rec["raw_bytes_hex"]
        out.append(item)
    # Order WITHIN a database is resolver semantics; order BETWEEN databases is not, so it
    # must not move the digest (red team, LOW). A stable sort keeps duplicates in file order.
    return sorted(out, key=lambda item: item["database"])


def _contained(root, path):
    """Resolved-target containment, as mounts and authorized_keys do it.

    hostpath owns the arithmetic; the caller resolves. realpath is a CHECK, never identity:
    the recorded path stays lexical. This does not prove race-free acquisition.
    """
    return hostpath.contains(os.path.realpath(root), os.path.realpath(path))


def _unsupported_anywhere(records):
    """Every line this lane could not interpret, in ANY database, in file order.

    glibc 2.43 fails the whole file when one known database line carries an invalid
    action bracket, and identity lookups fail with it (red team pass 2, #2). So the
    identity digest must move when any line becomes uninterpretable, not only an identity
    line.
    """
    return [{"database": rec["database"], "raw": rec["raw"],
             "raw_bytes_hex": rec.get("raw_bytes_hex")}
            for rec in records if rec["semantics"] == model.UNSUPPORTED]


def _regular_file(path):
    """(ok, reason). A FIFO or device would block or misreport a read (red team pass 2, #13).

    Only an existing non-regular file is refused here; absence is reported by the read.
    """
    try:
        info = os.stat(path)
    except OSError:
        return True, None
    if stat.S_ISREG(info.st_mode):
        return True, None
    return False, "SOURCE_NOT_REGULAR: /%s is not a regular file and was not read." % model.SOURCE


def _undeclared(records, declared):
    """Identity databases glibc will default, recorded as defaults and never guessed.

    A database using `compat` reads its +/- inclusions from <db>_compat, whose default
    nsswitch.conf(5) states is nis. Left undeclared, that remote source is recorded as a
    default, not assumed and not hidden (red team pass 3, F7).
    """
    out = {db: model.DEFAULT_NOT_ASSERTED
           for db in model.REQUIRED_IDENTITY_DATABASES if db not in declared}
    for rec in records:
        pseudo = "%s_compat" % rec["database"]
        if pseudo in model.IDENTITY_DATABASES and pseudo not in declared and any(
                e["class"] == model.COMPAT for e in rec["entries"]):
            out[pseudo] = model.DEFAULT_NOT_ASSERTED
    return out


def _digest(value):
    return hashlib.sha256(canonical.canonical_bytes(value)).hexdigest()


def collect(root="/"):
    """Read <root>/etc/nsswitch.conf. `root` is joined, never escaped and never defaulted."""
    path = os.path.join(root, model.SOURCE)
    base = {"source": "/" + model.SOURCE, "records": [], "anomalies": []}
    if not _contained(root, path):
        # A fixture root holding a symlink to the live /etc must not report the machine
        # running the tool as the machine under test (red team F9; mounts ruling E).
        reason = ("SOURCE_OUTSIDE_COLLECTION_ROOT: /%s resolves outside the collection root "
                  "and was not read." % model.SOURCE)
        base.update({
            "status": model.NOT_TESTED, "reason": reason,
            "identity_nss_topology": [], "identity_nss_topology_digest": None,
            "non_files_identity_sources": [], "undeclared_identity_databases": None,
            "coverage": coverage.source("nss", model.SOURCE, model.NOT_TESTED,
                                        coverage.NOT_SUPPORTED, coverage.OP_FILE_READ,
                                        reason=reason,
                                        universe=coverage.UNIVERSE_INCOMPLETE),
        })
        return base
    regular, why = _regular_file(path)
    if not regular:
        base.update({
            "status": model.ERROR, "reason": why,
            "identity_nss_topology": [], "identity_nss_topology_digest": None,
            "non_files_identity_sources": [], "undeclared_identity_databases": None,
            "coverage": coverage.source("nss", model.SOURCE, model.ERROR,
                                        coverage.NOT_SUPPORTED, coverage.OP_FILE_READ,
                                        reason=why, universe=coverage.UNIVERSE_INCOMPLETE),
        })
        return base
    outcome = hostio.read_file_lossless(path)

    if not outcome.ok:
        if outcome.detail == hostio.NOT_FOUND:
            status = model.NOT_TESTED
            reason = ("SOURCE_ABSENT: /%s does not exist. glibc then applies built-in "
                      "defaults that vary by version; none is asserted." % model.SOURCE)
            undeclared = {db: model.DEFAULT_NOT_ASSERTED
                          for db in model.REQUIRED_IDENTITY_DATABASES}
            digest = _digest(model.ABSENT_TOPOLOGY)
        else:
            status = (model.NOT_TESTED if outcome.detail == hostio.PERMISSION_DENIED
                      else model.ERROR)
            reason = ("SOURCE_UNREADABLE: /%s could not be read; no topology is claimed."
                      % model.SOURCE)
            undeclared, digest = None, None
        base.update({
            "status": status, "reason": reason,
            "identity_nss_topology": [], "identity_nss_topology_digest": digest,
            "non_files_identity_sources": [], "undeclared_identity_databases": undeclared,
            "coverage": coverage.source("nss", model.SOURCE, status, outcome.detail,
                                        coverage.OP_FILE_READ, reason=reason,
                                        universe=coverage.UNIVERSE_INCOMPLETE),
        })
        return base

    parsed = sources.parse_nsswitch(outcome.value)
    for rec in parsed.records:
        if rec["database"] not in model.IDENTITY_DATABASES:
            continue
        unknown = [e["service"] for e in rec["entries"] if e["class"] == model.UNKNOWN]
        if unknown:
            # IQ-037: what an unknown module does is not asserted, so neither is whether
            # the local file is an effective source. The token itself is configuration
            # the owner wrote, not host-derived secret text; only its count is echoed.
            parsed.anomalies.append(sources._anomaly(
                model.ANOMALY_UNKNOWN_SERVICE,
                "%s: %d service(s) no class covers; their semantics are not asserted"
                % (rec["database"], len(unknown)), rec["line"]))
    incomplete = [a for a in parsed.anomalies
                  if a["anomaly"] in (model.ANOMALY_UNSUPPORTED, model.ANOMALY_DUPLICATE,
                                      model.ANOMALY_NO_DATABASE, model.ANOMALY_UNDECODABLE,
                                      model.ANOMALY_UNKNOWN_SERVICE)]
    status = model.PARTIAL if incomplete else model.COLLECTED
    reason = None
    if incomplete:
        reason = ("PARTIAL: %d line(s) of /%s could not be fully interpreted and are "
                  "retained verbatim: %s" % (len(incomplete), model.SOURCE,
                                             "; ".join(a["detail"] for a in incomplete)))
    topology = _topology(parsed.records)
    declared = {rec["database"] for rec in parsed.records}
    non_files = [{"database": rec["database"], "service": e["service"], "class": e["class"]}
                 for rec in parsed.records if rec["database"] in model.IDENTITY_DATABASES
                 for e in rec["entries"] if e["class"] != model.LOCAL_FILES]
    base.update({
        "status": status,
        "reason": reason,
        "records": parsed.records,
        "anomalies": parsed.anomalies,
        "identity_nss_topology": topology,
        "identity_nss_topology_digest": _digest(
            {"identity": topology,
             "unsupported_anywhere": _unsupported_anywhere(parsed.records)}),
        "non_files_identity_sources": non_files,
        "undeclared_identity_databases": _undeclared(parsed.records, declared),
        "coverage": coverage.source("nss", model.SOURCE, status, outcome.detail,
                                    coverage.OP_FILE_READ, reason=reason,
                                    universe=(coverage.UNIVERSE_COMPLETE
                                              if status == model.COLLECTED
                                              else coverage.UNIVERSE_INCOMPLETE)),
    })
    return base
