# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Read four login-policy families, each with its own grammar.
# Implements: SCOPE-022, SCOPE-045, GOV-001
#
# S1 parses the three key/value families. S5 enumerates the fragment directories. S4
# records metadata for every file read. The domain chooses the profile per family and
# decides which fragment filenames count, because those are the two judgements a shared
# primitive is not entitled to make.
#
# No cross-source resolution. Four families are collected and kept apart.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Login-policy acquisition across four independent source families."""
import hashlib
import os

from .. import coverage, hostio, textbytes
from ..shared import bounded, filemeta, result
from ..shared import keyvalue
from . import model, sources

# family -> (main file, fragment directory or None)
LAYOUT = (
    (model.LOGIN_DEFS, "etc/login.defs", None),
    (model.PWQUALITY, "etc/security/pwquality.conf", "etc/security/pwquality.conf.d"),
    (model.FAILLOCK, "etc/security/faillock.conf", None),
    (model.LIMITS, "etc/security/limits.conf", "etc/security/limits.d"),
)


class Fragments(bounded.Universe):
    """One level, files only. The domain filters afterwards by filename."""

    name = "loginpolicy.d"
    max_depth = 1
    include_files = True
    include_directories = False


def collect(root="/"):
    records, files, sources_meta = [], [], []
    ordinal = 0
    any_readable = False

    for family, main, fragment_dir in LAYOUT:
        for path in _paths(root, main, fragment_dir, sources_meta, family):
            outcome = hostio.read_file_lossless(path)
            files.append(filemeta.observe(path).records[0])
            entry = {"family": family, "path": path}
            if not outcome.ok:
                # ABSENT and REFUSED are different facts about this host, and an
                # earlier version collapsed them. A family that is simply not
                # configured is an ordinary state; a file that EXISTS and could not be
                # read is evidence we do not have and must not be dropped from the
                # aggregate. ARCH-02 found the consequence: login.defs refused while
                # pwquality was readable reported COLLECTED with no reason - Defect A,
                # in a new domain.
                entry["status"] = (result.NOT_TESTED if outcome.detail == hostio.NOT_FOUND
                                   else result.ERROR if outcome.detail == hostio.IO_ERROR
                                   else result.NOT_TESTED)
                entry["detail"] = outcome.detail
                entry["access_outcome"] = outcome.detail
                entry["reason"] = "%s: %s" % (outcome.reason, path)
                sources_meta.append(entry)
                continue
            any_readable = True
            parsed, status, reason, digest = _parse(family, outcome.value, path, ordinal)
            records.extend(parsed)
            ordinal += len(parsed)
            entry.update({"status": status, "reason": reason, "grammar_digest": digest,
                          "access_outcome": outcome.detail})
            sources_meta.append(entry)

    if not any_readable:
        # IQ-046 (2): absent only when nothing exists. A source that exists and was
        # refused, or failed, is unseen evidence and is named as such.
        unseen = [s for s in sources_meta
                  if not (s["status"] == result.NOT_TESTED
                          and s.get("detail") == hostio.NOT_FOUND)]
        reason = ("SOURCE_UNREADABLE: no login-policy source could be read under %s; %d "
                  "existing source(s) were refused or failed: %s." % (
                      root, len(unseen),
                      ", ".join(s.get("path") or s.get("reason", "") for s in unseen))
                  if unseen else
                  "SOURCE_ABSENT: no login-policy source was readable under %s." % root)
        return result.Evidence(
            result.NOT_TESTED, records=[], source=root, reason=reason,
            provenance=_provenance(sources_meta, files))

    status, reason = _status(sources_meta)
    return result.Evidence(status, records=records, reason=reason, source=root,
                           provenance=_provenance(sources_meta, files))


def _paths(root, main, fragment_dir, sources_meta, family):
    """The main file, then the eligible fragments in byte order."""
    yield os.path.join(root, main)
    if fragment_dir is None:
        return
    directory = os.path.join(root, fragment_dir)
    listing = bounded.enumerate_paths(directory, Fragments())
    events = set(a.get("event") for a in listing.anomalies)
    if bounded.ROOT_MISSING in events:
        # An absent .d directory is an ordinary configuration, not missing evidence.
        return
    if listing.status != result.COLLECTED:
        # IQ-046 (2): a .d directory that exists and could not be listed, in whole or in
        # part, holds fragments that were never seen. Only a listdir refusal is known to
        # be a privilege limit; any other failure is recorded without claiming one.
        outcome = (hostio.PERMISSION_DENIED if bounded.ENTRY_UNREADABLE in events
                   else hostio.IO_ERROR)
        sources_meta.append({"family": family, "path": directory,
                             "status": result.NOT_TESTED, "detail": outcome,
                             "access_outcome": outcome,
                             "operation": coverage.OP_DIRECTORY_LIST,
                             "reason": "SOURCE_UNREADABLE: %s could not be listed."
                                       % directory})
    for entry in listing.records:
        name = entry["name"]
        if name is None:
            sources_meta.append({"family": family, "path": None,
                                 "status": result.PARTIAL,
                                 "reason": "UNDECODABLE_FILENAME: %s"
                                           % entry["name_bytes_hex"]})
            continue
        if model.fragment_eligible(name):
            yield entry["path"]


def _parse(family, text, path, ordinal):
    if family == model.LIMITS:
        parsed, malformed = sources.parse_limits(text, path, ordinal)
        digest = None
    else:
        profile = model.PROFILES[family]
        evidence = keyvalue.parse(text, profile, path)
        digest = evidence.provenance["grammar_digest"]
        parsed = []
        malformed = 0
        for index, record in enumerate(evidence.records):
            record = dict(record)
            record["family"] = family
            record["grammar_digest"] = digest
            record["ordinal"] = ordinal + index
            record.setdefault("source_path", path)
            if record.get("malformed") and family == model.FAILLOCK:
                # faillock accepts bare boolean keys. S1 correctly reports a line with no
                # delimiter as malformed, because that IS the answer from a key/value
                # grammar; the domain reclassifies it rather than teaching S1 a special
                # case that one consumer wants.
                record["malformed"] = False
                record["key"] = record.get("key_raw")
                record["value"] = None
                record["anomalies"] = [a for a in record.get("anomalies", [])
                                       if a != keyvalue.NO_DELIMITER]
            if record.get("malformed"):
                malformed += 1
                # ARCH-02 consistency finding. For a malformed line S1 keeps the WHOLE
                # line as key_raw, because it found no delimiter to split on. sudo, ssh
                # and pam all digest unparsed content on the principle that the line we
                # understand least is the one whose contents we are least entitled to
                # publish - a mistyped pwquality entry would otherwise retain its
                # dictpath verbatim. This domain now does the same. The key token is
                # still kept when the line parsed; only unparsed content is digested.
                record["raw_digest"] = "sha256:" + hashlib.sha256(
                    textbytes.original_bytes(record.get("key_raw") or "")).hexdigest()
                record["key_raw"] = None
                record["key"] = None
                record["value"] = None
            parsed.append(record)
    if parsed and malformed == len(parsed):
        return parsed, result.ERROR, (
            "UNPARSEABLE: no line in %s could be read as a %s declaration."
            % (path, family)), digest
    if malformed:
        return parsed, result.PARTIAL, (
            "MALFORMED_RECORDS: %d of %d lines in %s could not be read as %s "
            "declarations." % (malformed, len(parsed), path, family)), digest
    return parsed, result.COLLECTED, None, digest


def _status(sources_meta):
    """A family that is absent is not configured. A family that is REFUSED is unseen.

    SCOPE-022 puts privilege denial at NOT_TESTED for the SOURCE, and that stays true
    per source. The aggregate is a different question: one readable family never
    satisfies completeness for a family that exists and could not be read.
    """
    absent = [s for s in sources_meta
              if s["status"] == result.NOT_TESTED
              and s.get("detail") == hostio.NOT_FOUND]
    considered = [s for s in sources_meta if s not in absent]
    bad = [s for s in considered if s["status"] != result.COLLECTED]
    if not bad:
        return result.COLLECTED, None
    if considered and all(s["status"] == result.ERROR for s in considered):
        return result.ERROR, " ".join(s["reason"] for s in bad if s.get("reason"))
    return result.PARTIAL, " ".join(s["reason"] for s in bad if s.get("reason"))


def _provenance(sources_meta, files):
    return {"scope": "DECLARED_LOGIN_POLICY_SOURCES",
            "limitation": model.LIMITATION,
            "families": list(model.FAMILIES),
            "sources": sources_meta,
            "coverage": _coverage(sources_meta),
            "files": files}


def _coverage(sources_meta):
    """R1.5-P. Facts in, derivation central.

    This lane already separated ABSENT from REFUSED - ARCH-02 made it, after the same
    collapse turned up here as Defect A in a new domain. What it did not do was say so in
    a field a machine could read. Nothing about the login-policy facts changes; an
    acquisition-context record is added beside them.
    """
    out = []
    for entry in sources_meta:
        if entry.get("path") is None:
            continue
        outcome = entry.get("access_outcome")
        if outcome not in coverage.OUTCOMES:
            # A provenance builder MUST NOT raise. R1.5-P is acquisition CONTEXT; a
            # collector that died because its context could not be classified would
            # convert a describable gap into no evidence at all - the opposite of the
            # contract. An unclassifiable outcome is recorded as one.
            outcome = coverage.NOT_SUPPORTED
        status = entry.get("status")
        if status not in (result.COLLECTED, result.PARTIAL, result.NOT_TESTED,
                          result.ERROR):
            status = result.NOT_TESTED
        out.append(coverage.source(
            "loginpolicy", entry["path"], status, outcome,
            entry.get("operation", coverage.OP_FILE_READ),
            reason=entry.get("reason"),
            universe=(coverage.UNIVERSE_COMPLETE if status == result.COLLECTED
                      else coverage.UNIVERSE_INCOMPLETE)))
    return out
