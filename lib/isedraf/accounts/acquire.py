# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Read the three local account files, apply SCOPE-022, and join them honestly.
# Implements: SCOPE-022, SCOPE-045, IDENT-013, IDENT-041, IDENT-060
#
# The parsers in sources.py are pure and know nothing about permissions. This module is
# where "we could not read /etc/shadow" becomes a status, and where the passwd-to-shadow
# relationship is expressed without pretending to know more than was read.
#
# The defect this is shaped to prevent is Defect A, one layer up. There, a readable
# hypervisor fact satisfied completeness for an unreadable DMI source, and the subdomain
# reported COLLECTED with two null identity fields and no reason. The account equivalent
# would be worse: /etc/passwd is world-readable and /etc/shadow is not, so an
# unprivileged run reads every account name and no password state at all. Reporting that
# as a complete account collection would tell an operator their accounts have no
# password ageing, when the truth is that nothing was looked at.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Acquisition, SCOPE-022 status, and the passwd/group/shadow join."""
import hashlib
import os

from .. import canonical, coverage, hostio as _exec, textbytes
from ..nss import model as nss_model
from . import model, sources

PASSWD = "etc/passwd"
GROUP = "etc/group"
SHADOW = "etc/shadow"

_PARSERS = {PASSWD: sources.parse_passwd,
            GROUP: sources.parse_group,
            SHADOW: sources.parse_shadow}


def acquire(root, relative):
    """Read one source under `root` and decide its SCOPE-022 status.

    `root` is joined, never escaped and never defaulted. A fixture run that silently fell
    back to the real /etc would produce a report about the machine running the test
    instead of the machine under test, and would look entirely plausible while doing it.
    """
    path = os.path.join(root, relative)
    # Lossless: an identifier must survive acquisition as the bytes the host has.
    outcome = _exec.read_file_lossless(path)

    if not outcome.ok:
        if outcome.detail == _exec.PERMISSION_DENIED:
            # SCOPE-022, frozen: privilege or MAC denial -> NOT_TESTED. NOT an error, and
            # emphatically not an empty success. /etc/shadow refuses an unprivileged
            # reader by design, and that is a statement about who is asking, not about
            # the accounts.
            return {"source": relative, "status": model.NOT_TESTED,
                    "reason": "SOURCE_UNREADABLE: %s could not be read: permission "
                              "denied. Password and ageing evidence requires privilege; "
                              "nothing about it was observed." % relative,
                    "detail": outcome.detail, "parsed": None}
        if outcome.detail == _exec.NOT_FOUND:
            return {"source": relative, "status": model.NOT_TESTED,
                    "reason": "SOURCE_ABSENT: %s does not exist on this host."
                              % relative,
                    "detail": outcome.detail, "parsed": None}
        if outcome.detail == _exec.TRUNCATED:
            # Truncated input is never complete evidence (owner invariant, 2026-09-24).
            return {"source": relative, "status": model.ERROR,
                    "reason": "SOURCE_TRUNCATED: %s is larger than the %d-byte read bound "
                              "and was not read as complete evidence." % (
                                  relative, _exec.OUTPUT_LIMIT),
                    "detail": outcome.detail, "parsed": None}
        # Present and failed. SCOPE-022 calls that ERROR.
        return {"source": relative, "status": model.ERROR,
                "reason": "SOURCE_UNREADABLE: %s exists but could not be read." % relative,
                "detail": outcome.detail, "parsed": None}

    parsed = _PARSERS[relative](outcome.value)

    if parsed.line_count == 0:
        # Owner ruling Q3: read succeeded, parse succeeded, zero records -> COLLECTED.
        # An empty /etc/passwd is deeply abnormal, but abnormal is not incomplete, and
        # reporting it as PARTIAL would mix collection truth with security
        # interpretation - the exact confusion this model exists to prevent. A criterion
        # may later call "zero local accounts" a serious finding. The collector's job is
        # to say, accurately, that it read the source and the source was empty.
        return {"source": relative, "status": model.COLLECTED, "reason": None,
                "detail": outcome.detail, "parsed": parsed}

    if parsed.malformed_count:
        # Owner ruling Q1, clarifying SCOPE-022 rather than contradicting it.
        #
        # "Unparseable output -> ERROR" means content for which no trustworthy normalized
        # interpretation can be produced. A source where every line failed is that. A
        # source where 40 lines parsed and one did not is NOT: the record boundaries held,
        # the 40 remain trustworthy, and discarding them to punish a typo would destroy
        # evidence. That is PARTIAL, with the malformed records retained and counted so
        # nothing is silently skipped and nothing is called complete.
        if parsed.malformed_count == parsed.line_count:
            return {"source": relative, "status": model.ERROR,
                    "reason": "UNPARSEABLE: all %d records in %s failed to parse as the "
                              "expected format; no trustworthy normalized interpretation "
                              "can be produced." % (parsed.line_count, relative),
                    "detail": outcome.detail, "parsed": parsed}
        return {"source": relative, "status": model.PARTIAL,
                "reason": "MALFORMED_RECORDS: %d of %d records in %s could not be "
                          "parsed as the expected format and are retained as anomalies."
                          % (parsed.malformed_count, parsed.line_count, relative),
                "detail": outcome.detail, "parsed": parsed}

    return {"source": relative, "status": model.COLLECTED, "reason": None,
            "detail": outcome.detail, "parsed": parsed}


# Marks a shadow name whose first record is malformed: its relation is unknown.
_UNCERTAIN = {"uncertain": True}


def _shadow_relation(name, shadow_result, shadow_index):
    """How this account relates to the shadow source. Three answers, never one.

    FROZEN INVARIANT (owner ruling, W1-D review):
    `ABSENT_FROM_COLLECTED_SOURCE` is valid ONLY when the counterpart source is fully
    COLLECTED. If shadow is PARTIAL, this account's record may have been one of the
    malformed lines, so "not in the index" means unknown, not absent. ERROR and
    NOT_TESTED are likewise unknown.

    A successfully parsed matching record is PRESENT even when the source overall is
    PARTIAL - those two facts are compatible, and the record is evidence regardless of
    what happened to other lines.
    """
    if name is not None and shadow_index.get(name) is _UNCERTAIN:
        return model.RECORD_SOURCE_NOT_COLLECTED
    if name is not None and name in shadow_index:
        return model.RECORD_PRESENT
    if not _domain_complete(shadow_result):
        # Including an INCLUDE directive: the NIS map may hold this account's shadow
        # entry, so "not in the local file" is unknown, not absent (pass 3, F2).
        return model.RECORD_SOURCE_NOT_COLLECTED
    # The source was read COMPLETELY and says no. Only now is absence evidence.
    return model.RECORD_ABSENT_FROM_COLLECTED_SOURCE


def _redact_untrusted(record, text_fields):
    """Keep a malformed record's shape, never its text (re-check R4-1, R4-2).

    W1-D §9 retains a malformed record so its presence forces PARTIAL; it does not require
    the record's text. A line glibc rejects, or one ISEDRAF cannot state exactly, is not
    identity: with its first colon missing the "name" is the password field, and a
    commented /etc/group line is free text. Owner ruling N3 keeps such text out of
    diagnostics; this keeps it out of STATE. Numbers and anomalies stay; the name is
    replaced by its byte length.
    """
    raw = record["name_bytes_hex"]
    record["name_length"] = len(raw) // 2 if raw else 0
    for field in ("name", "name_encoding", "name_bytes_hex", "name_non_ascii") + text_fields:
        record[field] = None
    return record


_NSS_DATABASE = {PASSWD: "passwd", GROUP: "group", SHADOW: "shadow"}


def compat_context(nss_evidence):
    """The NSS mode of each account database, from NSS evidence (owner ruling IQ-036).

    Pure over the evidence the NSS collector produced; nothing is read here. compat is
    established only when nsswitch.conf was fully interpreted and the database lists
    `compat` without `files`: `files` reads the same lines literally, so both together
    are ambiguous. Missing, unreadable, partially interpreted, duplicated or undeclared
    means the mode is not asserted, never guessed.
    """
    unknown = {rel: model.NSS_MODE_NOT_ASSERTED for rel in _NSS_DATABASE}
    if not nss_evidence or nss_evidence.get("status") != nss_model.COLLECTED:
        return unknown
    context = {}
    for rel, database in _NSS_DATABASE.items():
        lines = [r for r in nss_evidence.get("records", []) if r.get("database") == database]
        if len(lines) != 1 or lines[0].get("semantics") != nss_model.KNOWN:
            context[rel] = model.NSS_MODE_NOT_ASSERTED
            continue
        context[rel] = _mode_of(lines[0])
        if context[rel] == model.NSS_COMPAT:
            # The included map is `<db>_compat`. When a service reading the local file
            # supplies it, "+" re-reads this very file literally, and a bare "+" becomes
            # a uid-0 account named "+" (red team pass 8, N1). Undeclared, it is nis.
            maps = [r for r in nss_evidence.get("records", [])
                    if r.get("database") == database + "_compat"]
            if maps and (len(maps) != 1 or maps[0].get("semantics") != nss_model.KNOWN
                         or {e.get("class") for e in maps[0].get("entries", [])}
                         & {nss_model.LOCAL_FILES, nss_model.COMPAT, nss_model.UNKNOWN}):
                context[rel] = model.NSS_MODE_NOT_ASSERTED
    if context[GROUP] != model.NSS_MODE_NOT_ASSERTED:
        # initgroups decides supplementary groups and reads /etc/group itself: declared
        # with `files` it reads "+wheel:x:0:alice" literally and grants gid 0 (red team pass
        # 7, F1). group is compat only when initgroups is undeclared or compat as well.
        lines = [r for r in nss_evidence.get("records", [])
                 if r.get("database") == "initgroups"]
        # Its mirror too: `group: files` with `initgroups: compat` (pass 8, N3). Whenever
        # initgroups reads /etc/group in a different mode from group, the file's lines do
        # not mean one thing, and the mode is not asserted.
        if lines and (len(lines) != 1 or lines[0].get("semantics") != nss_model.KNOWN
                      or _mode_of(lines[0]) != context[GROUP]):
            context[GROUP] = model.NSS_MODE_NOT_ASSERTED
    return context


def file_effectiveness(nss_evidence):
    """Whether NSS consults each local account file (owner ruling IQ-037).

    A fact about the resolver, separate from what the file holds: `passwd: sss` makes
    /etc/passwd INACTIVE while its records stay COLLECTED and fully confident. Only a
    configuration whose every identity line was interpreted (unknown services aside,
    which make their own database NOT_ASSERTED) supports ACTIVE or INACTIVE; an unknown
    service token never lets ISEDRAF infer that the file is ineffective.
    """
    unknown = {rel: {"files_effective": model.FILES_NOT_ASSERTED, "configured_services": None}
               for rel in _NSS_DATABASE}
    unknown[GROUP]["initgroups_files_effective"] = model.FILES_NOT_ASSERTED
    if not nss_evidence or nss_evidence.get("status") not in (nss_model.COLLECTED,
                                                             nss_model.PARTIAL):
        return unknown
    # glibc discards the whole file for a line it cannot parse, so such a line leaves
    # every database unasserted. A duplicated database or an unknown service affects only
    # its own line, which _effective judges.
    if any(a.get("anomaly") not in (nss_model.ANOMALY_UNKNOWN_SERVICE,
                                    nss_model.ANOMALY_DUPLICATE)
           for a in nss_evidence.get("anomalies", [])):
        return unknown
    out = {rel: _effective(nss_evidence, database) for rel, database in _NSS_DATABASE.items()}
    # Supplementary groups come from `initgroups` when it is declared; undeclared, glibc
    # uses the group line. /etc/group can be a source for one and not the other.
    declared = any(r.get("database") == "initgroups" for r in nss_evidence.get("records", []))
    out[GROUP]["initgroups_files_effective"] = (
        _effective(nss_evidence, "initgroups")["files_effective"] if declared
        else out[GROUP]["files_effective"])
    return out


def _effective(nss_evidence, database):
    """ACTIVE / INACTIVE / NOT_ASSERTED for one database line (see file_effectiveness)."""
    lines = [r for r in nss_evidence.get("records", []) if r.get("database") == database]
    if len(lines) != 1 or lines[0].get("semantics") != nss_model.KNOWN:
        return {"files_effective": model.FILES_NOT_ASSERTED, "configured_services": None}
    entries = lines[0].get("entries", [])
    classes = [e.get("class") for e in entries]
    if nss_model.UNKNOWN in classes:
        # A module nobody classified: what it contributes or shadows, and so whether the
        # file decides anything, is not asserted - even beside `files`.
        state = model.FILES_NOT_ASSERTED
    elif nss_model.LOCAL_FILES in classes or nss_model.COMPAT in classes:
        state = model.FILES_ACTIVE
    else:
        state = model.FILES_INACTIVE
    return {"files_effective": state,
            "configured_services": [e.get("service") for e in entries]}


def _mode_of(record):
    classes = [e.get("class") for e in record.get("entries", [])]
    if nss_model.COMPAT in classes:
        return (model.NSS_MODE_NOT_ASSERTED if nss_model.LOCAL_FILES in classes
                else model.NSS_COMPAT)
    return model.NSS_NOT_COMPAT


def _interpret_compat_syntax(results, context):
    """Give "+"/"-" lines their meaning from the NSS context, or none (owner ruling IQ-036).

    The parser recognised compat-SHAPED lines from the text alone. Only a database whose
    mode is compat turns them into directive evidence. Anywhere else they are not
    reinterpreted - under `files` glibc enumerates "+alice:x:1000:..." as a literal entry
    and a bare "+" as uid 0 - and the source cannot claim complete local identity
    evidence, so it is PARTIAL with the reason named. Only line numbers and shape are kept.
    """
    uninterpreted = {}
    for rel, r in results.items():
        mode = context.get(rel, model.NSS_MODE_NOT_ASSERTED)
        r["compat_mode"] = mode
        parsed = r["parsed"]
        if parsed is None or not parsed.directives:
            uninterpreted[rel] = []
            continue
        if mode == model.NSS_COMPAT:
            uninterpreted[rel] = []
            _local_after_include(r, rel, parsed)
            _local_after_exclude(r, rel, parsed)
            continue
        if mode == model.NSS_MODE_NOT_ASSERTED:
            # Nothing after the first +/- line is known either way (pass 7, F4).
            first = min(d["line"] for d in parsed.directives)
            for rec in parsed.records:
                if rec["line"] > first:
                    _mark(rec, parsed, model.ANOMALY_AFTER_UNINTERPRETED_COMPAT,
                          "follows compat syntax in a database whose NSS mode is not "
                          "established")
        uninterpreted[rel] = [{"line": d["line"], "sign": "+" if d["kind"] ==
                               model.DIRECTIVE_INCLUDE else "-", "target": d["target"],
                               "name_length": len(d["name"] or "") if d["name"] is not None
                               else d.get("name_length", 0)}
                              for d in parsed.directives]
        code = (model.REASON_COMPAT_WITHOUT_COMPAT if mode == model.NSS_NOT_COMPAT
                else model.REASON_NSS_MODE_NOT_ASSERTED)
        note = ("%s: %d line(s) of %s have compat directive syntax, but the NSS "
                "configuration %s; they are not interpreted and local identity evidence "
                "is not complete." % (
                    code, len(parsed.directives), rel,
                    "does not establish compat for this database"
                    if mode == model.NSS_NOT_COMPAT
                    else "for this database could not be established"))
        if r["status"] == model.COLLECTED:
            r["status"], r["reason"] = model.PARTIAL, note
        elif r["status"] == model.PARTIAL:
            r["reason"] = "%s %s" % (r["reason"], note)
    return uninterpreted


def _local_after_include(r, rel, parsed):
    """Under compat, a local record after an INCLUDE is not resolved from the file alone.

    glibc consults the included map at the INCLUDE's position: with the map unavailable a
    later local line is not resolved at all, and with it available the map may supply or
    shadow that line (measured by the NSS-aware differential harness, IQ-036). A local
    line before every INCLUDE, or after only EXCLUDEs, resolves locally. The classic NIS
    host keeps "+" as its last line and is unaffected.
    """
    includes = [d["line"] for d in parsed.directives if d["kind"] == model.DIRECTIVE_INCLUDE]
    if not includes:
        return
    later = [rec for rec in parsed.records if rec["line"] > min(includes)]
    if not later:
        return
    for rec in later:
        # Per record: none of these is a confident local account (harness, FALSE_PRESENT).
        _mark(rec, parsed, model.ANOMALY_AFTER_COMPAT_INCLUDE,
              "follows an INCLUDE directive; its effective resolution depends on the map")
    note = ("%s: %d local record(s) of %s follow an INCLUDE directive; under compat the "
            "included map is consulted first and can supply or shadow them, so their "
            "effective resolution is not established locally." % (
                model.REASON_COMPAT_LOCAL_AFTER_INCLUDE, len(later), rel))
    if r["status"] == model.COLLECTED:
        r["status"], r["reason"] = model.PARTIAL, note
    elif r["status"] == model.PARTIAL:
        r["reason"] = "%s %s" % (r["reason"], note)


def _mark(rec, parsed, anomaly, detail):
    if anomaly not in rec["anomalies"]:
        rec["anomalies"].append(anomaly)
        parsed.anomalies.append(sources._anomaly(anomaly, detail, rec["line"]))


def _local_after_exclude(r, rel, parsed):
    """Under compat, a local record after an EXCLUDE that may name it is not resolvable.

    glibc's keyed lookups (getpwnam, getspnam, getgrnam) apply "-alice" to a local alice
    line after it, while enumeration still lists her (measured, red team pass 7, F2). An
    EXCLUDE of a netgroup, or one whose name could not be read, may name anyone after it.
    """
    later = []
    for d in parsed.directives:
        if d["kind"] != model.DIRECTIVE_EXCLUDE:
            continue
        key = parsed.directive_keys.get(d["line"])
        named = d["target"] == model.DIRECTIVE_NAME and key is not None
        later.extend(rec for rec in parsed.records if rec["line"] > d["line"]
                     and (not named or rec["name_bytes_hex"] == key))
    if not later:
        return
    for rec in later:
        _mark(rec, parsed, model.ANOMALY_AFTER_COMPAT_EXCLUDE,
              "follows an EXCLUDE directive that may name it; glibc does not resolve it "
              "by name")
    count = len({rec["line"] for rec in later})
    note = ("%s: %d local record(s) of %s follow an EXCLUDE directive that may name them; "
            "under compat glibc enumerates them but does not resolve them by name." % (
                model.REASON_COMPAT_LOCAL_AFTER_EXCLUDE, count, rel))
    if r["status"] == model.COLLECTED:
        r["status"], r["reason"] = model.PARTIAL, note
    elif r["status"] == model.PARTIAL:
        r["reason"] = "%s %s" % (r["reason"], note)


def _shadowed_by_earlier_line(result):
    """A record whose name first appears on a malformed line is not what glibc resolves.

    glibc accepts some lines ISEDRAF rejects (a 6- or 8-field passwd line, for one) and
    resolves a name from the first line it accepts, so "alice:x:0:0::/r" before a clean
    alice makes getpwnam return uid 0 (red team pass 8, N2). The same rule the shadow
    index already applies: the later record carries an anomaly, never confidence.
    """
    parsed = result["parsed"]
    if parsed is None:
        return
    first = {}
    for rec in parsed.records:
        key = rec["name_bytes_hex"]
        if key is None:
            continue
        if key not in first:
            first[key] = rec
        elif first[key]["malformed"]:
            _mark(rec, parsed, model.ANOMALY_SHADOWED_BY_EARLIER_LINE,
                  "an earlier line with the same name, which glibc may resolve instead, "
                  "could not be read exactly")


def _directives(result):
    """Directive evidence exists only where the NSS mode is compat (IQ-036)."""
    if result.get("compat_mode") != model.NSS_COMPAT or result["parsed"] is None:
        return []
    return result["parsed"].directives


def collect(root="/", nss_context=None, effectiveness=None):
    """Collect the three local account files and join them.

    Returns local account records, local group records, per-source status, and the
    anomalies. It returns no judgement: nothing here decides whether an account is
    privileged, human, active or compliant.

    `nss_context` maps each source to its NSS mode (see compat_context). It is supplied
    explicitly, never discovered here; without it the mode is not asserted, so compat
    syntax makes its source PARTIAL rather than being guessed into directives (IQ-036).

    `effectiveness` (see file_effectiveness) says whether NSS consults each file. It is
    reported beside the evidence and never changes it (IQ-037).
    """
    results = {rel: acquire(root, rel) for rel in (PASSWD, GROUP, SHADOW)}
    context = dict({rel: model.NSS_MODE_NOT_ASSERTED for rel in _NSS_DATABASE},
                   **(nss_context or {}))
    uninterpreted = _interpret_compat_syntax(results, context)
    for rel in (PASSWD, GROUP):
        _shadowed_by_earlier_line(results[rel])
    passwd_result, group_result, shadow_result = (
        results[PASSWD], results[GROUP], results[SHADOW])

    shadow_index = {}
    if shadow_result["parsed"] is not None:
        for rec in shadow_result["parsed"].records:
            if rec["name_bytes_hex"] is not None:
                # Keyed on the exact bytes: an undecodable name decodes to None and was
                # never joined (hardening red team F5).
                # First occurrence wins the INDEX only; the duplicate is already recorded
                # as an anomaly by the parser, and both records remain in `records`.
                # Only the FIRST record for a name can be joined, and only when it is
                # well formed. If a malformed line for the same name comes first, glibc
                # may have used it - ISEDRAF is sometimes stricter than glibc - so the
                # relation is unknown, never a confident join of a later line
                # (differential harness, N2). A malformed line is never an orphan.
                key = rec["name_bytes_hex"]
                if key not in shadow_index:
                    # A record compat leaves unresolved by name is never a confident
                    # join either (red team pass 7, F3).
                    uncertain = rec["malformed"] or any(
                        x in model.COMPAT_RESOLUTION_ANOMALIES for x in rec["anomalies"])
                    shadow_index[key] = _UNCERTAIN if uncertain else rec

    accounts = []
    if passwd_result["parsed"] is not None:
        for rec in passwd_result["parsed"].records:
            name = rec["name"]
            # The join is on the exact name bytes, never the decoded text (red team F5).
            relation = _shadow_relation(rec["name_bytes_hex"], shadow_result, shadow_index)
            account = {
                # --- from passwd, STATE -------------------------------------------
                "name": name,
                "name_encoding": rec["name_encoding"],
                "name_bytes_hex": rec["name_bytes_hex"],
                "name_non_ascii": rec["name_non_ascii"],
                "uid": rec["uid"],
                "primary_gid": rec["primary_gid"],
                "home": rec["home"],
                "shell": rec["shell"],
                "gecos": rec["gecos"],
                # --- provenance ---------------------------------------------------
                "nss_source": model.NSS_SOURCE,       # IDENT-041
                "passwd_line": rec["line"],
                "passwd_anomalies": rec["anomalies"],
                "shadow_record": relation,
                # --- from shadow, only when shadow was actually read ---------------
                "shadow": None,
            }
            if relation == model.RECORD_PRESENT:
                s = shadow_index[rec["name_bytes_hex"]]
                account["shadow"] = {
                    "password_state": s["password_state"],
                    "last_change_days": s["last_change_days"],
                    "last_change_days_source": s["last_change_days_source"],
                    "min_days": s["min_days"], "min_days_source": s["min_days_source"],
                    "max_days": s["max_days"], "max_days_source": s["max_days_source"],
                    "warn_days": s["warn_days"], "warn_days_source": s["warn_days_source"],
                    "inactive_days": s["inactive_days"],
                    "inactive_days_source": s["inactive_days_source"],
                    "expire_days": s["expire_days"],
                    "expire_days_source": s["expire_days_source"],
                    "shadow_line": s["line"],
                }
            if rec["malformed"]:
                _redact_untrusted(account, ("home", "shell", "gecos"))
            accounts.append(account)

    groups = []
    if group_result["parsed"] is not None:
        for rec in group_result["parsed"].records:
            group = {
                "name": rec["name"],
                "name_encoding": rec["name_encoding"],
                "name_bytes_hex": rec["name_bytes_hex"],
                "name_non_ascii": rec["name_non_ascii"],
                "gid": rec["gid"],
                # EXPLICIT supplementary members only. Primary membership is the passwd
                # GID relationship and is NOT merged in: a consumer that needs the
                # combined view must build it and say that it did.
                "explicit_members": rec["explicit_members"],
                "nss_source": model.NSS_SOURCE,
                "group_line": rec["line"],
                "group_anomalies": rec["anomalies"],
            }
            if rec["malformed"]:
                group["member_count"] = len(group["explicit_members"])
                _redact_untrusted(group, ())
                group["explicit_members"] = []
            groups.append(group)

    # Orphans in both directions, computed only where the evidence supports the question.
    # ABSENCE CLAIM REQUIRES COMPLETE EVIDENCE OVER THE RELEVANT SOURCE DOMAIN.
    #
    # Every entry below asserts that something is MISSING from a source. That claim is
    # only supportable when the source it is missing from was read completely. If passwd
    # is PARTIAL, a shadow record with no matching account may simply correspond to one
    # of the passwd lines that failed to parse - reporting it as an orphan would be an
    # accusation manufactured from a gap in our own reading.
    orphan_shadow, orphan_members, orphan_gids = [], [], []
    # W1-D §11a: an absence claim needs complete evidence over the source DOMAIN. A valid
    # "+" does not make collection PARTIAL (W1-D §9), but it includes the NIS map, which
    # may hold exactly the entries missing locally - so it withdraws absence claims
    # (red team pass 3, F2: orphans were asserted under "+").
    passwd_complete = _domain_complete(passwd_result)
    group_complete = _domain_complete(group_result)
    passwd_names = set(a["name_bytes_hex"] for a in accounts if a["name_bytes_hex"])

    if passwd_complete and shadow_result["parsed"] is not None:
        # The absence is asserted about passwd, so passwd must be complete. shadow may be
        # PARTIAL: we only enumerate the records it did yield.
        # Owner ruling N3 (2026-09-26): an orphan shadow record is reported by its line
        # and name length, never its text. Its "name" is untrusted - a line missing its
        # first colon makes glibc read name+hash as the name - and no pattern can tell a
        # name from a secret (DES carries no "$"), so no text is copied at all.
        orphan_shadow = sorted(
            ({"line": shadow_index[k]["line"], "name_length": len(k) // 2}
             for k in shadow_index if k not in passwd_names
             and shadow_index[k] is not _UNCERTAIN), key=lambda o: o["line"])

    if passwd_complete and group_result["parsed"] is not None:
        seen = set()
        # A malformed group line is untrusted text: its members are never orphan claims,
        # and a commented or broken line never echoes its content here (R3-3).
        for g in groups:
            if g["group_anomalies"]:
                continue
            for member in g["explicit_members"]:
                key = (member[4:] if member.startswith("hex:")
                       else textbytes.hex_of(member))
                # Deduplicated on the group's exact bytes: two undecodable groups both
                # decode to None and one orphan was lost (hardening re-check N6).
                if key not in passwd_names and (g["name_bytes_hex"], member) not in seen:
                    seen.add((g["name_bytes_hex"], member))
                    orphan_members.append({"group": g["name"], "member": member})

    if group_complete and passwd_result["parsed"] is not None:
        # A passwd primary GID with no matching group. Asserted about the group source,
        # so the group source must be complete.
        gids = set(g["gid"] for g in groups if g["gid"] is not None)
        seen_gid = set()
        for a in accounts:
            if a["passwd_anomalies"]:
                continue                  # an untrusted account line claims nothing (R3-3)
            gid = a["primary_gid"]
            if gid is not None and gid not in gids and gid not in seen_gid:
                seen_gid.add(gid)
                orphan_gids.append({"account": a["name"], "primary_gid": gid})

    topology = _compat_topology(results)
    return {
        "scope": model.SOURCE_SCOPE,
        "limitation": model.LIMITATION,
        # UNCHANGED, deliberately. The frozen shape of this block is what existing
        # consumers read, and R1.5-P is additive collection provenance rather than a
        # revision of domain facts. The machine answer lives in `coverage` below, in
        # ONE place: carrying `access_outcome` here as well would be the same fact in two
        # objects, which is the duplication the central-derivation ruling exists to stop.
        "sources": {rel: {"status": r["status"], "reason": r["reason"]}
                    for rel, r in results.items()},
        "coverage": [
            coverage.source("accounts", rel, r["status"], r["detail"],
                            coverage.OP_FILE_READ, reason=r["reason"],
                            universe=(coverage.UNIVERSE_COMPLETE
                                      if r["status"] == model.COLLECTED
                                      else coverage.UNIVERSE_INCOMPLETE))
            for rel, r in sorted(results.items())],
        "collection_status": _combined(results),
        "reason": _combined_reason(results),
        "local_accounts": accounts,
        "local_groups": groups,
        "orphan_shadow_records": orphan_shadow,
        "orphan_group_members": orphan_members,
        "orphan_primary_gids": orphan_gids,
        "absence_claims_supported": {
            "shadow_orphans": passwd_complete,
            "group_member_orphans": passwd_complete,
            "primary_gid_orphans": group_complete,
        },
        "group_limitation": model.GROUP_LIMITATION,
        "not_collected": list(model.NOT_COLLECTED),
        "anomalies": {rel: (r["parsed"].anomalies if r["parsed"] else [])
                      for rel, r in results.items()},
        # W1-D §9 clarification (owner, 2026-09-24). compat directives are retained as
        # directive evidence, never as accounts or groups, never in identity STATE.
        "compat_directives": {rel: _directives(r) for rel, r in results.items()},
        "nss_compat_context": {rel: results[rel]["compat_mode"] for rel in results},
        "nss_file_effectiveness": (effectiveness if effectiveness is not None
                                   else file_effectiveness(None)),
        "uninterpreted_compat_syntax": uninterpreted,
        "remote_identity_inclusion": _remote_inclusion(results),
        "compat_directive_topology": topology,
        "compat_directive_topology_digest": hashlib.sha256(
            canonical.canonical_bytes(topology)).hexdigest(),
    }


# Override positions that change resolution, per file, as glibc 2.43 applies them under
# compat (red team pass 4, L1). passwd overrides are uid, gid, gecos, home, shell: glibc
# ignores uid and gid, and gecos is personal data left out by owner ruling, so home and
# shell remain. glibc ignores every group override. shadow keeps shape only.
_RESOLVING_OVERRIDES = {PASSWD: (3, 4), GROUP: ()}
_EMPTY_PASSWORD = sources._password_state("")


def _compat_topology(results):
    """Canonical compat directive topology: collection/method identity, never STATE.

    Owner ruling F6 (2026-09-24). Under `compat`, where a directive sits among the local
    lines changes resolution. Each file is recorded as ONE ordered sequence of its local
    records and directives, up to its last directive: a local record after every directive
    interacts with none of them, so it does not enter.

    Red team pass 5 replaced a per-directive "which records precede it" set, which copied
    record names into the topology (a hash-shaped name leaked, H1), grew with directives x
    records (39 s and 1.4 GiB at 90 KB, H3), and could not express duplicate names or lines
    glibc rejects (M1, M2). The sequence is linear and captures every relative order.

    A local record appears only as its name when that name is a valid account name, and
    otherwise as a text-free placeholder: never its text, never its line number (L-a).
    Password and hash text, gecos and malformed field text never enter.
    """
    # Text-free references (red team pass 6, P6-2/P6-3): a name the topology may not
    # print is referred to by the position of the local record with the same bytes -
    # passwd for passwd and shadow, group for group. No name text, no name hash (N3).
    index = {PASSWD: _positions(results[PASSWD]), GROUP: _positions(results[GROUP])}
    index[SHADOW] = index[PASSWD]
    label = {PASSWD: "passwd", GROUP: "group", SHADOW: "passwd"}
    out = {}
    for rel in (PASSWD, GROUP, SHADOW):
        parsed = results[rel]["parsed"]
        if parsed is None:
            out[rel] = None
            continue
        directives = _directives(results[rel])
        if not directives:
            out[rel] = []
            continue
        last = max(d["line"] for d in directives)
        events = sorted([(r["line"], "local", r) for r in parsed.records
                         if r["line"] < last] +
                        [(d["line"], "directive", d) for d in directives])
        out[rel] = [{"local": _local_key(item, index[rel], label[rel])} if kind == "local"
                    else _directive_item(rel, item, parsed.directive_keys.get(item["line"]),
                                         index[rel], label[rel])
                    for _, kind, item in events]
    return out


def _positions(result):
    """name bytes (hex) -> position of the first local record with those bytes."""
    out = {}
    if result["parsed"] is not None:
        for position, rec in enumerate(result["parsed"].records):
            if rec["name_bytes_hex"] is not None:
                out.setdefault(rec["name_bytes_hex"], position)
    return out


def _reference(key, index, label):
    """"<file>:<position>" of the local record with these name bytes, or None."""
    position = index.get(key) if key is not None else None
    return None if position is None else "%s:%d" % (label, position)


def _local_key(record, index, label):
    """A local record's name when it is a valid account name, else a text-free reference.

    The reference is the position of the local record with the same name bytes, so two
    different names the topology may not print no longer share one marker (P6-2). Only a
    name with no local record to refer to falls back to the marker.
    """
    name = record.get("name")
    # A record the parser marked malformed never appears by name, however valid its
    # characters: a shadow line missing its first colon joins name and a DES hash, which
    # has no "$" or "/" to fail the character check (red team pass 6, P6-5).
    if (name is not None and not record.get("malformed")
            and sources._DIRECTIVE_NAME.match(name)):
        return name
    ref = _reference(record.get("name_bytes_hex"), index, label)
    return {"ref": ref} if ref is not None else "INVALID_OR_UNDECODABLE_NAME"


def _directive_item(rel, d, key=None, index=None, label=None):
    item = {"kind": d["kind"], "target": d["target"], "name": d["name"],
            "malformed": d["malformed"]}
    if rel != GROUP:
        # glibc ignores every group override, the password included (pass 5, L-c).
        password = d["password_field_state"]
        if rel in _RESOLVING_OVERRIDES and password is None:
            # glibc treats "+bob" and "+bob::::::" alike in passwd (pass 4, L1).
            password = _EMPTY_PASSWORD
        item["password_field_state"] = password
    fields = d["override_fields"]
    if d.get("ageing_values") is not None:
        # M2: validated integers, never text; source identity, never STATE.
        item["ageing_values"] = d["ageing_values"]
    elif _RESOLVING_OVERRIDES.get(rel) == ():
        # glibc ignores every group override, so none enters source identity, text or
        # shape (pass 5, L-c; the text is no longer even kept, pass 7, F7).
        item["overrides"] = []
    elif fields is None or rel not in _RESOLVING_OVERRIDES:
        item["override_shape"] = d["override_shape"]
    else:
        item["overrides"] = [fields[i] if i < len(fields) else ""
                             for i in _RESOLVING_OVERRIDES[rel]]
    if d["malformed"]:
        item["name_length"] = d["name_length"]
        if d["target"] == model.DIRECTIVE_NAME and index is not None:
            # Two malformed NAME directives of one length collided (P6-3): refer to the
            # local record with the same name bytes, never to the text.
            ref = _reference(key, index, label)
            if ref is not None:
                item["name_ref"] = ref
    return item


def _includes(result):
    """True when a source carries any INCLUDE directive, valid or malformed."""
    return any(d["kind"] == model.DIRECTIVE_INCLUDE for d in _directives(result))


def _domain_complete(result):
    """COLLECTED, and no INCLUDE directive widening the domain beyond the file."""
    return result["status"] == model.COLLECTED and not _includes(result)


def _remote_inclusion(results):
    """Remote identity scope, as IDENT-040 frames it: detected, never enumerated.

    A valid INCLUDE directive means the host's effective identity set may be broader than
    the local accounts above. That is scope evidence, not a failed collection: the local
    accounts were fully observed, and the NIS map was deliberately not read. What the map
    contains, and whether the NSS topology makes the directive effective, is not claimed.
    """
    # Malformed includes count: glibc applies "\t+alice…", so a conservative MALFORMED
    # label must not also report the inclusion as absent (red team pass 3, F8).
    via = sorted(rel for rel, r in results.items() if _includes(r))
    return {"detected": bool(via), "via_compat_directives_in": via, "enumerated": False}


def _combined(results):
    """Per-source first, then the aggregate. Never the other way round.

    Defect A's rule: one readable source does not satisfy completeness for an unreadable
    one. /etc/passwd being perfectly readable says nothing whatsoever about password
    state, so a run that could not open /etc/shadow is PARTIAL - never COLLECTED.
    """
    statuses = [r["status"] for r in results.values()]
    if all(s == model.COLLECTED for s in statuses):
        return model.COLLECTED
    if results[PASSWD]["status"] == model.ERROR:
        return model.ERROR
    if results[PASSWD]["status"] == model.NOT_TESTED:
        # Without passwd there is no account universe to be partial about.
        return model.NOT_TESTED
    return model.PARTIAL


def _combined_reason(results):
    incomplete = [(rel, r) for rel, r in results.items()
                  if r["status"] != model.COLLECTED]
    if not incomplete:
        return None
    return " ".join("%s: %s" % (rel, r["reason"]) for rel, r in sorted(incomplete))
