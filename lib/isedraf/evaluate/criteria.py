# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Native criterion evaluation over committed evidence - pure functions.
# Implements: D-121, D-125, CMP-003, EVAL-003, EVAL-004, ISE-ACCOUNT-001, ISE-ACCOUNT-002,
#             ISE-ACCOUNT-003, ISE-ACCOUNT-004, ISE-ACCOUNT-005, ISE-AUTH-001, ISE-SSH-001,
#             ISE-SSH-002
#
# Data in, data out: a section object already read from a verified snapshot, and the
# criterion record from the installed registry. Nothing here opens a file, reads the
# host, or fills in a missing fact.
#
# Each evaluator declares the JSON pointers it reads. They must equal the record's
# evidence_pointers exactly (EVAL-002: the record is the only description), and
# `pointers_match` is checked before a criterion is evaluated, so a record and its code
# cannot drift apart unnoticed.
#
# Malformed is not insufficient. A value the evidence model does not define - a status
# outside SCOPE-022, a list that is not a list, a COLLECTED source holding a record
# without a UID - is refused (MalformedEvidence), never turned into NOT_EVALUATED. Only a
# defined state of the model that cannot support a conclusion yields NOT_EVALUATED.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""EVAL-004: one result per criterion, from committed evidence only."""
import re

from ..status import COLLECTED, ERROR, NOT_TESTED, PARTIAL

STATUSES = (COLLECTED, PARTIAL, NOT_TESTED, ERROR)
SECTION_SCHEMA_VERSION = 2          # audit.SCHEMA_VERSION when this evaluator was written
ARTIFACT_ACCOUNTS = "sections/accounts.json"
ROOT_NAME_HEX = "726f6f74"          # the bytes of "root"
_HEX = re.compile(r"^(?:[0-9a-f]{2})+$")


class MalformedEvidence(ValueError):
    """The evidence holds a value its model does not define. Refused, never a result."""


# --- JSON pointers (RFC 6901), with <i> standing for every element of an array ---------

def _unescape(token):
    return token.replace("~1", "/").replace("~0", "~")


def resolve(document, pointer):
    """The value at `pointer`. A missing step is MalformedEvidence, never a default."""
    node = document
    for token in pointer.split("/")[1:]:
        key = _unescape(token)
        if isinstance(node, dict) and key in node:
            node = node[key]
        elif isinstance(node, list) and key.isdigit() and int(key) < len(node):
            node = node[int(key)]
        else:
            raise MalformedEvidence("the evidence has no %s" % pointer)
    return node


# --- ISE-ACCOUNT-001: restrict UID 0 to the root account -------------------------------

ACCOUNT_001 = "ISE-ACCOUNT-001"
P_STATUS = "/evidence/sources/etc~1passwd/status"
P_INCLUDED = "/evidence/remote_identity_inclusion/via_compat_directives_in"
P_ACCOUNTS = "/evidence/local_accounts"
P_UID = P_ACCOUNTS + "/<i>/uid"
P_NAME = P_ACCOUNTS + "/<i>/name_bytes_hex"
P_LINE = P_ACCOUNTS + "/<i>/passwd_line"
ACCOUNT_001_POINTERS = (
    ("manifest.json", "/manifest_core/auxiliary_artifacts/sections~1accounts.json"),
    (ARTIFACT_ACCOUNTS, P_STATUS),
    (ARTIFACT_ACCOUNTS, P_INCLUDED),
    (ARTIFACT_ACCOUNTS, P_UID),
    (ARTIFACT_ACCOUNTS, P_NAME),
    (ARTIFACT_ACCOUNTS, P_LINE),
)


def pointers_match(record, declared):
    """True when the record's evidence_pointers are exactly what the code reads."""
    try:
        listed = [(p["artifact"], p["pointer"]) for p in record["evidence_pointers"]]
    except (KeyError, TypeError):
        return False
    return sorted(listed) == sorted(declared)


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _accounts(section):
    """The local passwd records as (index, uid, name hex, line); shape is checked."""
    rows = resolve(section, P_ACCOUNTS)
    if not isinstance(rows, list):
        raise MalformedEvidence("%s is not a list" % P_ACCOUNTS)
    out = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or not {"uid", "name_bytes_hex", "passwd_line"} <= set(row):
            raise MalformedEvidence("%s/%d is not an account record" % (P_ACCOUNTS, i))
        uid, name, line = row["uid"], row["name_bytes_hex"], row["passwd_line"]
        if not (uid is None or _int(uid)) or not (name is None or (
                isinstance(name, str) and _HEX.match(name))) or not _int(line):
            raise MalformedEvidence("%s/%d holds a value the account model does not define"
                                    % (P_ACCOUNTS, i))
        out.append((i, uid, name, line, row.get("name")))
    return out


def _pointer(artifact, pointer, digests):
    return {"artifact": artifact, "digest": digests[artifact], "pointer": pointer}


def ise_account_001(section, record, digests):
    """(result, reason_code, reason, observations, evidence) for one accounts section.

    `digests` maps each artifact the evidence pointers name to the digest the snapshot
    manifest binds for it. The section is the whole sections/accounts.json object.
    """
    if not isinstance(section, dict) or section.get("section") != "accounts" or \
            section.get("schema_version") != SECTION_SCHEMA_VERSION:
        raise MalformedEvidence("sections/accounts.json is not an accounts section of schema %d"
                                % SECTION_SCHEMA_VERSION)
    section_status = section.get("collection_status")
    if section_status not in STATUSES:
        raise MalformedEvidence("the accounts section status %r is not a SCOPE-022 status"
                                % (section_status,))
    bound = [_pointer("manifest.json", ACCOUNT_001_POINTERS[0][1], digests)]

    if section.get("evidence") is None:
        # The collector produced nothing. That is a defined state only for a section that
        # says so; a COLLECTED section without evidence contradicts itself.
        if section_status == COLLECTED:
            raise MalformedEvidence("the accounts section is COLLECTED and holds no evidence")
        return (NOT_EVALUATED_RESULT, "SECTION_" + section_status,
                "the accounts section is %s and holds no evidence, so etc/passwd was not "
                "observed" % section_status, [], bound)

    status = resolve(section, P_STATUS)
    if status not in STATUSES:
        raise MalformedEvidence("%s is %r, not a SCOPE-022 status" % (P_STATUS, status))
    included = resolve(section, P_INCLUDED)
    if not isinstance(included, list) or not all(isinstance(x, str) for x in included):
        raise MalformedEvidence("%s is not a list of sources" % P_INCLUDED)
    rows = _accounts(section)
    evidence = bound + [_pointer(ARTIFACT_ACCOUNTS, P_STATUS, digests),
                        _pointer(ARTIFACT_ACCOUNTS, P_INCLUDED, digests)]
    uid0 = [r for r in rows if r[1] == 0]
    observations = [{"passwd_line": line, "name": shown, "name_bytes_hex": name, "uid": 0}
                    for (_i, _uid, name, line, shown) in uid0]
    for (i, _uid, _name, _line, _shown) in uid0:
        for p in (P_UID, P_NAME, P_LINE):
            evidence.append(_pointer(ARTIFACT_ACCOUNTS, p.replace("<i>", str(i)), digests))

    # EVAL-004: CMP-003 per required fact. An extra UID-0 record seen here is shown as an
    # observation; it is never a FAIL, because the source it came from is incomplete.
    if status != COLLECTED:
        return (NOT_EVALUATED_RESULT, "SOURCE_" + status,
                "etc/passwd is %s, so the local account set is not completely observed"
                % status, observations, evidence)
    if "etc/passwd" in included:
        return (NOT_EVALUATED_RESULT, "SOURCE_NOT_TESTED",
                "etc/passwd includes a NIS map through a compat INCLUDE directive; the map "
                "is NOT_TESTED, so the identity domain is not completely observed",
                observations, evidence)
    if any(uid is None or name is None for (_i, uid, name, _l, _s) in rows):
        # The collector makes a malformed record PARTIAL. COLLECTED with one is a
        # contradiction in the evidence, not a gap in it.
        raise MalformedEvidence("etc/passwd is COLLECTED and holds a record without an "
                                "exact UID or name")

    roots = [r for r in uid0 if r[2] == ROOT_NAME_HEX]
    if len(uid0) == 1 and len(roots) == 1:
        return ("PASS", "ONLY_ROOT_HAS_UID_0",
                "in etc/passwd as committed, exactly one entry has UID 0 and it is root",
                observations, evidence)
    if not uid0:
        code, why = "NO_UID_0_ENTRY", "no entry in etc/passwd has UID 0"
    elif not roots:
        code, why = "UID_0_NOT_ROOT", "the UID-0 entry in etc/passwd is not named root"
    elif len(roots) > 1 and len(roots) == len(uid0):
        code, why = "DUPLICATE_ROOT_ENTRY", "etc/passwd holds more than one root entry with UID 0"
    else:
        code, why = "ADDITIONAL_UID_0_ENTRY", "etc/passwd holds a UID-0 entry other than root"
    return ("FAIL", code, why + " (%d UID-0 entr%s)" % (len(uid0), "y" if len(uid0) == 1 else "ies"),
            observations, evidence)


NOT_EVALUATED_RESULT = "NOT_EVALUATED"
NE = NOT_EVALUATED_RESULT


# --- shared reading of the accounts section (ISE-ACCOUNT-002, -003, -004) --------------

P_SHADOW_STATUS = "/evidence/sources/etc~1shadow/status"
P_RELATION = P_ACCOUNTS + "/<i>/shadow_record"
P_PWSTATE = P_ACCOUNTS + "/<i>/shadow/password_state"
P_ORPHANS = "/evidence/orphan_shadow_records"
RELATIONS = ("PRESENT", "ABSENT_FROM_COLLECTED_SOURCE", "SOURCE_NOT_COLLECTED")
LOCKS = ("LOCK_PREFIX_PRESENT", "LOCK_PREFIX_ABSENT")
CONTENTS = ("EMPTY", "DISABLED_TOKEN", "HASH_PRESENT", "OTHER")
MD5_SCHEMES = ("MD5_CRYPT", "SUN_MD5")
NON_MD5_SCHEMES = ("BCRYPT", "SHA256_CRYPT", "SHA512_CRYPT", "SCRYPT", "YESCRYPT", "GOST_YESCRYPT")
OTHER_SCHEME = "OTHER_RECOGNIZED_FORMAT"


def _accounts_envelope(section, digests):
    """(section_status, has_evidence, the manifest pointer). Shape refused, never guessed."""
    if not isinstance(section, dict) or section.get("section") != "accounts" or \
            section.get("schema_version") != SECTION_SCHEMA_VERSION:
        raise MalformedEvidence("sections/accounts.json is not an accounts section of schema %d"
                                % SECTION_SCHEMA_VERSION)
    status = section.get("collection_status")
    if status not in STATUSES:
        raise MalformedEvidence("the accounts section status %r is not a SCOPE-022 status" % (status,))
    if section.get("evidence") is None and status == COLLECTED:
        raise MalformedEvidence("the accounts section is COLLECTED and holds no evidence")
    return status, section.get("evidence") is not None, [
        _pointer("manifest.json", ACCOUNT_001_POINTERS[0][1], digests)]


def _source_status(section, pointer):
    status = resolve(section, pointer)
    if status not in STATUSES:
        raise MalformedEvidence("%s is %r, not a SCOPE-022 status" % (pointer, status))
    return status


def _included(section):
    included = resolve(section, P_INCLUDED)
    if not isinstance(included, list) or not all(isinstance(x, str) for x in included):
        raise MalformedEvidence("%s is not a list of sources" % P_INCLUDED)
    return included


def _shadow_rows(section):
    """[(index, name hex, line, relation, password state or None)], shape checked."""
    rows = resolve(section, P_ACCOUNTS)
    if not isinstance(rows, list):
        raise MalformedEvidence("%s is not a list" % P_ACCOUNTS)
    out = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or not {"shadow_record", "shadow", "name_bytes_hex",
                                             "passwd_line"} <= set(row):
            raise MalformedEvidence("%s/%d is not an account record" % (P_ACCOUNTS, i))
        relation, shadow = row["shadow_record"], row["shadow"]
        if relation not in RELATIONS:
            raise MalformedEvidence("%s/%d/shadow_record %r is not a shadow relation"
                                    % (P_ACCOUNTS, i, relation))
        state = None
        if relation == "PRESENT":
            state = shadow.get("password_state") if isinstance(shadow, dict) else None
            if not isinstance(state, dict) or state.get("lock_prefix") not in LOCKS or \
                    state.get("content") not in CONTENTS:
                raise MalformedEvidence("%s/%d holds a password state the model does not define"
                                        % (P_ACCOUNTS, i))
            scheme = state.get("hash_scheme")
            if state["content"] == "HASH_PRESENT":
                if scheme not in MD5_SCHEMES + NON_MD5_SCHEMES + (OTHER_SCHEME,):
                    raise MalformedEvidence("%s/%d names a hash scheme outside the bounded "
                                            "vocabulary" % (P_ACCOUNTS, i))
            elif scheme is not None:
                raise MalformedEvidence("%s/%d names a hash scheme without a hash" % (P_ACCOUNTS, i))
        elif shadow is not None:
            raise MalformedEvidence("%s/%d carries shadow data without a PRESENT relation"
                                    % (P_ACCOUNTS, i))
        out.append((i, row["name_bytes_hex"], row["passwd_line"], relation, state,
                    row.get("name")))
    return out


def _named(name_hex, shown):
    return shown if shown is not None else ("hex:" + (name_hex or ""))


# --- ISE-ACCOUNT-002: empty local shadow password fields -------------------------------

ACCOUNT_002 = "ISE-ACCOUNT-002"
ACCOUNT_002_POINTERS = (
    ACCOUNT_001_POINTERS[0], (ARTIFACT_ACCOUNTS, P_STATUS), (ARTIFACT_ACCOUNTS, P_SHADOW_STATUS),
    (ARTIFACT_ACCOUNTS, P_INCLUDED), (ARTIFACT_ACCOUNTS, P_RELATION),
    (ARTIFACT_ACCOUNTS, P_PWSTATE), (ARTIFACT_ACCOUNTS, P_NAME), (ARTIFACT_ACCOUNTS, P_LINE))


def _shadow_sources(section, evidence, digests):
    """(passwd status, shadow status, included) and their pointers."""
    passwd = _source_status(section, P_STATUS)
    shadow = _source_status(section, P_SHADOW_STATUS)
    included = _included(section)
    evidence += [_pointer(ARTIFACT_ACCOUNTS, p, digests)
                 for p in (P_STATUS, P_SHADOW_STATUS, P_INCLUDED)]
    return passwd, shadow, included


def _insufficient(passwd, shadow, included, sources=("etc/passwd", "etc/shadow")):
    """A NOT_EVALUATED (code, reason) when a required source is not complete, else None."""
    for name, status in (("etc/passwd", passwd), ("etc/shadow", shadow)):
        if name in sources and status != COLLECTED:
            return ("SOURCE_" + status, "%s is %s, so the facts this criterion needs are not "
                    "completely observed" % (name, status))
    for name in sources:
        if name in included:
            return ("SOURCE_NOT_TESTED", "%s includes a NIS map through a compat INCLUDE "
                    "directive; the map is NOT_TESTED" % name)
    return None


def ise_account_002(section, record, digests):
    status, has, evidence = _accounts_envelope(section, digests)
    if not has:
        return (NE, "SECTION_" + status, "the accounts section is %s and holds no evidence"
                % status, [], evidence)
    passwd, shadow, included = _shadow_sources(section, evidence, digests)
    rows = _shadow_rows(section)
    empty = [r for r in rows if r[4] is not None and r[4]["content"] == "EMPTY"
             and r[4]["lock_prefix"] == "LOCK_PREFIX_ABSENT"]
    observations = [{"passwd_line": line, "name": _named(h, shown), "shadow_field": "EMPTY_UNLOCKED"}
                    for (_i, h, line, _rel, _st, shown) in empty]
    for (i, _h, _l, _r, _s, _n) in empty:
        for p in (P_RELATION, P_PWSTATE, P_NAME, P_LINE):
            evidence.append(_pointer(ARTIFACT_ACCOUNTS, p.replace("<i>", str(i)), digests))
    gap = _insufficient(passwd, shadow, included)
    if gap:
        return (NE, gap[0], gap[1], observations, evidence)
    unknown = [r for r in rows if r[3] == "SOURCE_NOT_COLLECTED"]
    if unknown:
        return (NE, "SHADOW_RELATION_UNKNOWN", "%d account(s) have a shadow relation that is "
                "not established" % len(unknown), observations, evidence)
    absent = [r for r in rows if r[3] == "ABSENT_FROM_COLLECTED_SOURCE"]
    if absent:
        return (NE, "SHADOW_RECORD_ABSENT", "%d account(s) have no /etc/shadow record; the "
                "/etc/passwd password field the system then consults is not in the committed "
                "evidence (IQ-077)" % len(absent), observations, evidence)
    if empty:
        return ("FAIL", "EMPTY_SHADOW_PASSWORD_FIELD", "in /etc/shadow as committed, %d "
                "account(s) have an empty, unlocked password field; this is an observation of "
                "the field, not a test of whether a login succeeds" % len(empty),
                observations, evidence)
    return ("PASS", "NO_EMPTY_SHADOW_PASSWORD_FIELD", "in /etc/shadow as committed, no account "
            "has an empty, unlocked password field", observations, evidence)


# --- ISE-ACCOUNT-003: duplicate local UIDs -------------------------------------------

ACCOUNT_003 = "ISE-ACCOUNT-003"
ACCOUNT_003_POINTERS = (
    ACCOUNT_001_POINTERS[0], (ARTIFACT_ACCOUNTS, P_STATUS), (ARTIFACT_ACCOUNTS, P_INCLUDED),
    (ARTIFACT_ACCOUNTS, P_UID), (ARTIFACT_ACCOUNTS, P_NAME), (ARTIFACT_ACCOUNTS, P_LINE))


def ise_account_003(section, record, digests):
    status, has, evidence = _accounts_envelope(section, digests)
    if not has:
        return (NE, "SECTION_" + status, "the accounts section is %s and holds no evidence"
                % status, [], evidence)
    passwd = _source_status(section, P_STATUS)
    included = _included(section)
    evidence += [_pointer(ARTIFACT_ACCOUNTS, p, digests) for p in (P_STATUS, P_INCLUDED)]
    rows = _accounts(section)
    by_uid, by_name = {}, {}
    for (i, uid, name, line, shown) in rows:
        if uid is not None and name is not None:
            by_uid.setdefault(uid, []).append((i, name, line, shown))
            by_name.setdefault(name, []).append((i, uid, line, shown))
    collisions = dict((u, v) for u, v in by_uid.items() if len(set(n for _i, n, _l, _s in v)) > 1)
    ambiguous = dict((n, v) for n, v in by_name.items() if len(set(u for _i, u, _l, _s in v)) > 1)
    repeated = dict((n, v) for n, v in by_name.items() if len(v) > 1 and n not in ambiguous)
    observations = []
    for uid in sorted(collisions):
        observations.append({"uid": uid, "kind": "UID_SHARED_BY_NAMES",
                             "entries": [{"passwd_line": l, "name": _named(n, s)}
                                         for (_i, n, l, s) in collisions[uid]]})
    for name in sorted(ambiguous):
        observations.append({"name": _named(name, ambiguous[name][0][3]), "kind": "NAME_WITH_UIDS",
                             "entries": [{"passwd_line": l, "uid": u} for (_i, u, l, _s) in ambiguous[name]]})
    for name in sorted(repeated):
        observations.append({"name": _named(name, repeated[name][0][3]), "kind": "REPEATED_ENTRY",
                             "entries": [{"passwd_line": l, "uid": u} for (_i, u, l, _s) in repeated[name]]})
    cited = set(i for v in collisions.values() for (i, _n, _l, _s) in v) | set(
        i for v in list(ambiguous.values()) + list(repeated.values()) for (i, _u, _l, _s) in v)
    for i in sorted(cited):
        for p in (P_UID, P_NAME, P_LINE):
            evidence.append(_pointer(ARTIFACT_ACCOUNTS, p.replace("<i>", str(i)), digests))
    gap = _insufficient(passwd, None, included, sources=("etc/passwd",))
    if gap:
        return (NE, gap[0], gap[1], observations, evidence)
    if any(uid is None or name is None for (_i, uid, name, _l, _s) in rows):
        raise MalformedEvidence("etc/passwd is COLLECTED and holds a record without an exact "
                                "UID or name")
    # Precedence (owner ruling 2026-11-04): a proven collision first, then ambiguity.
    if collisions:
        return ("FAIL", "UID_SHARED_BY_NAMES", "in /etc/passwd as committed, %d UID(s) are "
                "shared by different account names" % len(collisions), observations, evidence)
    if ambiguous:
        return ("MANUAL_REVIEW", "NAME_WITH_SEVERAL_UIDS", "in /etc/passwd as committed, %d "
                "name(s) appear on several lines with different UIDs, and both lines are in the "
                "evidence; which line the system resolves needs a person" % len(ambiguous),
                observations, evidence)
    return ("PASS", "UIDS_UNIQUE", "in /etc/passwd as committed, every UID belongs to one name"
            + (" (repeated identical entries are listed as observations)" if repeated else ""),
            observations, evidence)


# --- ISE-ACCOUNT-004: legacy MD5 password hash schemes -------------------------------

ACCOUNT_004 = "ISE-ACCOUNT-004"
ACCOUNT_004_POINTERS = (
    ACCOUNT_001_POINTERS[0], (ARTIFACT_ACCOUNTS, P_STATUS), (ARTIFACT_ACCOUNTS, P_SHADOW_STATUS),
    (ARTIFACT_ACCOUNTS, P_INCLUDED), (ARTIFACT_ACCOUNTS, P_RELATION),
    (ARTIFACT_ACCOUNTS, P_PWSTATE), (ARTIFACT_ACCOUNTS, P_NAME), (ARTIFACT_ACCOUNTS, P_ORPHANS))


def ise_account_004(section, record, digests):
    status, has, evidence = _accounts_envelope(section, digests)
    if not has:
        return (NE, "SECTION_" + status, "the accounts section is %s and holds no evidence"
                % status, [], evidence)
    passwd, shadow, included = _shadow_sources(section, evidence, digests)
    rows = _shadow_rows(section)
    orphans = resolve(section, P_ORPHANS)
    if not isinstance(orphans, list):
        raise MalformedEvidence("%s is not a list" % P_ORPHANS)
    evidence.append(_pointer(ARTIFACT_ACCOUNTS, P_ORPHANS, digests))
    md5 = [r for r in rows if r[4] is not None and r[4]["content"] == "HASH_PRESENT"
           and r[4]["hash_scheme"] in MD5_SCHEMES]
    observations = [{"passwd_line": line, "name": _named(h, shown), "hash_scheme": st["hash_scheme"],
                     "locked": st["lock_prefix"] == "LOCK_PREFIX_PRESENT"}
                    for (_i, h, line, _rel, st, shown) in md5]
    for (i, _h, _l, _r, _s, _n) in md5:
        for p in (P_RELATION, P_PWSTATE, P_NAME):
            evidence.append(_pointer(ARTIFACT_ACCOUNTS, p.replace("<i>", str(i)), digests))
    gap = _insufficient(passwd, shadow, included)
    if gap:
        return (NE, gap[0], gap[1], observations, evidence)
    if md5:
        return ("FAIL", "MD5_PASSWORD_HASH", "in /etc/shadow as committed, %d stored password "
                "hash(es) use an MD5-based scheme; this concerns the stored scheme, not whether "
                "the account can log in" % len(md5), observations, evidence)
    unclassified = [r for r in rows if r[4] is not None and (
        r[4]["content"] == "OTHER" or r[4]["hash_scheme"] == OTHER_SCHEME)]
    if unclassified:
        return (NE, "UNCLASSIFIED_PASSWORD_FIELD", "no MD5-based scheme is seen, but %d password "
                "field(s) are of a form the collector does not classify (OTHER); OTHER is never "
                "read as safe" % len(unclassified), observations, evidence)
    if any(r[3] != "PRESENT" for r in rows) or orphans:
        return (NE, "SHADOW_STATE_NOT_RECORDED", "no MD5-based scheme is seen, but some shadow "
                "states are not recorded (an account without a shadow record, or a shadow line "
                "without an account)", observations, evidence)
    return ("PASS", "NO_MD5_PASSWORD_HASH", "in /etc/shadow as committed, every stored password "
            "hash uses a recognised non-MD5 scheme", observations, evidence)


# --- ISE-SSH-001: global effective PermitEmptyPasswords ------------------------------

SSH_001 = "ISE-SSH-001"
ARTIFACT_SSH = "sections/ssh.json"
EFFECTIVE_OPERATION = "resolve_sshd_effective_config_v1"
P_COV = "/evidence/provenance/coverage"
P_RECORDS = "/evidence/records"
SSH_SCOPE_NOTE = ("Global effective SSH configuration only. Connection-specific Match values "
                  "are not resolved.")
SSH_001_POINTERS = (
    ("manifest.json", "/manifest_core/auxiliary_artifacts/sections~1ssh.json"),
    (ARTIFACT_SSH, P_COV + "/<i>/status"), (ARTIFACT_SSH, P_COV + "/<i>/operation_id"),
    (ARTIFACT_SSH, P_RECORDS + "/<i>/kind"), (ARTIFACT_SSH, P_RECORDS + "/<i>/keyword"),
    (ARTIFACT_SSH, P_RECORDS + "/<i>/value"), (ARTIFACT_SSH, P_RECORDS + "/<i>/scope"))


def ise_ssh_001(section, record, digests):
    if not isinstance(section, dict) or section.get("section") != "ssh" or \
            section.get("schema_version") != SECTION_SCHEMA_VERSION:
        raise MalformedEvidence("sections/ssh.json is not an ssh section of schema %d"
                                % SECTION_SCHEMA_VERSION)
    status = section.get("collection_status")
    if status not in STATUSES:
        raise MalformedEvidence("the ssh section status %r is not a SCOPE-022 status" % (status,))
    evidence = [_pointer("manifest.json", SSH_001_POINTERS[0][1], digests)]
    if section.get("evidence") is None:
        if status == COLLECTED:
            raise MalformedEvidence("the ssh section is COLLECTED and holds no evidence")
        return (NE, "SECTION_" + status, "the ssh section is %s and holds no evidence. "
                % status + SSH_SCOPE_NOTE, [], evidence)
    coverage = resolve(section, P_COV)
    records = resolve(section, P_RECORDS)
    if not isinstance(coverage, list) or not isinstance(records, list) or not all(
            isinstance(x, dict) for x in coverage + records):
        raise MalformedEvidence("the ssh coverage or records are not lists of objects")
    entries = [(i, e) for i, e in enumerate(coverage) if e.get("operation_id") == EFFECTIVE_OPERATION]
    if len(entries) > 1:
        raise MalformedEvidence("more than one coverage entry names %s" % EFFECTIVE_OPERATION)
    observations = []
    for i, r in enumerate(records):
        if r.get("kind") == "DIRECTIVE" and r.get("keyword") == "permitemptypasswords" \
                and r.get("scope") == "MATCH":
            observations.append({"declared_in_match": r.get("match_index"), "value": r.get("value")})
            for p in ("/kind", "/keyword", "/value", "/scope"):
                evidence.append(_pointer(ARTIFACT_SSH, "%s/%d%s" % (P_RECORDS, i, p), digests))
    if not entries:
        return (NE, "SOURCE_NOT_TESTED", "sshd -T was not run for this snapshot (a Standard "
                "Audit does not run it). " + SSH_SCOPE_NOTE, observations, evidence)
    (ci, entry), = entries
    evidence += [_pointer(ARTIFACT_SSH, "%s/%d/%s" % (P_COV, ci, f), digests)
                 for f in ("status", "operation_id")]
    cstatus = entry.get("status")
    if cstatus not in STATUSES:
        raise MalformedEvidence("the sshd -T coverage status %r is not a SCOPE-022 status" % (cstatus,))
    if cstatus != COLLECTED:
        return (NE, "SOURCE_" + cstatus, "sshd -T is %s (%s). " % (cstatus, entry.get("reason"))
                + SSH_SCOPE_NOTE, observations, evidence)
    found = [(i, r) for i, r in enumerate(records)
             if r.get("kind") == "RESOLVED_SETTING" and r.get("keyword") == "permitemptypasswords"]
    for i, _r in found:
        evidence += [_pointer(ARTIFACT_SSH, "%s/%d%s" % (P_RECORDS, i, p), digests)
                     for p in ("/kind", "/keyword", "/value")]
    if len(found) != 1:
        return (NE, "SETTING_NOT_REPORTED_ONCE", "sshd -T reported permitemptypasswords %d "
                "time(s), not once. " % len(found) + SSH_SCOPE_NOTE, observations, evidence)
    value = found[0][1].get("value")
    if value == "no":
        return ("PASS", "GLOBAL_PERMITEMPTYPASSWORDS_NO", "sshd -T reports PermitEmptyPasswords "
                "no. " + SSH_SCOPE_NOTE, observations, evidence)
    if value == "yes":
        return ("FAIL", "GLOBAL_PERMITEMPTYPASSWORDS_YES", "sshd -T reports PermitEmptyPasswords "
                "yes. " + SSH_SCOPE_NOTE, observations, evidence)
    return (NE, "SETTING_VALUE_UNKNOWN", "sshd -T reports a PermitEmptyPasswords value that is "
            "neither yes nor no. " + SSH_SCOPE_NOTE, observations, evidence)


# --- ISE-ACCOUNT-005: duplicate local GIDs -------------------------------------------

ACCOUNT_005 = "ISE-ACCOUNT-005"
P_GROUP_STATUS = "/evidence/sources/etc~1group/status"
P_GROUPS = "/evidence/local_groups"
P_GID = P_GROUPS + "/<i>/gid"
P_GNAME = P_GROUPS + "/<i>/name_bytes_hex"
P_GLINE = P_GROUPS + "/<i>/group_line"
ACCOUNT_005_POINTERS = (
    ACCOUNT_001_POINTERS[0], (ARTIFACT_ACCOUNTS, P_GROUP_STATUS), (ARTIFACT_ACCOUNTS, P_INCLUDED),
    (ARTIFACT_ACCOUNTS, P_GID), (ARTIFACT_ACCOUNTS, P_GNAME), (ARTIFACT_ACCOUNTS, P_GLINE))


def _groups(section):
    """The local group records as (index, gid, name hex, line, shown); shape is checked."""
    rows = resolve(section, P_GROUPS)
    if not isinstance(rows, list):
        raise MalformedEvidence("%s is not a list" % P_GROUPS)
    out = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or not {"gid", "name_bytes_hex", "group_line"} <= set(row):
            raise MalformedEvidence("%s/%d is not a group record" % (P_GROUPS, i))
        gid, name, line = row["gid"], row["name_bytes_hex"], row["group_line"]
        if not (gid is None or _int(gid)) or not (name is None or (
                isinstance(name, str) and _HEX.match(name))) or not _int(line):
            raise MalformedEvidence("%s/%d holds a value the group model does not define"
                                    % (P_GROUPS, i))
        out.append((i, gid, name, line, row.get("name")))
    return out


def ise_account_005(section, record, digests):
    status, has, evidence = _accounts_envelope(section, digests)
    if not has:
        return (NE, "SECTION_" + status, "the accounts section is %s and holds no evidence"
                % status, [], evidence)
    group_status = _source_status(section, P_GROUP_STATUS)
    included = _included(section)
    evidence += [_pointer(ARTIFACT_ACCOUNTS, p, digests) for p in (P_GROUP_STATUS, P_INCLUDED)]
    rows = _groups(section)
    by_gid, by_name = {}, {}
    for (i, gid, name, line, shown) in rows:
        if gid is not None and name is not None:
            by_gid.setdefault(gid, []).append((i, name, line, shown))
            by_name.setdefault(name, []).append((i, gid, line, shown))
    shared = dict((g, v) for g, v in by_gid.items() if len(set(n for _i, n, _l, _s in v)) > 1)
    several = dict((n, v) for n, v in by_name.items() if len(set(g for _i, g, _l, _s in v)) > 1)
    again = dict((n, v) for n, v in by_name.items() if len(v) > 1 and n not in several)
    observations = []
    for gid in sorted(shared):
        observations.append({"gid": gid, "kind": "GID_SHARED_BY_NAMES",
                             "entries": [{"group_line": l, "name": _named(n, s)}
                                         for (_i, n, l, s) in shared[gid]]})
    for name in sorted(several):
        observations.append({"name": _named(name, several[name][0][3]), "kind": "GROUP_NAME_WITH_GIDS",
                             "entries": [{"group_line": l, "gid": g} for (_i, g, l, _s) in several[name]]})
    for name in sorted(again):
        observations.append({"name": _named(name, again[name][0][3]), "kind": "REPEATED_GROUP_ENTRY",
                             "entries": [{"group_line": l, "gid": g} for (_i, g, l, _s) in again[name]]})
    cited = set(i for v in shared.values() for (i, _n, _l, _s) in v) | set(
        i for v in list(several.values()) + list(again.values()) for (i, _g, _l, _s) in v)
    for i in sorted(cited):
        for p in (P_GID, P_GNAME, P_GLINE):
            evidence.append(_pointer(ARTIFACT_ACCOUNTS, p.replace("<i>", str(i)), digests))
    # CMP-003 per required fact: a duplicate seen in an incomplete source is an observation.
    if group_status != COLLECTED:
        return (NE, "SOURCE_" + group_status, "etc/group is %s, so the local group set is not "
                "completely observed" % group_status, observations, evidence)
    if "etc/group" in included:
        return (NE, "SOURCE_NOT_TESTED", "etc/group includes a NIS map through a compat INCLUDE "
                "directive; the map is NOT_TESTED", observations, evidence)
    if any(gid is None or name is None for (_i, gid, name, _l, _s) in rows):
        raise MalformedEvidence("etc/group is COLLECTED and holds a record without an exact "
                                "GID or name")
    # Precedence as ISE-ACCOUNT-003 (owner ruling 2026-11-04): a proven collision first.
    if shared:
        return ("FAIL", "GID_SHARED_BY_NAMES", "in /etc/group as committed, %d GID(s) are shared "
                "by different group names" % len(shared), observations, evidence)
    if several:
        return ("MANUAL_REVIEW", "GROUP_NAME_WITH_SEVERAL_GIDS", "in /etc/group as committed, %d "
                "group name(s) appear on several lines with different GIDs, and both lines are in "
                "the evidence; which line the system resolves needs a person" % len(several),
                observations, evidence)
    return ("PASS", "GIDS_UNIQUE", "in /etc/group as committed, every GID belongs to one name"
            + (" (repeated identical entries are listed as observations)" if again else ""),
            observations, evidence)


# --- ISE-AUTH-001: declared login.defs ENCRYPT_METHOD --------------------------------

AUTH_001 = "ISE-AUTH-001"
ARTIFACT_LOGIN = "sections/loginpolicy.json"
LOGIN_DEFS_FAMILY = "LOGIN_DEFS"
ENCRYPT_KEY = "ENCRYPT_METHOD"
P_LSOURCES = "/evidence/provenance/sources"
P_LRECORDS = "/evidence/records"
# Compared exactly: login.defs keys and values are case-sensitive, and a value spelled
# otherwise is not one of these methods to the tools that read it, so it never passes.
LEGACY_METHODS = ("MD5", "DES")
NON_LEGACY_METHODS = ("SHA256", "SHA512")
PLATFORM_DEPENDENT_METHODS = ("YESCRYPT", "BCRYPT")
AUTH_SCOPE_NOTE = ("The declared /etc/login.defs setting only; the method PAM applies when a "
                   "password is changed is not evaluated.")
AUTH_001_POINTERS = (
    ("manifest.json", "/manifest_core/auxiliary_artifacts/sections~1loginpolicy.json"),
    (ARTIFACT_LOGIN, P_LSOURCES + "/<i>/family"), (ARTIFACT_LOGIN, P_LSOURCES + "/<i>/status"),
    (ARTIFACT_LOGIN, P_LRECORDS + "/<i>/family"), (ARTIFACT_LOGIN, P_LRECORDS + "/<i>/key"),
    (ARTIFACT_LOGIN, P_LRECORDS + "/<i>/value"), (ARTIFACT_LOGIN, P_LRECORDS + "/<i>/retention"),
    (ARTIFACT_LOGIN, P_LRECORDS + "/<i>/malformed"))
RETENTIONS = ("RETAIN_VALUE", "REDACT_VALUE", "DIGEST_VALUE", "NOT_RETAINED")


def ise_auth_001(section, record, digests):
    if not isinstance(section, dict) or section.get("section") != "loginpolicy" or \
            section.get("schema_version") != SECTION_SCHEMA_VERSION:
        raise MalformedEvidence("sections/loginpolicy.json is not a loginpolicy section of "
                                "schema %d" % SECTION_SCHEMA_VERSION)
    section_status = section.get("collection_status")
    if section_status not in STATUSES:
        raise MalformedEvidence("the loginpolicy section status %r is not a SCOPE-022 status"
                                % (section_status,))
    evidence = [_pointer("manifest.json", AUTH_001_POINTERS[0][1], digests)]
    if section.get("evidence") is None:
        if section_status == COLLECTED:
            raise MalformedEvidence("the loginpolicy section is COLLECTED and holds no evidence")
        return (NE, "SECTION_" + section_status, "the loginpolicy section is %s and holds no "
                "evidence. " % section_status + AUTH_SCOPE_NOTE, [], evidence)
    sources = resolve(section, P_LSOURCES)
    records = resolve(section, P_LRECORDS)
    if not isinstance(sources, list) or not isinstance(records, list) or not all(
            isinstance(x, dict) for x in sources + records):
        raise MalformedEvidence("the loginpolicy sources or records are not lists of objects")
    declared = [(i, s) for i, s in enumerate(sources) if s.get("family") == LOGIN_DEFS_FAMILY]
    if not declared:
        raise MalformedEvidence("the loginpolicy provenance lists no %s source" % LOGIN_DEFS_FAMILY)
    for i, s in declared:
        if s.get("status") not in STATUSES:
            raise MalformedEvidence("%s/%d/status %r is not a SCOPE-022 status"
                                    % (P_LSOURCES, i, s.get("status")))
        evidence += [_pointer(ARTIFACT_LOGIN, "%s/%d/%s" % (P_LSOURCES, i, f), digests)
                     for f in ("family", "status")]
    ours = [(i, r) for i, r in enumerate(records) if r.get("family") == LOGIN_DEFS_FAMILY]
    for i, r in ours:
        if not isinstance(r.get("malformed"), bool):
            raise MalformedEvidence("%s/%d/malformed is not a boolean" % (P_LRECORDS, i))
    found = [(i, r) for i, r in ours if r.get("key") == ENCRYPT_KEY]
    observations = []
    for i, r in found:
        evidence += [_pointer(ARTIFACT_LOGIN, "%s/%d/%s" % (P_LRECORDS, i, f), digests)
                     for f in ("family", "key", "value", "retention", "malformed")]
        observations.append({"key": ENCRYPT_KEY, "value": r.get("value"),
                             "retention": r.get("retention")})
    unseen = [s for _i, s in declared if s.get("status") != COLLECTED]
    if unseen:
        return (NE, "SOURCE_" + unseen[0]["status"], "%s is %s, so the declared setting is not "
                "completely observed. " % (unseen[0].get("path") or LOGIN_DEFS_FAMILY,
                                           unseen[0]["status"]) + AUTH_SCOPE_NOTE,
                observations, evidence)
    if any(r["malformed"] for _i, r in ours):
        # The collector makes a malformed line PARTIAL; COLLECTED with one contradicts itself.
        raise MalformedEvidence("the LOGIN_DEFS source is COLLECTED and holds a malformed record")
    if not found:
        return (NE, "ENCRYPT_METHOD_NOT_DECLARED", "/etc/login.defs declares no ENCRYPT_METHOD; "
                "the built-in default is not in the committed evidence. " + AUTH_SCOPE_NOTE,
                observations, evidence)
    if len(found) > 1:
        return (NE, "ENCRYPT_METHOD_DECLARED_MORE_THAN_ONCE", "/etc/login.defs declares "
                "ENCRYPT_METHOD %d times; conflicting declarations never pass. " % len(found)
                + AUTH_SCOPE_NOTE, observations, evidence)
    (_i, only), = found
    retention, value = only.get("retention"), only.get("value")
    if retention not in RETENTIONS:
        raise MalformedEvidence("the ENCRYPT_METHOD retention %r is not defined" % (retention,))
    if retention != "RETAIN_VALUE":
        return (NE, "VALUE_NOT_RETAINED", "the ENCRYPT_METHOD value is not retained verbatim. "
                + AUTH_SCOPE_NOTE, observations, evidence)
    if not isinstance(value, str):
        raise MalformedEvidence("a retained ENCRYPT_METHOD value is not a string")
    if value in LEGACY_METHODS:
        return ("FAIL", "LEGACY_METHOD_DECLARED", "/etc/login.defs declares ENCRYPT_METHOD %s, a "
                "legacy method. " % value + AUTH_SCOPE_NOTE, observations, evidence)
    if value in NON_LEGACY_METHODS:
        return ("PASS", "DECLARED_METHOD_NOT_LEGACY", "/etc/login.defs declares ENCRYPT_METHOD "
                "%s, which is not MD5 or DES. This does not establish that the system as a whole "
                "uses a secure password hashing policy. " % value + AUTH_SCOPE_NOTE,
                observations, evidence)
    if value in PLATFORM_DEPENDENT_METHODS:
        return (NE, "PLATFORM_SUPPORT_NOT_EVIDENCED", "/etc/login.defs declares ENCRYPT_METHOD "
                "%s; whether this platform supports it is not in the committed evidence. "
                % value + AUTH_SCOPE_NOTE, observations, evidence)
    return (NE, "METHOD_NOT_RECOGNISED", "/etc/login.defs declares an ENCRYPT_METHOD value that "
            "is not one this criterion recognises exactly; it never passes. " + AUTH_SCOPE_NOTE,
            observations, evidence)


# --- ISE-SSH-002: global effective StrictModes ---------------------------------------

SSH_002 = "ISE-SSH-002"
SSH_002_POINTERS = SSH_001_POINTERS[:6]                 # no Match observations: no scope


def ise_ssh_002(section, record, digests):
    if not isinstance(section, dict) or section.get("section") != "ssh" or \
            section.get("schema_version") != SECTION_SCHEMA_VERSION:
        raise MalformedEvidence("sections/ssh.json is not an ssh section of schema %d"
                                % SECTION_SCHEMA_VERSION)
    section_status = section.get("collection_status")
    if section_status not in STATUSES:
        raise MalformedEvidence("the ssh section status %r is not a SCOPE-022 status"
                                % (section_status,))
    evidence = [_pointer("manifest.json", SSH_002_POINTERS[0][1], digests)]
    if section.get("evidence") is None:
        if section_status == COLLECTED:
            raise MalformedEvidence("the ssh section is COLLECTED and holds no evidence")
        return (NE, "SECTION_" + section_status, "the ssh section is %s and holds no evidence. "
                % section_status + SSH_SCOPE_NOTE, [], evidence)
    coverage = resolve(section, P_COV)
    records = resolve(section, P_RECORDS)
    if not isinstance(coverage, list) or not isinstance(records, list) or not all(
            isinstance(x, dict) for x in coverage + records):
        raise MalformedEvidence("the ssh coverage or records are not lists of objects")
    resolved = [(i, e) for i, e in enumerate(coverage) if e.get("operation_id") == EFFECTIVE_OPERATION]
    if len(resolved) > 1:
        raise MalformedEvidence("more than one coverage entry names %s" % EFFECTIVE_OPERATION)
    if not resolved:
        return (NE, "SOURCE_NOT_TESTED", "sshd -T was not run for this snapshot (a Standard "
                "Audit does not run it). " + SSH_SCOPE_NOTE, [], evidence)
    (ci, entry), = resolved
    evidence += [_pointer(ARTIFACT_SSH, "%s/%d/%s" % (P_COV, ci, f), digests)
                 for f in ("status", "operation_id")]
    entry_status = entry.get("status")
    if entry_status not in STATUSES:
        raise MalformedEvidence("the sshd -T coverage status %r is not a SCOPE-022 status"
                                % (entry_status,))
    if entry_status != COLLECTED:
        return (NE, "SOURCE_" + entry_status, "sshd -T is %s (%s). " % (entry_status,
                entry.get("reason")) + SSH_SCOPE_NOTE, [], evidence)
    settings = [(i, r) for i, r in enumerate(records)
                if r.get("kind") == "RESOLVED_SETTING" and r.get("keyword") == "strictmodes"]
    for i, _r in settings:
        evidence += [_pointer(ARTIFACT_SSH, "%s/%d%s" % (P_RECORDS, i, p), digests)
                     for p in ("/kind", "/keyword", "/value")]
    if len(settings) != 1:
        return (NE, "SETTING_NOT_REPORTED_ONCE", "sshd -T reported strictmodes %d time(s), not "
                "once. " % len(settings) + SSH_SCOPE_NOTE, [], evidence)
    setting = settings[0][1].get("value")
    if setting == "yes":
        return ("PASS", "GLOBAL_STRICTMODES_YES", "sshd -T reports StrictModes yes. "
                + SSH_SCOPE_NOTE, [], evidence)
    if setting == "no":
        return ("FAIL", "GLOBAL_STRICTMODES_NO", "sshd -T reports StrictModes no. "
                + SSH_SCOPE_NOTE, [], evidence)
    return (NE, "SETTING_VALUE_UNKNOWN", "sshd -T reports a StrictModes value that is neither "
            "yes nor no. " + SSH_SCOPE_NOTE, [], evidence)


# --- ISE-PRIV-001 / ISE-PRIV-002: the declared local sudo policy (D-131) ---------------
# Both read sections/sudo.json, which a Full Audit fills through read_sudoers_graph_v1. The
# evidence is the DECLARED policy: aliases are recorded, not resolved; group membership is not
# consulted; host matching and sudo's last-match rule are not applied. The position of an
# include directive is not in the committed evidence, so the order of declarations is known
# within one file (source_line) and not between files.

PRIV_001 = "ISE-PRIV-001"
PRIV_002 = "ISE-PRIV-002"
ARTIFACT_SUDO = "sections/sudo.json"
SUDOERS_OPERATION = "read_sudoers_graph_v1"
SUDOERS_ROOT = "/etc/sudoers"
P_SUDO_STATUS = "/collection_status"
P_INCLUDE_STATUS = "/evidence/provenance/include_status"
P_MALFORMED = "/evidence/provenance/malformed_count"
ALIAS_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
SUDO_SCOPE_NOTE = ("Declared local sudo policy only: aliases are not resolved, group membership "
                   "is not consulted, and sudo's last-match rule is not applied.")
_SUDO_COMMON = (
    ("manifest.json", "/manifest_core/auxiliary_artifacts/sections~1sudo.json"),
    (ARTIFACT_SUDO, P_SUDO_STATUS),
    (ARTIFACT_SUDO, P_COV + "/<i>/status"), (ARTIFACT_SUDO, P_COV + "/<i>/operation_id"),
    (ARTIFACT_SUDO, P_COV + "/<i>/source"), (ARTIFACT_SUDO, P_COV + "/<i>/access_outcome"),
    (ARTIFACT_SUDO, P_INCLUDE_STATUS), (ARTIFACT_SUDO, P_MALFORMED),
    (ARTIFACT_SUDO, P_RECORDS + "/<i>/kind"), (ARTIFACT_SUDO, P_RECORDS + "/<i>/source_path"),
    (ARTIFACT_SUDO, P_RECORDS + "/<i>/source_line"))
PRIV_001_POINTERS = _SUDO_COMMON + tuple(
    (ARTIFACT_SUDO, P_RECORDS + "/<i>/" + f)
    for f in ("principals", "host", "runas_users", "runas_groups", "commands",
              "scope_type", "scope", "options"))
ROOT_TARGETS = ("root", "#0")


def _runas_default(records):
    """Who a rule without a run-as list runs as: sudoers(5) - "the runas_default user (root by
    default)". Returns ("root" | "other" | "uncertain", [indexes of the settings])."""
    found = [(i, r.get("scope_type"), o) for i, r in enumerate(records)
             if r.get("kind") == "DEFAULTS" for o in (r.get("options") or [])
             if o.get("name") == "runas_default"]
    if not found:
        return "root", []
    cited = sorted(set(i for i, _s, _o in found))
    values = set(o.get("value") for _i, _s, o in found)
    if any(s != "GLOBAL" or o.get("negated") for _i, s, o in found) or len(values) != 1:
        return "uncertain", cited
    return ("root" if values.pop() in ROOT_TARGETS else "other"), cited
PRIV_002_POINTERS = _SUDO_COMMON + tuple(
    (ARTIFACT_SUDO, P_RECORDS + "/<i>/" + f) for f in ("scope_type", "scope", "options"))


def _sudo_policy(section, digests):
    """(records, None, evidence) when the declared policy is sufficient, else
    (None, (reason, detail), evidence). Raises MalformedEvidence on a value the model lacks."""
    if not isinstance(section, dict) or section.get("section") != "sudo" or \
            section.get("schema_version") != SECTION_SCHEMA_VERSION:
        raise MalformedEvidence("sections/sudo.json is not a sudo section of schema %d"
                                % SECTION_SCHEMA_VERSION)
    status = section.get("collection_status")
    if status not in STATUSES:
        raise MalformedEvidence("the sudo section status %r is not a SCOPE-022 status" % (status,))
    evidence = [_pointer("manifest.json", _SUDO_COMMON[0][1], digests),
                _pointer(ARTIFACT_SUDO, P_SUDO_STATUS, digests)]
    if section.get("evidence") is None:
        if status == COLLECTED:
            raise MalformedEvidence("the sudo section is COLLECTED and holds no evidence")
        return None, ("SECTION_" + status, "the sudo section is %s and holds no evidence"
                      % status), evidence
    coverage = resolve(section, P_COV)
    records = resolve(section, P_RECORDS)
    if not isinstance(coverage, list) or not isinstance(records, list) or not all(
            isinstance(x, dict) for x in coverage + records):
        raise MalformedEvidence("the sudo coverage or records are not lists of objects")
    roots = [(i, e) for i, e in enumerate(coverage)
             if e.get("operation_id") == SUDOERS_OPERATION and e.get("source") == SUDOERS_ROOT]
    if len(roots) > 1:
        raise MalformedEvidence("more than one coverage entry names %s for %s"
                                % (SUDOERS_OPERATION, SUDOERS_ROOT))
    if not roots:
        return None, ("SOURCE_NOT_TESTED", "/etc/sudoers was not read through %s for this "
                      "snapshot (a Standard Audit does not read it)" % SUDOERS_OPERATION), evidence
    (ci, root), = roots
    evidence += [_pointer(ARTIFACT_SUDO, "%s/%d/%s" % (P_COV, ci, f), digests)
                 for f in ("status", "operation_id", "source", "access_outcome")]
    if root.get("status") != COLLECTED:
        if root.get("access_outcome") == "NOT_FOUND":
            return None, ("SUDOERS_ABSENT", "the Full Audit found no /etc/sudoers; with no "
                          "declared policy to read, the criterion is not evaluated (sudo being "
                          "absent is not established by this alone)"), evidence
        return None, ("SOURCE_" + str(root.get("status")), "/etc/sudoers was not read (%s)"
                      % root.get("access_outcome")), evidence
    evidence += [_pointer(ARTIFACT_SUDO, P_INCLUDE_STATUS, digests),
                 _pointer(ARTIFACT_SUDO, P_MALFORMED, digests)]
    if status != COLLECTED:
        return None, ("SECTION_" + status, "the declared sudo policy is %s: %s"
                      % (status, section.get("reason"))), evidence
    if resolve(section, P_INCLUDE_STATUS) != COLLECTED:
        return None, ("INCLUDES_INCOMPLETE", "not every include of the sudo policy was read"), \
            evidence
    if resolve(section, P_MALFORMED) != 0 or any(r.get("kind") == "UNSUPPORTED" for r in records):
        return None, ("UNSUPPORTED_LINES", "a line of the sudo policy could not be read"), evidence
    return records, None, evidence


def _alias_names(records):
    return set(r.get("name") for r in records if r.get("kind") == "ALIAS")


def _is_alias(value, aliases):
    return value in aliases or (isinstance(value, str) and value != "ALL"
                                and bool(ALIAS_NAME.match(value)))


def _cite(i, fields, digests):
    return [_pointer(ARTIFACT_SUDO, "%s/%d/%s" % (P_RECORDS, i, f), digests)
            for f in ("kind", "source_path", "source_line") + fields]


def ise_priv_001(section, record, digests):
    records, gap, evidence = _sudo_policy(section, digests)
    if gap:
        return (NE, gap[0], gap[1] + ". " + SUDO_SCOPE_NOTE, [], evidence)
    aliases = _alias_names(records)
    default_target, default_cited = _runas_default(records)
    for i in default_cited:
        evidence += _cite(i, ("scope_type", "scope", "options"), digests)
    decisive, unresolved = [], []
    for i, r in enumerate(records):
        if r.get("kind") != "SPEC":
            continue
        principals, commands = r.get("principals"), r.get("commands")
        host, runas_u, runas_g = r.get("host"), r.get("runas_users"), r.get("runas_groups")
        if not isinstance(principals, list) or not isinstance(commands, list) or \
                not isinstance(host, dict):
            raise MalformedEvidence("a SPEC record lacks principals, commands or host")
        passwordless = [c for c in commands if "NOPASSWD" in (c.get("tags") or [])]
        relevant = [c for c in passwordless
                    if c.get("command") == "ALL" or _is_alias(c.get("command"), aliases)]
        if not relevant:
            continue
        if all(p.get("kind") == "USER" and p.get("value") == "root" and not p.get("negated")
               for p in principals):
            continue                                   # a declaration only for root: excluded
        # As root: a user list naming ALL or root, or no run-as list while runas_default is root.
        users = runas_u or []
        if runas_u is None and runas_g:
            continue                                   # (:group) runs as the invoking user
        if runas_u is None and default_target == "other":
            continue                                   # runas_default names another user
        as_root_plain = (runas_u is None and default_target == "root") or any(
            u.get("value") in ("ALL",) + ROOT_TARGETS and not u.get("negated") for u in users)
        default_open = runas_u is None and default_target == "uncertain"
        runas_open = any(u.get("negated") or _is_alias(u.get("value"), aliases) for u in users)
        if not as_root_plain and not runas_open and not default_open:
            continue                                   # a named non-root target: outside
        why = []
        if any(p.get("negated") for p in principals):
            why.append("a negated principal")
        if any(p.get("kind") == "ALIAS_REFERENCE" or _is_alias(p.get("value"), aliases)
               for p in principals):
            why.append("a principal alias")
        if host.get("negated") or host.get("value") != "ALL":
            why.append("a named or negated host" if not _is_alias(host.get("value"), aliases)
                       else "a host alias")
        if runas_open:
            why.append("a run-as alias or negation")
        if default_open:
            why.append("runas_default set in a way the evidence does not decide")
        if any(c.get("negated") for c in commands):
            why.append("a negated command")
        if not any(c.get("command") == "ALL" and not c.get("negated") for c in relevant):
            why.append("a command alias")
        cited = _cite(i, ("principals", "host", "runas_users", "runas_groups", "commands"),
                      digests)
        where = {"source_path": r.get("source_path"), "source_line": r.get("source_line"),
                 "principals": [("!" if p.get("negated") else "") + str(p.get("value"))
                                for p in principals]}
        if why:
            unresolved.append(dict(where, undecided_by=why))
        else:
            decisive.append(where)
        evidence += cited
    observations = ([dict(d, kind="UNAUTHENTICATED_ALL_AS_ROOT") for d in decisive]
                    + [dict(u, kind="UNRESOLVED_CANDIDATE") for u in unresolved])
    if decisive:
        return ("FAIL", "UNAUTHENTICATED_ALL_AS_ROOT", "the declared sudo policy grants every "
                "command as root, on every host, without authentication, to %d declaration(s) "
                "for principals other than root. " % len(decisive) + SUDO_SCOPE_NOTE,
                observations, evidence)
    if unresolved:
        return ("MANUAL_REVIEW", "CANDIDATE_NOT_RESOLVED", "%d passwordless rule(s) may grant "
                "every command as root, but an alias, a named host or a negation decides it, "
                "and the evidence does not resolve it. " % len(unresolved) + SUDO_SCOPE_NOTE,
                observations, evidence)
    return ("PASS", "NO_UNAUTHENTICATED_ALL_AS_ROOT", "no declaration in the sudo policy grants "
            "every command as root without authentication to a principal other than root, and "
            "no passwordless rule is left unresolved. " + SUDO_SCOPE_NOTE, [], evidence)


def _authenticate_settings(records):
    """[(i, scope_type, member, negated, source_path, source_line)] for every `authenticate`
    option, one entry per member of the scope as written (GLOBAL has the one member "*")."""
    out = []
    for i, r in enumerate(records):
        if r.get("kind") != "DEFAULTS":
            continue
        options = r.get("options")
        if not isinstance(options, list):
            raise MalformedEvidence("a DEFAULTS record lacks its options")
        stype = r.get("scope_type")
        members = ["*"] if stype == "GLOBAL" else [
            m.strip() for m in str(r.get("scope") or "").split(",") if m.strip()]
        for o in options:
            if o.get("name") != "authenticate":
                continue
            for m in members:
                out.append((i, stype, m, bool(o.get("negated")), r.get("source_path"),
                            r.get("source_line")))
    return out


def ise_priv_002(section, record, digests):
    records, gap, evidence = _sudo_policy(section, digests)
    if gap:
        return (NE, gap[0], gap[1] + ". " + SUDO_SCOPE_NOTE, [], evidence)
    aliases = _alias_names(records)
    settings = _authenticate_settings(records)
    by_scope = {}
    for s in settings:
        by_scope.setdefault((s[1], s[2]), []).append(s)
    disabled, unresolved = [], []
    for (stype, member), entries in sorted(by_scope.items()):
        values = set(e[3] for e in entries)
        files = set(e[4] for e in entries)
        where = {"scope_type": stype, "scope_member": member,
                 "declarations": [{"source_path": e[4], "source_line": e[5],
                                   "negated": e[3]} for e in entries]}
        if member != "*" and (member.startswith("!") or _is_alias(member, aliases)):
            if True in values:
                unresolved.append(dict(where, undecided_by="an alias or negation as the scope"))
            continue
        if len(values) > 1 and len(files) > 1:
            unresolved.append(dict(where, undecided_by="settings in several files: the order "
                                   "between files is not in the evidence"))
            continue
        last = max(entries, key=lambda e: (e[5] if isinstance(e[5], int) else -1))
        if last[3]:
            disabled.append(where)
    cited = sorted(set(e[0] for e in settings))
    for i in cited:
        evidence += _cite(i, ("scope_type", "scope", "options"), digests)
    observations = ([dict(d, kind="AUTHENTICATION_DISABLED") for d in disabled]
                    + [dict(u, kind="UNRESOLVED_SCOPE") for u in unresolved])
    if disabled:
        return ("FAIL", "AUTHENTICATION_DISABLED", "in %d scope(s) of the declared sudo policy "
                "the last authenticate setting is !authenticate. " % len(disabled)
                + SUDO_SCOPE_NOTE,
                observations, evidence)
    if unresolved:
        return ("MANUAL_REVIEW", "SCOPE_NOT_RESOLVED", "%d scope(s) set authenticate in a way the "
                "evidence does not decide (an alias or negation as the scope, or settings in "
                "several files). " % len(unresolved) + SUDO_SCOPE_NOTE, observations, evidence)
    return ("PASS", "AUTHENTICATION_NOT_DISABLED", "no scope of the declared sudo policy ends "
            "with !authenticate, and no setting is left unresolved. " + SUDO_SCOPE_NOTE,
            observations, evidence)


# --- ISE-SSH-003 / -004 / -005: more global sshd -T settings (D-132) --------------------

SSH_003 = "ISE-SSH-003"
SSH_004 = "ISE-SSH-004"
SSH_005 = "ISE-SSH-005"
SSH_003_POINTERS = SSH_002_POINTERS
SSH_004_POINTERS = SSH_002_POINTERS
SSH_005_POINTERS = SSH_002_POINTERS


def _sshd_settings(section, digests, keywords):
    """({keyword: value}, None, evidence) when sshd -T was collected and reports each keyword
    exactly once, else (None, (reason, detail), evidence). As ISE-SSH-002 reads it."""
    if not isinstance(section, dict) or section.get("section") != "ssh" or \
            section.get("schema_version") != SECTION_SCHEMA_VERSION:
        raise MalformedEvidence("sections/ssh.json is not an ssh section of schema %d"
                                % SECTION_SCHEMA_VERSION)
    status = section.get("collection_status")
    if status not in STATUSES:
        raise MalformedEvidence("the ssh section status %r is not a SCOPE-022 status" % (status,))
    evidence = [_pointer("manifest.json", SSH_002_POINTERS[0][1], digests)]
    if section.get("evidence") is None:
        if status == COLLECTED:
            raise MalformedEvidence("the ssh section is COLLECTED and holds no evidence")
        return None, ("SECTION_" + status, "the ssh section is %s and holds no evidence" % status), \
            evidence
    coverage = resolve(section, P_COV)
    records = resolve(section, P_RECORDS)
    if not isinstance(coverage, list) or not isinstance(records, list) or not all(
            isinstance(x, dict) for x in coverage + records):
        raise MalformedEvidence("the ssh coverage or records are not lists of objects")
    resolved = [(i, e) for i, e in enumerate(coverage) if e.get("operation_id") == EFFECTIVE_OPERATION]
    if len(resolved) > 1:
        raise MalformedEvidence("more than one coverage entry names %s" % EFFECTIVE_OPERATION)
    if not resolved:
        return None, ("SOURCE_NOT_TESTED", "sshd -T was not run for this snapshot (a Standard "
                      "Audit does not run it)"), evidence
    (ci, entry), = resolved
    evidence += [_pointer(ARTIFACT_SSH, "%s/%d/%s" % (P_COV, ci, f), digests)
                 for f in ("status", "operation_id")]
    if entry.get("status") not in STATUSES:
        raise MalformedEvidence("the sshd -T coverage status %r is not a SCOPE-022 status"
                                % (entry.get("status"),))
    if entry.get("status") != COLLECTED:
        return None, ("SOURCE_" + entry["status"], "sshd -T is %s (%s)" % (
            entry["status"], entry.get("reason"))), evidence
    values = {}
    for keyword in keywords:
        hits = [(i, r) for i, r in enumerate(records)
                if r.get("kind") == "RESOLVED_SETTING" and r.get("keyword") == keyword]
        for i, _r in hits:
            evidence += [_pointer(ARTIFACT_SSH, "%s/%d%s" % (P_RECORDS, i, p), digests)
                         for p in ("/kind", "/keyword", "/value")]
        if len(hits) != 1:
            return None, ("SETTING_NOT_REPORTED_ONCE", "sshd -T reported %s %d time(s), not once"
                          % (keyword, len(hits))), evidence
        values[keyword] = hits[0][1].get("value")
    return values, None, evidence


def ise_ssh_003(section, record, digests):
    values, gap, evidence = _sshd_settings(section, digests, ("permitrootlogin",))
    if gap:
        return (NE, gap[0], gap[1] + ". " + SSH_SCOPE_NOTE, [], evidence)
    value = values["permitrootlogin"]
    seen = [{"permitrootlogin": value}]
    if value == "no":
        return ("PASS", "ROOT_LOGIN_NO", "sshd -T reports PermitRootLogin no: root cannot log in "
                "over SSH by any method. " + SSH_SCOPE_NOTE, seen, evidence)
    if value == "yes":
        return ("FAIL", "ROOT_LOGIN_YES", "sshd -T reports PermitRootLogin yes: root can log in "
                "over SSH with any enabled method, a password included. " + SSH_SCOPE_NOTE,
                seen, evidence)
    if value in ("prohibit-password", "without-password"):
        return ("MANUAL_REVIEW", "ROOT_LOGIN_WITHOUT_PASSWORD", "sshd -T reports PermitRootLogin "
                "%s: root cannot log in with a password or keyboard-interactive authentication, "
                "but can with a key or another method that is not a password; whether that access "
                "is intended needs a person. " % value + SSH_SCOPE_NOTE, seen, evidence)
    if value == "forced-commands-only":
        return ("MANUAL_REVIEW", "ROOT_LOGIN_FORCED_COMMANDS", "sshd -T reports PermitRootLogin "
                "forced-commands-only: root can log in only with a public key whose authorized_keys "
                "entry forces a command, and runs only that command; whether those commands are "
                "intended needs a person. " + SSH_SCOPE_NOTE, seen, evidence)
    return (NE, "SETTING_VALUE_UNKNOWN", "sshd -T reports a PermitRootLogin value this criterion "
            "does not know. " + SSH_SCOPE_NOTE, seen, evidence)


def ise_ssh_004(section, record, digests):
    values, gap, evidence = _sshd_settings(section, digests, ("hostbasedauthentication",))
    if gap:
        return (NE, gap[0], gap[1] + ". " + SSH_SCOPE_NOTE, [], evidence)
    value = values["hostbasedauthentication"]
    seen = [{"hostbasedauthentication": value}]
    if value == "no":
        return ("PASS", "HOSTBASED_NO", "sshd -T reports HostbasedAuthentication no: host-based "
                "authentication is off globally. " + SSH_SCOPE_NOTE, seen, evidence)
    if value == "yes":
        return ("FAIL", "HOSTBASED_YES", "sshd -T reports HostbasedAuthentication yes: a user can "
                "log in because the connecting host is trusted, without proving who they are "
                "(host-based authentication). " + SSH_SCOPE_NOTE, seen, evidence)
    return (NE, "SETTING_VALUE_UNKNOWN", "sshd -T reports a HostbasedAuthentication value that is "
            "neither yes nor no. " + SSH_SCOPE_NOTE, seen, evidence)


def ise_ssh_005(section, record, digests):
    values, gap, evidence = _sshd_settings(section, digests,
                                           ("hostbasedauthentication", "ignorerhosts"))
    if gap:
        return (NE, gap[0], gap[1] + ". " + SSH_SCOPE_NOTE, [], evidence)
    hostbased, ignore = values["hostbasedauthentication"], values["ignorerhosts"]
    seen = [{"hostbasedauthentication": hostbased, "ignorerhosts": ignore}]
    if hostbased == "no":
        return ("NOT_APPLICABLE", "HOSTBASED_OFF", "sshd -T reports HostbasedAuthentication no, so "
                "no user trust file can grant a host-based login; IgnoreRhosts %s is recorded. "
                % ignore + SSH_SCOPE_NOTE, seen, evidence)
    if hostbased != "yes":
        return (NE, "SETTING_VALUE_UNKNOWN", "sshd -T reports a HostbasedAuthentication value that "
                "is neither yes nor no. " + SSH_SCOPE_NOTE, seen, evidence)
    if ignore == "yes":
        return ("PASS", "USER_TRUST_FILES_IGNORED", "host-based authentication is on and sshd -T "
                "reports IgnoreRhosts yes: users' .rhosts and .shosts files are not used. "
                + SSH_SCOPE_NOTE, seen, evidence)
    if ignore == "no":
        return ("FAIL", "USER_TRUST_FILES_USED", "host-based authentication is on and sshd -T "
                "reports IgnoreRhosts no: users' .rhosts and .shosts files are used. "
                + SSH_SCOPE_NOTE, seen, evidence)
    if ignore == "shosts-only":
        return ("FAIL", "USER_SHOSTS_USED", "host-based authentication is on and sshd -T reports "
                "IgnoreRhosts shosts-only: users' .shosts files are used (.rhosts is ignored). "
                + SSH_SCOPE_NOTE, seen, evidence)
    return (NE, "SETTING_VALUE_UNKNOWN", "sshd -T reports an IgnoreRhosts value this criterion "
            "does not know. " + SSH_SCOPE_NOTE, seen, evidence)


# --- ISE-STORAGE-001: /dev/shm mounted nosuid (D-132) ----------------------------------

STORAGE_001 = "ISE-STORAGE-001"
ARTIFACT_MOUNTS = "sections/mounts.json"
HOST_MOUNT_TABLE = "/proc/1/mountinfo"
P_ACTIVE_STATUS = "/evidence/provenance/comparison/active_status"
P_ACTIVE_COMPLETE = "/evidence/provenance/active/universe_complete"
P_ACTIVE = "/evidence/provenance/active/records"
SHM = "/dev/shm"
STORAGE_001_POINTERS = (
    ("manifest.json", "/manifest_core/auxiliary_artifacts/sections~1mounts.json"),
    (ARTIFACT_MOUNTS, P_ACTIVE_STATUS), (ARTIFACT_MOUNTS, P_ACTIVE_COMPLETE),
    (ARTIFACT_MOUNTS, P_ACTIVE + "/<i>/mount_point"), (ARTIFACT_MOUNTS, P_ACTIVE + "/<i>/source_path"),
    (ARTIFACT_MOUNTS, P_ACTIVE + "/<i>/parse_status"), (ARTIFACT_MOUNTS, P_ACTIVE + "/<i>/fstype"),
    (ARTIFACT_MOUNTS, P_ACTIVE + "/<i>/mount_options"))
MOUNT_NOTE = ("The active mount of /dev/shm in the host's mount table (PID 1's mount namespace); "
              "other mount namespaces are not observed.")


def ise_storage_001(section, record, digests):
    if not isinstance(section, dict) or section.get("section") != "mounts" or \
            section.get("schema_version") != SECTION_SCHEMA_VERSION:
        raise MalformedEvidence("sections/mounts.json is not a mounts section of schema %d"
                                % SECTION_SCHEMA_VERSION)
    status = section.get("collection_status")
    if status not in STATUSES:
        raise MalformedEvidence("the mounts section status %r is not a SCOPE-022 status" % (status,))
    evidence = [_pointer("manifest.json", STORAGE_001_POINTERS[0][1], digests)]
    if section.get("evidence") is None:
        if status == COLLECTED:
            raise MalformedEvidence("the mounts section is COLLECTED and holds no evidence")
        return (NE, "SECTION_" + status, "the mounts section is %s and holds no evidence. "
                % status + MOUNT_NOTE, [], evidence)
    evidence += [_pointer(ARTIFACT_MOUNTS, p, digests) for p in (P_ACTIVE_STATUS, P_ACTIVE_COMPLETE)]
    active_status, complete = resolve(section, P_ACTIVE_STATUS), resolve(section, P_ACTIVE_COMPLETE)
    records = resolve(section, P_ACTIVE)
    if active_status != COLLECTED or complete is not True:
        return (NE, "ACTIVE_MOUNTS_NOT_COLLECTED", "the active mount table is %s (complete: %s). "
                % (active_status, complete) + MOUNT_NOTE, [], evidence)
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise MalformedEvidence("the active mount records are not a list of objects")
    if any(r.get("source_path") != HOST_MOUNT_TABLE for r in records):
        return (NE, "HOST_NAMESPACE_NOT_ESTABLISHED", "the active mounts were not read from the "
                "host's mount table (%s), so they may be one process's view; a Standard Audit "
                "cannot establish the host's namespace. " % HOST_MOUNT_TABLE + MOUNT_NOTE,
                [], evidence)
    hits = [(i, r) for i, r in enumerate(records) if r.get("mount_point") == SHM]
    for i, _r in hits:
        evidence += [_pointer(ARTIFACT_MOUNTS, "%s/%d/%s" % (P_ACTIVE, i, f), digests)
                     for f in ("mount_point", "source_path", "parse_status", "fstype",
                               "mount_options")]
    seen = [{"mount_point": SHM, "fstype": r.get("fstype"), "mount_options": r.get("mount_options")}
            for _i, r in hits]
    if not hits:
        return (NE, "NO_DEV_SHM_MOUNT", "the host's mount table has no mount at /dev/shm, so there "
                "are no mount options to evaluate. " + MOUNT_NOTE, [], evidence)
    if len(hits) > 1:
        return (NE, "DEV_SHM_MOUNTED_MORE_THAN_ONCE", "the host's mount table has %d mounts at "
                "/dev/shm; which one is in effect is not decided here. " % len(hits) + MOUNT_NOTE,
                seen, evidence)
    (_i, shm), = hits
    options = shm.get("mount_options")
    if shm.get("parse_status") != "OK" or not isinstance(options, list):
        return (NE, "DEV_SHM_MOUNT_NOT_PARSED", "the /dev/shm mount line could not be read. "
                + MOUNT_NOTE, seen, evidence)
    if "nosuid" in options:
        return ("PASS", "DEV_SHM_NOSUID", "/dev/shm is mounted nosuid: set-user-ID and set-group-ID "
                "bits on files there are ignored. " + MOUNT_NOTE, seen, evidence)
    return ("FAIL", "DEV_SHM_SUID_ALLOWED", "/dev/shm is mounted without nosuid: a set-user-ID file "
            "placed in this world-writable directory would run with its owner's privileges. "
            + MOUNT_NOTE, seen, evidence)


# The evaluators this engine implements, keyed by criterion_id, with the pointers each
# reads and the artifacts it needs. An admitted criterion with no entry stops the
# evaluation (EVAL-004: every admitted criterion yields exactly one result).
EVALUATORS = {
    ACCOUNT_001: (ise_account_001, ACCOUNT_001_POINTERS, (ARTIFACT_ACCOUNTS,)),
    ACCOUNT_002: (ise_account_002, ACCOUNT_002_POINTERS, (ARTIFACT_ACCOUNTS,)),
    ACCOUNT_003: (ise_account_003, ACCOUNT_003_POINTERS, (ARTIFACT_ACCOUNTS,)),
    ACCOUNT_004: (ise_account_004, ACCOUNT_004_POINTERS, (ARTIFACT_ACCOUNTS,)),
    SSH_001: (ise_ssh_001, SSH_001_POINTERS, (ARTIFACT_SSH,)),
    ACCOUNT_005: (ise_account_005, ACCOUNT_005_POINTERS, (ARTIFACT_ACCOUNTS,)),
    AUTH_001: (ise_auth_001, AUTH_001_POINTERS, (ARTIFACT_LOGIN,)),
    SSH_002: (ise_ssh_002, SSH_002_POINTERS, (ARTIFACT_SSH,)),
    PRIV_001: (ise_priv_001, PRIV_001_POINTERS, (ARTIFACT_SUDO,)),
    PRIV_002: (ise_priv_002, PRIV_002_POINTERS, (ARTIFACT_SUDO,)),
    SSH_003: (ise_ssh_003, SSH_003_POINTERS, (ARTIFACT_SSH,)),
    SSH_004: (ise_ssh_004, SSH_004_POINTERS, (ARTIFACT_SSH,)),
    SSH_005: (ise_ssh_005, SSH_005_POINTERS, (ARTIFACT_SSH,)),
    STORAGE_001: (ise_storage_001, STORAGE_001_POINTERS, (ARTIFACT_MOUNTS,)),
}
# Which record dimension states a result's scope (EVAL-004): the declared files for the
# account and login.defs criteria, the resolved configuration for sshd -T.
SCOPE_DIMENSION = {SSH_001: "resolved", SSH_002: "resolved", SSH_003: "resolved",
                   SSH_004: "resolved", SSH_005: "resolved", STORAGE_001: "active"}
