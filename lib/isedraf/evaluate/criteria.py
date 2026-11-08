# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
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
}
# Which record dimension states a result's scope (EVAL-004): the declared files for the
# account and login.defs criteria, the resolved configuration for sshd -T.
SCOPE_DIMENSION = {SSH_001: "resolved", SSH_002: "resolved"}
