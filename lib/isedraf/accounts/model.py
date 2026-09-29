# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The vocabulary of the local account-file evidence source, and its limits.
# Implements: SCOPE-022, SCOPE-045, IDENT-013, IDENT-041, IDENT-060, NORM-035
#
# THIS IS NOT "THE USERS ON THIS MACHINE".
#
# /etc/passwd, /etc/group and /etc/shadow are three local files. A Linux system may
# resolve identities through NSS from SSSD, LDAP, Active Directory, systemd-homed or a
# container runtime, and none of those appears in these files. A model built from them
# describes the LOCAL ACCOUNT FILES and nothing wider. IDENT-041 already freezes the
# consequence: canonical identity state contains only accounts whose NSS source is
# `files`, and each entity records that source as a state field.
#
# Naming everything `local_*` is deliberate. D-114 happened because one field name
# implied more than the source supported; calling this "users" would be the same defect
# one layer up, and far more consequential, because a missing administrator is a worse
# answer than a mislabelled disk.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Status, provenance and password-state vocabulary for the local account files."""

# --- collection status (SCOPE-022, reused verbatim - not a second model) ----------------
from ..status import COLLECTED, ERROR, NOT_TESTED, PARTIAL   # noqa: F401

# --- SCOPE-045 categories (the frozen four) ---------------------------------------------
# The inventory module carries a DIFFERENT table - PLATFORM_FACT, HARDWARE_OBSERVATION and
# so on - which answers "does this change on an untouched host?" for data that is
# explicitly outside the snapshot contract (SNAP-021). It is not SCOPE-045 and must not be
# confused with it. SCOPE-045 answers a different question: what is hashed and diffed.
STATE = "STATE"                 # hashed, diffed, baseline-bound
OBSERVATION = "OBSERVATION"     # true when read, not configuration
DERIVED = "DERIVED"             # computed from other fields, never hashed as fact
PROVENANCE = "PROVENANCE"       # how we know, not what is

# --- which local file a fact came from --------------------------------------------------
# Provenance is per field, never per record. An account is not "from passwd and shadow";
# its shell is from passwd and its ageing fields are from shadow, and when shadow was
# never read the ageing fields are absent rather than defaulted. Defect A is the same
# lesson: status is decided per source, and one readable source must never satisfy
# completeness for an unreadable one.
SOURCE_PASSWD = "PASSWD"
SOURCE_GROUP = "GROUP"
SOURCE_SHADOW = "SHADOW"

# --- how a record relates to a source that may not have been read -----------------------
# Three outcomes that a single "shadow: null" would flatten into one lie.
RECORD_PRESENT = "PRESENT"
# The source was read and a matching record exists.

RECORD_ABSENT_FROM_COLLECTED_SOURCE = "ABSENT_FROM_COLLECTED_SOURCE"
# The source WAS read, successfully and completely, and contains no matching record.
# This is positive evidence of absence and a real anomaly worth reporting.

RECORD_SOURCE_NOT_COLLECTED = "SOURCE_NOT_COLLECTED"
# The source was not read - absent, refused, or unreadable. NOTHING is known about
# whether a matching record exists. This is the case that must never be rendered as
# "the account has no password" or "the account does not expire".

# --- password field: what the SYNTAX supports, and not one inch further -----------------
# The second field of /etc/shadow is the credential verifier. It is never stored, never
# normalized into canonical state, never written to a fixture, and never rendered.
#
# Two INDEPENDENT dimensions, because collapsing them is how "locked" becomes "has no
# password". A locked account may still carry a full hash underneath the `!` prefix -
# `!$6$...` is the normal result of `passwd -l` - and unlocking it restores that password.
# The frozen pitfall list already says a locked password is not an expired password;
# it is also not an absent one.
LOCK_PREFIX_PRESENT = "LOCK_PREFIX_PRESENT"     # field begins with '!'
LOCK_PREFIX_ABSENT = "LOCK_PREFIX_ABSENT"

# The remainder, after any leading '!' characters are removed:
CONTENT_EMPTY = "EMPTY"
# Zero-length. On a normally configured host this means login with no password, but that
# is an INTERPRETATION for a criterion; the parser records only that the field is empty.

CONTENT_DISABLED_TOKEN = "DISABLED_TOKEN"
# Exactly "*" - conventionally "no password will ever authenticate". Still an observation
# of a token, not a conclusion about access: SSH keys and sudo do not consult this field.

CONTENT_HASH_PRESENT = "HASH_PRESENT"
# Matches the crypt(3) shape $id$...$...  The hash ITSELF is discarded here.

# Recognized crypt(3) algorithm identifiers, mapped to a BOUNDED normalized vocabulary.
# The raw `$id$` token is never published: an unrecognized identifier is an arbitrary
# string taken from the credential field, and copying it out verbatim would be a small
# leak of exactly the material this boundary exists to contain. Anything crypt-shaped but
# unrecognized becomes OTHER_RECOGNIZED_FORMAT and nothing more.
HASH_SCHEMES = {
    "1": "MD5_CRYPT",
    "2": "BCRYPT", "2a": "BCRYPT", "2b": "BCRYPT", "2x": "BCRYPT", "2y": "BCRYPT",
    "5": "SHA256_CRYPT",
    "6": "SHA512_CRYPT",
    "7": "SCRYPT",
    "y": "YESCRYPT",
    "gy": "GOST_YESCRYPT",
    "md5": "SUN_MD5",
}
HASH_SCHEME_OTHER = "OTHER_RECOGNIZED_FORMAT"

CONTENT_OTHER = "OTHER"
# Non-empty, not "*", not crypt-shaped. Legacy DES hashes land here, and so does
# corruption. The parser does NOT guess which, because it cannot.

# --- identifier decodability (acquisition truth) ----------------------------------------
# OBSERVED IDENTIFIER BYTES MUST NEVER SILENTLY BECOME A DIFFERENT CANONICAL IDENTIFIER.
#
# /etc/passwd is bytes. Most of the world puts ASCII in it; nothing enforces that. Reading
# it with errors="replace" turned b"jos\xe9" into 'jos\ufffd', and the tool would then
# hash, baseline, diff and report a name the host does not have - and two different
# undecodable names would collapse to the same replacement character, so a delta could not
# even tell them apart. That is the D-114 failure wearing different clothes: a convenient
# representation asserted as the fact.
#
# So the name is either genuinely decodable, or it is not and we say so and keep the bytes.
NAME_UTF8 = "UTF8"
# Valid UTF-8. `name` carries it and is safe for canonical state.

NAME_UNDECODABLE = "UNDECODABLE"
# Not valid UTF-8. `name` is NULL - never a guess, never a replacement character - and
# `name_bytes_hex` carries the exact bytes, losslessly and canonically representable.

# --- anomalies the source can express, which a dictionary would silently resolve --------
# Python's dict would make duplicate usernames into last-one-wins, turning an ambiguous
# and security-relevant source into a clean-looking database. Each of these retains both
# sides so a later criterion can report the conflict rather than inherit a coin flip.
ANOMALY_DUPLICATE_NAME = "DUPLICATE_NAME"
ANOMALY_DUPLICATE_ID = "DUPLICATE_ID"
ANOMALY_MALFORMED_RECORD = "MALFORMED_RECORD"
ANOMALY_NON_NUMERIC_ID = "NON_NUMERIC_ID"
ANOMALY_FIELD_COUNT = "FIELD_COUNT"
ANOMALY_MALFORMED_DIRECTIVE = "MALFORMED_COMPAT_DIRECTIVE"

# Owner ruling IQ-036 (2026-09-27): what "+"/"-" lines mean depends on the host's NSS mode
# for that database, supplied to collect() explicitly. The parser never reads nsswitch.conf.
NSS_COMPAT = "COMPAT"                          # NSS establishes compat for the database
NSS_NOT_COMPAT = "NOT_COMPAT"                  # NSS establishes a mode that is not compat
NSS_MODE_NOT_ASSERTED = "NSS_MODE_NOT_ASSERTED"  # missing, unsupported or ambiguous
REASON_COMPAT_WITHOUT_COMPAT = "COMPAT_SYNTAX_WITHOUT_COMPAT"
REASON_NSS_MODE_NOT_ASSERTED = "NSS_MODE_NOT_ASSERTED"
REASON_COMPAT_LOCAL_AFTER_INCLUDE = "COMPAT_LOCAL_AFTER_INCLUDE"
# Owner ruling IQ-037 (2026-09-27): whether NSS consults the local file for a database is a
# separate fact from what the file holds. It never changes collection status or record
# confidence: the file contained those records either way.
FILES_ACTIVE = "ACTIVE"                 # files or compat is a configured source
FILES_INACTIVE = "INACTIVE"             # only known non-file services are configured
FILES_NOT_ASSERTED = "NOT_ASSERTED"     # unknown token, undeclared, or unreliable nsswitch
ANOMALY_AFTER_COMPAT_INCLUDE = "RESOLUTION_AFTER_COMPAT_INCLUDE"
# Red team pass 7: under compat an EXCLUDE before a local line leaves it enumerated but not
# resolvable by name (F2); in a mode that cannot be established nothing after the first
# +/- line is known either way (F4).
REASON_COMPAT_LOCAL_AFTER_EXCLUDE = "COMPAT_LOCAL_AFTER_EXCLUDE"
ANOMALY_AFTER_COMPAT_EXCLUDE = "RESOLUTION_AFTER_COMPAT_EXCLUDE"
ANOMALY_AFTER_UNINTERPRETED_COMPAT = "RESOLUTION_AFTER_UNINTERPRETED_COMPAT_SYNTAX"
# Red team pass 8, N2: glibc resolves a name from the FIRST line it accepts, which may be a
# line ISEDRAF rejected; a later record of that name is not what a lookup returns.
ANOMALY_SHADOWED_BY_EARLIER_LINE = "RESOLUTION_SHADOWED_BY_EARLIER_LINE"
COMPAT_RESOLUTION_ANOMALIES = (ANOMALY_AFTER_COMPAT_INCLUDE, ANOMALY_AFTER_COMPAT_EXCLUDE,
                               ANOMALY_AFTER_UNINTERPRETED_COMPAT,
                               ANOMALY_SHADOWED_BY_EARLIER_LINE)

# --- compat directives (W1-D §9 clarification, owner 2026-09-24) ------------------------
# A line whose name field begins with "+" or "-" is an NSS inclusion or exclusion directive
# for the NIS map under nsswitch.conf's `compat` service, not an account. nsswitch.conf(5)
# defines "+", "+NAME", "-NAME", "+@NETGROUP" and "-@NETGROUP" for passwd and shadow, and
# "+", "+NAME", "-NAME" for group. Nothing else starting with "+" or "-" is valid.
DIRECTIVE_INCLUDE = "INCLUDE"
DIRECTIVE_EXCLUDE = "EXCLUDE"
DIRECTIVE_ALL = "ALL"
DIRECTIVE_NAME = "NAME"
DIRECTIVE_NETGROUP = "NETGROUP"

# --- what this source is, stated so it survives into every consumer ---------------------
SOURCE_SCOPE = "LOCAL_ACCOUNT_FILES"
NSS_SOURCE = "files"                 # IDENT-041: recorded as a state field per entity

# --- SCOPE-045 classification of every field this source emits --------------------------
# Owner ruling, W1-D review: `gecos` is OBSERVATION, not STATE. It is free-form identity
# metadata that routinely carries a person's name, room and telephone number, and it does
# not determine authentication or privilege. Making it STATE would turn "Room 12" becoming
# "Room 14" into a security baseline delta, and would bind personal data into a hashed,
# diffed, baseline-bound surface. If a concrete control later needs GECOS integrity, it is
# promoted by an explicit decision rather than by treating all account metadata as
# security configuration.
CLASSIFICATION = {
    "name": STATE,
    "name_encoding": PROVENANCE,
    "name_bytes_hex": STATE,
    "name_non_ascii": DERIVED,
    "uid": STATE,
    "primary_gid": STATE,
    "home": STATE,
    "shell": STATE,
    "gecos": OBSERVATION,
    "nss_source": STATE,
    "shadow.password_state.lock_prefix": STATE,
    "shadow.password_state.content": STATE,
    "shadow.password_state.hash_scheme": STATE,
    "shadow.last_change_days": STATE,
    "shadow.min_days": STATE,
    "shadow.max_days": STATE,
    "shadow.warn_days": STATE,
    "shadow.inactive_days": STATE,
    "shadow.expire_days": STATE,
    "shadow.last_change_days_source": PROVENANCE,
    "shadow.min_days_source": PROVENANCE,
    "shadow.max_days_source": PROVENANCE,
    "shadow.warn_days_source": PROVENANCE,
    "shadow.inactive_days_source": PROVENANCE,
    "shadow.expire_days_source": PROVENANCE,
    "shadow.shadow_line": PROVENANCE,
    "shadow_record": PROVENANCE,
    "passwd_line": PROVENANCE,
    "passwd_anomalies": DERIVED,
    # Malformed records only: the shape of text that is never kept (re-check R4).
    "name_length": OBSERVATION,
    "group.name": STATE,
    "group.name_encoding": PROVENANCE,
    "group.name_bytes_hex": STATE,
    "group.name_non_ascii": DERIVED,
    "group.gid": STATE,
    "group.explicit_members": STATE,
    "group.nss_source": STATE,
    "group.group_line": PROVENANCE,
    "group.group_anomalies": DERIVED,
    "group.name_length": OBSERVATION,
    # IQ-036: the NSS context a run was given, and "+"/"-" lines left uninterpreted
    # because that context did not establish compat. Shape only, never text.
    "nss_compat_context": PROVENANCE,
    "uninterpreted_compat_syntax": OBSERVATION,
    # IQ-037: effective NSS applicability of each local file, never collection truth.
    "nss_file_effectiveness": PROVENANCE,
    "group.member_count": OBSERVATION,
    # compat directives. None is STATE: a directive says where identity MAY come from,
    # which is scope evidence, never an identity. The password field of a directive line
    # passes through _password_state like any other (W1-D §7 outranks "verbatim").
    "directive.line": PROVENANCE,
    "directive.kind": OBSERVATION,
    "directive.target": OBSERVATION,
    "directive.name": OBSERVATION,
    "directive.field_count": OBSERVATION,
    "directive.override_fields": OBSERVATION,
    "directive.override_shape": OBSERVATION,
    "directive.ageing_values": OBSERVATION,
    "directive.name_bytes_hex": OBSERVATION,
    "directive.name_length": OBSERVATION,
    # Owner ruling F6: directive order is collection/method identity, never STATE.
    "compat_directive_topology": PROVENANCE,
    "compat_directive_topology_digest": PROVENANCE,
    "directive.password_field_state": OBSERVATION,
    "directive.malformed": DERIVED,
    "directive.anomalies": DERIVED,
}

# --- what is NOT collected, stated so no consumer overclaims ----------------------------
# Owner ruling: /etc/gshadow is out of scope for this contract. Group administrators and
# group passwords live there, so this source cannot describe complete group administration
# state and must never be presented as doing so. A later privilege or group-administration
# requirement can justify adding it; nothing speculative is collected now.
NOT_COLLECTED = ("etc/gshadow",)
GROUP_LIMITATION = (
    "Group membership here is the explicit supplementary list from /etc/group plus the "
    "primary GID relationship from /etc/passwd, kept separate. /etc/gshadow is not read, "
    "so group administrators and group passwords are not observed and complete group "
    "administration state is not claimed.")

LIMITATION = (
    "Describes the local account files only. A host may resolve additional identities "
    "through NSS from SSSD, LDAP, Active Directory, systemd-homed or a container "
    "runtime; none of those appears in these files and none is claimed here. This is "
    "not a complete list of the identities that can authenticate to this host.")
