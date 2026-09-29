# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The vocabulary of authorized-key SOURCE evidence, and the line it must not cross.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045
#
# THIS IS NOT "WHO CAN LOG IN TO THIS HOST".
#
# An authorized_keys file is a source of candidate public keys. Whether sshd consults it
# depends on the build's compiled defaults, on Match blocks evaluated against a connection
# that has not happened, on PubkeyAuthentication, on the file's ownership and mode, on
# AuthorizedKeysCommand, on revocation, and on whether anyone holds the private key. None
# of that is observable from the file, and none of it is claimed here.
#
# The vocabulary below exists to keep three things apart that a single list of paths would
# flatten into one false statement:
#
#   what was DECLARED          an AuthorizedKeysFile value, in some scope
#   what was OBSERVED          a file that was actually read
#   what is KNOWN to be all    almost never, and it says so
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Source-universe, candidate, parse and retention vocabulary for authorized keys."""

from ..shared.result import (DIGEST_VALUE, NOT_RETAINED,      # noqa: F401
                             REDACT_VALUE, RETAIN_VALUE)
from ..status import COLLECTED, ERROR, NOT_TESTED, PARTIAL    # noqa: F401

# --- SCOPE-045, the frozen four -------------------------------------------------------
STATE = "STATE"
OBSERVATION = "OBSERVATION"
DERIVED = "DERIVED"
PROVENANCE = "PROVENANCE"

# --- THREE AXES, not one state ---------------------------------------------------------
# The adversarial pass read the contract as putting DECLARED_CANDIDATE_SOURCE and
# OBSERVED_FILE on one axis, which is what the contract's prose implied and which is a
# real loss of information: a Match-scoped candidate that WAS read would then have to be
# either unresolved or observed, and it is both. The contract now names the axes.
#
#   kind         what the record IS           - constant for a candidate
#   resolution   how far the DECLARATION went - global / match / token / home / none
#   observation  what happened when we LOOKED - read / absent / unreadable / no match
#
# A candidate that was read is `observation == FILE_READ`; its `kind` does not change,
# because it is still a candidate. Nothing in this lane turns a candidate into a source
# sshd would use, and a field that changed identity on a successful read would imply it.
DECLARED_CANDIDATE_SOURCE = "DECLARED_CANDIDATE_SOURCE"
OBSERVED_FILE = "OBSERVED_FILE"
# Retained as the name of the OBSERVATION that a candidate was read. See FILE_READ, which
# is its value on the observation axis.

SOURCE_SCOPE = "LOCAL_ACCOUNT_FILES"
# What the ACCOUNTS lane calls itself. Named rather than inlined so that a second
# spelling of the same claim cannot drift in beside the first; a test asserts it equals
# isedraf.accounts.model.SOURCE_SCOPE rather than importing it, because a reference into
# another domain at runtime would be coupling this lane does not need.

# --- FOUR axes, because the owner ruling says four ------------------------------------
# IQ-014. The first version put "the path derived" and "the declaration applies" on ONE
# axis, so RESOLVED_FROM_GLOBAL meant both "we built the path" and "nothing conditions
# it". That is the same collapse IQ-016 fixed one layer up, and it made a Match-scoped
# candidate that was successfully read impossible to describe.
#
#   scope         GLOBAL | MATCH                  where the declaration sits
#   resolution    could the PATH be built?
#   applicability does the declaration APPLY?
#   observation   what happened when we LOOKED
#
# and, per account, two more that must never be collapsed into each other:
#
#   source_universe            is the set of DECLARED CANDIDATES known to be all of them?
#   effective_source_universe  which of them sshd would actually consult - NOT_EVALUATED

# --- could the candidate path be built? -----------------------------------------------
PATH_DERIVED = "PATH_DERIVED"
# The declaration expanded into a path under the collection root. It says nothing about
# whether the declaration applies to anything; that is the applicability axis.

UNEXPANDED_TOKEN = "UNEXPANDED_TOKEN"
# The value carries a % token this lane does not expand. Guessing it invents a path.

HOME_NOT_AVAILABLE = "HOME_NOT_AVAILABLE"
# The value is relative, or uses %h, and the account evidence carries no usable home.

DECLARED_NONE = "DECLARED_NONE"
# `AuthorizedKeysFile none`. A statement that no file is consulted - which is neither a
# path, nor the absence of a declaration, nor an empty universe that was observed.

RESOLUTIONS = (PATH_DERIVED, UNEXPANDED_TOKEN, HOME_NOT_AVAILABLE, DECLARED_NONE)

# --- does the declaration apply? ------------------------------------------------------
UNCONDITIONAL = "UNCONDITIONAL"
# Global scope. Nothing in the declared configuration conditions it. Still not a claim
# that sshd consults the file: PubkeyAuthentication, AuthorizedKeysCommand, file
# ownership and revocation are all unobserved, and the limitation says so.

UNRESOLVED_MATCH_SCOPED = "UNRESOLVED_MATCH_SCOPED"
# The declaration sits inside a Match block whose criteria need a connection context this
# collection does not have. The criteria are recorded and NOT evaluated.
#
# OWNER RULING, IQ-014: such a candidate IS read when its path can be built
# deterministically from declared SSH evidence and frozen account evidence. Discarding a
# safely observable host fact because a later layer cannot yet decide whether a
# connection activates it would break COLLECT ONCE / NORMALIZE ONCE / INTERPRET LATER.
# What acquisition proves is that the file and its keys were observed - never that sshd
# would consult them.

APPLICABILITIES = (UNCONDITIONAL, UNRESOLVED_MATCH_SCOPED)

# --- whether the set of candidates is known to be all of them -------------------------
UNIVERSE_COMPLETE = "COMPLETE"
UNIVERSE_INCOMPLETE = "UNRESOLVED_SOURCE_UNIVERSE"

NO_DECLARATION_OBSERVED = "NO_DECLARATION_OBSERVED"
# The strongest trap in this lane, and the reason it has its own constant.
#
# OpenSSH has a compiled-in default for AuthorizedKeysFile. That default is a property of
# a BUILD - a distribution may patch it - and this lane has no evidence of which build the
# host under test runs. Producing the conventional path from an absence would be
# manufacturing a declaration that was never observed and then reporting the file it
# happens to find as configured policy. The universe is incomplete and says why.

MATCH_SCOPED_DECLARATION = "MATCH_SCOPED_DECLARATION"
TOKEN_NOT_EXPANDED = "TOKEN_NOT_EXPANDED"
HOME_UNKNOWN = "HOME_UNKNOWN"
GLOB_NOT_ENUMERABLE = "GLOB_NOT_ENUMERABLE"
CANDIDATE_NOT_OBSERVED = "CANDIDATE_NOT_OBSERVED"
ACCOUNT_EVIDENCE_INCOMPLETE = "ACCOUNT_EVIDENCE_INCOMPLETE"
SSH_EVIDENCE_INCOMPLETE = "SSH_EVIDENCE_INCOMPLETE"

EFFECTIVE_NOT_EVALUATED = "NOT_EVALUATED"
# The effective authorized-key source universe: which declarations sshd would actually
# consult for a given authentication. R1.5 does not evaluate it and does not estimate it.
#
# This is a SEPARATE axis from source_universe, and the separation is the point of the
# IQ-014 ruling. Every declared candidate may have been read perfectly - candidate
# universe COMPLETE - while the effective universe remains unknown, because a Match
# condition is unresolved. Collapsing the two would let "we read every file we could
# name" be reported as "we know every file sshd uses", which is the single most
# attractive false claim available to this lane.

EFFECTIVE_REASON_MATCH_UNRESOLVED = "MATCH_APPLICABILITY_UNRESOLVED"
EFFECTIVE_REASON_NOT_IN_SCOPE = "EFFECTIVE_SOURCE_EVALUATION_NOT_IN_R15"

INCOMPLETE_REASONS = (NO_DECLARATION_OBSERVED, MATCH_SCOPED_DECLARATION,
                      TOKEN_NOT_EXPANDED, HOME_UNKNOWN, GLOB_NOT_ENUMERABLE,
                      CANDIDATE_NOT_OBSERVED, ACCOUNT_EVIDENCE_INCOMPLETE,
                      SSH_EVIDENCE_INCOMPLETE)

# --- how a candidate's observation went -----------------------------------------------
FILE_READ = "FILE_READ"
FILE_ABSENT = "FILE_ABSENT"
FILE_UNREADABLE = "FILE_UNREADABLE"
FILE_NOT_REGULAR = "FILE_NOT_REGULAR"
GLOB_NO_MATCH = "NO_MATCH"
# A pattern that matched nothing. NOT the same observation as a named file being absent:
# the administrator wrote a pattern, and nothing was there to match it.

FILE_OUTSIDE_COLLECTION_ROOT = "FILE_OUTSIDE_COLLECTION_ROOT"
# The path is lexically inside the root and the OBJECT it names is not, because some
# component of it is a symlink pointing out. hostpath is lexical and cannot see this;
# only resolution can. Recorded as an observation rather than an absence, because the
# file may well exist - it is simply not part of the tree this collection was given.

# --- per line -------------------------------------------------------------------------
PARSE_OK = "OK"
PARSE_MALFORMED_BASE64 = "MALFORMED_BASE64"
PARSE_NO_KEY_MATERIAL = "NO_KEY_MATERIAL"
PARSE_MALFORMED_OPTIONS = "MALFORMED_OPTIONS"
PARSE_UNDECODABLE = "UNDECODABLE_LINE"

# Three states the first draft folded into OK or into MALFORMED_BASE64, each of them a
# distinct and security-relevant observation. The adversarial pass named all three.
PARSE_NOT_A_KEY_BLOB = "NOT_A_KEY_BLOB"
# The material is valid base64 and decodes to something that is not a key: no length
# prefix, or no algorithm string where the wire format puts one.

PARSE_KEY_TYPE_MISMATCH = "KEY_TYPE_MISMATCH"
# The text says one algorithm and the blob says another. `ssh-rsa <ed25519 blob>` is not
# an OK line: a lane reporting it as OK reports an RSA key the host does not have and
# that sshd would reject. Both spellings are kept; neither is corrected.

PARSE_OPTIONS_ONLY = "OPTIONS_ONLY"
# A line carrying options and no key at all.

# The contract's first draft printed UNKNOWN_KEY_TYPE. This lane never reports a key type
# as unknown, because it maintains no list of key types to be unknown against - the blob
# names its own algorithm. What the contract meant by it is PARSE_KEY_TYPE_MISMATCH, and
# the contract now says so. One spelling per concept: an alias would be the same drift
# this project refuses everywhere else.

PARSE_STATUSES = (PARSE_OK, PARSE_MALFORMED_BASE64, PARSE_NO_KEY_MATERIAL,
                  PARSE_MALFORMED_OPTIONS, PARSE_UNDECODABLE, PARSE_NOT_A_KEY_BLOB,
                  PARSE_KEY_TYPE_MISMATCH, PARSE_OPTIONS_ONLY)

BLOB_TYPE_MATCHES = "BLOB_TYPE_MATCHES"
BLOB_TYPE_MISMATCH = "BLOB_TYPE_MISMATCH"
# The wire format names its own algorithm in the first string of the blob. When the text
# says one thing and the blob says another, both are recorded and neither is corrected.
BLOB_TYPE_UNREADABLE = "BLOB_TYPE_UNREADABLE"

DIGEST_SHA256 = "SHA256"
# OpenSSH's own fingerprint basis: SHA-256 over the base64-decoded blob, re-encoded
# base64 without padding. Verified against `ssh-keygen -lf` rather than asserted.

# --- privacy --------------------------------------------------------------------------
# Public keys are not secret. What surrounds them frequently is.
#
# The OPTION NAME is always kept: `command`, `from`, `no-pty`, `restrict` and
# `cert-authority` are the behavioural facts a later criterion needs, and a name carries
# no operator data. The VALUE is a different object. `command="..."` is a command line,
# `from="..."` is network topology, `environment="..."` is environment content. None of
# those is needed to know that a key is command-forced or address-restricted, and all of
# them are exactly what should not leak into an evidence file because a public key is
# non-secret.
#
# A value-bearing option that is NOT in this table defaults to NOT_RETAINED. An unknown
# option is the one most likely to be carrying something unexpected.
OPTION_VALUE_POLICY = {
    "command": NOT_RETAINED,
    "environment": NOT_RETAINED,
    "from": NOT_RETAINED,
    "permitopen": NOT_RETAINED,
    "permitlisten": NOT_RETAINED,
    "tunnel": NOT_RETAINED,
    "principals": NOT_RETAINED,
    "expiry-time": RETAIN_VALUE,
    # A timestamp. It states when the entry stops applying and carries nothing about a
    # person, a command or a network - the one value in this grammar that is pure policy.
}
DEFAULT_OPTION_VALUE_POLICY = NOT_RETAINED

COMMENT_POLICY = NOT_RETAINED
# Comments carry names, email addresses, hostnames and ticket references, by convention
# rather than by accident: ssh-keygen puts user@host there by default.

# --- what this lane may never say -----------------------------------------------------
# Kept as data so the test suite can assert against the list rather than a memory of it.
PROHIBITED_CLAIMS = (
    "TRUSTED", "UNTRUSTED", "SECURE", "INSECURE", "WEAK", "STRONG", "EXPOSED",
    "GRANTS_LOGIN", "CAN_LOGIN", "EFFECTIVE_SOURCE", "AUTHORIZED", "OWNER_IDENTITY",
)

SCOPE = "DECLARED_AUTHORIZED_KEY_SOURCES"

LIMITATION = (
    "Candidate authorized-key sources derived from declared sshd configuration and "
    "observed on disk. Whether sshd would consult any of these files is not determined: "
    "Match blocks are recorded and not evaluated, compiled-in defaults are not known to "
    "this collection, AuthorizedKeysCommand is not consulted, and key revocation, file "
    "ownership requirements and PubkeyAuthentication are not assessed. A key recorded "
    "here is a key present in a file, not a key that grants access."
)

NOT_COLLECTED = (
    "AuthorizedKeysCommand output",
    "sshd -T resolved configuration",
    "compiled-in AuthorizedKeysFile default",
    "RevokedKeys",
    "certificate validity",
)
