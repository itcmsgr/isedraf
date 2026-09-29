# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The one result envelope every shared primitive returns.
# Implements: SCOPE-022, SCOPE-045
#
# Three result-bearing types already exist and agree on the shape without sharing it:
# _exec.Outcome (a read), inventory.model.subdomain() (a subdomain) and
# accounts.sources.ParsedSource (a parsed file). This is the fourth shape they were all
# reaching for, defined once so S1-S5 do not each grow their own.
#
# It reuses SCOPE-022 verbatim. Nothing here invents a second status vocabulary: a
# primitive that cannot express what it needs in COLLECTED / PARTIAL / NOT_TESTED / ERROR
# plus a reason is a contract gap to be reported, not a reason to add a fifth value.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""The shared evidence envelope, and the retention policy that protects secrets."""

from ..status import (COLLECTED, ERROR, NOT_TESTED, PARTIAL,   # noqa: F401
                      requires_reason)

# --- SCOPE-045, the frozen four ----------------------------------------------------------
STATE = "STATE"
OBSERVATION = "OBSERVATION"
DERIVED = "DERIVED"
PROVENANCE = "PROVENANCE"

# --- how a raw value may be retained -----------------------------------------------------
# A generic parser that always serializes the raw line is a secret leak waiting for its
# first consumer. /etc/shadow has hashes, repository URLs have credentials, sudoers has rule
# bodies, and a certificate directory has key material. Making downstream collectors scrub
# values the shared parser already emitted is the wrong order: by then the value exists in
# an object someone may serialize.
#
# So retention is declared by the CALLER, per grammar, and the parser honours it. There is
# no "raw is always available" escape hatch.
RETAIN_VALUE = "RETAIN_VALUE"        # the parsed value is not sensitive
REDACT_VALUE = "REDACT_VALUE"        # a placeholder is stored; the value is discarded
DIGEST_VALUE = "DIGEST_VALUE"        # only a digest of the value is stored
# NOT a general-purpose way to make a secret safe. A digest of a low-entropy value - a
# short password, a PIN, an enum - is recoverable offline by anyone who obtains the
# report, so hashing is not a substitute for not collecting. DIGEST_VALUE exists for
# values where comparability matters and the domain privacy contract has explicitly
# judged the digest publishable. It is never applied automatically.
NOT_RETAINED = "NOT_RETAINED"        # nothing at all is stored, not even a digest

RETENTION = (RETAIN_VALUE, REDACT_VALUE, DIGEST_VALUE, NOT_RETAINED)

# --- anomaly kinds shared by more than one primitive -------------------------------------
# Domain-specific anomalies stay in their own modules. These are the ones the shared
# primitives themselves can produce.
ANOMALY_UNREADABLE = "UNREADABLE"
ANOMALY_MISSING = "MISSING"
ANOMALY_MALFORMED = "MALFORMED"
ANOMALY_CYCLE = "CYCLE"
ANOMALY_DUPLICATE = "DUPLICATE"
ANOMALY_UNSUPPORTED = "UNSUPPORTED"
ANOMALY_LIMIT = "LIMIT_REACHED"


class Evidence(object):
    """What a shared primitive produced, and why it is not more than that.

    `status` is SCOPE-022. A status other than COLLECTED REQUIRES a reason, for the same
    argument inventory.model.subdomain() makes: an incomplete observation that does not
    explain itself tells the reader nothing.

    `records` is the payload and is always a list, in the order the source presented it.
    Nothing is sorted here. Several of the domains that will consume this - audit rules
    above all - are order-sensitive, and a shared primitive that quietly sorted its output
    would make an equivalence claim on their behalf.
    """

    __slots__ = ("status", "reason", "source", "records", "anomalies", "provenance")

    def __init__(self, status, records=None, reason=None, source=None,
                 anomalies=None, provenance=None):
        if requires_reason(status) and not reason:
            raise ValueError(
                "collection status %s requires a reason: an unexplained incomplete "
                "observation tells the reader nothing" % status)
        self.status = status
        self.reason = reason
        self.source = source
        self.records = [] if records is None else records
        self.anomalies = [] if anomalies is None else anomalies
        self.provenance = {} if provenance is None else provenance

    @property
    def complete(self):
        """True only for COLLECTED.

        Read this before asserting that something is absent. The invariant frozen in the
        account contract applies to every consumer of these primitives:

            An absence claim requires complete evidence over the source domain in which
            the absence is asserted.

        PARTIAL means the thing you did not find may be in the part you could not read.
        """
        return self.status == COLLECTED

    def as_dict(self):
        return {"status": self.status, "reason": self.reason, "source": self.source,
                "records": self.records, "anomalies": self.anomalies,
                "provenance": self.provenance}


def anomaly(kind, detail, **where):
    """One anomaly. `where` carries whatever provenance the caller has."""
    out = {"anomaly": kind, "detail": detail}
    out.update(where)
    return out


def retained(value, policy, digest_fn=None):
    """Apply a retention policy to one raw value.

    Returns (stored_value, retention_marker). The caller stores both, so a reader can
    always tell the difference between "the value was empty" and "the value was not kept".
    """
    if policy == RETAIN_VALUE:
        return value, RETAIN_VALUE
    if policy == REDACT_VALUE:
        return None, REDACT_VALUE
    if policy == DIGEST_VALUE:
        if digest_fn is None:
            import hashlib
            digest_fn = lambda v: "sha256:" + hashlib.sha256(
                v.encode("utf-8", "surrogateescape")).hexdigest()
        return (digest_fn(value) if value is not None else None), DIGEST_VALUE
    if policy == NOT_RETAINED:
        return None, NOT_RETAINED
    raise ValueError("unknown retention policy %r" % policy)


# --- SCOPE-045 for the fields the shared primitives themselves emit ----------------------
# Parser mechanics are PROVENANCE. None of this is baseline-bound STATE: a line number
# moving because a comment was added above it is not a security change, and classifying it
# as STATE would make every cosmetic edit a delta. What the DOMAIN does with a parsed value
# is the domain's classification to make, and these primitives deliberately do not make it.
CLASSIFICATION = {
    "status": PROVENANCE,
    "reason": PROVENANCE,
    "source": PROVENANCE,
    "source_path": PROVENANCE,
    "source_line": PROVENANCE,
    "source_kind": PROVENANCE,
    "ordinal": PROVENANCE,
    "expansion_ordinal": PROVENANCE,
    "parent": PROVENANCE,
    "directive": PROVENANCE,
    "retention": PROVENANCE,
    "anomalies": DERIVED,
    "duplicate_of": DERIVED,
}
