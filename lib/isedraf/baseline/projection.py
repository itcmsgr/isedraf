# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The STATE projection of a committed section, its state hash and method fingerprint.
# Implements: SCOPE-045, SCOPE-046, SCOPE-047, CMP-020, CMP-021, DELTA-006, DELTA-010, NORM-038
#
# D-127 freezes this definition (projection_version 1). It reads a committed, verified
# section object and returns data; it performs no I/O and changes no snapshot. Only fields
# a domain's CLASSIFICATION table names STATE take part. A field the table does not name
# makes the section NOT comparable - there is no implicit default (SCOPE-045), and an
# unknown field is never silently dropped.
#
# Order is kept and nothing is deduplicated: declared sshd records and duplicate passwd
# names are first-wins, so the order a collector recorded can be security-relevant, and the
# shared Evidence contract already keeps source order (shared/result.py). A pure reorder is
# therefore reported, never hidden.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""D-127: section STATE projection (version 1), state hash and method fingerprint."""
import hashlib

from .. import canonical
from ..accounts import model as accounts_model
from ..loginpolicy import model as loginpolicy_model
from ..ssh import model as ssh_model

PROJECTION_VERSION = 1
STATE = "STATE"

# Per section: the classification table and the entity lists, as (list key under
# `evidence`, table prefix). Every other key of `evidence` is outside the projection and is
# named in OUTSIDE, so a key the engine does not know is refused rather than ignored.
SECTIONS = {
    "accounts": {
        "table": accounts_model.CLASSIFICATION,
        "lists": (("local_accounts", ""), ("local_groups", "group.")),
        "outside": ("scope", "limitation", "sources", "coverage", "collection_status",
                    "reason", "orphan_shadow_records", "orphan_group_members",
                    "orphan_primary_gids", "absence_claims_supported", "group_limitation",
                    "not_collected", "anomalies", "compat_directives",
                    "nss_compat_context", "nss_file_effectiveness",
                    "uninterpreted_compat_syntax", "remote_identity_inclusion",
                    "compat_directive_topology", "compat_directive_topology_digest"),
    },
    "ssh": {
        "table": ssh_model.CLASSIFICATION,
        "lists": (("records", ""),),
        "outside": ("status", "reason", "source", "anomalies", "provenance"),
    },
    "loginpolicy": {
        "table": loginpolicy_model.CLASSIFICATION,
        "lists": (("records", ""),),
        "outside": ("status", "reason", "source", "anomalies", "provenance"),
    },
}

# Reason tokens (D-127).
UNCLASSIFIED_FIELD = "UNCLASSIFIED_FIELD"
UNKNOWN_SECTION_FIELD = "UNKNOWN_SECTION_FIELD"
MALFORMED_SECTION = "MALFORMED_SECTION"
UNSUPPORTED_SECTION = "UNSUPPORTED_SECTION"


class NotProjectable(Exception):
    """The section's STATE cannot be stated; it is NOT comparable. args = (token, detail)."""

    def __init__(self, token, detail):
        Exception.__init__(self, token, detail)
        self.token = token
        self.detail = detail

    def __str__(self):
        return "%s: %s" % (self.token, self.detail)


def _containers(table):
    """Names that are not fields themselves but prefix fields (`shadow`, `shadow.password_state`)."""
    out = set()
    for name in table:
        parts = name.split(".")
        for i in range(1, len(parts)):
            out.add(".".join(parts[:i]))
    return out


def _entity(section, obj, prefix, table, containers, where):
    if not isinstance(obj, dict):
        raise NotProjectable(MALFORMED_SECTION, "%s: %s is not an object" % (section, where))
    out = {}
    for key in sorted(obj):
        if not isinstance(key, str):
            raise NotProjectable(MALFORMED_SECTION, "%s: %s has a non-string key"
                                 % (section, where))
        name = prefix + key
        value = obj[key]
        if name in table:
            if table[name] == STATE:
                out[name] = value               # verbatim; arrays keep recorded order
            continue
        if name in containers:
            if value is None:
                out[name] = None                # present-and-null is kept, never dropped
            elif isinstance(value, dict):
                out.update(_entity(section, value, name + ".", table, containers,
                                   "%s.%s" % (where, key)))
            else:
                raise NotProjectable(MALFORMED_SECTION, "%s: %s.%s is neither an object "
                                     "nor null" % (section, where, key))
            continue
        raise NotProjectable(UNCLASSIFIED_FIELD, "%s: field %r has no classification"
                             % (section, name))
    return out


def project(name, section):
    """The canonical STATE object of one committed section. Raises NotProjectable."""
    spec = SECTIONS.get(name)
    if spec is None:
        raise NotProjectable(UNSUPPORTED_SECTION, "%s has no projection" % name)
    evidence = section.get("evidence") if isinstance(section, dict) else None
    if not isinstance(evidence, dict):
        raise NotProjectable(MALFORMED_SECTION, "%s: evidence is not an object" % name)
    known = set(k for k, _ in spec["lists"]) | set(spec["outside"])
    for key in sorted(evidence):
        if key not in known:
            raise NotProjectable(UNKNOWN_SECTION_FIELD, "%s: evidence key %r is not known "
                                 "to this engine" % (name, key))
    table = spec["table"]
    containers = _containers(table)
    lists = {}
    for key, prefix in spec["lists"]:
        items = evidence.get(key)
        if not isinstance(items, list):
            raise NotProjectable(MALFORMED_SECTION, "%s: evidence.%s is not a list"
                                 % (name, key))
        lists[key] = [_entity(name, item, prefix, table, containers, "%s[%d]" % (key, i))
                      for i, item in enumerate(items)]
    return {"projection_version": PROJECTION_VERSION, "section": name, "lists": lists}


def projection_bytes(name, section):
    return canonical.canonical_bytes(project(name, section))


def state_hash(name, section):
    """HASH_FRAME_V1("ISEDRAF:STATE:V1", canonical_bytes(section STATE object))."""
    return canonical.rendered(canonical.hash_frame(canonical.DOMAIN_STATE,
                                                   projection_bytes(name, section)))


def method_fingerprint(name, section):
    """D-127 (D4, provisional): what this engine can say about how the section was made.

    The recorded collector identity and versions, the section schema version, the
    projection version, and the classification table OF THIS ENGINE. A mismatch is a
    comparability fact. A match does not prove the method identical: source_id and
    classification_table_version are not recorded on audit sections.
    """
    spec = SECTIONS.get(name)
    if spec is None:
        raise NotProjectable(UNSUPPORTED_SECTION, "%s has no projection" % name)
    try:
        method = section["method"]
        obj = {"projection_version": PROJECTION_VERSION, "section": name,
               "schema_version": section["schema_version"],
               "collector_id": method["collector_id"],
               "collector_version": method["collector_version"],
               "parser_version": method["parser_version"],
               "classification": dict(spec["table"])}
        data = canonical.canonical_bytes(obj)
    except (KeyError, TypeError, canonical.CanonicalError):
        raise NotProjectable(MALFORMED_SECTION, "%s: the section method is not readable"
                             % name)
    return "sha256:" + hashlib.sha256(data).hexdigest()


HOST_IDENTITY_METHOD = ("collector_id", "collector_version", "parser_version", "source_id",
                        "classification_table_version")


def host_identity_fingerprint(manifest_section):
    """CMP-020's five elements, as host_identity records them in manifest_core."""
    try:
        obj = dict((k, manifest_section[k]) for k in HOST_IDENTITY_METHOD)
        obj["section"] = "host_identity"
        data = canonical.canonical_bytes(obj)
    except (KeyError, TypeError, canonical.CanonicalError):
        raise NotProjectable(MALFORMED_SECTION, "host_identity: the method is not readable")
    return "sha256:" + hashlib.sha256(data).hexdigest()
