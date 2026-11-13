# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The baseline revision artifact: build, integrity verification, comparison.
# Implements: D-128, BASE-001, BASE-003, BASE-005, BASE-007, BASE-008, BASE-009, BASE-020,
#             BASE-021, BASE-022, BASE-024, BASE-026, SCOPE-074, CMP-021, CMP-030, CMP-031,
#             DELTA-001, DELTA-002, DELTA-003, DELTA-006, DELTA-010
#
# BL-000001 = HASH_FRAME_V1("ISEDRAF:BASELINE:V1", manifest_hash, profile_hash) binds the
# approved snapshot and the profile, and nothing else (SCOPE-074, unchanged). Every other
# field of the revision artifact is bound by the ledger record's artifact_digest AND
# re-derived from its verified source before any comparison (D-127, BASE-008): an artifact
# whose bytes or fields disagree with what the verified evidence gives is an integrity
# failure (exit 5), never re-read silently and never repaired.
#
# Nothing here writes or reads the host. Reading the store goes through the caller's
# verified-snapshot loader; writing is baseline/approve.py's job alone.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""BASE-007/008: the baseline revision, its verification, and the comparison."""
import hashlib
import json
import os

from .. import canonical, ledger, stateroot
from ..status import COLLECTED
from . import profile as profile_mod
from . import projection

SCHEMA_VERSION = 1
REVISION_ID = "BL-000001"                       # slice 1: the initial revision only
BASELINES_DIR = "baselines"
CURRENT_NAME = "current"
# D-127 / D1: DEV (slice 1); D-128: SYSTEM_PRODUCTION through the Full Audit route (slice 2).
# USER_PRODUCTION is never a baseline class (BASE-003, OD-16).
ADMITTED_CLASSES = (stateroot.DEV, stateroot.SYSTEM_PRODUCTION)
HOST_IDENTITY = "host_identity"

# Approval refusals (exit 65), D-127.
BASELINE_CLASS_NOT_ADMITTED = "BASELINE_CLASS_NOT_ADMITTED"
BASELINE_ALREADY_APPROVED = "BASELINE_ALREADY_APPROVED"
UNLEDGERED_REVISION_PRESENT = "UNLEDGERED_REVISION_PRESENT"
INCOMPLETE_FOR_BASELINE = "INCOMPLETE_FOR_BASELINE"
NOT_COMPARABLE_FOR_BASELINE = "NOT_COMPARABLE_FOR_BASELINE"

# Integrity failures (exit 5), D-127 / BASE-008.
BASELINE_POINTER_MISSING = "BASELINE_POINTER_MISSING"
BASELINE_POINTER_MISMATCH = "BASELINE_POINTER_MISMATCH"
BASELINE_ARTIFACT_INVALID = "BASELINE_ARTIFACT_INVALID"
BASELINE_SOURCE_INVALID = "BASELINE_SOURCE_INVALID"
BASELINE_LEDGER_INVALID = "BASELINE_LEDGER_INVALID"

# Comparison vocabulary (DELTA-001, DELTA-002, CMP-030, OUT-001 names).
MODIFIED = "MODIFIED"
NOT_COMPARABLE = "NOT_COMPARABLE"
UNCHANGED = "UNCHANGED"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
APPLICABLE = "APPLICABLE"
BASELINE_NOT_APPLICABLE = "BASELINE_NOT_APPLICABLE"
NOT_ESTABLISHED = "NOT_ESTABLISHED"


class ApprovalRefused(Exception):
    """Approval refused; nothing was written (exit 65). args = (token, detail)."""

    def __init__(self, token, detail):
        Exception.__init__(self, token, detail)
        self.token, self.detail = token, detail

    def __str__(self):
        return "%s: %s" % (self.token, self.detail)


class IntegrityFailure(Exception):
    """The baseline cannot be trusted; nothing was written (exit 5)."""

    def __init__(self, token, detail):
        Exception.__init__(self, token, detail)
        self.token, self.detail = token, detail

    def __str__(self):
        return "%s: %s" % (self.token, self.detail)


def digest(data):
    """Plain SHA-256 of exact bytes, rendered. Not a framed hash: no new domain."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _raw(rendered_hash):
    if not (isinstance(rendered_hash, str) and rendered_hash.startswith("sha256:")
            and len(rendered_hash) == 71):
        raise ValueError("not a rendered sha256 digest: %r" % (rendered_hash,))
    return bytes.fromhex(rendered_hash[7:])


def revision_hash(manifest_hash, profile_hash):
    """SCOPE-074: HASH_FRAME_V1("ISEDRAF:BASELINE:V1", manifest_hash, profile_hash), raw."""
    return canonical.rendered(canonical.hash_frame(
        canonical.DOMAIN_BASELINE, _raw(manifest_hash), _raw(profile_hash)))


def baselines_dir(root):
    return os.path.join(root, BASELINES_DIR)


def revision_path(root):
    return os.path.join(baselines_dir(root), REVISION_ID + ".json")


def current_path(root):
    return os.path.join(baselines_dir(root), CURRENT_NAME)


# --- one section's baseline-relevant facts --------------------------------------------------

def _section_object(data, name):
    raw = data.get("sections/%s.json" % name)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        return None


def section_facts(name, core, data):
    """(status, reason, fingerprint, state_hash or None, projection_error or None).

    Computed by THIS engine from one verified snapshot. host_identity keeps its frozen
    state_hash (IDENT-002); an audit section is projected (projection.py).
    """
    if name == HOST_IDENTITY:
        sect = (core.get("sections") or {}).get(HOST_IDENTITY) or {}
        status = sect.get("collection_status")
        try:
            fingerprint = projection.host_identity_fingerprint(sect)
        except projection.NotProjectable as exc:
            return status, sect.get("reason"), None, None, exc
        return (status, sect.get("reason"), fingerprint,
                sect.get("state_hash") if status == COLLECTED else None, None)
    sect = _section_object(data, name)
    if sect is None:
        return None, "the snapshot has no %s section" % name, None, None, None
    status, reason = sect.get("collection_status"), sect.get("reason")
    try:
        fingerprint = projection.method_fingerprint(name, sect)
    except projection.NotProjectable as exc:
        return status, reason, None, None, exc
    if status != COLLECTED:
        return status, reason, fingerprint, None, None
    try:
        return status, reason, fingerprint, projection.state_hash(name, sect), None
    except projection.NotProjectable as exc:
        return status, reason, fingerprint, None, exc


# --- the revision artifact -------------------------------------------------------------------

def check_class(snapshot_id, core, store_class):
    """D1: the class is decided first; a non-admitted class is refused whatever else holds."""
    if store_class not in ADMITTED_CLASSES or core.get("state_root") != store_class:
        raise ApprovalRefused(BASELINE_CLASS_NOT_ADMITTED, (
            "%s is a %s snapshot; only a DEV snapshot (BASE-009) or a Full Audit "
            "snapshot of the system store (`sudo isedraf baseline approve`) can become a "
            "baseline (BASE-003)." % (snapshot_id, core.get("state_root"))))


def build(snapshot_id, manifest_hash, core, data, store_class, the_profile=None):
    """The revision object for approving this verified snapshot. Raises ApprovalRefused.

    Class first (D1): a snapshot of a non-admitted class is refused for its class whatever
    its completeness. Then completeness: every REQUIRED section COLLECTED (BASE-021/026),
    each blocking section named with its status and its own reason; never narrowed.
    """
    check_class(snapshot_id, core, store_class)
    the_profile = the_profile or profile_mod.default()
    blocking, unprojectable, sections = [], [], {}
    for name in the_profile["required_sections"]:
        status, reason, fingerprint, state, error = section_facts(name, core, data)
        if status != COLLECTED:
            blocking.append("%s is %s: %s" % (name, status or "MISSING",
                                              reason or "no reason recorded"))
            continue
        if error is not None or state is None or fingerprint is None:
            unprojectable.append("%s: %s" % (name, error or "no state hash"))
            continue
        sections[name] = {"collection_status": status, "state_hash": state,
                          "method_fingerprint": fingerprint,
                          "projection_version": (None if name == HOST_IDENTITY
                                                 else projection.PROJECTION_VERSION)}
    if blocking:
        raise ApprovalRefused(INCOMPLETE_FOR_BASELINE, (
            "profile %s requires %s; not COLLECTED in %s:\n  %s"
            % (the_profile["profile_id"], ", ".join(the_profile["required_sections"]),
               snapshot_id, "\n  ".join(blocking))))
    if unprojectable:
        raise ApprovalRefused(NOT_COMPARABLE_FOR_BASELINE, (
            "the state of a required section cannot be stated in %s:\n  %s"
            % (snapshot_id, "\n  ".join(unprojectable))))
    return _assemble(snapshot_id, manifest_hash, core, store_class, the_profile, sections)


def _assemble(snapshot_id, manifest_hash, core, store_class, the_profile, sections):
    p_hash = profile_mod.profile_hash(the_profile)
    return {
        "schema_version": SCHEMA_VERSION,
        "revision_id": REVISION_ID,
        "revision_hash": revision_hash(manifest_hash, p_hash),
        "previous_revision_hash": None,
        "baseline_class": store_class,
        "state_root": store_class,
        "snapshot_id": snapshot_id,
        "manifest_hash": manifest_hash,
        "host_id": core.get("host_id"),
        "profile": {"object": the_profile, "profile_hash": p_hash},
        "required_sections": list(the_profile["required_sections"]),
        "tracked_sections": list(the_profile["tracked_sections"]),
        "sections": sections,
    }


def artifact_bytes(obj):
    return canonical.canonical_bytes(obj)


def current_bytes(obj, artifact_digest):
    return canonical.canonical_bytes({"revision_id": obj["revision_id"],
                                      "revision_hash": obj["revision_hash"],
                                      "artifact_digest": artifact_digest})


# --- reading the store's baseline state ------------------------------------------------------

def _read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def store_state(root):
    """What exists: (records, artifact bytes or None, current bytes or None)."""
    return (ledger.baseline_records(root), _read(revision_path(root)),
            _read(current_path(root)))


# --- BASE-008: verify before any comparison ----------------------------------------------------

def verify(root, store_class, load_snapshot, require_pointer=True):
    """The verified revision in force, or None when there is none. Raises IntegrityFailure.

    `load_snapshot(snapshot_id)` returns (core, manifest_hash, data) of a ledgered snapshot
    that verifies, or raises; any exception it raises is an integrity failure here, because
    a baseline whose approved evidence is gone or altered cannot be compared against.

    Returns (revision, info) where info = {"artifact_digest", "method_changed": {section:
    bool}, "unledgered_revision": None}. With no baseline_approved record: None, or
    (None, {"unledgered_revision": REVISION_ID}) when an unledgered artifact is present.
    """
    records, raw, current = store_state(root)
    if not records:
        if current is not None:
            raise IntegrityFailure(BASELINE_LEDGER_INVALID, (
                "baselines/current exists but the ledger records no approved baseline"))
        if raw is not None:
            return None, {"unledgered_revision": REVISION_ID}
        return None, None
    if len(records) != 1:
        raise IntegrityFailure(BASELINE_LEDGER_INVALID, (
            "the ledger records %d baseline approvals; this version writes exactly one"
            % len(records)))
    record = records[0]
    if raw is None:
        raise IntegrityFailure(BASELINE_ARTIFACT_INVALID, (
            "the ledger records %s but baselines/%s.json is missing"
            % (record.get("baseline_revision"), REVISION_ID)))
    if digest(raw) != record.get("artifact_digest"):
        raise IntegrityFailure(BASELINE_ARTIFACT_INVALID, (
            "baselines/%s.json does not match the digest its ledger record binds"
            % REVISION_ID))
    try:
        obj = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise IntegrityFailure(BASELINE_ARTIFACT_INVALID, "the revision is not JSON")
    if not isinstance(obj, dict) or artifact_bytes(obj) != raw:
        raise IntegrityFailure(BASELINE_ARTIFACT_INVALID, "the revision is not canonical")
    for field in ("revision_hash", "snapshot_id", "manifest_hash", "state_root"):
        if obj.get(field) != record.get(field):
            raise IntegrityFailure(BASELINE_ARTIFACT_INVALID, (
                "the revision's %s is not the one its ledger record binds" % field))
    if record.get("baseline_revision") != REVISION_ID or obj.get("revision_id") != REVISION_ID:
        raise IntegrityFailure(BASELINE_ARTIFACT_INVALID, "unexpected revision identifier")
    if store_class not in ADMITTED_CLASSES or obj.get("baseline_class") != store_class:
        raise IntegrityFailure(BASELINE_ARTIFACT_INVALID, (
            "a %r baseline in a %s store" % (obj.get("baseline_class"), store_class)))

    try:
        core, manifest_hash, data = load_snapshot(obj.get("snapshot_id"))
    except Exception as exc:                      # the approved evidence must verify
        raise IntegrityFailure(BASELINE_SOURCE_INVALID, (
            "the approved snapshot %s cannot be verified: %s" % (obj.get("snapshot_id"), exc)))
    if manifest_hash != obj.get("manifest_hash"):
        raise IntegrityFailure(BASELINE_SOURCE_INVALID, "the approved manifest hash differs")
    if core.get("state_root") != store_class:
        raise IntegrityFailure(BASELINE_SOURCE_INVALID, (
            "the approved snapshot is %r, not of this %s store"
            % (core.get("state_root"), store_class)))

    # Re-derive every field from its source and require byte equality (D-127).
    prof = obj.get("profile") if isinstance(obj.get("profile"), dict) else {}
    pobj = prof.get("object") if isinstance(prof.get("object"), dict) else {}
    packaged = profile_mod.lookup(pobj.get("profile_id"), pobj.get("profile_version"))
    if packaged is None or packaged != pobj:
        raise IntegrityFailure(BASELINE_ARTIFACT_INVALID, (
            "the revision's profile is not a profile this version ships"))
    stored_sections = obj.get("sections") if isinstance(obj.get("sections"), dict) else {}
    sections, method_changed = {}, {}
    for name in packaged["required_sections"]:
        stored = stored_sections.get(name)
        if not isinstance(stored, dict):
            raise IntegrityFailure(BASELINE_ARTIFACT_INVALID, "section %s is missing" % name)
        status, _reason, fingerprint, state, _error = section_facts(name, core, data)
        if fingerprint is not None and fingerprint == stored.get("method_fingerprint"):
            entry = {"collection_status": status, "state_hash": state,
                     "method_fingerprint": fingerprint,
                     "projection_version": (None if name == HOST_IDENTITY
                                            else projection.PROJECTION_VERSION)}
            method_changed[name] = False
        else:
            # This engine cannot reproduce the stored values: they stay bound by the
            # ledger's artifact_digest only (stated limitation). The recorded status is
            # engine-independent and is still re-derived.
            entry = dict(stored, collection_status=status)
            method_changed[name] = True
        sections[name] = entry
    expected = _assemble(obj.get("snapshot_id"), manifest_hash, core, store_class,
                         packaged, sections)
    if artifact_bytes(expected) != raw:
        raise IntegrityFailure(BASELINE_ARTIFACT_INVALID, (
            "baselines/%s.json does not match what its approved snapshot and the packaged "
            "profile give" % REVISION_ID))

    if require_pointer:
        if current is None:
            raise IntegrityFailure(BASELINE_POINTER_MISSING, (
                "baselines/current is missing: the approval was interrupted after its "
                "ledger record. Run `isedraf baseline approve %s` again to complete it."
                % obj["snapshot_id"]))
        if current != current_bytes(obj, record["artifact_digest"]):
            raise IntegrityFailure(BASELINE_POINTER_MISMATCH, (
                "baselines/current does not name the approved revision"))
    return obj, {"artifact_digest": record["artifact_digest"],
                 "method_changed": method_changed, "unledgered_revision": None,
                 "approved": (core, data)}


# --- the comparison (CMP-030/031, DELTA-006, D3) ---------------------------------------------

def compare(revision, approved, new_core, new_data):
    """changes.json content for one verified snapshot against the verified revision."""
    base_core, base_data = approved
    out = {"comparison_performed": False, "baseline_revision": revision["revision_id"],
           "revision_hash": revision["revision_hash"],
           "approved_snapshot_id": revision["snapshot_id"],
           "profile": {"profile_id": revision["profile"]["object"]["profile_id"],
                       "profile_version": revision["profile"]["object"]["profile_version"],
                       "profile_hash": revision["profile"]["profile_hash"]},
           "applicability": None, "reason": None, "sections": {}, "changes": []}
    tracked = list(revision["tracked_sections"])
    new_host = (new_core.get("sections") or {}).get(HOST_IDENTITY) or {}
    if new_host.get("collection_status") != COLLECTED or new_core.get("host_id") is None:
        out["applicability"] = NOT_ESTABLISHED
        out["reason"] = ("HOST_IDENTITY_NOT_COLLECTED: the snapshot's host identity is %s, "
                         "so applicability cannot be established" % new_host.get("collection_status"))
        for name in tracked:
            out["sections"][name] = {"result": NOT_COMPARABLE, "method_changed": None}
            out["changes"].append({"section": name, "primitive": NOT_COMPARABLE,
                                   "reason": "HOST_IDENTITY_NOT_COLLECTED"})
        return out
    if new_core.get("host_id") != revision["host_id"]:
        out["applicability"] = BASELINE_NOT_APPLICABLE
        out["reason"] = ("HOST_MISMATCH: the snapshot's host_id is not the baseline's; no "
                         "difference is computed (CMP-030). The `check` exit 4 is deferred; "
                         "evaluate keeps its exit codes (D-127).")
        out["baseline_host_id"] = revision["host_id"]
        out["snapshot_host_id"] = new_core.get("host_id")
        return out
    out["applicability"] = APPLICABLE
    out["comparison_performed"] = True
    for name in tracked:
        b_status, _br, _bf, b_state, b_err = section_facts(name, base_core, base_data)
        n_status, _nr, n_fp, n_state, n_err = section_facts(name, new_core, new_data)
        changed = n_fp is None or n_fp != revision["sections"][name]["method_fingerprint"]
        reason = None
        if b_status != COLLECTED or n_status != COLLECTED:
            reason = ("NOT_COLLECTED: baseline side %s, new side %s (CMP-030); never REMOVED "
                      "and never an improvement (CMP-031)" % (b_status or "MISSING",
                                                               n_status or "MISSING"))
        elif name != HOST_IDENTITY and _schema(base_data, name) != _schema(new_data, name):
            reason = ("SCHEMA_VERSION_CHANGED: section schema %r -> %r"
                      % (_schema(base_data, name), _schema(new_data, name)))
        elif b_err is not None or n_err is not None or b_state is None or n_state is None:
            reason = "%s" % (b_err or n_err or "NO_STATE_HASH")
        if reason is not None:
            out["sections"][name] = {"result": NOT_COMPARABLE, "method_changed": changed}
            out["changes"].append({"section": name, "primitive": NOT_COMPARABLE,
                                   "reason": reason})
            continue
        if b_state == n_state:
            out["sections"][name] = {"result": UNCHANGED, "method_changed": changed}
            continue
        out["sections"][name] = {"result": MODIFIED, "method_changed": changed}
        out["changes"].append({"section": name, "primitive": MODIFIED,
                               "interpretation": REVIEW_REQUIRED,
                               "before_state_hash": b_state, "after_state_hash": n_state,
                               "method_changed": changed})
    return out


def _schema(data, name):
    sect = _section_object(data, name)
    return sect.get("schema_version") if isinstance(sect, dict) else None
