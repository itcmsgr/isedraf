# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The one report model. Every renderer consumes this and nothing else.
# Implements: SNAP-020, SNAP-023, STORE-024, REC-005, SCOPE-045, SCOPE-063
#
# The rule this file exists to enforce: a report may never make a stronger evidentiary
# claim than the artifacts behind it support. Identity evidence is snapshot-bound,
# manifest-hashed, ledger-chained and independently verified. The inventory is collected,
# normalized and digested - and is NOT inside the frozen snapshot. The model keeps them in
# separate blocks, each carrying its own maturity, so a renderer cannot blur them even by
# accident.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Build the report model from evidence already on disk plus one inventory collection."""
import hashlib
import json
import os

from .. import ENGINE_VERSION, coverage, ids, ledger, verify
from ..inventory import model as inventory_model
from . import artifact as artifact_module
from . import sections as section_summaries
from .profile import IDENTITY_DISCLAIMER

REPORT_SCHEMA_VERSION = 1

# Plain words on the report itself (GA v0.1 public docs review): the two blocks stay
# distinct, because host identity is part of host state and inventory is not.
IDENTITY_MATURITY = ("committed host identity - part of the snapshot's host state, "
                     "manifest-hashed and ledger-chained")
INVENTORY_MATURITY = ("collected and normalized; committed with the audit run as a bound "
                      "section, NOT part of the snapshot's host-state hash")

# Only limitations that say something. A reader who has to wade through boilerplate stops
# reading the ones that matter.
BASE_LIMITATIONS = [
    "Host identity derives from a locally readable machine identity. It is not remote "
    "attestation, and a local root adversary can change the source it derives from.",
    "Cloned systems share a machine identity when cloning did not regenerate it, so two "
    "hosts can legitimately present the same host_id.",
    "Hardware facts — CPU model, core counts, memory capacity, disk topology — are "
    "observations, not configuration. They change legitimately on virtualized hosts and "
    "do not by themselves indicate drift.",
    "Network addresses and routes describe local configuration. They do not prove that "
    "anything outside this host can reach it.",
    "Configured DNS servers are what this host is told to use. No query was performed, "
    "so nothing here describes resolution behaviour.",
    "Host inventory is not part of the frozen snapshot contract. It is bound to this "
    "report by an artifact digest, which is a content digest and not a snapshot hash.",
    IDENTITY_DISCLAIMER,
]


def _latest_snapshot(root):
    """The snapshot of the LAST LEDGER RECORD - the latest committed run.

    D-50: the ledger append is the commit. The newest directory under snapshots/ can be an
    orphan whose run stopped between the atomic rename and the append; reporting it would
    present uncommitted evidence as the run (GA track, found while wiring `audit`).
    """
    try:
        records = list(ledger.read_records(root))
    except (OSError, ValueError):
        return None
    if not records:
        return None
    name = records[-1]["record_core"]["snapshot_id"]
    return name if os.path.isdir(os.path.join(root, "snapshots", name)) else None


def committed_run(root):
    """The latest committed run's audit sections, or None when it has none.

    Read from the bundle, never collected. An identity-only run is a committed run but not
    an audit run, and a report never mixes one run's identity with another's sections.
    """
    name = _latest_snapshot(root)
    if name is None:
        return None
    base = os.path.join(root, "snapshots", name, "sections")
    if not os.path.isdir(base):
        return None
    sections = {}
    for entry in sorted(os.listdir(base)):
        if entry.endswith(".json"):
            with open(os.path.join(base, entry), "rb") as fh:
                sections[entry[:-5]] = json.loads(fh.read().decode("utf-8"))
    if "inventory" not in sections:
        return None
    try:
        with open(os.path.join(root, "snapshots", name, "manifest.json"), "rb") as fh:
            bound = json.loads(fh.read().decode("utf-8"))["manifest_core"]["auxiliary_artifacts"]
    except (OSError, ValueError, KeyError):
        bound = {}
    digests = {n: bound.get("sections/%s.json" % n) for n in sections}
    return {"snapshot_id": name, "sections": sections, "digests": digests}


def identity_evidence(root):
    """Read the committed identity evidence and re-verify it. Never re-collect it.

    A report renders evidence that already exists; collecting during rendering would mean
    the report described something the ledger had never seen.
    """
    block = {"available": False, "maturity": IDENTITY_MATURITY, "evidence_root": root,
             "snapshot_id": None, "manifest_hash": None, "host_id": None,
             "collection_status": None, "reason": None, "state_root_class": None,
             "ledger_sequence": None, "ledger_record_hash": None,
             "verification": {"verified": None, "problems": []}}
    name = _latest_snapshot(root)
    if name is None:
        block["reason"] = "no snapshot has been committed in this evidence root"
        return block
    manifest = os.path.join(root, "snapshots", name, "manifest.json")
    try:
        with open(manifest, "rb") as fh:
            envelope = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        block["reason"] = "snapshot %s is unreadable: %s" % (name, exc)
        return block
    core = envelope["manifest_core"]
    section = core["sections"]["host_identity"]
    problems = verify.verify_store(root)
    record = None
    for row in ledger.read_records(root):
        if row["record_core"]["snapshot_id"] == name:
            record = row
    block.update({
        "available": True,
        "snapshot_id": name,
        "manifest_hash": envelope.get("manifest_hash"),
        "host_id": core.get("host_id"),
        "collection_status": section.get("collection_status"),
        "reason": section.get("reason"),
        "state_hash": section.get("state_hash"),
        "state_root_class": core.get("state_root"),
        "created_at": core.get("created_at"),
        "run_id": core.get("run_id"),
        "ledger_sequence": record["record_core"]["sequence"] if record else None,
        "ledger_record_hash": record["record_hash"] if record else None,
        "verification": {"verified": not problems, "problems": problems},
    })
    return block


def _collection_summary(inventory):
    rows = []
    for name in inventory_model.SUBDOMAINS:
        block = inventory.get("subdomains", {}).get(name, {})
        rows.append({"subdomain": name,
                     "collection_status": block.get("collection_status"),
                     "reason": block.get("reason"),
                     "method": block.get("method")})
    return rows


def _limitations(inventory):
    out = list(BASE_LIMITATIONS)
    network = (inventory.get("subdomains", {}).get("network", {}).get("data") or {})
    if network.get("ipv6_volatile"):
        out.append("Temporary IPv6 addresses (RFC 4941) are present. They rotate by "
                   "design and are reported separately from stable addresses so that "
                   "normal IPv6 behaviour does not read as configuration change.")
    time_data = (inventory.get("subdomains", {}).get("time", {}).get("data") or {})
    if time_data.get("ntp_enabled") and time_data.get("synchronized") is False:
        out.append("Time synchronization is configured but the clock is NOT "
                   "synchronized. Event times observed on this host carry no ordering "
                   "guarantee (REC-005, CLOCK_UNSYNCHRONIZED).")
    elif time_data.get("synchronized") is None:
        out.append("Clock synchronization state could not be determined. That is not a "
                   "statement that the clock is correct.")
    return out


def _coverage_limitations(manifest):
    """Limitation sentences derived from STRUCTURED coverage, never from prose.

    R1.5-P's point in one function: the renderer reads fields. It does not parse the
    English `reason` a collector wrote, because a consumer that has to parse a sentence to
    learn whether privilege caused a gap is a consumer that will eventually parse it
    wrong.
    """
    if not manifest:
        return []
    out = []
    limited = [s for s in manifest["limitations"] if s["privilege_limited"]]
    if limited:
        classes = sorted(set(s["required_access"] for s in limited))
        out.append(
            "%d requested source(s) were not observed because the collection identity "
            "lacked sufficient access. Additional evidence access required: %s. This is "
            "a statement about who was asking, not about the host's security."
            % (len(limited), ", ".join(classes)))
    other = [s for s in manifest["limitations"] if not s["privilege_limited"]]
    if other:
        out.append(
            "%d requested source(s) were not fully observed for reasons unrelated to "
            "access. Additional authority would not change them." % len(other))
    forbidden = [s for s in manifest["sources"] if not s["absence_claim_allowed"]]
    if forbidden:
        out.append(
            "%d requested source(s) were not observed completely, so absence of a record "
            "in them is NOT evidence that the record does not exist."
            % len(forbidden))
    if manifest["limitations"]:
        out.append(
            "This collection is incomplete over its requested evidence universe. No "
            "acquisition mode makes it complete: additional authority would change the "
            "access-limited sources above and nothing else.")
    return out


def build(root, inventory, assessment=None, generated_at=None, report_id=None,
          inventory_artifact=None, coverage_manifest=None, audit_sections=None,
          audit_digests=None):
    """The whole model. Assessment metadata is presentation and touches no evidence."""
    generated_at = generated_at or ids.now_utc()
    report_id = report_id or ids.new_id("RPT", generated_at)
    art = inventory_artifact or artifact_module.build(inventory)
    identity = identity_evidence(root)
    summary = _collection_summary(inventory)

    host = (inventory.get("subdomains", {}).get("host", {}).get("data") or {})
    statuses = [r["collection_status"] for r in summary]
    # Every audited section counts, not only inventory: a run with a NOT_TESTED section
    # was labelled COMPLETE and exited 0 (GA smoke test, 2026-09-27).
    statuses += [s.get("collection_status") for s in (audit_sections or {}).values()]
    status = "COMPLETE" if all(s == inventory_model.COLLECTED for s in statuses) \
        else "PARTIAL"

    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "report": {
            "report_id": report_id,
            "generated_at": generated_at,
            "engine_version": ENGINE_VERSION,
            # Evidence completeness only. There is deliberately no secure/insecure and no
            # pass/fail here: inventory is evidence, and a score would be a judgement the
            # data does not support.
            "status": status,
        },
        "assessment": assessment or None,
        "target": {
            "hostname": host.get("hostname"),
            "fqdn": host.get("fqdn"),
            "fqdn_source": host.get("fqdn_source"),
            "host_id": identity.get("host_id"),
        },
        "identity_evidence": identity,
        "inventory": {
            "maturity": INVENTORY_MATURITY,
            "collection_id": art["core"]["collection_id"],
            "artifact_digest": art["artifact_digest"],
            "collected_at": art["core"]["collected_at"],
            "schema_version": inventory.get("schema_version"),
            "collection_status": inventory.get("collection_status"),
            "subdomains": inventory.get("subdomains", {}),
        },
        "collection_summary": summary,
        # GA track: one line per audited domain of the committed run. Status and reason
        # only; the evidence itself stays in the bundle's section files.
        "audit_sections": ({name: {"collection_status": s.get("collection_status"),
                                   "reason": s.get("reason"),
                                   "title": section_summaries.TITLES.get(name, name),
                                   "summary": [[label, value] for label, value in
                                               section_summaries.summarize(name, s)],
                                   "evidence_ref": {
                                       "path": "sections/%s.json" % name,
                                       "digest": (audit_digests or {}).get(name)}}
                            for name, s in sorted(audit_sections.items())}
                           if audit_sections is not None else None),
        # R1.5-P. The Evidence Limits Manifest is carried, not re-derived: the report
        # RENDERS coverage evidence and does not compute it, for the same reason a
        # renderer does not collect. Absent when the caller supplied none, so that
        # "no manifest" and "an empty manifest" stay distinguishable (NORM-034).
        "evidence_limits": coverage_manifest,
        "limitations": _limitations(inventory) + _coverage_limitations(coverage_manifest),
        "provenance": {
            "engine_version": ENGINE_VERSION,
            "inventory_schema_version": inventory.get("schema_version"),
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "collection_methods": {r["subdomain"]: r["method"] for r in summary},
        },
    }


# Fields that must change between two renderings of the same evidence. Excluding them is
# what makes a reproducibility claim meaningful rather than trivially false.
NON_REPRODUCIBLE = ("report.report_id", "report.generated_at")


def content_digest(report):
    """A digest over everything EXCEPT the fields that must differ per rendering.

    Two reports built from the same evidence, the same inventory artifact and the same
    assessment metadata produce the same value; changing only the assessor changes it,
    because assessment metadata is part of the report even though it is not evidence.
    """
    copy = json.loads(json.dumps(report, sort_keys=True))
    for path in NON_REPRODUCIBLE:
        block, _, field = path.partition(".")
        copy.get(block, {}).pop(field, None)
    payload = json.dumps(copy, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()
