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

from .. import ENGINE_VERSION, ids, ledger, verify
from ..inventory import model as inventory_model
from . import artifact as artifact_module
from .profile import IDENTITY_DISCLAIMER

REPORT_SCHEMA_VERSION = 1

IDENTITY_MATURITY = "W1-A CERTIFIED — snapshot-bound, manifest-hashed, ledger-chained"
INVENTORY_MATURITY = ("W1-C1 — collected and normalized, bound by an artifact digest. "
                      "NOT part of the frozen W1-A snapshot contract (SNAP-021)")

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
    base = os.path.join(root, "snapshots")
    if not os.path.isdir(base):
        return None
    names = sorted(n for n in os.listdir(base) if n.startswith("SDS-"))
    return names[-1] if names else None


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


def build(root, inventory, assessment=None, generated_at=None, report_id=None,
          inventory_artifact=None):
    """The whole model. Assessment metadata is presentation and touches no evidence."""
    generated_at = generated_at or ids.now_utc()
    report_id = report_id or ids.new_id("RPT", generated_at)
    art = inventory_artifact or artifact_module.build(inventory)
    identity = identity_evidence(root)
    summary = _collection_summary(inventory)

    host = (inventory.get("subdomains", {}).get("host", {}).get("data") or {})
    statuses = [r["collection_status"] for r in summary]
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
        "limitations": _limitations(inventory),
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
