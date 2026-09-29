# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The host inventory domain — one normalized object from many sources.
# Implements: SCOPE-022, SCOPE-045, REC-005
#
# NOT yet written into snapshots. SNAP-021 freezes a W1-A snapshot as exactly three
# files, so adding an inventory artifact would change frozen canonical bytes. Integration
# belongs to a W1-C freeze set, and inventing a place for it here would be the one thing
# this project has consistently refused to do.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""`collect()` returns the whole inventory; nothing here raises on a hostile system."""
from .. import coverage
from . import collectors, model
from .model import (CLASSIFICATION, COLLECTED, ERROR, INVENTORY_SCHEMA_VERSION,
                    NOT_TESTED, PARTIAL, SUBDOMAINS, VOLATILE_FIELDS)

_COLLECTORS = (
    ("host", collectors.collect_host),
    ("platform", collectors.collect_platform),
    ("machine", collectors.collect_machine),
    ("compute", collectors.collect_compute),
    ("memory", collectors.collect_memory),
    ("storage", collectors.collect_storage),
    ("network", collectors.collect_network),
    ("dns", collectors.collect_dns),
    ("time", collectors.collect_time),
)

# R1.5-P. The PRIMARY acquisition operation of each collector, declared once here rather
# than threaded through eighteen return statements. It is a static property of the
# collector - what kind of thing it reads - and declaring it at the registry keeps the
# retrofit additive instead of a rewrite of code that is already frozen and working.
#
# Where a collector determines an access outcome for itself it passes one, and that answer
# wins. Where it does not, the assembler classifies CONSERVATIVELY: see _coverage.
_OPERATIONS = {
    "host": coverage.OP_FILE_READ,
    "platform": coverage.OP_FILE_READ,
    "machine": coverage.OP_FILE_READ,
    "compute": coverage.OP_FILE_READ,
    "memory": coverage.OP_FILE_READ,
    "storage": coverage.OP_FILE_READ,
    "network": coverage.OP_COMMAND,
    "dns": coverage.OP_FILE_READ,
    "time": coverage.OP_COMMAND,
}


def collect(root="/"):
    """Every subdomain, each carrying its own collection status and provenance.

    A collector that raises becomes an ERROR subdomain rather than an aborted run: the
    point of an inventory is to report what could be seen, and one unreadable source is
    not a reason to report nothing.
    """
    out = {"schema_version": INVENTORY_SCHEMA_VERSION, "subdomains": {}}
    for name, function in _COLLECTORS:
        try:
            out["subdomains"][name] = function(root)
        except Exception as exc:                    # noqa: BLE001 - reported, not raised
            out["subdomains"][name] = model.subdomain(
                model.ERROR, {}, method=getattr(function, "__name__", name),
                reason="INTERNAL_ERROR: %s" % type(exc).__name__)
    out["coverage"] = _coverage(out["subdomains"])
    statuses = [s["collection_status"] for s in out["subdomains"].values()]
    if all(s == COLLECTED for s in statuses):
        out["collection_status"] = COLLECTED
    elif all(s in (NOT_TESTED, ERROR) for s in statuses):
        out["collection_status"] = ERROR
    else:
        out["collection_status"] = PARTIAL
    return out


def _coverage(subdomains):
    """R1.5-P acquisition context for the inventory, classified conservatively.

    THE RULE THE OWNER NAMED: a nonzero exit is not a privilege problem. hostio.run
    returns ERROR for a nonzero exit, a timeout and an OSError alike, and it has no
    contract for telling a refusal apart from any other failure. Parsing stderr for the
    word "permission" would be a privilege detector built on other projects' error
    messages, and it would be wrong the first time one of them changed its wording.

    So a subdomain that did not determine an access outcome for itself gets one that
    claims nothing about authority: NOT_TESTED becomes NOT_SUPPORTED and ERROR becomes
    IO_ERROR, both with ACCESS_NONE and privilege_limited false. PERMISSION_DENIED appears
    here ONLY when a collector established it - which today means a file read, because
    read_file knows EACCES from ENOENT and hostio.run knows neither.

    Under-claiming is the right failure direction. Telling an operator to obtain access
    that would change nothing is worse than telling them a source could not be read.
    """
    out = []
    for name in sorted(subdomains):
        block = subdomains[name]
        status = block["collection_status"]
        outcome = block.get("access_outcome")
        if outcome not in coverage.OUTCOMES:
            outcome = (coverage.READ_OK if status == COLLECTED
                       else coverage.NOT_SUPPORTED if status == NOT_TESTED
                       else coverage.IO_ERROR)
        out.append(coverage.source(
            "inventory", name, status, outcome,
            block.get("operation") or _OPERATIONS.get(name, coverage.OP_FILE_READ),
            reason=block.get("reason"),
            universe=(coverage.UNIVERSE_COMPLETE if status == COLLECTED
                      else coverage.UNIVERSE_INCOMPLETE)))
    return out


def flatten(inventory):
    """`subdomain.field` -> value, for classification checks and the noise test."""
    flat = {}
    for name, block in sorted(inventory.get("subdomains", {}).items()):
        for field, value in sorted((block.get("data") or {}).items()):
            flat["%s.%s" % (name, field)] = value
    return flat


def clock_unsynchronized(inventory):
    """REC-005. True when the clock is known NOT to be synchronized.

    An unknown synchronization state is NOT an assertion that the clock is fine, so it
    returns None: the caller must decide, and cannot accidentally read absence as safety.
    """
    block = inventory.get("subdomains", {}).get("time", {})
    value = (block.get("data") or {}).get("synchronized")
    if value is None:
        return None
    return not value
