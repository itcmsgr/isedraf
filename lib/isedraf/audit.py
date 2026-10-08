# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: One audit run - every built collector once, in dependency order.
# Implements: SCOPE-022, SNAP-020, IDENT-040, IDENT-041
#
# GA track, `isedraf audit`. Each domain becomes one report section: its collection status,
# its reason, and its evidence exactly as the collector produced it. The sections travel in
# the snapshot bundle as D-115 auxiliary artifacts - bound by manifest_core, outside
# state_hash - and the run is committed by the existing ledger append. Nothing here
# interprets evidence: collectors collect, and a later engine judges.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""`isedraf audit`: collect every section once."""
import re

from . import coverage, inventory, snapshot
from .accounts import acquire as accounts
from .authorizedkeys import acquire as authorizedkeys
from .hostname import acquire as hostname
from .loginpolicy import acquire as loginpolicy
from .mounts import acquire as mounts
from .nss import acquire as nss
from .pam import acquire as pam
from .ssh import acquire as ssh
from .status import COLLECTED, ERROR, NOT_TESTED, PARTIAL
from .sudo import acquire as sudo

SCHEMA_VERSION = 2                  # 2: each section carries its method identity

# Dependency order: accounts need the NSS evidence (IQ-036, IQ-037); authorized_keys need
# the account and SSH evidence. Every other section is independent.
SECTIONS = snapshot.SECTION_NAMES           # the contract's list, in dependency order

# The collectors, named once so a run can prove each ran exactly once. Each takes the
# collection root and the evidence gathered so far, and returns a JSON-ready object.
COLLECTORS = {
    "inventory": lambda root, done: inventory.collect(root=root),
    "nss": lambda root, done: nss.collect(root),
    "hostname": lambda root, done: hostname.collect(root),
    "accounts": lambda root, done: accounts.collect(
        root, nss_context=accounts.compat_context(done.get("nss")),
        effectiveness=accounts.file_effectiveness(done.get("nss"))),
    "sudo": lambda root, done: sudo.collect(root),
    "ssh": lambda root, done: ssh.collect(root),
    "pam": lambda root, done: pam.collect(root),
    "loginpolicy": lambda root, done: loginpolicy.collect(root),
    "mounts": lambda root, done: mounts.collect(root),
    "authorizedkeys": lambda root, done: authorizedkeys.collect(
        root, done.get("accounts"), done.get("ssh_raw")),
}

# CMP-020 method identity, declared beside COLLECTORS rather than in a second registry
# (IQ-042). A collector or parser change bumps its version here, so a changed observation
# can be told apart from a changed host. Versions are strings, as Evidence Limits schema 2
# requires (ELIM-006).
METHODS = dict((name, {"collector_id": "isedraf." + name, "collector_version": "1",
                       "parser_version": "1"}) for name in SECTIONS)
if set(METHODS) != set(COLLECTORS):
    raise AssertionError("audit.METHODS and audit.COLLECTORS must name the same sections")

_ORDER = (COLLECTED, PARTIAL, NOT_TESTED, ERROR)


def _status(name, evidence):
    """(status, reason) of one section, in SCOPE-022's vocabulary."""
    if name == "hostname":
        parts = [evidence.get(k, {}).get("status") for k in ("declared", "active")]
        status = max(parts, key=lambda s: _ORDER.index(s) if s in _ORDER else len(_ORDER))
        if status not in _ORDER:
            return ERROR, "SECTION_STATUS_UNKNOWN: the collector reported no status"
        reasons = [evidence.get(k, {}).get("reason") for k in ("declared", "active")]
        return status, "; ".join(r for r in reasons if r) or None
    status = evidence.get("collection_status", evidence.get("status"))
    if status not in _ORDER:
        return ERROR, "SECTION_STATUS_UNKNOWN: the collector reported no status"
    return status, evidence.get("reason")


def collect(root="/"):
    """Every section once. Returns (sections, run_status).

    A collector that raises becomes an ERROR section: the audit continues and exits
    incomplete, and the exception's text is not recorded - it can carry host-derived
    content, which diagnostics never echo.
    """
    done, sections = {}, {}
    for name in SECTIONS:
        try:
            produced = COLLECTORS[name](root, done)
            if name == "ssh":
                done["ssh_raw"] = produced
            evidence = produced.as_dict() if hasattr(produced, "as_dict") else produced
            done[name] = evidence
            status, reason = _status(name, evidence)
        except Exception as exc:                     # a collector bug is evidence too
            evidence = None
            status = ERROR
            reason = "COLLECTOR_ERROR: %s raised %s" % (name, type(exc).__name__)
        if status != COLLECTED and not reason:
            reason = "SEE_SECTION_EVIDENCE: the collector gave no summary reason"
        sections[name] = {"schema_version": SCHEMA_VERSION, "section": name,
                          "method": dict(METHODS[name]),
                          "collection_status": status, "reason": reason,
                          "evidence": evidence}
    statuses = [s["collection_status"] for s in sections.values()]
    run_status = (COLLECTED if all(s == COLLECTED for s in statuses)
                  else ERROR if ERROR in statuses else PARTIAL)
    return sections, run_status


# --- Evidence Limits Manifest (IQ-042 (2), D-122) -----------------------------------------

_REASON = re.compile(r"^[A-Z][A-Z0-9_]*: .+")


def _coverage_records(evidence):
    """The section's own coverage records, in whichever of the three shapes it emits:
    evidence.coverage as a list or a single dict, or evidence.provenance.coverage."""
    if not isinstance(evidence, dict):
        return []
    found = evidence.get("coverage")
    if found is None:
        found = (evidence.get("provenance") or {}).get("coverage")
    if isinstance(found, dict):
        found = [found]
    return [r for r in (found or []) if isinstance(r, dict)]


def _relative(source, root):
    """ELIM: a collection-root-relative path, or the stable name a section already uses."""
    base = root.rstrip("/")
    if base and source.startswith(base + "/"):
        return source[len(base) + 1:]
    return source.lstrip("/") if source.startswith("/") else source


def evidence_limits(sections, root="/"):
    """The Evidence Limits Manifest for one audit run (schema 2, D-122).

    Pure: it reads only the committed sections. Every requested section is reported
    through its coverage records or listed as unreported with its own reason, so a missing
    record is never read as complete coverage (ELIM-003). Collector identity is the
    section's method object (CMP-020); acquisition authority is the identity the engine ran
    as. Nothing here evaluates anything.
    """
    records, unreported = [], []
    for name in SECTIONS:
        section = sections.get(name) or {}
        found = _coverage_records(section.get("evidence"))
        if not found:
            reason = section.get("reason")
            unreported.append({"section": name, "reason": (
                reason if isinstance(reason, str) and _REASON.match(reason)
                else "COVERAGE_NOT_RECORDED: the section reported no acquisition coverage.")})
            continue
        for record in found:
            record = dict(record)
            record["domain"] = name
            record["source"] = _relative(str(record.get("source")), root)
            records.append(record)
    return coverage.manifest(records, coverage.MODE_CURRENT_IDENTITY, METHODS,
                             requested_sections=SECTIONS, unreported_sections=unreported)
