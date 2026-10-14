# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: A few factual lines per committed audit section, for Report 0.1.
# Implements: OUT-010, D-117
#
# Presentation only: it reads one committed section's evidence and states what it contains -
# counts and plain host facts. No judgement (no pass, no fail, no score), no collection, and
# no free text from account or configuration files, which stays in the evidence itself.
#
# meta:type="renderer"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Factual summaries of committed audit sections."""

# Report order (owner, 2026-09-27): the host first, then identity, then access paths.
ORDER = ("inventory", "accounts", "nss", "hostname", "mounts", "ssh", "pam", "sudo",
         "authorizedkeys", "loginpolicy")

TITLES = {
    "inventory": "Host and platform", "nss": "Name service (NSS) configuration",
    "hostname": "Hostname", "accounts": "Local accounts and groups", "sudo": "sudo",
    "ssh": "SSH server configuration", "pam": "PAM", "loginpolicy": "Login policy",
    "mounts": "Mounts", "authorizedkeys": "SSH authorized keys",
}


def _data(evidence, subdomain):
    return (((evidence or {}).get("subdomains") or {}).get(subdomain) or {}).get("data") or {}


def _inventory(e):
    host, plat = _data(e, "host"), _data(e, "platform")
    comp, mem = _data(e, "compute"), _data(e, "memory")
    net, sto = _data(e, "network"), _data(e, "storage")
    total = mem.get("total_bytes")
    return [
        ("Hostname", host.get("hostname")),
        ("FQDN", host.get("fqdn")),
        ("Operating system", plat.get("pretty_name")),
        ("Kernel", plat.get("kernel_release")),
        ("Architecture", plat.get("architecture")),
        ("CPU", comp.get("cpu_model")),
        ("Logical CPUs", comp.get("logical_cpus")),
        ("Memory", "%.1f GiB" % (total / 1024.0 ** 3) if total else None),
        ("Network interfaces", len(net.get("interfaces") or []) if net else None),
        ("Block devices", len(sto.get("devices") or []) if sto else None),
    ]


def _accounts(e):
    accounts = e.get("local_accounts") or []
    effective = ((e.get("nss_file_effectiveness") or {}).get("etc/passwd") or {})
    return [
        ("Local account records (/etc/passwd)", len(accounts)),
        ("Accounts with uid 0", sum(1 for a in accounts if a.get("uid") == 0)),
        ("Local group records (/etc/group)", len(e.get("local_groups") or [])),
        ("/etc/passwd consulted by NSS", effective.get("files_effective")),
    ]


def _nss(e):
    rows = []
    for rec in e.get("records") or []:
        if rec.get("database") in ("passwd", "group", "shadow", "initgroups"):
            rows.append(("%s" % rec["database"],
                         " ".join(x.get("service") or "?" for x in rec.get("entries") or [])))
    return rows or [("Identity databases", "none declared")]


def _hostname(e):
    return [("Declared (/etc/hostname)", (e.get("declared") or {}).get("value")),
            ("Active (kernel)", (e.get("active") or {}).get("value")),
            ("Declared vs active", e.get("relation"))]


def _records(e):
    return [("Records observed", len((e or {}).get("records") or []))]


MATCH_NOT_RESOLVED = ("not resolved by this audit: sshd -T ran without a connection context, "
                      "so Match blocks were not applied; the Match blocks are recorded as "
                      "declared configuration")


def ssh_dimensions(e):
    """AUTH-031: [(dimension, collection status, detail)] for an ssh section with a resolved
    dimension, else None. Each dimension keeps its own status; the global effective
    configuration is never presented as the effective configuration of every connection."""
    provenance = (e or {}).get("provenance") or {}
    resolved = provenance.get("resolved")
    if not resolved:
        return None
    records = (e or {}).get("records") or []
    settings = [r for r in records if r.get("kind") == "RESOLVED_SETTING"]
    declared = provenance.get("declared") or {}
    d_status = declared.get("status") or "NOT RECORDED SEPARATELY"
    d_detail = "%d records" % (len(records) - len(settings))
    if declared.get("status") not in (None, "COLLECTED") and declared.get("reason"):
        d_detail += "; " + declared["reason"]
    r_status = resolved.get("status")
    r_detail = ("%d settings" % len(settings) if r_status == "COLLECTED"
                else (resolved.get("reason") or "no reason recorded"))
    return [("Declared configuration", d_status, d_detail),
            ("Global effective configuration (sshd -T, global only)", r_status, r_detail),
            ("Match-dependent (connection-specific) values", "NOT_TESTED", MATCH_NOT_RESOLVED)]


def _ssh(e):
    """A declared-only section renders exactly as before."""
    dims = ssh_dimensions(e)
    if dims is None:
        return _records(e)
    return [(label, "%s - %s" % (status, detail)) for label, status, detail in dims]


def dimensions(name, section):
    """The per-dimension rows of a section, for both formats; empty when it has none."""
    if name != "ssh" or section.get("evidence") is None:
        return []
    try:
        return ssh_dimensions(section["evidence"]) or []
    except (AttributeError, TypeError, KeyError):
        return []


_SUMMARIES = {"inventory": _inventory, "accounts": _accounts, "nss": _nss,
              "hostname": _hostname, "ssh": _ssh}


def summarize(name, section):
    """[(label, value)] for one committed section; empty when it holds no evidence."""
    evidence = section.get("evidence")
    if evidence is None:
        return []
    try:
        rows = _SUMMARIES.get(name, _records)(evidence)
    except (AttributeError, TypeError, KeyError):
        # A summary is a convenience, never evidence: an unexpected shape shows nothing
        # rather than something wrong. The section's evidence file remains authoritative.
        return []
    return [(label, value) for label, value in rows if value not in (None, "", [])]
