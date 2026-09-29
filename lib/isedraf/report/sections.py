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


_SUMMARIES = {"inventory": _inventory, "accounts": _accounts, "nss": _nss,
              "hostname": _hostname}


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
