# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Renderers. They format the model and decide nothing.
# Implements: REC-005, SCOPE-063
#
# Every renderer reads the same model and adds no facts of its own. A PDF renderer added
# later reads this same structure, which is the only way two formats of one report cannot
# disagree.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""JSON and Markdown, both from the report model and from nothing else."""
import json

from ..inventory import model as inventory_model

_ASSESSMENT_LABELS = (
    ("report_title", "Report title"), ("prepared_by", "Prepared by"), ("role", "Role"),
    ("organization", "Organization"), ("email", "Email"), ("customer", "Customer"),
    ("engagement", "Engagement"), ("reference", "Reference"), ("notes", "Notes"),
)


def to_json(report, indent=2):
    return json.dumps(report, indent=indent, sort_keys=True, ensure_ascii=False) + "\n"


def _gib(value):
    return "%.1f GiB" % (value / (1024.0 ** 3)) if value else "—"


def _row(out, label, value):
    out.append("%-20s %s" % (label, "—" if value in (None, "") else value))


def to_markdown(report):
    out = []
    r, target = report["report"], report["target"]
    inv = report["inventory"]
    d = inv.get("subdomains", {})

    def data(name):
        return (d.get(name, {}).get("data") or {})

    out.append("# ISEDRAF System Assurance Report")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| Report ID | `%s` |" % r["report_id"])
    out.append("| Generated (UTC) | %s |" % r["generated_at"])
    out.append("| ISEDRAF version | %s |" % r["engine_version"])
    out.append("| Report status | **%s** |" % r["status"])
    out.append("")
    out.append("> This report describes what was **observed**. It contains no "
               "secure/insecure verdict, because host inventory is evidence and a score "
               "would be a judgement the data does not support.")
    out.append("")

    assessment = report.get("assessment")
    if assessment:
        out.append("## Assessment")
        out.append("")
        out.append("| | |")
        out.append("|---|---|")
        for key, label in _ASSESSMENT_LABELS:
            if assessment.get(key):
                out.append("| %s | %s |" % (label, assessment[key]))
        out.append("")

    out.append("## Target")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| Hostname | %s |" % (target.get("hostname") or "—"))
    fqdn = target.get("fqdn")
    out.append("| FQDN | %s |" % (fqdn if fqdn else
                                  "*not resolvable locally — no resolver was consulted*"))
    out.append("| Host ID | `%s` |" % (target.get("host_id") or "—"))
    out.append("")

    # --- evidence: two blocks, two maturities, never merged ----------------------------
    ident = report["identity_evidence"]
    out.append("## Evidence")
    out.append("")
    out.append("### Host identity — %s" % ident["maturity"])
    out.append("")
    if not ident["available"]:
        out.append("No identity evidence in this evidence root: %s"
                   % (ident.get("reason") or "unknown"))
    else:
        out.append("| | |")
        out.append("|---|---|")
        out.append("| Snapshot ID | `%s` |" % ident["snapshot_id"])
        out.append("| Manifest hash | `%s` |" % ident["manifest_hash"])
        out.append("| State hash | `%s` |" % (ident.get("state_hash") or "—"))
        out.append("| Ledger record | sequence %s, `%s` |"
                   % (ident.get("ledger_sequence"), ident.get("ledger_record_hash")))
        out.append("| Collection status | %s |" % ident["collection_status"])
        out.append("| Evidence root | `%s` (%s) |"
                   % (ident["evidence_root"], ident.get("state_root_class")))
        verified = ident["verification"]["verified"]
        out.append("| Independent verification | %s |"
                   % ("**PASS** — every hash recomputed from the stored preimages"
                      if verified else "**FAIL**"))
        for problem in ident["verification"]["problems"]:
            out.append("| Verification problem | %s |" % problem)
    out.append("")
    out.append("### Host inventory — %s" % inv["maturity"])
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| Collection ID | `%s` |" % inv["collection_id"])
    out.append("| Artifact digest | `%s` |" % inv["artifact_digest"])
    out.append("| Collected (UTC) | %s |" % inv["collected_at"])
    out.append("| Inventory schema | %s |" % inv["schema_version"])
    out.append("| Collection status | %s |" % inv["collection_status"])
    out.append("")
    out.append("The artifact digest is a content SHA-256 over the deterministic "
               "inventory artifact. It is **not** a snapshot hash and the inventory is "
               "**not** inside the frozen snapshot.")
    out.append("")

    # --- the system profile -------------------------------------------------------------
    platform, machine = data("platform"), data("machine")
    out.append("## Platform")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| Operating system | %s |" % (platform.get("pretty_name") or "—"))
    out.append("| Version | %s |" % (platform.get("version_id") or "—"))
    out.append("| Family | %s |" % (platform.get("family") or "—"))
    out.append("| Kernel | `%s` |" % (platform.get("kernel_release") or "—"))
    out.append("| Architecture | %s |" % (platform.get("architecture") or "—"))
    out.append("| Init system | %s |" % (platform.get("init_system") or "—"))
    virt = machine.get("virtualized")
    out.append("| Machine | %s |" % {True: "virtual", False: "physical",
                                     None: "unknown"}[virt])
    out.append("| Hypervisor | %s |" % (machine.get("hypervisor") or "—"))
    out.append("| Vendor / product | %s / %s |" % (machine.get("vendor") or "—",
                                                   machine.get("product") or "—"))
    out.append("")

    compute, memory = data("compute"), data("memory")
    out.append("## Compute and memory")
    out.append("")
    out.append("*Hardware observations. They change legitimately on virtualized hosts "
               "and do not by themselves indicate configuration drift.*")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| CPU | %s |" % (compute.get("cpu_model") or "—"))
    out.append("| Vendor | %s |" % (compute.get("cpu_vendor") or "—"))
    out.append("| Sockets / cores per socket | %s / %s |"
               % (compute.get("sockets") or "—", compute.get("cores_per_socket") or "—"))
    out.append("| Logical CPUs | %s |" % (compute.get("logical_cpus") or "—"))
    out.append("| Memory | %s |" % _gib(memory.get("total_bytes")))
    out.append("| Swap | %s |" % _gib(memory.get("swap_total_bytes")))
    out.append("")

    storage = data("storage")
    out.append("## Storage")
    out.append("")
    devices = storage.get("devices") or []
    if devices:
        # D-114. Column headers name the SOURCE, so a reader cannot mistake a kernel
        # flag for a physical fact: "Kernel removable flag", not "Removable".
        out.append("| Device | Size | Kernel subsystem | Queue rotational | "
                   "Kernel removable flag | Vendor | Model |")
        out.append("|---|---|---|---|---|---|---|")
        for dev in devices:
            size = "%.1f GB" % (dev["size_bytes"] / 1e9) if dev.get("size_bytes") else "—"

            def tri(v):
                return "—" if v is None else ("true" if v else "false")

            out.append("| `%s` | %s | %s | %s | %s | %s | %s |"
                       % (dev["name"], size,
                          dev.get("kernel_subsystem") or "—",
                          tri(dev.get("queue_rotational")),
                          tri(dev.get("kernel_removable")),
                          dev.get("vendor") or "—",
                          dev.get("model") or "—"))
        out.append("")
        out.append("*Kernel-reported block-device attributes. `Queue rotational` and "
                   "`Kernel removable flag` describe how Linux presents the block "
                   "queue; neither establishes the physical storage medium, and a "
                   "block device does not necessarily correspond to one physical "
                   "disk (D-114).*")
        out.append("")
    filesystems = storage.get("filesystems") or []
    if filesystems:
        out.append("| Mount point | Source | Type | Mode | Options |")
        out.append("|---|---|---|---|---|")
        for fs in filesystems:
            out.append("| `%s` | `%s` | %s | %s | `%s` |"
                       % (fs["mount_point"], fs["source"], fs["fstype"],
                          "read-only" if fs["read_only"] else "read-write",
                          ",".join(fs["options"][:6])))
        out.append("")
    utilisation = storage.get("utilisation") or []
    if utilisation:
        out.append("**Utilisation** — a volatile observation, not configuration:")
        out.append("")
        out.append("| Mount point | Used |")
        out.append("|---|---|")
        for u in utilisation:
            out.append("| `%s` | %s%% |" % (u["mount_point"],
                                            round(u["used_permille"] / 10.0, 1)))
        out.append("")

    network, dns = data("network"), data("dns")
    out.append("## Network")
    out.append("")
    interfaces = [i for i in (network.get("interfaces") or []) if not i["loopback"]]
    if interfaces:
        out.append("| Interface | State | MTU |")
        out.append("|---|---|---|")
        for i in interfaces:
            out.append("| `%s` | %s | %s |" % (i["name"], i["state"] or "—",
                                               i["mtu"] or "—"))
        out.append("")
    ipv4 = [a for a in (network.get("ipv4") or []) if not a["loopback"]]
    if ipv4:
        out.append("**IPv4**")
        out.append("")
        out.append("| Address | Interface | Scope |")
        out.append("|---|---|---|")
        for a in ipv4:
            out.append("| `%s/%s` | `%s` | %s |" % (a["address"], a["prefix_length"],
                                                    a["interface"], a["scope"] or "—"))
        out.append("")
    stable = [a for a in (network.get("ipv6_stable") or [])
              if a["classification"] != inventory_model.IPV6_LOOPBACK]
    volatile = network.get("ipv6_volatile") or []
    if stable or volatile:
        out.append("**IPv6**")
        out.append("")
        out.append("| Address | Interface | Classification |")
        out.append("|---|---|---|")
        for a in stable:
            out.append("| `%s/%s` | `%s` | %s |" % (a["address"], a["prefix_length"],
                                                    a["interface"],
                                                    a["classification"]))
        for a in volatile:
            out.append("| `%s/%s` | `%s` | **%s** |" % (a["address"],
                                                        a["prefix_length"],
                                                        a["interface"],
                                                        a["classification"]))
        out.append("")
        if volatile:
            out.append("Temporary privacy addresses rotate by design (RFC 4941) and are "
                       "reported separately from stable configuration.")
            out.append("")
    routes = network.get("default_routes") or []
    if routes:
        out.append("| Default route | Gateway | Interface |")
        out.append("|---|---|---|")
        for route in routes:
            out.append("| %s | `%s` | `%s` |" % (route["family"],
                                                 route.get("gateway") or "—",
                                                 route.get("interface") or "—"))
        out.append("")
    out.append("**DNS** — %s" % (", ".join("`%s`" % s for s in (dns.get("servers") or []))
                                 or "none observed"))
    if dns.get("method"):
        out.append("")
        out.append("Source: `%s`%s" % (dns["method"],
                                       " (%s)" % dns["note"] if dns.get("note") else ""))
    out.append("")
    out.append("Addresses and routes describe local configuration. They do not prove "
               "that anything outside this host can reach it.")
    out.append("")

    time_data = data("time")
    out.append("## Time")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| Timezone | %s |" % (time_data.get("timezone") or "—"))
    out.append("| NTP provider | %s |" % (time_data.get("provider") or "none detected"))
    enabled = time_data.get("ntp_enabled")
    synced = time_data.get("synchronized")
    out.append("| NTP enabled | %s |" % {True: "yes", False: "no",
                                         None: "unknown"}[enabled])
    out.append("| **Clock synchronized** | %s |" % {True: "yes", False: "**NO**",
                                                    None: "unknown"}[synced])
    if time_data.get("source"):
        out.append("| Current source | `%s` (stratum %s) |"
                   % (time_data["source"], time_data.get("stratum")))
    if time_data.get("offset_nanoseconds") is not None:
        out.append("| Offset | %s ms |"
                   % round(time_data["offset_nanoseconds"] / 1e6, 3))
    out.append("")
    out.append("*NTP enabled and clock synchronized are different facts.* Configuration "
               "says what was intended; synchronization says what is true now.")
    if synced is False:
        out.append("")
        out.append("> **CLOCK_UNSYNCHRONIZED.** Event times observed on this host carry "
                   "no ordering guarantee (`REC-005`).")
    out.append("")

    out.append("## Collection completeness")
    out.append("")
    out.append("| Subdomain | Status | Method | Reason |")
    out.append("|---|---|---|---|")
    for row in report["collection_summary"]:
        out.append("| %s | %s | `%s` | %s |"
                   % (row["subdomain"], row["collection_status"],
                      row.get("method") or "—", row.get("reason") or "—"))
    out.append("")
    out.append("An incomplete observation is reported as incomplete. A missing tool is "
               "`NOT_TESTED`, a present tool that failed is `ERROR`, and neither is "
               "rendered as an empty success.")
    out.append("")

    out.append("## Limitations")
    out.append("")
    for limitation in report["limitations"]:
        out.append("- %s" % limitation)
    out.append("")
    return "\n".join(out) + "\n"
