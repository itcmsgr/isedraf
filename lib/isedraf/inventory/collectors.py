# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The host inventory collectors — platform, machine, compute, storage,
#          network, DNS and time.
# Implements: SCOPE-022, SCOPE-045, REC-005, IDENT-041
#
# Capability-driven throughout. There is no `if rhel / elif debian` here and there is not
# meant to be: W1-C measured ten distributions and found the interpreter, not the
# distribution, to be the only boundary. A tool is either present or it is not, and that
# question has the same answer everywhere.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="ip,timedatectl,chronyc,findmnt (all optional, detected)"
# =============================================================================

"""Each collector returns a model.subdomain(); none of them raises."""
import json
import os
import re

from . import model
from ._exec import Outcome, read_file, read_lines, run, which

PROC = "/proc"
SYS = "/sys"


def _live(root):
    """True when we are inspecting the running system rather than a fixture root.

    A fixture root describes a FILESYSTEM. Running host commands against it mixes two
    different machines into one result: the CI runner reported its own timezone over a
    fixture's, and the test only passed locally because the two happened to match.
    """
    return root in ("/", "")


def _osrelease(root="/"):
    for candidate in ("etc/os-release", "usr/lib/os-release"):
        outcome = read_file(os.path.join(root, candidate))
        if outcome.ok:
            values = {}
            for line in outcome.value.splitlines():
                if "=" not in line or line.startswith("#"):
                    continue
                key, _, value = line.partition("=")
                values[key.strip().lower()] = value.strip().strip('"').strip("'")
            return values, outcome.source
    return None, None


# --- host naming -------------------------------------------------------------------------
def collect_host(root="/"):
    """Hostname from the kernel; FQDN only if it can be established LOCALLY.

    No resolver is consulted. A network lookup would make the inventory depend on DNS
    being up, and would let a DNS answer decide what this host is called.
    """
    outcome = read_file(os.path.join(root, "proc/sys/kernel/hostname"))
    if not outcome.ok:
        return model.subdomain(model.ERROR, {}, method="/proc/sys/kernel/hostname",
                               reason=outcome.reason)
    hostname = outcome.value.strip()
    fqdn, source, status = None, None, model.COLLECTED
    if "." in hostname:
        fqdn, source = hostname, "kernel hostname"
    else:
        hosts = read_lines(os.path.join(root, "etc/hosts"))
        if hosts.ok:
            for line in hosts.value:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                names = line.split()[1:]
                if hostname in names:
                    for name in names:
                        if "." in name and name.split(".")[0] == hostname:
                            fqdn, source = name, "/etc/hosts"
                            break
                if fqdn:
                    break
    if fqdn is None:
        # Stated, never fabricated: <hostname>.<some domain> would be an invention.
        #
        # And NOT a partial collection. Most standalone, lab and edge Linux hosts have no
        # locally resolvable FQDN; that is their normal state, not a failure to observe
        # one. Marking it PARTIAL would put almost every such host into an incomplete
        # report while CPU, memory, storage, network, DNS, time and identity were all
        # collected in full - which is how a status stops meaning anything.
        #
        # The absence is still reported, explicitly, in fqdn_source. Presence encodes
        # presence (NORM-040); it is not hidden, it is simply not a defect.
        source = "NOT_AVAILABLE_LOCALLY"
    return model.subdomain(status, {"hostname": hostname, "fqdn": fqdn,
                                    "fqdn_source": source},
                           method="/proc/sys/kernel/hostname + /etc/hosts")


# --- platform ----------------------------------------------------------------------------
def collect_platform(root="/"):
    values, source = _osrelease(root)
    uname = os.uname()
    init = read_file(os.path.join(root, "proc/1/comm"))
    data = {
        "id": (values or {}).get("id"),
        "version_id": (values or {}).get("version_id"),
        "pretty_name": (values or {}).get("pretty_name"),
        "family": (values or {}).get("id_like"),
        "kernel_release": uname.release,
        "architecture": uname.machine,
        "init_system": init.value.strip() if init.ok else None,
    }
    status = model.COLLECTED if values else model.PARTIAL
    return model.subdomain(status, data, method="%s + uname(2) + /proc/1/comm"
                           % (source or "os-release absent"),
                           reason=None if values
                           else "SOURCE_ABSENT: neither /etc/os-release nor "
                                "/usr/lib/os-release is readable")


# --- machine / virtualization -------------------------------------------------------------
def collect_machine(root="/"):
    """Deliberately excludes the DMI system UUID and every hardware serial."""
    def dmi(name):
        outcome = read_file(os.path.join(root, "sys/class/dmi/id", name))
        return outcome.value.strip() if outcome.ok and outcome.value.strip() else None

    hypervisor = None
    detect = run(["systemd-detect-virt"]) if _live(root) else Outcome(ok=False)
    if detect.ok:
        hypervisor = detect.value.strip()
    else:
        hv = read_file(os.path.join(root, "sys/hypervisor/type"))
        if hv.ok:
            hypervisor = hv.value.strip()
    if hypervisor in ("none", ""):
        hypervisor = None

    virtualized = None
    if hypervisor:
        virtualized = True
    else:
        cpuinfo = read_file(os.path.join(root, "proc/cpuinfo"))
        if cpuinfo.ok:
            virtualized = bool(re.search(r"^flags\s*:.*\bhypervisor\b", cpuinfo.value,
                                         re.M))
    data = {"virtualized": virtualized, "hypervisor": hypervisor,
            "vendor": dmi("sys_vendor"), "product": dmi("product_name")}
    known = [v for v in data.values() if v is not None]
    status = model.COLLECTED if len(known) >= 2 else model.PARTIAL
    return model.subdomain(
        status, data,
        method="systemd-detect-virt | /sys/hypervisor + /sys/class/dmi/id",
        reason=None if status == model.COLLECTED
        else "SOURCE_ABSENT: DMI is not exposed on this platform (common on ARM "
             "single-board computers) and no hypervisor could be identified")


# --- compute and memory --------------------------------------------------------------------
def collect_compute(root="/"):
    outcome = read_file(os.path.join(root, "proc/cpuinfo"))
    if not outcome.ok:
        return model.subdomain(model.ERROR, {}, method="/proc/cpuinfo",
                               reason=outcome.reason)
    vendor = modelname = None
    logical = 0
    sockets, cores = set(), None
    for block in outcome.value.split("\n\n"):
        if not block.strip():
            continue
        logical += 1
        for line in block.splitlines():
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if key == "vendor_id" and vendor is None:
                vendor = value
            elif key == "model name" and modelname is None:
                modelname = value
            elif key == "physical id":
                sockets.add(value)
            elif key == "cpu cores" and cores is None:
                try:
                    cores = int(value)
                except ValueError:
                    pass
    data = {"cpu_vendor": vendor, "cpu_model": modelname,
            "sockets": len(sockets) or None, "cores_per_socket": cores,
            "logical_cpus": logical or None}
    return model.subdomain(model.COLLECTED, data, method="/proc/cpuinfo")


def collect_memory(root="/"):
    outcome = read_file(os.path.join(root, "proc/meminfo"))
    if not outcome.ok:
        return model.subdomain(model.ERROR, {}, method="/proc/meminfo",
                               reason=outcome.reason)
    fields = {}
    for line in outcome.value.splitlines():
        key, _, value = line.partition(":")
        parts = value.split()
        if parts and parts[0].isdigit():
            fields[key.strip()] = int(parts[0]) * 1024        # kB in /proc/meminfo
    return model.subdomain(
        model.COLLECTED,
        {"total_bytes": fields.get("MemTotal"),
         "swap_total_bytes": fields.get("SwapTotal")},
        method="/proc/meminfo")


# --- storage -------------------------------------------------------------------------------
def collect_storage(root="/"):
    """Topology and mount configuration are separated from utilisation, which is volatile."""
    devices = []
    block = os.path.join(root, "sys/block")
    if os.path.isdir(block):
        for name in sorted(os.listdir(block)):
            if name.startswith(("loop", "ram", "zram", "dm-")):
                continue
            size = read_file(os.path.join(block, name, "size"))
            rotational = read_file(os.path.join(block, name, "queue/rotational"))
            devmodel = read_file(os.path.join(block, name, "device/model"))
            removable = read_file(os.path.join(block, name, "removable"))
            scsi_type = read_file(os.path.join(block, name, "device/type"))
            is_removable = removable.ok and removable.value.strip() == "1"

            # Order matters. `rotational == 0` is true of an optical drive as well as an
            # SSD, so the optical checks come FIRST - otherwise a DVD-ROM is reported as
            # solid-state storage, which is what the first published sample did.
            kind = model.DEVICE_UNKNOWN
            if name.startswith("nvme"):
                kind = model.DEVICE_NVME
            elif name.startswith(("sr", "scd")) or (
                    scsi_type.ok and scsi_type.value.strip() == "5"):   # SCSI TYPE_ROM
                kind = model.DEVICE_OPTICAL
            elif name.startswith("vd"):
                # virtio-blk. What backs it is not observable from the guest, so naming
                # the transport is the honest answer rather than guessing the medium.
                kind = model.DEVICE_VIRTUAL
            elif rotational.ok:
                kind = (model.DEVICE_ROTATIONAL if rotational.value.strip() == "1"
                        else model.DEVICE_SOLID_STATE)
            devices.append({
                "name": name,
                # /sys/block/*/size is in 512-byte sectors regardless of logical size.
                "size_bytes": int(size.value.strip()) * 512 if size.ok else None,
                "type": kind,
                "removable": is_removable,
                "model": devmodel.value.strip() if devmodel.ok else None,
            })

    filesystems, utilisation = [], []
    mounts = read_lines(os.path.join(root, "proc/self/mounts"))
    if mounts.ok:
        for line in mounts.value:
            parts = line.split()
            if len(parts) < 4:
                continue
            source, target, fstype, options = parts[0], parts[1], parts[2], parts[3]
            if fstype in ("proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2",
                          "securityfs", "pstore", "bpf", "tracefs", "debugfs",
                          "configfs", "fusectl", "mqueue", "hugetlbfs", "autofs",
                          "binfmt_misc", "efivarfs", "ramfs", "nsfs", "squashfs"):
                continue
            option_list = options.split(",")
            filesystems.append({
                "source": source, "mount_point": target, "fstype": fstype,
                "options": sorted(option_list),
                "read_only": "ro" in option_list,
            })
            try:
                st = os.statvfs(target)
            except OSError:
                continue
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            if total:
                utilisation.append({
                    "mount_point": target, "total_bytes": total,
                    "available_bytes": free,
                    # Per mille as an integer: NORM-035 forbids floats, and a percentage
                    # is a derived convenience anyway - the two byte counts above are the
                    # measurement. Renderers divide by ten; evidence keeps integers.
                    "used_permille": int(round((total - free) * 1000.0 / total)),
                })
    status = model.COLLECTED if (devices or filesystems) else model.PARTIAL
    return model.subdomain(status, {"devices": devices, "filesystems": filesystems,
                                    "utilisation": utilisation},
                           method="/sys/block + /proc/self/mounts + statvfs(2)",
                           reason=None if status == model.COLLECTED
                           else "SOURCE_ABSENT: neither /sys/block nor "
                                "/proc/self/mounts yielded any entry")


# --- network --------------------------------------------------------------------------------
def _classify_ipv6(address, scope, flags):
    """RFC 4941 temporary addresses are the reason this function exists."""
    if "temporary" in flags:
        return model.IPV6_TEMPORARY_PRIVACY
    if scope == "link":
        return model.IPV6_LINK_LOCAL
    if scope == "host" or address == "::1":
        return model.IPV6_LOOPBACK
    if scope == "global":
        return model.IPV6_GLOBAL_STABLE
    return model.IPV6_OTHER


def collect_network(root="/"):
    if not _live(root):
        return model.subdomain(model.NOT_TESTED, {}, method="ip(8)",
                               reason="NOT_TESTED: netlink is not readable from a "
                                      "fixture root")
    if which("ip") is None:
        return model.subdomain(model.NOT_TESTED, {}, method="ip(8)",
                               reason="NOT_TESTED")
    addr = run(["ip", "-json", "addr", "show"])
    route = run(["ip", "-json", "route", "show", "default"])
    route6 = run(["ip", "-json", "-6", "route", "show", "default"])
    if not addr.ok:
        return model.subdomain(model.ERROR, {}, method="ip -json addr",
                               reason=addr.reason)
    try:
        links = json.loads(addr.value)
    except ValueError:
        return model.subdomain(model.ERROR, {}, method="ip -json addr", reason="ERROR")

    interfaces, ipv4, ipv6_stable, ipv6_volatile = [], [], [], []
    for link in links:
        name = link.get("ifname")
        interfaces.append({"name": name, "state": link.get("operstate"),
                           "mtu": link.get("mtu"),
                           "loopback": "LOOPBACK" in (link.get("flags") or [])})
        for info in link.get("addr_info", []):
            family, address = info.get("family"), info.get("local")
            scope = info.get("scope", "")
            flags = [f for f in ("temporary", "permanent", "dynamic", "mngtmpaddr",
                                 "deprecated") if info.get(f)]
            if family == "inet":
                ipv4.append({"interface": name, "address": address,
                             "prefix_length": info.get("prefixlen"), "scope": scope,
                             "loopback": scope == "host" or address == "127.0.0.1"})
            elif family == "inet6":
                entry = {"interface": name, "address": address,
                         "prefix_length": info.get("prefixlen"), "scope": scope,
                         "classification": _classify_ipv6(address, scope, flags)}
                # A privacy address rotates on its own. Keeping it out of the stable set
                # is what stops normal IPv6 behaviour from reading as configuration drift.
                if entry["classification"] == model.IPV6_TEMPORARY_PRIVACY:
                    ipv6_volatile.append(entry)
                else:
                    ipv6_stable.append(entry)

    defaults = []
    for outcome, family in ((route, "inet"), (route6, "inet6")):
        if not outcome.ok:
            continue
        try:
            for entry in json.loads(outcome.value):
                defaults.append({"family": family, "gateway": entry.get("gateway"),
                                 "interface": entry.get("dev")})
        except ValueError:
            continue
    return model.subdomain(model.COLLECTED,
                           {"interfaces": interfaces, "ipv4": ipv4,
                            "ipv6_stable": ipv6_stable, "ipv6_volatile": ipv6_volatile,
                            "default_routes": defaults},
                           method="ip -json addr/route")


# --- DNS -------------------------------------------------------------------------------------
def collect_dns(root="/"):
    """resolv.conf alone is not effective DNS state when a local stub is in front of it."""
    servers, method, note = [], None, None
    stub = os.path.join(root, "run/systemd/resolve/resolv.conf")
    primary = os.path.join(root, "etc/resolv.conf")
    outcome = read_file(primary)
    if outcome.ok:
        method = "/etc/resolv.conf"
        for line in outcome.value.splitlines():
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                servers.append(parts[1])
    if servers and all(s.startswith("127.0.0.5") for s in servers):
        # A local stub resolver. The configured upstreams live elsewhere, and reporting
        # 127.0.0.53 as "the DNS servers" would be true and useless.
        note = "LOCAL_STUB_RESOLVER"
        upstream = read_file(stub)
        if upstream.ok:
            upstream_servers = [l.split()[1] for l in upstream.value.splitlines()
                                if l.split()[:1] == ["nameserver"] and len(l.split()) >= 2]
            if upstream_servers:
                servers = upstream_servers
                method = "/run/systemd/resolve/resolv.conf (upstream behind the stub)"
    if not outcome.ok:
        return model.subdomain(model.NOT_TESTED, {"servers": [], "method": None,
                                                  "note": None},
                               method=primary, reason=outcome.reason)
    return model.subdomain(model.COLLECTED if servers else model.PARTIAL,
                           {"servers": servers, "method": method, "note": note},
                           method=method, dimension=model.RESOLVED,
                           reason=None if servers
                           else "SOURCE_ABSENT: no nameserver entry was found")


# --- time --------------------------------------------------------------------------------------
def collect_time(root="/"):
    """NTP enabled and clock synchronized are different facts. Both are reported.

    `synchronized` is what REC-005 needs: when it is false, every event-time observation
    elsewhere must carry CLOCK_UNSYNCHRONIZED.
    """
    timezone = None
    link = os.path.join(root, "etc/localtime")
    try:
        target = os.readlink(link)
        if "zoneinfo/" in target:
            timezone = target.split("zoneinfo/", 1)[1]
    except OSError:
        tz = read_file(os.path.join(root, "etc/timezone"))
        if tz.ok:
            timezone = tz.value.strip() or None

    uptime, seconds = read_file(os.path.join(root, "proc/uptime")), None
    if uptime.ok:
        try:
            seconds = int(float(uptime.value.split()[0]))
        except (ValueError, IndexError):
            pass

    data = {"timezone": timezone, "provider": None, "ntp_enabled": None,
            "synchronized": None, "source": None, "stratum": None,
            "offset_nanoseconds": None, "uptime_seconds": seconds}
    method, status = "/etc/localtime + /proc/uptime", model.PARTIAL
    partial_reason = ("NOT_TESTED: timedatectl is unavailable, so NTP configuration and "
                      "clock synchronization state could not be resolved")

    timedatectl = run(["timedatectl", "show"]) if _live(root) else Outcome(ok=False)
    if timedatectl.ok:
        properties = {}
        for line in timedatectl.value.splitlines():
            key, _, value = line.partition("=")
            properties[key.strip()] = value.strip()
        if properties.get("Timezone"):
            data["timezone"] = properties["Timezone"]
        if "NTP" in properties:
            data["ntp_enabled"] = properties["NTP"] == "yes"
        if "NTPSynchronized" in properties:
            data["synchronized"] = properties["NTPSynchronized"] == "yes"
        method, status = "timedatectl show", model.COLLECTED

    for candidate, name in (("chronyc", "chrony"), ("ntpq", "ntpd")):
        if _live(root) and which(candidate):
            data["provider"] = name
            break
    if data["provider"] is None:
        if os.path.exists(os.path.join(root, "run/systemd/timesync")):
            data["provider"] = "systemd-timesyncd"

    if data["provider"] == "chrony" and _live(root):
        tracking = run(["chronyc", "-n", "tracking"])
        if tracking.ok:
            for line in tracking.value.splitlines():
                key, _, value = line.partition(":")
                key, value = key.strip(), value.strip()
                if key == "Reference ID":
                    data["source"] = value.split()[0] if value else None
                elif key == "Stratum":
                    try:
                        data["stratum"] = int(value)
                    except ValueError:
                        pass
                elif key == "System time":
                    m = re.match(r"([0-9.]+)", value)
                    if m:
                        # Integer nanoseconds: NORM-035 forbids floats in canonical
                        # form, and a measurement that cannot be serialized
                        # deterministically has no business in evidence.
                        data["offset_nanoseconds"] = int(round(float(m.group(1)) * 1e9))
            method += " + chronyc tracking"
    return model.subdomain(status, data, method=method, dimension=model.RESOLVED,
                           reason=None if status == model.COLLECTED
                           else partial_reason)
