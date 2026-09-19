# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Read-only platform and capability fingerprint for the W1-C campaign.
# Implements: SCOPE-022, IDENT-003, PRIV-004, STORE-001
#
# THIS FILE IS DELIBERATELY PYTHON 3.6 COMPATIBLE, unlike the rest of the project.
# RHEL 8's default python3 is 3.6, and a probe that crashes there cannot report the one
# fact that matters most on RHEL 8: which interpreter is available. A compatibility probe
# that requires the compatibility it is testing for is useless.
#
# It spawns NO subprocess and writes NOTHING. It is safe on a production fleet host.
#
# meta:type="tool"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Platform fingerprint. Reads files, never executes anything, never prints a secret."""
import datetime
import json
import os
import sys

PROBE_VERSION = 1
PYTHON_FLOOR = (3, 9)                       # D-12; not negotiable per distribution
MACHINE_ID = "/etc/machine-id"
READ_BOUND = 4096                           # IDENT-003
STATE_ROOT = "/var/lib/isedraf"
HEX = set("0123456789abcdefABCDEF")

# Commands later collectors will need. Presence only - nothing is executed (D-84, SCOPE-022).
CAPABILITY_BINARIES = [
    "sshd", "auditctl", "findmnt", "chronyc", "timedatectl", "journalctl",
    "systemctl", "getent", "cvtsudoers", "setpriv", "systemd-run",
]
SEARCH_DIRS = ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin",
               "/usr/local/bin"]


def read_text(path, limit=65536):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except (OSError, IOError):
        return None


def os_release():
    out = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        text = read_text(path)
        if not text:
            continue
        for line in text.splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            out[key.strip().lower()] = value.strip().strip('"').strip("'")
        break
    return {k: out.get(k) for k in
            ("id", "id_like", "version_id", "pretty_name", "variant_id", "name")}


def init_system():
    comm = read_text("/proc/1/comm")
    comm = comm.strip() if comm else None
    return {
        "pid1": comm,
        "systemd": comm == "systemd" or os.path.isdir("/run/systemd/system"),
    }


def interpreters():
    """Which python3.x are installed, found by path only - nothing is executed."""
    found = []
    for minor in range(6, 20):
        name = "python3.%d" % minor
        for directory in SEARCH_DIRS:
            candidate = os.path.join(directory, name)
            if os.path.exists(candidate):
                found.append({"version": "3.%d" % minor, "path": candidate})
                break
    running = "%d.%d.%d" % sys.version_info[:3]
    meets = sys.version_info[:2] >= PYTHON_FLOOR
    suitable = [i for i in found
                if tuple(int(p) for p in i["version"].split(".")) >= PYTHON_FLOOR]
    return {
        "running": running,
        "running_meets_floor": meets,
        "floor": "%d.%d" % PYTHON_FLOOR,
        "installed": found,
        "suitable_installed": suitable,
        # The distinction that decides the support tier: an OS whose DEFAULT python3 is
        # too old but which ships a suitable one is CONDITIONALLY_SUPPORTED, not
        # UNSUPPORTED - the prerequisite is an installation step, not a code change.
        "verdict": ("DEFAULT_INTERPRETER_SUFFICIENT" if meets
                    else ("SUITABLE_INTERPRETER_AVAILABLE" if suitable
                          else "NO_SUITABLE_INTERPRETER")),
    }


def machine_id_shape():
    """Does the source satisfy IDENT-003? Reported WITHOUT the value or any digest.

    A compatibility probe has no business exporting a host identifier, so this reports
    only the verdict the frozen grammar would reach.
    """
    result = {"path": MACHINE_ID, "present": False, "readable": False,
              "length_bytes": None, "expected_status": None, "expected_reason": None}
    if not os.path.exists(MACHINE_ID):
        result["expected_status"] = "NOT_TESTED"
        result["expected_reason"] = "SOURCE_ABSENT"
        return result
    result["present"] = True
    try:
        fd = os.open(MACHINE_ID, os.O_RDONLY)
    except (OSError, IOError):
        result["expected_status"] = "ERROR"
        result["expected_reason"] = "SOURCE_UNREADABLE"
        return result
    try:
        raw = os.read(fd, READ_BOUND + 1)
    finally:
        os.close(fd)
    result["readable"] = True
    result["length_bytes"] = len(raw)
    if len(raw) > READ_BOUND:
        result["expected_status"] = "ERROR"
        result["expected_reason"] = "SOURCE_UNREADABLE"
        return result
    body = raw[:-1] if raw.endswith(b"\n") else raw
    ok = (len(body) == 32 and b"\n" not in body and b"\r" not in body)
    if ok:
        try:
            text = body.decode("ascii")
        except UnicodeDecodeError:
            ok = False
        else:
            ok = all(c in HEX for c in text) and \
                text.lower() not in ("0" * 32, "uninitialized")
    result["expected_status"] = "COLLECTED" if ok else "ERROR"
    result["expected_reason"] = None if ok else "SYNTAX_REJECTED"
    return result


def state_root():
    parent = os.path.dirname(STATE_ROOT)
    info = {
        "path": STATE_ROOT,
        "exists": os.path.isdir(STATE_ROOT),
        "writable": os.access(STATE_ROOT, os.W_OK) if os.path.isdir(STATE_ROOT) else False,
        "parent_writable": os.access(parent, os.W_OK),
        "filesystem": None,
    }
    # flock semantics differ on network filesystems; the run lock depends on them.
    mounts = read_text("/proc/mounts") or ""
    best = ""
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) >= 3 and (parent + "/").startswith(parts[1].rstrip("/") + "/"):
            if len(parts[1]) >= len(best):
                best, info["filesystem"] = parts[1], parts[2]
    return info


def mac_state():
    selinux = None
    if os.path.isdir("/sys/fs/selinux"):
        enforce = read_text("/sys/fs/selinux/enforce")
        selinux = {"0": "permissive", "1": "enforcing"}.get(
            (enforce or "").strip(), "present")
    apparmor = None
    if os.path.isdir("/sys/module/apparmor"):
        enabled = read_text("/sys/module/apparmor/parameters/enabled")
        apparmor = "enabled" if (enabled or "").strip() in ("Y", "1") else "present"
    return {"selinux": selinux, "apparmor": apparmor}


def virtualization():
    hints = {}
    for key, path in (("sys_vendor", "/sys/class/dmi/id/sys_vendor"),
                      ("product_name", "/sys/class/dmi/id/product_name"),
                      ("hypervisor", "/sys/hypervisor/type")):
        value = read_text(path)
        hints[key] = value.strip() if value else None
    return hints


def capabilities():
    out = {}
    for name in CAPABILITY_BINARIES:
        path = None
        for directory in SEARCH_DIRS:
            candidate = os.path.join(directory, name)
            if os.path.exists(candidate):
                path = candidate
                break
        out[name] = path
    return out


def main():
    uname = os.uname()
    report = {
        "probe_version": PROBE_VERSION,
        "collected_at": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "os_release": os_release(),
        "kernel": {"release": uname.release, "version": uname.version},
        "architecture": uname.machine,
        "init": init_system(),
        "virtualization": virtualization(),
        "python": interpreters(),
        "machine_id": machine_id_shape(),
        "state_root": state_root(),
        "mac": mac_state(),
        "capabilities": capabilities(),
        "euid": os.geteuid(),
        "sudo_user_set": bool(os.environ.get("SUDO_USER")),
    }
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
