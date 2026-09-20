# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The normalized host inventory object, and what each field MEANS over time.
# Implements: SCOPE-045, SCOPE-063, REC-005, NORM-034
#
# The classification is the point of this file. Collecting a CPU model is easy; deciding
# that a changed CPU model is NOT a security configuration delta is the part that keeps
# the tool quiet on a live-migrated VM.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Field classification, collection status, and the shape of the inventory object."""

# --- how a field behaves over time ------------------------------------------------------
PLATFORM_FACT = "PLATFORM_FACT"
# Identifies the operating system itself. A change is a real, reportable event.

INVENTORY_FACT = "INVENTORY_FACT"
# Describes the machine's shape. Stable in practice, and a change is worth reporting -
# but not necessarily a security regression.

HARDWARE_OBSERVATION = "HARDWARE_OBSERVATION"
# CPU model, core counts, RAM capacity, disk topology. Legitimately changes on a
# live-migrated or hot-plugged VM, so it SHALL NOT drive an ordinary configuration delta.
# SCOPE-063 already names the correct outcome: SAME_HOST_HARDWARE_CHANGED.

NETWORK_CONFIGURATION = "NETWORK_CONFIGURATION"
# Interfaces, stable addresses, routes, resolvers. Security-relevant configuration.

VOLATILE_OBSERVATION = "VOLATILE_OBSERVATION"
# Uptime, filesystem utilisation, NTP offset, RFC 4941 privacy addresses, the current
# NTP peer. These change constantly WITHOUT anything having been configured, and
# reporting them as drift is how a tool teaches its operator to ignore it.

# --- collection status (SCOPE-022, IDENT-004 vocabulary) --------------------------------
COLLECTED = "COLLECTED"
PARTIAL = "PARTIAL"
NOT_TESTED = "NOT_TESTED"
ERROR = "ERROR"

# --- block device classes ---------------------------------------------------------------
# `rotational == 0` does not mean "SSD". An optical drive reports 0 too, which is how a
# QEMU DVD-ROM was classified as SOLID_STATE in the first sample report anyone read.
# D-114: the overloaded `type` enum is RETIRED, not deprecated. It conflated kernel
# subsystem (NVME, VIRTUAL), block-queue behaviour (ROTATIONAL, SOLID_STATE) and
# peripheral class (OPTICAL) into one apparently authoritative answer, and the
# `rotational == 0 -> SOLID_STATE` branch made an SD card a solid-state drive and,
# before that, a DVD-ROM one.
#
# A convenient but semantically broken field that remains readable continues to be read,
# so there is no compatibility alias. Replaced by the dimensions Linux actually exposes:
# kernel_subsystem, queue_rotational, kernel_removable, scsi_peripheral_type.
#
# STORAGE-SEMANTICS-001:
#   queue_rotational = false   MUST NOT imply SOLID_STATE
#   kernel_subsystem = scsi    MUST NOT imply SATA / SAS / USB / iSCSI / FC
#   kernel_subsystem = nvme    MUST NOT imply a solid-state physical medium
#   a block-layer object       MUST NOT be assumed to represent one physical device

# --- IPv6 address classes ---------------------------------------------------------------
# Flattening these is how privacy addresses become permanent false churn: RFC 4941
# temporary addresses rotate by design, several times a day, with nothing configured.
IPV6_GLOBAL_STABLE = "GLOBAL_STABLE"
IPV6_TEMPORARY_PRIVACY = "TEMPORARY_PRIVACY"
IPV6_LINK_LOCAL = "LINK_LOCAL"
IPV6_LOOPBACK = "LOOPBACK"
IPV6_OTHER = "OTHER"
IPV6_UNKNOWN = "UNKNOWN"

# --- state dimension (SCOPE-020/SCOPE-021 vocabulary) -----------------------------------
DECLARED = "DECLARED"
RESOLVED = "RESOLVED"
ACTIVE = "ACTIVE"
NOT_APPLICABLE = "NOT_APPLICABLE"

INVENTORY_SCHEMA_VERSION = 1

# Every subdomain the inventory declares. Present in the output even when empty, because
# a missing key and an empty result are different statements (NORM-034).
SUBDOMAINS = ("host", "platform", "machine", "compute", "memory", "storage",
              "network", "dns", "time")

# The classification of every field the inventory emits. An unclassified field is a
# defect, not a default (SCOPE-045), and `test_inventory.py` asserts this table covers
# everything actually produced.
CLASSIFICATION = {
    "host.hostname": PLATFORM_FACT,
    "host.fqdn": PLATFORM_FACT,
    "host.fqdn_source": PLATFORM_FACT,
    "platform.id": PLATFORM_FACT,
    "platform.version_id": PLATFORM_FACT,
    "platform.pretty_name": PLATFORM_FACT,
    "platform.family": PLATFORM_FACT,
    "platform.kernel_release": PLATFORM_FACT,
    "platform.architecture": PLATFORM_FACT,
    "platform.init_system": PLATFORM_FACT,
    "machine.virtualized": INVENTORY_FACT,
    "machine.hypervisor": INVENTORY_FACT,
    "machine.vendor": INVENTORY_FACT,
    "machine.product": INVENTORY_FACT,
    "compute.cpu_vendor": HARDWARE_OBSERVATION,
    "compute.cpu_model": HARDWARE_OBSERVATION,
    "compute.sockets": HARDWARE_OBSERVATION,
    "compute.cores_per_socket": HARDWARE_OBSERVATION,
    "compute.logical_cpus": HARDWARE_OBSERVATION,
    "memory.total_bytes": HARDWARE_OBSERVATION,
    "memory.swap_total_bytes": HARDWARE_OBSERVATION,
    "storage.devices": HARDWARE_OBSERVATION,
    "storage.filesystems": NETWORK_CONFIGURATION,   # mount options are configuration
    "storage.utilisation": VOLATILE_OBSERVATION,
    "network.interfaces": NETWORK_CONFIGURATION,
    "network.ipv4": NETWORK_CONFIGURATION,
    "network.ipv6_stable": NETWORK_CONFIGURATION,
    "network.ipv6_volatile": VOLATILE_OBSERVATION,
    "network.default_routes": NETWORK_CONFIGURATION,
    "dns.servers": NETWORK_CONFIGURATION,
    "dns.method": NETWORK_CONFIGURATION,
    "dns.note": NETWORK_CONFIGURATION,
    "time.timezone": NETWORK_CONFIGURATION,
    "time.provider": NETWORK_CONFIGURATION,
    "time.ntp_enabled": NETWORK_CONFIGURATION,
    "time.synchronized": VOLATILE_OBSERVATION,
    "time.source": VOLATILE_OBSERVATION,
    "time.stratum": VOLATILE_OBSERVATION,
    "time.offset_nanoseconds": VOLATILE_OBSERVATION,
    "time.uptime_seconds": VOLATILE_OBSERVATION,
}

# Fields whose value legitimately changes on an otherwise untouched host. The noise test
# asserts that everything OUTSIDE this set is stable across repeated collection.
VOLATILE_FIELDS = frozenset(
    k for k, v in CLASSIFICATION.items() if v == VOLATILE_OBSERVATION)


def subdomain(status, data, method=None, reason=None, dimension=ACTIVE):
    """One subdomain result. Status and data never contradict each other.

    An empty result with status COLLECTED would be a lie; callers that found nothing
    report NOT_TESTED or ERROR with the reason, which is what SCOPE-022 requires.

    A status other than COLLECTED REQUIRES a reason. The report tells its reader that
    incomplete observations explain themselves, and a PARTIAL row with an em dash in the
    reason column makes that sentence false.
    """
    if status != COLLECTED and not reason:
        raise ValueError(
            "collection status %s requires a reason: an unexplained incomplete "
            "observation tells the reader nothing" % status)
    return {"collection_status": status, "reason": reason, "method": method,
            "state_dimension": dimension, "data": data}
