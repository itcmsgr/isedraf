<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED SAMPLE — real output from `isedraf report` on a DISPOSABLE lab VM
     (AlmaLinux 9.7, KVM, Python 3.9.25), 2026-09-18. Unedited apart from this header.
     Identifiers and timestamps were pinned so the sample is stable across regeneration.
     No production host appears in this repository. -->

# ISEDRAF System Assurance Report

| | |
|---|---|
| Report ID | `RPT-FIXED` |
| Generated (UTC) | 2026-09-18T00:00:00Z |
| ISEDRAF version | 0.0.0-pre |
| Report status | **COMPLETE** |

> This report describes what was **observed**. It contains no secure/insecure verdict, because host inventory is evidence and a score would be a judgement the data does not support.

## Assessment

| | |
|---|---|
| Prepared by | A. Reviewer |
| Organization | ITCMS |
| Customer | Example Company S.A. |
| Reference | AUDIT-2026-017 |

## Target

| | |
|---|---|
| Hostname | isd-a9 |
| FQDN | *not resolvable locally — no resolver was consulted* |
| Host ID | `sha256:672ebe0048dd70ce5695bae49ac535c13caaf344e0c8833f84c5f1fcb46bf746` |

## Evidence

### Host identity — W1-A CERTIFIED — snapshot-bound, manifest-hashed, ledger-chained

| | |
|---|---|
| Snapshot ID | `SDS-20260918T173825Z-e4d0e8596510180c` |
| Manifest hash | `sha256:053313f08b9f173212225d855937b01f43dfa2f4e336421f89e8718aad2d6f1a` |
| State hash | `sha256:fb74919253ca54f43a12b3260cc13e1651b9d8065e68fcad3161d5c071efe63d` |
| Ledger record | sequence 1, `sha256:ccb6f10f5214a4c36dd39032ff31f197eb3091a6adc819429d8378e37868a66e` |
| Collection status | COLLECTED |
| Evidence root | `/tmp/tmpiv5d2cqc/state` (DEV) |
| Independent verification | **PASS** — every hash recomputed from the stored preimages |

### Host inventory — W1-C1 — collected and normalized, bound by an artifact digest. NOT part of the frozen W1-A snapshot contract (SNAP-021)

| | |
|---|---|
| Collection ID | `INV-20260918T000000Z-0000000000000000` |
| Artifact digest | `sha256:528c0c991f4f59b12463767aaef828d0f7cab70c7b2a0aa5980d42b26b984560` |
| Collected (UTC) | 2026-09-18T00:00:00Z |
| Inventory schema | 1 |
| Collection status | COLLECTED |

The artifact digest is a content SHA-256 over the deterministic inventory artifact. It is **not** a snapshot hash and the inventory is **not** inside the frozen snapshot.

## Platform

| | |
|---|---|
| Operating system | AlmaLinux 9.7 (Moss Jungle Cat) |
| Version | 9.7 |
| Family | rhel centos fedora |
| Kernel | `5.14.0-611.45.1.el9_7.x86_64` |
| Architecture | x86_64 |
| Init system | systemd |
| Machine | virtual |
| Hypervisor | kvm |
| Vendor / product | QEMU / Ubuntu 24.04 PC v2 (i440FX + PIIX, arch_caps fix, 1996) |

## Compute and memory

*Hardware observations. They change legitimately on virtualized hosts and do not by themselves indicate configuration drift.*

| | |
|---|---|
| CPU | Intel(R) Xeon(R) CPU E5-2640 0 @ 2.50GHz |
| Vendor | GenuineIntel |
| Sockets / cores per socket | 2 / 1 |
| Logical CPUs | 2 |
| Memory | 1.9 GiB |
| Swap | — |

## Storage

| Device | Size | Class | Removable | Model |
|---|---|---|---|---|
| `sda` | 12.9 GB | ROTATIONAL | no | QEMU HARDDISK |
| `sr0` | 0.0 GB | OPTICAL | yes | QEMU DVD-ROM |

| Mount point | Source | Type | Mode | Options |
|---|---|---|---|---|
| `/dev/shm` | `tmpfs` | tmpfs | read-write | `inode64,nodev,nosuid,rw,seclabel` |
| `/run` | `tmpfs` | tmpfs | read-write | `inode64,mode=755,nodev,nosuid,nr_inodes=819200,rw` |
| `/` | `/dev/sda4` | xfs | read-write | `attr2,inode64,logbsize=32k,logbufs=8,noquota,relatime` |
| `/sys/fs/selinux` | `selinuxfs` | selinuxfs | read-write | `noexec,nosuid,relatime,rw` |
| `/boot` | `/dev/sda3` | xfs | read-write | `attr2,inode64,logbsize=32k,logbufs=8,noquota,relatime` |
| `/boot/efi` | `/dev/sda2` | vfat | read-write | `codepage=437,dmask=0077,errors=remount-ro,fmask=0077,iocharset=ascii,relatime` |
| `/var/lib/nfs/rpc_pipefs` | `sunrpc` | rpc_pipefs | read-write | `relatime,rw` |
| `/run/user/1000` | `tmpfs` | tmpfs | read-write | `gid=1000,inode64,mode=700,nodev,nosuid,nr_inodes=50255` |

**Utilisation** — a volatile observation, not configuration:

| Mount point | Used |
|---|---|
| `/dev/shm` | 0.0% |
| `/run` | 1.4% |
| `/` | 7.7% |
| `/boot` | 14.9% |
| `/boot/efi` | 3.7% |
| `/run/user/1000` | 0.0% |

## Network

| Interface | State | MTU |
|---|---|---|
| `eth0` | UP | 1500 |

**IPv4**

| Address | Interface | Scope |
|---|---|---|
| `192.168.122.54/24` | `eth0` | global |

**IPv6**

| Address | Interface | Classification |
|---|---|---|
| `fe80::5054:ff:fed8:b374/64` | `eth0` | LINK_LOCAL |

| Default route | Gateway | Interface |
|---|---|---|
| inet | `192.168.122.1` | `eth0` |

**DNS** — `192.168.122.1`

Source: `/etc/resolv.conf`

Addresses and routes describe local configuration. They do not prove that anything outside this host can reach it.

## Time

| | |
|---|---|
| Timezone | UTC |
| NTP provider | chrony |
| NTP enabled | yes |
| **Clock synchronized** | yes |
| Current source | `A29FC801` (stratum 4) |
| Offset | 0.131 ms |

*NTP enabled and clock synchronized are different facts.* Configuration says what was intended; synchronization says what is true now.

## Collection completeness

| Subdomain | Status | Method | Reason |
|---|---|---|---|
| host | COLLECTED | `/proc/sys/kernel/hostname + /etc/hosts` | — |
| platform | COLLECTED | `/etc/os-release + uname(2) + /proc/1/comm` | — |
| machine | COLLECTED | `systemd-detect-virt | /sys/hypervisor + /sys/class/dmi/id` | — |
| compute | COLLECTED | `/proc/cpuinfo` | — |
| memory | COLLECTED | `/proc/meminfo` | — |
| storage | COLLECTED | `/sys/block + /proc/self/mounts + statvfs(2)` | — |
| network | COLLECTED | `ip -json addr/route` | — |
| dns | COLLECTED | `/etc/resolv.conf` | — |
| time | COLLECTED | `timedatectl show + chronyc tracking` | — |

An incomplete observation is reported as incomplete. A missing tool is `NOT_TESTED`, a present tool that failed is `ERROR`, and neither is rendered as an empty success.

## Limitations

- Host identity derives from a locally readable machine identity. It is not remote attestation, and a local root adversary can change the source it derives from.
- Cloned systems share a machine identity when cloning did not regenerate it, so two hosts can legitimately present the same host_id.
- Hardware facts — CPU model, core counts, memory capacity, disk topology — are observations, not configuration. They change legitimately on virtualized hosts and do not by themselves indicate drift.
- Network addresses and routes describe local configuration. They do not prove that anything outside this host can reach it.
- Configured DNS servers are what this host is told to use. No query was performed, so nothing here describes resolution behaviour.
- Host inventory is not part of the frozen snapshot contract. It is bound to this report by an artifact digest, which is a content digest and not a snapshot hash.
- Assessment details identify the person or organization declared in the report metadata. They are declarative and are NOT cryptographically authenticated; this report is not signed.

