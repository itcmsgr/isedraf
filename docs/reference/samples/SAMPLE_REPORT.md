<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE - DO NOT EDIT MANUALLY.
     Source: docs/reference/samples/evidence/ (committed evidence bytes)
     Regenerate: python3 scripts/docs/sample_report.py generate
     `make check` fails when this file and the evidence disagree.

     Real `isedraf report` output from a disposable Debian 12 VM, collected with the
     released 0.1.0-alpha1 package by an unprivileged user. The report identifier and
     generation timestamp are pinned to the values of that collection so the document is
     stable; nothing else is edited, and no value is supplied by hand. -->

# ISEDRAF System Assurance Report

| | |
|---|---|
| Report ID | `RPT-20260920T171548Z-71072fdd5e6cd97e` |
| Generated (UTC) | 2026-09-20T17:15:48Z |
| ISEDRAF version | 0.1.0-alpha1 |
| Report status | **COMPLETE** |

> This report describes what was **observed**. It contains no secure/insecure verdict, because host inventory is evidence and a score would be a judgement the data does not support.

## Target

| | |
|---|---|
| Hostname | isd-sample |
| FQDN | *not resolvable locally — no resolver was consulted* |
| Host ID | `sha256:4d3e3c2abb1f71c13a45ba590cda91e3ded6c7ccdc3f28dc63b5ac20f74dcfd1` |

## Evidence

### Host identity — W1-A CERTIFIED — snapshot-bound, manifest-hashed, ledger-chained

| | |
|---|---|
| Snapshot ID | `SDS-20260920T171541Z-4810e53a3805777d` |
| Manifest hash | `sha256:32f41a2a89693063b85580791a257363833f0438f32732a645ec63fbcdd09c8f` |
| State hash | `sha256:8a69abe5f51d61d333818427118548224c0bc9d3efb31415e7355caf60e8d5b4` |
| Ledger record | sequence 1, `sha256:1dab505f28bdb65d63fe62e1ecaeecb4f099e6ef4b4109bd6784b2a319f12698` |
| Collection status | COLLECTED |
| Evidence root | `docs/reference/samples/evidence/state-root` (DEV) |
| Independent verification | **PASS** — every hash recomputed from the stored preimages |

### Host inventory — W1-C1 — collected and normalized, bound by an artifact digest. NOT part of the frozen W1-A snapshot contract (SNAP-021)

| | |
|---|---|
| Collection ID | `INV-20260920T171548Z-11885ac7cb292572` |
| Artifact digest | `sha256:267f19bf54a7532559919a57e6b6b12c34db87d8c80141369e64c237b7e8f010` |
| Collected (UTC) | 2026-09-20T17:15:48Z |
| Inventory schema | 1 |
| Collection status | COLLECTED |

The artifact digest is a content SHA-256 over the deterministic inventory artifact. It is **not** a snapshot hash and the inventory is **not** inside the frozen snapshot.

## Platform

| | |
|---|---|
| Operating system | Debian GNU/Linux 12 (bookworm) |
| Version | 12 |
| Family | — |
| Kernel | `6.1.0-53-cloud-amd64` |
| Architecture | x86_64 |
| Init system | systemd |
| Machine | virtual |
| Hypervisor | kvm |
| Vendor / product | QEMU / Ubuntu 24.04 PC (Q35 + ICH9, 2009) |

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

| Device | Size | Kernel subsystem | Queue rotational | Kernel removable flag | Vendor | Model |
|---|---|---|---|---|---|---|
| `vda` | 6.4 GB | virtio | true | false | 0x1af4 | — |

*Kernel-reported block-device attributes. `Queue rotational` and `Kernel removable flag` describe how Linux presents the block queue; neither establishes the physical storage medium, and a block device does not necessarily correspond to one physical disk (D-114).*

| Mount point | Source | Type | Mode | Options |
|---|---|---|---|---|
| `/run` | `tmpfs` | tmpfs | read-write | `inode64,mode=755,nodev,noexec,nosuid,relatime` |
| `/` | `/dev/vda1` | ext4 | read-write | `discard,errors=remount-ro,relatime,rw` |
| `/dev/shm` | `tmpfs` | tmpfs | read-write | `inode64,nodev,nosuid,rw` |
| `/run/lock` | `tmpfs` | tmpfs | read-write | `inode64,nodev,noexec,nosuid,relatime,rw` |
| `/boot/efi` | `/dev/vda15` | vfat | read-write | `codepage=437,dmask=0022,errors=remount-ro,fmask=0022,iocharset=ascii,relatime` |
| `/run/user/1000` | `tmpfs` | tmpfs | read-write | `gid=1000,inode64,mode=700,nodev,nosuid,nr_inodes=50675` |

**Utilisation** — a volatile observation, not configuration:

| Mount point | Used |
|---|---|
| `/run` | 0.3% |
| `/` | 17.3% |
| `/dev/shm` | 0.0% |
| `/run/lock` | 0.0% |
| `/boot/efi` | 9.5% |
| `/run/user/1000` | 0.0% |

## Network

| Interface | State | MTU |
|---|---|---|
| `enp1s0` | UP | 1500 |

**IPv4**

| Address | Interface | Scope |
|---|---|---|
| `192.168.122.128/24` | `enp1s0` | global |

**IPv6**

| Address | Interface | Classification |
|---|---|---|
| `fe80::5054:ff:fe9c:1a7c/64` | `enp1s0` | LINK_LOCAL |

| Default route | Gateway | Interface |
|---|---|---|
| inet | `192.168.122.1` | `enp1s0` |

**DNS** — `192.168.122.1`

Source: `/etc/resolv.conf`

Addresses and routes describe local configuration. They do not prove that anything outside this host can reach it.

## Time

| | |
|---|---|
| Timezone | Etc/UTC |
| NTP provider | systemd-timesyncd |
| NTP enabled | yes |
| **Clock synchronized** | yes |

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
| time | COLLECTED | `timedatectl show` | — |

An incomplete observation is reported as incomplete. A missing tool is `NOT_TESTED`, a present tool that failed is `ERROR`, and neither is rendered as an empty success.

## Limitations

- Host identity derives from a locally readable machine identity. It is not remote attestation, and a local root adversary can change the source it derives from.
- Cloned systems share a machine identity when cloning did not regenerate it, so two hosts can legitimately present the same host_id.
- Hardware facts — CPU model, core counts, memory capacity, disk topology — are observations, not configuration. They change legitimately on virtualized hosts and do not by themselves indicate drift.
- Network addresses and routes describe local configuration. They do not prove that anything outside this host can reach it.
- Configured DNS servers are what this host is told to use. No query was performed, so nothing here describes resolution behaviour.
- Host inventory is not part of the frozen snapshot contract. It is bound to this report by an artifact digest, which is a content digest and not a snapshot hash.
- Assessment details identify the person or organization declared in the report metadata. They are declarative and are NOT cryptographically authenticated; this report is not signed.

