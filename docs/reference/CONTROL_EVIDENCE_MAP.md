<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Control & Evidence Map

Status: EXPERIMENTAL · Canonical source for control-to-evidence mapping. A PDF, when one exists, is
generated from this file and never maintained beside it.

## What this is

One row per fact ISEDRAF observes, answering six questions from the same line:

```text
CONTROL / FACT
    ↓  what do we expect from the system?
    ↓  where does the operating system keep it?
    ↓  how did ISEDRAF actually observe it?
    ↓  which normalized field represents it?
    ↓  where is the evidence stored?
    ↓  what may, and may not, be concluded?
```

**This is not a compliance checklist.** It says what is observed, where it came from, how it is
represented, where it is kept, and — the column that matters most to an auditor — what the observation
does *not* prove. ISEDRAF records host technical facts; it never converts them into a claim of
organizational compliance.

## Why it is nearly empty

A row here means the fact **is collected today**, by code, into a named field, in a locatable artifact.
Writing rows for domains that are not implemented would turn a reference document into a design sketch,
and the first operator to follow one to a field that does not exist would be right to stop trusting the
rest of the page.

**One domain is implemented. It has a complete row. Every other domain gains its row in the milestone that
implements it** — see the engineering-debt table in [the roadmap](../roadmap/ROADMAP.md).

## The two status vocabularies never merge

| Collection status | Meaning |
|---|---|
| `COLLECTED` | the fact was observed |
| `NOT_TESTED` | it was not observable here — no source, no privilege, no tool |
| `ERROR` | the source existed and observation failed |
| `PARTIAL` | some of the domain was observed |

| Evaluation result | Meaning |
|---|---|
| `PASS` · `FAIL` | the observed state was compared with an approved baseline or criterion |
| `MISMATCH` | two dimensions of the same fact disagree |
| `MANUAL_REVIEW` · `NOT_APPLICABLE` · `NOT_EVALUATED` | judgement is required, or none was made |

**A collection failure never becomes `PASS` or `FAIL`.** "We could not look" and "we looked and it is
wrong" are different statements, and a tool that merges them is lying in whichever direction is
convenient. Evaluation does not exist yet: it is W1-C.

## State dimension

| Dimension | Means | Example |
|---|---|---|
| `DECLARED` | what a configuration file says | `sshd_config` on disk |
| `RESOLVED` | what the subsystem computes from its configuration | `sshd -T` |
| `ACTIVE` | what the running system is doing | the live daemon, a mounted filesystem |

These are never equated. A `DECLARED` setting is what an administrator wrote; it is not proof of effective
state, and a running daemon may predate the file it was configured from. Where a domain has no meaningful
distinction, the dimension is marked `NOT_APPLICABLE` rather than guessed.

## Assessment class

`FACT` · `CRITERION` · `HOST_TECHNICAL` · `HOST_SUPPORTING_EVIDENCE` · `MANUAL_ORGANIZATIONAL` ·
`NOT_HOST_ASSESSABLE`. An organizational control never appears as locally measurable.

## Host Identity — IMPLEMENTED

| | |
|---|---|
| **Domain** | Host Identity |
| **Fact** | the local machine identity, as a derived identifier |
| **Implementation status** | IMPLEMENTED (W1-B) |
| **Assessment class** | `FACT` / `HOST_TECHNICAL` |
| **State dimension** | `RESOLVED` — the value is read and normalized; there is no separate declared or active form |
| **Expected from the system** | `/etc/machine-id` exists, is readable, and contains exactly 32 hexadecimal characters with at most one trailing newline |
| **System source** | `/etc/machine-id` |
| **Effective collector** | a direct bounded read — at most 4096 bytes, no subprocess, no shell |
| **Native setting or parameter** | the machine-id value itself; there is no tunable parameter |
| **Normalized ISEDRAF field** | `host_id` — `"sha256:" + hex(HASH_FRAME_V1("ISEDRAF:HOST-ID:V1", utf8(normalized machine-id)))` |
| **Evidence artifact** | `state/host_identity.json` — the hashed state object, exactly `{"host_id":"sha256:…"}` |
| **Provenance artifact** | `method/host_identity.json` — collector, parser and classification-table versions, `source_id`, `identity_scheme` |
| **Persistent location** | `/var/lib/isedraf/snapshots/SDS-<ts>-<id>/` |
| **Collection status** | `COLLECTED` · `NOT_TESTED` (source absent) · `ERROR` (unreadable, or rejected by the grammar) |
| **Reason vocabulary** | `SOURCE_ABSENT` · `SOURCE_UNREADABLE` · `SYNTAX_REJECTED` · `INTERNAL_ERROR` |
| **Evaluation / interpretation** | `NOT_EVALUATED` — comparison and delta are W1-C |
| **Explain / manual verification** | `isedraf explain` is PLANNED. Today: compare the rendered `host_id` with the `state_hash` in the snapshot manifest, and re-derive both from `state/host_identity.json` |

### What a `COLLECTED` host identity does **not** prove

- **It does not prove the host is unique.** A cloned VM carries its source's machine-id, so two hosts can
  present the same `host_id`. Clone and rollback detection needs the composite anchors that are not in
  this freeze set.
- **It does not prove the host is the one you think it is.** The identifier is derived from a file a local
  root adversary can rewrite. It binds evidence to a *claimed* identity, not to hardware.
- **It does not prove continuity.** Re-imaging a host regenerates the machine-id; the new `host_id` is a
  new identity, and ISEDRAF reports a different host rather than a changed one.
- **It is not a hardware serial and is not reversible.** The raw machine-id never appears in canonical
  state, in exports, or in the default CLI output.
- **`NOT_TESTED` is not "no identity".** It means the source was absent when we looked.

### Where each answer comes from

| Question | Answer |
|---|---|
| Which Linux setting do I inspect? | `/etc/machine-id` |
| What evidence supports this fact? | `state/host_identity.json` and `method/host_identity.json` inside the snapshot, bound by `manifest.json`'s hashes |
| Which field implements the requirement? | `host_id`, per `IDENT-002` and `IDENT-005` |

## Host Inventory — IMPLEMENTED (W1-C1)

Nine subdomains, each carrying its own collection status, method and state dimension. Collection is
**capability-driven**: a tool is either present or it is not, and that question has the same answer on
every distribution. There is no `if rhel / elif debian` anywhere in it.

| Fact | System source | Collector / method | Normalized field | Classification |
|---|---|---|---|---|
| hostname | kernel | `/proc/sys/kernel/hostname` | `host.hostname` | `PLATFORM_FACT` |
| FQDN | `/etc/hosts`, or a dotted kernel hostname | local lookup only — **no resolver is consulted** | `host.fqdn`, `host.fqdn_source` | `PLATFORM_FACT` |
| OS and version | `/etc/os-release` | direct read | `platform.id`, `platform.version_id`, `platform.pretty_name`, `platform.family` | `PLATFORM_FACT` |
| kernel, architecture | kernel | `uname(2)` | `platform.kernel_release`, `platform.architecture` | `PLATFORM_FACT` |
| init system | kernel | `/proc/1/comm` | `platform.init_system` | `PLATFORM_FACT` |
| virtualization | DMI, hypervisor node, CPU flags | `systemd-detect-virt`, else `/sys/hypervisor/type`, else the `hypervisor` CPU flag | `machine.virtualized`, `machine.hypervisor` | `INVENTORY_FACT` |
| vendor, product | DMI | `/sys/class/dmi/id` — **never the system UUID or any serial** | `machine.vendor`, `machine.product` | `INVENTORY_FACT` |
| CPU | kernel | `/proc/cpuinfo` | `compute.cpu_vendor`, `compute.cpu_model`, `compute.sockets`, `compute.cores_per_socket`, `compute.logical_cpus` | `HARDWARE_OBSERVATION` |
| memory, swap | kernel | `/proc/meminfo`, converted to **bytes** | `memory.total_bytes`, `memory.swap_total_bytes` | `HARDWARE_OBSERVATION` |
| block devices | kernel | `/sys/block` — size is in 512-byte sectors regardless of logical block size | `storage.devices` | `HARDWARE_OBSERVATION` |
| filesystems, mount options | kernel | `/proc/self/mounts` | `storage.filesystems` | `NETWORK_CONFIGURATION` |
| filesystem utilisation | kernel | `statvfs(2)` | `storage.utilisation` | **`VOLATILE_OBSERVATION`** |
| interfaces, IPv4 | netlink | `ip -json addr` | `network.interfaces`, `network.ipv4` | `NETWORK_CONFIGURATION` |
| IPv6, stable | netlink | `ip -json addr`, classified by scope and flags | `network.ipv6_stable` | `NETWORK_CONFIGURATION` |
| IPv6, temporary | netlink | same source, `temporary` flag | `network.ipv6_volatile` | **`VOLATILE_OBSERVATION`** |
| default routes | netlink | `ip -json route show default`, v4 and v6 | `network.default_routes` | `NETWORK_CONFIGURATION` |
| DNS resolvers | `/etc/resolv.conf`, systemd stub | stub detected; the **upstream** servers are reported, not `127.0.0.53` | `dns.servers`, `dns.method`, `dns.note` | `NETWORK_CONFIGURATION` |
| timezone | `/etc/localtime` symlink, `timedatectl` | direct | `time.timezone` | `NETWORK_CONFIGURATION` |
| NTP provider, enabled | `timedatectl show`, provider presence | capability detection | `time.provider`, `time.ntp_enabled` | `NETWORK_CONFIGURATION` |
| **clock synchronized** | `timedatectl show` | `NTPSynchronized` | `time.synchronized` | **`VOLATILE_OBSERVATION`** |
| current source, stratum, offset | `chronyc tracking` | when chrony is the provider | `time.source`, `time.stratum`, `time.offset_seconds` | **`VOLATILE_OBSERVATION`** |
| uptime | kernel | `/proc/uptime` | `time.uptime_seconds` | **`VOLATILE_OBSERVATION`** |

### `NTP enabled` is not `clock synchronized`

They are separate fields because they are separate facts, and the lab proved it rather than the
documentation asserting it: Debian 12, 21 seconds after boot, reported `ntp_enabled: true` and
`synchronized: **false**`. A tool that collapsed those two would have reported a correctly configured,
correctly behaving clock on a host whose clock was not yet right.

`time.synchronized` is what feeds `REC-005`: when it is false, every event-time observation elsewhere
carries `CLOCK_UNSYNCHRONIZED` and no ordering conclusion may be drawn. `inventory.clock_unsynchronized()`
returns `None` for an unknown state, because not knowing is not the same as being fine.

### What the inventory does **not** prove

- **It is not the host's identity.** `host_id` comes from `IDENT-005` and nothing here replaces it. A
  hostname can be changed in a second; two hosts can share one.
- **An IP address is not internet exposure.** A routable address says a route exists, not that anything
  reaches it.
- **Hardware facts are not security configuration.** CPU model, core counts and RAM capacity are
  `HARDWARE_OBSERVATION` precisely because a live-migrated VM reports different ones. `SCOPE-063` names
  the correct outcome, `SAME_HOST_HARDWARE_CHANGED`, and it is not an ordinary delta.
- **Configured DNS is not resolution behaviour.** The servers listed are what is configured; nothing here
  queries them, and no DNS lookup is performed to populate the inventory.
- **`PARTIAL` means partial.** A missing tool is `NOT_TESTED`, a present tool that failed is `ERROR`, and
  neither is rendered as an empty success.

### Not yet in a snapshot

`SNAP-021` freezes a W1-A snapshot as exactly three files, so writing an inventory artifact into one would
change certified canonical bytes. Integration belongs to a **W1-C freeze set**, and no place was invented
for it in the meantime. Today the inventory is produced by `isedraf inventory` and consumed directly.

## Where each fact appears in a report

`isedraf report` renders the two evidence classes in **separate blocks with separate maturities**, because
they are not equally strong and a report must not blur them:

```text
Report
├── Host identity  —  W1-A CERTIFIED
│   ├── snapshot_id
│   ├── manifest_hash
│   ├── ledger record hash and sequence
│   └── independent verification result
│
└── Host inventory —  W1-C1, NOT in the frozen snapshot
    ├── collection_id
    └── artifact digest (a content SHA-256, not a snapshot hash)
```

| Report section | Domain | Evidence class |
|---|---|---|
| Target · Evidence → Host identity | Host Identity | snapshot-bound, verified |
| Platform · Compute · Storage · Network · Time | Host Inventory | artifact-digest bound |
| Collection completeness | both | per-subdomain status |
| Limitations | both | what the evidence does not support |

A rendered sample of the real output is **not published with this preview**. The previous sample was
generated on a disposable lab VM that no longer exists, and it describes the retired storage schema:
it reports a device `type` of `ROTATIONAL` or `OPTICAL`, which is exactly the inference the storage
observation model now refuses to make. It could not be migrated, because the fields that replaced
that one - `kernel_subsystem`, `queue_rotational`, `kernel_removable`, `scsi_peripheral_type` - were
never collected from that host, and writing plausible values for them would be inventing evidence.
A sample returns when it can be produced by running the tool, not by editing a document.

## Domains not yet mapped

Each is listed so the intended shape of the map is knowable, and each is **absent from the table above on
purpose**: nothing collects them yet.

| Domain | Status | Arrives with |
|---|---|---|
| Users & Groups · Privilege / sudo · Password & account ageing · `authorized_keys` | PLANNED | identity breadth (W1-D) |
| SSH · PAM / authentication | PLANNED | W3 — the domain where `DECLARED` vs `RESOLVED` vs `ACTIVE` first genuinely diverges |
| Mounts / filesystems | PLANNED | W3 |
| Recording · Audit · Journald · Time synchronization | PLANNED | W4 |
| Kernel / platform · SELinux / AppArmor · Services · Timers / cron | FUTURE | v0.1 |
| Software inventory | FUTURE | later; observation only |
| Framework mapping column (ISO / NIS2 / NIST) | FUTURE — v0.2 | a **view over** this map, never a replacement for it, and never canonical |

## Auditor workflow

1. Find the fact.
2. Read what was expected of the system, and the state dimension.
3. Read the system source and the effective collector — they are different questions.
4. Locate the normalized field.
5. Open the evidence artifact at its persistent location.
6. Read the collection status **and**, separately, the evaluation result.
7. **Read the limitations.** They are the part of the row that prevents an overstatement.
8. Verify independently against the native source.

## Operator workflow

```text
a fact looks wrong
        ↓  find the native setting or parameter in its row
        ↓  check which dimension you are looking at: declared, resolved or active
        ↓  open the evidence artifact
        ↓  change the operating system with the system's own tools
        ↓  run isedraf again and compare
```

ISEDRAF does not remediate. It tells you what it observed and where it looked; the change is yours to
make, with the tools that own the setting.

## Structure note

The table shape is deliberately regular so that this page can one day be **generated** from a
machine-readable registry of facts, with the PDF generated from the same source. That is FUTURE and needs
no database (`STORE-002`). Until the number of domains makes hand-maintenance the real problem, this
Markdown file is the canonical source.
