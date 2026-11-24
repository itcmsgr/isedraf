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

**Host identity has a complete row below. The audit sections that `isedraf audit` collects - host and
platform inventory, local accounts and groups, NSS configuration, hostname, mounts, SSH server
configuration, PAM, sudo, SSH authorized keys and login policy - do not have their rows here yet.** Until
they do, the reference for each is its evidence file in the committed run (`sections/<area>.json`), the
report's "Evidence limitations" table, which names every source each area tried to read and what that
means for the evidence, and, for the facts a native criterion reads, the
[criteria catalogue](NATIVE_CRITERIA.csv) and the [criterion pages](criteria/), which name the evidence
each criterion uses and what its result does not establish. Rows follow as each area's mapping is written; see the engineering-debt table in
[the roadmap](../roadmap/ROADMAP.md).

## The two status vocabularies never merge

| Collection status | Meaning |
|---|---|
| `COLLECTED` | the fact was observed |
| `NOT_TESTED` | it was not observable here — no source, no privilege, no tool |
| `ERROR` | the source existed and observation failed |
| `PARTIAL` | some of the domain was observed |

| Evaluation result | Meaning |
|---|---|
| `PASS` · `FAIL` | the collected state satisfies or violates the criterion |
| `NOT_APPLICABLE` | the criterion legitimately does not apply to this host |
| `MANUAL_REVIEW` | the evidence was collected, but an automated determination would be unsafe |
| `NOT_EVALUATED` | collection was `PARTIAL`, `NOT_TESTED` or `ERROR`, so no valid evaluation was possible |

`MISMATCH` — two dimensions of the same fact disagree — is a relationship between dimensions and a
delta primitive, not an evaluation result (D-121).

**A collection failure never becomes `PASS` or `FAIL`.** "We could not look" and "we looked and it is
wrong" are different statements, and a tool that merges them is lying in whichever direction is
convenient. Evaluation is a separate step (`isedraf evaluate`), recorded apart from the run it reads, and
it never changes collected evidence.

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
| **Persistent location** | `<store>/snapshots/SDS-<ts>-<id>/` - the user store for a standard audit, `/var/lib/isedraf/` for a Full Audit |
| **Collection status** | `COLLECTED` · `NOT_TESTED` (source absent) · `ERROR` (unreadable, or rejected by the grammar) |
| **Reason vocabulary** | `SOURCE_ABSENT` · `SOURCE_UNREADABLE` · `SYNTAX_REJECTED` · `INTERNAL_ERROR` |
| **Evaluation / interpretation** | no native criterion reads it; a baseline comparison uses it to decide applicability - a run whose `host_id` is not the baseline's is not compared |
| **Explain / manual verification** | `isedraf explain` explains criteria, not facts. Compare the rendered `host_id` with the `state_hash` in the snapshot manifest, and re-derive both from `state/host_identity.json` |

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

### Committed with the run, outside the host-state hash

`isedraf audit` commits the inventory with the run as `sections/inventory.json`, bound by the run's
manifest digest but not part of the snapshot's host-state hash: hardware and utilisation facts change
legitimately and must not read as configuration change. `isedraf inventory` shows the inventory without
committing anything.

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
└── Host inventory —  a bound section of the run, NOT in the host-state hash
    ├── collection_id
    └── artifact digest (a content SHA-256, not a snapshot hash)
```

| Report section | Domain | Evidence class |
|---|---|---|
| Target · Evidence → Host identity | Host Identity | snapshot-bound, verified |
| Platform · Compute · Storage · Network · Time | Host Inventory | artifact-digest bound |
| Audit sections | the ten audited areas | each a bound section of the run, with its status and reason |
| Native criteria | the evidence each criterion names | from the committed evaluation, kept apart from collection status |
| Baseline comparison | the sections the baseline tracks | from the committed evaluation; a report never compares |
| Recorded settings (`nullok`, maximum password age) | PAM, local accounts | from the run's sections; not criteria |
| Collection completeness · Evidence limitations | all | per-area status and what each source could not show |
| Limitations | all | what the evidence does not support |

A historical sample of the real output is in [`samples/SAMPLE_REPORT.md`](samples/SAMPLE_REPORT.md),
with the same report as JSON beside it. Its evidence was collected by an unprivileged user on
a disposable Debian 12 VM using the `0.1.0-alpha1` package; the current build renders it.

It is **generated from committed evidence**, not pasted in. The collection it came from is in
[`samples/evidence/`](samples/evidence/) — the inventory as collected, and the snapshot, manifest
and ledger as written — and `python3 scripts/docs/sample_report.py generate` rebuilds both
documents from those bytes. Regenerating re-verifies the ledger chain as it goes, so the sample
demonstrates the verification rather than asserting it. `make check` fails if the published
sample and its evidence disagree.

The previous sample was withdrawn because it described a retired storage schema and its source
machine no longer existed, so it could not be regenerated. That cannot happen again: the sample
no longer depends on anyone still having the host. What committed bytes cannot reproduce is the
collection itself — reading `/sys` and `/proc` needs the machine — so the evidence is captured
once and the report is reproducible from it.

## Domains not yet mapped

Each is listed so the intended shape of the map is knowable, and each is **absent from the table above on
purpose**.

| Domain | Collected today | Row in this map |
|---|---|---|
| Users & Groups · Privilege / sudo · Password & account ageing · `authorized_keys` | yes - the accounts, NSS, sudo, authorized keys and login policy sections | not yet written |
| SSH · PAM / authentication | yes - the SSH and PAM sections (`DECLARED` and, for SSH, the global `RESOLVED` configuration) | not yet written |
| Mounts / filesystems | yes - the mounts section (declared and active) | not yet written |
| Time synchronization | in the inventory only (`NTP enabled`, `clock synchronized`) | see Host Inventory above |
| Recording · Audit · Journald | no | PLANNED |
| Kernel / platform · SELinux / AppArmor · Services · Timers / cron | no | FUTURE |
| Software inventory | no | FUTURE; observation only |
| Framework mapping column | no | FUTURE - the roadmap's first framework release; a **view over** this map, never a replacement for it, and never canonical |

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
