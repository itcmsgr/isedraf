<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Roadmap

Status: PLANNED
Implements: D-65, D-66, D-82, D-88

Everything on this page is `PLANNED`, `FUTURE` or `OUT_OF_SCOPE`. Nothing here is released.
For what exists, see [`../CURRENT_STATE.md`](../CURRENT_STATE.md).

## Prototype — PLANNED

Host identity · identity views (`users`, `user <name>`, `groups`, `group <name>`, `privileged`) from one
canonical collection · account-creation provenance · local sudo · `authorized_keys` fingerprints ·
password and account aging · SSH resolved state · mounts declared/resolved/active · recording coverage ·
`explain <id>` · snapshot, baseline, comparability, delta, acceptance · JSON/JSONL export · DEB/RPM
skeleton.

### Built — what the prototype actually does today

Listed here because a roadmap that still *plans* what already exists stops being read. Detail lives in
[`../CURRENT_STATE.md`](../CURRENT_STATE.md) and the compatibility record.

| Slice | State | What it produces |
|---|---|---|
| **W1-A** evidence contract | **CERTIFIED**, byte-pinned by `freeze/W1A_CORE.sha256` | canonical serialization, hash framing, snapshot/manifest/ledger shapes, a falsifiable golden corpus, an independent verifier |
| **W1-B** identity slice | **COMPLETE** | `isedraf identity` — `/etc/machine-id` → normalize → `host_id` → immutable snapshot → hash-chained ledger → verification |
| **W1-C** cross-distro core | **PROVEN** on ten distributions | zero distribution-specific code; the interpreter is the only portability boundary found |
| **W1-C1** host inventory | **COMPLETE** | `isedraf inventory` — nine subdomains, every field classified, noise-tested |
| **W1-C2** report engine | **COMPLETE** | `isedraf report` — one model, JSON and Markdown, optional assessment profile |

Measured, not asserted: identical canonical bytes from **CPython 3.6.8 through 3.14.4**, across Debian
11/12/13, Ubuntu 22.04/24.04/26.04, AlmaLinux 8/9, Rocky 9, CentOS Stream 9 and openSUSE Leap 15.6.

### What may be said about this, and what may not

Defensible today:

> ISEDRAF is an early-stage Linux host assurance and evidence engine that produces deterministic,
> independently verifiable host-state evidence across heterogeneous Linux systems.

**Not** defensible today, and not to be written anywhere until it is earned:

- *"runs on every Linux"* — ten distributions on one architecture is not every Linux.
- *"supports ARM / IoT / edge"* — **zero ARM campaigns have run.** See below.
- *"no comparable tool exists"* — adjacent tools exist and do overlapping work. The interesting claim
  is the **shape**: a local-first evidence engine whose output is deterministic and verifiable without
  trusting the tool that produced it. That claim stands on its own and needs no comparison, and `C-06`
  forbids competitive framing in this repository for exactly that reason.

The discipline that produced the results above is the same discipline that keeps these three sentences
unwritten until there is a record behind them.

### Architecture support — OWNER DECISION, 2026-09-18

| Architecture | Target class | Status |
|---|---|---|
| `x86_64` / `amd64` | **PRIMARY** | ten distributions measured |
| `aarch64` / `arm64` | **PRIMARY, second architecture** | **`NOT_TESTED`** — no campaign has run |
| `armhf` / ARMv7 32-bit | best effort | no certification commitment |
| `armel` and older ARM | **OUT_OF_SCOPE** | high testing cost, negligible strategic value |

`aarch64` is a first-class target because it reaches ARM servers, Graviton, Ampere, edge gateways,
appliances and 64-bit Raspberry Pi from one campaign — not because of any single board.

**Why it is plausible, and why plausible is not proven.** The production package is Python standard
library only, with no compiled component, no native extension, no architecture-specific code, and
collectors that read `/proc`, `/sys` and standard Linux interfaces. Nothing in it is x86-shaped. That
makes ARM64 a low-risk expectation — and an expectation is not a result. The failures worth anticipating
are platform details the inventory model already handles as `PARTIAL`: `/proc/cpuinfo` is laid out
differently on ARM, Raspberry Pi exposes no DMI at all, and block-device naming differs.

**The campaign that would change the row**, when the hardware is available:

```text
Raspberry Pi 4 or 5 · Raspberry Pi OS 64-bit · aarch64
Debian 13 arm64                    ← the second target, so that "ARM support"
                                     cannot quietly mean "Raspberry Pi support"
        ↓
identity · inventory · 10 unchanged runs · reboot · verifier · noise test · report
```

Two targets, deliberately. One board would prove a board.

### 32-bit ARM is not a gap to close

It is a decision. `armhf` may work wherever the Linux and Python requirements are met, and nothing
excludes it, but it will not be certified and its absence is not a defect. `armel` is out of scope
entirely.

### Engineering debt — carried deliberately

| Item | Status | Why it is recorded rather than done |
|---|---|---|
| **Control & Evidence Map** — one row per observable fact: expected system state · state dimension (`DECLARED`/`RESOLVED`/`ACTIVE`) · assessment class · system source · effective collector · native setting or parameter · normalized ISEDRAF field · evidence location · collection status · evaluation result · **limitations** | PLANNED | The structure is seeded in [`reference/CONTROL_EVIDENCE_MAP.md`](../reference/CONTROL_EVIDENCE_MAP.md) with the one domain that exists. A row per unimplemented domain would be a design sketch wearing a reference document's clothes, and the whole value of the map is that a row means something is actually collected. **Each domain gains its row in the milestone that implements it**, not before. |
| PDF publication of the map | PLANNED | Markdown stays canonical and the PDF is generated from it, never maintained beside it. No PDF toolchain is approved yet, and none will be added merely to publish one document (D-84). |
| Machine-readable control/fact registry → generated Markdown → generated PDF → JSON export | FUTURE | Only once enough domains exist for hand-maintenance to be the actual problem. Not a database (`STORE-002`). |
| `git-hooks/` are not installed in `.git/hooks` (`Z-22`) | OPEN | `make check` and CI remain the authoritative gates; a separate owner-controlled governance lane. |

### Public technical preview — the remaining condition

The engine is not what is missing. What is missing is everything that lets a third party install it, run
it, understand it and send back a finding: packaging, a quick start, a fresh-machine install and removal
test, and the support matrix.

ARM64 does **not** block the preview. `x86_64` with the measured distributions is a coherent, honest
first release, and ARM64 validation lands beside it or immediately after.

## v0.1 — PLANNED

Adds kernel and platform facts · mandatory access control state · services · timers and cron ·
single-file HTML report · packaging.

Platforms: Debian 12 · Ubuntu 24.04 · Rocky Linux 9 · AlmaLinux 9.

## v0.2 — FUTURE

Framework mapping **views over existing evidence**, all `PROPOSED`, with explicit coverage classes
(`HOST_TECHNICAL`, `HOST_SUPPORTING_EVIDENCE`, `MANUAL_ORGANIZATIONAL`, `NOT_HOST_ASSESSABLE`). Mappings
never change collection, and ISEDRAF never converts host technical evidence into a claim of organizational
compliance.

## Later — FUTURE

Reusing the same collection → normalization → state/observation → snapshot → baseline → comparability →
delta → export engine, never as separate scanners or databases:

**Software inventory** — package name, version, architecture, package manager, locally determinable origin
and signature facts, native version comparison, normalized delta. Full inventory at baseline, delta
routinely. Designed so an organization can ingest exported JSON/JSONL into its own database and ask
*which hosts have package X version Y* — without ISEDRAF containing a database connector.
CVE matching and remote patch availability remain external enrichment.

**Hardware inventory · local listening state · service inventory** — same model.

**Export signing** — optional, via `ssh-keygen -Y sign`. Claims only: unchanged since signing, signed by a
pinned host key. Never non-repudiation or trusted time.

**Documentation publishing** — publish `/docs` itself; blocked by OD-11 and OD-01.

**Provider-neutral concepts** — canonical concepts describe outcomes, not Linux technologies, so future
Unix-like providers could be added without redefining host concepts. **This is not BSD support.**

## Permanently OUT_OF_SCOPE

Firewall products and rulesets · antivirus · EDR/XDR · IDS/IPS · WAF · SIEM · cloud and network controls ·
external backup · remote repository patch availability · CVE matching · whole-filesystem file integrity
monitoring · remote attestation · organizational "required agent" checks · network egress · telemetry ·
API client or server · database connectors · automatic remediation · daemon.

The absence of a locally detectable external agent is never reported as the absence of the control.

## Blocking open decisions

**OD-01 — public project name.** Blocks any public release; an existing cybersecurity company uses
"ISEDRAF". **OD-07** repository hosting and package signing-key custody · **OD-09** release signing ·
**OD-11** documentation publishing. Full list in `../architecture/INTERNAL_RECORDS.md`.
