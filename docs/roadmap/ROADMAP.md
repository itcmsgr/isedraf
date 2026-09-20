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

## The product model — three modes (D-112)

```text
A  NATIVE         Linux facts -> ISE-* controls -> findings -> evidence.  Always available.
B  OPEN MAP       A + a mapping whose exact reuse rights were validated first.
C  LICENSED BYOL  A + a provider-authorized pack + the customer's provider entitlement.
```

**A exists independently. B and C add information to A. Neither may change A.**

The practical consequence for planning: **framework negotiations never block development.** Mode A is
the product, and it is finished on its own schedule. Modes B and C increase the value of evidence that
already exists. `docs/architecture/ISEDRAF_PRODUCT_HLD.md` holds the full model.

## Development order

```text
1  native collectors                        ← W1-A/B/C done: identity, inventory, reporting
2  native ISE-* criteria                    ← W1-D. Namespace frozen (D-111), catalog EMPTY
3  native findings / evidence / reporting
4  generic authority-mapping engine
5  first verified-open mapping              ← NIST is the candidate; rights NOT yet verified
6  provider BYOL, only with written rights  ← SCF first conversation, then CIS, then ISO/IEC
7  more architectures and distributions     ← runs in PARALLEL with all of the above
```

Step 7 is deliberately not last. Platform validation has no dependency on steps 2-6 and should not
queue behind them.

## How a platform joins the matrix

A platform is supported when five things are true, and the fifth is the one usually skipped:

```text
CPU architecture + distribution family + version + collector capability + DEMONSTRATED VALIDATION
```

`make check-public-claims` refuses a platform claim the measured record does not support, so a row
moves by producing evidence and not by editing a table.

### Adding an architecture — ARM64 is the next one

ARM64 is a **primary** target with **zero campaigns run**. What the campaign has to answer, in order:

| # | Question | Why it is not obvious |
|---|---|---|
| 1 | Does the launcher find a suitable interpreter? | vendor interpreter paths differ on ARM images |
| 2 | Do the canonical bytes match the x86_64 golden vectors **exactly**? | this is the one that matters — a byte difference here invalidates cross-architecture baselines |
| 3 | `/proc/cpuinfo` parsing | **different layout on ARM**: no `model name`, no `siblings`; Pi reports `Hardware`/`Revision` |
| 4 | DMI / machine identity | **Raspberry Pi exposes no DMI at all** — must degrade to `PARTIAL` with a reason, never to a guess |
| 5 | Block-device naming and classification | `mmcblk*` on Pi, `nvme*`/`sd*` elsewhere; the device taxonomy needs a row |
| 6 | Reboot stability of `host_id` and `state_hash` | the property the whole baseline model rests on |
| 7 | Package build and install | `noarch`/`all` should hold, because nothing is compiled — verify rather than assume |

Reference targets: **Debian 13 arm64** and **Raspberry Pi OS 64-bit**. Two targets, deliberately:
a generic distribution on ARM and the most constrained realistic board. One passing is not the other
passing, and `aarch64` must never quietly come to mean *"Raspberry Pi support"*.

**32-bit ARM (`armhf`) is not a gap to close.** It is out of scope by architecture, not by backlog.

### Adding a distribution

1. Confirm the image is obtainable and record its exact version.
2. Run the existing compatibility campaign — no new code should be needed. **If it needs
   distribution-specific code, that is a finding about the collector, not about the distribution.**
3. Record the result in `docs/reference/PLATFORM_COMPATIBILITY.md`, including failures and
   `IMAGE_UNAVAILABLE`.
4. Add the distribution to `distributions_measured` in the status registry **only** if it passed.
5. Regenerate `docs/CURRENT_STATE.md`.

Candidates, none validated: **SLES** (completes the SUSE family) · **Oracle Linux**, **Rocky 8**
(complete EL coverage) · **Amazon Linux 2023** (cloud reach) · **Fedora** (early warning of what EL
inherits) · **Alpine** (musl, no systemd — the most likely to find a genuine portability assumption,
and therefore the most valuable failure).

Alpine is worth singling out: it is the candidate most likely to *fail*, which is exactly why it is
worth running. A campaign that only ever confirms what was expected is not measuring anything.

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
