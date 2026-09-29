<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Roadmap

Status: PLANNED
Implements: D-65, D-66, D-82, D-88

Everything on this page is `PLANNED`, `FUTURE` or `OUT_OF_SCOPE`. Nothing here is released.
For what exists, see [`../CURRENT_STATE.md`](../CURRENT_STATE.md).

## GA release track — current priority (owner directive, 2026-09-27)

The goal is a usable, GA-quality operational release: installable, operational,
predictable, honest, with safe failure modes, a useful report and clear limitations, and
no known major blocker. A GA release will still have bugs; it must not have those.

```text
1  CLI / command surface audit      install, run, collect, output, clear errors,
                                    no built module left unreachable
2  install / package audit
3  end-to-end factual audit run
4  first report                     factual JSON + readable HTML, coverage, limitations;
                                    no comparison engine or findings required
5  P0/P1 operational defects
6  supported-platform smoke tests
7  public documentation cleanup     the DOC-PUBLIC-01 gate
8  GA candidate                     publication stays a separate owner act
```

### What GA means for ISEDRAF

ISEDRAF produces evidence. Its principal failure is not a crash; it is evidence that
claims more certainty than the collection supports. GA is judged against six priorities,
and each one names what would block it.

| # | Priority | GA blocker if |
|---|---|---|
| 1 | Install and upgrade integrity | DEB or RPM install fails; an upgrade loses evidence or state; an upgrade on an unchanged host reports a security change; uninstall deletes the evidence under `/var/lib/isedraf` (it never may) |
| 2 | CLI truth | a command does not exist or does not do what it says; an exit code disagrees with the frozen exit-code contract; an error is silent or gives the operator nothing to act on |
| 3 | Do no harm | ISEDRAF changes the host it inspects, or makes a network connection |
| 4 | Run and snapshot lifecycle | the run lock fails; a snapshot is committed non-atomically; an interrupted run leaves evidence that looks valid; orphaned runs are not handled deterministically |
| 5 | Evidence truthfulness | a source is reported `COLLECTED` without complete evidence; something is reported absent that was not fully observed; a result passes without the evidence for it |
| 6 | Supported production paths | the supported distributions, the unprivileged run with its user-mode store, or a human-readable first report do not work (privileged runs belong to the Full Audit release, D-117) |

**Privacy is a blocker in every priority.** Evidence is made to leave the host, so a
secret, a password hash or other raw sensitive material reaching output stops GA however
rare the input that causes it.

GA does not mean zero bugs. It means none of the above is known.

### How a newly found issue is handled

Before any code is written, one question: **does this stop GA? Yes or no.**

- **Yes** when it breaks install, run or report; gives wrong exit semantics; mutates the
  host or reaches the network; corrupts a snapshot or the ledger; produces false confident
  evidence; crashes or hangs on a supported path; or leaks sensitive material.
- **No** when it can be contained as an explicit conservative result - `PARTIAL`,
  `NOT_TESTED`, `NOT_ASSERTED` - without misleading the operator.

```text
DISCOVER -> CLASSIFY -> CONTAIN (if needed) -> REGISTER
```

A **no** is registered and the roadmap continues; it does not open a new investigation. A
**yes** gets the smallest correction that restores the property, and a weakness found
beside it is classified on its own rather than folded in. A bounded defect never becomes
a subsystem redesign. The roadmap decides which investigations happen, not the other way
round.

The phase model below still describes where each capability belongs; this track sets the
order of work until GA.

## Canonical phase model — the single roadmap interpretation

Owner decision, 2026-09-20. This section is the authoritative reading of the roadmap. It exists
because the work kept drifting between "release work", "report work", "controls", "ARM" and
"frameworks" as though they competed for the same slot. They do not. No new architecture decision
is taken from this page: an amendment follows implementation evidence, never the reverse.

Everything from Phase 1 onward is `PLANNED` or `FUTURE`. Nothing below Phase 0 is built.

| Phase | Name | State | What closes it |
|---|---|---|---|
| 0 | Technical preview foundation | **IMPLEMENTED** | the evidence engine, packaging, deterministic semantics and release process are trustworthy enough to build an assurance layer on |
| 1 | Reproducible example report | `PLANNED` | a fresh, schema-current public example rendered from committed input bytes (closes `IQ-011`) |
| 2 | W1-D host assurance collection | `PLANNED` | the ten control domains below, each with its full fixture set |
| 3 | Native `ISE-*` control catalog | `PLANNED` | criteria authored against frozen collector schemas, in our numbering and our technical reasoning |
| 4 | Findings report | `PLANNED` | the first customer-useful output: native findings with result classes and evidence references |
| 5 | Approved baseline and classified delta | `PLANNED` | "what changed since the state I approved?", plus the unchanged-runs and engine-upgrade acceptance tests |
| 6 | Platform expansion | `PLANNED` | ARM64, Raspberry Pi, Alpine, then further distributions; support grows from evidence |
| 7 | Generic mapping engine | `FUTURE` | an overlay that never modifies facts, criteria, results, snapshots, ledger, baseline or delta |
| 8 | Mode B — validated open mappings | `FUTURE` | an external authority whose exact reuse rights were verified first |
| 9 | Mode C — provider-authorized BYOL | `FUTURE` | a written provider agreement; the core stays MPL-2.0 |

### The alpha goal, stated plainly

`v0.1.0-alpha1` is a **technical preview**, and its goal is *not* to complete assurance content. Its
goal is to prove the engine, the packaging, the deterministic semantics and the release process are
sound enough to build on. Measuring that against assurance breadth would fail it for the wrong reason.

### Four report milestones

The reporting engine is not what is missing. What is `PLANNED` is the assurance intelligence that
makes a report worth giving to a customer.

| Level | Meaning | State |
|---|---|---|
| **R0** Evidence report | identity + inventory + completeness + evidence references | **IMPLEMENTED** — `isedraf report` |
| **R1** Public sample | a reproducible, current-schema published example | `PLANNED` — Phase 1 |
| **R2** Assurance report | users, privilege, SSH, authentication and the rest, plus native findings | `PLANNED` — Phases 2-4 |
| **R3** Continuous assurance | approved baseline plus classified delta | `PLANNED` — Phase 5 |

### W1-D control domains, in order

The order is by control domain, not by release. Each domain is complete only when it carries the
fixture set this repository already requires of every parser: normal, missing, malformed, permission
denied, partial, unsupported, and fixture isolation.

```text
 1  users and groups            6  services
 2  privilege and sudo          7  logging and audit
 3  account ageing              8  mounts and filesystem security
 4  SSH                         9  kernel and security posture
 5  PAM and authentication     10  update and support posture
```

### Three tracks, run in parallel, never conflated

```text
PRODUCT DEPTH        inventory -> controls -> findings -> baseline/delta
PLATFORM BREADTH     x86_64 -> ARM64 -> Raspberry Pi -> further distributions
FRAMEWORK ECOSYSTEM  native only -> verified open maps -> provider-authorized BYOL
```

Platform validation has no dependency on the control or framework tracks and does not queue behind
them. Framework negotiation blocks nothing, because Mode A is the product.

### How the remaining effort is estimated

No duration is frozen here. A number produced before any domain has been built is a guess wearing a
schedule's clothing, and this repository does not publish confidence the evidence has not earned.
The method instead:

```text
implement the first two full domains
        -> measure the real cost of collector + fixtures + criterion + renderer + falsification
        -> re-estimate the remaining domains from observed velocity
```

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
| `git-hooks/` are not installed in `.git/hooks` (`Z-22`) | CLOSED | Installed and byte-identical to `git-hooks/`; rejections observed for a failing tree, a missing `Assisted-by:` and an AI `Co-Authored-By:` (`IQ-021`). What the pre-commit hook validates is still open (`IQ-029`). |

### Public technical preview — the remaining condition

The engine is not what is missing. Packaging exists (`.deb` and `.rpm`), install, run, remove and
reinstall are proven on Debian 12, AlmaLinux 8.10 and AlmaLinux 9.7, and the support matrix is
`../reference/PLATFORM_COMPATIBILITY.md`. What is still missing for a third party is a quick start, and
the two release blockers in `../CURRENT_STATE.md`.

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

## R1.5 execution sequence — canonical

**This table is the authoritative execution order.** It was not here before DOC-R15P, and
the sequence lived only in `../development/INVENTORY_COVERAGE_MATRIX.md`, which meant the
canonical roadmap and the order work actually followed were two documents that did not
reference each other. The matrix is now the domain coverage detail and cites these
milestones; it no longer defines the order.

A row says COMPLETE only when a merged or frozen SHA proves it.

| Milestone | Contents | State |
|---|---|---|
| Batch 0 | account-source contract; `IQ-012` closed by amending the requirement | **COMPLETE** `723459ad` frozen · `9db3de42` merged |
| Batch 1 | shared primitives S1–S5, one serialized lane | **COMPLETE** |
| ARCH-01 | structural and evidence-flow review | **COMPLETE** |
| Batch 2 | sudo · SSH · PAM · login policy | **COMPLETE** `ace82d58` frozen · `3235e7d1` merged |
| ARCH-02 | architecture review with the semantic oracle matrix | **COMPLETE** |
| bridge | `authorized_keys`; `IQ-014` closed by owner ruling | **COMPLETE** `79f885f7` frozen |
| **R1.5-P** | privilege and evidence acquisition contract (`D-115`) | **COMPLETE** `f256c9ce` frozen |
| **DOC-R15P** | repository-wide documentation reconciliation | **ACTIVE** — runs in parallel with Batch 3, not ahead of it (owner sequencing, 2026-09-23) |
| Batch 3 | fstab/mounts declared-vs-active · NSS/hostname — S3's first natural consumer | **ACTIVE** — mounts lane merged `ded73ec` (182 tests), awaiting owner closure, and not yet reachable from any command; NSS/hostname not started |
| **TA-1 … TA-9** | trust and assurance — source/governance, build identity, reproducibility, SBOM, runtime trust, adversarial testing, offline verification, independent review (`docs/development/TRUST_AND_ASSURANCE_DOCTRINE.md`) | `PLANNED` — cross-cutting, does not block unprivileged R1.5 work; TA-1 and TA-4 are startable independently |
| **R1.5-P2** | verifiable least-authority acquisition — portable core + platform confinement backends (`docs/development/R15P2_LEAST_AUTHORITY_ACQUISITION_CONTRACT.md`) | `PLANNED` — **DESIGN ONLY**, awaiting owner architecture review; four conflicts with frozen authority open as `IQ-024`…`IQ-027` |
| Batch 4 | audit policy · journald/logging · time | `PLANNED` |
| ARCH-03 | architecture review after Batches 3–4 | `PLANNED` |
| Batch 5 | services · timers/cron · kernel · LSM · listeners | `PLANNED` — **governance-dependent** |
| Batch 6 | packages · repositories · offline update observation · crypto | `PLANNED` — **governance-dependent** |
| Batch 7 | network · DNS · local packet-filter state | `PLANNED` — **governance-dependent** |
| Batch 8 | certificates · targeted files · bounded capabilities/setuid | `PLANNED` |
| ARCH-04 | architecture review at full R1.5 completion | `PLANNED` |
| R1.5 freeze | the factual inventory layer closes | `PLANNED` |
| R2 | native `ISE-*` criteria — interpretation begins | `PLANNED` |

### Why R2 waits

R1.5 collects facts; R2 interprets them. The boundary is enforced per domain, not as a
slogan:

```text
service active            FACT      service insecure          NOT R1.5
listener on a port        FACT      exposed to the Internet   NOT R1.5
nft policy ACCEPT         FACT      host unprotected          NOT R1.5
package version present   FACT      vulnerable                NOT R1.5
LSM profile loaded        FACT      adequately confined       NOT R1.5
cached update candidate   OBSERVATION   host out of date      NOT R1.5
```

### Governance dependency for Batches 5–7

The `IQ-013` owner ruling admits services, kernel, LSM, listeners, packages, repositories,
offline update observations, crypto, network, DNS and local packet-filter facts into R1.5.
**`AMENDMENTS.md` does not yet formally record it.** Until it does, those batches have a
ruling and not an amendment, and `PLANNED` in the table above is not authorization.

Batches 3 and 4 are **not** affected: their domains were already inside the frozen scope.

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

**Documentation publishing** — publish `/docs` itself; blocked by OD-11 (OD-01, the project name, is resolved by D-108).

**Provider-neutral concepts** — canonical concepts describe outcomes, not Linux technologies, so future
Unix-like providers could be added without redefining host concepts. **This is not BSD support.**

## Release direction after GA (owner decision, 2026-09-27)

No calendar is attached to these releases; each is re-estimated after the one before it.

```text
v0.1  GA - unprivileged evidence product
      Python standard-library engine; user-mode production store; `isedraf audit`;
      committed evidence; first report; DEB/RPM; upgrade, reboot and uninstall proven.
      No privileged component and no compiled code.

v0.2  Full Audit - prove the privilege architecture
      root supervisor, systemd sandbox, a dedicated non-login isedraf identity for the
      engine, authority classes, bounded one-run IPC, root-only acquisition, and the
      system production store.

later compiled acquisition core, when measurement justifies it
      the same IPC contract and authority classes, no engine redesign.
```

**The security property this protects** - and the language is secondary to it:

```text
main engine        large, feature-rich, UNPRIVILEGED
privileged worker  tiny, fixed authority, minimal logic
IPC                narrow, typed, bounded, one run, no generic privileged operation
```

**The v0.2 worker.** The first implementation may be a minimal Python worker, used to
prove the authority and IPC model; it is permitted, not required. It accepts a fixed
operation identifier - "the shadow file", "the audit status", "the resolved sudoers" -
performs that one predefined acquisition and returns bounded bytes and a status. It never
takes a path, an argument vector or a tool name, never runs a shell, and holds no plugin,
evaluator, normalization or report logic: a generic privileged broker would defeat the
design. If the required privilege isolation cannot be demonstrated with it, the release
does not widen authority; the worker moves to the compiled lane instead.

**The compiled acquisition core.** Rust is the preferred candidate, chosen by measurement,
not in advance. It is taken up when there is evidence that it improves the privileged
attack surface, memory-safety exposure, an interpreter inside the privileged boundary,
kernel-interface quality, performance, cross-platform or embedded needs - or when a
finding against the prototype worker calls for it. Rust can reduce classes of
memory-safety defects in the privileged acquisition component when implemented
predominantly in safe Rust; it does not make the IPC contract, the privilege model, the
logic or any unsafe code automatically correct. Adopting it changes the package model -
architecture-specific packages, a hybrid runtime statement, a reproducibility proof and
provenance for compiled artifacts, a CI toolchain per architecture, a policy for
third-party crates - and requires amending the rule that the runtime has no compiled
component. The IPC contract is then tested against both implementations.

## After GA — FUTURE: external standards and validation readiness

Not current scope, and nothing in it is claimed. It begins only after GA, with the
architecture stable enough to fix an evaluation boundary. Its question is which external
standards and validation frameworks genuinely apply to what ISEDRAF does - host inspection,
evidence collection and factual assessment reporting - and what evidence-based path would
lead to independent validation. It does not assume that any one framework is the right
destination, and it records "none applies" as a result rather than forcing a fit.

```text
1  product security purpose and evaluation boundary (supported configuration is not the
   evaluated configuration)
2  which external frameworks could apply - candidates to be assessed, not assumed:
   Common Criteria protection profiles, CIS benchmarks, DISA STIG, SCAP formats,
   NIST guidance - using the documents current when the phase starts
3  requirement-by-requirement evidence matrix: PASS / PARTIAL / GAP / N/A /
   NEEDS EVIDENCE / NEEDS CLARIFICATION, and a PASS carries its evidence
4  a deterministic evaluated configuration
5  independent pre-assessment
6  confirmed gap roadmap, each change marked as improving the product itself, existing
   only for evaluation, or restricting only the evaluated configuration
7  a formal decision whether to pursue validation
```

For an assessment engine, false assurance is the failure that matters most. This lane
measures false PASS, false FAIL and false PARTIAL, unsupported assumptions, incomplete
evidence, platform semantic differences, parser ambiguity and benchmark version drift, and
it requires each result to trace from its source requirement through collection,
normalization, evaluation and evidence to the report. The existing glibc differential
harness and the falsification suite are the kind of evidence it will reuse.

Content that belongs to a third party - benchmark text, rules, mappings - enters only
under the licensing modes above (validated open mappings, provider-authorized BYOL); this
lane never copies it.

**Project-level criteria that can be verified before any product standard.** Some
evidence already exists and is recorded in `../CURRENT_STATE.md`: code scanning, the
OpenSSF Scorecard workflow, a software bill of materials, a reproducible build and build
provenance attestation. The OpenSSF Best Practices criteria are the next such checklist to
assess. Each is reported as measured, never as a badge the project has not been granted.

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
