<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# ISEDRAF Native Control Catalog

Implements: D-78, D-79, D-82, D-84, D-111, D-125

**Architecture invariant, owner decision 2026-09-19 (`D-111`), frozen before W1-D is designed.**

> The ISEDRAF native control catalog is authored first. Framework authority is mapped second, and
> only where licensing permits. **An external framework is never the source of a control.**

## The layering

```text
LINUX FACT
    ↓
ISEDRAF NATIVE CONTROL
    ↓
ISEDRAF RESULT / EVIDENCE
    ↓
OPTIONAL AUTHORITY MAPPING
    ├── open / public mapping
    ├── provider-licensed mapping
    └── no mapping
```

The arrow runs one way. A framework requirement never defines how a collector is implemented or what
a criterion says, and removing every mapping leaves the catalog exactly as useful.

## Three ownerships, kept apart

| | |
|---|---|
| **Control ownership** | ISEDRAF |
| **Evidence ownership** | the customer, and the host observed |
| **Framework mapping rights** | framework- and provider-specific |

Separating these is the whole point. The first two are ours and the customer's and carry no
third-party licensing question. Only the third does, and it is isolated so that a licensing problem
in one framework cannot reach the engine, the evidence, or any other framework.

## What ISEDRAF claims about authorship — and what it does not

> ISEDRAF independently authors technical host-assurance criteria based on Linux system behaviour,
> security engineering principles, and sources whose reuse rights permit that use. External framework
> content is not required to define those criteria.

That is the claim, and it is deliberately narrower than *"nothing could ever forbid a control"*. This
project does not assert that no patent, contract, trademark, copyright, database right or other
restriction could exist anywhere in the world. It asserts what it can support: the criteria are
independently authored, and they do not depend on licensed framework content.

The distinction matters in a legal document. An absolute claim is the kind of sentence that is
cost-free to write and expensive to defend.

## Namespace

Authority: `lib/isedraf/catalog/native_controls.json` (`EVAL-002`), installed with the package.
`make check-native-catalog` requires this document and
that file to agree, because two authorities that can disagree are how a namespace drifts.

| Family | Domain |
|---|---|
| `ISE-ASSET-*` | asset and host inventory |
| `ISE-SW-*` | software and package state |
| `ISE-ACCOUNT-*` | user, service and administrative accounts |
| `ISE-AUTH-*` | authentication |
| `ISE-PRIV-*` | sudo and privilege |
| `ISE-SSH-*` | SSH posture |
| `ISE-SVC-*` | service exposure and state |
| `ISE-KERNEL-*` | sysctl and kernel security |
| `ISE-LOG-*` | audit and logging |
| `ISE-TIME-*` | clock and time synchronization |
| `ISE-CRYPTO-*` | cryptographic posture |
| `ISE-STORAGE-*` | filesystem, storage and mount security |
| `ISE-NET-*` | network configuration |
| `ISE-UPDATE-*` | update and support posture |

**`ISE-IDENT-*` is reserved and not in use.** An earlier draft used it for accounts. Host *identity*
(`machine-id`, `host_id`) and user *accounts* are different domains, and one prefix meaning both
would have been a permanent source of confusion. Accounts are `ISE-ACCOUNT-*`; the reservation stands
so the earlier draft resolves to this explanation rather than to silence.

## What a criterion contains

Required: `criterion_id` · `purpose` · `rationale` · `check_type` · `facts_required` · `dimensions`
(declared / resolved / active, where applicable) · `evaluation_semantics` · `applicability` ·
`limitations` · `evidence_pointers` · `version` · `default_severity`. Optional: `manual_verification` ·
`remediation_guidance`.

**Extended by the owner, 2026-10-14 (`D-111` extended; design only, no criterion authored):**

- `rationale`: why the condition matters, written so a reader who is not a Linux specialist can
  follow it. It explains; it never claims more than `evaluation_semantics` decides. The technical
  depth stays in `facts_required`, `evaluation_semantics`, `applicability`, `limitations` and
  `evidence_pointers`.
- `check_type`: the group the criterion belongs to inside its family, one of the check types the
  registry declares for that family (`check_types`). A check type is an ISEDRAF-authored name, never
  a framework's category, and declaring one authors no criterion.
- `manual_verification`: optional, read-only steps a person can follow to confirm the observed facts
  without ISEDRAF. Never a command that changes the host.
- `remediation_guidance`: optional, as before. It may describe a possible change, its operational
  impact and its risks; it is guidance only. ISEDRAF applies nothing.

Result states (D-121): `PASS` · `FAIL` · `NOT_APPLICABLE` · `MANUAL_REVIEW` · `NOT_EVALUATED`.
A criterion is atomic: it evaluates one normative condition. Only `COLLECTED` evidence yields a
result other than `NOT_EVALUATED` (`CMP-003`).

Severity (D-121): `critical` · `high` · `medium` · `low`. A `FAIL` produces a security finding
that takes the criterion's `default_severity` unchanged; a `MANUAL_REVIEW` produces a review
finding without a security severity.

Every field is ISEDRAF-authored. No framework identifier, title, description or safeguard text
appears in a criterion — a mapping is a separate object in a separate layer.

### Identity, versioning and retirement

- A `criterion_id` is immutable. It names one normative condition for as long as the catalog exists.
- `version` is an integer, separate from the ID, starting at 1. It increases when `facts_required`,
  `evaluation_semantics`, `applicability`, `dimensions` or `default_severity` change in a way that
  keeps the same condition. A change to WHAT the criterion asserts is a new criterion with a new ID.
- A criterion that is withdrawn moves to `retired_criteria` in the registry with its last version and
  the date. Its ID is never reused, and a retired ID never reappears among the active criteria.
- Renumbering does not exist: an ID is never changed to tidy an ordering.

### Family boundaries

A criterion belongs to the family of its **subject**, not to the mechanism that collects its facts.
A protocol version (IPv4, IPv6) is part of a criterion, never a family of its own.

| Family | Subject | Not here |
|---|---|---|
| ACCOUNT | which users, groups and service accounts exist, and their attributes | how they authenticate (AUTH), what they may elevate to (PRIV) |
| AUTH | how a person authenticates: PAM, password and login policy | SSH daemon settings (SSH) |
| PRIV | what an identity may elevate to: sudo and other delegation | the accounts themselves (ACCOUNT) |
| SSH | the SSH daemon's declared and effective configuration | PAM stacks SSH calls (AUTH) |
| STORAGE | filesystems, mounts and their protection options | kernel self-protection (KERNEL) |
| KERNEL | the kernel's protection of itself and of processes | network stack parameters (NET) |
| NET | network stack configuration, IPv4 and IPv6, forwarding included | firewall policy (out of scope) |

The other families keep the subjects in the namespace table above. **No family exists, or is added
through this catalog, for an area the frozen scope excludes**: firewall effectiveness, antivirus and
EDR products, intrusion detection, SIEM, backup systems, cloud or network controls, patch
availability and vulnerabilities (`D-09`). Changing that scope is a separate owner decision.

### Results without evidence or without context

Two cases are kept apart and never confused:

- `NOT_EVALUATED`: a required fact was not `COLLECTED`, so the condition cannot be decided (`CMP-003`).
- `MANUAL_REVIEW`: the facts were collected, but whether the criterion applies needs a judgement the
  evidence cannot make, for example a host's role or a mount's purpose, and no declared policy gives
  it.

How a declared role or policy reaches `applicability` is an open v0.3 design question. Until it is
decided, no criterion whose applicability depends on role or purpose is authored.

### One record, every surface

The registry entry is the only description of a criterion. `isedraf explain <criterion_id>` (`D-77`),
the report and a generated documentation page render that one record. There is no second registry,
no wiki copy and no hand-written explanation that could disagree with it.

### Illustrative shape

```text
ISE-SSH-001
  purpose      Determine the effective SSH root-login posture.
  rationale    Direct root login exposes the most privileged account to network login
               attempts and makes actions harder to attribute to a person.
  check_type   authentication settings
  facts        effective PermitRootLogin value · configuration source · resolution status
  states       PASS / FAIL / NOT_APPLICABLE / MANUAL_REVIEW / NOT_EVALUATED
  severity     high (default_severity)
  evidence     the exact normalized observed state
```

Nobody's permission is required to write a Linux security criterion about effective SSH
configuration. The licensing question begins one layer later, at *"this corresponds to provider X
control Y"* — which can involve another party's identifiers, taxonomy, titles, descriptions,
profiles, selection and arrangement, trademarks or proprietary mapping data. That is exactly why it
is isolated.

## Evaluation (`D-125`)

Owner decision 2026-11-01. These requirements govern how an admitted criterion is evaluated, recorded
and shown. They add no family, field, result, collector or policy input. Evaluation execution status
and the native assurance result are separate things: an evaluation that completes and records a
`FAIL` has succeeded.

**EVAL-001 (D-125) SHALL** **Four commands, four jobs.** `isedraf audit` collects evidence and is
unchanged by `D-125`. `isedraf evaluate` verifies committed evidence, evaluates the admitted criteria
and commits one evaluation. `isedraf explain <criterion_id>` renders a criterion record. `isedraf
report` renders committed evidence and committed evaluations. Evaluation never collects, never reads
a live host file and never reconstructs or repairs evidence. `explain` neither evaluates, collects
nor reads the state root, so it works on a host where no audit has run. `report` never evaluates.

**EVAL-002 (D-125) SHALL** **One installed record.** The registry is
`lib/isedraf/catalog/native_controls.json`. It is in every package payload, DEB and RPM alike. The
catalog gate, the evaluator, `explain`, the report and the generated criterion pages all read this one
file. No other copy exists in the repository or in a package, and none is made at build time.

**EVAL-003 (D-125) SHALL** **Verified input, fail closed.** `evaluate` reads one committed, ledgered
snapshot, the latest by default, and verifies it before use: its manifest hash, its ledger entry and
the digest of every section a criterion reads. An unledgered snapshot, a snapshot or section that does
not verify, a section schema the evaluator does not know, or a catalog record that fails the catalog
contract stops the evaluation with nothing written. Such a failure is never recorded as a result.

**EVAL-004 (D-125) SHALL** **One result per criterion; CMP-003 per required fact.** Every admitted
criterion yields exactly one result. `CMP-003` applies to the sources a criterion's `facts_required`
name, not to the section as a whole. When one of those sources is not `COLLECTED`, the result is
`NOT_EVALUATED`, with a reason naming the source and its status. That includes a source the evidence
shows to be part of the fact's domain but that was not collected (a compat INCLUDE of a NIS map is a
source that is `NOT_TESTED`). Facts observed in insufficient evidence may be shown as observations,
never as a result or a finding. Every result states its scope from the criterion record: what was
evaluated, and what a `PASS` does not establish.

**EVAL-005 (D-125) SHALL** **The evaluation record** (`SNAP-012` as amended, `SNAP-013`).
`evaluations/EVL-*/` holds:

- `manifest.json`: the `SNAP-013` fields, with `baseline_revision` null and `profile` null in v0.3,
  and the digest of the catalog file used;
- `results.json`: one record per evaluated criterion, carrying `criterion_id`, `version`, result,
  reason, scope and evidence pointers. Each pointer names the snapshot artifact, that artifact's digest
  as the snapshot manifest records it, and a JSON pointer into the artifact;
- `findings.json`: exactly what `D-121` section 5 defines. A `FAIL` gives one security finding with
  the criterion's `default_severity`, and a `MANUAL_REVIEW` gives one review finding with no security
  severity. `PASS`, `NOT_APPLICABLE` and `NOT_EVALUATED` give none, and there is no `PASS` finding;
- `changes.json`: no change record in v0.3. It states that no comparison was performed and why
  (baseline and delta are v0.4, `D-120`), and its list of changes is empty. A change is never
  manufactured.

An evaluation has no ledger entry (`STORE-020`) and never modifies a snapshot (`SNAP-011`).

**EVAL-006 (D-125) SHALL** **Regenerable identity.** An evaluation is identified by
`EVL-<the snapshot's created_at, compact>-<the first 16 hex digits of the SHA-256 of the canonical
SNAP-012 key>`. The key is the snapshot ID, the snapshot manifest hash, the baseline revision, the
engine version and the catalog digest. The ID is derived, not random: it is not computed from its own
manifest, so `SNAP-019`'s reason for randomness does not apply. No artifact holds a wall-clock time,
so the same key always yields byte-identical artifacts. When an evaluation with the key already
exists, `evaluate` checks it is identical and writes nothing. A difference is an engine error, never
an overwrite. Writes follow the snapshot discipline under the whole-run lock: a private temporary
directory, umask 077, exclusive creation, fsync, then an atomic rename.

**EVAL-007 (D-125) SHALL** **Exit codes keep their existing meanings (`OUT-001`).** `evaluate`
returns `0` when the evaluation is committed, or an identical one already exists, whatever results it
holds: a `FAIL` or a `NOT_EVALUATED` result does not change the exit code. It returns `64` for a usage
or engine error, including any `EVAL-003` failure, with nothing committed; `66` when the whole-run
lock is held; `67` when the state root cannot be used; and `70` when a root or sudo invocation is
refused (`AUTH-019`). `evaluate` never returns `2`: every criterion gets a result or nothing is
committed, so no partial evaluation exists, and an incomplete collection is reported by the audit's
own exit code. It never returns `1`, which is comparison semantics (v0.4). `explain` returns `0`,
`64` for an unknown criterion ID, and `70` under root. These rows enter `lib/isedraf/exitcodes.json`
together with the commands, not before.

**EVAL-008 (D-125, D-126) SHALL** **System-store evaluation is phased.** The first implementation evaluates
the stores the invoking user's unprivileged engine already writes: `USER_PRODUCTION`, and `DEV`, whose
artifacts are marked `DEV`. `D-126` admits `sudo isedraf evaluate` through `AUTH-033`; until that
route is implemented it stays refused with `70`. That amendment keeps the v0.2 boundary. The evaluator stays the unprivileged engine,
running as the `isedraf` account within the `AUTH-019` execution model. It reads committed evidence
only, uses no supervisor operation, needs no root evaluator and no root file access, collects nothing
live, and does not change the modes of `/var/lib/isedraf`. Until `AUTH-033` is implemented,
system-store evaluation is `PLANNED`, and nothing describes it as available.

**EVAL-009 (D-125) SHALL** **Explaining a criterion** (`D-77` applied to rule knowledge). `explain`
renders every field of the record, its lifecycle `EXPERIMENTAL` (`D-80`) and its result scope, and it
gives baseline state and delta as "not available: baseline and delta are v0.4". A generated
documentation page per criterion renders the same record and is never edited by hand. Explaining a
recorded result, with its evidence, is a later extension of the same contract.

## Build order

**Stage 1 — the catalog.** Author the ISEDRAF control universe. No CIS, ISO, SCF or anything else is
required anywhere in it. *(v0.3 and later. The first criterion, `ISE-ACCOUNT-001`, was admitted
by the owner on 2026-11-01.)*

**Stage 2 — open authorities.** For sources whose exact reuse rights are verified, add mappings. The
ISEDRAF criterion remains authoritative for the engine even here.

**Stage 3 — restricted authorities.** An encrypted licensed mapping pack plus a provider entitlement.

```text
ISEDRAF control       always available
ISEDRAF evidence      always available
provider mapping      entitlement required
provider report view  entitlement required
provider content      provider controlled
```

## Why this is frozen before W1-D

It means the technical engine can be finished without waiting for anyone.

```text
provider says yes later   →  existing controls + licensed mapping pack
provider says no          →  existing controls
```

Either way there is no collector rewrite and nothing is lost — which is what
*measure once, map everywhere, fix only the delta* has to mean in practice if it is going to survive
contact with a licensing negotiation.

## Current state

**Eight native criteria are admitted and evaluated:** `ISE-ACCOUNT-001` (owner decision 2026-11-01),
`ISE-ACCOUNT-002`, `ISE-ACCOUNT-003`, `ISE-ACCOUNT-004` and `ISE-SSH-001` (owner decision 2026-11-04), and
`ISE-ACCOUNT-005`, `ISE-AUTH-001` and `ISE-SSH-002` (owner decision 2026-11-05, `D-111`). Each record in `lib/isedraf/catalog/native_controls.json` is its criterion's only description. No
mapping of any kind exists.

Admission is an owner amendment. Since an evaluator exists, a criterion is admitted in the same owner
commit as its evaluator: `EVAL-004` requires a result for every admitted criterion, so a record without
its evaluator would stop every evaluation. A criterion is admitted when its record carries every required field,
names a check type its family declares, states which facts make its evidence sufficient and which
results it can produce, and cites no framework. A criterion yields only the results its semantics
justify; it is never made to produce all five to exercise them.
