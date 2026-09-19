<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# ISEDRAF Native Control Catalog

Implements: D-78, D-79, D-82, D-84, D-111

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

Authority: `scripts/ci/native_controls.json`. `make check-native-catalog` requires this document and
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

Required: `criterion_id` · `purpose` · `facts_required` · `dimensions` (declared / resolved / active,
where applicable) · `evaluation_semantics` · `applicability` · `limitations` · `evidence_pointers` ·
`version`. Optional: `remediation_guidance`.

Result states: `PASS` · `FAIL` · `PARTIAL` · `NOT_EVALUATED`.

Every field is ISEDRAF-authored. No framework identifier, title, description or safeguard text
appears in a criterion — a mapping is a separate object in a separate layer.

### Illustrative shape

```text
ISE-SSH-001
  purpose      Determine the effective SSH root-login posture.
  facts        effective PermitRootLogin value · configuration source · resolution status
  states       PASS / FAIL / PARTIAL / NOT_EVALUATED
  evidence     the exact normalized observed state
```

Nobody's permission is required to write a Linux security criterion about effective SSH
configuration. The licensing question begins one layer later, at *"this corresponds to provider X
control Y"* — which can involve another party's identifiers, taxonomy, titles, descriptions,
profiles, selection and arrangement, trademarks or proprietary mapping data. That is exactly why it
is isolated.

## Build order

**Stage 1 — the catalog.** Author the ISEDRAF control universe. No CIS, ISO, SCF or anything else is
required anywhere in it. *(W1-D and later. Nothing is authored today.)*

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

**No native criterion is authored.** The namespace is frozen; the catalog is empty; no mapping of any
kind exists. `scripts/ci/native_controls.json` says so, and the gate does not treat an empty catalog
as a pass by omission.
