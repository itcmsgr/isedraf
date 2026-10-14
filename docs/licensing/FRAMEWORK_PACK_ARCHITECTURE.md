<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Framework pack architecture — design only

Status: PLANNED
Implements: D-78, D-79, D-82, GOV-001

**Nothing here is implemented.** There is no pack loader, no manifest reader, no entitlement
mechanism and no signing. This records the intended boundary so that the first pack cannot quietly
establish a worse one.

## Native criteria come first

ISEDRAF authors its own technical criteria in a stable namespace, independent of any framework:

```text
ISE-ASSET-*   ISE-IDENT-*   ISE-AUTH-*    ISE-PRIV-*   ISE-SSH-*    ISE-LOG-*
ISE-TIME-*    ISE-KERNEL-*  ISE-SVC-*     ISE-STORAGE-*  ISE-NET-*
```

Each criterion states: `criterion_id`, purpose, facts required, collection requirements, evaluation
semantics, limitations, evidence references, version.

These are independently authored. They do not copy or paraphrase restricted third-party safeguard
text, and the clean-room rule that governs the rest of this project governs them too.

## A pack is a downstream overlay

```text
framework_pack
    metadata
    license
    provenance
    mappings[]
```

Each mapping links an ISEDRAF criterion to an external identifier and carries its strength:

| Strength | Meaning |
|---|---|
| `DIRECT_TECHNICAL` | The host observation decides the external requirement. |
| `SUPPORTING_EVIDENCE` | The observation contributes; it does not decide. |
| `PARTIAL` | Only part of the requirement is host-observable. |
| `ORGANIZATIONAL_ONLY` | The requirement is about process, not host state. |
| `NOT_HOST_ASSESSABLE` | A single host cannot answer it at all. |

Whole-framework compliance is never inferred from a host-level observation. Most rows in a real pack
would be the bottom three.

## Intended manifest fields

```text
pack_id          framework_id       framework_version     pack_version
publisher        provider           source_reference      license_id
license_class    entitlement_required                     redistribution_status
commercial_use_status                mapping_schema_version
created_at       content_digest     signature_status
```

Per mapping: `native_criterion_id`, `external_control_id`, `mapping_strength`, `scope`,
`limitations`. No restricted external text appears in the schema or its examples.

## Licensing classes for packs

`OPEN` · `LICENSED_PROVIDER` · `BYOL` · `PARTNER_DISTRIBUTED` · `USER_SUPPLIED`

No framework is assigned a class until contract review establishes one.

## Offline first

ISEDRAF's engine is local by design, and that must not change to serve licensing. The intended
mechanism is a signed pack plus a signed entitlement file, verified locally:

```text
framework.pack
framework.lic
```

**No audited production host should need continuous internet connectivity merely to assess itself.**
An optional online activation path may exist later; it must not add a network dependency to the core.

No cryptography and no licensing server is implemented in this lane, and none is designed here — a
protocol written before its legal and commercial constraints are known is a protocol that will be
rewritten.

## Reserved command surface

```text
isedraf framework list
isedraf framework status
isedraf framework install <pack>
isedraf framework verify <pack>
```

Provider-specific activation is not designed until an agreement defines what it must enforce.

## Behaviour without a pack — which is today

Identity, inventory, native criteria, evidence, delta and reports all work. Framework-specific output
simply does not exist. Reports say:

```text
Framework mappings:
    None installed
```

or omit the section. **Locked provider names are never rendered as teasers.** Core functionality is
never degraded to make an absent pack noticeable.

## Future acceptance requirements

Recorded now, to be tested when a loader exists rather than implemented opportunistically:

1. The core report is complete with zero packs installed.
2. Absence of a pack does not alter native evidence in any way.
3. Framework metadata cannot alter `host_id`, canonical host facts, snapshot hashes or ledger
   records. Mapping is strictly downstream of the hashed state.
4. A public package contains no `LICENSE_REQUIRED` pack.
5. Removing every pack leaves the collectors and criteria meaningful.

## USER_SUPPLIED framework import — future design question

**PROPOSAL / DESIGN OPEN (recorded 2026-10-09).** It does not alter D-112's modes, and it does not
authorize any CIS content or mapping. D-112's modes keep their frozen meaning: A is the native report,
always available; B is an open-authority mapping whose reuse rights were validated first; C is
licensed BYOL - a provider-authorized pack plus the customer's provider entitlement, verified
offline. A user-supplied import is a separate question, not a reading of Mode C.

**Purpose.** Let an organization import framework material it is independently authorized to possess
and use, without ISEDRAF redistributing that framework.

Three acts are kept apart, because each raises a different legal and technical question:

```text
the user supplies framework content  !=  the user authors the mapping  !=  ISEDRAF may distribute the mapping
```

Holding a licensed copy does not settle the third: an ISEDRAF-authored mapping from `ISE-*` criteria
to a provider's identifiers may fall under the provider's terms and OD-08 however the user obtained
the source. Two distinctions are kept for the design, as concepts, not fields:
`framework_source_origin` (`OPEN_AUTHORITY`, `PROVIDER_AUTHORIZED`, `USER_SUPPLIED`) and
`mapping_author` (`ISEDRAF`, `PROVIDER`, `USER`, `THIRD_PARTY`).

Open questions:

1. What source formats are accepted?
2. Does import occur on the audited host or off it?
3. Who authors the `ISE-*` to external-control mapping?
4. Is a user-authored mapping treated differently from an ISEDRAF-authored one?
5. What framework-derived material may be persisted, exported or redistributed?
6. How is provider entitlement or user authority represented?
7. How does OD-08 apply to identifiers, titles, objectives and derived mappings?
8. Can imported material be converted into the signed pack format above?
9. What parser and security boundary does a hostile or malformed source file require?

**Owner direction, not a decision.** No document parser (for example for `.xlsx`) runs in the audited
host's runtime. The preferred direction is that source material goes to an off-host importer and
converter, which produces a normalized signed pack that the mapping engine reads. That keeps document
parsing and licensing-sensitive source material outside the assurance runtime. Questions 2 and 8 stay
open until the v0.5 design.
