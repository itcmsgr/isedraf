<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# ISEDRAF consolidated product HLD

Implements: D-78, D-79, D-82, D-84, D-111, D-112

The product model, frozen. What ISEDRAF is, what it runs on, and the three ways a finding can be
interpreted — with the boundaries between them stated so that a commercial negotiation cannot move
them later.

```text
                 64-BIT LINUX
              x86_64      ARM64
                  \        /
                   \      /
                    FACTS
                      ↓
              ISEDRAF CONTROLS
                      ↓
             FINDINGS + EVIDENCE
                      ↓
          ┌───────────┼────────────┐
          ↓           ↓            ↓
       NATIVE      OPEN MAP    LICENSED BYOL
         A            B             C
```

ISEDRAF owns the native criteria. The customer owns its host evidence. External providers retain
rights in their frameworks. Mappings are optional downstream interpretations, and the core never
depends on them.

## Platform model

ISEDRAF targets **64-bit Linux**, across two architecture families:

```text
x86_64 / AMD64          ARM64 / AArch64
```

**Support is a matrix, not a sentence.** A platform is supported when five things are true together,
and the fifth is the one that is usually skipped:

```text
CPU architecture  +  distribution family  +  version
                  +  collector capability
                  +  DEMONSTRATED VALIDATION
```

The claim ISEDRAF may make is therefore:

> ISEDRAF is designed for heterogeneous 64-bit Linux systems across x86-64 and ARM64, with
> distribution and platform support published according to demonstrated validation.

Not *"all Linux"*, not *"every distribution"*, and not *"ARM supported"* on the strength of the code
containing no architecture branches. Portable code is a reason to expect a platform to work; it is not
evidence that it does.

`docs/reference/PLATFORM_COMPATIBILITY.md` is the authority for what has actually been measured, and
`make check-public-claims` refuses a platform claim the status registry does not support.

### Families, in the order they become real

| Family | Position |
|---|---|
| Debian · Ubuntu | measured on `x86_64` |
| Enterprise Linux — RHEL-compatible, AlmaLinux, Rocky, CentOS Stream | measured on `x86_64`; other EL variants only after validation |
| SUSE — openSUSE; SLES **only after validation** | openSUSE measured on `x86_64` |
| ARM64 — Debian/Ubuntu arm64, Raspberry Pi OS 64-bit, other edge targets progressively | **no campaign has run** |

A family appearing in that table is a target, not a certification. The matrix grows as evidence grows,
one platform at a time, and a row moves only when a campaign produces the evidence for it.

## Core flow

```text
LINUX SYSTEM → COLLECTORS → NORMALIZED FACTS → ISEDRAF NATIVE CONTROLS
             → EVALUATION → FINDINGS + EVIDENCE
```

Collection is **capability-driven**: a tool is either present or it is not, and that question has the
same answer on every distribution. There is no `if rhel / elif debian` anywhere in the collectors, and
that is why one implementation reached eleven distributions and CPython 3.6.8 through 3.14.4 without
distribution-specific code.

Native controls live in the `ISE-*` namespace fixed by `D-111`. They answer what ISEDRAF observed,
what its own criterion expected, what differs, what evidence proves it and what the limitation is.
They do not answer what any external framework requires.

## The three modes

### Mode A — native report. Always available.

```text
Linux facts → ISE-* controls → findings → evidence → report
```

No external framework is involved, and the report says exactly what it is: *these are the technical
findings ISEDRAF identified against its own published criteria.* No mapping, no provider, no claim of
regulatory compliance.

**This is the product.** ISEDRAF is a complete Linux assurance engine using only its own controls,
and remains fully useful if no external framework agreement is ever signed.

### Mode B — optional open authority mapping.

```text
A  +  mapping to an external authority whose exact reuse rights were validated first
```

Candidates for investigation include NIST, NIS2 and DORA. **That list is not evidence that any of
them is approved.** Before a mapping becomes public, the exact source, exact version, reuse terms,
attribution requirements, machine-readable rights and derivative rights are validated and recorded.
*"Government"* and *"open source"* are not evidence by themselves — they are the cases where
everyone assumes and nobody checks.

### Mode C — optional commercial BYOL mapping.

```text
A  +  provider-authorized pack  +  the customer's own provider entitlement
```

Only after a written agreement. The provider keeps its IP, licensing, subscription, billing,
entitlement issuance and customer relationship. ISEDRAF supplies the host evidence, the native
controls, the generic mapping engine, entitlement verification and the authorized evaluation.

**No provider is supported because this architecture exists.** The architecture being ready is not a
provider having agreed.

### The invariant

```text
A exists independently.
B adds information to A.
C adds information to A.
NEITHER B NOR C CAN CHANGE A.
```

A mapping never alters a collector, a fact, a native control, a native result, or any evidence. It is
an additional interpretation of something already decided. Concretely: no framework may change
`host_id`, canonical facts, snapshot bytes, `manifest_hash`, or ledger records.

That is what gives three clean failure domains. A licensing disagreement with one provider can
invalidate that provider's mapping pack; it cannot invalidate `ISE-SSH-*`, the collected SSH state, or
a different mapping built later under different rights.

## Mapping is not compliance

```text
mapped evidence  ≠  organizational compliance  ≠  certification
```

A mapping carries its strength — `DIRECT_TECHNICAL`, `SUPPORTING_EVIDENCE`, `PARTIAL`,
`ORGANIZATIONAL_ONLY`, `NOT_HOST_ASSESSABLE` — because most of what a framework asks for is not
decidable from one host. Whole-regime compliance is never inferred from Linux evidence.

## Report structure

```text
1. Host identity      2. Platform / inventory     3. Native findings
4. Evidence           5. Delta from approved baseline
6. Authority mappings                                          OPTIONAL
   ├── open mappings      if installed
   └── licensed mappings  if authorized
```

**No mapping installed is a normal, fully supported state**, rendered as `Framework mappings: None
installed` or omitted. Locked provider names are never shown as teasers. Where a licensed mapping is
present, the report records provider, framework, version, pack digest, entitlement status at
evaluation time and evaluation time — and never the customer's credential.

## Development order

```text
1 native collectors        2 native ISE-* criteria     3 findings / evidence / reporting
4 generic mapping engine   5 first verified-open map   6 provider BYOL, only with written rights
7 more architectures, distributions and edge targets — validated individually, in parallel throughout
```

Platform validation runs in parallel and never waits on a framework negotiation. Steps 1-3 are the
product; 4-6 increase the value of evidence that already exists.

## Current state

Mode A is partially built — identity, inventory and reporting work; the native control catalog is
frozen and **empty**, and W1-D authors it. Mode B and Mode C are **design only**. Zero mappings, zero
licensed packs, zero provider agreements, zero bundled framework content.
