<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Framework mapping policy

Status: IMPLEMENTED
Implements: D-84, D-90, GOV-001

**ISEDRAF is framework-neutral.** The open-source engine produces native host evidence independently
of any third-party framework. Optional mappings may be distributed separately where licensing
permits. Third-party marks and control content remain the property of their respective owners.
**Availability of a mapping pack does not imply certification or endorsement.**

## What that means in practice

The collectors and the technical criteria are authored by ISEDRAF and describe the Linux host. They
do not exist because a framework asked for them, and removing every framework would leave them
exactly as useful:

```text
LINUX HOST
    ↓
ISEDRAF FACTS                 what the operating system can actually show
    ↓
ISEDRAF NATIVE CRITERIA       ISEDRAF's own technical judgements
    ↓
ISEDRAF EVIDENCE / RESULT     observed, with its limits stated
    ↓
OPTIONAL FRAMEWORK MAPPING    a downstream overlay, if one is licensed
```

The arrow never runs the other way. A framework requirement does not define how a collector is
implemented, and there is no `cis_collector.py`, `iso_collector.py` or `scf_collector.py` — there is
a users collector, an SSH collector, a logging collector. One host collection can then serve many
mappings.

> Measure once. Map everywhere. Fix only the delta.

## What is available today

**No framework mapping pack exists, is bundled, or is licensed.** No third-party control text,
identifier set or mapping dataset is present in this repository, in the packages, or in the SBOM.

The engine is designed so that mappings can be added later as independently versioned packs. That is
a statement about architecture, not about availability, and this document is the only place either is
claimed.

## Licensing is decided before content arrives, not after

Third-party framework content is **not** relicensed by sitting in this repository or by being
processed by this engine. MPL-2.0 applies to what ISEDRAF has the right to license, and nothing else.

`scripts/ci/framework_sources.json` records the licensing state of every framework source, and it is
**deny by default**: anything not recorded as `BUNDLED_OPEN` does not enter the public repository,
the export, the packages or the SBOM. Unknown licensing state means not distributable.

`make check-licensing` enforces this, and five defect injections prove it can refuse: an unregistered
pack, a `LICENSE_REQUIRED` pack bundled anyway, private research committed into the tree, a public
document claiming support for a restricted framework, and a file with no licence statement.

## A mapping is not a certification

Even with an authorised pack installed, ISEDRAF reports what it observed on a host and which external
identifier a mapping associates with that observation. Each mapping carries its strength —
`DIRECT_TECHNICAL`, `SUPPORTING_EVIDENCE`, `PARTIAL`, `ORGANIZATIONAL_ONLY`, `NOT_HOST_ASSESSABLE` —
because most of what a framework asks for is not decidable from a single host.

Host evidence is supporting technical evidence. It is not organisational compliance, and ISEDRAF does
not use the words *compliant* or *certified* about either.

## Trademarks

MPL-2.0 licenses the ISEDRAF **source code**. It does not grant rights to third-party framework
names, marks, logos or certification badges, and no framework logo is present in this repository.
The same separation applies to the ISEDRAF name itself under a future project trademark policy.
