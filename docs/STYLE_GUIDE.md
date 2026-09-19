<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Documentation Style Guide

Status: IMPLEMENTED
Implements: D-87, D-88, D-89, §34

<!-- doclint:exempt-forbidden-terms — this file must name the terms it forbids -->

This guide freezes ISEDRAF's voice so that it does not drift across sessions, contributors or years.
It is not a general writing guide.

## Product name

**ISEDRAF** — one word, all capitals. Never `Isedraf`, `IseDraf`, `ISE-DRAF` or `ise draf`.
The CLI and package identifier is lowercase `isedraf`.

OD-01 is resolved (D-108): ISEDRAF is the project name. Formal trademark clearance is still
outstanding, so public-release material stays gated on that. Public-facing pages say so once, near the top; they do not
repeat the disclaimer in every paragraph. The command is lowercase: `isedraf`.

## Voice

Technical · calm · precise · vendor-neutral · non-adversarial. Let the corpus and the engineering
discipline establish credibility.

Write for three readers over one truth: the **administrator** (*what changed and what needs attention?*),
the **auditor** (*what was observed, how, what is provable, what is not?*), the **organization**
(*how do I ingest this?*). Never build three separate truths.

## Forbidden terms

Never: `revolutionary` · `world-leading` · `best` · `beats` · `destroys` · `replacement` ·
`competitors fail` · `100% secure` · `fully compliant` · `military-grade` · `zero-trust certified` ·
`guaranteed` · `tamper-proof` · `non-repudiable` · `host unchanged` · `kernel-generated` ·
`read-only guaranteed`.

Gate C-05 enforces this. A file that must name these terms — this one, `DOCUMENTATION_POLICY.md`,
`LLM_PROTOCOL.md` — carries `<!-- doclint:exempt-forbidden-terms -->`. A single quoted span uses
`<!-- doclint:quote -->`.

## Preferred wording

| Instead of | Write |
|---|---|
| the host is secure | no security-relevant change observed |
| the host is unchanged | no security-relevant change observed |
| verified | observed · collected · locally consistent · package consistent |
| guaranteed read-only | filesystem protection enforced; kernel mutation minimized |
| compliant | host technical evidence for … |
| not applicable | `NOT_TESTED` with a reason |

## Enum values

Uppercase, in code font, exactly as the schema spells them:
`COLLECTED` `PARTIAL` `NOT_TESTED` `ERROR` · `PASS` `FAIL` `MISMATCH` `NOT_APPLICABLE` `MANUAL_REVIEW`
`NOT_EVALUATED` · `NOT_COMPARABLE` · `ADDED` `REMOVED` `MODIFIED` `ENABLED` `DISABLED` ·
`SECURITY_REGRESSION` `SECURITY_IMPROVEMENT` `EXPECTED_CHANGE` `REVIEW_REQUIRED` `INFORMATIONAL` ·
`EVENT_RECORDED` `ESTIMATED` `UNKNOWN` · `DRAFT` `EXPERIMENTAL` `STABLE` `DEPRECATED` `RETIRED`.

Never invent a competing spelling or a synonym in prose. `docs/reference/GLOSSARY.md` is canonical.

## Commands

`$` for an unprivileged prompt, `#` for root. Never hide `sudo` inside an example — if a command needs
privilege, show the `#` prompt and say why.

```
$ isedraf identity users
# isedraf
```

## Status labels

Every feature statement is `IMPLEMENTED` · `EXPERIMENTAL` · `PLANNED` · `FUTURE` · `OUT_OF_SCOPE`.
Present tense only for the first two. `PLANNED` and `FUTURE` belong in `docs/roadmap/ROADMAP.md` or a
clearly labelled architecture reservation.

Wrong: *ISEDRAF inventories all installed software.*
Right: *Future direction: a local software inventory module is planned to reuse the same
snapshot → baseline → delta model.*

## Limitations

Written in plain language, **adjacent to the feature they qualify** — never footnoted away, never collected
into a single page nobody reads. A limitation is a feature of honest evidence.

## Requirement citation

`Implements: SNAP-012, D-37` in headers. In prose, cite where it helps:
*Prototype requirement DELTA-004 — verified by `tests/unit/test_not_comparable.py` *(PLANNED — not yet created)*.*

## Dates and times

Artifacts: UTC RFC 3339 (`2026-09-17T14:03:21Z`). Prose: ISO dates (`2026-09-17`). Never a bare
locale-dependent format. Relative values (*63 days remaining*) are render-time observations computed from
absolute facts, never stored as canonical state.

## Coexistence phrasing

Never `X vs Y`, `replaces X`, `better than X`, `X cannot do Y`, rankings, scores or winners — about any  <!-- doclint:allow-framing: this line STATES the prohibition -->
project, including NFTBan.

- *OpenSCAP evaluates SCAP content. ISEDRAF does not implement SCAP internally.*
- *osquery provides broad queryable host telemetry. ISEDRAF focuses on approved baselines, classified
  state delta and evidence semantics. They can coexist.*
- *AIDE performs file integrity monitoring. ISEDRAF does not attempt whole-filesystem FIM.*
- *NFTBan provides runtime Linux network protection. ISEDRAF does not assess firewall effectiveness.
  They are independent ITCMS projects.*

Never describe another project's current capabilities without verifying them against that project's own
documentation.

## Language

English is canonical. Translations may exist later; they never become authoritative.
