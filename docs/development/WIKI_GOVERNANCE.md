<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Wiki Governance

Status: PLANNED
Implements: D-87, OD-11, §37

## Current position

**There is no GitHub Wiki for ISEDRAF, and none may be created without an owner amendment** (D-87).

This document is the contract that applies **if** one is ever enabled. It is written now so that the
decision is already governed when it is taken, rather than improvised afterwards.

## Why `/docs` and not a wiki

`/docs` is canonical because it is reviewed like code: it is versioned with the change that caused it,
it passes doc lint in `make check`, its generated files are freshness-verified, and its history is bisectable
alongside the implementation. A wiki has none of those properties — it is edited out of band, has no
review gate, and drifts silently from the code it describes.

The preferred route for navigation and presentation is therefore **publishing `/docs` itself** (for
example via GitHub Pages) from the same reviewed tree — open decision **OD-11**, itself blocked behind
**OD-01**, the public project name.

## If a wiki is ever enabled

**The wiki is a presentation and navigation surface. It is never authoritative.**

Permitted: navigation · onboarding · simplified operator walkthroughs · links into canonical
documentation · selected mirrored material where genuinely useful.

**Forbidden:** a requirement, architecture decision, security limitation, schema contract, supported-platform
statement or evidence-model explanation existing **only** in the wiki. If it matters, it lives in `/docs`
first.

Every mirrored page identifies its canonical source:

```
Canonical source: docs/<document>.md

This wiki page is a convenience view.
If the two differ, the repository document governs.
```

Never maintain two independently authored versions of architectural truth.

## Suggested structure, if enabled

Home · Quick Start · Understanding Snapshot → Baseline → Delta · Identity and Privilege ·
Recording Coverage · For System Administrators · For Security Auditors · Exporting ISEDRAF Evidence ·
Integrity Verification · FAQ · Troubleshooting · Roadmap.

Each technical page links back to its canonical `/docs` source. The wiki is written for navigation and
accessibility, not architecture ownership.

## Rules that still apply

Everything in `docs/development/DOCUMENTATION_POLICY.md` and `docs/STYLE_GUIDE.md` applies unchanged:
coexistence rather than competition · no copied external prose · status labels on every feature statement ·
no forbidden claims · limitations stated adjacent to the feature.

Wiki content is **not** covered by `make check`. That is precisely why it may not hold anything that
matters — there is no gate to catch it when it goes stale.

## Enabling it

An owner amendment in `docs/architecture/INTERNAL_RECORDS.md` that resolves OD-11, records how wiki drift will
be detected, and states who reviews wiki edits. Gate **C-13** currently fails on any wiki-only
architectural content.
