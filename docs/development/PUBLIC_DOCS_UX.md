<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Public documentation UX — owner requirement

Status: EXPERIMENTAL
Implements: D-87, D-88

**Owner requirement, 2026-09-26.** The text between the rules below is the owner's, recorded
verbatim. Nothing in it has been edited; the sections after it are the implementation's.

---

## DOC-PUBLIC-UX-001 — Human-first documentation

ISEDRAF public, operator-facing and auditor-facing documentation SHALL be written for a technically competent human who did not build the project.

The goal is **understanding, not completeness on every page**.

Public documentation SHALL prefer:

- plain language before internal terminology;
- short sections and short paragraphs;
- one concept per section;
- diagrams and concrete examples where they explain faster than prose;
- progressive disclosure: overview first, detail second, normative references last;
- direct statements of what ISEDRAF does, does not do, observed, could not observe, and cannot conclude;
- links to the normative HLD, decision records and implementation contracts instead of reproducing them;
- the minimum amount of information necessary for the reader to make the next correct decision.

Public documentation SHALL NOT require the reader to understand decision IDs, freeze sets, amendment history, implementation questions, CI gates, lane names or development chronology merely to understand the product.

Internal identifiers such as `HLD-*`, `D-*`, `IQ-*`, `CMP-*`, `EVID-*` and freeze-manifest terminology MAY appear as secondary references, but SHALL NOT drive the narrative.

### Writing persona

The public documentation voice is:

**calm · precise · human · concise · technically credible · non-marketing · non-academic**

Write as an experienced infrastructure/security engineer explaining the system to another professional.

Do not write like:

- a standards committee unless the document is itself normative;
- a source-code comment;
- an internal engineering handoff;
- a legal contract;
- a research paper;
- promotional copy.

Prefer:

> ISEDRAF records what the host exposes locally and preserves the source and collection status.

over:

> EVID-001/D-13 normative resolved-state semantics SHALL establish the authoritative evidence precedence...

The normative requirement can be linked afterwards.

### Less is a feature

A public document is not improved by containing more information.

If a paragraph does not help the reader understand:

1. what ISEDRAF is;
2. what it observed;
3. how it reached that observation;
4. what can be concluded;
5. what cannot be concluded; or
6. what the reader should do next,

it probably belongs in the internal/normative documentation instead.

Repeated information SHALL be consolidated rather than copied between documents.

### Two documentation layers

ISEDRAF maintains two deliberate documentation layers:

**Human/public layer**

`README`, Getting Started, Architecture, Evidence Model, Auditor Guide, Report Guide, Security & Limitations, Development Guide.

These documents explain the product and provide a clear path through it.

**Normative/internal layer**

HLD, Evidence & Trust specification, decision register, amendments, freeze manifests, lane contracts, implementation questions, falsification records and engineering governance.

These preserve precision, traceability and engineering authority.

The public layer SHALL explain the normative layer; it SHALL NOT duplicate it.

### Reader test

A new administrator or auditor SHALL be able to answer, without reading the internal corpus:

> What is ISEDRAF?  
> What did it collect?  
> What did it not collect?  
> What does this report tell me?  
> What does it not prove?  
> Where did this fact come from?  
> What should I read next?

If those answers require navigating dozens of documents, the documentation design has failed.

### Redesign principle

**Less, but clearer.**

The documentation redesign SHALL optimize for comprehension and navigation rather than document count, requirement count or information density.

The technical depth remains available, but it is revealed when the reader needs it rather than presented all at once.

---

## Which documents are public

The owner separately directed, on 2026-09-26, that the public GitHub surface carries no
architect or developer documents: "we keep only what needs to be there, all other local".
The public layer checked here is therefore:

README, Getting Started, Evidence Model, Auditor Guide, Report Guide, Security & Limitations.

Architecture and Development Guide appear in the owner text above but are left out of the
checked list until the owner confirms whether they are public. The list lives in
`scripts/ci/public_layer.json`; a document not listed there is internal and is not checked.

## How it is checked

`scripts/docs/public_ux.py` runs in `make check` as `check-public-ux`. It is **REPORT-ONLY**
until milestone DOC-PUBLIC-01: findings print as NOTE lines and the build passes. Setting
`"enforce": true` in `scripts/ci/public_layer.json` makes every finding a failure; that is the
only change needed, and it is meant to be reviewed on its own.

The gate's self-test builds synthetic documents, proves each rule fires on a bad one and
that a clean set produces no findings, and exercises both modes. The self-test is never
report-only: it must pass for `make check` to pass.

### Machine-checked (exact)

- Every listed public document exists. A missing one is reported as NOT YET WRITTEN.
- The README links to every public document that exists.
- The README stays within the front-door length the documentation policy sets (150 lines).

### Proxies (measured, but only a signal)

Each of these goes wrong when comprehension does. None of them proves comprehension.

| Rule | What is measured | What it stands for |
|---|---|---|
| a | Internal identifiers (shapes taken from the reference-integrity gate) and internal-process words (freeze set, amendment, lane, gate, register, implementation question) outside a final "References" section | internal terms driving the narrative |
| b | Paragraphs over 120 words, sections over 400 words, outside code and tables | short sections, short paragraphs, one concept per section |
| c | README headings answering: what it is, what it does not do, install, first run, where next | the reader test, for the front door |
| d | The same paragraph of 40 words or more in two public documents | consolidate, do not copy |
| e | The claim and framing term lists the documentation lint already uses | non-marketing voice |

Heading keywords are a weak proxy: a heading can contain "what is" without answering it.

### Human review (not machine-checkable)

- Whether the reader test is actually passed: can a new administrator or auditor answer the
  seven questions without the internal corpus?
- Plain language, tone and persona: calm, precise, human, non-academic.
- One concept per section, and progressive disclosure: overview, then detail, then references.
- Whether a diagram or example would explain faster than the prose.
- Whether a paragraph helps the reader decide what to do next, or belongs in the internal layer.
- Academic register. There is no existing term list for it, so none has been invented.

## References

Documentation policy: `docs/development/DOCUMENTATION_POLICY.md` (D-87, D-88, D-89).
Registry: `scripts/ci/public_layer.json`. Gate: `scripts/docs/public_ux.py`.
