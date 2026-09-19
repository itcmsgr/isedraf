<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# AI-Assisted Development

Status: IMPLEMENTED
Implements: D-91, D-92, D-93, D-94

ISEDRAF is developed with the assistance of AI tools, under human ownership. We disclose this openly so
that users, contributors and auditors can evaluate the project with full context. Nothing is hidden.

The structure of this document follows the convention already established in the ITCMS NFTBan project
(inspected, not copied). One difference is deliberate and is explained in *Commit metadata policy* below.

## AI-assisted development

ISEDRAF is conceived, directed, owned and maintained by:

**Antonios Voulvoulis / ITCMS**

AI systems are used as engineering assistance tools during design, review, implementation and testing.
They do not own the project, make final architectural decisions, or independently determine project scope.

Final decisions, acceptance of changes, licensing, release authority and project responsibility remain
with the human project owner.

## AI tools used

| Tool | Provider | Use in the project |
|---|---|---|
| ChatGPT | OpenAI | Architecture discussion, design review, challenge analysis, research assistance, documentation and prompt development |
| Claude / Claude Code | Anthropic | Architecture review and challenge, repository analysis, implementation assistance, testing and development workflows |
| Gemini | Google | Independent design proposals, challenge/review input and alternative architectural perspectives |

AI-generated proposals are treated as **input for human review**, not as authoritative project decisions.

A proposal from any AI system may be accepted · modified · rejected · superseded · recorded as an open
question.

Only decisions incorporated into the project's authoritative architecture and decision records become
ISEDRAF requirements.

## Attribution policy

ISEDRAF does not assign titles such as **architect**, **lead architect**, **maintainer**, **author** or
**owner** to AI systems.

Where useful for design provenance, project records may identify which AI system proposed or challenged a
particular idea. This is informational provenance only and does not imply authorship, ownership or
decision authority.

Model names or versions may be recorded when materially relevant to reproducibility, but the project does
not require an exhaustive historical inventory of every AI model interaction.

## Engineering responsibility

All AI-assisted code, documentation and design changes remain subject to the same ISEDRAF requirements
for human approval · clean-room development · requirement traceability · testing · security review ·
licensing · provenance · repository governance.

AI assistance does not alter **Copyright © 2026 Antonios Voulvoulis / ITCMS** or the project's licensing
and ownership.

## How AI tools are used day to day

AI tools may assist with drafting, code review, tests, audit prompts, architecture challenge and
documentation. They operate under a written contract — `docs/development/LLM_PROTOCOL.md` — which is
tool-neutral: no assistant receives its own competing version of project truth.

## What AI tools are not

- AI tools are **not authors, contributors, maintainers, copyright holders or owners** of ISEDRAF.
  They hold no rights in the project.
- All copyright in ISEDRAF is claimed by **Antonios Voulvoulis / ITCMS `<contact@itcms.gr>`** to the
  fullest extent permitted by law.
- AI assistance does not alter copyright or licence ownership.
- ISEDRAF is distributed under the **Mozilla Public License 2.0**; see `LICENSE`.

## Commit metadata policy

Two different trailers, with two different meanings:

| Trailer | Meaning | Policy |
|---|---|---|
| `Assisted-by: <tool> (<role>)` | **Disclosure.** This work was AI-assisted. Implies no authorship and no rights. | **Required** on every commit. `Assisted-by: none` when no AI was used. Enforced by the `commit-msg` hook. |
| `Co-Authored-By: <AI tool>` | **Authorship claim.** | **Must not be added** for any AI tool, in any form, including `OpenAI`, `Anthropic` or `Google` equivalents. |

Disclosure is mandatory; authorship credit to a tool is not granted. This gives complete transparency
without implying that an AI tool holds rights in the work.

`Co-Authored-By` trailers for **human** collaborators remain normal and expected. Any historical AI
`Co-Authored-By` trailer is legacy metadata only, is not an authorship or copyright assignment, and
history is not rewritten to remove it.

This is **decision D-93** in `docs/architecture/INTERNAL_RECORDS.md`, which is the authoritative current
statement. `docs/architecture/INTERNAL_RECORDS.md` records only the history of how it changed. Disclosure is
mandatory; authorship credit to a tool is not granted.

Contributors must configure their tooling accordingly. If an AI assistant or IDE adds an AI
`Co-Authored-By:` trailer automatically, remove it before committing; the `Assisted-by:` trailer is what
records the assistance.

## Never accepted without human review

Architecture decisions · security claims and limitations · privilege and capability changes ·
licensing and provenance statements · release notes · anything under `docs/architecture/` or covered by
the governance manifest.

## Verification

All code, AI-assisted or not, passes the same gates: `make check`, negative tests, corpus scenarios and
requirement traceability. AI assistance is never a reason to relax a gate, and no gate may be weakened to
make AI-generated work pass.

## What is not published

Private prompts, hidden reasoning, chain-of-thought and raw chat transcripts are not committed. Transcripts
may contain sensitive host data. `docs/development/DESIGN_PROVENANCE.md` *(PLANNED — not yet created)* records design phases, which
AI-assisted discussions produced which decision IDs, which external proposals were reviewed and their
outcome, and the human approval point — as summaries.

---

Copyright © 2026 Antonios Voulvoulis / ITCMS.
