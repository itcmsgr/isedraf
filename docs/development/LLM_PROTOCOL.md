<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# LLM Contribution Protocol

Status: IMPLEMENTED
Implements: D-87, D-91, D-92, D-93, D-94, OD-01

<!-- doclint:exempt-forbidden-terms — this file names the claims it forbids -->

This is the **tool-neutral** contract for every AI-assisted contribution to ISEDRAF: Claude, ChatGPT,
Gemini and any future assistant. `CLAUDE.md` is the Claude Code entry point and does not replace this
document; it points here. **No AI tool receives its own competing project truth.**

Human ownership is unchanged by any of this. Antonios Voulvoulis / ITCMS defines scope, makes and approves
decisions, reviews output, and is responsible for the project.

---

## 1. Authority order

1. Frozen architecture documents — `docs/architecture/` (hash-locked by `FROZEN_MANIFEST.sha256`)
2. `docs/architecture/INTERNAL_RECORDS.md` — the only repository copy
3. `CLAUDE.md` (or the tool-specific entry point) and this protocol
4. Canonical documentation under `/docs`
5. `README.md`
6. Issues, discussions, external articles

A lower layer never contradicts a higher one. On conflict: **keep the higher statement**, record the
conflict in `docs/IMPLEMENTATION_QUESTIONS.md`, and mark the lower document stale.
**Never update documentation to match a bug.**

## 2. Mandatory read order

Before proposing or making any change, read in this order:

1. `CLAUDE.md` — or the tool-specific entry point
2. **this file**
3. `docs/architecture/INTERNAL_RECORDS.md`
4. `docs/architecture/FROZEN_MANIFEST.sha256` *(PLANNED — not yet created)*
5. the relevant frozen architecture documents
6. `docs/CURRENT_STATE.md` — what exists *right now*
7. `docs/REPOSITORY_MAP.md` — where things live, what must never be edited
8. `docs/development/requirements-trace.md` *(PLANNED — not yet created)* — generated
9. `VERSION`
10. `CHANGELOG.md`
11. the relevant implementation module
12. the relevant tests and corpus fixtures
13. `docs/IMPLEMENTATION_QUESTIONS.md` — assumptions, never authority

**Architecture is never reconstructed from incomplete implementation.** Code may be partial, stubbed or
wrong. Frozen requirements govern. Do not begin by searching the codebase and inferring the design from
what you find.

Before changing a domain, state: the requirement IDs · the canonical state schema · the collector and
parser versions · the comparability effect · the existing negative tests · the related open decisions.

## 3. Claim labels

Every statement about the project is labelled:

| Label | Meaning |
|---|---|
| `REPOSITORY FACT` | verified in this repository, with a path |
| `FROZEN REQUIREMENT` | from a frozen document, with a requirement ID |
| `OPEN DECISION` | an `OD-` item, unresolved |
| `INFERENCE` | reasoned, not verified |
| `PROPOSAL` | suggested, not decided |
| `EXTERNAL INFORMATION` | from outside the repository |

**An inference is never presented as implemented behaviour. A roadmap item is never presented as released
functionality.** If you cannot cite a path, a command output or a decision ID, say `ASSUMPTION` or
`OPEN_DECISION`.

## 4. Scope discipline

Interesting does not mean in scope. When asked for something outside the current prototype scope (D-66),
do **not** implement it opportunistically. Record it in `docs/IMPLEMENTATION_QUESTIONS.md` as `FUTURE`.

Out of scope by decision, not by oversight: software inventory · hardware inventory · listeners ·
BSD support · firewall / AV / EDR / IDS / WAF / SIEM / cloud assessment · CVE matching · remote patch
availability · whole-filesystem FIM · remote attestation · fleet server · REST API · database connector ·
automatic remediation · framework mapping expansion.

## 5. Blocked-work protocol

On an architecture conflict, ambiguity, impossible frozen assumption, capability problem or unsupported
platform behaviour:

1. Do **not** silently change the architecture.
2. Record it in `docs/IMPLEMENTATION_QUESTIONS.md` — requirement IDs, affected code, the safest behaviour
   you implemented, your proposed clarification.
3. Mark the requirement `BLOCKED` in `docs/development/requirements-trace.md` *(PLANNED — not yet created)*.
4. Continue unrelated in-scope work.
5. List it in the milestone report.

**Never weaken a requirement, a test or a gate to clear a blockage.** A requirement must not disappear
merely because no source file currently implements it.

Specifically (OD-06): if corpus testing shows the frozen capability / `setpriv` / SELinux model cannot work
as written, stop that lane and record the evidence. Never add `CAP_SYS_ADMIN`, widen capabilities, add
setuid, add a privileged daemon, disable SELinux, or weaken the sandbox.

## 6. Hard prohibitions

**Publication.** No push, no remote, no tag, no release, no GitHub settings, no wiki, no upload, no
external service. Publication is an explicit owner decision, blocked until OD-01 resolves the public name.

**Clean room.** Never copy code, rules, tests, prose, tables, mappings or remediation from NFTBan,
ComplianceAsCode, OpenSCAP, Lynis, osquery, Wazuh, AIDE, CIS, ISO, PCI DSS or any commercial product.
Reference identifiers and authoritative sources; write ISEDRAF prose independently.

**Runtime.** Nothing beyond Bash, Python ≥ 3.9 standard library, coreutils, util-linux and optional
subsystem tools discovered at runtime. No Go, no compiled components, no plugins, no third-party runtime
modules. No network egress, no embedded database.

**Evidence honesty.** `NOT_TESTED` is never `PASS`. Absence of a locally detectable product is never
absence of the control. Host technical evidence is never organizational compliance.

**Forbidden claims.** `compliant` · `guaranteed` · `tamper-proof` · `non-repudiable` · `host unchanged` ·
`kernel-generated` · `read-only guaranteed` · `100% secure` · `military-grade`.
Use instead: *observed*, *collected*, *not tested*, *no security-relevant change observed*,
*locally consistent*, *package consistent*, *filesystem protection enforced*, *kernel mutation minimized*.

**Coexistence.** Never `X vs Y`, `replaces X`, `better than X`, `X cannot do Y`, rankings, scores or
winners — about any project, including NFTBan. Neutral scope descriptions only. Never describe another
project's capabilities without verifying them against that project's own documentation.

## 7. Transparency

Every commit discloses AI assistance: `Assisted-by: <tool> (<role>)`, or `Assisted-by: none`. The
`commit-msg` hook enforces it. Tooling-added `Co-Authored-By:` trailers are kept, never disabled. Pull
requests declare the AI tools and roles used. `docs/development/DESIGN_PROVENANCE.md` *(PLANNED — not yet created)* maps design phases to
decision IDs, the AI tools involved and the human approval point.

Never omit or minimize AI involvement. Never imply AI output is authoritative without human review.

**Not published:** private prompts, hidden reasoning, chain-of-thought or raw chat transcripts — the last
because they may contain sensitive host data. Summaries only.

## 8. Self-check before responding

- Did I read in the required order, or did I infer from code?
- Is every claim labelled and traceable to a path, command output or decision ID?
- Am I inside the prototype scope?
- Did I weaken any requirement, test or gate?
- Does anything I wrote present a `FUTURE` item in the present tense?
- Did I frame ISEDRAF against another project?
- Does my commit disclose AI assistance?
