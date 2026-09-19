<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# ISEDRAF Documentation

Status: IMPLEMENTED

`/docs` is canonical. The repository `README.md` is the front door. There is no GitHub Wiki (D-87).

**Start here:** [`CURRENT_STATE.md`](CURRENT_STATE.md) — what exists right now ·
[`operator/STORAGE_AND_OUTPUTS.md`](operator/STORAGE_AND_OUTPUTS.md) — where snapshots, evidence,
the ledger, reports and logs are stored ·
[`reference/CONTROL_EVIDENCE_MAP.md`](reference/CONTROL_EVIDENCE_MAP.md) — which Linux fact maps to
which evidence field, and what it does not prove ·
[`REPOSITORY_MAP.md`](REPOSITORY_MAP.md) — where everything lives ·
[`reference/GLOSSARY.md`](reference/GLOSSARY.md) — canonical terms.

| Section | For | Contents |
|---|---|---|
| `architecture/` | everyone | frozen design, decisions register, amendments, requirement IDs |
| `getting-started/` | new users | installation, quickstart, first baseline, package verification |
| `operator/` | administrators | daily use, identity and privilege, recording coverage, baselines and delta, change acceptance, explain, exit codes, troubleshooting |
| `auditor/` | auditors | evidence model, collection status, trust and limitations, data provenance, auditing ISEDRAF itself |
| `integration/` | organizations | export formats, JSON/JSONL schemas, ingestion guidance, schema versioning |
| `security/` | everyone | threat model, privilege model, execution sandbox, integrity verification, data sensitivity, privacy and retention |
| `development/` | contributors | development, testing, corpus, documentation policy, style guide, LLM protocol, wiki governance, release process, requirements trace |
| `reference/` | everyone | CLI, status values, glossary, filesystem layout, supported platforms |
| `roadmap/` | everyone | planned and future direction only |

## Conventions

Every feature statement carries a status: `IMPLEMENTED` · `EXPERIMENTAL` · `PLANNED` · `FUTURE` ·
`OUT_OF_SCOPE`. Present tense is used only for the first two. A document marked `Status: STUB` contains
headings only.

Some files are **generated** and must never be hand-edited: `CURRENT_STATE.md`,
`development/requirements-trace.md` *(PLANNED — not yet created)*, `reference/CLI.md`, `operator/EXIT_CODES.md`. `make check` fails when
they are stale.

Limitations are written next to the feature they qualify, not collected into a page nobody reads.

## Working on ISEDRAF with an AI assistant

Read [`development/LLM_PROTOCOL.md`](development/LLM_PROTOCOL.md) first. It is tool-neutral and mandatory.
