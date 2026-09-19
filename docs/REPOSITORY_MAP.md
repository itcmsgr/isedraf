<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Repository Map

Status: IMPLEMENTED
Implements: D-89, §38

Where things live, and what must never be edited. This exists so a new session reads the correct files
instead of reverse-engineering the project from whatever source file it happens to open.

**Paths marked PLANNED do not exist yet.** See `CURRENT_STATE.md`.

## Authority — read these first

| Path | What it is | Editable by |
|---|---|---|
| `CLAUDE.md` | Claude Code entry point, hard stops | **owner only** |
| `docs/development/LLM_PROTOCOL.md` | tool-neutral AI contract | **owner only** |
| `docs/architecture/` | frozen architecture + requirement IDs | **owner only, via AMENDMENTS.md** |
| `docs/architecture/DECISIONS_REGISTER.md` | D-/OD- decisions; the **only** repository copy | **owner only** |
| `docs/architecture/FROZEN_MANIFEST.sha256` *(PLANNED — not yet created)* | hash lock over the above | regenerated per amendment |
| `docs/architecture/AMENDMENTS.md` | the **only** way frozen material changes | **owner only** |

## Governance — integrity-protected

Covered by `docs/development/GOVERNANCE_MANIFEST.sha256` *(PLANNED — not yet created)* (D-83). Changing any of these without an owner
manifest update fails `make check` and the pre-commit hook.

`CLAUDE.md` · `.claude/settings.json` · `git-hooks/pre-commit` · `git-hooks/pre-push` ·
`git-hooks/commit-msg` · the frozen-manifest verifier · `lib/isedraf/exitcodes.json` *(PLANNED — not yet created)* ·
`lib/isedraf/runtime-imports.allow` *(PLANNED — not yet created)* · the doc-lint configuration.

## Generated — never hand-edit

`make docs-check` fails when any of these is stale.

| Path | Generator |
|---|---|
| `docs/CURRENT_STATE.md` | `scripts/docs/current_state.py` *(PLANNED — not yet created)* |
| `docs/development/requirements-trace.md` *(PLANNED — not yet created)* | `scripts/docs/requirements_trace.py` |
| `docs/reference/CLI.md` *(PLANNED — not yet created)* | `scripts/docs/cli_reference.py` |
| `docs/operator/EXIT_CODES.md` *(PLANNED — not yet created)* | `scripts/docs/exit_codes.py` |
| `isedraf.8` | `scripts/docs/manpage.py` *(PLANNED — not yet created)* |

## Implementation (PLANNED)

| Path | Contents |
|---|---|
| `bin/isedraf` | entry point, `#!/usr/bin/python3 -IB`, path-safety check |
| `lib/isedraf/launcher/` | privilege detection, `systemd-run` re-exec, `setpriv` — **the only place `os.execv*` is allowed** |
| `lib/isedraf/exec/` | safe subprocess: argv list, clean env, fixed PATH, timeouts, output caps |
| `lib/isedraf/probe/` | capability probe |
| `lib/isedraf/collect/` | one module per domain; declares its argv and file sources |
| `lib/isedraf/parse/` | parsers — every one fixture-tested |
| `lib/isedraf/normalize/` | canonical state vs observations; canonical serialization |
| `lib/isedraf/identity/` | host identity, HMAC, applicability |
| `lib/isedraf/store/` | snapshots, evaluations, acceptances, ledger, locking |
| `lib/isedraf/compare/` | comparability and delta |
| `lib/isedraf/interpret/` | classification rules, guidance |
| `lib/isedraf/integrity/` | manifest, verify, trust levels |
| `lib/isedraf/render/` | console, JSON/JSONL, HTML |
| `lib/isedraf/exitcodes.json` *(PLANNED — not yet created)* | **single source** of exit codes (D-72) |
| `lib/isedraf/runtime-imports.allow` *(PLANNED — not yet created)* | stdlib import allowlist (D-84) |
| `collectors/` | Bash sequences, only where unavoidable |
| `schemas/` | JSON Schemas, 0.x during prototype |
| `rules/` | interpretation rules as JSON **data** — never sourced or executed |
| `tests/{unit,fixtures,golden,negative}/` | fixtures and golden files are **byte-sensitive** |
| `corpus/` | scenario definitions |
| `packaging/{common,debian,rpm}/` | single install manifest drives both |
| `scripts/ci/` | gate scripts, all reachable from `make check` |
| `scripts/docs/` | documentation generators |
| `provenance/REGISTRY.json` | provenance registry |

## Documentation

`/docs` is canonical. `README.md` is the front door. There is **no GitHub Wiki** (D-87) —
see `docs/development/WIKI_GOVERNANCE.md`.

`architecture/` frozen design · `getting-started/` install and first baseline · `operator/` daily use ·
`auditor/` evidence, provenance, limitations · `integration/` export formats and schemas ·
`security/` threat model, privilege, sandbox, integrity, privacy · `development/` contributing, testing,
corpus, policies, generated trace · `reference/` CLI, status values, glossary, layout, platforms ·
`roadmap/` future direction only.

## Planning — local only, never published

`planning/prompts/` prompt pack · `planning/blueprint/00_nftban/` NFTBan reference notes and engineering
inventory (**gitignored**) · `planning/blueprint/10_architecture/` frozen-document drafts ·
`planning/blueprint/20_review/` adversarial review · `planning/bootstrap/` repository material staged
before Prompt 04.

## Never touch

`<nftban-checkout>` — read-only reference, a separate project. Never modified, never copied from.

## Reading order for a new session

`CLAUDE.md` → `docs/development/LLM_PROTOCOL.md` → `DECISIONS_REGISTER.md` → `FROZEN_MANIFEST.sha256` →
relevant frozen documents → `CURRENT_STATE.md` → this file → `requirements-trace.md` → `VERSION` →
`CHANGELOG.md` → the module → its tests → `IMPLEMENTATION_QUESTIONS.md`.

**Never infer architecture from code.**
