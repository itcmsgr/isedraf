<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Contributing to ISEDRAF

Status: IMPLEMENTED
Implements: D-63, D-69, D-90, D-91, D-93, §13

ISEDRAF is a trust tool. Its value is that what it reports is true and that its limits are stated. Most
of the rules below exist to protect that property, not to protect a coding style.

**The project is pre-release and not accepting external contributions yet.** This document is the contract
that will apply when it does.

## Before you write code

Read, in order: `CLAUDE.md` (or `docs/development/LLM_PROTOCOL.md` if you are using any AI assistant) →
`docs/architecture/INTERNAL_RECORDS.md` → the relevant frozen architecture documents →
`docs/CURRENT_STATE.md` → `docs/REPOSITORY_MAP.md` → `docs/development/requirements-trace.md` *(PLANNED — not yet created)*.

Architecture is not inferred from the code. The code may be incomplete; the frozen requirements govern.

## The invariants

**Host evidence boundary.** ISEDRAF assesses state directly observable on the local operating system.
Firewalls, AV, EDR, IDS/IPS, WAF, SIEM, cloud and network controls, CVE matching and whole-filesystem
integrity monitoring are permanently out of scope. The absence of a locally detectable agent is never the
absence of the control.

**Read-only audit.** ISEDRAF never modifies host state. Collectors collect; the engine interprets.
Nothing in the runtime may change PAM, SSH, audit, sysctl, users, services, MAC or mounts.

**Clean room.** Never copy code, rules, tests, prose, tables, mappings or remediation from NFTBan,
ComplianceAsCode, OpenSCAP, Lynis, osquery, Wazuh, AIDE, CIS, ISO, PCI DSS or any commercial product.
Reference identifiers and authoritative sources; write ISEDRAF prose independently.

**Runtime dependencies.** Bash where a shell sequence is genuinely required, plus Python ≥ 3.9 **standard
library only**. No Go, no compiled components, no plugins, no third-party runtime modules. Development and
CI tools live in `requirements-dev.txt` and are never imported by runtime code. No network egress and no
embedded database — both are enforced by an import allowlist, not by convention.

**Traceability.** Every function that implements a requirement cites it: `Implements: SNAP-012`. The
generated `docs/development/requirements-trace.md` *(PLANNED — not yet created)* must stay fresh.

**Negative tests.** Every parser needs normal, malformed, missing-data and permission-failure fixtures.
Every bug gets a regression test *before* the fix.

**Canonical serialization.** Only canonicalized state is hashed and diffed. Observations — last login,
PID, uptime, "days remaining" — are displayed but never cause a change.

**Snapshot immutability.** A completed snapshot is never modified and never contains findings. Findings
live in regenerable evaluations.

**Collection vs evaluation.** Collection status (`COLLECTED`, `PARTIAL`, `NOT_TESTED`, `ERROR`) and
evaluation result (`PASS`, `FAIL`, `PARTIAL`, `MISMATCH`, `NOT_APPLICABLE`, `MANUAL_REVIEW`,
`NOT_EVALUATED`) are separate fields with separate counters. Never conflate them.

**`NOT_TESTED` semantics.** `NOT_TESTED` is not `PASS`. It never becomes `REMOVED` and never becomes an
improvement. Where either side was not collected, the result is `NOT_COMPARABLE` with a reason.

**No scope expansion without an amendment.** Interesting is not in scope. Out-of-scope ideas go to
`docs/IMPLEMENTATION_QUESTIONS.md` as `FUTURE`. Architecture changes happen only through an owner-written
`docs/architecture/INTERNAL_RECORDS.md` entry and a regenerated manifest.

## Local validation

```
make check
```

This is the authoritative pre-commit entry point, and the `pre-commit` hook runs it. CI runs the same
targets. There is no warning tier: a gate either passes or fails.

Install the repository hooks once:

```
cp git-hooks/* .git/hooks/ && chmod 0755 .git/hooks/*
```

Never use `git commit --no-verify`, never change `core.hooksPath`, never edit `.git/hooks/` directly.

## Commits

Sign off every commit (DCO):

```
Signed-off-by: Your Name <you@example.com>
```

Disclose AI assistance on every commit — the `commit-msg` hook enforces it:

```
Assisted-by: Claude (implementation via Claude Code)
Assisted-by: none
```

Keep any `Co-Authored-By:` trailers your tooling adds. Never remove or disable them.

## Pull requests

The template asks for requirement IDs, the domain touched, behaviour changed, collector/parser/schema
changes, negative tests added, corpus fixtures, privilege and capability impact, data sensitivity impact,
documentation updated, and the AI tools and roles used.

It also asks the question that matters most for a delta engine:

> **Does this change alter normalized state for an unchanged host?**
> If yes, describe the comparability and `baseline rebind` handling.

If the answer is yes and unhandled, the change silently invalidates every existing baseline.

## When you get stuck

Do not silently reinterpret a requirement. Record it in `docs/IMPLEMENTATION_QUESTIONS.md` with the
requirement IDs, the affected code, the safest behaviour you implemented and your proposed clarification;
mark the requirement `BLOCKED` in the trace; continue other in-scope work.

**Never weaken a requirement, a test or a gate to make work pass.**

## Documentation

Documentation is part of product correctness and is reviewed like code. `/docs` is canonical; the README is
the front door. Follow `docs/development/DOCUMENTATION_POLICY.md` and `docs/STYLE_GUIDE.md`. Do not
position ISEDRAF against another project, and do not describe a planned feature in the present tense.
