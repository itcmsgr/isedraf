# ISEDRAF (codename)

**Linux Host Assurance, Approved Baseline, State Delta & Evidence Bridge**

> Measure once. Map everywhere. Fix only the delta.

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.0.0--pre-lightgrey)](VERSION)
[![Status](https://img.shields.io/badge/status-prototype-orange)](docs/CURRENT_STATE.md)
[![Platforms](https://img.shields.io/badge/platforms-Debian%2012%20%C2%B7%20Ubuntu%2024.04%20%C2%B7%20Rocky%2FAlma%209-informational)](docs/reference/SUPPORTED_PLATFORMS.md)

**CI / Correctness**

[![Governance](https://github.com/itcmsgr/isedraf/actions/workflows/governance.yml/badge.svg)](https://github.com/itcmsgr/isedraf/actions/workflows/governance.yml)

> **Status:** Private pre-release development. ISEDRAF is currently a codename and is not yet a public release.

> **Every mark above is backed by a control that runs, or by a file in this repository.** Decorative trust
> badges are not used. Badges that cannot yet be earned are listed in
> [Security & supply-chain assurance](#security--supply-chain-assurance) as *planned*, not displayed.

ISEDRAF is an open-source Linux host assurance project designed to bridge day-to-day system administration with security audit and governance evidence.

It collects security-relevant state that the local operating system can actually prove, normalizes that state into stable machine-readable evidence, creates explicit approved baselines, and reports meaningful changes between runs.

The same evidence is intended to serve three views:

- the system administrator — what changed and what needs attention;
- the security auditor — what was observed, how it was collected, and what can or cannot be concluded;
- the organization — portable JSON/JSONL evidence that can later be ingested into existing governance, inventory or analytics workflows.

## Core model

```text
local host evidence
        ↓
normalization
        ↓
immutable snapshot
        ↓
approved baseline
        ↓
comparable state
        ↓
classified delta
        ↓
explanation
        ↓
portable evidence
```

A baseline means accepted state, not automatically secure state.

No observed security-relevant delta does not prove that a host is uncompromised.

## Prototype scope

The initial prototype is deliberately narrow:

- host identity;
- local users and groups;
- local sudo privilege;
- `authorized_keys` fingerprints;
- password/account ageing;
- SSH resolved state;
- mounts — declared, resolved and active;
- audit subsystem state;
- journald recording coverage;
- time synchronization quality required for trustworthy recording evidence.

The objective is not maximum control count.

The first objective is trustworthy state and trustworthy delta.

## Explicitly outside the host evidence boundary

ISEDRAF core does not assess:

- firewall effectiveness;
- AV/EDR/XDR;
- IDS/IPS;
- SIEM effectiveness;
- cloud controls;
- external network controls;
- WAF;
- external backup systems;
- remote patch availability;
- vulnerability-feed/CVE correlation.

Absence of a locally detectable external product is not interpreted as absence of that security control.

## Design principles

ISEDRAF is designed around:

- read-only host assessment;
- no privileged daemon;
- no internal sudo;
- no embedded database;
- no API server;
- no network egress from the core collector;
- canonical JSON/JSONL artifacts;
- immutable snapshots;
- explicit baseline approval;
- granular accepted changes;
- collection truth separate from evaluation;
- `NOT_TESTED` and `NOT_COMPARABLE` instead of invented PASS/FAIL;
- declared / resolved / active state where applicable;
- operator and auditor views derived from the same evidence.

## Scope

ISEDRAF's scope is its own host-state, evidence, baseline and delta model. It does not implement
SCAP content, file-integrity monitoring, vulnerability scanning, telemetry query or log shipping,
and it makes no assessment of tools that do.

The previous wording here named eight other projects in order to say ISEDRAF was not competing with
them. Naming them was itself the comparison: it placed ISEDRAF on the same axis and invited the
reader to make it. `C-06` forbids that, and `make check-docs-truth` now enforces it.

## Security & supply-chain assurance

What is true today, and verifiable from this repository:

| Control | Where it is proven |
|---|---|
| Governance, header identity, shell syntax and documentation gates run on every push and pull request | `.github/workflows/governance.yml`, `make check` |
| Every gate is proven able to fail, by deliberate defect injection | `make check-falsifiable` |
| Every third-party GitHub Action is pinned to a full commit SHA, enforced rather than asserted | `.github/workflows/`, `make check-docs-truth` |
| Workflow tokens default to read-only; Actions cannot approve pull requests | repository Actions settings |
| The runtime imports only the Python standard library | `lib/isedraf/` source; a mechanical import-allowlist gate is PLANNED |
| No networking module is imported and no egress path exists in the collector | source inspection; a mechanical allowlist gate and any kernel-level restriction are PLANNED |
| Canonical artifacts are hashed with a named algorithm, and an independent verifier re-derives every hash from the stored preimages | `scripts/vectors/verify.py`, `test-vectors/w1a/v1/` |
| Security-sensitive failures are tested with deliberate negative cases | corpus acceptance tests |
| No real operator identifier reaches the publication surface | `make check-privacy` |
| Documentation references, action pins, competitive framing and quoted digests are checked mechanically | `make check-docs-truth` |
| A machine-readable SBOM describes each artifact, generated from the **final package** and checked against it — for the RPM, against `rpm`'s own recorded per-file digests | `scripts/ci/generate_sbom.py`, `make check-sbom` |
| Controls that are intended but **not** in force are written down, not glossed over | [`docs/development/GOVERNANCE_GAPS.md`](docs/development/GOVERNANCE_GAPS.md) |

### Planned, not yet displayed

These are deliberately absent until they are earned. Several are also unavailable on the current GitHub
plan for a private repository — verified, not assumed: CodeQL, artifact attestations and secret scanning
all return "not available" today.

`SLSA Build L3` — only once release artifacts genuinely meet the build-platform and provenance
requirements; the SLSA generator's own documentation states that using its workflows alone does not
satisfy every L3 obligation · `OpenSSF Scorecard` (needs a public repository) ·
`OpenSSF Best Practices` (earned by satisfying the criteria, not by inserting the image) · `CodeQL` ·
`OSV-Scanner` · `Gitleaks` · `REUSE compliance` · `provenance / attestation` ·
`SHA-256 release checksums` · `signed release artifacts` ·
**`Baseline & delta invariants`** — the ISEDRAF-specific one: ten unchanged runs produce zero changes,
`NOT_TESTED` never becomes `REMOVED`, an engine upgrade produces zero false security changes, snapshots
stay immutable, and a new privileged user is detected.

### Written, and never run

A third state, between *in force* and *planned*, which this project needs a word for because
collapsing it into either one would be a claim the evidence has not earned:

| Control | State |
|---|---|
| CodeQL (`python` and `actions`, security-extended) | committed, **never executed** — needs a public repository |
| OpenSSF Scorecard | committed, **never executed** — needs a public repository |
| Artifact build provenance and SBOM attestation | committed, **never executed** — needs a public repository on this plan |
| The control that proves an attestation refuses a forgery | committed, **never executed** — it runs only after an attestation exists |

Each of those jobs is conditional on the repository being public. A skipped job reports green, so
every one of them is paired with a `guard` job that **fails** if the analysis was due and did not run.
Nothing is displayed for any of them. See [`KGG-011`](docs/development/GOVERNANCE_GAPS.md).

### The rule

Every green mark is clickable and leads to the evidence behind it — a workflow run, a release provenance
record with verification instructions, a live scorecard, or the criteria page. A badge that cannot link to
evidence is not added.

Never used: *secure* · *audited* · *compliant* · *enterprise ready* · *100% tests* · *tamper proof*.
Those are marketing claims, not evidence.

## What exists today

ISEDRAF is an **early-stage prototype**. What follows is measured, not projected:

| | |
|---|---|
| `isedraf identity` | `/etc/machine-id` → normalized → `host_id` → immutable snapshot → hash-chained ledger → independent verification |
| `isedraf inventory` | platform, machine, CPU, memory, storage, network with classified IPv6, DNS, time — every field classified as fact or observation |
| `isedraf report` | one report model, rendered as JSON and Markdown, with an optional assessment profile |

Measured across **ten Linux distributions** — Debian 11/12/13, Ubuntu 22.04/24.04/26.04, AlmaLinux 8/9,
Rocky 9, CentOS Stream 9, openSUSE Leap 15.6 — producing **identical canonical bytes on CPython 3.6.8
through 3.14.4**, with **no distribution-specific code**. All of it on `x86_64`; ARM64 is a first-class
target that **has not been tested yet**, and [the compatibility record](docs/reference/PLATFORM_COMPATIBILITY.md)
says so rather than implying otherwise.

Nothing is released. See [the roadmap](docs/roadmap/ROADMAP.md).

## Where ISEDRAF stores data

```text
/etc/isedraf/        administrator configuration            (PLANNED)
/var/lib/isedraf/    persistent canonical state and evidence
journal              operational records, via journald      (PLANNED)
/run/isedraf/        ephemeral runtime state                (PLANNED)
```

**Logs explain the run. Evidence describes the host.** Back up `/var/lib/isedraf/`; log retention is a
separate concern and is not a substitute for evidence.

Snapshots, the hash-chained ledger, reports, exports, permissions, identifiers and the development state
root are all covered in **[Storage and Outputs](docs/operator/STORAGE_AND_OUTPUTS.md)**, which is the
canonical reference and says which paths exist today.

For how an observed fact maps to its Linux source, its normalized field, its evidence artifact and — crucially — what it does **not** prove, see
**[Control & Evidence Map](docs/reference/CONTROL_EVIDENCE_MAP.md)**.

## Documentation

Canonical technical documentation lives under:

```text
docs/
```

Architecture and implementation are traceable through frozen requirement IDs and the project decisions register.

The GitHub Wiki is not authoritative.

## Development status

Implementation status is tracked in:

```text
docs/CURRENT_STATE.md
```

Future capabilities described in architecture or roadmap material must not be interpreted as released functionality.

## Security

Do not publish sensitive host evidence or suspected vulnerabilities in ordinary issues.

See:

```text
SECURITY.md
```

Security contact:

```text
contact@itcms.gr
```

## AI-assisted development

AI systems may assist with design review, implementation, testing and documentation.

They do not own the project or hold architectural authority.

Final project decisions, acceptance, release authority and responsibility remain with Antonios Voulvoulis / ITCMS.

See:

```text
AI_ASSISTED_DEVELOPMENT.md
```

## License

ISEDRAF is licensed under the Mozilla Public License 2.0.

Copyright © 2026 Antonios Voulvoulis / ITCMS.

See `LICENSE`.
