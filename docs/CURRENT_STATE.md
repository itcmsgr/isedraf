<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: scripts/ci/project_status.json
     Regenerate: python3 scripts/docs/current_state.py generate
     `make check` fails when this file and the registry disagree. -->

# Current State

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page exists so that no reader — human or model — mistakes the roadmap or the architecture
for shipped functionality. It is generated from one registry, because the hand-maintained
version drifted until it announced that no product code existed while three commands worked.

| | |
|---|---|
| Project stage | **TECHNICAL_PREVIEW_CANDIDATE** |
| Public release | **NOT_AUTHORIZED** |
| Production Python floor | 3.6 |
| Tooling Python floor | 3.9 |
| Execution model | unprivileged, ISEDRAF_STATE_ROOT required |
| Runtime dependencies | Python standard library only |

## Implemented

What exists and runs today. Nothing else on this page does.

| Capability | Evidence | Command |
|---|---|---|
| `w1a_evidence_contract` | `docs/architecture/freeze/W1A_CORE.sha256` | — |
| `artifact_attestation` | `.github/workflows/release-candidate.yml` | — |
| `clean_public_export` | `scripts/ci/release_export.sh` | — |
| `code_scanning` | `.github/workflows/codeql.yml` | — |
| `identity` | `lib/isedraf/identity.py` | `isedraf identity` |
| `independent_verifier` | `scripts/vectors/verify.py` | — |
| `inventory` | `lib/isedraf/inventory/` | `isedraf inventory` |
| `ledger` | `lib/isedraf/ledger.py` | — |
| `package_deb` | `packaging/deb/control.in` | — |
| `package_lifecycle_verified` | `scripts/compat/package_lifecycle.sh` | — |
| `package_rpm` | `packaging/rpm/isedraf.spec.in` | — |
| `report_json` | `lib/isedraf/report/render.py` | `isedraf report --json` |
| `report_markdown` | `lib/isedraf/report/render.py` | `isedraf report` |
| `reproducible_build` | `scripts/ci/check_reproducible.sh` | `make check-reproducible` |
| `sbom` | `scripts/ci/generate_sbom.py` | — |
| `scorecard` | `.github/workflows/scorecard.yml` | — |
| `snapshot` | `lib/isedraf/snapshot.py` | — |

## Planned

Designed, not built. No part of this runs.

- `audit_subsystem`
- `baseline_approval`
- `delta_comparison`
- `export`
- `journald_recording`
- `mounts`
- `pam`
- `report_pdf`
- `services`
- `signing`
- `ssh_state`
- `sudo_privilege`
- `users_groups`

## Deferred

Deliberately postponed to a later freeze set.

- `production_mode_a` — the privileged topology that owns /var/lib/isedraf is Freeze Set 2

## Not tested

No evidence exists in either direction.

- `arm64` — zero campaigns have run; planned second architecture

## Future

Beyond the current roadmap horizon.

- `software_inventory`

## Platforms

| | |
|---|---|
| Architectures measured | x86_64 |
| Architectures **not tested** | aarch64, armhf |
| Distributions measured | 11: Debian 11, Debian 12, Debian 13, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 26.04, AlmaLinux 8.10, AlmaLinux 9.7, Rocky 9.7, CentOS Stream 9, openSUSE Leap 15.6 |
| Certified | **none** — reboot stability and version-upgrade stability were not exercised |

## Counted from the repository

Not asserted. Each number is counted at generation time.

| | |
|---|---|
| Gates | 15 |
| Falsification injections | 61 |
| Golden vector cases | 15 |
| Frozen artifacts | 8 |
| Test files | 3 |

## Release blockers

The public repository is **not** authorized while any of these is open.

- no GitHub Release or tag is published; publication is a separate owner decision
