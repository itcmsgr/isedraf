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
| Public release | **AWAITING_OWNER_AUTHORIZATION** |
| Production Python floor | 3.6 |
| Tooling Python floor | 3.9 |
| Execution model | unprivileged, ISEDRAF_STATE_ROOT required |
| Runtime dependencies | Python standard library only |

## Implemented

What exists and runs today. Nothing else on this page does.

| Capability | Evidence | Command |
|---|---|---|
| `w1a_evidence_contract` | `docs/architecture/freeze/W1A_CORE_PUBLIC.sha256` | — |
| `artifact_attestation` | `.github/workflows/release-candidate.yml` | — |
| `clean_public_export` | `scripts/ci/release_export.sh` | — |
| `code_scanning` | `.github/workflows/codeql.yml` | — |
| `consolidated_product_model` | `docs/architecture/ISEDRAF_PRODUCT_HLD.md` | `make check-public-claims` |
| `framework_neutral_core` | `docs/licensing/FRAMEWORK_MAPPING_POLICY.md` | — |
| `framework_source_registry` | `scripts/ci/framework_sources.json` | `make check-licensing` |
| `identity` | `lib/isedraf/identity.py` | `isedraf identity` |
| `independent_verifier` | `scripts/vectors/verify.py` | — |
| `inventory` | `lib/isedraf/inventory/` | `isedraf inventory` |
| `ledger` | `lib/isedraf/ledger.py` | — |
| `package_deb` | `packaging/deb/control.in` | — |
| `package_lifecycle_verified` | `scripts/compat/package_lifecycle.sh` | — |
| `package_rpm` | `packaging/rpm/isedraf.spec.in` | — |
| `provider_alignment_check` | `scripts/ci/check_provider_alignment.py` | `make check-provider-alignment` |
| `public_licensing_boundary` | `scripts/ci/public_licensing_policy.json` | `make check-licensing` |
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
- `framework_entitlement` — intended boundary recorded (signed pack plus signed local entitlement file, verified offline); no cryptography and no licensing server is implemented or designed, because a protocol written before its legal constraints are known is one that will be rewritten (design: `docs/licensing/FRAMEWORK_PACK_ARCHITECTURE.md`)
- `framework_mapping_packs` — design only - no pack loader, no manifest reader, no entitlement mechanism and no signing exists; no third-party mapping is licensed, reviewed or bundled (design: `docs/licensing/FRAMEWORK_PACK_ARCHITECTURE.md`)
- `journald_recording`
- `mode_b_open_mapping` — optional mapping to an external authority whose exact reuse rights were validated first. NIST is the candidate and its rights are NOT yet verified - 'government' and 'open source' are where everyone assumes and nobody checks (design: `docs/architecture/ISEDRAF_PRODUCT_HLD.md`)
- `mode_c_licensed_byol` — provider-authorized pack plus the customer's own provider entitlement, only after a written agreement. Zero providers approached, zero agreements, and the architecture being ready is not a provider having agreed (design: `docs/architecture/ISEDRAF_PRODUCT_HLD.md`)
- `mounts`
- `native_control_catalog` — D-111 freezes the invariant and the ISE-* namespace: 14 families, ISE-IDENT reserved and not in use. NO native criterion is authored yet - they arrive in W1-D. make check-native-catalog enforces that the registry and the catalog document agree, that criteria hold to the namespace, that no criterion is derived from a framework, and that no production module is named after a provider (design: `docs/architecture/NATIVE_CONTROL_CATALOG.md`)
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
- `framework_specific_reports` — not available: framework-specific output does not exist, and core reports are complete without it

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
| Gates | 18 |
| Falsification injections | 100 |
| Golden vector cases | 15 |
| Frozen artifacts | 7 |
| Test files | 3 |

## Release blockers

The public repository is **not** authorized while any of these is open.

- an external integration boundary is under review; the Technical Preview is not released until the required repository-isolation condition is verified
- no GitHub Release or tag is published; publication is a separate owner-authorized act (D-110)
