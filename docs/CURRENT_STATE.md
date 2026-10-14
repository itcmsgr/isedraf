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
| Project stage | **GENERAL_AVAILABILITY** |
| Public release | **0.1.2, published 2026-10-08; 0.2.0 awaiting owner authorization** |
| Production Python floor | 3.6 |
| Tooling Python floor | 3.9 |
| Execution model | unprivileged by default (`isedraf audit`, user evidence store); Full Audit (`sudo isedraf audit`) from 0.2.0 |
| Runtime dependencies | Python standard library only |

## Releases and engineering status

Engineering status is not a release: an item marked NOT RELEASED is in no published package.

| Item | Status |
|---|---|
| 0.1.0 | PUBLISHED 2026-09-28 - general availability, unprivileged |
| 0.1.1 | PUBLISHED 2026-10-06 - correction release (authorized_keys evidence) |
| 0.1.2 | PUBLISHED 2026-10-08 - correction release (evidence truth, evidence limits); latest |
| v0.2 P0 authority model | DONE (D-122, D-123) |
| v0.2 P1 truth fixes | DONE - released in 0.1.1 and 0.1.2 |
| v0.2 P2 registry truth | DONE - released in 0.1.2 |
| v0.2 P3 evidence contract | DONE - released in 0.1.2 |
| v0.2 P4/P5 supervisor and Full Audit route | DONE - in 0.2.0 |
| read_shadow_v1 | IMPLEMENTED and corpus-validated in engineering - in 0.2.0 |
| v0.2 P6 corpus proof | PASSED 2026-10-08 (Debian 12, Ubuntu 24.04, Rocky 9, AlmaLinux 9) |
| OD-06 capability model under SELinux | CLOSED 2026-10-08 |
| AUTH-025 admission of privileged operations | AMENDED 2026-10-09 - one new operation at a time; validated: read_shadow_v1, read_sudoers_graph_v1, read_sshd_declared_config_v1, resolve_sshd_effective_config_v1 - the order is complete; admission grants no capability |
| read_sudoers_graph_v1 | IMPLEMENTED and corpus-validated in engineering (AUTH-029; lab proof 2026-10-09) - in 0.2.0 |
| read_sshd_declared_config_v1 | IMPLEMENTED and corpus-validated in engineering (AUTH-030; lab proof 2026-10-09) - in 0.2.0 |
| resolve_sshd_effective_config_v1 | IMPLEMENTED and corpus-validated in engineering (AUTH-031; lab proof 2026-10-09) - the global effective configuration only, Match not resolved - in 0.2.0 |
| Full Audit mounts and storage | engine reads PID 1's mount table with no added privilege (IQ-055); space only where the device matches; four-platform lab proof PASSED 2026-10-09 |
| Full Audit time on SELinux-enforcing EL9 | chronyc not executed; recorded as MAC_DOMAIN_TRANSITION_UNAVAILABLE |
| Deferred past v0.2 (owner decision 2026-10-10) | inspect_mount_namespaces_v1 (PLANNED) and read_authorized_keys_v1 (DESIGN_OPEN) - post-v0.2 candidates, not v0.2 scope; Full Audit does not collect other users' authorized_keys |
| v0.2 release | 0.2.0 prepared; release acceptance PASSED 2026-10-12 (Debian 12, Ubuntu 24.04, Rocky 9.7, AlmaLinux 9.7 Full Audit; AlmaLinux 8.10 standard audit); publication awaits owner authorization |

## Implemented

What exists and runs today. Nothing else on this page does.

| Capability | Evidence | Command |
|---|---|---|
| `w1a_evidence_contract` | `docs/architecture/freeze/W1A_CORE_PUBLIC.sha256` | — |
| `artifact_attestation` | `.github/workflows/release-candidate.yml` | — |
| `audit_command` | `lib/isedraf/audit.py` | `isedraf audit` |
| `authorized_keys` | `lib/isedraf/authorizedkeys/` | `isedraf audit` |
| `block_storage_observation_model` | `lib/isedraf/inventory/collectors.py` | — |
| `clean_public_export` | `scripts/ci/release_export.sh` | — |
| `code_scanning` | `.github/workflows/codeql.yml` | — |
| `consolidated_product_model` | `docs/architecture/ISEDRAF_PRODUCT_HLD.md` | `make check-public-claims` |
| `framework_neutral_core` | `docs/licensing/FRAMEWORK_MAPPING_POLICY.md` | — |
| `framework_source_registry` | `scripts/ci/framework_sources.json` | `make check-licensing` |
| `hostname_state` | `lib/isedraf/hostname/` | `isedraf audit` |
| `identity` | `lib/isedraf/identity.py` | `isedraf identity` |
| `independent_verifier` | `scripts/vectors/verify.py` | — |
| `inventory` | `lib/isedraf/inventory/` | `isedraf inventory` |
| `ledger` | `lib/isedraf/ledger.py` | — |
| `login_policy` | `lib/isedraf/loginpolicy/` | `isedraf audit` |
| `mounts` | `lib/isedraf/mounts/` | `isedraf audit` |
| `nss_configuration` | `lib/isedraf/nss/` | `isedraf audit` |
| `package_deb` | `packaging/deb/control.in` | — |
| `package_lifecycle_verified` | `scripts/compat/package_lifecycle.sh` | — |
| `package_rpm` | `packaging/rpm/isedraf.spec.in` | — |
| `pam` | `lib/isedraf/pam/` | `isedraf audit` |
| `production_mode_a` | `lib/isedraf/launcher` | `sudo isedraf audit` |
| `provider_alignment_check` | `scripts/ci/check_provider_alignment.py` | `make check-provider-alignment` |
| `public_licensing_boundary` | `scripts/ci/public_licensing_policy.json` | `make check-licensing` |
| `report_html` | `lib/isedraf/report/render.py` | `isedraf report --html` |
| `report_json` | `lib/isedraf/report/render.py` | `isedraf report --json` |
| `report_markdown` | `lib/isedraf/report/render.py` | `isedraf report` |
| `reproducible_build` | `scripts/ci/check_reproducible.sh` | `make check-reproducible` |
| `sbom` | `scripts/ci/generate_sbom.py` | — |
| `scorecard` | `.github/workflows/scorecard.yml` | — |
| `snapshot` | `lib/isedraf/snapshot.py` | — |
| `ssh_state` | `lib/isedraf/ssh/` | `isedraf audit` |
| `sudo_privilege` | `lib/isedraf/sudo/` | `isedraf audit` |
| `users_groups` | `lib/isedraf/accounts/` | `isedraf audit` |

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
- `native_control_catalog` — D-111 freezes the invariant and the ISE-* namespace: 14 families, ISE-IDENT reserved and not in use. NO native criterion is authored yet - they arrive in W1-D. make check-native-catalog enforces that the registry and the catalog document agree, that criteria hold to the namespace, that no criterion is derived from a framework, and that no production module is named after a provider (design: `docs/architecture/NATIVE_CONTROL_CATALOG.md`)
- `report_pdf`
- `services`
- `signing`

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
| Certified | **none** — no external or independent certification exists or is claimed. Reboot and version-upgrade stability are exercised in the release rehearsals and the v0.2 corpus proof; that is testing, not certification |

## Counted from the repository

Not asserted. Each number is counted at generation time.

| | |
|---|---|
| Gates | 33 |
| Falsification injections | 518 |
| Golden vector cases | 15 |
| Frozen artifacts | 7 |
| Test files | 49 |

## Release blockers

None recorded.
