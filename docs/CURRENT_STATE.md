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

What comes next, and where every other source of truth is: [`roadmap/ROADMAP.md`](roadmap/ROADMAP.md#sources-of-truth).

| | |
|---|---|
| Project stage | **GENERAL_AVAILABILITY** |
| Public release | **0.6.0, published 2026-11-24** |
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
| 0.1.2 | PUBLISHED 2026-10-08 - correction release (evidence truth, evidence limits) |
| 0.2.0 | PUBLISHED 2026-10-19 - Full Audit (sudo isedraf audit, sudo isedraf report) |
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
| 0.3.0 | PUBLISHED 2026-11-09 - native criteria: isedraf evaluate and sudo isedraf evaluate (eight ISEDRAF-authored criteria, EXPERIMENTAL), isedraf explain |
| v0.4 slice 1 | DONE - in 0.4.0: DEV baseline approval and comparison inside evaluate (D-127) |
| v0.4 slice 2 | DONE - in 0.4.0: production baselines through Full Audit, sudo isedraf baseline approve (D-128) |
| 0.4.0 | PUBLISHED 2026-11-13 - approved baselines: sudo isedraf baseline approve, comparison in isedraf evaluate and sudo isedraf evaluate, Baseline comparison in the report |
| 0.5.0-rc1 | RELEASE CANDIDATE, NOT RELEASED - operator experience: start page and help on both routes, bash completion, run summaries, isedraf list, plain refusals, free-space check (exit 68), ledger recovery (STORE-016) |
| 0.5.0-rc2 | RELEASE CANDIDATE, NOT RELEASED - internal: the rc1 acceptance findings (four messages wrapped at 80 columns) |
| 0.5.0-rc3 | RELEASE CANDIDATE, NOT RELEASED - internal: the rc2 acceptance findings (the audit summary's identity and privilege lines wrapped at 80 columns); the README logo |
| 0.5.0-rc4 | RELEASE CANDIDATE, NOT RELEASED - internal: the terminal text of every command within 80 columns on both routes, with a coverage test |
| 0.6.0-rc1 | RELEASE CANDIDATE, NOT RELEASED - native audit coverage: fourteen native criteria in five families (ISE-PRIV-001, -002, ISE-SSH-003, -004, -005, ISE-STORAGE-001 new), the criteria catalogue CSV, PAM @include on Debian-family hosts, nullok and maximum password age in the report |
| 0.5.0 | PUBLISHED 2026-11-21 - operator experience: help on both routes, bash completion, run summaries, isedraf list and sudo isedraf list, plain refusals, a free-space check (exit 68), ledger recovery (STORE-016), terminal text within 80 columns |
| v0.4 release | 0.4.0 prepared; release-candidate acceptance of 0.4.0-rc1 PASSED 2026-11-12 (upgrade from 0.3.0 on existing stores: Debian 12, Ubuntu 24.04, Rocky 9.7, AlmaLinux 9.7 Full Audit; AlmaLinux 8.10 standard audit); a report regression found in review was fixed and checked on Debian 12 and Rocky 9.7; published 2026-11-13 as 0.4.0 (package upgrade from 0.4.0-rc1 with a Full Audit baseline comparison checked on the lab before publication) |
| v0.5 release | 0.5.0 prepared 2026-11-20 from 0.5.0-rc4 (version only); rc4 acceptance PASSED 2026-11-20: full falsification 601/601, installed packages on Ubuntu 24.04, Debian 12 and AlmaLinux 9.7, 109 cases each on both routes in an 80-column terminal; upgrade from the published 0.4.0 tested with rc1 on Rocky 9.7, Debian 12 and AlmaLinux 8.10; published 2026-11-21 as 0.5.0 (tag v0.5.0 -> public main 0f087bd, tree e36fac0b; release run 44919508226; attestations verified; tag-built packages smoke-tested on Debian 12 and Rocky 9.7; published assets re-downloaded and verified) |
| 0.6.0 | PUBLISHED 2026-11-24 - native audit coverage: fourteen native criteria in five families, the criteria catalogue CSV, PAM @include on Debian-family hosts, nullok and maximum password age in the report; latest |
| v0.6 release | 0.6.0 prepared 2026-11-24 from 0.6.0-rc1 (version only); rc1 acceptance PASSED 2026-11-24: full falsification 620/620, installed packages upgraded from the published 0.5.0 with a Full Audit on Debian 12, Ubuntu 24.04, Rocky Linux 9.7 and AlmaLinux 9.7, 115 cases each on both routes in an 80-column terminal; published 2026-11-24 as 0.6.0 (tag v0.6.0 -> public main 9269f22, tree c06ec9df; release run 45465685156; attestations verified; tag-built packages smoke-tested on Debian 12 and Rocky 9.7; published assets, NATIVE_CRITERIA.csv included, re-downloaded and verified) |
| v0.6 (in development) | Published as 0.6.0 (2026-11-24). On the engineering line: the native criteria catalogue docs/reference/NATIVE_CRITERIA.csv (D-130), with title, lifecycle, introducing release and minimum collection route per criterion; isedraf explain describes a criterion's capability, never a store's state; the name without "codename" (D-108). Checked by make check and the falsification harness, and from installed 0.6.0-dev packages on Debian 12 and Rocky Linux 9.7 (the catalogue, the eight criterion pages, offline links, isedraf explain; the system store unchanged by the upgrade from 0.5.0). The 14-row CSV checked visually in a spreadsheet application by the owner (2026-11-24). PAM: @include lines are read on Debian-family hosts (parser version 2), checked from installed packages on Ubuntu 24.04 (the PAM area now COLLECTED) and Rocky Linux 9.7. The first PRIV criteria (ISE-PRIV-001, ISE-PRIV-002) and the NO_BASELINE wording are admitted (D-131); upgrade from the published 0.5.0 checked on Debian 12 and Rocky Linux 9.7 (every 0.5.0 file unchanged, the baseline comparison UNCHANGED) with the 80-column sweep. Four more criteria admitted (D-132: ISE-SSH-003, -004, -005, ISE-STORAGE-001; 14 in five families), checked from installed packages on Debian 12 and Rocky Linux 9.7. The report shows two recorded settings (D-132): pam_unix nullok on auth lines beside ISE-ACCOUNT-002, without changing its result, and the maximum password age per local account (no limit, days as written, not collected). Release candidate 0.6.0-rc1 (bf0c0a6) checked 2026-11-24: full falsification 620/620; installed DEB and RPM upgraded from the published 0.5.0 on Debian 12, Ubuntu 24.04, Rocky Linux 9.7 and AlmaLinux 9.7 (every 0.5.0 file unchanged, the baseline comparison UNCHANGED, the new reports equal to the hosts' files), 115 of 115 sweep cases on each. Owner GO 2026-11-24; 0.6.0 prepared from it. |
| v0.3 release | 0.3.0 prepared; upgrade and release-candidate acceptance of 0.3.0-rc1 PASSED 2026-11-08 (in-place upgrade from 0.2.0 on existing stores: Debian 12, Ubuntu 24.04, Rocky 9.7, AlmaLinux 9.7 Full Audit; AlmaLinux 8.10 standard audit); published 2026-11-09 as 0.3.0 (smoke of the tag-build packages on Debian 12 and Rocky 9.7 the same day) |
| v0.2 release | 0.2.0 prepared; release acceptance PASSED 2026-10-12 (Debian 12, Ubuntu 24.04, Rocky 9.7, AlmaLinux 9.7 Full Audit; AlmaLinux 8.10 standard audit); published 2026-10-19 as 0.2.0 (final smoke of the tag-build packages on the same five platforms 2026-10-19) |

## Implemented

What exists and runs today. Nothing else on this page does.

| Capability | Evidence | Command |
|---|---|---|
| `w1a_evidence_contract` | `docs/architecture/freeze/W1A_CORE_PUBLIC.sha256` | — |
| `artifact_attestation` | `.github/workflows/release-candidate.yml` | — |
| `audit_command` | `lib/isedraf/audit.py` | `isedraf audit` |
| `authorized_keys` | `lib/isedraf/authorizedkeys/` | `isedraf audit` |
| `baseline_approval` | `tests/test_baseline.py` | `isedraf baseline approve <SDS-id>; sudo isedraf baseline approve` |
| `block_storage_observation_model` | `lib/isedraf/inventory/collectors.py` | — |
| `clean_public_export` | `scripts/ci/release_export.sh` | — |
| `code_scanning` | `.github/workflows/codeql.yml` | — |
| `consolidated_product_model` | `docs/architecture/ISEDRAF_PRODUCT_HLD.md` | `make check-public-claims` |
| `criterion_explanation` | `lib/isedraf/explain.py` | `isedraf explain <criterion_id>` |
| `delta_comparison` | `tests/test_baseline.py` | `isedraf evaluate` |
| `framework_neutral_core` | `docs/licensing/FRAMEWORK_MAPPING_POLICY.md` | — |
| `framework_source_registry` | `scripts/ci/framework_sources.json` | `make check-licensing` |
| `help_and_start_page` | `lib/isedraf/commands.py` | `isedraf help [--all] [COMMAND]` |
| `hostname_state` | `lib/isedraf/hostname/` | `isedraf audit` |
| `identity` | `lib/isedraf/identity.py` | `isedraf identity` |
| `independent_verifier` | `scripts/vectors/verify.py` | — |
| `inventory` | `lib/isedraf/inventory/` | `isedraf inventory` |
| `ledger` | `lib/isedraf/ledger.py` | — |
| `login_policy` | `lib/isedraf/loginpolicy/` | `isedraf audit` |
| `mounts` | `lib/isedraf/mounts/` | `isedraf audit` |
| `native_control_catalog` | `lib/isedraf/catalog/native_controls.json` | — |
| `native_evaluation` | `tests/test_evaluate.py` | `isedraf evaluate` |
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
| `store_listing` | `lib/isedraf/listing.py` | `isedraf list [--all]` |
| `sudo_privilege` | `lib/isedraf/sudo/` | `isedraf audit` |
| `users_groups` | `lib/isedraf/accounts/` | `isedraf audit` |

## Planned

Designed, not built. No part of this runs.

- `audit_subsystem`
- `export`
- `framework_entitlement` — intended boundary recorded (signed pack plus signed local entitlement file, verified offline); no cryptography and no licensing server is implemented or designed, because a protocol written before its legal constraints are known is one that will be rewritten (design: `docs/licensing/FRAMEWORK_PACK_ARCHITECTURE.md`)
- `framework_mapping_packs` — design only - no pack loader, no manifest reader, no entitlement mechanism and no signing exists; no third-party mapping is licensed, reviewed or bundled (design: `docs/licensing/FRAMEWORK_PACK_ARCHITECTURE.md`)
- `journald_recording`
- `mode_b_open_mapping` — optional mapping to an external authority whose exact reuse rights were validated first. NIST is the candidate and its rights are NOT yet verified - 'government' and 'open source' are where everyone assumes and nobody checks (design: `docs/architecture/ISEDRAF_PRODUCT_HLD.md`)
- `mode_c_licensed_byol` — provider-authorized pack plus the customer's own provider entitlement, only after a written agreement. Zero providers approached, zero agreements, and the architecture being ready is not a provider having agreed (design: `docs/architecture/ISEDRAF_PRODUCT_HLD.md`)
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
| Gates | 36 |
| Falsification injections | 622 |
| Golden vector cases | 15 |
| Frozen artifacts | 7 |
| Test files | 69 |

## Release blockers

None recorded.
