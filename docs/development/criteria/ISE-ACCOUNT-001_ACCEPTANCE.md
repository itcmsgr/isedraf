<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# ISE-ACCOUNT-001 — Acceptance Record

Status: PLANNING

Owner disposition: ACCEPTED, 2026-11-02 (section 6).
Implements: D-111, D-121, D-125

An evidence index for the reference implementation, following
`docs/development/V0_3_NATIVE_CRITERION_EVIDENCE_PROTOCOL.md`. It defines nothing: the criterion is
its record in `lib/isedraf/catalog/native_controls.json`, rendered in
`docs/reference/criteria/ISE-ACCOUNT-001.md`.

| | |
|---|---|
| Criterion | `ISE-ACCOUNT-001`, version 1, `EXPERIMENTAL` (`D-80`) |
| Family / check type | ACCOUNT / local account identity |
| Catalog | `catalog_version` 1 |
| Implementation commit | `7c02defa3c9ba8b94b5e2c0ca44704a7f5880429` (owner-signed), tree `7c1a1b70b40afdb74ab516b279724ff4b4716606`, parent `168ca22` |
| Candidate DEB | `isedraf_0.2.0_all.deb` sha256 `5281a98357107aea1dc29e609567027915ebf7d104209ded9d0a8d027526b20c` |
| Candidate RPM | `isedraf-0.2.0-1.noarch.rpm` sha256 `5ec4bf077e25e56dd19627f32c8908bfd2cffb5af38347cff2993839d1fe4322` |
| Lab evidence | owner lab evidence store, directory `a047-slice-2026-11-01`; its `SHA256SUMS` has sha256 `e041ee7d3a7ce9e655d3021ea218083f82d0284056756222fce39f8c3aa12209` (includes the retained EVL artifacts under `evl/`) |

## Stages

| Stage | Status | Evidence |
|---|---|---|
| 01 SELECT | DONE | role-independent; the facts are already committed by a Standard Audit |
| 02 DEFINE | DONE | owner admission, commit `585ad7b`; evidence pointers corrected in `7c02def` |
| 03 MAP | DONE | section 1 |
| 04 SPECIFY | DONE | `evaluation_semantics` in the record; section 2 |
| 05 IMPLEMENT | DONE | `lib/isedraf/evaluate/criteria.py` (`ise_account_001`), `run.py`, `record.py` |
| 06 FALSIFY | DONE | section 3: 33 tests; 7 injections, 527 executed and detected, 0 unexpected non-firing |
| 07 INTEGRATE | DONE | `isedraf evaluate`, `isedraf explain`, report schema 3 `native_results`, generated page |
| 08 PACKAGE | DONE | both payloads carry `catalog/native_controls.json` and `evaluate/`; `check_package_payload.sh` passes with the catalog required |
| 09 VALIDATE | DONE | section 4, five platforms |
| 10 ACCEPT | DONE | owner disposition ACCEPTED, 2026-11-02 |

## 1. Evidence coverage

| Required fact | Section and pointer | Route | Completeness requirement | Otherwise |
|---|---|---|---|---|
| passwd source status | `sections/accounts.json` `/evidence/sources/etc~1passwd/status` | Standard Audit | `COLLECTED` (per source; the section's combined status is not used) | `NOT_EVALUATED` `SOURCE_<status>` |
| identity domain | `/evidence/remote_identity_inclusion/via_compat_directives_in` | Standard Audit | does not list `etc/passwd` | `NOT_EVALUATED` `SOURCE_NOT_TESTED` (the NIS map) |
| each record's UID and exact name | `/evidence/local_accounts/<i>/uid`, `/name_bytes_hex`, `/passwd_line` | Standard Audit | every record well formed | `COLLECTED` with a malformed record is refused as contradictory |
| section binding | `manifest.json` `/manifest_core/auxiliary_artifacts/sections~1accounts.json` | Standard Audit | digest matches as read | refused, exit `64`, nothing written |

## 2. Decision table

| Condition | Result | Reason code |
|---|---|---|
| sufficient evidence, exactly one UID-0 record, named exactly `root` | `PASS` | `ONLY_ROOT_HAS_UID_0` |
| sufficient evidence, an extra UID-0 record | `FAIL` (security finding, `high`) | `ADDITIONAL_UID_0_ENTRY` |
| sufficient evidence, the UID-0 record is not `root` | `FAIL` | `UID_0_NOT_ROOT` |
| sufficient evidence, no UID-0 record | `FAIL` | `NO_UID_0_ENTRY` |
| sufficient evidence, only duplicate `root` lines at UID 0 | `FAIL` | `DUPLICATE_ROOT_ENTRY` |
| passwd `PARTIAL`, `ERROR` or `NOT_TESTED` | `NOT_EVALUATED` (extra UID-0 records only observed) | `SOURCE_<status>` |
| compat INCLUDE in `etc/passwd` | `NOT_EVALUATED` | `SOURCE_NOT_TESTED` |
| accounts section without evidence | `NOT_EVALUATED` | `SECTION_<status>` |
| undefined value, contradiction, integrity failure | refused, exit `64` | — |

Never produced: `NOT_APPLICABLE`, `MANUAL_REVIEW`. Scope: `/etc/passwd` as committed only. A `PASS`
does not establish the absence of UID-0 identities from LDAP, SSSD, NIS, containers or namespaces.

## 3. Tests and falsification (fixtures, not lab hosts)

`tests/test_evaluate.py`, 33 tests, at `7c02def`. Negative branches are proven here, from real
fixture audits and synthetic section objects:

- **Results:** `test_pass_when_root_is_the_only_uid_0_entry`,
  `test_fail_with_an_additional_uid_0_entry_is_a_high_finding_and_exits_0`,
  `test_fail_when_the_uid_0_entry_is_not_root`, `test_fail_when_no_entry_has_uid_0`,
  `test_a_duplicate_root_entry_fails`,
  `test_partial_passwd_never_passes_and_an_extra_uid_0_is_only_observed`,
  `test_unreadable_passwd_is_not_evaluated`,
  `test_a_compat_include_is_a_real_model_state_and_is_not_evaluated`,
  `test_a_section_that_says_it_has_no_evidence_is_not_evaluated`.
- **Refusal:** `test_undefined_values_are_refused` (nine undefined values),
  `test_a_modified_section_is_refused`,
  `test_a_section_changed_after_verification_is_refused_as_it_is_read`,
  `test_a_modified_manifest_is_refused`, `test_a_damaged_catalog_record_is_refused`.
- **Determinism:** `test_a_second_evaluation_is_identical_and_writes_nothing`,
  `test_regeneration_is_byte_identical`,
  `test_different_content_under_the_same_identity_is_never_overwritten`,
  `test_the_identity_is_derived_from_the_snapshot_key`.
- **Separation and record:** `test_audit_does_not_evaluate`,
  `test_report_shows_an_evaluation_and_never_creates_one`,
  `test_a_tampered_evaluation_is_not_shown_as_a_result`,
  `test_explain_needs_no_audit_and_no_store`, `test_root_is_refused_with_the_existing_code`,
  `test_every_admitted_criterion_has_an_evaluator_reading_its_pointers`,
  `test_the_snapshot_and_ledger_are_untouched`.

Falsification injections, all firing in the owner's apply run of `7c02def` (527 executed and
detected, 2 declared skips, 0 unexpected non-firing): an incomplete passwd source yields `PASS` or
`FAIL`; a compat INCLUDE is ignored; malformed evidence is turned into a result; a section is used
without checking its binding; an artifact carries a wall-clock time; a `PASS` produces a finding; a
generated criterion page is edited by hand. The architecture self-test also refuses a renderer that
imports the evaluation writer.

## 4. Platform acceptance

Standard Audit, unprivileged, the published 0.2.0 first as reference, then the candidate, then the
published 0.2.0 again.

| Platform | Result | EVL | `manifest.json` sha256 (prefix) | Regeneration | Root refusal | Full Audit route |
|---|---|---|---|---|---|---|
| Debian 12 | `PASS` `ONLY_ROOT_HAS_UID_0` | `EVL-20261101T180723Z-6db3a4fd11ad3acb` | `0711d77ccd219364` | byte-identical | 70 / 70 | works; system-store evaluation `PLANNED` |
| Ubuntu 24.04 | `PASS` | `EVL-20261101T180749Z-dba621372bb11f2a` | `462e6e2ede2000b1` | byte-identical | 70 / 70 | as above |
| Rocky Linux 9.7 | `PASS` | `EVL-20261101T180749Z-ce8c9d153418444a` | `3c5880dbc6bddf36` | byte-identical | 70 / 70 | as above |
| AlmaLinux 9.7 | `PASS` | `EVL-20261101T180749Z-132050672e0de2c1` | `a7b4539c0c9cc362` | byte-identical | 70 / 70 | as above |
| AlmaLinux 8.10 | `PASS` | `EVL-20261101T180832Z-a56bf68801bda074` | `4ea5bc60bba5dd4a` | byte-identical | 70 / 70 | not supported (by design) |

On every platform: `explain` works with no store and creates none; an unknown ID exits 64; a
snapshot taken by the published 0.2.0 evaluates (`PASS`); audit creates no evaluation; the report
shows the result in Markdown and JSON; modes are 0700/0600; no bytecode is left behind. Every
collected section is byte-identical to the published 0.2.0's except `inventory`, which holds
time-varying observations.

**Anomaly:** the first AlmaLinux 8.10 run never installed the candidate. rpm 4.14 refuses
`--replacepkgs` of the same package version with changed files. With the corrected procedure
(remove, then install) it passed. The first run is kept under `ga-a8-r1/` and is not counted.

## 5. Limitations and open issues

- System-store (Full Audit) evaluation is `PLANNED` (`EVAL-008`); no Full Audit snapshot was
  evaluated.
- A live host shows only the `PASS` branch; the other branches rest on section 3.
- The candidate packages carry the version 0.2.0, as the published build does; a release needs a
  version bump.
- IQ-073: the DEB and RPM still differ in two non-runtime files.

## 6. Owner disposition

Disposition: ACCEPTED (owner ruling 2026-11-02), on the verified evidence above. No second
five-platform campaign is required. ISE-ACCOUNT-001 is the reference implementation of the
evidence protocol.
Acceptance reference: owner ruling of 2026-11-02 on IQ-074 and IQ-075, section 4.
