<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# ISE-SSH-001 — Acceptance Record

Status: PLANNING

Owner disposition: ACCEPTED, 2026-11-05 (section 5). An evidence index following
`docs/development/V0_3_NATIVE_CRITERION_EVIDENCE_PROTOCOL.md`. The criterion is its record in
`lib/isedraf/catalog/native_controls.json`, rendered in `docs/reference/criteria/ISE-SSH-001.md`; the
tables below quote it for review and are not a second definition.

| | |
|---|---|
| Criterion | `ISE-SSH-001`, version 1, `EXPERIMENTAL` (`D-80`) |
| Check type | effective daemon configuration |
| Default severity | high |
| Evidence route | Full Audit only (sshd -T through resolve_sshd_effective_config_v1) |
| Implementation commit | `7fe1d2e` (owner-signed), tree `a1576359bbec053616e38b3fa66e72ec0496d4eb`, parent `bc8c667` |
| Candidate DEB | `isedraf_0.2.0_all.deb` sha256 `ed5c70b2cfa2e93d8c9d1b800cc2ebb31b9b526c2e84d4853b2c850df61c9ece` |
| Candidate RPM | `isedraf-0.2.0-1.noarch.rpm` sha256 `e807e65c048ae4ad5504c53fcafed91edc2ec7523fec149ebcc292ae0b52a379` |
| Lab evidence | owner lab evidence store, directory `a050-combined-acceptance-2026-11-05`; its `SHA256SUMS` has sha256 `d6ccec1d3e60be8b593bd5a24836a3b79acc86876f26b216e3ab108528a7e101` |

## Stages

| Stage | Status | Evidence |
|---|---|---|
| 01 SELECT | DONE | role-independent; the facts are committed today (owner ruling 2026-11-04) |
| 02 DEFINE | DONE in the admission commit | owner rulings 2026-11-04 |
| 03 MAP | DONE | section 1 |
| 04 SPECIFY | DONE | section 2 |
| 05 IMPLEMENT | DONE | `lib/isedraf/evaluate/criteria.py` |
| 06 FALSIFY | DONE | build VM, tree `a1576359`: falsification 539 executed and detected, 0 unexpected non-firing |
| 07 INTEGRATE | DONE | evaluate, explain, report, generated page |
| 08 PACKAGE | DONE | DEB and RPM built from that tree; payload check passes |
| 09 VALIDATE | DONE | combined acceptance, 2026-11-05, section 6 |
| 10 ACCEPT | DONE | owner disposition ACCEPTED, 2026-11-05 |

## 1. Evidence pointers

- `manifest.json` `/manifest_core/auxiliary_artifacts/sections~1ssh.json`
- `sections/ssh.json` `/evidence/provenance/coverage/<i>/status`
- `sections/ssh.json` `/evidence/provenance/coverage/<i>/operation_id`
- `sections/ssh.json` `/evidence/records/<i>/kind`
- `sections/ssh.json` `/evidence/records/<i>/keyword`
- `sections/ssh.json` `/evidence/records/<i>/value`
- `sections/ssh.json` `/evidence/records/<i>/scope`

## 2. Decision table

| Result | When |
|---|---|
| NOT_EVALUATED | the resolved dimension is not COLLECTED (including TOOL_ABSENT, a refused or failed sshd -T, and every Standard Audit), or the setting is not reported exactly once. The reason names the coverage status. |
| PASS | the evidence is sufficient and the value is no. The result concerns the global configuration. |
| FAIL | the evidence is sufficient and the value is yes. |
| NOT_EVALUATED | the evidence is sufficient but the value is neither yes nor no. |

Never produced: NOT_APPLICABLE, MANUAL_REVIEW.

## 3. Tests

`tests/test_criteria_batch1.py`: test_pass_fail_and_the_scope_note, test_tool_absent_is_not_evaluated_never_not_applicable, test_a_standard_audit_has_no_resolved_entry, test_a_match_override_is_an_observation_and_never_changes_the_result, test_a_setting_not_reported_once_or_an_odd_value_is_not_evaluated, test_undefined_shapes_are_refused.

## 4. Limitations

- sshd -T is run without a connection context, so Match blocks are not applied. A global no does not establish that every connection refuses empty passwords; Match-scoped PermitEmptyPasswords declarations are listed as observations and never change the result.
- Only the sshd at /usr/sbin/sshd is observed; another SSH server (another path, a different implementation) is not.
- Whether any account has an empty password is ISE-ACCOUNT-002, not this criterion.

## 5. Owner disposition

Disposition: ACCEPTED (owner review of the evidence archive, 2026-11-05: technical
implementation and lab evidence). The acceptance concerns the verified tree and the archived evidence;
it does not replace a release decision. No further five-platform run is required.

## 6. Platform acceptance (2026-11-05)

Real hosts were observed, never altered: the negative results rest on section 3.

| Platform | Full Audit (`sudo isedraf evaluate`) | Standard Audit (`isedraf evaluate`) |
|---|---|---|
| Debian 12 | PASS `GLOBAL_PERMITEMPTYPASSWORDS_NO` | NOT_EVALUATED `SOURCE_NOT_TESTED` (sshd -T is Full Audit only) |
| Ubuntu 24.04 | PASS `GLOBAL_PERMITEMPTYPASSWORDS_NO` | NOT_EVALUATED `SOURCE_NOT_TESTED` (sshd -T is Full Audit only) |
| Rocky Linux 9.7 (SELinux enforcing) | PASS `GLOBAL_PERMITEMPTYPASSWORDS_NO` | NOT_EVALUATED `SOURCE_NOT_TESTED` (sshd -T is Full Audit only) |
| AlmaLinux 9.7 (SELinux enforcing) | PASS `GLOBAL_PERMITEMPTYPASSWORDS_NO` | NOT_EVALUATED `SOURCE_NOT_TESTED` (sshd -T is Full Audit only) |
| AlmaLinux 8.10 | refused, 70 (Full Audit not supported, by design) | NOT_EVALUATED `SOURCE_NOT_TESTED` (sshd -T is Full Audit only) |

On every platform: `isedraf explain ISE-SSH-001` renders the record; a second evaluation is an identical no-op;
the report lists the five native results and states that Connection-specific Match values are not resolved; no finding was raised; no bytecode is left behind; the
published 0.2.0 was restored afterwards. The evaluation files of every run are retained in the evidence.

## 7. Evaluation records and evidence pointers

Each evaluation holds the results of all five admitted criteria; the files are retained in the
evidence directory (`<platform>-system_evl.tar`, `<platform>-user_evl.tar`).

| Platform | Store | Evaluation | `manifest.json` sha256 | `results.json` sha256 |
|---|---|---|---|---|
| Debian 12 | system (Full Audit) | `EVL-20261105T044902Z-bd64a2176630d115` | `63f940c9a7c4dc24764cde73e5af9ad6b530412aeac9ac3fd0dc1f9588621cfd` | `6390fbba422bf716225f92c0f0bc93c51074b5d48ea7a3bcccf00eeae367d664` |
| Debian 12 | user (Standard Audit) | `EVL-20261105T044900Z-e61f2f91c27063c8` | `b0610cbab9f6b1dfbfd96f1dd3ded44fa2f69eb06284592f7f643ec4746bc460` | `b9c2a4ba14e736542e070ccad7ff9e89cd20e1bfe5328cf0730c7a366dc6189e` |
| Ubuntu 24.04 | system (Full Audit) | `EVL-20261105T044903Z-c6c2d7dd14686bd1` | `fb895c4a7a7d1857b4d48820a09733e7436163cd8128b7e14d056be7541d3c7a` | `59011f06888cbad0c489546c3efe85016ea74dbfe37badde4999ff44563ee64b` |
| Ubuntu 24.04 | user (Standard Audit) | `EVL-20261105T044901Z-c5a1b537ae17b17a` | `b28c405739db77b3a18aae80b586869f4266fcbdae8983fe243a77d18eb276e0` | `17d36ebcccd817251b20c78d30905f4ccb15e5af1a85086526861038bbd7b5b4` |
| Rocky Linux 9.7 | system (Full Audit) | `EVL-20261105T044903Z-f5b1c3b510c095bd` | `e94f25a42a1629c32940bdc4f25be5a14fc5399412516d0912d67566cb7242d3` | `74ec95f8040287f07b46368b431c62943826b246b736955a01ebd9151fb2f2df` |
| Rocky Linux 9.7 | user (Standard Audit) | `EVL-20261105T044901Z-63399cc2320d9549` | `4207d758d742d49e28c9f8ffc76099391ec546d8afd381e421a8ee697d7a6393` | `dbf72ec35f773d44b1149ffc4476cff0c3648da33c5b47f46f64c0292b4854b4` |
| AlmaLinux 9.7 | system (Full Audit) | `EVL-20261105T044903Z-2ed35c6317866155` | `363ec96f10dcefb6c1a3f6c3e1c11348ef09dd12d2e0a8feb922e049e869968c` | `7941c40e46b63a1dde67831073c1ccec5da4c8a7aadbafadb15ce393747e9a7e` |
| AlmaLinux 9.7 | user (Standard Audit) | `EVL-20261105T044901Z-84fbc4b5b4c3bf65` | `5753fae832e3c68ef4ceaf4580656c31c016228bcc51b26c2b643cae56869792` | `7de82d2ce3ca89c34f61b7d52e9f6594771775b03fd87ad022f7de97d4fd3773` |
| AlmaLinux 8.10 | user (Standard Audit) | `EVL-20261105T044900Z-be290aef2801b127` | `a923ee14fd69d71275e0f70d5a19f230fa6e2de66d770e350795239b498fdf04` | `35aafa6104d138189b921f312a3f20ea5b20b15bdc67c8f3256497385c18964b` |

**Real evidence pointers.** Every pointer of this record (section 1) was resolved in real committed
snapshots before the commit: the latest Full Audit snapshot of each of the four Full Audit platforms
and one Standard Audit snapshot (owner lab evidence store, directory
`a050-real-snapshots-2026-11-04`, `result.txt`). In the Full Audit snapshots every pointer resolved
on every element it names; in the Standard Audit snapshot the shadow password state and the `sshd -T`
coverage entry are absent, which is why the Standard Audit result is `NOT_EVALUATED`.
