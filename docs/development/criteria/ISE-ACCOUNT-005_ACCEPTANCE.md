<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# ISE-ACCOUNT-005 — Acceptance Record

Status: PLANNING

Owner disposition: ACCEPTED, 2026-11-08 (section 5). An evidence index following
`docs/development/V0_3_NATIVE_CRITERION_EVIDENCE_PROTOCOL.md`. The criterion is its record in
`lib/isedraf/catalog/native_controls.json`, rendered in `docs/reference/criteria/ISE-ACCOUNT-005.md`; the
tables below quote it for review and are not a second definition.

| | |
|---|---|
| Criterion | `ISE-ACCOUNT-005`, version 1, `EXPERIMENTAL` (`D-80`) |
| Check type | local account identity |
| Default severity | low |
| Evidence route | Standard Audit (etc/group) |
| Implementation commit | `cee1195` (owner-signed), tree `e511cb8d9f25b115ffe8281cdb06019cb0b3599d`, parent `50e4e93` |
| Candidate DEB | `isedraf_0.2.0_all.deb` sha256 `957c72e1e4ee1c7374dca5aea3f7d8e172549707bef81c40b39aaf013a69a5ea` |
| Candidate RPM | `isedraf-0.2.0-1.noarch.rpm` sha256 `0ad97a1cb42dfe573076c6fe23081458051f76f67d1fa3f4d7a9baffb21e6657` |
| Lab evidence | owner lab evidence store, directory `a051-combined-acceptance-2026-11-05`; its `SHA256SUMS` has sha256 `27cfd5a224d306cec797440a0b00e4b9101038d57a6a6e4fafcc96d48d92c5ff` |

## Stages

| Stage | Status | Evidence |
|---|---|---|
| 01 SELECT | DONE | role-independent; the facts are committed by every audit (owner ruling 2026-11-05) |
| 02 DEFINE | DONE in the admission commit | owner ruling 2026-11-05 |
| 03 MAP | DONE | section 1 |
| 04 SPECIFY | DONE | section 2 |
| 05 IMPLEMENT | DONE | `lib/isedraf/evaluate/criteria.py` |
| 06 FALSIFY | DONE | build VM, tree `e511cb8d`: falsification 547 executed and detected, 2 declared skips, 0 unexpected non-firing; the batch's 8 injections all fire |
| 07 INTEGRATE | DONE | evaluate, explain, report, generated page |
| 08 PACKAGE | DONE | DEB and RPM built from that tree; payload check passes |
| 09 VALIDATE | DONE | combined acceptance, 2026-11-05, section 6 |
| 10 ACCEPT | DONE | owner disposition ACCEPTED, 2026-11-08 |

## 1. Evidence pointers

- `manifest.json` `/manifest_core/auxiliary_artifacts/sections~1accounts.json`
- `sections/accounts.json` `/evidence/sources/etc~1group/status`
- `sections/accounts.json` `/evidence/remote_identity_inclusion/via_compat_directives_in`
- `sections/accounts.json` `/evidence/local_groups/<i>/gid`
- `sections/accounts.json` `/evidence/local_groups/<i>/name_bytes_hex`
- `sections/accounts.json` `/evidence/local_groups/<i>/group_line`

## 2. Decision table

| Result | When |
|---|---|
| NOT_EVALUATED | the evidence is not sufficient (above). A duplicate seen in insufficient evidence is reported as an observation, never as FAIL. |
| FAIL | the evidence is sufficient and two or more records with different exact name bytes have the same GID. |
| MANUAL_REVIEW | the evidence is sufficient, no two different names share a GID, but one name appears on more than one line with different GIDs, both lines kept in the evidence: which line the system resolves needs a person. Repeated identical entries are listed as observations and do not change the result. |
| PASS | the evidence is sufficient and every GID belongs to exactly one name. |

Never produced: NOT_APPLICABLE.

## 3. Tests

`tests/test_criteria_batch2.py` (Groups): test_pass_with_unique_gids, test_fail_when_two_names_share_a_gid, test_one_name_with_two_gids_is_manual_review_when_both_lines_are_kept, test_a_collision_takes_precedence_over_ambiguity, test_a_repeated_identical_entry_is_an_observation_only, test_partial_group_is_not_evaluated_and_a_duplicate_there_is_an_observation, test_a_compat_include_in_group_is_not_evaluated, test_an_include_in_passwd_alone_does_not_touch_the_group_conclusion, test_unreadable_group_is_not_evaluated, test_undefined_states_are_refused.

## 4. Limitations

- Only /etc/group is evaluated. A PASS means that, in /etc/group as committed, every GID belongs to one name; groups from LDAP, SSSD, NIS or other NSS services are not observed.
- A shared GID is an identity and accountability problem; on its own it is not evidence of a privilege escalation.
- Group membership and group passwords are not evaluated.

## 5. Owner disposition

Disposition: ACCEPTED (owner review of the reported results of this batch (D-111, D-125), 2026-11-08: technical
implementation and lab evidence). The acceptance rests on the results the engineering agent reported
and is not an independent re-run of the lab tests. It concerns the verified tree and the archived
evidence; it does not replace a release decision. No further five-platform run is required.

## 6. Platform acceptance (2026-11-05)

Real hosts were observed, never altered. All five hosts produced PASS where evidence was sufficient;
the other results this criterion can produce (the FAIL (`GID_SHARED_BY_NAMES`), MANUAL_REVIEW (`GROUP_NAME_WITH_SEVERAL_GIDS`), the repeated-entry observation, the NOT_EVALUATED cases (a PARTIAL or unreadable /etc/group, a compat INCLUDE in /etc/group) and the refusal of malformed evidence) rest on the fixtures of section 3 and on the
falsification injections, not on the configuration of these five hosts.

| Platform | Full Audit (`sudo isedraf evaluate`) | Standard Audit (`isedraf evaluate`) |
|---|---|---|
| Debian 12 | PASS `GIDS_UNIQUE` | PASS `GIDS_UNIQUE` |
| Ubuntu 24.04 | PASS `GIDS_UNIQUE` | PASS `GIDS_UNIQUE` |
| Rocky Linux 9.7 (SELinux enforcing) | PASS `GIDS_UNIQUE` | PASS `GIDS_UNIQUE` |
| AlmaLinux 9.7 (SELinux enforcing) | PASS `GIDS_UNIQUE` | PASS `GIDS_UNIQUE` |
| AlmaLinux 8.10 | refused, 70 (Full Audit not supported, by design) | PASS `GIDS_UNIQUE` |

On every platform: `isedraf explain ISE-ACCOUNT-005` renders the record; the installed registry holds eight
criteria; a second evaluation is an identical no-op; the report lists the eight native results; no
finding was raised; no bytecode is left behind; the published 0.2.0 was restored afterwards. The
results of the five earlier criteria are unchanged. The evaluation files of every run are retained in
the evidence.

## 7. Evaluation records and evidence pointers

Each evaluation holds the results of all eight admitted criteria; the files are retained in the
evidence directory (`<platform>-system_evl.tar`, `<platform>-user_evl.tar`).

| Platform | Store | Evaluation | `manifest.json` sha256 | `results.json` sha256 |
|---|---|---|---|---|
| Debian 12 | system (Full Audit) | `EVL-20261105T172906Z-6e3aaa40a8b52045` | `f9a8b04ccc864a65198ba4e7146b3ba9a7ddbec57402862111de122e5e2bbb18` | `dbe0df7b7fdde6c21d9dd4fbd7f6073b026cf9c8486bdd7d3bcc25c3ee384c90` |
| Debian 12 | user (Standard Audit) | `EVL-20261105T172904Z-8e1c25d6f9b87f77` | `857ee65cbcfcf3edd65707593669104d7e4706f226a8fbd943f233a4f147ec0a` | `36bcd96426f92a9bb7c28111ca78bc77942eaa2509fc590297cfd3d0b47d15f7` |
| Ubuntu 24.04 | system (Full Audit) | `EVL-20261105T172907Z-2cf2242febcee3e0` | `9fd47e38a7926c96fc79cf6b8ab0fda3808e00cd54a532d895b97f985249f599` | `b5d94b47369aaec31da023e8294f725fa343eec5c5d1929fcc17697e8e398afe` |
| Ubuntu 24.04 | user (Standard Audit) | `EVL-20261105T172905Z-3b4884d96d368201` | `ee6cacc09114b0f81a26faa92716ce13a5b8626c12674b18d4423431c8caf266` | `d36cb1ddb7a9b018e4fc23159cfd872d5570e314946eb9dc772c26283ac2cc04` |
| Rocky Linux 9.7 | system (Full Audit) | `EVL-20261105T172907Z-e97d4e7409850974` | `e692e9460d59e1a23ba20f2a693372acae858be91b69601b3b98e6cb3537cb90` | `e805c646c484795e69de0050dc0f09c6c0b48269530bbc32dff0a97d33ccc416` |
| Rocky Linux 9.7 | user (Standard Audit) | `EVL-20261105T172905Z-861df516425f5548` | `900a66c37a9944eb796557e0c430f96b748f3d57f7eec9a8462151c2bc9ab48f` | `506f9a2a4018a8df02815eac5fc138a13a0ba26ba8b1df8182e777d54d5f96ed` |
| AlmaLinux 9.7 | system (Full Audit) | `EVL-20261105T172907Z-9e48a1cc4df7e691` | `585db9060038d3ad5332969cd99483705772110d2ff68e72794c36b08d78abe2` | `e4bba51f5813496e6769343d68c97d8acb2e48f0d0d60360057e38276952a5ab` |
| AlmaLinux 9.7 | user (Standard Audit) | `EVL-20261105T172905Z-16989a4b75eb863b` | `0705cf8283f1e1f23d2318dcbe592c840d088db79b5aeb99116bcd666c51e348` | `ea7262c6af3ccce808ec2d322830bf90e3af1392771878cad31a6e0f3653bbed` |
| AlmaLinux 8.10 | user (Standard Audit) | `EVL-20261105T172905Z-10e8034619bd220f` | `660ecca6516da28b154d954c9409a2d0690094105f539cec8fe96f739dc1be1d` | `5d755dd1cfa24ac155da3b941e6ac6e4640a9f0887b8807f9b3264f5f609551b` |

**Real evidence pointers.** Every pointer of this record (section 1) was resolved in real committed
snapshots before the commit (build VM, owner lab evidence store, build run `20261105T170844Z-ea31105-b2ptr`):
the four Full Audit snapshots and the Standard Audit snapshot of `a050-real-snapshots-2026-11-04`, and the Debian 12 and Rocky 9 Full Audit snapshots of `proposal-batch2-2026-11-05`. Every pointer resolved on every element it names (for example 56 of 56 group records on Debian 12), and every pointer the evaluator cited resolved; the result was PASS `GIDS_UNIQUE` on all of them.
