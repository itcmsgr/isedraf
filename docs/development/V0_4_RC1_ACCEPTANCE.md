<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# ISEDRAF 0.4.0-rc1 — Acceptance Record

Status: PLANNING

Owner disposition: release candidate ACCEPTED as the v0.4.0-rc1 checkpoint, 2026-11-12; publication then
held for the regression of section 7, fixed in `a1910d7`. Not
published: push, public sync, tag and publication need a separate owner authorization. This record
indexes the evidence; the normative text is `D-127` and `D-128` (`BASE-011`…`BASE-013`,
`DELTA-007`, `DELTA-008`, `AUTH-034`) and the design is
`docs/development/V0_4_BASELINE_DELTA_DESIGN.md`.

Implements: D-127, D-128

## 1. Commits and trees

| Commit | What | Tree |
|---|---|---|
| `47bcca6` | v0.4 slice 1: DEV baselines (D-127) | `883a2887` |
| `2a41e75` | v0.4 slice 2: production baselines through Full Audit (D-128) | `bc66649f` |
| `060a9c9` | Release candidate 0.4.0-rc1: release integration | `86200af35e80308525319f9de1801b2acd631ff0` |

**The package-tested tree is not the committed tree.** The packages and the lab acceptance of section
3 were built from tree `fd57b8c603a08c182a301da3b1f17cedd0edd23a`. The committed tree `86200af3`
differs from it in exactly one file, `scripts/ci/falsifiable.sh` (the corrected injection of section
4), checked by a recursive comparison of the two working trees on the build VM. That file is a CI
harness file and is not in the installed payload, so the tested packages carry the runtime code of the
commit.

## 2. Packages tested

Built on the lab build VM from tree `fd57b8c6` with `bash packaging/build.sh`; the published 0.3.0
assets are the upgrade source, as verified at publication.

| Package | sha256 |
|---|---|
| `isedraf_0.4.0~rc1_all.deb` (candidate) | `8728fb48ab2175ec2b265f4c336452eb3d44f540d7406f4e7388258d1a378ea1` |
| `isedraf-0.4.0-0.rc1.noarch.rpm` (candidate) | `e8a2f38a3a67b52b4f7e339b02624eb5501c18493f6c3512722dbe64645fa393` |
| `isedraf_0.3.0_all.deb` (published) | `25474c8d10a7b555a8c23b2462e3c000a322e117fed8235a8fef50afce4ce325` |
| `isedraf-0.3.0-1.noarch.rpm` (published) | `a62dcdb4fa55cb232059b7a43417a8cabb781c668119ea4abaed65999ec97388` |

## 3. Release-candidate acceptance, 2026-11-12

One scripted run per platform, packages of section 2, unprivileged operator account with `sudo`. Existing
stores were moved aside, never deleted. Evidence: owner lab evidence store, `rc040-acceptance-20261112`
(78 files, sealed by its `SHA256SUMS`).

| | Debian 12 | Ubuntu 24.04 | Rocky Linux 9.7 (SELinux enforcing) | AlmaLinux 9.7 (SELinux enforcing) | AlmaLinux 8.10 |
|---|---|---|---|---|---|
| Upgrade 0.3.0 → 0.4.0-rc1: every pre-existing file of the user and system stores byte-identical (0 missing, 0 changed); stores verify, 0 problems | PASS | PASS | PASS | PASS | PASS (user store; no Full Audit store) |
| New evaluation after the upgrade; earlier evaluations kept; report shows "No approved baseline" | PASS | PASS | PASS | PASS | PASS |
| User-store approval refused, 65 `BASELINE_CLASS_NOT_ADMITTED` | PASS | PASS | PASS | PASS | PASS |
| `sudo isedraf baseline approve SDS-…` refused, 70 | PASS | PASS | PASS | PASS | refused, 70 (see below) |
| Incomplete Full Audit (induced, see below): 65 `INCOMPLETE_FOR_BASELINE`, `loginpolicy is PARTIAL` named, no `baselines/`, no ledger record, the earlier complete run not approved | PASS | PASS | PASS | PASS | n/a |
| Approve the latest complete run: 0; the approved snapshot is the latest run; root:root 0700/0600 | PASS | PASS | PASS | PASS | n/a |
| Second approval, 65 `BASELINE_ALREADY_APPROVED` | PASS | PASS | PASS | PASS | n/a |
| Unchanged run: no change rows | PASS | PASS | PASS | PASS | n/a |
| Controlled change (induced): one `accounts` MODIFIED / REVIEW_REQUIRED row; the Markdown report shows it, with the eight criterion rows; the HTML report has the "Baseline comparison" part (see below) | PASS | PASS | PASS | PASS | n/a |
| Change reverted: no change rows | PASS | PASS | PASS | PASS | n/a |
| System store verifies at the end | PASS | PASS | PASS | PASS | n/a |

AlmaLinux 8.10 has no `/usr/bin/python3`, so `bin/isedraf` refuses any invocation under sudo with 70
before the launcher runs, as 0.3.0 does there; Full Audit, and therefore a production baseline, is not
available on that platform.

**Deliberately induced conditions (owner-authorized, 2026-11-12).** Neither was found on the hosts; both
were created by the acceptance script, held around exactly one Full Audit run, removed, and checked
removed in the same script:

- P1, the incomplete-evidence case: `/etc/security/limits.d/zz-isedraf-lab-probe.conf` holding one
  malformed line. The login-policy collector records that source as UNPARSEABLE, so `loginpolicy` is
  PARTIAL; pam_limits skips a malformed line.
- P2, the controlled change: a system account `isedraf-lab-probe` (no home, no login shell).

The incomplete Full Audit refusal, an open validation gap after `2a41e75` (fixture-proven only), is
therefore observed on four real hosts under an induced condition.

**HTML content, checked after the run.** The script checked the MODIFIED line in the Markdown report
and only the presence of the "Baseline comparison" part in the HTML report. The retained HTML reports
(`<platform>-sudo_report.html`) were checked afterwards: each of the four contains the line
`accounts MODIFIED, REVIEW_REQUIRED`.

**Corrected evidence-script calculation.** The script's `U_still_preserved` line compared the stores'
hash lists with `comm` on input sorted by path, which `comm` does not support, and printed meaningless
"missing or changed" counts (2 to 19). Recomputed by path from the fetched lists `<platform>-user.pre`,
`-user.post`, `-system.pre` and `-system.post`: 0 missing and 0 changed on every platform, and 4 new
user-store files, which are the new 0.4.0-rc1 evaluation. The direct comparison made right after the
upgrade (`U_preserved ... identical`) was unaffected.

## 4. Gates and falsification

| Check | Tree | Result | Evidence (build runs, owner lab evidence store) |
|---|---|---|---|
| `make check` | `fd57b8c6` | all gates passed | `20261112T195922Z-2a41e75-wip-s3c` |
| `make check` (pre-commit hook of `060a9c9`) | `86200af3` | all gates passed | `20261112T202101Z-2a41e75-rc040-commit` |
| Report, evaluate and route suites after the report change | slice 3 | 8 suites OK | `20261112T195511Z-2a41e75-wip-s3a` |
| **Full falsification harness** | `fd57b8c6` | **566 executed and detected · 2 declared skips · 1 unexpected non-firing (harness error)** | `20261112-fd57b8c-rc040-falsification/full.log`, sha256 `94e0aadf…bf8052e` |
| **Targeted rerun** of the one injection after its fix | `86200af3` | 1 executed and detected | `20261112T201915Z-2a41e75-wip-s3g` |

These are two separate results, not one clean full run. The full harness was not repeated for the
one-line harness fix, because no product artifact changed (verification levels, owner ruling
2026-11-08).

- **The two declared skips** are `D-83 a release export marker no longer binds the manifest` and `D-83 a
  release export omits a governance file it publishes`. Their subject, the public-export marker file, is
  written only during a release export and is absent from an engineering checkout; the full runs of 2026-11-04 and
  2026-11-05 report the same two skips.
- **The harness error** was `GA-AUDIT-1 the report follows the newest directory, not the ledger`. Its
  mutation had matched nothing since `47bcca6` rewrote the line it mutates in `report/model.py`, so the
  injection tested nothing; the guarantee itself held (the reader takes the last snapshot record). It is
  re-anchored in `060a9c9` and detected again by the targeted rerun.

## 5. Compatibility

- **Report schema 3 → 4.** The report gains `baseline_comparison` (JSON) and a "Baseline comparison"
  part (Markdown, HTML): the committed comparison as the evaluation recorded it; a report never
  compares. Existing fields are unchanged. `native_results` additionally carries the evaluation's
  `changes` object when an evaluation is shown.
- **Upgrade.** Snapshots, ledger and evaluations of 0.3.0 are kept and verify. A store without a
  baseline evaluates as before; because the engine version is part of an evaluation's identity, the
  first 0.4.0-rc1 evaluation is a new one beside the old. Nothing is approved automatically. The ledger
  gains `baseline_approved` records only through an explicit approval.
- **Exit codes.** 5 and 65 are reachable, per command as `lib/isedraf/exitcodes.json` lists them;
  `evaluate` reports a change in its record, never in its exit code.

## 6. Limitations retained

- One baseline per store; accepting a change, re-approval, tracking, the `check` journey and its exit
  codes come later.
- A pure reorder of configuration lines is reported as MODIFIED (REVIEW_REQUIRED).
- The method fingerprint is provisional (`DELTA-008`): a match does not prove an identical collection
  method.
- Fields the domain tables classify as PROVENANCE do not take part in a comparison.
- Someone with root on the host can rewrite the store, the baseline and the ledger together
  (`STORE-017`).
- AlmaLinux 8: no Full Audit, so no production baseline.
- A standard (unprivileged) audit is never complete enough to approve; DEV baselines are never
  production baselines.

## 7. Post-review regression and fix (2026-11-12)

The owner's review of the release-candidate bundle found a release-blocking regression, and publication
was held for it.

- **Defect.** `47bcca6` changed `identity_evidence()` in `lib/isedraf/report/model.py` to select the
  `snapshot_committed` ledger record and reused the name `core` for that record, shadowing the snapshot's
  `manifest_core`. From `47bcca6` to `2986c80` every report rendered `host_id`, `created_at`, `run_id`
  and `run_mode` as null and took `state_root_class` from the ledger record, while verification still
  reported success; before and after an approval; user route and Full Audit route alike. The committed
  sample report carried the nulls too, because its gate compares a regenerated sample with the committed
  one and both came from the same code. The acceptance of section 3 did not check these fields, so its
  packages carried the defect.
- **Fix:** `a1910d7`, tree `42d2a368f8af5754ebb8682c48e5fcd8df7bb4c4`: separate `manifest_core` and
  `record_core`. Regression tests written first, both failing before the fix: report metadata equals the
  selected snapshot's manifest before approval, after approval and after a later run, on the user route
  and through the Full Audit report route (root-side frame and reduced renderer). One falsification
  injection recreates the defect. The sample report, CURRENT_STATE and the falsification coverage page
  are regenerated.
- **Checks:** 15 affected suites OK; `make check` all gates passed (pre-commit hook of `a1910d7`); the new
  injection and the two earlier report-reader injections detected (targeted run). The full falsification
  campaign was not repeated for this fix (owner, 2026-11-12).
- **Packages rebuilt from commit `a1910d7`** (these supersede the packages of section 2):

  | Package | sha256 |
  |---|---|
  | `isedraf_0.4.0~rc1_all.deb` | `152eabb7a2dd0429d826ec2605f0e1d376fe5af82986b4e8dada4dda3fa7e143` |
  | `isedraf-0.4.0-0.rc1.noarch.rpm` | `def9266224fadc1e0ed67fdd2a9e999e9f0e61986dc406c22604fe96a8e50918` |

- **Bounded DEB/RPM report check** with those packages, Debian 12 and Rocky Linux 9.7, on the stores the
  acceptance of section 3 left: the report's identity equals the selected snapshot's manifest for the
  user store (no baseline), for the Full Audit store after approval, and after a later Full Audit run; the
  Markdown report shows no null host. Evidence: owner lab evidence store,
  `fix1-report-identity-final-20261112`.
- The rest of section 3 (upgrade, approval workflow, incomplete case, comparison) is not repeated: the fix
  changes only how the report reads run metadata.

## 8. Not covered by this record

Push of the engineering branch, the public sync, tag and publication; the open code-scanning alerts;
the owner-only `CLAUDE.md` wording correction.
