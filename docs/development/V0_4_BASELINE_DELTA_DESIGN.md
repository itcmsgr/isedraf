<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.4 Baseline and Delta — slice plan, slice 1 design and acceptance

Status: IMPLEMENTED in engineering for slices 1 and 2; not released. Ruled by the owner on 2026-11-11 and
recorded as `D-127`; the normative text is in `docs/architecture/SNAPSHOT_BASELINE_DELTA_MODEL.md`
(`BASE-011`, `BASE-012`, `BASE-013`, `DELTA-007`, `DELTA-008` and the "Amended for v0.4 by D-127"
paragraphs), `V0_1_IMPLEMENTATION_SCOPE.md` (`SCOPE-073`) and `NATIVE_CONTROL_CATALOG.md`
(`EVAL-005`, `EVAL-007`). This page is the working design; where it and those texts differ, they win.
Implements: D-120, D-127, BASE-007, BASE-008, BASE-011, BASE-012, BASE-013, DELTA-007, DELTA-008

## 1. The three slices

| Slice | Content | Done when |
|---|---|---|
| 1 — DEV engine | `isedraf baseline approve` for complete `DEV` snapshots; comparison inside `isedraf evaluate`; frozen text amended with the code | the acceptance in section 4 passes |
| 2 — production | `SYSTEM_PRODUCTION` baselines through Full Audit: a root write route for `baselines/`, an authorization amendment, lab validation; the system-store readers select `snapshot_committed` records | lab proof of eligible approval, refused incomplete Full Audit snapshots, and refused misuse of the route |
| 3 — release integration | the comparison in the report, help, exit documentation, packaging, upgrade proof, release candidate | the release verification level |

Slice 1 proves the engine. It does not complete the production feature; slice 2 does, and both are
v0.4 scope. A Full Audit snapshot is not eligible because it is privileged: it must meet the profile's
completeness like any other. `USER_PRODUCTION` is never a production baseline.

## 2. Owner rulings (2026-11-11)

- **D1** — slice 1 approves `DEV` baselines only; slice 2 adds `SYSTEM_PRODUCTION`.
- **D2** — profile `v0.4-default-1`, version 1, requiring `host_identity`, `accounts`, `ssh`,
  `loginpolicy`. **Strict:** an incomplete snapshot is refused (`INCOMPLETE_FOR_BASELINE`, exit 65),
  each blocking section named with its status and reason. A standard (unprivileged) audit cannot read
  `/etc/shadow`, so a real host is refused; approval is proven on complete DEV fixtures.
- **D3** — every `MODIFIED` row is `REVIEW_REQUIRED`; `evaluate` keeps its exits and adds `5` for a
  baseline that does not verify; `65` is approval refused; `check` and its codes come later.
- **D4** — the method fingerprint is provisional: a mismatch is a comparability fact; a match does not
  prove the method identical.
- **O1–O4** — the frozen text needed more than the four amendments first named; profile identity
  `v0.4-default-1` / 1; a second approval is refused (`BASELINE_ALREADY_APPROVED`); documentation
  alignment committed first.

## 3. Slice 1 in one page

- **Revision.** `BL-000001 = HASH_FRAME_V1("ISEDRAF:BASELINE:V1", manifest_hash, profile_hash)`
  (`SCOPE-074`, unchanged). The artifact `baselines/BL-000001.json` also records the class, host,
  profile, required and tracked sections, and per section the status, `state_hash` and method
  fingerprint. It holds no time and no ledger sequence, so an interrupted approval can be completed
  byte for byte.
- **Ledger.** `baseline_approved` records the revision hash and the digest of the artifact's exact
  bytes. Readers of "the latest run" take the last `snapshot_committed` record.
- **Integrity before comparison** (`BASE-011`). The digest binds the bytes; every field is then
  re-derived from the verified approved snapshot and the packaged profile, and must match. A stored
  value this engine cannot reproduce because its method fingerprint changed stays bound by the digest
  only, and the section is marked `METHOD_CHANGED`.
- **Section state** (`DELTA-007`). Only fields the domain tables classify `STATE`; lists keep the
  collector's order and are not deduplicated; `null` and absent differ; an unknown field makes the
  section not comparable instead of being dropped.
- **Comparison.** Both sides are projected by the current engine from verified snapshots. Equal → no
  row; different → one `MODIFIED`, `REVIEW_REQUIRED` row; a section not `COLLECTED` on either side →
  `NOT_COMPARABLE` with the reason, never `REMOVED` or an improvement; another host →
  `BASELINE_NOT_APPLICABLE`, no rows; a new snapshot without host identity → `NOT_ESTABLISHED`.
- **Writes** (`BASE-012`). Stage in `tmp/`, link into `baselines/`, append the ledger record (the
  commit point), then write `current`. Each interruption has a defined outcome; nothing outside `tmp/`
  is ever deleted.

## 4. Acceptance of slice 1

Verified on the lab build VM (Ubuntu 24.04), never on the workstation:

- `make check`: all gates passed on the complete change.
- `tests/test_baseline.py` (39 tests): approval of a complete DEV fixture with modes 0600/0700 and a
  verifying chain; audit never creates `baselines/`; second approval refused; incomplete snapshot
  refused naming both sections; USER_PRODUCTION refused for its class, before completeness; unknown
  snapshot `64`, root `70`, lock held `66`; no baseline → the v0.3 `changes.json`; 10 unchanged runs
  → no rows; one row per changed section (accounts, ssh, loginpolicy); a pure reorder reported; gecos
  and comment lines silent; collector-version change silent with equal state and `REVIEW_REQUIRED`
  with different state; a PARTIAL section `NOT_COMPARABLE`; another host `BASELINE_NOT_APPLICABLE`;
  the evaluation key names the revision and profile; exit `5` for an edited revision, a forged revision
  with a re-chained ledger, a missing or mismatching pointer, a missing revision, an altered approved
  snapshot, and a pointer without a ledger record; interruptions before the link, before the ledger
  append and before the pointer, each with its outcome and completion; projection rules.
- `tests/test_baseline_vectors.py`: `test-vectors/v04/v1/` reproduce from the independent reference,
  and production matches them: profile hash, one `BL-000001`, three section state objects.
- Falsification: 11 injections, one per guarantee, each detected; the 7 existing evaluation
  injections still detected.
- Lab, unprivileged, the slice run from source on Debian 12 and Rocky Linux 9.7:
  a real-host DEV snapshot (accounts and ssh PARTIAL) is refused `INCOMPLETE_FOR_BASELINE`, 65, with
  nothing written; the host's own USER_PRODUCTION snapshot is refused `BASELINE_CLASS_NOT_ADMITTED`,
  65, store bytes unchanged; a complete fixture is approved, an unchanged run gives no rows, a changed
  `PermitRootLogin` gives one `ssh` `MODIFIED` / `REVIEW_REQUIRED` row, and a tampered pointer exits 5.

## 5. Limitations stated, not hidden

- The method fingerprint's classification element is the computing engine's table; audit sections do
  not record `source_id` or `classification_table_version`.
- Fields the existing tables classify as `PROVENANCE` do not take part: an identical login-policy
  value moved between files or families is not a change.
- A pure reorder of records is reported as a change.
- The ledger is tamper-evident to a non-root actor only (`STORE-017`); a local root user can rebuild
  the chain, and re-derivation then still catches a stored value the evidence does not give.

## 6. Slice 2 — production baselines (D-128, AUTH-034)

- **Route.** `sudo isedraf baseline approve`, no argument: the latest committed Full Audit run. The
  `AUTH-033` model is reused: outer entry, `systemd-run` unit with the audit properties, root side in
  the unit, a reduced approver started through the engine reduction.
- **Root side reads metadata only** and derives the action from the ledger's events and whether
  `baselines/BL-000001.json` and `baselines/current` exist: already approved (65, the approver never
  runs), complete the recorded approval, resume at the ledger append, or new. `current` without a
  record is an integrity failure (5).
- **Reduced approver** verifies the frame and runs slice 1's `plan` unchanged; the root side checks
  its two-item answer against values it computes itself (latest run, manifest hash, class, packaged
  profile and hash, revision hash) and runs slice 1's `commit` (`BASE-012`) with the stop signals
  blocked.
- **Readers.** `reportunit`, `renderer` and `evalunit` take the last `snapshot_committed` record as
  the latest run; the evaluation frame carries the baseline state and, when it is another run, the
  approved snapshot; the evaluation identity names the revision and profile from the ledger record and
  the packaged profile; the reduced evaluator exits 5 when the baseline does not verify.
- **Slice 1 defect found and fixed here.** The report computed the evaluation identity without the
  baseline, so after an approval it said the run was not evaluated (DEV and system store alike). One
  derivation, `evaluate/record.baseline_key` (the revision from the ledger record, the profile from
  the packaged profile), now serves the report, the user route and the system route; a regression
  test and an injection keep it.
- **Acceptance.** `tests/test_baseline_route.py` (18 tests) and the affected route suites;
  8 new injections, 3 re-anchored, 32 selected injections detected; the bounded DEB/RPM lab acceptance
  is recorded with the D-128 commit.

## 7. Not in v0.4 slices 1 and 2

The `check` journey and its exits `1`, `2`, `3`, `4`, `6`; accept, acknowledge, rebind, track and
untrack; baseline events and acceptance records; pruning, checkpoints and ledger recovery; new
collectors or criteria. The report's view of the comparison, help, operator documentation and
packaging belong to slice 3, release integration.
