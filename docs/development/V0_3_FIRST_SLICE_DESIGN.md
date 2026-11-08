<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.3 first vertical slice — ISE-ACCOUNT-001 end to end

Status: PLANNING. Ruled by the owner on 2026-11-01 and incorporated as `D-125` (`EVAL-001` …
`EVAL-009` in `docs/architecture/NATIVE_CONTROL_CATALOG.md`), which supersedes section 3 below,
S3 in particular: `70` already means a refused privileged invocation.
Implements: D-41, D-42, D-77, D-111, D-121, CMP-003

This is the design input for the first v0.3 slice: one admitted criterion, `ISE-ACCOUNT-001`,
evaluated from committed evidence, written to `evaluations/EVL-*`, and rendered by `isedraf explain`,
the report and a generated page. It authorizes nothing. The decisions S1 to S5 wait for the owner;
three of them touch owner-only files and need a kit. No evaluation code is written before they are
ruled (IQ-072).

Audited at engineering `release/v0.3` `585ad7b`. Labels follow `docs/development/DOCUMENTATION_POLICY.md`
§9.

## 1. What the frozen text already fixes

- FROZEN REQUIREMENT `SNAP-011`: a snapshot never contains `changes.json`, `findings.json` or any
  evaluated result.
- FROZEN REQUIREMENT `SNAP-012` (D-41): `evaluations/EVL-*/` contains `changes.json`, `findings.json`
  and a manifest; it is derived and regenerable, keyed by `snapshot_id` + `baseline_revision` +
  `engine_version` + rules/profile version.
- FROZEN REQUIREMENT `SNAP-013` (D-42): the evaluation manifest records the snapshot manifest hash,
  baseline revision, engine version, collector and parser version per section, evaluation-rules
  version, schema versions and profile.
- FROZEN REQUIREMENT `STORE-020`: `evaluations/` carries no ledger entry.
- FROZEN REQUIREMENT `D-77`: `explain` shows collected sources, collection status, normalized state,
  baseline state, exact delta, classification reason, limitations, evidence references, manual
  verification, guidance and operational risk, and never turns uncertainty into certainty.
- FROZEN REQUIREMENT `D-80`: controls in the prototype are `EXPERIMENTAL`.
- REPOSITORY FACT: the criterion record was in `scripts/ci/native_controls.json` (D-125 moved it; that path does not exist any more) (owner admission 2026-11-01, D-111).
  `packaging/rpm/isedraf.spec.in` and `packaging/build.sh` ship `lib/isedraf/` only, so an installed
  host has no copy of the record.
- REPOSITORY FACT: `lib/isedraf/exitcodes.json` (owner-only) lists the exit codes per subcommand;
  neither `isedraf evaluate` nor `isedraf explain` exists.
- REPOSITORY FACT: `lib/isedraf/ids.py` has no `EVL` prefix, and `lib/isedraf/stateroot.py` does not
  create `evaluations/`.

## 2. The path

```text
snapshots/SDS-*  (committed, ledgered; verified before use)
      |  read only: manifest.json, sections/accounts.json (digest checked)
      v
evaluate ISE-ACCOUNT-001   pure function of the evidence and the criterion record
      v
evaluations/EVL-*/         manifest.json, changes.json, findings.json, results (S4)
      v
isedraf explain ISE-ACCOUNT-001  ·  isedraf report  ·  generated criterion page
```

The evaluator reads no live file, starts no collector, and never fills in missing evidence. Standard
and Full Audit collection do not change.

## 3. Decisions for the owner

**S1 — where the one record lives at runtime (owner-only: `NATIVE_CONTROL_CATALOG.md` names the path).**
PROPOSAL (A): move the registry to `lib/isedraf/catalog/native_controls.json` *(PLANNED — not yet created)*. That file is the only
record. It is shipped in the package, and the gate, `explain`, the report and the generated page all
read it. (B): keep `scripts/ci/` as the authority and copy it into the package at build time, with a
gate proving the two copies are identical. Recommended: A. B is a second copy of the record, and the
catalog's "no second registry" rule exists to prevent exactly that.

**S2 — the commands (owner-only: `exitcodes.json`).** PROPOSAL:
`isedraf evaluate [SDS-id]` writes one EVL from a committed snapshot (the latest by default) and
never collects. `isedraf explain ISE-ACCOUNT-001` renders the record and the latest result, and
writes nothing. `isedraf report` shows the EVL for its snapshot when one exists, and never evaluates.
`isedraf audit` is unchanged. The alternative, evaluating inside `audit`, would change the
collection command, which the owner's acceptance list says stays unchanged.

**S3 — exit codes for `evaluate` (owner-only: `exitcodes.json`).** PROPOSAL: `0` EVL written and
every result decided; `2` EVL written with at least one `NOT_EVALUATED`; `64` usage; `66` run in
progress; `67` state root unwritable; `70` evidence that does not verify (fail closed, no EVL
written). A `FAIL` result does not set `1`: in the frozen precedence, `1` means an unaccepted security
change, which is delta semantics (v0.4). For `explain`: `0`, `64`, `70`. Owner choice: whether a
`FAIL` should have an exit code of its own, which would be a new code.

**S4 — where `PASS` and `NOT_EVALUATED` results live (owner-only: `SNAP-012` is frozen).** `SNAP-012`
names three artifacts; `findings.json` holds findings, and a `PASS` is not a finding (D-121). PROPOSAL:
add `results.json` (every criterion's result, with reasons and evidence references) and amend
`SNAP-012` to list it. `findings.json` holds the `FAIL` security findings with `default_severity`.
`changes.json` is written with an empty list and the reason `NO_BASELINE` until v0.4. The
alternatives are to put all results in the manifest, which mixes provenance with results, or to
store `PASS` in `findings.json`, which misnames it.

**S5 — which stores the slice covers.** PROPOSAL: the slice covers the stores the unprivileged
engine writes (`USER_PRODUCTION`, and `DEV` with every artifact marked `DEV`). A Standard Audit is
enough for `PASS` and `FAIL` because sufficiency uses the passwd source's own status (D-111, admission 2026-11-01).
Evaluating the system store needs a root route (`sudo isedraf evaluate`) like `sudo isedraf report`,
and that is the next step, not this slice. The lab acceptance then runs a Standard Audit and
`evaluate` on the five VMs, plus one Full Audit snapshot showing that `sudo isedraf report` is
unchanged.

## 4. Engine rules that need no owner decision

- `EVL` joins the frozen prefixes in `ids.py` (named by D-41).
- An EVL is regenerable: its identity is derived from the `SNAP-012` key, so evaluating the same
  snapshot with the same engine and catalog yields byte-identical artifacts. If an EVL with that key
  already exists, `evaluate` verifies it is identical and writes nothing; a difference is an engine
  error (`70`), never an overwrite.
- Writes follow the snapshot discipline: private temp dir, umask 077, exclusive creation, fsync,
  atomic rename. No ledger entry (`STORE-020`).
- Fail closed (exit `70`, nothing written): a snapshot that does not verify, an unledgered snapshot,
  a section digest mismatch, an unknown section schema, or a criterion record that fails the catalog
  contract.
- `explain` shows baseline state and delta as "not available: no baseline (v0.4)", and the
  criterion as `EXPERIMENTAL` (D-80).

## 5. Tests (owner's list, 2026-11-01)

PASS with root as the only UID 0 · FAIL with an extra UID-0 entry · FAIL with no UID-0 entry ·
NOT_EVALUATED for PARTIAL, ERROR, NOT_TESTED and INCLUDE-widened passwd, including an extra UID-0
entry seen in PARTIAL evidence · fail closed on a digest mismatch and on a malformed section ·
the same snapshot evaluated twice gives identical artifacts · audit output unchanged. Each test
case gets a falsification injection. After local gates pass: one focused five-VM lab acceptance.
