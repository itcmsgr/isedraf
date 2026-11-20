<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.5 Ledger recovery (STORE-016) — design

Status: PLANNING

Implements: STORE-016, STORE-010, STORE-022, STORE-024, D-129

Owner decision 2026-11-16: implement `STORE-016` in v0.5, before the release candidate, within these
limits: the damaged segment's exact bytes are kept, private, in the same store; recovery only for a
recognisable interruption of the last record; corruption of an earlier record or a broken chain is
refused; everything under the existing lock and safe against a new interruption, with no silent
loss, no duplicate record and no false success; tests for a short write, `ENOSPC`, an interruption at
each recovery step, and a repeated run.

## 1. Facts (engineering `88b2907`)

| # | Fact | Source |
|---|---|---|
| F1 | One segment only: every writer and reader uses `ledger/segment-000001.jsonl` | `stateroot.LEDGER_SEGMENT`; `ledger.py`; `launcher/reportunit.py`, `evalunit.py`, `baselineunit.py`, `renderer.py`, `listunit.py` |
| F2 | `ledger.append` makes one `os.write` and does not compare the byte count | `ledger.py` (`append`) |
| F3 | No recovery exists: a trailing partial line makes `read_records` raise, so every later run fails as an engine error | `ledger.py` (`read_records`) |
| F4 | `STORE-016` (frozen): byte count verified; a torn tail preserved; the chain recovered to the last verified record; a new segment opened by a `ledger_recovered` record naming the damaged segment and the torn tail's byte hash; no uninterrupted integrity claimed across it | `SNAPSHOT_BASELINE_DELTA_MODEL.md` |
| F5 | `STORE-010` (frozen): `ledger/segment-NNNNNN.jsonl`; the first record of segment N+1 carries the last record of segment N as its previous hash; the sequence is monotonic across segments | idem |
| F6 | `ledger_recovered`'s record is not frozen ("belongs with recovery") | `STORE-024` |

## 2. Design

### 2.1 What counts as a recoverable interruption

The newest segment ends in bytes after its last newline (a write that did not complete), **and** every
newline-terminated record before them parses, has its `record_hash`, and chains (`STORE-024`). Only
then is it a torn tail. Anything else is refused with `LEDGER_INTEGRITY_FAILURE` and nothing is written:
a complete last line that does not verify, an earlier record that does not verify, a broken chain, a
torn tail in a segment that is not the newest, or a tail longer than one record's bound.

### 2.2 The recovery, step by step (under the whole-run lock)

1. Read the newest segment, bounded; classify it (2.1). Nothing torn: no recovery.
2. The damaged segment stays where it is, **byte for byte unchanged**, mode 0600: it is never
   appended to again. Its verified prefix keeps its records; its torn tail is kept as forensic evidence.
3. Build the `ledger_recovered` record (2.3) as the first record of the next segment number.
4. Write it to `tmp/ledger-recovery-segment-NNNNNN.jsonl` (exclusive within the run's lock; an earlier
   uncommitted copy of the same name is replaced, because nothing has ever referenced it), verify the
   byte count, fsync.
5. Rename it to `ledger/segment-NNNNNN.jsonl` (the target never exists: the next number is derived
   from the existing segments), fsync the directory.

An interruption before step 5 leaves the store as it was (plus an unreferenced temporary file), and the
next writer repeats the recovery. After step 5 the new segment exists complete or not at all. A second
recovery of the same segment cannot happen: the next segment's first record seals it.

### 2.3 The `ledger_recovered` record (proposed; owner to freeze)

```text
record_core:
    ledger_schema_version  1
    sequence               last verified record's sequence + 1
    event                  "ledger_recovered"
    event_id, occurred_at  as for every record
    previous_record_hash   the last verified record's record_hash (genesis if none)
    state_root             the store's class
    damaged_segment        "segment-NNNNNN.jsonl"
    verified_length        bytes of the damaged segment that hold its verified records
    damaged_length         the damaged segment's total length
    torn_tail_hash         "sha256:<64 hex>" of the torn tail's bytes
record_hash = the STORE-024 rule
```

### 2.4 Readers, verification and the routes

- One pure function in `ledger.py` turns the segment files (name → bytes) into the records and
  problems: a segment sealed by a later `ledger_recovered` contributes exactly its `verified_length`
  bytes, and its length and tail hash must still match the record. Every reader uses it: the user
  route, `verify`, and the root sides of report, evaluate, baseline and list, which frame or read
  **all** segment files (bounded in number and size), never only the first.
- `verify_ledger` checks the chain across segments, and reports a torn tail that is not yet recovered
  as such. Reports state "recovered at segment N" wherever the ledger is summarised; no uninterrupted
  integrity is claimed across a recovery.
- Only the operations that append to the ledger recover, after taking the lock and before collecting
  or writing: `isedraf audit`, `isedraf identity`, `isedraf baseline approve`, `sudo isedraf audit`,
  `sudo isedraf baseline approve`. `report` and `list` (both routes) and `evaluate` (both routes;
  it writes an evaluation, never the ledger) never recover: each refuses an unrecovered tail with 64,
  writes nothing and names the command that recovers it. (Found 2026-11-16 after the first recovery commit: the user
  route's `report` and `list` rendered the verified prefix without saying the tail was torn; fixed.)

### 2.5 Exit codes and space

- A refused recovery (2.1) exits `64` with `LEDGER_INTEGRITY_FAILURE` (the code committed evidence that
  does not verify already uses); nothing is written.
- A recovery write that fails for want of space exits `68` (`STORE-022`), before anything is collected,
  and does not loop; the preflight's `RECOVERY_RESERVE` is the room for it.
- A short write or `ENOSPC` on a normal append: the run is not committed (its snapshot directory is
  unledgered, `SNAP-018`); the next writer recovers the tail.

## 3. For the owner to decide in the kit

L5 is new from the implementation: `STORE-016` calls a complete last record that fails its hash a
torn tail too; this implementation refuses it instead, because a single interrupted write leaves bytes
after the last newline and a complete record that fails is not an interruption. The amendment states
the narrowing.

| # | Question | Recommendation |
|---|---|---|
| L1 | Freeze the `ledger_recovered` record of 2.3 | yes, in `STORE-024` beside `baseline_approved` |
| L2 | Where the damaged bytes are kept | in place, `ledger/segment-NNNNNN.jsonl`, unchanged and sealed by the next segment (no move, so no second copy and no rename that could fail half-way) |
| L3 | Exit code of a refused recovery | `64` with `LEDGER_INTEGRITY_FAILURE`, no new code |
| L4 | `STORE-021` (segment number and head recorded outside the ledger, against deletion of the newest segments) | not in v0.5; recorded as an open item: it is a separate protection with its own design |
| L5 | A complete last record that does not verify | refused, not recovered (the owner's "recognisable interruption of the last record") |
