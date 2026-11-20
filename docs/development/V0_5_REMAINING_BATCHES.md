<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.5 remaining batches — plan

Status: PLANNING

Implements: D-129

The register (`docs/development/V0_5_OPERATOR_EXPERIENCE.md`) stays the one list of items, their
acceptance conditions and status. This page only orders the items still open after B1–B4 (commands,
help, completion, root help: `docs/development/V0_5_COMMAND_DEFINITIONS_DESIGN.md`) into bounded
batches and names what each needs from the owner.

## 1. Batches

| Batch | Items | Main code | Owner-controlled parts |
|---|---|---|---|
| B5 | P1 compact header, P2 audit summary, P3 readable errors (user route first) | `cli.py` output of `audit`, `identity`, `evaluate`, `baseline approve`, `inventory`; the pure renderer `lib/isedraf/summary.py`; the report keeps its own title until R5 (B10) | none: output text only, exit codes unchanged, `--json` unchanged |
| B6 | P4 the same summaries on the Full Audit route, P5 approval shown before and after writing | the unit launchers' human output (`launcher/unit.py`, `evalunit.py`, `baselineunit.py`) reusing B5's renderer | none expected, unless a frozen message text changes (then an `AUTH-*` note) |
| B7 | R1 discover runs and reports, R2 save shows the absolute path, R3 private storage explained, R4 root export guidance | a read-only listing command (new command record, `exitcodes.json` row), `report --save` output, guides | `exitcodes.json` row for the new command (owner kit) |
| B8 | H8 refusals in operator language, H9 account switched through sudo; R1 `sudo isedraf list` (AUTH-035); R4 export guidance; H10 explained; 80-column wrapping | `summary.explained`, `launcher/listunit.py`, the root refusal and `bin/isedraf` | owner kit: `AUTH-035`, `AUTH-019` paragraph, `D-129` point 12, `exitcodes.json` row |
| B9 | S1 free-space preflight (`STORE-016`, `STORE-022`) | preflight before collection in the user and system routes, headroom for a recovery record | Q4 DECIDED: new code `68 INSUFFICIENT_SPACE`; owner kit (`exitcodes.json`, `D-129` point 11); code in `lib/isedraf/space.py` |
| B10 | R5 report a junior can read; D1 release documentation check; D2 install instructions; K1 upgrade from 0.4 verified | renderer section order, a bounded documentation gate, guides, lab upgrade check | none expected |
| — | P6 read-only baseline preview | design only unless adopted | owner decision if adopted |
| — | H10 root help where `/usr/bin/python3` is absent (IQ-078) | none until decided | owner compatibility decision |

Each batch: tests and falsification injections in the same commit, guides updated with the change
(D1), `make check` on the build VM, then a bounded lab check from installed development packages.

## 2. Open for the owner

| # | Question | Recommendation |
|---|---|---|
| Q4 | S1: which exit code for insufficient space, and how much headroom | DECIDED (owner, 2026-11-15): `68 INSUFFICIENT_SPACE`, once checked unused; one shared preflight implementation; the estimate of the pending write and the headroom documented, any margin an explicit named value; the refusal leaves committed evidence intact and states available against required space; write failures after the preflight still handled safely; nothing is ever deleted automatically |
| Q5 | B7: name of the read-only listing command | DECIDED (owner, 2026-11-15): `isedraf list`, for runs, evaluations, reports and the current baseline, with dates, IDs, classes and report paths; no collection, approval or modification. The system-store listing needs its own bounded authorization amendment and never exposes protected evidence |
