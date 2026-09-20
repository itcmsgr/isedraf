<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Python floor — runtime evidence

Status: EXPERIMENTAL · Evidence for an owner decision on `D-12`. **No requirement has been amended.**

## The question

`D-12` declares `Python ≥ 3.9`. W1-C found that the interpreter is the **only** portability boundary in
the whole matrix, so the floor — not any distribution — decides which enterprise platforms ISEDRAF can run
on without installing anything.

A static scan showed the production code uses no feature newer than 3.6. **That was not accepted as a
basis for changing a frozen requirement.** What follows is execution.

## Method

The certified W1-A corpus is the pivot. CI already proves that CPython 3.9.25 and 3.12.14 reproduce it
byte for byte, so an interpreter that also reproduces it is byte-identical to both **without any result
being copied between interpreters**.

`scripts/compat/floor_experiment.py` runs the production pipeline over all 13 machine-id vector inputs and
compares every artifact — `status`, `reason`, `normalized-machine-id.bin`, `host-id.txt`,
`state.canonical`, `state.sha256`, `method.canonical`, `manifest-core.canonical`, `manifest-hash.txt`,
`manifest.json`, `record-core.canonical`, `record-hash.txt`, `record.json` — against the committed bytes.
It diverges in both directions: an artifact produced that the corpus lacks counts, and so does one the
corpus has that was not produced.

The full campaign was then run a second time under `ISEDRAF_EXPERIMENTAL_FLOOR=3.6`. Every record produced
that way carries `experimental_floor_override`, so no such result can later be mistaken for a run at the
declared floor.

## Results — 2026-09-18

| Platform | Interpreter | Source | Install required | Golden cases | Divergences | Campaign |
|---|---|---|---|---|---|---|
| AlmaLinux 8.10 | **3.6.8** | `/usr/libexec/platform-python` | **none** | 13 | **0** | **PASS** |
| openSUSE Leap 15.6 | **3.6.15** | `/usr/bin/python3` (stock) | **none** | 13 | **0** | **PASS** |
| openSUSE Leap 15.6 | 3.6.15 | `/usr/bin/python3.6` | none | 13 | 0 | — |
| Debian 12 | 3.11.2 | stock | none | 13 | 0 | PASS |
| Fedora 44 | 3.14.7 | stock | none | 13 | 0 | PASS |
| *(CI)* | 3.9.25 · 3.12.14 · 3.12.3 | setup-python / runner | — | corpus digest `5f2ac4d7a9ddeec1…` | 0 | PASS |

Campaign under the 3.6 floor, both hosts: **10 runs · 10 chained ledger records · 1 state object · one
exit code `[0]` · independent verifier PASS with zero problems · 7/7 frozen negative cases**.

### The EL8 finding that changes the deployment picture

The AlmaLinux 8 cloud image has **nothing on `PATH` as `python3`** — the probe reported
`NO_SUITABLE_INTERPRETER` and the ordinary campaign reported `NO_PYTHON3_ON_PATH`.

It nevertheless has a working vendor Python 3.6.8 at **`/usr/libexec/platform-python`**, because `dnf`
itself is written in Python and cannot function without one. **An EL8 host therefore always has a suitable
interpreter**, whether or not anything is installed — and ISEDRAF ran on it with zero installation and
produced byte-identical evidence.

This is why `python3` on `PATH` is the wrong thing to look for.

## What this does and does not establish

**Established.** On vendor Python 3.6, the production implementation produces exactly the certified bytes,
commits real snapshots and a chained ledger, and satisfies the independent verifier — on two different
distribution families, with no installation on either.

**Not established.** Reboot stability under 3.6 was **not** exercised: no VM in this campaign was rebooted
and re-measured. Version-upgrade stability was not exercised either. Neither is implied by the results
above.

**Not claimed.** These results say nothing about a self-built or upstream Python 3.6 on an unsupported
platform. Upstream CPython 3.6 has been end-of-life since 2021-12-23; what was measured here is
**vendor-maintained** runtime that is part of a supported operating system.

## The distinction any amendment must preserve

`3.6` would be a **language and API compatibility level**, never a version to install or prefer.

```text
find the vendor/system python3 the host already has
        ↓
is it >= the compatibility floor?
        ├── yes → use it, whatever version it is
        └── no  → report the missing prerequisite; install nothing
```

On Debian 13 that means using its 3.13.5. On Ubuntu 26.04, its 3.14.4. On EL8, its vendor 3.6.8. ISEDRAF
never downgrades, never pins, never bundles an interpreter and never installs one.

## If the floor is lowered

Two obligations follow, and they should be written down before, not after:

1. **A permanent compatibility gate.** `lib/isedraf/` must be held to 3.6 by CI, or in six months someone
   writes `subprocess.run(..., capture_output=True)` — 3.7+ — and EL8 breaks silently. The probe and the
   floor experiment are already written to 3.6; the production package would join them.
2. **A split, stated explicitly.** `lib/isedraf/` at the production floor; `scripts/`, `tests/` and
   development tooling remain free to use a newer Python, because they never run on a target host.

## Reboot proof — 2026-09-18

The one part of the owner's list that the byte comparison did not cover. Two disposable lab VMs, each
running the **production CLI entry point**, with the evidence store in the guest's home directory rather
than `/tmp` so that it genuinely survives the reboot.

| | openSUSE Leap 15.6 | AlmaLinux 8.10 |
|---|---|---|
| Interpreter | `/usr/bin/python3` **3.6.15** | `/usr/libexec/platform-python` **3.6.8** |
| Uptime after reboot | 23 s | 26 s |
| Snapshots | 1 → 2 | 1 → 2 |
| `host_id` across reboot | **identical** | **identical** |
| `state.canonical` bytes | **identical** | **identical** |
| `state_hash` | **identical** | **identical** |
| Snapshot ids | distinct, as they must be | distinct |
| Ledger | 2 records, chain valid | 2 records, chain valid |
| Independent verifier | **PASS**, zero problems | **PASS**, zero problems |
| Verdict | **PASS** | **PASS** |

A reboot is exactly the event that separates identity from session state. The host identity survived it
unchanged while the run and snapshot identifiers correctly did not — which is the distinction between
canonical state and provenance working as designed, observed rather than asserted.

## The decision this evidence supports

**`EXEC-016`** is the normative statement and **`D-12`** the decision; the production floor is a
**Python 3.6 language and API level** for code that runs on a target host, while development, test and
certification tooling stays unconstrained. The amendment that carried the change is recorded in
`AMENDMENTS.md` as history — implementation reads the requirement, never the amendment (`D-106`).

**One frozen artifact changed**, `EVIDENCE_AND_TRUST_MODEL.md`, and `W1A_CORE.sha256` was regenerated over
the same eight paths. The corpus digest `5f2ac4d7a9ddeec1…` is unchanged: **no canonical evidence byte
moved**, which is what a specification clarification should look like.

`make check-python-floor` now holds `lib/isedraf/` and `scripts/compat/` to the floor permanently. Syntax
is decided by the grammar itself — `ast.parse(feature_version=(3, 6))` — and the library surface the
grammar cannot see is a named list with the version that introduced each item. Two injections prove it
fires: one API newer than the floor, one syntax newer than the floor, because they fail differently.
