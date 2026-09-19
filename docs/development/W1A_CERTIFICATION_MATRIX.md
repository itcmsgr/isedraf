<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# W1-A Certification Matrix


Implements: GOV-001, GOV-002, NORM-039, D-107

## What is being certified, and what is not

W1-A is a **specification freeze plus the golden corpus that pins its durable evidence contract**
(`W1A_CORE_FREEZE_SCOPE.md`). It is not an implementation. The release condition in that document reads:

```text
W1-A BLOCKING = 0  →  generate docs/architecture/freeze/W1A_CORE.sha256  →  implement W1-A
```

So this matrix answers exactly one question: **does every W1-A claim that can be evidenced before the code
exists actually have that evidence?** Requirements about runtime behaviour — root refusal, `fsync`, atomic
rename, exit codes, on-disk layout — are frozen and **have no executable evidence and cannot have any
yet**. They are marked `AWAITS_IMPLEMENTATION`, which is a statement of fact, not a gap being excused.

Status vocabulary, used exactly:

| Status | Meaning |
|---|---|
| `CERTIFIED` | positive evidence **and** a falsification that fails without it |
| `COVERED` | positive evidence only — a conforming implementation is exercised; no mutation distinguishes it |
| `NOT_APPLICABLE_TO_W1A` | the requirement is valid and W1-A has no surface that exercises it |
| `AWAITS_IMPLEMENTATION` | only running code can evidence it; nothing here claims otherwise |
| `SPECIFICATION_GAP` | an open finding says the frozen text does not decide something the bytes depend on |

Runtime coverage column: `3.9/3.12/3.14` means the evidence was produced under CPython 3.9.25 and 3.12.14
in CI and 3.12.3 + 3.14.7 locally, producing **one** corpus digest.

**The authoritative corpus digest is `5f2ac4d7a9ddeec172e6f22dac1d604565fd6ff750d31f4da6fd44fad4d3fc31`** — the SHA-256 of
`test-vectors/w1a/v1/EXPECTED.sha256`, which is the artifact pinned by
`freeze/W1A_CORE.sha256`. `make check-docs-truth` compares every digest quoted here against
that file, so this line cannot go stale again without a gate failing.

> **Historical, superseded — not authoritative.** An earlier revision of this document quoted
> `f3e0f21bef6afd68…` as the corpus digest — **historical, superseded**. It was correct for the pre-expansion
> corpus of 14 cases, before `D1-domain-separation` and `13-non-utf8` were added (commit
> `fd6b05a`). It is recorded here as history because the measurement was real; it describes a
> corpus that no longer exists, and it must never be read as describing the certified one.
> Two unlabelled digests in one certification document are two equally authoritative-looking
> claims, and exactly one of them can be true.

## Canonical serialization and hashing

| Requirement | Normative claim | Positive evidence | Falsification | Runtime | Applicability | Status |
|---|---|---|---|---|---|---|
| `NORM-034` | null ≠ absent; each field declares which | `manifest_core` carries `"reason":null` in all 14 cases | sidecar corruptions (5) | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `NORM-035` escape alphabet | exactly five short escapes, `\u00xx` for C0/DEL/C1/U+2028/9, nothing else | `S1-serializer-conformance`, hand-written expected bytes | naive serializer → *"U+007F DEL appears RAW"* | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `NORM-035` key order | sorted by Unicode code point, per object | `S1` (astral + lone-surrogate-replacement keys), every `.canonical` | same injection; verifier re-parses and orders each nesting level | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `NORM-035` one trailing LF | exactly one LF, and it is hashed | every canonical artifact | `reason.txt missing its trailing LF` negative test | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `NORM-036` | non-UTF-8 → tagged base64 object at normalization | none — W1-A has no field permitting opaque bytes | verifier fails on **any** `__isedraf_encoding` in W1-A evidence | 3.9/3.12/3.14 | **none** | `NOT_APPLICABLE_TO_W1A` (`Z-13`) |
| `NORM-042` | field-specific grammar takes precedence over generic byte representation | `13-non-utf8` → `ERROR`/`SYNTAX_REJECTED` | parser preserves non-UTF-8 bytes instead → *"NORM-042 VIOLATED"* | 3.9/3.12/3.14 | W1-A | `CERTIFIED` (`Z-13`) |
| `NORM-037` | set-like fields need a total, schema-defined ordering | none — W1-A has no array-typed field anywhere | verifier **fails on any array** in W1-A evidence; injection adds one | 3.9/3.12/3.14 | **none** | `NOT_APPLICABLE_TO_W1A` (`Z-11`) |
| `NORM-038` framing | `SHA-256(ASCII(domain) ‖ uint64_be(len) ‖ bytes)` | every `host-id`, `state`, `manifest-hash`, `record-hash` reframed from first principles | `NORM-039` one-byte vector mutation | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `NORM-038` non-prefixing | domains SHALL be mutually non-prefixing; **the golden vectors assert it** | `D1-domain-separation`, derived from the requirement table | domain renamed to a prefix in spec + generator + verifier, corpus regenerated → *"NORM-038 VIOLATED"* | 3.9/3.12/3.14 | W1-A | `CERTIFIED` (`Z-10`) |
| `NORM-038` domain set | four frozen domains, exact ordered components | `D1`, three-way equality: requirement ↔ vector ↔ domains the verifier frames with | 4 negative tests on `domains.txt` | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `NORM-039` | golden vectors release-blocking on 3.9 **and** the current CI Python | both lanes regenerate and byte-compare against the same committed corpus | 2 injections: 3.9 lane removed; lane stops running the vectors | **3.9 + 3.12** | W1-A | `CERTIFIED` (`Z-12`) |
| `NORM-030`…`NORM-033` | timestamp format, section hash, locale independence | fixture-pinned `created_at`/`occurred_at`; no locale-dependent call in the corpus path | none | 3.9/3.12/3.14 | W1-A | `COVERED` |

## Host identity

| Requirement | Normative claim | Positive evidence | Falsification | Runtime | Applicability | Status |
|---|---|---|---|---|---|---|
| `IDENT-002` | state object is exactly `{"host_id":"sha256:<64 hex>"}` | 3 `COLLECTED` cases | compared to the frozen literal; corruption rejected | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `IDENT-003` accepted syntax | 32 hex chars, optional single LF, uppercase lowercased; encoding failure is `SYNTAX_REJECTED` too (`NORM-042`) | `01`, `02`, `03` metamorphic — identical hashes | `09-double-lf` must not produce state | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `IDENT-003` all-zero | the all-zero value is rejected | `10-all-zero` | guard removed → *"independent parse says ERROR"* | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `IDENT-003` `uninitialized` | systemd first-boot literal rejected | `11-uninitialized` | subsumed by the length rule; retained as explicit evidence | 3.9/3.12/3.14 | W1-A | `COVERED` |
| `IDENT-003` read bound | at most exactly 4096 bytes (`Z-21`) | `12-over-long` (5033 bytes) | guard removed → *"IDENT-004 selects 'SOURCE_UNREADABLE'"* | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `IDENT-004` rows 1–4 | total ordered decision list, first match wins | 14 cases; the verifier **walks the list** and derives status **and** reason | over-long and all-zero injections | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `IDENT-004` row 5 | catch-all `INTERNAL_ERROR` | `lib/isedraf/identity.py`; test forces an unanticipated failure in the parser | — | 3.9/3.12/3.14 | W1-A | `COVERED` (W1-B) |
| `IDENT-005` | `host_id` from **normalized** bytes via `HASH_FRAME_V1` | every `COLLECTED` case, reframed independently | one-byte vector mutation | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `IDENT-006` | `source_id` per field | `method.canonical` frozen literal | 3 `method.canonical` corruptions | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |

## Snapshot, ledger and method identity

| Requirement | Normative claim | Positive evidence | Falsification | Runtime | Applicability | Status |
|---|---|---|---|---|---|---|
| `SNAP-020` core | field table; `manifest_hash` excluded from its own preimage | 14 cases; preimage asserted free of its own hash | envelope contradicting its core | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `SNAP-023` `host_id` | string **iff** `COLLECTED` **and** `IDENT-005` derived it; otherwise `null`; key always present | 15 cases; verifier re-derives the expected shape from the input | 3 injections (null on `COLLECTED`, string on non-`COLLECTED`, key omitted) + 6 negative tests with the manifest and ledger hashes recomputed | 3.9/3.12/3.14 | W1-A | `CERTIFIED` (`Z-08`) |
| `SNAP-021` | exactly three files, each `canonical_bytes`; frozen `method` object | 14 cases | `method.canonical` corruptions | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `SNAP-022` | non-`COLLECTED` still commits; frozen reason vocabulary | 9 non-`COLLECTED` cases | token outside the vocabulary rejected | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `NORM-040`/`NORM-041` | presence encodes presence; no byte string spells "no reason" | 14 cases | 5 sidecar corruptions (`null`, `None`, empty, present-on-COLLECTED, no LF) | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `STORE-024` record | field table; `record_hash` excluded from its preimage | 14 cases | envelope contradicting its core | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `STORE-024` chaining | `sequence` strictly increments; `previous_record_hash` links | synthetic two-record ledger | broken link; wrong `sequence` | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `CMP-020` | method identity recorded per field | `method.canonical` carries all six components | corruption of each | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `SNAP-014` | temp dir → fsync → atomic rename → ledger append + fsync, under a whole-run `flock` | `lib/isedraf/snapshot.py`, `lib/isedraf/stateroot.py`; layout, permission and chaining tests | — | 3.9/3.12/3.14 | W1-A | `COVERED` (W1-B) |
| `SNAP-018` | one unledgered snapshot recovers; more is `STORE_DISCONTINUITY`, exit `2` | `lib/isedraf/ledger.py`; test plants two unledgered snapshots and asserts the refusal | — | 3.9/3.12/3.14 | W1-A | `COVERED` (W1-B) |
| `SNAP-019` | `SDS-`/`RUN-`/`EVT-` grammar, UTC, CSPRNG suffix | `lib/isedraf/ids.py`; grammar and uniqueness tests | — | 3.9/3.12/3.14 | W1-A | `COVERED` (W1-B) |
| `STORE-001`, `STORE-025` | state root `0700`, W1-A creates only `snapshots/`, `tmp/`, `ledger/`, `.lock` | `lib/isedraf/stateroot.py`; test asserts modes and that later-set directories are **absent** | — | 3.9/3.12/3.14 | W1-A | `COVERED` (W1-B) |

## Execution, exit codes and hostile input

| Requirement | Normative claim | Positive evidence | Falsification | Runtime | Applicability | Status |
|---|---|---|---|---|---|---|
| `SCOPE-070`, `SCOPE-071` | W1 is unprivileged; root execution refused, exit `70` | `lib/isedraf/stateroot.py`; tests for euid 0, `SUDO_USER`, and the override under sudo | — | 3.9/3.12/3.14 | W1-A | `COVERED` (W1-B) |
| `SCOPE-077` | exit set is `0`, `2`, `64`, `70` | `lib/isedraf/exitcodes.py`; **all four are reachable** in W1-B and asserted through the real CLI entry point | — | 3.9/3.12/3.14 | W1-A | `COVERED` (W1-B, closes `Z-09`) |
| `PRIV-004` | every artifact carries the DEV marker | 15 vector manifests **and** production output: test asserts the marker in the manifest and the ledger record | — | 3.9/3.12/3.14 | W1-A | `COVERED` (W1-B) |
| `SCOPE-045`…`SCOPE-047` | every field classified; only `STATE` is hashed | `method`/provenance sits outside the state hash in all 14 cases | none | 3.9/3.12/3.14 | W1-A | `COVERED` |
| `OUT-013`, `OUT-015`, `EVID-002`, `EVID-004` | hostile input on W1-A surfaces | `S1` carries DEL, C1, U+2028/9, astral and replacement characters | naive serializer | 3.9/3.12/3.14 | W1-A | `COVERED` |

## Governance

| Requirement | Normative claim | Positive evidence | Falsification | Runtime | Applicability | Status |
|---|---|---|---|---|---|---|
| `GOV-001` | policy text is not enforcement | 10 gates in `make check`, all wired via `check-gate-coverage` | gate declared but not aggregated → refused | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `GOV-002` | a gate never observed failing is not a gate | 29 injections, 0 non-firing | **the harness itself**: 5 self-tests (`falsifiable_selftest.sh`) | 3.9/3.12/3.14 | W1-A | `CERTIFIED` (`Z-20`) |
| `D-105`, `D-106` | every cited ID resolves; amendments are not authority | 242 IDs, 124 decisions, 55 files | 4 injections | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `D-107` | staged freeze by reviewed set | `check-freeze` reports *"candidate phase; nothing is frozen"* | manifested artifact modified → digest mismatch | 3.9/3.12/3.14 | W1-A | `CERTIFIED`, and **the W1-A set is not yet frozen** |
| `HDR-001`…`HDR-003` | one metadata grammar | every tracked `.sh`/`.py` | 3 header injections | 3.9/3.12/3.14 | W1-A | `CERTIFIED` |
| `D-83`, `D-93` | hook parity; `Assisted-by` discipline | 2 injections prove `commit-msg` rejects | — but **no hook is installed** | 3.9/3.12/3.14 | W1-A | `SPECIFICATION_GAP` (`Z-22`) |

## W1-B — the first production implementation

`lib/isedraf/` implements the frozen contract. It imports nothing from `scripts/vectors/`: the reference
generator certified the specification, and production code re-derives every byte from the requirements.

**The strongest single result of W1-B**: for all 13 machine-id vector inputs, production output equals the
certified expected bytes — `state.canonical`, `host-id`, `state.sha256`, `method.canonical`,
`manifest-core.canonical`, `manifest-hash`, `manifest.json`, `record-core.canonical`, `record-hash` and
`record.json`. A further test rebuilds the whole corpus from production output, regenerates
`EXPECTED.sha256` so no checksum can be what passes it, and runs the **unmodified** certified verifier
against it. It accepts.

## The freeze — `docs/architecture/freeze/W1A_CORE.sha256`

Created under owner authorization, as the **last semantic act** of the certification lane. The set is
**derived** from `W1A_CORE_FREEZE_SCOPE.md`, not chosen: every requirement that document lists as frozen
for W1-A was resolved to the artifact that *defines* it, and those artifacts are the manifest.

| Artifact | Why it is in the set |
|---|---|
| `SNAPSHOT_BASELINE_DELTA_MODEL.md` | defines 27 of the listed requirements |
| `V0_1_IMPLEMENTATION_SCOPE.md` | 12 |
| `ISEDRAF_HLD.md` | 7 |
| `EVIDENCE_AND_TRUST_MODEL.md` | 3 |
| `NORMATIVE_SOURCES.md` | 3 — `NRM-001`…`NRM-003` |
| `HEADER_POLICY.md` | 3 — `HDR-001`…`HDR-003`, named explicitly by the scope document as outside `docs/architecture/` |
| `W1A_CORE_FREEZE_SCOPE.md` | the definition of the set; if it moves, the set moves |
| `test-vectors/w1a/v1/EXPECTED.sha256` | pins every byte of the corpus transitively — it carries a SHA-256 for every corpus file, `verify.py` checks each, and `check.sh`'s `diff -r` catches anything extra or missing |

**Deliberately excluded: `DECISIONS_REGISTER.md`.** The scope document lists `D-105`, `D-106` and `D-107`
under governance, but the register is an append-only decision log. Freezing it would make every future,
unrelated owner decision invalidate the W1-A freeze — the opposite of what `D-107` exists to achieve. This
is a judgement call and is recorded as one rather than left implicit.

Verification after creation: `check-freeze` → *8 artifacts verified*; corpus digest unchanged at
`5f2ac4d7a9ddeec1…`, the same value both CI Python lanes reproduced before the freeze existed. **The
freeze altered no evidence digest and no canonical artifact.**

### What the freeze switched on, and what it exposed

`check-scope` consumes `check-freeze`'s verdict (`D-107`, X-01): a verified set means implementation of
that scope is permitted, so the `D-96` pre-freeze rule correctly stops applying.

It was doing more than that. The gate `exit 0`-ed on a verified freeze set, which also switched off
**`D-84`** (no network imports in tooling) and **`D-17`/`D-86`** (no committed bytecode) — permanent
posture rules with nothing pre-freeze about them. The falsifiability harness reported it within seconds of
the manifest being written, because those two injections stopped firing. Fixed: only the `D-96` block is
conditional now, and the `D-96` injection removes the freeze manifests so that it keeps testing the rule
instead of quietly ceasing to apply.

## Blank cells

There are none. Every row states its evidence or states that it has none and why.
