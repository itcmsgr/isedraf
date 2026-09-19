<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# W1-A Corpus Coverage Matrix



A requirement is **certified** only when a case distinguishes a conforming implementation from the
specific non-conforming class the review identified. `15/15 passing` is not certification.

| Requirement | Case(s) | Pos/Neg | Mutation that falsifies it | Enforcement point | Status |
|---|---|---|---|---|---|
| `NORM-035` escape alphabet | `S1-serializer-conformance` | positive | canonical serializer → naive `ensure_ascii=False` | `verify.py` S1 block: escapes present, raw bytes absent | **CERTIFIED** |
| `NORM-035` key ordering | `S1-serializer-conformance` | positive | same | per-object code-point order check | **CERTIFIED** |
| `IDENT-003` all-zero identity | `10-all-zero` | negative | remove the `0*32` guard | parser → `ERROR`/`SYNTAX_REJECTED` | **CERTIFIED** |
| `IDENT-003` `uninitialized` | `11-uninitialized` | negative | — (subsumed by length rule; case retained as explicit evidence) | parser | covered |
| `IDENT-004` row 2 over-long read | `12-over-long` | negative | remove the 4 KiB guard | parser → `ERROR`/`SOURCE_UNREADABLE` | **CERTIFIED** |
| `IDENT-003` syntax rejection | `05`, `06`, `07`, `08`, `09` | negative | — | parser → `SYNTAX_REJECTED` | covered |
| `IDENT-004` row 1 absent source | `04-missing-source` | negative | — | parser → `NOT_TESTED`/`SOURCE_ABSENT` | covered |
| `IDENT-003` LF normalization | `01`, `02`, `03` metamorphic | positive | — | identical `host_id`/`state_hash` across all three | covered |
| `NORM-040`/`NORM-041` reason sidecar | all 15 | both | 5 sidecar corruptions | `verify.py` presence + vocabulary | **CERTIFIED** |
| `SNAP-021` method literal | all 15 | positive | 3 `method.canonical` corruptions | compared to the frozen literal | **CERTIFIED** |
| `STORE-024` chaining | two-record synthetic | negative | broken `previous_record_hash`, wrong `sequence` | `verify.py` chain walk | **CERTIFIED** |
| `SNAP-020`/`STORE-024` hash self-exclusion | all 15 | positive | — | preimage asserted free of its own hash | covered |
| `NORM-038` non-prefixing | `D1-domain-separation` | positive | rename a domain to a prefix of another, in the requirement, the generator and the verifier at once, then regenerate | requirement ↔ vector ↔ domains the verifier frames with, then every ordered pair | **CERTIFIED** (`Z-10`) |
| `NORM-037` totality | — | — | add an array to W1-A evidence | verifier fails on **any** array in the corpus | `NOT_APPLICABLE_TO_W1A` (`Z-11`) |
| `NORM-039` cross-version | whole corpus | positive | remove the 3.9 lane; or stop the lane running the vectors | CI matrix 3.9 + 3.12, one corpus digest | **CERTIFIED** (`Z-12`) |
| `SNAP-023` `host_id` | all 15 | both | null on `COLLECTED`; string on non-`COLLECTED`; key omitted | verifier re-derives the expected shape from the **input** | **CERTIFIED** (`Z-08`) |
| `NORM-042` precedence | `13-non-utf8` | negative | parser preserves non-UTF-8 bytes instead of rejecting | `ERROR`/`SYNTAX_REJECTED`; no `__isedraf_encoding` anywhere | **CERTIFIED** (`Z-13`) |

Every requirement that W1-A can evidence before the code exists now has that evidence. The requirements
only running code can evidence — root refusal, `fsync`, atomic rename, exit codes — are listed as
`AWAITS_IMPLEMENTATION` in [W1A_CERTIFICATION_MATRIX.md](W1A_CERTIFICATION_MATRIX.md).

## Independence of the `S1` expected bytes

`expected/canonical.bytes` is **hand-written and reviewable** (`CASE.md` shows the divergence table). It is
**not** produced by the serializer under test, by the generator, by `EXPECTED.sha256`, or by a wrapper
around the same serializer. `verify.py` additionally re-derives the rule structurally — asserting the four
required escapes are present and their raw forms absent — so the check does not depend on the literal
alone either.
