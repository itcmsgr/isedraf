<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# W1-A vector transition record — D-115

*(Kept outside `test-vectors/`: the corpus must contain exactly what the
generator produces, and `check-vectors` correctly refused an extra file there.)*

Status: IMPLEMENTED
Implements: NORM-039, SCOPE-045

The certified bytes in this directory changed on 2026-09-21. This file records why, so the
change reads as **integrity-contract evolution** rather than as host-evidence semantic
drift, which is what an unexplained hash change in a certification corpus otherwise looks
like.

## What changed

Decision **D-115**, incorporating amendment `D-115`, adds `auxiliary_artifacts` to `manifest_core`: a map from
bundle-relative path to a digest of that artifact's bytes, under the canonical domain
`ISEDRAF:AUXILIARY-ARTIFACT:V1`. It binds `method/host_identity.json` — previously present
in every bundle and bound by nothing — and, where one is produced,
`coverage/evidence_limits.json`.

## Measured blast radius

79 of 158 files, across the 13 cases that build a manifest:

| File | Cases | Why |
|---|---|---|
| `manifest-core.canonical` | 13 | the new field |
| `manifest-hash.txt` | 13 | hash of the above |
| `manifest.json` | 13 | envelope carries both |
| `record-core.canonical` | 13 | `record_core` embeds `manifest_hash` |
| `record-hash.txt` | 13 | hash of the above |
| `record.json` | 13 | envelope carries both |
| `EXPECTED.sha256` | 1 | corpus digest |

## What did NOT change, and why it matters

    state.canonical · state.sha256 · host-id.txt · normalized-machine-id.bin
    method.canonical · status.txt · reason.txt · domains.txt · canonical.bytes

**Host-state identity is untouched.** That is the architectural separation D-115 requires,
demonstrated by measurement rather than asserted: binding an auxiliary artifact for bundle
integrity moves `manifest_hash` and leaves `state_hash` exactly as it was. A coverage
delta is not a host-state delta, and this directory is the evidence.

## How they were regenerated

Through `scripts/vectors/generate.py`, twice, with the output required to be byte-identical
between runs. No expected hash was written by hand.

`generate.py` is a **second implementation** of the contract and imports nothing from
`lib/isedraf`. That is why it was useful here: it did not move when production did, so the
contract change surfaced as 14 failing golden-compatibility assertions instead of as two
copies of the same edit agreeing with each other.

## First attempt, and why it was wrong

`auxiliary_artifacts` was first written as an array of `{path, digest}` objects.
`NORM-039`'s structural verifier refused it under `NORM-037`: an array-typed field in W1-A
needs a schema-defined total ordering with a golden fixture, because an unordered array is
a set whose serialization nobody has pinned. A map has no such question — `canonical_bytes`
sorts object keys — and it follows the precedent of `sections`, which is a map keyed by
section name for the same reason.

The historical pre-amendment bytes are in git history at `78cb1247` and earlier. They are
the certified corpus of the pre-D-115 contract and remain valid evidence of it.
