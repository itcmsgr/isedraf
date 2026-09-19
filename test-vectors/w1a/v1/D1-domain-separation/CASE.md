# D1 — domain separation (NORM-038)

Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0

<!-- doclint:exempt-forbidden-terms -->

## What this case exists to catch

`NORM-038` states that `HASH_FRAME_V1` domain strings **SHALL be mutually non-prefixing**, and that
*"the golden vectors assert it"*. Before this case, no golden vector did — the property was written
down and nothing could have observed it failing (`Z-10`).

## Why non-prefixing is load-bearing

The frame is `SHA-256( ASCII(domain) || uint64_be(len(c₁)) || c₁ … )`. The domain is **not**
length-prefixed. If one domain were a prefix of another, the boundary between the domain and the
first length prefix would not be recoverable from the preimage: two different (domain, components)
tuples could produce the same byte string, and therefore the same hash. Domain separation is the
only thing keeping a state hash from being replayable as a manifest hash.

## The artifact

`expected/domains.txt` — the complete W1-A domain set, one ASCII domain per line, sorted, one
trailing LF. It is generated **from the frozen requirement table**, not from the generator's own
string literals: a vector built out of the code it certifies asserts only that the code equals
itself.

## What is asserted

| # | Assertion | Trust class |
|---|---|---|
| 1 | the file equals `NORM-038`'s frozen table, re-parsed independently by the verifier | `SPECIFICATION_CONSTANT` |
| 2 | the domains the **verifier frames with** are exactly that set | `CROSS_CHECKED` |
| 3 | for every ordered pair `(A, B)`, `A ≠ B` ⇒ `B` does not start with `A` | `STRUCTURALLY_VALIDATED` |
| 4 | every domain is ASCII, as `HASH_FRAME_V1` requires | `STRUCTURALLY_VALIDATED` |

Assertion 2 is what stops the proof being about a list nothing reads. The **generator's** domains
are bound separately and more strongly: every `host-id`, `state`, `manifest-hash` and `record-hash`
in the corpus is reframed from first principles by the verifier, so a generator using a different
domain fails on the hash, not on this file.

## Falsification

`scripts/ci/falsifiable.sh` injection *"NORM-038 domain made a prefix of another (Z-10)"* renames
`ISEDRAF:STATE:V1` to `ISEDRAF:HOST-ID` in the **requirement, the generator and the verifier at
once**, then regenerates the whole corpus before running the gate. Every digest, every sidecar and
all three domain sets are therefore mutually consistent: the byte-compare passes, and the only thing
left that can fail is the property itself. The gate must reject with the offending pair named.
