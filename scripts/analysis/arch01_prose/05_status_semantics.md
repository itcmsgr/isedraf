# Status and completeness reconciliation

Status: IMPLEMENTED

## The question

Five result-bearing types exist. Are they layer-specific representations of one truth, or
competing status universes?

## The matrix

| Type | Purpose | Statuses | Reason rule | Completeness | Serialized | Baseline-relevant |
|---|---|---|---|---|---|---|
| `isedraf.status` | **the single vocabulary** | `COLLECTED` `PARTIAL` `NOT_TESTED` `ERROR` | `requires_reason()` defined here | — | no | no |
| `hostio.Outcome` | one read or one command | `ok` + `reason` + `detail` | SCOPE-022 reason strings | per read | no | no |
| `inventory.model.subdomain()` | one inventory subdomain | re-exports `isedraf.status` | calls `requires_reason()` | per subdomain | yes | `SNAP-021`: outside the snapshot |
| `accounts.acquire` result | three sources + their join | re-exports `isedraf.status` | per-source, then aggregate | per source, then combined | yes | yes |
| `shared.result.Evidence` | every shared primitive | re-exports `isedraf.status` | calls `requires_reason()` | `.complete` property | yes | depends on consumer |
| `shared.compare` coverage | a comparison, not a collection | `COMPLETE` `PARTIAL` `NOT_COMPARABLE` `NOT_APPLICABLE` | mapped onto `isedraf.status` | directional, per side | yes | yes |

## Verdict: layer-specific representations, one truth

`COLLECTED`, `PARTIAL`, `NOT_TESTED` and `ERROR` are now defined **once**, in
`isedraf.status`, and re-exported everywhere. The architecture gate fails if a second
definition appears.

`hostio.Outcome.detail` refines rather than competes: `reason` keeps the frozen SCOPE-022
strings unchanged while `detail` distinguishes `PERMISSION_DENIED` from `IO_ERROR`, which
is what lets a caller apply the frozen decision table (privilege denial is `NOT_TESTED`, a
failed read is `ERROR`).

`shared.compare` coverage is deliberately a **different** vocabulary, because it answers a
different question. `COLLECTED` describes whether evidence was gathered; `COMPLETE`
describes whether a comparison could be carried out over two sides. Reusing one word for
both would have been the semantic collision this review exists to catch. It maps onto the
collection statuses explicitly rather than by coincidence.

## The completeness rule, stated once

> An absence claim requires complete evidence over the source domain in which the absence
> is asserted — and the requirement is **directional**.

Enforced in three places today, all consistent: the account passwd↔shadow join, the S2
include graph, and the S3 comparator. In S2 and S5 the *engine records the event* and the
*adapter decides whether it affects completeness*; in S3 the rule is applied per direction
so a partial side blocks claims against itself without erasing positive matches.
