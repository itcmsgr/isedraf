<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# R1.5-P — Privilege and Evidence Acquisition Contract

Status: EXPERIMENTAL
Implements: SCOPE-022, SCOPE-045, GOV-001, GOV-002

**AWAITING OWNER FREEZE APPROVAL. The vertical slice below IS implemented** — owner ruling
5 required a working end-to-end contract before freeze, on the ground that a beautiful
abstract contract can hide a defect until a real producer and a real consumer have to
carry the semantics. It did: two defects are recorded in section 11, both found by
falsification rather than by review.

What is implemented: `lib/isedraf/coverage.py`, the retrofit of six acquisition paths, the
manifest in the snapshot bundle, and the report rendering. What is NOT implemented and is
not proposed for implementation: the privileged helper. No frozen
domain semantics are changed by writing it, no privileged helper exists, and every
capability described below is `CONTRACTED` or `PLANNED` until the owner freezes it and the
implementation lands.

It is built from boundary cases the repository already produced, not designed in the
abstract. Every measurement below was taken from this checkout.

## 1. The gap, measured

`lib/isedraf/hostio.py` already distinguishes the three outcomes that matter:

    NOT_FOUND · PERMISSION_DENIED · IO_ERROR · READ_OK

Two of five acquiring domains consume that distinction (`accounts`, `loginpolicy`); `pam`
and `include_graph` consume only `NOT_FOUND`; `authorizedkeys` stores the detail without
classifying it. **No domain records privilege as a field**, and no report aggregates one.

The sharpest measurement. With `/etc/shadow` present and mode `0`, the account lane
produces exactly this:

    "etc/shadow": {
      "status": "NOT_TESTED",
      "reason": "SOURCE_UNREADABLE: etc/shadow could not be read: permission denied.
                 Password and ageing evidence requires privilege; nothing about it
                 was observed."
    }

The cause is correct, it is honest, and it exists **only as English prose**. The machine
answer — `detail = PERMISSION_DENIED` — is computed in `acquire()` and then dropped on the
way out, at `lib/isedraf/accounts/acquire.py:253`, which serialises `status` and `reason`
and nothing else.

So a consumer that wants to know *why* coverage is incomplete must parse a sentence. That
is the whole of R1.5-P: the distinction is already made and then thrown away.

## 2. Invariants

Seven, and the last five are already frozen elsewhere in the repository. R1.5-P collects
them into one place because they are the same idea at different layers.

    WHAT EXISTS ON THE HOST
        !=  WHAT THIS COLLECTION COULD OBSERVE
        !=  WHAT ADDITIONAL AUTHORITY COULD MAKE OBSERVABLE

    NOT PRESENT  !=  PRESENT BUT NOT OBSERVABLE  !=  PRESENT BUT PARTIALLY OBSERVED

    OBSERVATION CAPABILITY  !=  HOST STATE

    COLLECTION VISIBILITY DELTA  !=  HOST STATE DELTA

    HOST PATH  !=  COLLECTION-ROOT PATH
        normalise in HOST space first, then map EXACTLY ONCE

    lexical containment  !=  resolved-target containment  !=  race-free acquisition

    root  !=  completeness

### root does not mean complete

A privileged run may still lack evidence: an unsupported source, an unsupported parser, a
missing tool, an absent kernel feature, a namespace boundary, a malformed source, external
metadata that is unavailable, a collection error, or a universe the operator explicitly
excluded. None of those is a privilege problem and none is fixed by elevation.

Completeness is therefore always **completeness over the explicit requested evidence
universe**, never over "Linux security". A report may not describe itself as full or
complete because the process happened to run as root.

## 3. Acquisition-access vocabulary — PROVISIONAL

The names below are proposed, not frozen. They describe **what the evidence needs**, not
what mechanism an administrator should use to provide it.

| Class | Meaning |
|---|---|
| `ACCESS_NONE` | any account on the host can obtain it |
| `ACCESS_FILE_READ` | read of a file the collection identity may not read |
| `ACCESS_DIRECTORY_TRAVERSE` | traversal of a directory the identity may not enter |
| `ACCESS_COMMAND_QUERY` | a query command the identity may not run usefully |
| `ACCESS_KERNEL_INTERFACE` | a kernel interface restricted to privileged callers |
| `ACCESS_SERVICE_QUERY` | a service or subsystem that refuses unprivileged queries |
| `ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED` | additional authority is known to be necessary and the narrower requirement has not been established |

The abstraction is deliberately **not** a Linux `CAP_*` mapping. Access may be granted by
a file ACL, group membership, a sudo policy, a capability, a privileged helper, or root,
and which of those an operator should use is a decision about their host, not a fact about
the evidence. ISEDRAF should not guess it.

`ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED` exists so that "we know privilege is needed and we
have not established the minimum" is sayable. Collapsing it into `ACCESS_FILE_READ` would
be a precision the evidence has not earned.

### These are PROVENANCE, never STATE

Privilege information is collection context (`SCOPE-045` `PROVENANCE`). It is never hashed,
never diffed as host state, and never a finding. Specifically it must never be documented
or rendered as:

    permission denied      =>  the host is insecure
    uid 0                  =>  secure, or insecure
    root execution         =>  the collection is complete

## 4. Per-source evidence-access record — CONTRACTED

Every acquiring source should be able to answer, in fields rather than in prose:

    source                  what was addressed
    status                  SCOPE-022, unchanged
    reason                  unchanged, still human-readable
    detail                  NOT_FOUND | PERMISSION_DENIED | IO_ERROR | READ_OK
    privilege_limited       true only when the collection identity was the obstacle
    required_access         one class from section 3
    acquisition_mode        see section 7
    affects_completeness    whether the gap constrains what may be claimed
    prohibits_absence_claim whether an absence claim over this source is forbidden

The last field is the one that connects R1.5-P to work already frozen. The account
contract's §11a rule — *an existing but unreadable source cannot support an absence claim,
and neither can a partially observed one* — becomes a field a later criterion can read,
instead of a rule each criterion must remember.

## 5. Evidence Limits Manifest — CONTRACTED / PLANNED

A machine-readable section carried by every report, consumed by renderers rather than
written by them. Indicative shape; the schema is settled at freeze, not here:

    {
      "acquisition_mode": "UNPRIVILEGED",
      "requested_sources": <n>,
      "complete_sources": <n>,
      "partial_sources": <n>,
      "privilege_limited_sources": <n>,
      "other_unavailable_sources": <n>,
      "limitations": [
        {
          "domain": "accounts",
          "source": "etc/shadow",
          "status": "NOT_TESTED",
          "detail": "PERMISSION_DENIED",
          "privilege_limited": true,
          "required_access": "ACCESS_FILE_READ",
          "affects_completeness": true,
          "prohibits_absence_claim": true
        }
      ]
    }

It must be canonical structured evidence. A limitation that exists only as Markdown prose
cannot be consumed by a later criterion, an export, or a comparison — which is precisely
the defect section 1 measures.

Counts are over the **explicit requested evidence universe**. A percentage may be shown
only if its denominator is that universe and the denominator is stated beside it. A figure
such as "82% of host security checked" has no defensible denominator and must not appear.

## 6. Report semantics — CONTRACTED

The report should separate host facts from the boundary of what the run could prove, and
should answer:

    what was tested?           what was observed?      what was NOT observed?
    why?                       was privilege the cause?
    would additional authority increase coverage?
    does the gap prohibit an absence claim?

Two sections, side by side, never merged:

    HOST TRUTH          what was observed
    EVIDENCE BOUNDARY   what this run was capable of proving

The operator-facing model is **guided escalation, not blanket elevation**:

    ordinary unprivileged collection
        -> report what was observed
        -> report exactly what could not be observed
        -> explain why
        -> identify the minimum class of additional access required

"Run ISEDRAF as root for full results" is the sentence this contract exists to make
unnecessary, and it is also false, for the reasons in section 2.

## 7. Observation-capability identity — CONTRACTED

A report or snapshot records enough collection-context identity that a later comparison
can distinguish:

    the host changed        from        the collector's visibility changed

The case is concrete. Run A is unprivileged and cannot read `/etc/shadow`; run B is
granted a narrowly scoped read and can. The shadow facts in run B are **newly visible**,
not newly created, and reporting them as host-state additions would be the observation
capability masquerading as drift — the same failure class as a method change masquerading
as drift, which the prototype acceptance criteria already forbid.

    EVIDENCE-COVERAGE DELTA        computed and reported first
    HOST STATE DELTA               computed only where coverage is comparable

Where coverage differs between two runs, the affected domain is `NOT_COMPARABLE` with a
reason, never `ADDED` or `REMOVED`. R3 depends on this; R1.5-P records the identity that
makes it possible.

## 8. Future privileged helper — FUTURE, not implemented

Recorded as a boundary so that later work has one to hold to. No helper exists, none is
designed in detail, and nothing in R1.5-P requires one.

    unprivileged ISEDRAF
        -> narrowly scoped privileged evidence helper
        -> fixed allowlisted operations
        -> bounded structured evidence
        -> unprivileged normalisation and reporting

Constraints such a helper would have to meet: minimal privileged surface · fixed
operations · no arbitrary shell · no caller-selected paths · no criteria or framework
logic · no report logic · no security verdict logic · bounded structured responses ·
explicit provenance recording that the operation ran and under what authority.

A future two-pass workflow — collect unprivileged, present the gap, let the operator
approve selected additional acquisition — follows from that boundary. It is a direction,
not a commitment, and no CLI for it is designed.

## 9. What R1.5-P does not do

No privileged helper. No elevation. No change to any frozen domain's collection semantics.
No new host commands. No network. No security verdicts. No CAP_* mapping. No claim that a
privileged run is complete.

## 10. What the implementation actually is

    lib/isedraf/coverage.py          the single authority; pure, core layer
    accounts · loginpolicy · pam · ssh · sudo · authorizedkeys
                                     six acquisition paths retrofitted, additively
    lib/isedraf/shared/include_graph.py
                                     the graph node now carries its access outcome
    lib/isedraf/snapshot.py          coverage/evidence_limits.json in the bundle
    lib/isedraf/report/model.py      limitations rendered from FIELDS, never from prose
    tests/test_coverage.py           36 tests, including all eight required proofs
    scripts/ci/falsifiable.sh        9 injections, all firing

**Snapshot placement, stated rather than hidden.** The manifest is written to
`coverage/evidence_limits.json` beside `method/` and `state/`, not into `manifest_core`.
SNAP-020 freezes that field table and the golden vectors bind its hash; adding a key would
change every committed manifest hash in order to record something that is not host state.
The consequence is that in R1.5-P the coverage file is **not** covered by `manifest_hash`.
It carries its own `coverage_digest`, which is what a later comparison needs. Binding it
into the manifest requires a SNAP amendment and is question 3 below.

**Backward compatibility.** Strip the R1.5-P additions and every domain's evidence is what
it was. `accounts` keeps `sources` in its exact previous shape - `status` and `reason`,
nothing added - because the machine answer belongs in `coverage`, in one place. A test
asserts this rather than a comment claiming it.

## 11. Two defects the implementation found

Recorded because they are the argument for owner ruling 5.

**A provenance builder that could crash the collector.** The login-policy retrofit raised
`ValueError` when an outcome could not be classified, so a describable gap became no
evidence at all - the opposite of what this contract is for. Found by an existing
injection changing its failure mode, not by review. Coverage builders now record an
unclassifiable outcome rather than raising.

**A digest that could ignore the access outcome.** The visibility test changed status and
outcome together, so status alone separated the two runs and a digest that dropped the
outcome still passed. The injection that deleted it went undetected. A source that is
ABSENT and one that is REFUSED must produce different observation-capability identities
while sharing a status, and that is now its own test.

## 13. Freeze blockers

**One remains: the Evidence Limits Manifest is not integrity-bound to its snapshot.**
The analysis ruling A required is in `SNAP_COVERAGE_BINDING_PROPOSAL.md`, with the exact
amendment text. It stops for owner action because every anchor in the bundle is reached
through `manifest_core`, `SNAP-020` freezes that table, and `AMENDMENTS.md` is
owner-controlled. Measured blast radius: 90 golden-vector files regenerate.

The same analysis found that `method/host_identity.json` is bound by nothing either — a
pre-existing instance of the same gap, which is why the proposed amendment binds auxiliary
artifacts generally rather than adding a field for coverage alone.

## 12. Questions for the owner

All four earlier questions are answered by owner ruling and implemented:

| Ruling | Effect |
|---|---|
| A — binding required | analysis written; amendment prepared; **blocked on owner action** |
| B — retrofit inventory now | done; nine subdomains carry coverage; a nonzero exit never becomes a privilege limitation |
| C — `NOT_SUPPORTED` out of `hostio` | confirmed; `hostio` keeps only outcomes a file operation can establish |
| D — remove `MODE_ELEVATED` | removed; `MODE_CURRENT_IDENTITY` is the only producible mode |

The three axes are frozen as three fields and asserted as three:

    access_outcome     PERMISSION_DENIED     what happened
    required_access    ACCESS_FILE_READ      what would obtain the evidence
    acquisition_mode   CURRENT_IDENTITY      how it was attempted

One outcome can carry different requirements; one requirement can follow from different
outcomes; and completeness is computed from outcomes alone, with the mode not an input to
any count — so no mode, present or future, can make an incomplete collection report as
complete.
