<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# DOC-R15P — documentation reconciliation record

Status: IMPLEMENTED
Implements: GOV-001, SCOPE-045

What the repository's documentation said, what the frozen architecture actually does, and
where the two had drifted apart. Performed after R1.5-P froze at `f256c9ce`, against the
frozen state rather than against memory of it.

## 1. The authority split, corrected

| Document | Was | Is |
|---|---|---|
| `docs/roadmap/ROADMAP.md` | contained no mention of R1.5 at all | **canonical milestone and execution sequence** |
| `docs/development/INVENTORY_COVERAGE_MATRIX.md` | the only place the real order existed | domain coverage detail, citing roadmap milestones |

The canonical roadmap and the order the work actually followed were two documents that did
not reference each other. Anyone reading the roadmap would have concluded R1.5 did not
exist; anyone reading the matrix would have had no way to know it was not authority.

## 2. Frozen invariants, now stated in one place each

    NOT PRESENT != PRESENT BUT NOT OBSERVABLE != PARTIALLY OBSERVED
    HOST STATE != OBSERVATION CAPABILITY
    COLLECTION VISIBILITY DELTA != HOST STATE DELTA
    ACCESS OUTCOME != ACCESS REQUIREMENT != ACQUISITION MODE
    root != completeness
    HOST PATH != COLLECTION-ROOT PATH
    lexical containment != resolved-target containment != race-free acquisition

Each has a home: the absence invariant in `W1D_ACCOUNT_SOURCE_CONTRACT.md` §11a, the path
invariants in `ROOTED_PATH_CONTRACT.md`, the acquisition axes and `root != completeness` in
`R15P_PRIVILEGE_AND_EVIDENCE_CONTRACT.md`, and the identity separation in the product HLD.

`absence_claim_allowed` is derived centrally in `lib/isedraf/coverage.py` and is authored by
no domain. Verified rather than asserted: one definition exists, and each of `accounts`,
`ssh`, `sudo`, `pam`, `loginpolicy`, `authorizedkeys`, `inventory` and `shared` contains
**zero** references to it. `report/model.py` reads it, which is the intended direction.
`privilege_limited` is likewise a consequence of structured acquisition facts.

`os.path.realpath()` is **called in exactly two places**, both inside the containment check
in `authorizedkeys/acquire.py`. Every other mention in `lib/` is a comment explaining why it
is not used — in `hostpath.py`, `include_graph.py`, `inventory/collectors.py` and
`ssh/acquire.py`. It is a resolved-target check, never identity.

## 3. Domain semantics confirmed against the code

| Topic | Documented state |
|---|---|
| `IQ-012` | `OWNER_RESOLVED`. R1.5 emits no `CONFUSABLE` and no skeleton; `NON_ASCII_IDENTIFIER` is an OBSERVATION implying nothing |
| `IQ-014` | `OWNER_RESOLVED`. Four axes — scope, resolution, applicability, observation — plus two universes; a Match candidate is read and never becomes effective |
| SSH `Include`/`Match` | included content inherits the containing Match applicability; a child's scope changes do not travel back. No document claims an included file begins GLOBAL |
| `hostpath` / TOCTOU | `realpath` is a resolved-target check and never identity; race-free acquisition is explicitly NOT claimed |
| S1 boundary | four domains declined it for four different reasons; recorded as a real boundary, not as debt |
| S2 | engine records traversal, domain decides meaning; `seen` != `visiting`, so a diamond is not a cycle |
| S3 | declared-vs-active at one observation period, distinct from the temporal delta axis. Still unused, deliberately; Batch 3 mounts is its first natural consumer |

## 4. Governance status, stated exactly

**`IQ-013`**: the owner ruling exists; `AMENDMENTS.md` does **not** yet formally record it.

    Batch 3   not blocked by IQ-013
    Batch 4   not blocked by IQ-013
    Batch 5-7 governance-dependent until the amendment is recorded

An owner ruling is not a completed amendment, and no document here says otherwise. The exact
amendment text is prepared in `INVENTORY_COVERAGE_MATRIX.md` §0.

**`D-115`** is implementation authority. The amendment it incorporates is recorded in
`AMENDMENTS.md`, which is where amendment history belongs — `check-refs` refuses a document
that cites an amendment as authority, and refused this one until the sentence was corrected.

## 5. Frozen-document findings

One frozen document described a repository that had moved; the second finding did not
survive inspection and is corrected below.

**`SNAPSHOT_BASELINE_DELTA_MODEL.md` — REAL, and closed under PRE-BATCH3-GOV.** Its
canonical-domain table is declared exhaustive — *"Domains frozen for W1-A, with their exact
ordered component lists"* — and did not list `ISEDRAF:AUXILIARY-ARTIFACT:V1`, which `D-115`
put into production. That is a normative contradiction, not a documentation lag.

Closed by completing `D-115`'s step 4: the frozen document now carries the domain row and
the three-identity separation, and both W1-A freeze manifests were regenerated. The
`NORM-037` statement is unaffected and stays true, because `auxiliary_artifacts` is a map —
which it is partly because that verifier refused an array.

The correction had to be made **in the frozen document and nowhere else**: the vector
generator parses that very table to build `domains.txt`, and the verifier re-parses it
independently. Editing the generator instead would have made the vector assert that the code
equals itself.

**`V0_1_IMPLEMENTATION_SCOPE.md` — CORRECTED. My finding was overstated.**

I reported that it lists `getent passwd/group/shadow` and `~/.ssh/authorized_keys` as
identity sources in contradiction of `IDENT-040` and the bridge. Re-reading it before acting
showed the document **already** names `IDENT-040` in its Pitfalls row for exactly the SSSD /
LDAP / AD enumeration problem, and **already** records that `authorized_keys` may live
outside the home directory via `AuthorizedKeysFile`. It is not instructing anyone to do the
prohibited thing; it is a v0.1 SCOPE document listing planned sources with their pitfalls
named.

What genuinely differs is planned-versus-built, which is what a scope document is for: it
declares `Dimensions | declared (files) + resolved (getent, cvtsudoers)` while the account
lane implemented the `files` dimension only (`IDENT-041`) and no resolved layer exists.

No frozen-document change is proposed for it. A finding that dissolves on inspection is
worth recording as dissolved — reporting it as a contradiction and then editing a frozen
document to match would have been the worse outcome of the two.

## 6. What was checked and found already correct

The stale-language sweep over `run as root`, `requires root`, `full report`, `complete
report`, `all evidence`, `unavailable`, `missing`, `not found`, `effective`,
`~/.ssh/authorized_keys`, `GLOBAL scope`, `confusable`, `skeleton`, `realpath` and `complete
host` returned no claim needing correction outside section 5. Every hit was a negation, a
prohibition the document exists to state, or a correctly-labelled historical record.

Historical corpus digests are marked `Historical, superseded by D-115` in
`W1A_CERTIFICATION_MATRIX.md` and `PYTHON_FLOOR_EVIDENCE.md`, using the docs-truth gate's own
marker vocabulary, so history stays discoverable and cannot be mistaken for a current claim.
