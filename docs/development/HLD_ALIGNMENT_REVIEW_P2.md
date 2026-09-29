<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# HLD Alignment Review — current system and R1.5-P2

Status: PLANNING
Implements: GOV-001, GOV-002, SCOPE-045

Review of `R15P2_LEAST_AUTHORITY_ACQUISITION_CONTRACT.md` against the whole repository
rather than against itself. No implementation. No frozen authority altered. No owner
decision resolved here.

## 1. Executive verdict

```
NOT ALIGNED
```

Not because the P2 design is wrong. Because it is **scoped against the wrong freeze set**,
and that was discoverable from tier-1 authority before any of its eight owner decisions
were put to the owner.

REPOSITORY FACT. `docs/architecture/V0_1_IMPLEMENTATION_SCOPE.md` is hash-locked in both
`freeze/W1A_CORE.sha256` and `freeze/W1A_CORE_PUBLIC.sha256`, so it sits in tier 1 of
`CLAUDE.md` §1 — above the decisions register, above `CLAUDE.md` itself. It contains:

> **SCOPE-070 (owner directive, 2026-09-18) SHALL** **W1 is unprivileged only.** W1 SHALL
> NOT implement `systemd-run`, Linux capability manipulation, `auditctl`, privileged
> collectors, or a sudo execution path.

> **SCOPE-071 (owner directive) SHALL** If W1 is executed as root or through sudo it
> **REFUSES** … exit `70`.

> **SCOPE-072 (owner directive) SHALL** The privileged execution model — sandbox, root
> supervisor, capability ceiling, pre/post privileged collection, engine privilege
> reduction, SELinux enforcing — is **`DEFERRED_TO_FREEZE_SET_2`** and SHALL be proven
> against real Linux behaviour in the VM corpus rather than in another prose round.

Three consequences.

**(a) Every mechanism P2 proposes is named in SCOPE-070's prohibition.** `systemd-run`,
capability manipulation, `auditctl`, privileged collectors, a sudo execution path — the
list is not approximately P2's mechanism list, it is exactly it.

**(b) The whole privileged execution model is already deferred, by frozen requirement.**
SCOPE-072 does not leave the privileged model open for design; it assigns it to Freeze Set
2. So `IQ-024`…`IQ-027` are not four independent governance conflicts. They are four
symptoms of one prior question — **does Freeze Set 2 open?** — and answering them
individually inside Freeze Set 1 would amend a frozen requirement by accretion, which is
the failure mode `CLAUDE.md` §1 exists to prevent.

**(c) SCOPE-072 anticipated this document.** It requires the privileged model to be proven
"against real Linux behaviour in the VM corpus **rather than in another prose round**".
P2-A is a prose round. It is not thereby worthless — it found the CAP_AUDIT_CONTROL
contradiction, which is cheaper to find in prose than in a VM — but it cannot be frozen as
architecture on prose alone, and the frozen requirement says so.

### 1.1 A defect in P2-A found by this review

P2-A §9 proposes delivering capabilities through `AmbientCapabilities=`. The same frozen
document records, two lines below SCOPE-072:

> Round 4 finding U-04 (that `AmbientCapabilities=` **grants rather than bounds**) remains
> **BLOCKED** against Freeze Set 2.

The repository already knew that the mechanism I proposed is unresolved, and P2-A did not
incorporate it. `CapabilityBoundingSet=` bounds; `AmbientCapabilities=` grants into the
ambient set. Using the granting directive as the delivery mechanism for a least-authority
design is the wrong default, and U-04 is open precisely on this point.

### 1.2 What the verdict is not

It is not "P2 is wrong". The authority model, the per-class endpoints, the audit
contradiction, the minimization rule and the residual register survive this review. The
verdict is that P2 must be re-scoped as **Freeze Set 2 preparatory work**, and that its
governance conflicts collapse into one prior owner question.

## 2. Authority map

| Topic | Canonical authority | Secondary | Conflicts |
|---|---|---|---|
| Precedence | `CLAUDE.md` §1 | — | **yes, §3** |
| Project identity / descriptor | `docs/architecture/ISEDRAF_PRODUCT_HLD.md` | `README.md`, `CURRENT_STATE.md` | none found |
| Architecture layering | `scripts/ci/check_architecture.py` (executable authority) | `docs/development/architecture/generated/` | none found |
| Collector responsibility | `V0_1_IMPLEMENTATION_SCOPE.md` (frozen) | `CLAUDE.md` §4 | none found |
| `hostio` responsibility | `lib/isedraf/hostio.py` header + docstring | ARCH-01 | none found |
| Evidence acquisition | `V0_1_IMPLEMENTATION_SCOPE.md` `SCOPE-022` | `lib/isedraf/hostio.py` | none found |
| **Privilege / execution model** | **`SCOPE-070`, `SCOPE-071`, `SCOPE-072` (frozen)** | `D-26`, `D-27`, `CLAUDE.md` §2 | **yes, §16** |
| R1.5-P evidence limits | `lib/isedraf/coverage.py` + `R15P_PRIVILEGE_AND_EVIDENCE_CONTRACT.md` | `D-115` | none found |
| Snapshots / identities | `SNAP-020` as amended by **`D-115`** | `lib/isedraf/snapshot.py` | none found |
| `state_hash` | `D-115` | `SCOPE-045` | none found |
| `coverage_digest` | `D-115` | `coverage.py` | none found |
| Auxiliary artifacts | `D-115` | `snapshot.py` `AUXILIARY_ARTIFACTS` | none found |
| Source provenance | `SCOPE-045` (four categories) | domain lane contracts | none found |
| Portability | **none** | `CURRENT_STATE.md` platform table | **gap, §18** |
| Runtime / compiled code | `CLAUDE.md` §2 | — | **yes, IQ-024** |
| Daemon / sudo policy | `CLAUDE.md` §2 **and `SCOPE-070`/`SCOPE-071`** | — | **yes, IQ-027** |
| systemd policy | `D-27`, and `SCOPE-070` prohibiting `systemd-run` in W1 | — | **yes, IQ-026** |
| Roadmap | `docs/roadmap/ROADMAP.md` | `INVENTORY_COVERAGE_MATRIX.md` | none found |
| Amendments | the internal amendments record | `DECISIONS_REGISTER.md` | none found |
| Implementation questions | `docs/IMPLEMENTATION_QUESTIONS.md` — **never authority** | — | none |
| Governance / frozen rules | `CLAUDE.md` §1 | `D-83`, `D-68`, `D-107` | **yes, §3 and D-83 gap** |

## 3. Precedence, and where it is ambiguous

Declared order, `CLAUDE.md` §1:

```
1  docs/architecture/          frozen docs + requirement IDs
2  DECISIONS_REGISTER.md
3  CLAUDE.md
4  IMPLEMENTATION_QUESTIONS.md   assumptions only, never authority
```

**Ambiguity 1 — the tier-1 anchor does not exist.** `CLAUDE.md` §1 states that tier 1 is
"hash-locked by `FROZEN_MANIFEST.sha256`". Measured: that file **does not exist** and has
not yet been created under `docs/architecture/`. D-107 replaced it with per-set manifests
under `docs/architecture/freeze/`.
So the rule that establishes precedence names a lock that is not there. In practice
`check_freeze.sh` verifies the two per-set manifests, so the lock is real and the *pointer*
is stale — but a reader resolving authority by following `CLAUDE.md` finds nothing.

**Ambiguity 2 — register versus frozen tier on the same subject.** `D-26` and `D-27`
describe a privileged topology; `SCOPE-070`/`SCOPE-072` (tier 1) prohibit and defer that
topology for W1. Tier 1 wins, so D-26/D-27 describe Freeze Set 2 design, not W1 permission.
Neither decision says so on its face, and P2-A read them as current authority.

**Ambiguity 3 — the same class as the D-83 gap, and the reason both survived.** `D-83`
asserts a governance manifest that does not exist; `CLAUDE.md` §1 asserts a frozen manifest
that does not exist. Two governance rules pointing at absent artifacts is a pattern, and the
mechanism is now identified:

- `CLAUDE.md` lines 10 and 26 cite `FROZEN_MANIFEST.sha256` as a **bare filename**. The
  docs-truth gate treats a reference as a repository reference only when its first path
  segment names something at the repository root, so a bare filename is read as "not
  addressing this repository" and is skipped. Verified in both directions: the bare form
  passes, and this document's full-path citation of the same file was **caught by the gate
  on the first commit attempt**.
- `CLAUDE.md` line 16 cites `docs/development/GOVERNANCE_MANIFEST.sha256`, which does not exist,
  but the same line carries a "not yet created" marker belonging to a *different* item in
  the same list. The marker suppresses the check for the whole line.

So the gate is sound and its scope has two holes, both of which a governance document
happens to sit in. That is a gate finding independent of P2.

Not resolved here. Recorded for owner action.

## 4. Current HLD — implemented today, no P2

```
  operator (ordinary user, euid != 0)
        |
        v
  isedraf CLI  --------------------------------------------- lib/isedraf/cli.py
        |
        v
  domain collectors -------- accounts · identity · inventory · ssh · sudo
  (one per domain)           pam · loginpolicy · authorizedkeys · mounts
        |
        |  argv list · shell=False · clean env · fixed PATH · LC_ALL=C
        |  timeout · bounded output · stdin=DEVNULL
        v
  hostio ------------------- the ONLY filesystem/command surface
        |                    meta:privilege="unprivileged" · meta:mutates="none"
        |                    READ_OK · NOT_FOUND · PERMISSION_DENIED · IO_ERROR
  == HOST READ BOUNDARY == (read-only; no mutation path exists)
        |
        v
  host sources (files, /proc, fixed-argv command output)

  collectors -> normalized evidence -> domain artifacts
        |              |
        |              +--> coverage.py ------> evidence limits manifest
        |                   (operation, outcome, access requirement,
        |                    universe, absence_claim_allowed)
        |
        +--> shared/compare.py (S3) -------> comparison records
        |
        v
  snapshot.py
        state.canonical --> state_hash          host-state identity
        coverage         --> coverage_digest     observation-capability identity
        auxiliary_artifacts{} --> manifest_core --> manifest_hash
        |                            method/host_identity.json   (required)
        |                            coverage/evidence_limits.json (when produced)
        v
  ledger record_core -> record_hash (chain)
        |
        v
  report/render.py --------- renders committed evidence; never collects
        |
        v
  operator · JSON · external verifier (scripts/vectors/verify.py)
```

Trust boundaries today: exactly two. `operator -> ISEDRAF` (arguments and environment), and
`ISEDRAF -> host sources` (read-only, through `hostio`). There is no privilege boundary
because there is no privileged path: measured, `lib/` contains one `subprocess` use —
`hostio`'s bounded fixed-argv runner — and nothing invokes `sudo`.

Mutation boundary: `stateroot` only. 45 of 50 modules declare `meta:mutates="none"`; the
rest declare `state-root only` or `state-root reports/ only`. All 50 declare
`meta:privilege="unprivileged"`.

## 5. Future HLD — with P2

```
LEGEND   [E] existing   [N] new P2   [B] platform backend   [?] unresolved

  [E] operator (ordinary user)
        |
  [E] unprivileged ISEDRAF engine
        |
        +--> [E] collectors -> hostio -> host sources          (unchanged)
        |
        +--> [N] privilege planner
        |         reads coverage/evidence_limits.json
        |         emits PRIVILEGE PLAN; operator may decline
        |
        v
  [N] authorization endpoint          per authority class
  == AUTHORIZATION BOUNDARY ==        [B] socket unit  |  [B] digest-pinned sudo  [?]
        |
        v
  [N] transient one-shot worker       language pending P2-B
  == KERNEL AUTHORITY BOUNDARY ==
        |
        +-- [B] MAC       SELinux domain | AppArmor profile | NONE_ACTIVE
        +-- [B] seccomp   per-class syscall filter
        +-- [B] caps      bounding set   ([?] U-04: ambient grants, not bounds)
        +-- [B] sandbox   ProtectSystem=strict, no ReadWritePaths
        |
        v
  [N] protected evidence source
        |
        |  bounded result, minimized INSIDE the worker
        v
  [E] unprivileged engine
        |
        +--> [N] privilege receipt
        |         KERNEL_OBSERVED | POLICY_ARTIFACT_IDENTITY | HELPER_REPORTED
        |
        +--> [E] coverage.py  (acquisition mode: [?] new value required)
        |
        v
  [E] snapshot.py
        [N] auxiliary artifact -> manifest_core -> manifest_hash
        [E] state_hash UNCHANGED by any of the above
```

Nothing in the `[N]` or `[B]` columns exists. The `[E]` column is unchanged by this design.

## 6. Component responsibility matrix

`C` = current, `F` = future. "Runs as" for future components is the design intent, not a
measured fact.

| Component | C/F | Runs as | Input | Output | May read | May write | May exec | Network | Mutate host | Trust | Authority |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CLI | C | operator | argv, env | exit code, text | via collectors | state root | no | no | no | untrusted input | `SCOPE-070` |
| collectors | C | operator | host bytes | normalized evidence | via `hostio` | no | no | no | no | trusted code, untrusted data | lane contracts |
| `hostio` | C | operator | path, argv | bytes or outcome | host, read-only | no | fixed argv | no | no | boundary | `EXEC-016`, `SCOPE-022` |
| `coverage` | C | pure | facts | limits manifest | nothing | nothing | no | no | no | pure | `R15P` contract |
| S3 `compare` | C | pure | two record sets | relationships | nothing | nothing | no | no | no | pure | `SCOPE-020/021` |
| `snapshot` | C | operator | evidence | bundle, hashes | state root | state root | no | no | no | integrity owner | `SNAP-020`, `D-115` |
| report | C | operator | committed bundle | text, JSON | state root | reports only | no | no | no | renderer | ARCH-01 |
| privilege planner | F | operator | evidence limits | plan | limits manifest | no | no | no | no | unprivileged | **undecided** |
| authorization endpoint | F | systemd / sudo | connection | worker invocation | — | — | starts worker | no | no | authorization | **`SCOPE-070` forbids in W1** |
| P2 worker | F | service identity or uid 0 | operation id + bounded ids | minimized evidence + receipt | one class's objects | **nothing** | **no** | **no** | **no** | assumed buggy | **`SCOPE-072` defers** |
| SELinux backend | F | kernel | policy | denials | — | — | — | — | — | enforcement | **none yet** |
| AppArmor backend | F | kernel | profile | denials | — | — | — | — | — | enforcement | **none yet** |
| systemd backend | F | pid 1 | unit | confined process | — | — | — | — | — | enforcement | `D-27` (conflicted) |
| generic backend | F | kernel | caps/seccomp | denials | — | — | — | — | — | partial | **none yet** |
| sudo fallback | F | sudo | rule match | worker invocation | — | — | starts worker | no | no | authorization | **`SCOPE-071` refuses** |
| receipt producer | F | worker + engine | kernel facts | receipt | `/proc/self` | no | no | no | no | split trust | `D-115` pattern |

**Overlap found.** "authorization endpoint" and "sudo fallback" are the same
responsibility with two implementations, and the matrix shows both able to start the
worker. They must never be installed simultaneously on one host, or the authority envelope
becomes the union of two policies — a P2-N6 violation reachable by packaging rather than by
code. Recorded as a P2-D packaging constraint.

## 7. Trust-boundary matrix

| Boundary | What crosses | Input controlled by | Trusted | Max damage if receiver compromised | External enforcement | Residual |
|---|---|---|---|---|---|---|
| operator -> ISEDRAF | argv, env, state root | operator | no | ordinary user authority only | OS DAC | R7 |
| ISEDRAF -> host | read requests | ISEDRAF | n/a | reads what the identity may read | OS DAC | none new |
| host -> collectors | file bytes, command output | **the host** | **no** | parser bugs; contained, unprivileged | none | parser defects |
| engine -> endpoint | operation id, bounded ids | engine (**assume hostile**) | no | reaches one class's envelope | endpoint identity + unit | authority confusion if one endpoint serves many classes |
| endpoint -> worker | invocation | package policy | yes | — | systemd / sudo policy | R2 (digest race) |
| worker -> kernel | syscalls | worker (**assume buggy**) | no | bounded by seccomp + caps | seccomp, capability bounding | R3 |
| worker -> protected source | opens | worker | no | bounded by MAC where present | MAC; **nothing where absent** | R5 |
| worker -> engine | minimized evidence + receipt | worker | **evidence yes, claims no** | discloses what the operation returns | none — see R1 | **R1, the largest** |
| engine -> snapshot | evidence, auxiliary | engine | yes | bundle misstates acquisition | manifest binding | R6 |
| snapshot -> verifier | bundle | bundle author | no | verifier rejects | independent verifier | R4 |

The `worker -> engine` row is the one a network control does not touch, and it is where the
protected bytes actually go.

## 8. R1.5-P alignment

The doctrine, preserved:

```
WHAT EXISTS ON HOST  !=  WHAT CURRENT IDENTITY COULD OBSERVE
                     !=  WHAT ADDITIONAL AUTHORITY COULD MAKE OBSERVABLE
ACCESS OUTCOME       !=  ACCESS REQUIREMENT  !=  ACQUISITION MODE
```

P2 changes exactly one of these: **ACQUISITION MODE**. Measured, `lib/isedraf/coverage.py`:

```python
MODE_CURRENT_IDENTITY = "CURRENT_IDENTITY"
MODES = (MODE_CURRENT_IDENTITY,)
```

with the module's own reasoning recorded in place:

> There is deliberately no ELEVATED value. An earlier draft had one, and it was a fiction
> twice over: `SCOPE-071` refuses privileged execution so no collection path could emit it,
> and — the subtler half — a process that HAPPENS to run as uid 0 has not performed
> elevation. … Future modes … are CONTRACTED DIRECTION and are admitted when a mechanism
> exists to produce them.

So the schema already reserved this and already stated the admission rule: a mode is
admitted **when a mechanism exists to produce it**, not when a design proposes one. P2-A
proposes the mechanism, so the mode is still not admissible today.

The proposed addition, when P2-C produces a mechanism:

```
MODE_OPERATOR_AUTHORIZED_OPERATION
    an operator-approved, bounded, per-class privileged operation completed
    NOT "the process was root"
```

This requires owner approval, because `MODE_ELEVATED`'s removal was owner ruling D of
R1.5-P. Adding a mode reverses part of a ruling; it is not a schema edit.

Preserved without change: `privilege unavailable` never collapses into `collection
failure`. A declined plan yields the same evidence-limits entry the current unprivileged
refusal yields. `absence_claim_allowed` still derives centrally from the universe, never
from whether privilege was granted.

## 9. Hash and evidence identity model

| Identity | Question it answers | Binds | Changed by | MUST NOT be changed by |
|---|---|---|---|---|
| `state_hash` | what is the host's security state | `STATE` fields only | a host-state change | coverage, provenance, privilege, policy, worker identity |
| `coverage_digest` | what could this run observe | coverage facts | observation capability | host state |
| `manifest_hash` | is this bundle intact | `manifest_core` incl. `auxiliary_artifacts{}` | any bound artifact | — |
| `record_hash` | is the ledger chain intact | `record_core` | a new record | — |

Proposed P2 additions, assessed:

| Proposal | Verdict |
|---|---|
| `authority_contract_digest` | **not a new identity.** It is a field inside the receipt. |
| helper digest, policy digests | **not new identities.** Fields inside `POLICY_ARTIFACT_IDENTITY`. |
| privilege receipt | **a new auxiliary artifact**, not a new digest. |
| separate `acquisition_authority_digest` | **NOT JUSTIFIED.** D-115's `auxiliary_artifacts` mapping is already generic and bounded, keyed by canonical bundle-relative path. A receipt bound through it changes `manifest_hash` and cannot touch `state_hash`, which is exactly the property wanted. Inventing a fourth digest would add an identity whose semantic question is already answered. |

D-115's own words settle the required proofs:

> a coverage or provenance change MAY change `manifest_hash`, and a coverage or provenance
> change alone SHALL NOT imply a host-state change.

So: changing privilege policy changes `manifest_hash`, leaves `state_hash` alone, and is
therefore an **ACQUISITION AUTHORITY DELTA** — the third axis, alongside host-state delta
and observation-visibility delta. Falsifiable directly: hold host state constant, change
the receipt, assert `manifest_hash` moves and `state_hash` does not.

## 10. Privilege receipt classification

Assessed against the existing architecture rather than preference. `SCOPE-045` gives every
normalized field exactly one of `STATE` · `OBSERVATION` · `DERIVED` · `PROVENANCE`.

```
privilege receipt  =  PROVENANCE, carried as an AUXILIARY SNAPSHOT ARTIFACT
```

It is not `STATE` — a privilege envelope is not host security state, and making it `STATE`
would put policy changes into `state_hash`, which D-115 forbids. It is not `OBSERVATION` —
it describes how evidence was obtained, not what was seen. It is the same class as
`method/host_identity.json`, which is why the D-115 mechanism fits without extension.

| Field group | Created by | Verified by |
|---|---|---|
| `KERNEL_OBSERVED` | worker reading `/proc/self` | administrator, independently, against the live process |
| `POLICY_ARTIFACT_IDENTITY` | package/build | `sha256sum`, `systemctl cat`, `semodule -l`, `aa-status` |
| `HELPER_REPORTED_ACQUISITION` | worker | **nothing** — it is a claim, and the review must not present it otherwise |

No field is described as hardware- or kernel-attested. The correct phrase is
**kernel-derived execution state**, and it remains a reading taken by the worker itself.

## 11. Operation contract placement

The privileged operation contract is **not** a second evidence schema. Placement:

```
collector contract      what a domain collects and how it is normalized   (unchanged)
source contract         what a source family means                        (unchanged)
operation contract      what ONE privileged acquisition may touch         (new, P2)
evidence artifact       the normalized result                             (unchanged shape)
evidence-limits entry   what could not be observed, and why               (unchanged shape)
privilege receipt       under what authority it was obtained              (new, auxiliary)
snapshot                binds all of the above                            (unchanged mechanism)
```

The operation contract governs **acquisition authority**. It never describes evidence
meaning; that stays in the domain contract. If an operation contract ever needed a field
describing what evidence means, that is the signal it has grown into a second schema.

## 12. `OP_ACCOUNT_SHADOW_READ_V1` end to end

Traced against the frozen account contract, `W1D_ACCOUNT_SOURCE_CONTRACT.md`.

```
1  unprivileged run: /etc/shadow -> PERMISSION_DENIED
2  coverage entry: operation FILE_READ, outcome PERMISSION_DENIED,
   required_access ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED,
   universe INCOMPLETE, absence_claim_allowed false
3  passwd<->shadow join reports SOURCE_NOT_COLLECTED
   (not ABSENT_FROM_COLLECTED_SOURCE - the contract's three-answer rule)
4  planner emits PRIVILEGE PLAN naming OP_ACCOUNT_SHADOW_READ_V1
5  operator declines  -> state unchanged, evidence limits unchanged, run valid
   operator accepts   -> engine connects to the shadow-class endpoint
6  worker starts confined; reads /etc/shadow; PARSES AND MINIMIZES IN PLACE
7  returns ONLY: password_state.lock_prefix, password_state.content,
   password_state.hash_scheme, the *_days integers and named states, provenance
8  never returns: the file, any line verbatim, any password verifier
9  engine normalizes as it does today; STATE fields unchanged in meaning
10 coverage entry becomes READ_OK, universe COMPLETE, mode = the new value (§8)
11 receipt written as an auxiliary artifact; bound via manifest_core
12 state_hash reflects the newly observable account state - correctly, because
   host state is now better observed; manifest_hash also moves; the delta is
   reported as OBSERVATION VISIBILITY, not as host-state drift
```

Step 12 is the subtle one and is called out rather than buried: acquiring previously
unobservable evidence **does** change `state_hash`, because `STATE` fields that were absent
now have values. That is a **visibility delta presenting as a state delta**, and the
existing vocabulary already handles it — `NOT_TESTED` never becomes `REMOVED`, and a
method change never masquerades as drift. P2-F must prove this specific case, because it is
the first time the repository would produce it deliberately.

Contract compliance: no raw verifier retained (the contract already rules "the verifier is
not stored"); absence semantics preserved through the three-answer join; lossless doctrine
untouched, since the worker returns parsed fields and the byte-level rules apply to what it
parses; evidence-limits model unchanged in shape.

## 13. `hostio` ownership decision

`lib/isedraf/hostio.py` declares `meta:privilege="unprivileged"` in its header metadata, as
do all 50 modules under `lib/`. Its docstring states it "depends on nothing but the
standard library, which is what makes it safe to sit underneath everything."

```
privileged acquisition sits BESIDE hostio, never inside it
```

Reasons, in order of weight: putting privilege awareness into `hostio` would change a
declared header field that the header-identity gate reads; `hostio` is the dependency floor
for every collector, so a privileged branch there is reachable from every domain, which is
P2-N6 by construction; and `hostio`'s bounded responsibility — "reads bytes and returns
them, or says why it could not" — is what makes it reviewable.

Proposed: a separate `privileged acquisition client` in the engine, which is an ordinary
unprivileged module that speaks the endpoint protocol. It is a *client*, and the privilege
lives on the other side of the boundary. `hostio` is not modified by P2 at all.

## 14. S3 alignment

S3 compares normalized evidence. It has no concept of authority and must not acquire one.

Verified against `lib/isedraf/shared/compare.py`: its inputs are two record sets, a
comparator, and the two universe-completeness booleans. Nothing in its signature or
provenance names an identity, a privilege, or a source of authority.

P2 touches S3 only where it already touches it: through **universe completeness**. A
privileged acquisition that succeeds turns an incomplete universe into a complete one, and
S3's behaviour then follows the rules already frozen by IQ-019 and IQ-020. No P2 design
element asks S3 to select authority or interpret privilege, and any future one must be
rejected.

## 15. D-115 alignment

Measured bundle layout, `lib/isedraf/snapshot.py`:

```python
AUXILIARY_ARTIFACTS = ("coverage/evidence_limits.json", "method/host_identity.json")
REQUIRED_AUXILIARY  = ("method/host_identity.json",)
```

A privilege receipt fits this mechanism with no extension: `manifest_core` already carries a
bounded `auxiliary_artifacts` mapping keyed by canonical bundle-relative path. Candidate
placements, named only as candidates because the owner has not approved a bundle path:

```
coverage/privilege_receipts.json    if receipts are read as observation capability
method/acquisition_authority.json   if read as method provenance
```

PROPOSAL: `method/`, because the receipt answers "under what authority was this obtained",
which is method provenance, while `coverage/` answers "what could be observed". Owner
decision, deferred to P2-F — and not urgent, because the mechanism does not change either
way.

Proof obligation, which is directly falsifiable and belongs in P2-F: hold host state
constant, alter the receipt, and assert `manifest_hash` changes while `state_hash` does not.

## 16. Contradiction review — one table, four rows, one root

| Item | Existing authority | Conflict | Class | Resolution path |
|---|---|---|---|---|
| **ROOT** | `SCOPE-072` (**frozen**): the privileged execution model is `DEFERRED_TO_FREEZE_SET_2` and SHALL be proven in the VM corpus "rather than in another prose round" | P2 designs that model now, in prose | **frozen-contract** | **owner: does Freeze Set 2 open?** Nothing below can be decided before this |
| IQ-024 compiled worker | `CLAUDE.md` §2 "No Go, compiled parts" | P2 needs a compiled worker | governance (tier 3) | amendment — **but moot until ROOT** |
| IQ-025 audit | `D-26` grants `CAP_AUDIT_CONTROL` + `auditctl` fixed argv; `SCOPE-070` (**frozen**) forbids `auditctl` and capability manipulation in W1 | P2 §12a shows the capability cannot demonstrate read-only authority | **frozen-contract**, and D-26 is tier 2 describing Freeze Set 2 | measurement (SELinux netlink separability) **plus** owner, after ROOT |
| IQ-026 systemd | `D-27` `systemd-run`; `SCOPE-070` (**frozen**) forbids `systemd-run` in W1 | P2 proposes packaged units; P2-N8 forbids init coupling in core | **frozen-contract** for W1; architectural for Freeze Set 2 | owner, after ROOT |
| IQ-027 sudo / daemon | `CLAUDE.md` §2 "internal sudo, password prompts, daemons"; **`SCOPE-071` (frozen) REFUSES root or sudo execution, exit 70** | both authorization backends | **frozen-contract** — higher tier than P2-A classified it | owner, after ROOT |
| **new** U-04 | `V0_1_IMPLEMENTATION_SCOPE.md`: `AmbientCapabilities=` **grants rather than bounds**, BLOCKED against Freeze Set 2 | P2-A §9 proposed `AmbientCapabilities` as the delivery mechanism | **P2-A defect** | correct P2-A; use `CapabilityBoundingSet` reasoning and treat ambient as unresolved |

**Reclassification.** P2-A recorded IQ-025 and IQ-027 as conflicts with the register and
with `CLAUDE.md`. They are conflicts with the **frozen tier**. That is a higher tier and a
stricter amendment path, and P2-A understated it.

**Collapse.** The four are not four owner decisions. They are four consequences of ROOT.
Asking the owner to decide them individually would be asking for a Freeze Set 2 architecture
to be approved one clause at a time, inside Freeze Set 1, without the corpus proof
`SCOPE-072` requires.

## 17. Audit operation — unchanged status

```
OP_AUDIT_ACTIVE_RULES_READ_V1        DESIGN_UNRESOLVED
```

| Claim | Class |
|---|---|
| `CAP_AUDIT_CONTROL` includes mutation authority | **KNOWN** — `capabilities(7)`: "Enable and disable kernel auditing; change auditing filter rules; retrieve auditing status and filtering rules" |
| `CAP_AUDIT_READ` does not cover filter rules | **KNOWN** — same page: audit log via multicast netlink |
| seccomp cannot discriminate netlink message types | **KNOWN** — seccomp cannot dereference user-space pointers, so `nlmsg_type` is unreadable to a filter |
| SELinux can separate read-like from write-like netlink classes | **INFERENCE — MEASUREMENT REQUIRED** |
| AppArmor cannot | **INFERENCE — MEASUREMENT REQUIRED** |

Future experiment, P2-E: on an SELinux-enforcing corpus VM, place a worker in a domain
granted read-side access to `netlink_audit_socket` and denied `nlmsg_write`; attempt
`AUDIT_LIST_RULES` (expect success) and `AUDIT_ADD_RULE` (expect a recorded AVC denial).
The operation is admitted only if the denial is observed, and it stays unresolved
otherwise. SELinux being *able* to express the distinction is not the same as the
distinction being enforced, and the HLD does not resolve the operation on the inference.

## 18. Portability HLD

No authoritative portability document exists — this is a **gap**, not a conflict.
`CURRENT_STATE.md` records x86_64 measured and aarch64/armhf **not tested**, zero campaigns.

```
                     P2 CORE CONTRACT (identical everywhere)
        operation ids · IPC schema · response schema · receipt semantics
                     negative-security semantics
                                  |
   +--------------+---------------+---------------+---------------+
   |              |               |               |               |
 x86_64 EL    aarch64 EL     SBC / Pi       OpenWrt/procd    Yocto/Buildroot
 systemd       systemd        systemd?        procd           varies
 SELinux       SELinux        AppArmor?       maybe none      image-defined
 sudo          sudo           sudo            often absent    image-defined
 glibc         glibc          glibc           musl            either
   |              |               |               |               |
 full         full           full            reduced         image-defined
 assurance    assurance      assurance       assurance       assurance
```

The operation contract is identical in all five columns. What differs is the confinement
obtained, and P2-N10 requires that difference to be reported rather than smoothed. Where no
authorization backend exists at all, privileged acquisition is unavailable and the evidence
stays incomplete — the honest outcome, and the one the current architecture already
expresses.

## 19. Constrained-device architectures

Compared on properties only. **No selection made.**

| | A: full engine + worker | B: reduced engine + worker | C: acquisition agent only |
|---|---|---|---|
| Footprint | largest — interpreter on every node | medium | smallest |
| Trust boundary | as designed | as designed | adds a **network** boundary |
| Evidence portability | full | full if schemas identical | full |
| Offline operation | yes | yes | **no** |
| Network dependence | none | none | **required** |
| Snapshot integrity | on device | on device | **off device** — who signs the bundle? |
| Product complexity | one product | **two semantics — forbidden by the one-model invariant** | two components, one semantics |
| Blocker | interpreter requirement | violates one-model invariant | **crosses `CLAUDE.md` §2 network-egress prohibition** |

B is excluded by the product invariant. A and C each carry a blocker that is an owner
decision, not an engineering choice. Owner decision, with measurement input from P2-B.

## 20. Language alignment

Survives language replacement, therefore belongs in the HLD: operation ids, authority
classes, the IPC schema, the response schema, receipt semantics, negative-security
semantics, the confinement profiles themselves.

Does not belong in the HLD: allocator behaviour, runtime scheduler presence, libc choice,
build toolchain, crate or module names, binary layout.

```
Rust   preferred candidate
Go     comparison candidate
C      engineering baseline only, not a production candidate
```

No freeze before P2-B measurement. P2-A's earlier naming of Rust as the proposed
implementation is withdrawn and has been corrected in that document.

## 20a. Trust-model enhancement — proposals, and the challenge

A trust-signal proposal was submitted for evaluation. Assessed with the same vocabulary as
the rest of this review. The direction is right and two items cannot enter the repository.

### 20a.1 What must not be adopted

**A comparative matrix naming other products — CONTRADICTS EXISTING AUTHORITY.** Not a
style objection. `CLAUDE.md` §2 prohibits "vs"/"replaces"/"better than"/rankings about any
project, and `check_docs_truth.py` enforces C-06 "no competitive positioning, **including
NEGATED comparisons**", with a falsification injection proving the gate fires. A table
placing ISEDRAF against named scanners fails the gate on the next commit.

The stronger objection is evidentiary, and it is the owner's own ruling from the P2
directive: *"Do not market by oversimplifying competitors."* Statements such as "they
download dynamic detection scripts from the cloud", "unconstrained root access across the
entire server fleet", or a "TOTAL HOST COMPROMISE" blast-radius cell are claims about
third-party products, unversioned and unresearched. This repository refuses that for its
own product. It cannot assert it about someone else's.

What survives, and is defensible without naming anyone:

> The main ISEDRAF engine does not require unrestricted root authority. Protected evidence
> acquisition would use bounded, independently constrained authority envelopes.

**"Kernel attestation" / "Hardware TPM / IMA Measurement Support" — CONTRADICTS.** The
owner's own prior directive: do not use hardware-attested or kernel-attested language
unless real attestation machinery exists. It does not. IMA/TPM measurement is moreover a
**host** capability an administrator enables; a worker binary participates in it the way
every executable does. Listing it as an ISEDRAF specification claims credit for a kernel
feature. The honest form: *the worker is a package-owned file with a published digest;
where the host enforces IMA appraisal, it is appraised like any other executable.*

**"SLSA Level 3" — CONTRADICTS a standing instruction.** Levels, scores and badges are not
displayed before the corresponding evidence exists. SLSA L3 is a claim about the build
platform's resistance to tampering, and asserting a level is a certification claim this
project does not make about itself anywhere else.

### 20a.2 A contradiction inside the proposal

Pillar 2 proposes Sigstore/Cosign. Pillar 3 requires offline, air-gapped verification with
no external dependency.

```
cosign KEYLESS   -> OIDC + Fulcio + Rekor transparency log   = NETWORK REQUIRED
cosign KEY-BASED -> public key shipped in the package        = OFFLINE VERIFIABLE
GPG / PKCS#11    -> public key shipped in the package        = OFFLINE VERIFIABLE
```

Keyless Sigstore is the default people mean by "Sigstore", and it cannot satisfy Pillar 3
without a mirrored log bundle. The two pillars are compatible only in the key-based form.
That is not a detail — it selects the signing design, and `signing` is currently listed as
**Planned** in `CURRENT_STATE.md`, so nothing is locked in yet.

### 20a.3 What already exists, and is stronger than a badge

| Proposed pillar | Repository state |
|---|---|
| Reproducible builds | **EXISTS** — `scripts/ci/check_reproducible.sh`, gated by `make check-reproducible` |
| SBOM | **EXISTS** — `scripts/ci/generate_sbom.py`, three documents, licence-checked |
| Artifact attestation | **EXISTS and is falsified** — the release workflow attests, then proves a one-byte-flipped copy is refused. An attestation only ever run against a good artifact has proven nothing |
| Offline verification | **EXISTS** — `scripts/vectors/verify.py` is an independent reimplementation; W1-A vectors reproduce byte-for-byte |
| Binary signing | **PLANNED** — `signing` is in the Planned list; no key, no policy, no design |
| TPM / IMA integration | **does not exist**, and see above |
| Third-party audit | **does not exist** |

The defensible trust story is the one the repository already tells and can prove: *here is
the evidence, here is an independent verifier that does not share our implementation, and
here are the native OS commands to check our claims without trusting us.* That argument
needs no comparison and no badge.

### 20a.4 Proposals worth adopting, classified

| Proposal | Class | Stage |
|---|---|---|
| Key-based signing with the public key shipped in the package | COMPATIBLE EXTENSION | after `signing` leaves Planned |
| Publish the worker digest and the policy digests as release artifacts | COMPATIBLE EXTENSION | P2-H |
| Third-party audit of worker, MAC policies and seccomp filters | REQUIRES OWNER DECISION — budget and timing, no architecture impact | P2-G/P2-H, and premature before a worker exists |
| Remove badge-style trust signalling from release messaging | ALREADY THE RULE | — |
| "Zero network egress during elevated collection" | COMPATIBLE, with wording care | P2-D |

On the last row: the accurate claim is that the worker's unit denies `AF_INET`/`AF_INET6`
and that this is checkable in `systemctl show`. It is **not** a confidentiality control for
what the worker returns — residual R1 — and the phrase must not be allowed to imply it is.

### 20a.4a Doctrine scan — measured, and the result is zero

The competitor-neutrality doctrine was applied to all 71 tracked documents outside
`planning/`. Result: **80 raw hits, 0 doctrine violations.** 31 are the doctrine being
stated or enforced, 27 are required clean-room references, 14 are the neutral coexistence
examples, 5 are marked historical record, and 3 are ordinary English. Zero competitor
comparisons, zero superiority claims, zero overstated security claims.

The doctrine is therefore a **formalization of existing practice**, not a correction. It is
already canonical in `docs/STYLE_GUIDE.md` §103-110 and
`docs/development/DOCUMENTATION_POLICY.md` §31-37, and already enforced by C-06 including
negated comparisons. `TRUST_AND_ASSURANCE_DOCTRINE.md` therefore cites those rules rather
than copying them, and carries only the material with no canonical home: badges as indexes,
trust as a non-claim, provenance separated from reproducibility, external-review reporting,
and the TA track.

A third copy of the forbidden-word list would be a third thing to drift.

### 20a.5 One factual correction

The submitted analysis treats "NFTBan" as NFT or blockchain related and recommends removing
"NFT/Blockchain Verified" claims. NFTBan is an IP-firewall project; the name refers to
`nftables`. No NFT or blockchain claim exists in this repository to remove. The
recommendation is sound in general and does not apply here.

## 21. Failure model

Every failure maps onto existing collection/evaluation semantics. None produces a security
conclusion.

| Failure | Collection status | Evaluation | Evidence limits |
|---|---|---|---|
| operation not authorized | `NOT_TESTED` | `NOT_COMPARABLE` | required access recorded; absence not claimable |
| operator declines the plan | `NOT_TESTED` | `NOT_COMPARABLE` | identical to an unprivileged refusal — **by design** |
| confinement backend absent | operation not attempted | — | backend state reported (P2-N10) |
| MAC installed but permissive | attempted or refused, per owner decision 6 | — | reported as permissive, never as enforcing |
| seccomp unavailable | operation not attempted | — | reported |
| worker digest mismatch | `ERROR` | `NOT_COMPARABLE` | **authorization limitation**, never a collection failure |
| worker fails to start | `ERROR` | `NOT_COMPARABLE` | reason recorded |
| worker crashes mid-read | `PARTIAL` or `ERROR` | `NOT_COMPARABLE` | universe incomplete |
| evidence source absent | `NOT_TESTED` + `NOT_FOUND` | — | an absent source is not a denied one |
| result exceeds bounds | `PARTIAL` | `NOT_COMPARABLE` | truncation recorded; never silently trimmed |
| receipt cannot be produced | **operation result discarded** | `NOT_COMPARABLE` | evidence obtained without a receipt is unattributable acquisition |
| contract or policy identity mismatch | `ERROR` | `NOT_COMPARABLE` | drift recorded |

Two rows deserve emphasis. A **digest mismatch after upgrade** is an authorization problem
and must never be rendered as "collection failed" — the operator's fix is different. And a
**receipt that cannot be produced** invalidates the acquisition: evidence whose authority
cannot be described is not evidence this architecture accepts.

## 22. Security claim matrix

| Claim | Enforcement layer | Observable proof | Negative test | Residual |
|---|---|---|---|---|
| worker cannot execute an arbitrary program | protocol has no exec verb + seccomp denies `execve`/`execveat` | `/proc/<pid>/status` `Seccomp: 2` + policy digest | worker variant attempts `execve` | R3 |
| worker cannot run a shell | same | same | variant attempts `/bin/sh` | R3 |
| worker cannot take a caller-supplied path | contract admits bounded identifiers only + MAC object scope | contract digest; MAC policy | variant sends a path field | R5 where no MAC |
| worker cannot write anything | `ProtectSystem=strict`, no `ReadWritePaths` + MAC | `systemctl show` | variant attempts write to source and elsewhere | R5 |
| worker cannot reach the network | `RestrictAddressFamilies=` + seccomp | `systemctl show` | variant attempts socket creation | **R1 — does not protect returned evidence** |
| worker cannot read unrelated protected objects | MAC domain/profile | `/proc/<pid>/attr/current`, `sesearch`/`aa-status` | variant reads an out-of-scope object | **R5 — CLAIM_NOT_YET_PROVEN without MAC** |
| shadow worker cannot obtain audit authority | separate endpoint, unit, domain, filter | policy digests; endpoint layout | shadow worker attempts audit netlink | authority-union regression test |
| privileged metadata cannot alter host-state identity | serialization and hash construction | recompute both hashes | change receipt, hold state constant | none identified |
| the engine never holds root | no privileged path in the engine | `/proc/<pid>/status` of the engine | — | **CLAIM PROVEN TODAY** — no privileged path exists |
| audit rules can be read without mutation authority | **none identified** | — | — | **CLAIM_NOT_YET_PROVEN — see §17** |
| capabilities are bounded, not granted | `CapabilityBoundingSet` | `/proc/<pid>/status` `CapBnd` | variant uses an out-of-contract capability | **U-04 open: ambient grants** |

Two rows carry `CLAIM_NOT_YET_PROVEN` and one carries an open finding. They are not
softened.

## 23. Non-claims

P2 does not promise, and documentation must not imply:

```
protection against a compromised kernel
protection against an already-root adversary on the host
confidentiality of returned evidence against an authorized but malicious caller   (R1)
hardware attestation, TPM measurement or IMA appraisal as ISEDRAF features
assurance that does not vary by distribution, version or confinement backend       (P2-N10)
any "zero attack surface" or "zero root anywhere" property
support for non-Linux, RTOS or microcontroller targets
that a policy file's presence equals enforcement
that a passing negative test proves the absence of all escapes
```

## 24. Drift matrix

Statements in the repository that would become false if P2 were approved. **Not edited** —
this is a report.

| File | Existing text | Conflict | Tier | Action |
|---|---|---|---|---|
| `docs/architecture/V0_1_IMPLEMENTATION_SCOPE.md` | `SCOPE-070`: W1 SHALL NOT implement `systemd-run`, capability manipulation, `auditctl`, privileged collectors, or a sudo execution path | names every P2 mechanism | **frozen** | owner amendment, or confirm P2 is Freeze Set 2 and W1 is untouched |
| same | `SCOPE-071`: root or sudo execution REFUSES, exit 70 | both authorization backends | **frozen** | owner |
| same | `SCOPE-072`: privileged model `DEFERRED_TO_FREEZE_SET_2`, proven in the corpus "rather than in another prose round" | P2-A is a prose round | **frozen** | owner — the ROOT decision |
| same | U-04: `AmbientCapabilities=` grants rather than bounds, BLOCKED | P2-A §9 proposes ambient delivery | **frozen** | correct P2-A |
| `DECISIONS_REGISTER.md` D-26 | launcher holds "the minimum superset"; `auditctl` fixed argv | union authority in the launcher; §12a | register | owner, after ROOT |
| `DECISIONS_REGISTER.md` D-27 | `systemd-run` transient units | caller-constructed confinement | register | owner, after ROOT |
| `CLAUDE.md` §2 Runtime | "No Go, compiled parts" | compiled worker | governance | owner (IQ-024) |
| `CLAUDE.md` §2 Privilege | "internal sudo, password prompts, daemons" | both backends | governance | owner (IQ-027) |
| `CLAUDE.md` §1 | tier 1 "hash-locked by `FROZEN_MANIFEST.sha256`" | that file does not exist | governance | owner — independent of P2 |
| `CLAUDE.md` §2 | `lib/isedraf/launcher/` named as the only `os.execv*` site | the directory does not exist | governance | owner — independent of P2 |
| `lib/isedraf/coverage.py` | `MODES = (MODE_CURRENT_IDENTITY,)` | P2 needs a second mode | code, owner-ruled | owner ruling D reversal |
| all 50 modules | `meta:privilege="unprivileged"` | a worker would not be | code | new module declares otherwise; gate must accept it deliberately |
| `docs/CURRENT_STATE.md` | aarch64/armhf **not tested**, zero campaigns | portability targets | generated | unchanged until a campaign runs |

## 25. HLD traceability matrix

The primary deliverable. Every row is traceable to an authority or is marked as needing an
owner decision. `C` = current and proven today; `F` = future.

| HLD-ID | Requirement | Authority | Component | C/F | Enforcement | Verification | Falsification | Owner decision | Stage |
|---|---|---|---|---|---|---|---|---|---|
| HLD-C-001 | The engine runs unprivileged | `SCOPE-070` frozen | engine | C | refusal under root | `meta:privilege` on 50 modules; no privileged path in `lib/` | root-execution refusal, exit 70 | no | done |
| HLD-C-002 | All host access passes through `hostio` | ARCH-01, `EXEC-016` | `hostio` | C | architecture gate | `check_architecture.py` layering | unplaced-module injection | no | done |
| HLD-C-003 | No shell, fixed argv only | `CLAUDE.md` §4 | `hostio` | C | code + gate | `shell=False`, argv list | architecture self-test | no | done |
| HLD-C-004 | Collection status separate from evaluation result | `SCOPE-022` | all lanes | C | schema | separate fields and counters | S3 injections | no | done |
| HLD-C-005 | Every field carries one `SCOPE-045` category | `SCOPE-045` | all lanes | C | schema | field tables in lane contracts | vector verification | no | done |
| HLD-C-006 | `state_hash` = host-state identity only | `D-115` | `snapshot` | C | hash construction | vectors; auxiliary-binding tests | 8 auxiliary falsifications | no | done |
| HLD-C-007 | `coverage_digest` = observation capability | `D-115` | `coverage` | C | hash construction | coverage tests | coverage injections | no | done |
| HLD-C-008 | Auxiliary artifacts bound via `manifest_core` | `D-115` | `snapshot` | C | `auxiliary_artifacts{}` | `verify_snapshot` | modification, deletion, substitution, path substitution, digest mismatch | no | done |
| HLD-C-009 | Absence derives from universe, never from status | IQ-020, CQ-1 | `coverage`, S3 | C | central derivation | mandatory kwargs, no default | 5 S3 injections | no | done |
| HLD-C-010 | Only one acquisition mode is producible | owner ruling D | `coverage` | C | `MODES` tuple | code | — | no | done |
| HLD-C-011 | Evidence references resolve within the artifact | R1/R2 mounts | mounts, future lanes | C | retention in artifact | 41/41 at `/` | M01, M01b, M01c | no | done |
| HLD-P2-001 | The privileged model belongs to Freeze Set 2 | **`SCOPE-072` frozen** | all P2 | F | — | frozen text | — | **YES — ROOT** | before P2-A freeze |
| HLD-P2-002 | A compiled worker is permitted | `CLAUDE.md` §2 | worker | F | package | — | — | **YES (IQ-024)** | after ROOT |
| HLD-P2-003 | Implementation language chosen by measurement | P2-N7 | worker | F | — | P2-B measurements | — | no — measurement | P2-B |
| HLD-P2-004 | Authority selected by endpoint, not payload | P2-N6 | endpoint | F | separate sockets/units | `systemctl cat` | cross-endpoint attempt | **YES (5)** | P2-D |
| HLD-P2-005 | Worker cannot exec | P2-N1, P2-N3 | seccomp | F | seccomp | `Seccomp: 2` + digest | variant `execve` | no | P2-C/D |
| HLD-P2-006 | Worker takes no caller path | P2-N2 | contract + MAC | F | contract, MAC | contract digest | path-field attempt | no | P2-C |
| HLD-P2-007 | Worker cannot mutate the host | P2-N4 | sandbox + MAC | F | `ProtectSystem=strict` | `systemctl show` | write attempts | no | P2-D |
| HLD-P2-008 | Shadow worker cannot read unrelated protected objects | P2-N5 | MAC backend | F | SELinux/AppArmor | live context + policy | out-of-scope read | no | P2-C/D |
| HLD-P2-009 | No union authority across classes | P2-N6 | endpoints, packaging | F | separate units, separate paths | policy inventory | authority-union regression | **YES (5)** | P2-D |
| HLD-P2-010 | Per-class executables where SELinux is the backend | §6.3 inference | packaging | F | file labels | `ls -Z` | two classes, one inode | **YES (10)** | P2-D |
| HLD-P2-011 | Capabilities bounded, not granted | U-04 | unit | F | `CapabilityBoundingSet` | `CapBnd` | out-of-contract capability | **open finding** | P2-D |
| HLD-P2-012 | Audit rules readable without mutation authority | none | audit class | F | **unidentified** | — | SELinux `nlmsg_write` denial experiment | **YES (6)** | P2-E |
| HLD-P2-013 | New acquisition mode admitted only with a mechanism | `coverage.py`, ruling D | `coverage` | F | schema | — | — | **YES** | P2-F |
| HLD-P2-014 | Privilege receipt is `PROVENANCE`, auxiliary | `SCOPE-045`, `D-115` | receipt | F | serialization | manifest binding | change receipt, hold state | no | P2-F |
| HLD-P2-015 | Privilege metadata never alters `state_hash` | `D-115` | `snapshot` | F | hash construction | recompute both | receipt change with state constant | no | P2-F |
| HLD-P2-016 | No fourth digest is introduced | `D-115` | `snapshot` | F | `auxiliary_artifacts{}` | — | — | no — resolved here | P2-F |
| HLD-P2-017 | Kernel-observed facts separated from helper claims | §10 | receipt | F | schema | independent `/proc` read | receipt claiming what the kernel denies | no | P2-F |
| HLD-P2-018 | Minimization happens inside the worker | account contract | worker | F | worker code + response schema | response schema | worker returning a raw line | no | P2-C |
| HLD-P2-019 | Declining privilege is not collection failure | R1.5-P | planner | F | status mapping | evidence limits | declined plan rendered as failure | no | P2-F |
| HLD-P2-020 | Confinement reported, never assumed | P2-N10 | receipt | F | runtime observation | live context | policy present, not enforcing | no | P2-D |
| HLD-P2-021 | Core independent of init, distro, language | P2-N7/8/9 | core contract | F | contract | backend matrix | core calling `systemctl` | no | P2-D |
| HLD-P2-022 | Negative harness outside the production API | §14.1 | qualification | F | packaging | authorization layout | test flag on the production worker | no | P2-G |
| HLD-P2-023 | S3 never acquires authority semantics | §14 | S3 | F | signature | code review | S3 gaining a privilege parameter | no | all |
| HLD-P2-024 | `hostio` unmodified by P2 | §13 | `hostio` | F | header + layering | `meta:privilege` | privilege branch in `hostio` | no | P2-C |
| HLD-P2-025 | One endpoint model per host, never two | §6 overlap | packaging | F | packaging | installed policy inventory | both backends installed | no | P2-D |
| HLD-P2-026 | Signing verifiable offline | §20a.2 | release | F | key-based signature | offline verify | keyless-only flow | **YES** | after `signing` |
| HLD-P2-027 | No competitive framing anywhere | `CLAUDE.md` §2, C-06 | docs | C | doc gate | `check_docs_truth.py` | C-06 injection | no | done |
| HLD-P2-028 | No attestation language without attestation | owner directive | docs | C | doc lint | review | — | no | done |

## 26. HLD quality gates

| Gate | State |
|---|---|
| 0 unexplained architecture contradictions | **met** — every contradiction in §16 and §24 carries authority, class and path |
| every contradiction has an owner or measurement path | **met** |
| every new privilege claim has enforcement, verification and a negative test | **NOT met** — two rows in §22 are `CLAIM_NOT_YET_PROVEN` |
| every new component has one responsibility | **NOT met** — endpoint and sudo fallback overlap (§6) |
| no union authority behind a generic helper | met in design; unprovable until P2-D |
| R1.5-P semantics preserved | **met**, with the acquisition-mode addition identified rather than smuggled |
| D-115 semantics preserved | **met** — and no fourth digest introduced |
| S3 semantics preserved | **met** |
| collectors remain unprivileged | **met** — no collector is touched |
| portable core not tied to systemd/SELinux/AppArmor | **met** after the backend refactor |
| implementation language not frozen prematurely | **met** — withdrawn |
| audit operation remains unresolved | **met** |
| roadmap dependencies explicit | **met** |

Two gates are not met. The verdict cannot be ALIGNED while that is true, independently of
the freeze-set finding.

## 27. Owner decisions — collapsed

P2-A proposed eight. This review reduces them, because most were consequences rather than
choices.

**One decision comes first and gates all others:**

```
ROOT  Does Freeze Set 2 open for design work now?

      SCOPE-072 (frozen) defers the entire privileged execution model to Freeze Set 2
      and requires it proven in the VM corpus rather than in prose. Until this is
      answered, IQ-024 through IQ-027 cannot be decided without amending a frozen
      requirement one clause at a time.
```

**Decided by ROOT, not separately:** IQ-024 (compiled worker), IQ-026 (systemd units),
IQ-027 (sudo and daemon policy). Each is a mechanism `SCOPE-070` already prohibits for W1
and `SCOPE-072` already defers. They become live questions the moment Freeze Set 2 opens,
and are not live now.

**Remain genuine owner decisions, after ROOT:**

| # | Decision | Why it is not measurable |
|---|---|---|
| 1 | Operations that cannot demonstrate read-only kernel authority: excluded, or admitted under a separately named class not claimed read-only | a product-scope judgement |
| 2 | On a MAC-less platform: run with reported weaker confinement, or refuse | a risk-appetite judgement |
| 3 | Constrained device architecture A or C (§19) | each carries a different blocker, one of them the egress prohibition |
| 4 | Third-party audit scope and timing | budget |
| 5 | Signing approach, once `signing` leaves Planned — key-based is the only form compatible with offline verification | a procurement and operations judgement |

**Withdrawn as owner decisions** — this review answered them from evidence: per-class
endpoints (mechanically required by P2-N6 plus the trust model, not a preference);
per-class executable paths (follows from SELinux label semantics); the contract file
location (follows `scripts/ci/*.json` convention); a fourth digest (not justified; D-115
suffices).

**Not owner decisions at all** — measurement resolves them: implementation language (P2-B);
whether the first operation needs a capability or reaches the file by group membership
(P2-C); SELinux netlink separability (P2-E); constrained-profile budgets (P2-B).

## 28. Measurements required

| # | Measurement | Stage | Decides |
|---|---|---|---|
| M1 | Rust / Go / C baseline on x86_64, aarch64, constrained ARM: binary size, RSS, peak RSS, startup, threads, FDs, syscall inventory, seccomp allowlist size, dependencies, reproducibility, cross-compilation and packaging cost | P2-B | language |
| M2 | Can a dedicated identity in the `shadow` group read `/etc/shadow` on each corpus distribution without any capability | P2-C | whether the first operation needs a capability at all |
| M3 | SELinux `netlink_audit_socket`: read-side permitted, `nlmsg_write` denied, with the denial observed | P2-E | whether the audit operation can exist |
| M4 | AppArmor netlink mediation granularity | P2-E | audit operation on Debian-family |
| M5 | `AmbientCapabilities` versus `CapabilityBoundingSet` behaviour in the corpus | P2-D | closes U-04 |
| M6 | SELinux label behaviour across hardlinked and copied executables | P2-D | confirms HLD-P2-010 |
| M7 | Constrained-profile baselines on representative hardware | P2-B | acceptance budgets, which are not invented beforehand |

## 29. Roadmap alignment

```
CURRENT MAINLINE — unaffected by anything in this review
    D-83 governance closure
    mounts formal closure (af41b67)
    NSS / hostname          unprivileged, R1.5-P semantics
    Batch 3 closed
    Batch 4
    R1.5 inventory stabilized

P2 DESIGN LANE
    P2-A  ->  THIS REVIEW  ->  ROOT decision  ->  P2-A freeze
    then P2-B .. P2-H, gated on Freeze Set 2 being open

R2  may consume protected evidence only for an operation class P2 has qualified
```

Verified: P2 blocks no unprivileged R1.5 work. Every current collector, mounts included,
runs unprivileged and is untouched by this lane. The only coupling is that R2 assurance
claims needing protected evidence wait for the relevant P2 class.

## 30. Proposed document changes

None applied by this review. Proposed, for owner approval:

| Document | Change | Reason |
|---|---|---|
| `R15P2_LEAST_AUTHORITY_ACQUISITION_CONTRACT.md` | add `SCOPE-070/071/072` to §2 as the primary conflict, above the register-tier ones | the frozen tier was missed |
| same | correct §9: `AmbientCapabilities` grants rather than bounds; cite U-04 | P2-A defect |
| same | reclassify IQ-025 and IQ-027 as frozen-contract conflicts | tier was understated |
| same | record that per-class endpoints and per-class paths are derived, not owner preferences | removes two false owner decisions |
| `CLAUDE.md` §1 | `FROZEN_MANIFEST.sha256` does not exist; the lock is the per-set manifests | **owner-only**; precedence anchor is stale |
| `CLAUDE.md` §2 | `lib/isedraf/launcher/` does not exist | **owner-only**; names a directory that is absent |
| `DECISIONS_REGISTER.md` D-26, D-27 | mark as Freeze Set 2 design, not W1 permission | **owner-only**; both read as current authority today |
| `docs/development/GOVERNANCE_GAPS.md` | record the two stale governance pointers alongside the D-83 gap | same class of defect |
