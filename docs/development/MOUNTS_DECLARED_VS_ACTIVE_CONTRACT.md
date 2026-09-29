<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Mounts — declared-vs-active contract

Status: APPROVED
Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, GOV-001, GOV-002

**Owner-reviewed, rulings C–F applied.** `lib/isedraf/mounts/` is not yet written against
this corrected contract; an earlier implementation existed and is superseded — its
options-subset equivalence rule is exactly what ruling C rejects, so it is historical
evidence of a failed assumption and not authority for anything.

Every example below is structural. Real device UUIDs and the developer host's disk layout
are not reproduced; synthetic values preserve each finding's shape.

## 0. The S3 gaps this contract found — both CLOSED centrally

Writing this contract, before any code, found two defects in the shared comparator. Both
were fixed in S3 by the coordinator, never in this lane.

**Tri-state equivalence.** `Comparator.equal()` returned a bool, so a pair whose
equivalence could not be decided became `MODIFIED` — a confident mismatch manufactured
from missing evidence. On an ordinary host every fstab line declares `UUID=` while every
active mount reports a kernel device path, so that was every row, not an edge case.
`compare_pair()` now returns `EQUIVALENT` / `DIFFERENT` / `UNKNOWN`, and `UNKNOWN` maps to
`EQUIVALENCE_UNKNOWN`.

**Positional pairing (`IQ-019`).** `_pair` compared the first `min(len(d), len(a))`
records BY LIST POSITION and marked only the leftovers ambiguous, while its docstring
claimed it never guessed. Multiplicity on either side is now `AMBIGUOUS` for every record
in the group, and the result is asserted invariant under reordering either source.

An earlier draft of §6 claimed "S3 already does this … unchanged". That was false, and the
independent adversarial pass measured it. The claim is removed rather than softened.

### Three axes, frozen

```text
ACQUISITION COMPLETENESS  !=  PAIRING DETERMINACY  !=  SEMANTIC COMPARABILITY
```

Two files acquired perfectly whose records cannot be paired are COMPLETE acquisition
evidence about an ambiguous situation. A pair that cannot be judged leaves acquisition
complete too. Only the sources decide coverage.

## 1. Active evidence source

**Preferred: `/proc/self/mountinfo`.** Measured against `/proc/mounts` on the same host:
identical line count, and `/proc/mounts` **loses** the mount ID, the parent ID and the root
field. Without mount ID there is no stable record identity; without the root field a
subvolume or bind mount is indistinguishable from a whole-filesystem mount.

`findmnt` is **not** a production dependency. It may be used as a development oracle only.

### Source space — frozen (ruling E)

```text
collection_root == "/"     source /proc/self/mountinfo
                           scope  LIVE_CURRENT_COLLECTION_NAMESPACE

collection_root != "/"     source <collection_root>/proc/self/mountinfo
                           scope  FIXTURE_OR_OFFLINE_EVIDENCE
```

A non-root collection root MUST NEVER fall back to the running machine's live `/proc`.
And fixture evidence is never described as the current namespace of the process executing
ISEDRAF — a synthetic `mountinfo` under a corpus root describes whatever produced it, not
this process. The two scopes are distinguishable in provenance; no second status universe
is invented for the distinction.

### Namespace scope — frozen

```text
/proc/self/mountinfo  =  active mounts visible in the COLLECTOR'S CURRENT mount namespace
                      != every mount on the physical host
```

Measured: `/proc/self/ns/mnt` is readable and yields a namespace identity;
**`/proc/1/ns/mnt` is not readable unprivileged**, so the collector cannot prove it shares
pid 1's namespace. It may be in a container, a `systemd` service sandbox, or a private
namespace, and it cannot tell.

The evidence is therefore labelled `ACTIVE_MOUNTS_CURRENT_COLLECTION_NAMESPACE` and carries
the namespace identity it observed. It is never labelled "host active mounts".

`fallback policy`: none. If `mountinfo` cannot be read, the active side is `NOT_TESTED` or
`ERROR` per SCOPE-022 with the R1.5-P access outcome attached. Falling back to
`/proc/mounts` would silently drop record identity, and a comparison whose identity
silently degraded is worse than one that says it could not run.

`completeness`: `COMPLETE` only when `mountinfo` was read fully **and** the namespace
boundary is recorded. The namespace boundary does not make it incomplete — it is complete
*over the stated universe*, which is what completeness has meant since R1.5-P.

## 2. Declared evidence source

`/etc/fstab` only, under the collection root. No `fstab.d`; Linux has no such directory.

**Ruling D — source status and universe completeness are separate.** An earlier draft said
`NOT_TESTED` and "not incomplete" in one breath, which cannot both hold under the frozen
coverage model. They are two questions:

| `/etc/fstab` | source status | records | declared-fstab universe | absence claims |
|---|---|---|---|---|
| absent | `NOT_TESTED` / `NOT_FOUND` | zero | **COMPLETE** | permitted |
| permission denied | `NOT_TESTED` / `PERMISSION_DENIED` | zero | INCOMPLETE | **forbidden** |
| partially parsed | `PARTIAL` | those that parsed | INCOMPLETE | **forbidden** |

An absent file fully establishes that *this source* contributes zero declarations, so the
universe it bounds is completely known. The universe is **`FSTAB DECLARATIONS`** and
nothing wider: it does not establish that there are no systemd mount units, no generator
output and no transient mounts. Active mounts may therefore legitimately be `ACTIVE_ONLY`
relative to it, and the report must carry that scope so the reader knows what "only" means.

- **missing** → see the table above.
- **unreadable** → `NOT_TESTED` with `PERMISSION_DENIED`, or `ERROR` for an I/O failure, with
  `required_access = ACCESS_FILE_READ`.
- **malformed line** → the record is **retained** with `parse_status`, never skipped, and the
  side becomes `PARTIAL`. A dropped line is a declaration the operator wrote and the tool
  denies exists.
- `completeness`: `COMPLETE` when the file was read in full and every line parsed.

### `fstab` is NOT forced through S1

Six positional fields, no delimiter, no keys. Manufacturing keys to reuse S1 would be reuse
for its own sake — the fifth domain to decline S1, for a fifth specific reason.

Preserved verbatim, resolved not at all:

    source_spec · target · fstype · options_raw · dump · pass
    source_line · ordinal · parse_status

`UUID=` · `LABEL=` · `PARTUUID=` · `PARTLABEL=` · device aliases · network sources are kept
**as written**. Resolving them would require an authoritative resolution source this batch
does not define.

## 3. Declared record identity

```text
source file + source_line          (ordinal is provenance, not identity)
```

Two declarations are distinct if they are different lines. **Measured necessity:** the
development host declares the *same* `UUID=` for two different targets, distinguished only
by `subvol=` **inside the options field**. Source alone is not identity on the declared side.

## 4. Active record identity

```text
mount namespace identity + kernel mount ID
```

Mount ID is the kernel's own identity and is unique within a namespace. It is why
`mountinfo` is preferred: `/proc/mounts` cannot supply it.

**Mount ID is NOT stable across reboots or remounts.** It identifies a record within one
observation, which is all a same-instant comparison needs. It must never be used as a
baseline key.

## 5. Cross-source candidate key — not identity

```text
candidate key = normalized target path
```

It *permits an attempted pairing*. It is **not** record identity, and the distinction is
load-bearing.

**Measured on the development host:** `/proc/sys/fs/binfmt_misc` appears **twice** in
`mountinfo` — an `autofs` mount and a `binfmt_misc` mount stacked on the same target. One
target, two active records, different filesystem types. Any model treating the target as
unique identity is already wrong on a stock installation.

Normalization is lexical only: no trailing slash except for `/`, no `realpath`, no symlink
resolution. Resolving would consult the live filesystem and make identity depend on it.

## 6. Multiplicity

| Case | Behaviour |
|---|---|
| duplicate `fstab` target | every record preserved; no first-wins, no last-wins |
| duplicate `fstab` source | not special — source is not identity |
| stacked / overmounted active target | every record preserved; the topmost is not privileged |
| ambiguous pairing | `AMBIGUOUS` for every record under that key |

`AMBIGUOUS` unless a stronger authoritative pairing exists. **No such stronger pairing is
proposed for R1.5**: matching an `fstab` line to one of two stacked mounts would require
deciding which the kernel applied, which is resolution.

S3 does this **since `IQ-019`**, and did not before: an earlier draft of this contract
claimed it "survives contact with reality unchanged", and the adversarial pass measured
that claim false. `_pair` had been pairing positionally up to `min(len(d), len(a))`.

## 7. Semantic equality

### Required equivalence dimensions — frozen

```text
CANDIDATE CORRESPONDENCE     normalized target      pairing only, NOT a dimension

REQUIRED EQUIVALENCE         source identity
                             filesystem type
                             mount-option semantics

DECLARED-ONLY FACTS          dump · pass
ACTIVE-ONLY FACTS            mount_id · parent_mount_id · root · major:minor · propagation
NOT GENERICALLY COMPARED     mountinfo.root <-> subvol/bind declaration semantics
```

Three-valued aggregation over the required dimensions:

```text
any required dimension definitely DIFFERENT          -> DIFFERENT
none different, one or more UNKNOWN                  -> UNKNOWN
all authoritatively EQUIVALENT                       -> EQUIVALENT
```

**Mount-option semantics are a required dimension and stay one.** An earlier draft removed
them so that `MATCHED` would be reachable, which optimises the result distribution rather
than the evidence: `ro,nodev` declared against `rw` active would have become `MATCHED`
while observable mount semantics differed materially. Because Batch 3 defines no
authoritative option normalization, that dimension is generally unresolved, so **zero
MATCHED records on a normal host is the correct outcome** and is not a gap to close.



**Definitely comparable**

    target          both sides, lexically normalized
    fstype          both sides, with one caveat below

**Conditionally comparable — undecidable without a resolution source**

    source_spec     UUID= / LABEL= / PARTUUID= vs a kernel device path
    options         declared userspace options vs kernel-reported options

**Intentionally not compared**

    dump, pass                  no active counterpart exists; fstab-only fields
    mount ID, parent ID, root   no declared counterpart exists
    propagation flags           kernel topology, never declared in fstab

### Why options cannot be compared today

Measured, structurally:

```text
declared   subvol=root,compress=zstd:1,noatime
active     rw,seclabel,noatime,compress=zstd:1,ssd,discard=async,
           space_cache,subvolid=257,subvol=/root
```

Three distinct problems in one line. The kernel **adds** options never declared
(`seclabel`, `ssd`, `discard`, `space_cache`, `subvolid`). It **rewrites** one:
`subvol=root` declared, `subvol=/root` reported — same subvolume, different text. And
`defaults` expands to a set that is filesystem-dependent and never appears literally.

No normalization is proposed, because none can be stated to preserve Linux semantics for
all filesystems.

**Ruling C — the subset rule is rejected.** An earlier implementation treated
*declared options ⊆ active option strings* as `EQUIVALENT`. That is not authoritative
Linux mount equivalence and the observed host disproves it: the kernel adds options never
declared, declaration-only options such as `noauto` and `nofail` never appear in the
active set at all, and representations are rewritten. Batch 3 implements no mount-option
semantics engine, and no such heuristic may be introduced to make `MATCHED` reachable.

The rule is therefore:

```text
every dimension the adapter requires, authoritatively equivalent  -> EQUIVALENT
an authoritative comparable dimension contradicts                 -> DIFFERENT
any required dimension unresolved                                 -> UNKNOWN
```

**`MATCHED` is reachable in principle and is not a target metric.** It is acceptable —
expected — for ordinary real-host pairs to be `EQUIVALENCE_UNKNOWN`. Adding UUID/LABEL
resolution, option normalization or bind/subvolume resolution to improve that ratio is
forbidden: the ratio is not the goal, and later source-resolution work can legitimately
convert some of these into stronger conclusions.

### And `fstype` has a caveat

`autofs` on a target that later carries a real filesystem is the `binfmt_misc` case. The
declared fstype and the active fstype can legitimately differ while nothing is wrong.

## 8. Unknown comparability — the gap

Exact representation required: **a paired record whose equivalence could not be decided.**
No current S3 value carries it. See §0.

## 9. Ordering

```text
fstab line order      PROVENANCE. Retained as source_line/ordinal.
                      Semantically relevant to boot sequencing, which R1.5 does not model.
mountinfo order       PROVENANCE, and topologically meaningful (parent before child).
                      Retained; never sorted.
comparison            order_sensitive = FALSE
```

Mounts are **not** order-sensitive in the audit-rules sense: reordering two unrelated fstab
lines does not change the declared configuration. Retaining order as provenance while
comparing by identity is the correct split.

## 10. Completeness, per side

| Declared | Active | Absence that may be asserted |
|---|---|---|
| COMPLETE | COMPLETE | both directions |
| COMPLETE | PARTIAL | `ACTIVE_ONLY` only |
| PARTIAL | COMPLETE | `DECLARED_ONLY` only |
| PARTIAL | PARTIAL | neither; `COUNTERPART_UNKNOWN` |

### Worked cases

**Declared COMPLETE, active PARTIAL.** A declared `/data` with no active counterpart
observed → **not** `DECLARED_ONLY`; the counterpart may be in the part of the active side
that was not observed → `COUNTERPART_UNKNOWN`. An active `/tmp` with no declaration →
`ACTIVE_ONLY` **is** provable, because the declared side is complete.

**The mirror.** Declared PARTIAL, active COMPLETE: a declared `/data` with no active
counterpart → `DECLARED_ONLY` is provable. An active `/tmp` with no declaration →
`COUNTERPART_UNKNOWN`.

## 11. R1.5-P acquisition and coverage

| Source | operation | typical outcome |
|---|---|---|
| `/etc/fstab` | `OP_FILE_READ` | `READ_OK` · `NOT_FOUND` · `PERMISSION_DENIED` |
| `/proc/self/mountinfo` | `OP_FILE_READ` | `READ_OK` · `NOT_SUPPORTED` where `/proc` is absent |
| `/proc/self/ns/mnt` | `OP_FILE_METADATA` | `READ_OK` · `PERMISSION_DENIED` |

`absence_claim_allowed` is derived centrally and consumed, never authored. No prose-only
failure semantics: "could not read /etc/fstab" is a sentence for people, beside the fields.

The namespace boundary is recorded as coverage context, since R1.5-P now has somewhere to
put exactly this kind of observation boundary.

## 11a. Malformed active records

A malformed `mountinfo` line is never silently dropped. Dropping one denies that an active
mount exists, which manufactures a false `DECLARED_ONLY` — the worse direction, since §2's
retention rule was written for the declared side only.

```text
retained as parse-failure evidence, with its ordinal and provenance
content preserved losslessly
ACTIVE universe becomes INCOMPLETE
absence claims against unseen active counterparts are forbidden
```

So: a readable `mountinfo` with one unparsed record is **not** a COMPLETE active universe.

## 11b. Undecodable bytes in a target

The project's lossless-byte doctrine, unchanged: no replacement character, no silent
normalization.

```text
cleanly representable      target = text
otherwise                  target = null, exact bytes retained in the established
                           hex-identity field

UNDECODABLE  !=  REPLACEMENT-DECODED
```

Correspondence uses the exact path when one can be safely formed. If it cannot, no Unicode
target is fabricated: the evidence is retained and pairing stays unresolved.

## 11c. Omitted `dump` and `pass`

A four-field fstab entry is **valid**. `fstab(5)` treats an omitted field 5 or 6 as `0`.

```text
semantic value        0
declaration record    whether it was omitted or explicitly written
```

Deterministic grammar interpretation, not a security inference — and "wrote 0" stays
distinguishable from "wrote nothing" at the raw evidence layer.

## 12. Non-claims

    DECLARED_ONLY   is NOT "the mount failed"
    ACTIVE_ONLY     is NOT "unexpected" or "insecure"
    MODIFIED        is NOT "misconfigured"
    AMBIGUOUS       is NOT "suspicious"

`noauto` is the proof that the first two would be wrong. The development host declares
`/mnt/backup` with `noauto,nofail` **and** has it actively mounted. A declaration saying
"do not mount at boot" coexisting with an active mount is normal operation, and any rule
reading "declared + active = working as configured" would be wrong about it in the other
direction too.

No temporal vocabulary. `ADDED` / `REMOVED` describe change over time; this compares two
sources at one instant.

## 13. Collection-root testing rule — ruling F

**Every path-sensitive acquisition component that accepts a collection root is tested at a
non-root fixture root AND at the production root `/`.**

The rule exists because a whole class of defect is invisible to fixture tests, and one
reached frozen code: `authorizedkeys._inside("/", …)` returned `False`, so at the only root
production uses the lane read nothing, while 191 tests — including an independent
adversarial pass that specifically attacked containment — passed. No fixture root can be
`/`, so no fixture test could have found it.

What the pairing catches:

    root + separator degenerating at "/"      double-rooting
    live-host fallthrough                     component-prefix mistakes

Tests must exercise `collection_root="/"` on **pure path logic**; this is not licence to
read arbitrary live-host state. `hostpath` already does this and is the model.

**Recorded for ARCH-03:** identify every collection-root-sensitive path that has only
temp-directory coverage. No new gate is created during this lane — a gate keyed on path or
name conventions would be brittle, and ARCH-03 is where the question belongs.

## 14. Open questions for the owner

1. **`S3_DOMAIN_CONTRACT_GAP`** — which resolution in §0? Nothing can be implemented until
   this is answered, because the first entry on an ordinary host needs it.
2. **Is a UUID→device resolution source in scope for Batch 3?** If yes it is a third
   evidence layer (`RESOLVED`) with its own acquisition, completeness and coverage, and it
   is a materially larger batch. If no, source equivalence stays undecidable and §0 becomes
   unavoidable.
3. **Should the active side record propagation and topology** (`parent_id`, `shared:`,
   `master:`) as evidence now, or defer? They are real state with no declared counterpart.
4. **Does `mountinfo`'s `root` field belong in the comparison at all?** It distinguishes a
   bind or subvolume mount from a whole-filesystem mount, and has no `fstab` counterpart
   except inside the options text.
