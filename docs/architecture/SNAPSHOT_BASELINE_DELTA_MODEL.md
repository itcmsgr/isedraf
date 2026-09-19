# ISEDRAF — Snapshot, Baseline and Delta Model

Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0
Requirement IDs `NORM-###`, `SNAP-###`, `BASE-###`, `CMP-###`, `DELTA-###`, `STORE-###`


## 1. Pipeline

**NORM-001 (D-33) SHALL** collection → normalization → **comparability** → delta → interpretation →
views/export. Comparability is a distinct stage and SHALL NOT be folded into delta.

## 2. Declared / resolved / active

**NORM-010 (D-34, A8) SHALL** Three state dimensions. `MISMATCH` means **resolved ≠ active**. Declaration
conflicts are context, not `MISMATCH`. Not every domain has all three; a domain SHALL declare which it has.

| Prototype domain | declared | resolved | active | `MISMATCH` meaning |
|---|---|---|---|---|
| Host identity | – | – | ✓ | n/a |
| Users / groups | `/etc/passwd`, `/etc/group`, `/etc/shadow` | `getent` | – | n/a |
| Local sudo | `/etc/sudoers`, `sudoers.d` | `cvtsudoers -f json` | – | declared rules not reflected in the resolved policy → context |
| `authorized_keys` | file contents | – | – | n/a |
| Password / account ageing | `/etc/shadow` | `getent shadow` | – | n/a |
| SSH | `sshd_config` + includes | `sshd -T` | running process config | resolved config ≠ what the running daemon loaded |
| Mounts | `/etc/fstab` + `.mount` unit files | `systemctl show` | `findmnt -J` | fstab/unit intent ≠ kernel mount options |
| Audit | `/etc/audit/rules.d/*` | merged `audit.rules` from `augenrules` | `auditctl -l` / `-s` | declared-and-immutable vs loaded-and-unlocked is resolved ≠ active (test 10, R-18) |
| Journald | `journald.conf` | `journalctl --header` | runtime storage state | configured persistence ≠ actual storage |
| Time sync | config | `timedatectl show` | sync state | configured source ≠ active source |

## 3. Collection status vs evaluation result

**CMP-001 (D-35) SHALL** Collection status (`COLLECTED`, `PARTIAL`, `NOT_TESTED`, `ERROR`) and evaluation
result (`PASS`, `FAIL`, `PARTIAL`, `MISMATCH`, `NOT_APPLICABLE`, `MANUAL_REVIEW`, `NOT_EVALUATED`) are
**separate fields with separate counters** in every report. They SHALL NEVER be merged into one column.

**CMP-002 (D-35) SHALL NOT** `NOT_TESTED` or `ERROR` SHALL NEVER be rendered as `PASS`, `FAIL`, `REMOVED`
or `SECURITY_IMPROVEMENT`.

## 4. State vs observation — invariant I-1

**NORM-020 (D-36, D-102, T-16) SHALL** Every normalized field carries exactly one of the four categories
defined normatively in `SCOPE-045` — `STATE`, `OBSERVATION`, `DERIVED`, `PROVENANCE`. **Only `STATE` enters
the section hash and the delta.** `OBSERVATION`, `DERIVED` and `PROVENANCE` SHALL NEVER cause `CHANGED`.

| Always observation, never state |
|---|
| last login time · PID · uptime · journal size on disk · "days remaining" · current timestamp · run ID · free space · oldest/newest observable event time |

**NORM-021 (D-36) SHALL** Relative values are computed at **render time** from absolute facts. A relative
value SHALL NEVER be stored as canonical state (D-74).

> This requirement alone is what makes an unchanged host stay quiet. Acceptance tests 2 and 14 test it.

## 5. Canonical serialization

**NORM-030 (D-37, A16) SHALL** Before hashing: UTF-8; object keys sorted by Unicode code point; a defined
array ordering per entity; no insignificant whitespace; exactly one timestamp format (UTC RFC 3339);
types preserved (a number SHALL NOT become a string); locale-independent throughout.

**NORM-031 (D-37, W-03) SHALL** A section hash is
`HASH_FRAME_V1("ISEDRAF:STATE:V1", canonical_bytes(section_state))` — computed over the **canonical
normalized state**, never over the raw collected bytes. This requirement states *what is hashed*; the
framing is `NORM-038`'s and is not restated (`NRM-001`).

**NORM-033 (D-97, T-03) SHALL** Hash algorithm **SHA-256**, rendered `sha256:<lowercase-hex>`.

**NORM-034 (D-97, W-23) SHALL** Canonical state permits exactly six types: `null`, boolean, **integer**,
UTF-8 string, array, object. **No floats.** Duplicate JSON keys are **rejected on parsing**; object keys
are unique strings. An integer outside **[−2⁶³, 2⁶³−1]** is a **normalization error**: the section becomes
`ERROR` with reason `INTEGER_OUT_OF_RANGE`. It is never truncated, saturated or stringified — the frozen
serializer does not enforce the bound, so normalization must.

**NORM-035 (D-97, W-06, W-07) SHALL** **The escape alphabet is normative; the bytes live here.** Object
keys sorted by Unicode code point; separators exactly `","` and `":"`; encoded UTF-8, **no BOM**; followed
by **exactly one LF**, which **is** part of `canonical_bytes` and is hashed.

The output is **RFC 8259 JSON text** with the deviations frozen in this requirement. Integers are rendered
in decimal, a leading `-` only for negatives, no leading zeros, no `+`, no `-0`; `0` is `0`. Literals are
`true`, `false`, `null`. Within a string, escape **exactly** these and nothing else:

| Input | Output |
|---|---|
| `"` | `\"` |
| `\` | `\\` |
| U+0008 U+0009 U+000A U+000C U+000D | `\b` `\t` `\n` `\f` `\r` |
| any other U+0000–U+001F | `\u00xx`, **lowercase** hex |
| U+007F (DEL) | `\u007f` |
| U+0080–U+009F (C1) | `\u00xx`, lowercase hex |
| U+2028, U+2029 | `\u2028`, `\u2029` |

Everything else — including all other non-ASCII — is emitted as **raw UTF-8**. `/` is **never** escaped.
No `\uXXXX` form is used for any code point not listed above.

> Non-normative note: CPython's `json.dumps(value, ensure_ascii=False, sort_keys=True,
> separators=(",",":"), allow_nan=False)` is **not** byte-equal to this — measured, it emits DEL, C1 and
> U+2028 raw. An implementation using it MUST post-process those four rows. This mismatch is why the
> algorithm is written out rather than delegated (W-06), and it removes the `OUT-015` conflict, since the
> canonical form now escapes exactly what `OUT-015` requires (W-07). The trailing LF **is** part of
`canonical_bytes` and is hashed. No Unicode normalization is applied; valid Unicode is preserved exactly.
Arrays are **order-preserving** — the serializer never reorders them. Deterministic ordering of
semantically set-like data is the responsibility of **normalization**, not of the serializer.

**NORM-036 (D-97, W-08, W-24) SHALL** A collected byte string is decoded **strict UTF-8**. On failure, or
when the decoded string contains U+0000 or an unpaired surrogate, **the entire field** is replaced by the
tagged object below. The decision is made at **normalization**, per field, so **the serializer never sees a
string it cannot encode** — measured, an unpaired surrogate otherwise raises `UnicodeEncodeError` at
`.encode("utf-8")` with no defined exit code.

`__isedraf_encoding` is **reserved**: a normalizer SHALL NEVER emit it except as this exact **two-key**
object, and any other occurrence in host-derived data is a normalization error. Where a field also has a
frozen field-specific grammar, that grammar decides acceptance first — the precedence rule is `NORM-042`'s
and is not restated here (`NRM-001`). Decoders reject unknown or
extra keys.

```json
{ "__isedraf_encoding": "base64", "data": "<RFC 4648 standard base64, with padding>" }
```

**NORM-037 (OD-10, T-03, RESOLVES OD-10) SHALL** Every set-like field has a **field- or schema-defined
stable ordering applied before serialization**. No generic canonicalizer guesses array semantics. The
per-entity ordering keys are a property of the entity schema, and each SHALL be **total** — a tie means two
valid canonical forms and two hashes. Golden fixtures assert totality.

**Applicability to W1-A (`Z-11`, NEW).** W1-A's frozen objects — `IDENT-002`'s state object, `SNAP-020`'s
`snapshot_manifest_core`, `SNAP-021`'s `method` object and `STORE-024`'s `record_core` — contain **no
array-typed field**. `NORM-037` is therefore **`NOT_APPLICABLE_TO_W1A`**: there is nothing whose ordering
could be total or otherwise, and "golden fixtures assert totality" has no W1-A surface. Object *key*
ordering is `NORM-035`'s, not this requirement's. This is recorded rather than satisfied by a fabricated
case, because a vacuous test reported as coverage is worse than a stated gap.

The premise is **enforced, not promised**: the vector verifier walks every canonical artifact and **fails**
the moment an array appears anywhere in W1-A evidence. The first set-like field to enter the slice is the
explicit trigger that makes this requirement applicable, and it cannot arrive quietly.

**NORM-038 (D-97, U-03) SHALL** **One hash framing rule everywhere.** Ambiguous concatenation
(`H(A || B || C)`) SHALL NOT be used. The frame is:

```text
HASH_FRAME_V1(domain, component_1 … component_n) =
    SHA-256( ASCII(domain)
             || uint64_be(len(component_1)) || component_1
             ...
             || uint64_be(len(component_n)) || component_n )
```

Components are **raw bytes** — raw 32-byte digests where a component is a hash, never the rendered
`sha256:` string. Domain strings SHALL be **mutually non-prefixing**; the golden vectors assert it (U-36).

**Domains frozen for W1-A, with their exact ordered component lists** (X-03). A domain without a
component list is not a specification — and neither is a component list over an undefined object, so every
object named here has a frozen field table.

| Domain (ASCII) | Ordered components |
|---|---|
| `ISEDRAF:HOST-ID:V1` | `utf8(normalized_machine_id)` — `IDENT-005` |
| `ISEDRAF:STATE:V1` | `canonical_bytes(section_state_object)` — `IDENT-002` |
| `ISEDRAF:SNAPSHOT-MANIFEST:V1` | `canonical_bytes(snapshot_manifest_core)` — `SNAP-020` |
| `ISEDRAF:LEDGER-RECORD:V1` | `canonical_bytes(record_core)` — `STORE-024` |

Where a component is a hash it is the **raw 32-byte digest**, never the rendered `sha256:` string.

Domains for the baseline revision, evaluation manifest, evidence reference, profile and checkpoint are
**not frozen**: W1-A computes none of them, and speculative bytes are not specified (`D-107`).

**NORM-040 (Z-01, NEW) SHALL** **Canonical representation of `reason`, language-neutral.**

`reason` has exactly **two** semantic states, and the architecture already fixes the canonical-evidence
side: `SNAP-020` declares the field `string | null` and `NORM-034` makes *null* and *absent* distinct with
each field declaring which it uses. Therefore in `manifest_core` the key is **always present**:

| Semantic state | Canonical evidence (`manifest_core`) | Golden-vector sidecar |
|---|---|---|
| a reason exists | `"reason":<token>` — a token from `SNAP-022`'s vocabulary | `expected/reason.txt` **present**: the token, then exactly one LF |
| no reason (`COLLECTED`) | `"reason":null` | `expected/reason.txt` **absent** |

The sidecar rule is derived from the model, not from convenience: it **mirrors `state.canonical`**, which
is already absent when the section is not `COLLECTED`. Presence encodes presence. There is consequently
**no byte string that spells "no reason"**, which is what made the earlier state ambiguous.

**NORM-041 (Z-01, NEW) SHALL** Any other sidecar content is **REJECTED**, never normalized: a present
`reason.txt` whose content is empty, or is a rendering of nothingness in any programming language —
`null`, `nil`, `None`, `undefined`, `nullptr`, `Option::None` — is a verification failure. Those names
appear here only as examples of what is rejected; they carry no normative status. A token outside
`SNAP-022`'s vocabulary is likewise rejected. Exactly one canonical byte sequence exists per permitted
semantic value.

**NORM-039 (D-97, T-03) SHALL** **Golden byte vectors and expected SHA-256 values are release-blocking**,
exercised on Python 3.9 and the current CI Python. No external-reproducibility claim is made until
`NORM-035`, `NORM-037`, `NORM-038` and `NORM-039` all hold. **No formula in any other document may
independently restate this framing** (`NRM-001`).

**NORM-032 (OD-10, SUPERSEDED by `NORM-037`)** The per-entity ordering keys are schema properties, not a
separate proposal table. Normative source: `NORM-037`.

## 6. Host identity and applicability

**SNAP-001 (D-38) SHALL** Host identity is evaluated **before** any comparison. On mismatch the result is
`BASELINE_NOT_APPLICABLE`, exit `4`, and **no diff is produced** (acceptance test 7).

## 7. Snapshot — invariant I-4

**SNAP-010 (D-41, A1, R-03, S-11, S-16, R-21) SHALL** `snapshots/SDS-*/` contains `manifest.json`,
`state/` (per section), `observations/` (per section), `derived/`, `method/` (per-section `PROVENANCE`
including `collector_version` and `source_id` — outside the state hash, or invariant I-3 collapses), and
`evidence/` holding evidence-reference objects plus retained bytes at `evidence/blobs/<sha256>` mode 0600, retention `UNLIMITED_W1` in W1 (W-16). `manifest.json` hashes **every** subtree listed here and states which,
so no evidence an auditor inspects sits outside the integrity boundary (T-17). Once committed it is **treated as immutable by ISEDRAF and never
rewritten by it**. It is **not protected against a local root adversary** — see `EVID-040`. The word
*immutable* SHALL NOT be used unqualified.

**SNAP-018 (W-17, NEW) SHALL** **W1 unledgered-snapshot rule**, frozen so the crash window `SNAP-014`
creates has a defined outcome: exactly **one** `SDS-*` newer than the ledger head → append its
`snapshot_committed` record and continue; **more than one** → refuse with reason
`STORE_DISCONTINUITY` and exit `2`. The richer state vocabulary of `SNAP-015` is
`DEFERRED_TO_FREEZE_SET_2`.

**SNAP-019 (X-27, X-06, W1-A) SHALL** Identifier and timestamp grammars, frozen because they enter the
manifest preimage: `snapshot_id` is `SDS-<YYYYMMDDTHHMMSSZ>-<16 lowercase hex>` where the hex comes from a
cryptographic RNG — **never derived from the manifest**, which contains `snapshot_id` and would be
circular. `run_id` and `event_id` use the same grammar with prefixes `RUN-` and `EVT-`. All timestamps are
`YYYY-MM-DDTHH:MM:SSZ`: no fractional seconds, literal `Z`, never `+00:00`.

**SNAP-020 (X-03, W1-A) SHALL** **The snapshot manifest.** `manifest_hash` is excluded from its own
preimage, so there is no circularity:

```text
snapshot_manifest_core:
    schema_version        integer, W1-A literal 1
    host_id               string | null  binds the snapshot to its host (SCOPE-048, Y-15)
    snapshot_id           string   (SNAP-019)
    run_id                string   (SNAP-019)
    created_at            string   (SNAP-019)
    state_root            string   "DEV" | "PRODUCTION" — PRIV-004's literal spelling, never a
                          restatement (Y-03). PROVENANCE.
    engine_version        string  the VERSION file verbatim; W1-A literal "0.0.0-pre"   (Y-08)
    sections              object, keys sorted

sections.host_identity:
    collection_status     COLLECTED | NOT_TESTED | ERROR       (IDENT-004)
    state_hash            "sha256:<64 hex>" | null             (null unless COLLECTED, Y-07)
    reason                string | null                        (null when COLLECTED, Y-07)
    collector_id          string   W1-A literal "host_identity"
    collector_version     integer  W1-A literal 1
    parser_version        integer  W1-A literal 1
    classification_table_version  integer  W1-A literal 1      (CMP-020 requires it, Y-05)
    source_id             string   W1-A literal "file:/etc/machine-id"   (IDENT-006)

manifest_hash = HASH_FRAME_V1("ISEDRAF:SNAPSHOT-MANIFEST:V1",
                              canonical_bytes(snapshot_manifest_core))
```

Stored `manifest.json` is **`canonical_bytes`** of `{"manifest_core": ..., "manifest_hash": "sha256:..."}`
(Y-12). Every key is mandatory and present — optionality would change the bytes. `profile_id` and
`profile_version` are **absent in W1-A**: there is no profile until W1-B.

**SNAP-021 (Y-06, W1-A) SHALL** **A W1-A snapshot directory contains these three things and nothing
else**: `manifest.json`, `state/host_identity.json` and `method/host_identity.json`. The first and third
are always present; **whether `state/host_identity.json` exists is `SNAP-022`'s rule and is not restated
here** (`NRM-001`, `Z-15`). The earlier wording said *exactly three* unconditionally, which contradicted
`SNAP-022` for every non-`COLLECTED` snapshot — nine of the fifteen golden cases — so the two frozen
requirements disagreed about what is on disk. **Each of the three is `canonical_bytes` of its object** — stated for all three, because stating it for two was how
`state/host_identity.json` acquired two conforming on-disk forms (found while constructing the golden
vector; same defect class as Y-12). `observations/`, `derived/`
and `evidence/` are **not created in W1-A** — `SNAP-010`'s subtree and evidence clauses are scoped to
Freeze Set 2, and `manifest_core` carries no subtree-hash field because there are no other subtrees to
hash. The `method/` object is frozen here, since `IDENT-005`'s `identity_scheme` has no other home:

```text
method/host_identity.json = canonical_bytes({
    "classification_table_version": 1,
    "collector_id": "host_identity",
    "collector_version": 1,
    "identity_scheme": "machine-id-sha256-v1",
    "parser_version": 1,
    "source_id": "file:/etc/machine-id"
})
```

**SNAP-022 (Y-07, W1-A) SHALL** When `collection_status` is **not** `COLLECTED`, the snapshot **is still
committed** — an honest record of what could not be collected is evidence. `state/host_identity.json` is
**not written**, `state_hash` is `null`, and `reason` carries one of the frozen vocabulary:
`SOURCE_ABSENT` · `SOURCE_UNREADABLE` · `SYNTAX_REJECTED` · `INTEGER_OUT_OF_RANGE` · `INTERNAL_ERROR`.

**`INTEGER_OUT_OF_RANGE` has no W1-A producer, and that is stated rather than left to be discovered
(Z-05).** It is the named error of `NORM-034`, which is frozen for W1-A and would raise it if an
out-of-range integer ever entered normalization — but `IDENT-002` freezes the W1-A state object as a
single string field, so no host-derived integer is normalized. It is retained because removing it would
leave `NORM-034`'s own error unnamed; it is **unreachable in W1-A by construction**, and no implementer
should search for a path to it.

**SNAP-023 (Z-08, NEW) SHALL** **When `manifest_core.host_id` is a string, and when it is null.**

`SNAP-020` declares the field `string | null`; no requirement said which outcome produces which. The field
sits **inside the manifest preimage**, so the ambiguity was never cosmetic: two implementers reading the
same frozen text would compute two different `manifest_hash` values for the same host.

`manifest_core.host_id` carries the canonical host identifier **if and only if**
`sections.host_identity.collection_status` is `COLLECTED` **and** `IDENT-005` derived a valid `host_id`.
For every other outcome it is `null`.

| `collection_status` | valid `host_id` derived? | `manifest_core.host_id` |
|---|---|---|
| `COLLECTED` | yes | the `IDENT-005` string, **byte-identical** to the state object's `host_id` |
| `COLLECTED` | no | **INVARIANT VIOLATION** — not a second valid representation |
| `ERROR` | no | `null` |
| `NOT_TESTED` | no | `null` |

`PARTIAL` has no row because `IDENT-004` states it does not occur for `host_identity` in W1-A. The three
rows above are therefore total over the W1-A status vocabulary, not merely the cases the corpus happens to
contain.

**Canonicality — exactly one encoding per permitted semantic state.** The key is **mandatory and present**
in both: `SNAP-020` already requires every key to be present, and `NORM-034` already makes *null* and
*absent* distinct.

| Encoding | Permitted |
|---|---|
| `"host_id":"sha256:<64 lowercase hex>"` | yes — **only** when `COLLECTED` |
| `"host_id":null` | yes — **only** when not `COLLECTED` |
| key absent | **no** |
| `"host_id":""` | **no** |
| any other string shape | **no** |

**A `COLLECTED` section whose `host_id` is null, absent or malformed SHALL be REJECTED, never normalized
to `null`.** Normalizing it would turn a collection defect into a valid-looking snapshot that binds to no
host — and binding the snapshot to its host is the entire purpose of the field (`SCOPE-048`).

**NORM-042 (Z-13, NEW) SHALL** **A field-specific grammar takes precedence over generic byte
representation.** Where a field has a frozen, field-specific syntactic grammar, that grammar decides
acceptance **first**. `NORM-036`'s tagged representation SHALL NOT be used to carry bytes that the field's
own grammar rejects.

Both rules are frozen for W1-A, and for a malformed `/etc/machine-id` they gave opposite answers that were
each defensible from the text: `NORM-036` represents any byte sequence and would have yielded a
`COLLECTED` snapshot whose identity is a base64 blob, while `IDENT-003` rejects anything that is not 32
hex characters. One frozen input, two conforming outcomes, two different manifest hashes.

For `/etc/machine-id` the grammar is **`IDENT-003`**. A byte sequence it rejects is `SYNTAX_REJECTED`
(`IDENT-004` row 3) whether it failed on **encoding** or on **shape** — the distinction does not reach the
result. It SHALL NEVER be preserved as `__isedraf_encoding` material inside identity state.

`NORM-036` keeps its full scope wherever the canonical schema genuinely permits opaque bytes; it is not
weakened, only ordered. **W1-A contains no such field** — `IDENT-002` freezes the only state object as one
hex-derived string — so W1-A has no positive `NORM-036` surface, and none is invented to manufacture
coverage (the same treatment as `NORM-037` under `Z-11`).

**STORE-024 (X-05, Y-01, Y-02, W1-A) SHALL** **The W1-A ledger record — the single normative
definition** (`NRM-001`). W1-A writes exactly one event type, `snapshot_committed`, which is the literal
already in `STORE-010`'s enum and in `SNAP-018`:

```text
record_core:
    ledger_schema_version integer, W1-A literal 1
    sequence              integer, genesis = 1, strictly incrementing
    event                 string, W1-A literal "snapshot_committed"   (Y-02)
    event_id              string   (SNAP-019, prefix EVT-)
    occurred_at           string   (SNAP-019)
    previous_record_hash  "sha256:<64 hex>"; genesis = sha256: followed by 64 zeros
    snapshot_id           string
    manifest_hash         string
    state_root            string  "DEV" | "PRODUCTION"   (PRIV-004 marks EVERY artifact, Y-03)

record_hash = HASH_FRAME_V1("ISEDRAF:LEDGER-RECORD:V1", canonical_bytes(record_core))
```

**Chaining (Z-07).** The rule lives **here**, in the W1-A normative source, because the scope set freezes
`STORE-010` for its event enum only and a rule an implementer cannot look up is not frozen:

```text
record[1].sequence              = 1
record[1].previous_record_hash  = "sha256:" + 64 zeros
record[n].sequence              = record[n-1].sequence + 1        (strictly incrementing, no gaps)
record[n].previous_record_hash  = record[n-1].record_hash         (n > 1)
```

A record whose `previous_record_hash` does not equal its predecessor's `record_hash`, or whose `sequence`
is not exactly one greater, **breaks the chain** and is an integrity failure. W1-A appends one record per
run, so chaining is reachable from the second run onward — it is not a Freeze Set 2 concern.

Stored row: `canonical_bytes({"record_core": ..., "record_hash": "sha256:..."})`, one physical line.
`baseline_approved` is W1-B; `ledger_recovered` belongs with recovery. Neither is frozen here.

**SNAP-016 (S-16, NEW) SHALL** An **evidence reference** is a defined object: the collector and source that
produced it, the argv or file path, a `sha256:` hash of the retained bytes, whether raw output is retained
at all, its retention — **the W1 literal is `retention: "UNLIMITED_W1"`**, so no deferred retention vocabulary is needed (W-16) — and its redaction class. Which collectors retain raw output is
declared per collector. `explain` cites evidence references; a reference with no defined object SHALL NOT
be emitted.

**SNAP-011 (D-41) SHALL NOT** A snapshot directory SHALL NEVER contain `changes.json`, `findings.json`, or
any evaluated result.

**SNAP-012 (D-41) SHALL** `evaluations/EVL-*/` contains `changes.json`, `findings.json` and a manifest. It
is **derived and regenerable**, keyed by `snapshot_id` + `baseline_revision` + `engine_version` +
rules/profile version.

**SNAP-013 (D-42, A19) SHALL** Every evaluation manifest records: snapshot manifest hash, baseline
revision, engine version, collector version and parser version per section, evaluation-rules version,
schema versions, and profile.

### Snapshot lifecycle

```text
     (start)
        │  acquire whole-run flock
        ↓
   COLLECTING ──error──→ FAILED (temp dir removed; nothing committed)
        ↓
   NORMALIZING
        ↓
   HASHING  →  manifest written  →  fsync
        ↓
   atomic rename into snapshots/SDS-*
        ↓
   ledger append + fsync ──crash here──→ ORPHANED_UNLEDGERED
        ↓
   COMMITTED (treated as immutable by ISEDRAF)
        ↓
   approvable? ──no (incomplete/unprivileged/DEV)──→ never a baseline
        ↓ yes
   may become BL-n via explicit approval
        ↓
   PRUNED (dir removed; ledger records the prune event with IDs + hashes)
```

**SNAP-014 (D-50, A5) SHALL** Commit ordering: private temp dir → collect → normalize → hashes → manifest
→ **fsync** → **atomic rename** → **ledger append + fsync**, all under a whole-run exclusive `flock`.

**SNAP-015 (D-50, S-06, S-32) SHALL** The ledger is authoritative, and store discontinuity has **distinct
named states** — a rolled-back evidence store SHALL NOT be reported as a benign crash artifact:

| State | Evidence | Meaning |
|---|---|---|
| `ORPHANED_UNLEDGERED` | a single directory newer than the ledger head | crash between rename and ledger append (acceptance test 6) — recoverable |
| `LEDGER_BEHIND_STORE` / `POSSIBLE_ROLLBACK` | several unledgered directories, or a directory whose `ts_utc` precedes the ledger head | evidence-store discontinuity — **not** recovery |
| `LEDGER_REFERENCE_MISSING` | ledger entry with no directory and **no** `pruned` event | durability loss; recoverable, **distinct from `integrity_failure`** |
| `LEDGER_SEGMENT_MISSING` | a segment referenced by the chain is absent | discontinuity, **not** a crash |
| `integrity_failure` | content hash disagrees with the ledger | exit `5` |

A power cut SHALL NOT be reported with the same signal as tampering.

**SNAP-017 (S-07, S-10, NEW) SHALL** `POSSIBLE_ROLLBACK` has defined triggers: ledger head versus store
contents, boot-id history, snapshot `ts_utc` regression, or `shadow` last-change moving backwards. A
**pre-delta monotonicity check** runs before classification; while `POSSIBLE_ROLLBACK` is raised,
`SECURITY_IMPROVEMENT` and `REMOVED` are suppressed until the operator resolves it — otherwise a restore
reports every hardening change of the intervening period reversed.

## 8. Baseline and acceptance

**BASE-001 (D-43, D-101, W-04) SHALL** **Freeze Set 2 definition of baseline revision computation.**
For **W1 the normative source is `SCOPE-074`**, whose second component is `profile_hash`; the `BL-000001`
line below is **superseded for W1** and applies only once baseline policy exists (`NRM-003`: one of two
formulas must die, and for W1 it is this one).

```text
BL-000001 = HASH_FRAME_V1("ISEDRAF:BASELINE:V1",
                          approved_snapshot_manifest_hash,
                          canonical_baseline_policy_bytes)

BL-(n+1)  = HASH_FRAME_V1("ISEDRAF:BASELINE_REVISION:V1",
                          BL-n, baseline_event_hash)
```

Revision identifiers are `BL-000001`, `BL-000002`, … The **initial** approved revision is `BL-000001`;
there is no `BL-0`. Each event references **only** the previous revision, so the computation is not
circular. The effective baseline is reconstructed as *approved snapshot + ordered baseline events*.

**BASE-005 (T-03, T-04) SHALL** `baseline_policy` is a canonical object:
`{ profile_id, profile_version, profile_hash, required_sections[], optional_sections[],
tracked_sections[], comparison_policy_version }`, all lists sorted.

**BASE-006 (T-04, T-12) SHALL** A `baseline_event` is a canonical object:
`{ event_id, previous_baseline_revision, event_type, actor, ts_utc,
affected_entity_or_section, accepted_state_hash | policy_delta, artifact_hash }`.
It carries **actor and timestamp directly**, so a policy event needs no acceptance record shape it does
not fit.

**BASE-007 (T-06, NEW) SHALL** **Baseline revisions are stored and verified, not merely hashed
conceptually.** Immutable revision artifacts live at `/var/lib/isedraf/baselines/BL-NNNNNN.json`, each
carrying `revision_id`, `revision_hash`, `previous_revision_hash`, approved snapshot id and hash,
`profile_id`/`version`/`hash`, `required_sections`, `tracked_sections`, policy version, and event and
acceptance references. The ledger records the revision hash.

**BASE-008 (T-06, NEW) SHALL** **Before any comparison** the engine SHALL load the baseline revision
artifact, canonicalize it, recompute the revision hash, verify ledger linkage, and verify the current
baseline pointer. A mismatch is an **integrity failure, exit `5`** — never a silent re-read. Editing
`tracked_sections` on disk therefore changes the revision bytes without changing the ledger-bound hash,
and is detected. This is the binding that makes `BASE-025`'s claim true rather than aspirational.

**BASE-020 (D-101, Q-04) SHALL** **Completeness and tracking are separate concepts.** Three sets:

| Set | Meaning |
|---|---|
| `SUPPORTED` | collection capability exists on this host |
| `REQUIRED_FOR_BASELINE` | evidence required by the selected baseline profile |
| `TRACKED` | accepted evidence whose loss or change participates in later comparison |

**BASE-021 (D-101, T-05) SHALL** `REQUIRED_FOR_BASELINE` comes from a **versioned, packaged baseline
profile** — immutable data shipped with the release — **never** from the baseline being created. A profile
carries `profile_id`, `profile_version`, `profile_hash`, `required_sections`, `optional_sections`.
`isedraf baseline approve` uses the release's default profile unless an explicitly supported
`--profile <id>` is supplied. There is therefore **no circular dependency on an existing baseline**, and
approval eligibility is decidable at the very first approval:

```text
profile requires host_identity · snapshot host_identity = COLLECTED   → eligible
profile requires privilege     · snapshot privilege     = NOT_TESTED  → INCOMPLETE_FOR_BASELINE, refused
```

W1 uses a deliberately narrow fixture profile `prototype-host-identity-v1`
(`required_sections = ["host_identity"]`); the v0.1 release profile expands only as frozen scope is
completed.

**BASE-026 (T-05, NEW) SHALL** If `REQUIRED_FOR_BASELINE ⊄ SUPPORTED` on this host, approval is **refused
with a distinct reason** — the required set SHALL NEVER be silently narrowed to what the host can collect.

**BASE-022 (D-101, Q-04) SHALL** After approval, `REQUIRED_FOR_BASELINE ⊆ TRACKED`. A required section
SHALL NOT disappear from tracking.

**BASE-023 (D-101, Q-04) SHALL** Re-approval **inherits** the existing tracked set and SHALL NOT silently
shrink it. Removing an **optional** tracked section requires an explicit, reasoned baseline-policy event
and a new revision; changing the baseline profile is likewise a policy event. There is no
*re-approve → stop tracking audit → exit 0* path.

**BASE-024 (D-101, Q-04) SHALL** A tracked section that becomes unavailable is `NOT_COMPARABLE` →
incomplete → exit `2`. A section never collected or supported in the approved baseline SHALL NOT force
exit `2`. A newly supported collector becomes **available coverage**, never automatically tracked;
adoption is an explicit `isedraf baseline track <section>`, **not** `rebind`.

**BASE-025 (D-101, Q-04) SHALL** Every tracking or policy change is attributed, timestamped, reasoned and
hash-chained as a `baseline_event` (`BASE-006`), producing a new revision and a `section_tracked` /
`section_untracked` ledger event. Exit `2` **cannot** be silenced by editing a flag.

**BASE-002 (D-43) SHALL** The first snapshot SHALL NEVER be auto-approved. A baseline means **accepted**,
not secure.

**BASE-003 (D-46) SHALL** An unprivileged, incomplete or `DEV` snapshot SHALL NEVER become a **production**
baseline, and SHALL NEVER be exported as evidence.

**BASE-009 (W-01, NEW) SHALL** A `DEV` snapshot MAY become a **`DEV` baseline**, which is marked
`baseline_class: "DEV"`, is confined to the development state root (`PRIV-004`), SHALL NOT be exported as
evidence, and **SHALL NOT satisfy `BASE-003` for v0.1**. This exists because W1 is unprivileged-only
(`SCOPE-070`) and therefore produces only `DEV` artifacts: without this class the W1 lifecycle would be
forbidden by its own frozen set. `BASE-003` is not softened — a `DEV` baseline is a different, clearly
labelled object, and promotion of a `DEV` baseline to production is **not** defined and SHALL NOT be
attempted.

**BASE-004 (D-44) SHALL** An acceptance binds the **exact accepted normalized state hash**. Any later
change to that entity is a new change. A `MISMATCH` MAY be acknowledged but SHALL NEVER be normalized away.

### Baseline revision state machine

```text
  (no baseline) ──approve(SDS-a)──→ BL-1
        exit 6                          │
                                        ├── accept(change) ──→ BL-2 ──→ BL-n
                                        ├── acknowledge(MISMATCH) ──→ BL-n+1  (state NOT normalized)
                                        └── rebind(method change) ──→ BL-n+1  (state NOT re-accepted)
```

### Change lifecycle

```text
  DETECTED ──accept(--reason)──────→ ACCEPTED    (binds exact state hash)
     │
     ├──acknowledge (MISMATCH only)→ ACKNOWLEDGED (still visible, still reported)
     │
     └──entity changes again───────→ SUPERSEDED  (a NEW change is raised)
```

**BASE-010 (D-54, A12) SHALL** `--reason` is length-limited, escaped and CSV-guarded. Acceptance records
are the **only** place personal data (actor, timestamp, reason, accepted state hash) is stored outside
snapshots.

## 9. Collection-method versioning — invariant I-3

**CMP-020 (D-45, D-98, S-24) SHALL** Collection method identity is **source-aware**. Every section records
`collector_id`, `collector_version`, `parser_version`, **`source_id`**, **`classification_table_version`** (W-26 — `SCOPE-047` makes a
classification change a method change, so it must be an element), the source/executable identity, and the
source version where available. A change to **any** element raises `COLLECTION_METHOD_CHANGED` — so
switching lastlog → lastlog2 → wtmpdb, `cvtsudoers` → fallback, `aa-status --json` → text, or `getent` →
file is a method change **even when no ISEDRAF version changed**. The resolved NSS source set is part of
`source_id` (S-20). **Grammar (W-27):** command sources are `cmd:<absolute path>`; file sources are
`file:<absolute path>` and `files:<sorted comma-separated absolute paths>`. `source_id` is recorded **per field** (`IDENT-006`), never as one compound literal for a section. **W1-A's
only field is `host_id`, whose `source_id` is `file:/etc/machine-id`** — the earlier compound literal named
DMI anchors that W1-A does not collect, which was both a second normative statement and a scope leak
(Y-04).

**CMP-021 (D-45) SHALL** If the normalized values are **identical** across a method change, the change is
**silent** — no security change is reported (acceptance tests 3, 4). If they differ, the result is
`REVIEW_REQUIRED`, never an automatic regression or improvement.

> Tool evolution SHALL NEVER masquerade as host evolution. This is the requirement that enforces it.

### Rebind state machine

```text
  method change detected
        ↓
  isedraf baseline rebind        ("rebind", never "recollect")
        ↓
  normalized state equivalent? ──yes──→ SAFE_REBIND     (metadata updated, state unchanged)
        │
        └──no──→ REVIEW_REQUIRED  (owner decides; rebind SHALL NEVER auto-accept new state)
```

**BASE-030 (D-45) SHALL NOT** `baseline rebind` SHALL NEVER auto-accept new state.

## 10. Comparability — invariant I-2

**CMP-030 (D-46, A4) SHALL** A delta is computed **only** where both sides are `COLLECTED`. Otherwise the
result is `NOT_COMPARABLE` with a reason.

**CMP-031 (D-46) SHALL NOT** `NOT_TESTED` SHALL NEVER yield `REMOVED` and SHALL NEVER yield
`SECURITY_IMPROVEMENT` (acceptance test 5).

| Baseline side | New side | Result |
|---|---|---|
| `COLLECTED` | `COLLECTED` | diff |
| `COLLECTED` | `NOT_TESTED` / `ERROR` | `NOT_COMPARABLE` + reason; exit ≥ `2` **if tracked** (`BASE-024`) |
| `NOT_TESTED` | `COLLECTED` | `NOT_COMPARABLE` + reason (**not** an improvement) |
| any | any, incompatible schema major | `NOT_COMPARABLE`; rebind required |
| any | any, host identity mismatch | `BASELINE_NOT_APPLICABLE`; no diff; exit `4` |

## 11. Change primitives and interpretation

**DELTA-001 (D-47) SHALL** Primitives: `ADDED`, `REMOVED`, `MODIFIED`, `ENABLED`, `DISABLED`, `MISMATCH`.

**DELTA-002 (D-47) SHALL** Interpretations: `SECURITY_REGRESSION`, `SECURITY_IMPROVEMENT`,
`EXPECTED_CHANGE`, `REVIEW_REQUIRED`, `INFORMATIONAL`.

**DELTA-003 (D-47, D-100, S-21, S-38) SHALL NOT** **`EXPECTED_CHANGE` is not emitted automatically in
v0.1.** Its only correlating source — package ownership plus a package transaction — is out of prototype
scope (`SCOPE-003`) and remote package queries are barred (D-67). Routine package or kernel change is
`INFORMATIONAL` or `REVIEW_REQUIRED` according to the evidence. **ISEDRAF does not invent intent.** The
classification is reserved for a later evaluator.

**DELTA-005 (S-38, D-100) SHALL** When correlation is later introduced, its window SHALL be defined over
**monotonic evidence** — ledger `seq`, boot id, package-transaction ids — never wall clock, and SHALL be
withheld entirely when the observed time-sync state is unsynchronized or a backwards step is detected
between the two snapshots. A clock step SHALL NEVER launder a pre-baseline transaction into an expected
change.

**STORE-019 (S-39, NEW) SHALL** In the ledger, `seq` and `prev_hash` are authoritative for ordering;
`ts_utc` is an **observation**. A non-monotonic `ts_utc` is recorded with a `clock_regression` marker on
the record rather than silently accepted or rejected.

**DELTA-004 (D-47) SHALL** BIOS and firmware changes are `REVIEW_REQUIRED`.

**DELTA-006 (W-30, NEW) SHALL** **W1 entity model.** `host_identity` is a **single entity keyed by section
name**. A difference in its canonical state yields **exactly one `MODIFIED`** row carrying the before and
after section hashes. Per-anchor entities, `ADDED`/`REMOVED` rows and change-id granularity are
`DEFERRED_TO_FREEZE_SET_2`, so "one fact changed → deterministic delta" is deterministic in row count as
well as in detection.

**DELTA-010 (D-36, D-47) SHALL** When no security-relevant change is observed, the run is **quiet**:
exit `0`, no change rows. Ten consecutive runs on an unchanged host SHALL produce zero changes
(acceptance test 2).

**DELTA-020 (D-48) SHALL** Operational risk belongs to guidance, never to the delta: `NONE`,
`SERVICE_RESTART`, `POTENTIAL_SERVICE_DISRUPTION`, `POTENTIAL_LOCKOUT`, `REBOOT_REQUIRED`.

**DELTA-021 (D-48) SHALL** Guidance commands are labelled `ILLUSTRATIVE` and carry context (source file,
package ownership, dependencies). No exact revert and no apply in v0.1.

## 12. Storage

**STORE-025 (Y-13, W1-A) SHALL** **W1-A creates only** `snapshots/`, `tmp/`, `ledger/` and `.lock` under
the state root. `host/anchor.key`, `baselines/`, `evaluations/`, `acceptances/`, `reports/` and `exports/`
belong to later sets and are **not created**; the entries below are annotated
`DEFERRED_TO_FREEZE_SET_2` accordingly.

**STORE-001 (D-49) SHALL** Root `/var/lib/isedraf/` mode 0700, containing:
`host/ baselines/ snapshots/ evaluations/ acceptances/ reports/ exports/ tmp/ ledger/ .lock`,
where `host/` holds `host.json` (identity state) and `anchor.key` (the per-install HMAC key, mode 0600,
created `O_NOFOLLOW|O_EXCL`, **not collected in W1** — W-29), `ledger/` holds `segment-NNNNNN.jsonl`
(D-99) and `baselines/` holds `BL-NNNNNN.json`,
`baselines/events/BE-*.json` and `baselines/current` (U-16). This is the **single normative statement of
storage layout** (`NRM-001`); no other document restates it.

**STORE-002 (D-49) SHALL NOT** No database, no server, no API, no connectors, no credentials, no network
egress in v0.1 — including no authoritative SQLite.

### Ledger event schema (shape, not a file)

```text
{ seq, event, ts_utc, run_id, prev_hash, record_hash,
  snapshot_id?, evaluation_id?, baseline_revision?, acceptance_id?,
  manifest_hash?, reason_class? }

event ∈ { snapshot_committed, snapshot_orphan_detected, baseline_approved, ledger_recovered,
          change_accepted, mismatch_acknowledged, baseline_rebound,
          section_tracked, section_untracked, baseline_policy_changed,
          rollback_resolved, evaluation_generated,
          data_purged, pruned, checkpoint, integrity_failure }
```

**STORE-010 (D-51, D-99, R-03, R-08, S-31) SHALL** The ledger is **segmented**:
`ledger/segment-NNNNNN.jsonl`, append-only within a segment and hash-chained via `prev_hash`. It contains
**IDs and hashes only**. A verified record SHALL NEVER be rewritten. The **first record of segment
N+1 carries the last record of segment N as its `prev_hash`**, and `seq` is globally monotonic across
segments (Q-06).

**STORE-023 (SUPERSEDED for W1-A by `STORE-024`)** Retained for Freeze Set 2 context only. It names a
different domain, preimage and row shape; for W1-A it has no force (`NRM-003`: one of two must die).
Formerly: `record_hash = HASH_FRAME_V1("ISEDRAF:LEDGER:V1",
canonical_bytes(record_without_record_hash))`. The JSONL row is `canonical_bytes` of the record
**including** `record_hash`. The `prev_hash` of the **genesis** record of `segment-000001` is 32 zero
bytes, rendered `sha256:0000000000000000000000000000000000000000000000000000000000000000`. A golden ledger
vector is release-blocking (`NORM-039`).

**STORE-016 (D-99, R-08) SHALL** Crash recovery is defined and bounded. A free-space preflight precedes
commit. Each record is composed in memory and written with a single bounded `write()` whose byte count is
verified, then fsynced. A **torn tail** — a trailing record that fails to parse or whose `record_hash`
fails — is **preserved as forensic evidence**, the chain is recovered only to the last fully verified
record, and a **new segment** opens with an explicit `ledger_recovered` event referencing the damaged
segment and the torn tail's byte hash. Bytes are never silently discarded, and uninterrupted integrity is
never claimed across a recovery. Append-only SHALL NOT mean one torn write destroys the product.

**STORE-021 (T-24, NEW) SHALL** The current segment number and head `seq` are recorded **outside** the
ledger — in `host/` and in the `ISEDRAF_CHECKPOINT=` line — because deleting the highest-numbered segments
leaves a shorter but internally perfect chain that the chain alone cannot detect.

**STORE-022 (T-25, NEW) SHALL** If the recovery write itself fails for want of space, the run **refuses to
collect**, reports a named reason code and a dedicated exit code, and does not loop. The free-space
preflight reserves headroom for at least one recovery record, so a full disk cannot leave the ledger
permanently unadvanceable with no signal.

**STORE-017 (R-03, S-09) SHALL** The ledger is **tamper-evident to a non-root actor only**. Its chain uses
no secret and no external anchor. Local verification proves internal consistency, not authenticity — the
`LOCAL_CONSISTENT` level of `INTEG-002`. A root adversary can recompute the chain end to end. This
statement appears in `EVID-040`.

**STORE-018 (R-03) SHALL** Compaction rewrites **only** pre-checkpoint records; the checkpoint record
carries the cumulative hash of everything it replaces. `verify` SHALL print the **verification horizon**:
*chain verified from checkpoint `<id>`; earlier history is not locally verifiable.*

**STORE-011 (D-51) SHALL** Personal data lives only in snapshots and `acceptances/ACC-*.json`.

### Acceptance record schema (shape)

```text
{ acceptance_id, ts_utc, actor, change_id, entity_ref,
  accepted_state_hash, reason, baseline_revision_before, baseline_revision_after }
```

**STORE-020 (Q-09, NEW) SHALL** The `ORPHANED_UNLEDGERED` rule applies to `snapshots/` only;
`evaluations/` is derived and carries no ledger entry by design.

**STORE-012 (D-51) SHALL** Prune removes directories and appends a `pruned` event carrying the IDs and
manifest hashes. Compaction occurs only via an explicit `checkpoint` record.

**STORE-013 (D-52) SHALL** A checkpoint hash is emitted to the journal and stdout as
`ISEDRAF_CHECKPOINT=` for external retention.

**STORE-014 (D-53) SHALL** Default retention is the baseline plus the last 30 snapshots, configurable, via
`isedraf prune`. Package removal or purge SHALL NEVER delete `/var/lib/isedraf`; only
`isedraf purge-data` deletes evidence.

**STORE-015 (D-50) SHALL** The whole run holds an exclusive `flock`. Concurrent runs SHALL NOT interleave
writes.

## 13. Acceptance-test traceability

| Test | Requirement(s) |
|---|---|
| 1 default run < 10 s | `SCOPE-060` |
| 2 unchanged × 10 → 0 changes | `NORM-020`, `DELTA-010` |
| 3 upgrade → 0 security changes | `CMP-020`, `CMP-021` |
| 4 parser v1→v2 identical state | `CMP-021` |
| 5 root baseline + unprivileged run | `CMP-030`, `CMP-031` |
| 6 crash before ledger append | `SNAP-014`, `SNAP-015` |
| 7 cloned VM | `SNAP-001`, `EVID-013` |
| 8 new sudo user | `DELTA-002`, `IDENT-030` |
| 9 locked password + key + NOPASSWD | `IDENT-020`, `HLD-051` |
| 10 audit persistent vs loaded | `NORM-010` |
| 11 zero writes outside state root | `EXEC-001`, `STORE-001` |
| 12 SELinux confined | `PRIV-021`, `PRIV-022` |
| 13 no baseline → exit 6 | `HLD-040`, `OUT-001` |
| 14 only last-login changes | `NORM-020`, `NORM-021` |
| 15 home birth time never EVENT_RECORDED | `EVID-020`, `EVID-021` |
| 16 new sudo privilege | `IDENT-030`, `DELTA-002` |
| 17 quick/detailed same evidence | `HLD-050`, `IDENT-001` |
| 18 account-change recording | `EVID-030`, `EVID-033` |
| 19 governance file edited | `GOV-003` |
| 20 runtime sqlite3/network import | `EXEC-014`, `EXEC-002` |
| 21 logger spoof | `EVID-022` |
| 22 commit without `Assisted-by:` | `GOV-005` |
