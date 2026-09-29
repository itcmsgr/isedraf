<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# W1-D — the local account source contract

Status: FROZEN
Implements: SCOPE-022, SCOPE-045, IDENT-013, IDENT-041, IDENT-060, NORM-035

**FROZEN, 2026-09-21.** Q1–Q4 and Q6 were ruled during review; Q5 is closed by the owner
resolution in §11. Downstream work — `authorized_keys`, identity views, account criteria —
consumes this contract rather than reinterpreting it. The point of serializing this lane was
that later work is mechanical rather than architectural, and that is now in force.

## 1. What this source is, and what it is not

`/etc/passwd`, `/etc/group` and `/etc/shadow` are three local files. A Linux host may resolve
identities through NSS from SSSD, LDAP, Active Directory, `systemd-homed` or a container
runtime, and none of those appears in these files.

So the model is named for what it reads. Everything is `local_accounts`, `local_groups`,
`LOCAL_ACCOUNT_FILES`. It is never `users`, never `all accounts`, never `the identities of
this host`. `IDENT-041` already freezes the consequence — canonical identity state contains
only accounts whose NSS source is `files`, and each entity records that source as a state
field — and every record produced here carries `nss_source: "files"` for exactly that reason.

This naming is not pedantry. D-114 happened because one field name implied more than its
source supported. The same mistake at the identity layer is worse: a mislabelled disk is
embarrassing, a missing administrator is a security failure.

`IDENT-040` is already frozen and binds the future resolved lane: a bare `getent passwd`
fans out to every NSS module and **is** directory enumeration, so it is never used.

## 2. Layering — the parser cannot know about permissions

```
filesystem acquisition        acquire.py   knows about errno, decides SCOPE-022 status
        |
        v
      text
        |
        v
pure parser                   sources.py   text -> records, no I/O, no policy
        |
        v
normalized source records
```

`sources.parse_passwd/parse_group/parse_shadow` take a string and return a `ParsedSource`.
They do not open files and cannot consult the host they run on — a test asserts this by
inspecting their source for `open(`, `os.`, `read_file` and `subprocess`. That is what makes
the fixtures deterministic: a parser test cannot pass or fail because of the permissions of
the machine running it.

## 3. Parser API

| Function | Takes | Returns |
|---|---|---|
| `sources.parse_passwd(text)` | `str` | `ParsedSource` |
| `sources.parse_group(text)` | `str` | `ParsedSource` |
| `sources.parse_shadow(text)` | `str` | `ParsedSource` |
| `acquire.acquire(root, relative)` | fixture root, relative path | per-source status dict |
| `acquire.collect(root="/")` | fixture root | the joined result |

`ParsedSource` carries `records` (file order, nothing dropped, nothing de-duplicated),
`anomalies`, `line_count` and `malformed_count`.

## 4. SCOPE-045 classification

`SCOPE-045` freezes four categories — `STATE`, `OBSERVATION`, `DERIVED`, `PROVENANCE` — and
only `STATE` is hashed and diffed.

**The inventory module's five labels are a domain-local inventory sub-classification, not a
competing `SCOPE-045` taxonomy.** Owner ruling. `PLATFORM_FACT`, `HARDWARE_OBSERVATION` and
the rest answer "does this legitimately change on an untouched host?", for data that sits
entirely outside the snapshot contract (`SNAP-021`); they exist to keep a live-migrated VM
quiet, not to decide what is hashed. A note to that effect now sits at the top of
`lib/isedraf/inventory/model.py` so a future reader cannot conclude there are two
definitions. The inventory code is not refactored in this lane.

Account state is not inventory: it is security configuration that must be hashed, diffed and
baseline-bound, so it is classified under the frozen four.

| Field | Category | Why |
|---|---|---|
| `name`, `uid`, `primary_gid`, `home`, `shell` | `STATE` | security configuration; a change is a real event |
| `gecos` | `OBSERVATION` | **owner ruling Q4.** Free-form metadata carrying names, rooms and telephone numbers. It does not determine authentication or privilege, and making it `STATE` would turn "Room 12" → "Room 14" into a security baseline delta while binding personal data into a hashed surface. Promote it later by explicit decision if a control needs GECOS integrity. |
| `nss_source` | `STATE` | `IDENT-041` requires it as a state field |
| `shadow.password_state.lock_prefix` | `STATE` | locking an account is a configuration change |
| `shadow.password_state.content` | `STATE` | gaining or losing a password is a configuration change |
| `shadow.password_state.hash_scheme` | `STATE` | the algorithm is configuration; the verifier is not stored |
| `shadow.*_days` | `STATE` | `IDENT-060`: integers and named states only |
| `shadow.*_days_source` | `PROVENANCE` | whether the field was observed, unspecified or malformed |
| `shadow_record` | `PROVENANCE` | how we know, not what is |
| `collection_status`, `reason`, per-source status | `PROVENANCE` | `SCOPE-045` names these explicitly |
| `passwd_line`, `group_line`, `shadow_line` | `PROVENANCE` | where in the source it was seen |
| `orphan_shadow_records`, `orphan_group_members` | `DERIVED` | computed from two sources |
| `anomalies` | `DERIVED` | computed from the records |

"Days remaining" and similar rendered values are `OBSERVATION`, computed at render time, and
are deliberately not produced here.

## 5. Collection status truth table

`SCOPE-022` is frozen and decides status by table, not by implementer choice. Applied per
source, then aggregated — never the other way round.

| Source condition | Per-source status | Why |
|---|---|---|
| read, all records well-formed | `COLLECTED` | |
| read, **zero records** | `COLLECTED` | **owner ruling Q3.** Read succeeded, parse succeeded, nothing there. Abnormal is not incomplete, and calling it `PARTIAL` would mix collection truth with security interpretation. A criterion may later call zero local accounts a serious finding. |
| read, **some** records malformed | `PARTIAL` + `MALFORMED_RECORDS` | **owner ruling Q1.** Record boundaries held and the good records remain trustworthy; they are retained and counted, never skipped. |
| read, **every** record malformed | `ERROR` + `UNPARSEABLE` | **owner ruling Q1.** No trustworthy normalized interpretation can be produced. |
| `ENOENT` | `NOT_TESTED` + `SOURCE_ABSENT` | nothing to test |
| `EACCES` / `EPERM` | `NOT_TESTED` + permission reason | `SCOPE-022`: privilege denial → `NOT_TESTED` |
| other I/O error | `ERROR` | `SCOPE-022`: present and failed → `ERROR` |

| Aggregate condition | Combined |
|---|---|
| all three `COLLECTED` | `COLLECTED` |
| passwd `ERROR` | `ERROR` |
| passwd `NOT_TESTED` | `NOT_TESTED` — no account universe to be partial about |
| passwd usable, any other source not `COLLECTED` | `PARTIAL` with a reason naming each |

**`SCOPE-022` clarification, not contradiction (owner ruling Q1).** *Unparseable output* means
content for which **no trustworthy normalized interpretation can be produced**. A source where
every record failed is that case and is `ERROR`. A source where forty records parsed and one
did not is not that case: the record boundaries held, the forty remain trustworthy, and
discarding them to punish a typo would destroy evidence. That is `PARTIAL`, with the malformed
records retained, counted and reported. This narrows the frozen requirement's boundary; it
does not move it.

**Defect A, one layer up.** `/etc/passwd` is world-readable and `/etc/shadow` is not, so an
unprivileged run reads every account name and no password state at all. Reporting that as a
complete account collection would tell an operator their accounts have no ageing policy when
the truth is that nothing was looked at. A readable source never satisfies completeness for
an unreadable one.

Distinguishing `EACCES` from other I/O errors required a change to `_exec.Outcome`: it now
carries an additive `detail` (`NOT_FOUND`, `PERMISSION_DENIED`, `IO_ERROR`, `READ_OK`)
alongside the unchanged frozen `reason`. No existing caller changes behaviour. `identity.py`
does not use this reader at all — `IDENT-004` freezes ENOENT as row 1 and every other I/O
error including `EACCES` as row 2, and that collapse is intentional, not an oversight.

## 6. The passwd ↔ shadow join — three answers, never one

| Value | Meaning |
|---|---|
| `PRESENT` | shadow was read and a matching record exists |
| `ABSENT_FROM_COLLECTED_SOURCE` | shadow was read **completely** and contains no matching record — positive evidence of absence, and a real anomaly |
| `SOURCE_NOT_COLLECTED` | nothing is known about whether a record exists |

A single `shadow: null` would flatten all three into one statement. `SOURCE_NOT_COLLECTED`
must never be rendered as "the account has no password" or "the account does not expire".

### FROZEN INVARIANT — absence requires complete evidence

> **An absence claim requires complete evidence over the source domain in which the absence
> is asserted.**

`ABSENT_FROM_COLLECTED_SOURCE` is valid **only** when the counterpart source is fully
`COLLECTED`. If shadow is `PARTIAL`, this account's record may have been one of the malformed
lines, so "not in the index" means unknown, not absent. `ERROR` and `NOT_TESTED` are likewise
unknown.

A successfully parsed matching record is `PRESENT` **even when the source overall is
`PARTIAL`** — those two facts are compatible, and the record is evidence regardless of what
happened to other lines.

The same rule governs every missing-relationship claim, and the result reports which ones it
was entitled to make in `absence_claims_supported`:

| Claim | Requires |
|---|---|
| `orphan_shadow_records` — a shadow record with no passwd account | passwd fully `COLLECTED` |
| `orphan_group_members` — a group member with no passwd account | passwd fully `COLLECTED` |
| `orphan_primary_gids` — a passwd GID with no group | group fully `COLLECTED` |

With the counterpart incomplete, the list is empty and the corresponding flag is false. An
orphan reported from a gap in our own reading is an accusation we manufactured.

## 7. The password field — the redaction boundary

The second field of `/etc/shadow` is the credential verifier. `sources._password_state()` is
the only function that sees it, and it returns a small closed vocabulary. The salt and digest
are never returned, never stored, never written to a fixture and never rendered. There is
nothing downstream to leak, because nothing downstream has it.

Two **independent** dimensions, because collapsing them is how "locked" becomes "has no
password" — `passwd -l` leaves the hash in place behind a `!`, and unlocking restores it. The
frozen pitfall list already says a locked password is not an expired password; it is also not
an absent one. This is the D-114 lesson applied to credentials: do not overload one enum with
two orthogonal facts.

| `lock_prefix` | `LOCK_PREFIX_PRESENT` / `LOCK_PREFIX_ABSENT` — field begins with `!` |
| `content` | `EMPTY`, `DISABLED_TOKEN` (`*`), `HASH_PRESENT` (crypt-shaped), `OTHER` |
| `hash_scheme` | a **bounded normalized identifier** from a closed table — `MD5_CRYPT`, `BCRYPT`, `SHA256_CRYPT`, `SHA512_CRYPT`, `SCRYPT`, `YESCRYPT`, `GOST_YESCRYPT`, `SUN_MD5` — or `OTHER_RECOGNIZED_FORMAT`, or null |

`hash_scheme` is retained deliberately (owner ruling Q2): `$1$` means MD5 and that is a
legitimate security fact a later criterion needs. It is metadata about the verifier, not the
verifier — it authenticates nobody.

But the raw `$id$` token is **never** published. An unrecognized identifier is an arbitrary
string lifted out of the credential field, and copying it out verbatim would be a small leak
of exactly the material this boundary exists to contain. Anything crypt-shaped but
unrecognized becomes `OTHER_RECOGNIZED_FORMAT` and nothing more.

`CONTENT_OTHER` covers legacy DES hashes and corruption alike, and the parser does not guess
which, because it cannot.

## 8. Boundaries this contract freezes

**UID.** Recorded as an integer. No `human`, `service`, `system`, `interactive`,
`administrator` label is produced from a UID range. No `is_root` flag: the name and the UID
are separate observations and a host may carry several UID 0 entries under different names —
exactly the fact an assurance tool must report and cannot report if the parser has already
decided which one is "the" root account. A `uid == 0` flag was considered and omitted: it is
redundant `DERIVED` data over a `STATE` field any consumer can compare.

**Shell.** The string, and nothing else. `/usr/sbin/nologin` does not become `inactive`.

**Groups.** Group name, GID, and the **explicit** supplementary member list. Primary
membership lives in the passwd GID relationship and is deliberately not merged: a user whose
primary group is `staff` does not appear in the `staff` line of `/etc/group`, and merging
without saying so loses which source said what. A combined effective-membership view is a
consumer's job, and it must declare that it built one.

**`/etc/gshadow` is not read (owner ruling Q6).** Group administrators and group passwords
live there. This source therefore cannot describe complete group administration state and
must never be presented as doing so — `group_limitation` and `not_collected` travel with
every result to keep that limit attached to the evidence rather than to a document nobody
reads. A later privilege or group-administration requirement can justify adding it. Nothing
speculative is collected now.

**Sudo.** Membership in a group named `sudo`, `wheel` or `admin` is a membership fact and
nothing more. Effective privilege requires the future sudo lane to read actual sudo policy.
Account objects expose membership; they do not decide privilege.

**Ageing.** `IDENT-060`: integers and explicit named states only, never a computed date.
`''`, `-1` and `99999` are three different observations and stay that way. Each field carries
a `_source` of `OBSERVED`, `UNSPECIFIED` or `MALFORMED`, so "not set" and "could not be read"
are distinguishable.

**Account creation time.** `UNKNOWN`, and not produced in this lane at all. Never derived
from home directory `ctime`/`mtime`, passwd or shadow file timestamps, UID ordering or inode
metadata. `EVID-020` and `IDENT-050` permit `ESTIMATED` with confidence `LOW` from
home-directory **birth** time specifically; even that is out of scope here. A heuristic must
never silently become a fact — the same failure as calling `queue_rotational=false` an SSD.

## 9. Duplicates and malformed data

Python's `dict` would make a duplicated account last-one-wins, turning an ambiguous and
security-relevant source into a clean-looking database, with the survivor decided by file
order. Records are kept in file order, nothing is de-duplicated, and collisions are named in
`anomalies` with both line numbers. Malformed records are retained carrying their anomalies,
never silently skipped, and their presence forces `PARTIAL`.

The shadow lookup index keeps the first occurrence — for the **index only**. Both records
remain in `records` and the duplicate is already an anomaly.

### §9 clarification — `+`/`-` lines take their meaning from the NSS mode (owner, 2026-09-24; amended 2026-09-27)

Found during the Batch 3 NSS lane recon: `+@admins::::::`, `-user::::::` and `+` in
`/etc/passwd` were parsed as account records named `+@admins`, `-user` and `+`, each
carrying `nss_source: "files"`, and each forcing `PARTIAL` as malformed. Under
`nsswitch.conf`'s `compat` service they are NSS inclusion and exclusion directives: `+`
includes every entry of the NIS map, `+@netgroup` a netgroup, `-user` excludes one. Under
`files` they are not directives at all: glibc enumerates `+alice:x:1000:...` as a literal
entry, and a bare `+` as uid 0 (measured).

**The precondition (owner ruling IQ-036, 2026-09-27).** A `/etc/passwd`, `/etc/group` or
`/etc/shadow` line whose name field begins with `+` or `-` is interpreted as compat
directive syntax **only when the host's NSS configuration establishes `compat` semantics
for that database.** The parser recognises the shape from the line alone and never reads
`nsswitch.conf` (§2); the collection layer receives each database's NSS mode explicitly and
classifies the line from it. `compat` is established only when `nsswitch.conf` was fully
interpreted, the database lists `compat` without `files` (both together read the same
lines two ways), its `<db>_compat` map is undeclared or names no service that reads the
local file (otherwise `+` re-reads this file literally), and, for `group`, `initgroups`
is undeclared or resolves in the same mode (it reads `/etc/group` itself).

```text
NSS ESTABLISHES COMPAT     + valid +/- line    directive evidence · NOT an account
                                               NOT identity STATE · NOT PARTIAL by itself
NSS DOES NOT (e.g. files)  + +/- shaped line   not reinterpreted · PARTIAL
                                               reason COMPAT_SYNTAX_WITHOUT_COMPAT
NSS MODE NOT ESTABLISHED   + +/- shaped line   compat never guessed · PARTIAL
  (missing, unreadable, unsupported,           reason NSS_MODE_NOT_ASSERTED
   duplicate, undeclared, files + compat)
```

A line left uninterpreted is recorded by line number, sign, target kind and name length
only, never its text.

**Under `compat`.** A directive is retained, with its line number and provenance, in a
separate `directives` evidence structure; it never enters `records` or canonical identity
STATE. Its presence is remote-identity scope evidence (`IDENT-040`: detected, never
enumerated).

- *Leading blanks.* glibc skips leading C-locale blanks, so `\t+alice` is the directive
  `+alice`: valid, and never an account.
- *Redaction (§7 outranks "verbatim").* The password field passes through the same
  redaction as any account and is never retained as text. Override fields are kept as
  written only for a valid directive in `/etc/passwd` or `/etc/group`; in `/etc/shadow`,
  and in any malformed directive, only each field's shape (`EMPTY`, `INTEGER`, `OTHER`) is
  kept, because a hash can be placed in any field. A malformed directive keeps no name
  text, only its length.
- *Numeric overrides.* An override in a numeric position must be empty or an integer
  within the signed 64-bit range; anything else makes the directive malformed.
- *Absence claims (§11a).* A source carrying any INCLUDE directive, valid or malformed,
  supports no absence claim: the included map may hold exactly the entries missing locally.
- *Local records after an INCLUDE.* glibc consults the included map at the INCLUDE's
  position, so a local record after it is not resolved from the file alone (map
  unavailable: not returned; available: the map can supply or shadow it; measured). Such a
  record carries `RESOLUTION_AFTER_COMPAT_INCLUDE` and its source is `PARTIAL`
  (`COMPAT_LOCAL_AFTER_INCLUDE`). A local record before every INCLUDE, or after only
  NAME EXCLUDE naming a different account, is unaffected; the classic NIS layout with `+`
  last stays `COLLECTED`.
- *Local records after an EXCLUDE.* glibc applies `-alice` to a local `alice` after it:
  she is enumerated but not resolvable by name (measured). A local record after an EXCLUDE
  naming it, or after any netgroup or name-less EXCLUDE, carries
  `RESOLUTION_AFTER_COMPAT_EXCLUDE` and its source is `PARTIAL` (`COMPAT_LOCAL_AFTER_EXCLUDE`).
- *Shadow joins.* A record whose resolution is not local by these rules never joins
  `/etc/shadow` confidently.
- *Mode not established.* Every local record after the first `+`/`-` line carries
  `RESOLUTION_AFTER_UNINTERPRETED_COMPAT_SYNTAX`: in either mode it may not be what glibc
  resolves.
- *Overrides glibc ignores.* EXCLUDE lines and group directives keep no override text.

**Directive order is collection-method identity, never STATE (rulings F6, M2).** Where a
directive sits among local lines changes resolution, not identity. Each file's directives
and the local records before its last directive form one ordered sequence, digested as
the compat directive topology. Fields are interpreted according to the supported compat
semantics: values that do not affect the measured resolution are excluded from source
identity, fields that do are represented canonically (a valid shadow directive's ageing
fields as integers), and secret-bearing fields are never retained as raw topology text. A
local record appears by name only when that name is a valid account name; otherwise, and
for a malformed NAME directive, by a text-free reference to the position of the local
record with the same name bytes. No name text and no name hash enters the topology.

**Records the same name reaches first (all modes).** glibc resolves a name from the first
line it accepts, and it accepts some lines this contract counts as malformed. A record
whose name first appears on a malformed line carries `RESOLUTION_SHADOWED_BY_EARLIER_LINE`
and is never the confident answer for that name. A record field that is not UTF-8 is kept
exactly as `hex:<bytes>`; a field never contains `:`, so the form cannot collide.

**File evidence and effective resolution are separate facts (owner ruling IQ-037,
2026-09-27).** A correctly read file stays `COLLECTED` and its records keep their
confidence whatever NSS does. Whether NSS consults each file is reported beside it:
`ACTIVE` (files or compat configured), `INACTIVE` (only known non-file services, such as
`passwd: sss`), or `NOT_ASSERTED` (an unknown service, an undeclared or duplicated
database, or an `nsswitch.conf` glibc would discard). A later comparison reads a change
from files to sss as a source change, never as accounts added or removed.

```text
VALID COMPAT DIRECTIVE (compat mode)   directive evidence · remote scope detected
                                       NOT an account · NOT identity STATE · NOT PARTIAL by itself
+/- LINE WITHOUT COMPAT MODE           not interpreted · PARTIAL
+/- LINE, MODE NOT ESTABLISHED         not interpreted · PARTIAL
PASSWORD-BEARING DIRECTIVE FIELD       redacted by §7 · never retained verbatim
SHADOW OR MALFORMED OVERRIDES          shape only (EMPTY / INTEGER / OTHER) · never their text
LEADING BLANKS BEFORE + OR -           skipped as glibc skips them · still a directive
ANY INCLUDE                            withdraws absence claims for that source (§11a)
LOCAL RECORD AFTER AN INCLUDE          its resolution is not local · PARTIAL
LOCAL RECORD AFTER AN EXCLUDE NAMING IT  not resolvable by name · PARTIAL
SAME NAME FIRST ON A MALFORMED LINE    the later record is not the confident answer
MALFORMED LOCAL ACCOUNT RECORD         retained with its anomaly · PARTIAL
MALFORMED COMPAT DIRECTIVE             retained with its anomaly · PARTIAL
```

**Why a valid directive is not `PARTIAL` under compat.** `IDENT-040`/`IDENT-041` already
separate the two: local accounts are canonical identity state, remote identity is detected
and never enumerated. If every legitimate directive forced `PARTIAL`, every host with NIS
inclusion would be permanently unapprovable for doing exactly what the frozen model
expects. ISEDRAF states three facts, none of them a failure:

    local identity fully observed
    remote identity provider or scope detected
    remote identities intentionally not enumerated

The rule for malformed records above is unchanged: nothing is silently skipped, and
malformed data still forces `PARTIAL`. A directive recognised as a directive has stopped
being misclassified as a malformed account; it has not become exempt from anything.

Earlier wording in the lane record said that under `passwd: files` glibc lists such a line
"with its uid and gid blanked". That holds only when those fields are empty; a line that
gives values is listed with them.

## 10. Fixture confinement

`acquire()` joins `root` and never escapes or defaults it. A fixture run that fell back to
the real `/etc` would produce a plausible-looking report about the machine running the test
instead of the machine under test. The negative control asserts that the account running the
tests, and `root`, are absent from a fixture whose passwd contains one invented account.

## 11. Open questions — resolved by owner ruling, W1-D contract review

| # | Ruling | State |
|---|---|---|
| Q1 | Recoverable record-level defects are `PARTIAL`; `ERROR` only when no trustworthy normalized interpretation can be produced. `SCOPE-022` clarified, not contradicted. | **APPLIED** (§5) |
| Q2 | `hash_scheme` accepted as a bounded normalized non-secret identifier. Never hash, salt, full field or unknown raw prefix. | **APPLIED** (§7) |
| Q3 | Readable, successfully parsed, zero records → `COLLECTED`. Empty is observed state, not incomplete collection. | **APPLIED** (§5) |
| Q4 | `gecos` is `OBSERVATION`, not baseline-bound `STATE`. | **APPLIED** (§4) |
| Q5 | `IDENT-070` must be resolved before freeze, and not improvised. | **BLOCKED — see below** |
| Q6 | `/etc/gshadow` out of scope; no claim of complete group administration state. | **APPLIED** (§8) |

### Q5 — CLOSED by owner resolution, 2026-09-21

`IDENT-070` asked for "a normalized skeleton" and never defined one. No TR39 dataset or
other confusables implementation was chosen to satisfy that wording, because the correct
fix for a requirement whose semantics were never specified is to amend the requirement,
not to pick an algorithm and call the result authoritative.

**What R1.5 records**

| | |
|---|---|
| identifier text | when it decodes losslessly |
| `name_bytes_hex` | the exact bytes, when it does not |
| `name_non_ascii` | true when any code point lies outside ASCII |

`NON_ASCII_IDENTIFIER` is an **OBSERVATION**. It implies nothing about spoofing,
confusability, maliciousness, invalidity, or any security finding. A Cyrillic `U+0430`
impersonating `admin` is flagged as non-ASCII and nothing more is claimed — which is both
useful and honest, because a name being non-ASCII is a fact and a name being *confusable*
is a judgement requiring data this project does not have.

**What R1.5 does not record:** no confusable skeleton, no `CONFUSABLE` classification, no
"looks like another username".

**Amendment text for `AMENDMENTS.md`** — owner-only, reproduced here so the wording is
fixed rather than paraphrased later:

> For R1.5 account-source inventory, ISEDRAF does not compute or emit a Unicode confusable
> skeleton and does not classify identifiers as confusable. ISEDRAF records deterministic
> source evidence only: identifier text when losslessly decodable, identifier exact bytes
> when not decodable, and `NON_ASCII_IDENTIFIER` when any identifier code point is outside
> ASCII. `NON_ASCII_IDENTIFIER` is an observation and does not imply spoofing,
> confusability, maliciousness, invalidity, or a security finding. A future
> confusable-analysis feature may be admitted only after its contract freezes: the
> algorithm/specification, the Unicode/confusables data source, the exact data version,
> licensing and provenance, normalization rules, cross-Python reproducibility, and a
> deterministic canonical representation. Such a result will be `DERIVED`, not source
> `STATE`, and must not alter the underlying account identity. `IDENT-070`'s
> confusable-skeleton requirement is therefore deferred from the R1.5 account-source
> contract and does not block that contract's freeze.

The acquisition defect that originally sat underneath this — `errors="replace"` silently
rewriting an identifier — was fixed separately and is not deferred.

## 11a. The project-wide absence invariant

> **NOT PRESENT is not the same fact as PRESENT BUT NOT OBSERVABLE.**

Both may map to `NOT_TESTED` at the individual source envelope under `SCOPE-022`. An
aggregator must keep the distinction: a source that genuinely does not exist may still
allow completeness, and a source that exists and was refused can never disappear from the
aggregate.

This has now recurred three times in three shapes — the passwd↔shadow join, PAM's
cycle-versus-diamond, and login-policy dropping a refused family — so it is recorded here
as project-wide semantics rather than as an account-lane detail. Both directions are
tested and both are falsified:

| Observation | Relationship | Aggregate |
|---|---|---|
| shadow absent | `SOURCE_NOT_COLLECTED` | `PARTIAL` |
| shadow exists, refused | `SOURCE_NOT_COLLECTED` | `PARTIAL` |
| shadow read completely, name not in it | `ABSENT_FROM_COLLECTED_SOURCE` | `COLLECTED` |

Only the third is an absence claim, and it is available only because the counterpart was
read in full.

## 12. Freeze condition

**FROZEN.** Every condition is met.

Q1–Q4 and Q6 were ruled and applied during review. Q5 is closed by the owner resolution in
§11: `IDENT-070`'s confusable requirement is deferred, with its readmission conditions
written down, and the acquisition defect underneath it was fixed rather than deferred.

Source provenance is explicit · partial-source behaviour is explicit · passwd↔shadow join
semantics are explicit and directional · group membership provenance is explicit · the
credential verifier cannot leave the parser · no UID, shell or group-name policy inference
exists · no creation time is inferred · fixture confinement is proven · malformed and
duplicate behaviour is explicit · the consumer boundaries are documented.

Downstream work consumes this contract. It does not reinterpret it.
