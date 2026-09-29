<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# NSS topology and hostname — lane contract

Status: PLANNING
Implements: IDENT-040, IDENT-041, CMP-020, SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, GOV-001, GOV-002

Batch 3, coverage-matrix rows **R** (DNS / NSS resolution) and **AB** (hostname / NSS
config), both recorded PARTIAL with `nsswitch` missing. Scope approved by the owner on
2026-09-24. This contract is written before the code, and its adversarial cases are written
as tests before the collectors.

## 0. Scope and claim boundary

Two concerns, kept apart:

```text
B1  HOSTNAME   configured = /etc/hostname
               active     = /proc/sys/kernel/hostname
B2  NSS        configured source topology = /etc/nsswitch.conf
               identity evidence          = local files only
               remote providers           = detection only
```

**This lane produces evidence. It emits no comparison finding.**

> **Dependency.** The W1-C comparison engine is required to emit
> `COLLECTION_SCOPE_CHANGED` / `COLLECTION_METHOD_CHANGED`. Lane B only establishes the
> canonical evidence needed for that later interpretation.

`delta_comparison` is PLANNED and nothing in the repository emits either finding today. A
lane that claimed to produce them would be claiming a behaviour of code that does not exist.
What this lane proves instead, by test:

```text
same /etc/passwd, NSS   files  ->  files sss

NOW (this lane)                          LATER (W1-C)
identity STATE bytes      unchanged      one collection-scope / method change
identity STATE digest     unchanged      no account drift
NSS topology evidence     changed
remote provider presence  detected
remote accounts           never enumerated
```

## 1. Evidence sources

| Source | Side | Read how |
|---|---|---|
| `/etc/nsswitch.conf` | declared NSS topology | bounded read under the collection root |
| `/etc/hostname` | declared hostname | bounded read under the collection root |
| `/proc/sys/kernel/hostname` | active hostname | bounded read under the collection root |

Nothing here calls a resolver, `getent`, `hostname(1)`, `hostnamectl`, D-Bus or any NSS
function. A lookup through NSS would make the evidence depend on the very topology being
described, and for identity databases it **is** the directory enumeration `IDENT-040`
forbids. The FQDN that `inventory/` already derives from `/etc/hosts` is a third concept and
is not touched by this lane.

Every path-sensitive component is tested at a fixture root **and** at `/` (mounts contract
§13, ruling F).

## 2. NSS canonical object

One record per database line, in file order. Order is not incidental: it is the query order.

```text
database   "passwd"
entries    [ {service: "files", class: LOCAL_FILES,       actions: []},
             {service: "sss",   class: REMOTE_DIRECTORY,  actions: []} ]
line       the source line number
raw        the line verbatim, after comment removal       (OBSERVATION)
semantics  KNOWN | UNSUPPORTED                            (with the reason)
```

An action clause attaches to the service **before** it:

```text
files [NOTFOUND=return] sss
  -> files  actions [{negated: false, status: "notfound", action: "return"}]
     sss    actions []
```

**Equality is structural and ordered.** None of these are equal:

```text
files sss   !=   sss files
files sss   !=   files [NOTFOUND=return] sss
files [NOTFOUND=return] sss   !=   files [!NOTFOUND=return] sss
```

**Normalization, and only this** (nsswitch.conf(5)):

| Rule | Why |
|---|---|
| `#` to end of line is a comment | file syntax |
| lines end at `\n` only; runs of space, tab, `\f`, `\v` and `\r` are one separator | glibc (red team F1: `splitlines()` broke on `\f`, hiding a service) |
| ASCII blanks inside a bracket are accepted, except directly after `!`: `[ NOTFOUND = return ]` and `[ !NOTFOUND=return]` are the compact form; `[! NOTFOUND=return]` is `UNSUPPORTED` | glibc 2.43 (red team F11, corrected by pass 2 #3: glibc rejects a blank after `!` and any non-ASCII blank) |
| a NUL byte ends the line | glibc stops reading there; the line is `UNSUPPORTED` (pass 2 #12) |
| `STATUS` and `ACTION` are lower-cased | "The case of the keywords is not significant" |
| a bracket may hold several `STATUS=ACTION` pairs; their order is kept | not declared commutative, so not assumed so |
| service names are kept verbatim | they name `libnss_<service>.so`; case is not declared insignificant |

Nothing is sorted, de-duplicated or defaulted.

**Unsupported semantics are preserved, never normalized away.** An unknown `STATUS` or
`ACTION`, a malformed bracket, a bracket before any service, a second consecutive bracket
(glibc stops parsing there, red team F2), or a line with no colon after the database name
(glibc honours it, red team F3) keeps the line verbatim,
marks its record `semantics: UNSUPPORTED` with the reason, and adds an anomaly. The record
still counts: it is evidence that the host is configured in a way this lane cannot fully
interpret.

| Case | Treatment |
|---|---|
| database line absent | not synthesized. glibc applies a built-in default that varies by version, so the default is recorded as `DEFAULT_NOT_ASSERTED`, never guessed |
| file absent | `NOT_TESTED` with `SOURCE_ABSENT` (SCOPE-022, as the account lane does); every required database is `DEFAULT_NOT_ASSERTED`, and the absence has its own stable digest |
| file unreadable | `NOT_TESTED` when permission is denied, `ERROR` otherwise (SCOPE-022); no topology is claimed |
| file resolves outside the collection root | `NOT_TESTED` with `SOURCE_OUTSIDE_COLLECTION_ROOT`, refused when the check runs (red team F9; resolved-target containment as in mounts). **Not race-free, and no defence against a hostile collection root**: a symlink swapped after the check, or a `/proc/<pid>/root` magic link over a bind mount, can still redirect the read (pass 2 #9, #10). The claim is a refusal of an ordinary escaping path, not proof of what was read |
| file is not a regular file (FIFO, device, directory) | `ERROR` with `SOURCE_NOT_REGULAR`, never opened: a FIFO blocked the collector (pass 2 #13) |
| an undecodable byte | kept as exact hex (`raw_bytes_hex`, `service_bytes_hex`), never replaced; the line is `UNSUPPORTED` |
| database named twice | both records kept, `DUPLICATE` anomaly, `PARTIAL`: which line glibc honours is not asserted |
| database glibc does not know (`sudoers`, `subid`) | retained; glibc ignores it, applications may not |
| `[SUCCESS=merge]` | a known action (glibc 2.24+); retained as data, its effect not modelled |

## 3. Service classification — closed vocabulary

| Class | Services | Identity meaning |
|---|---|---|
| `LOCAL_FILES` | `files` | the source `IDENT-041` admits into STATE |
| `COMPAT` | `compat` | local files **plus** in-file NIS inclusion directives (§5) |
| `LOCAL_NON_FILES` | `systemd`, `myhostname`, `mymachines`, `db` | local, but not `/etc/passwd`-shaped; outside STATE |
| `REMOTE_DIRECTORY` | `sss`, `ldap`, `winbind`, `nis`, `nisplus`, `hesiod` | detected, never enumerated |
| `RESOLVER` | `dns`, `resolve`, `mdns`, `mdns4`, `mdns6`, `mdns_minimal`, `mdns4_minimal`, `mdns6_minimal`, `wins` | host resolution |
| `UNKNOWN` | anything else | retained verbatim; never assumed local |

`UNKNOWN` is never treated as local. A service this lane cannot name is outside the
"local files" guarantee until someone classifies it on purpose.

## 4. Identity scope evidence (CMP-020, S-20)

For the identity databases `passwd`, `group`, `shadow`, `initgroups`, `gshadow`, and the
sources `compat` reads its inclusions from: `passwd_compat`, `group_compat`, `shadow_compat`
(nsswitch.conf(5): "By default, the source is nis, but this may be overridden") and
`netgroup`, which resolves `+@netgroup` (red team F4). The lane derives:

| Field | Class | Meaning |
|---|---|---|
| `identity_nss_topology` | `PROVENANCE` | the canonical records of §2 for those databases |
| `identity_nss_topology_digest` | `PROVENANCE` | SHA-256 of their canonical bytes, databases sorted by name (order between databases is not semantics; order within one is), **plus every `UNSUPPORTED` line of the whole file**: glibc 2.43 fails the whole file when one database line carries an invalid bracket, and identity lookups fail with it (pass 2 #2) |
| `non_files_identity_sources` | `DERIVED` | every service outside `LOCAL_FILES`, with its class |

**None of these is `STATE`.** The topology describes *how* identity is resolved; it is not
the identity. That is the whole mechanism by which an NSS change becomes a method or scope
change and never account drift: it never touches the hashed surface.

**Invariance, proven by test:** with `/etc/passwd`, `/etc/group` and `/etc/shadow` fixed,
changing only `nsswitch.conf` leaves the STATE projection of the account records (the
fields `accounts/model.py` classifies `STATE`, serialized by `canonical.canonical_bytes`)
byte-identical, and changes `identity_nss_topology_digest`.

The snapshot-level identity `state_hash` does not exist yet (`users_groups` is PLANNED,
`IQ-035`). This lane proves invariance of the STATE projection, which is what that hash will
be computed over; it does not claim the hash.

## 5. `compat` directives (W1-D §9 clarification, owner 2026-09-24)

In `/etc/passwd`, `/etc/group` and `/etc/shadow`, a line whose name field begins with `+`
or `-` is an NSS inclusion or exclusion directive, not an account.

```text
root:x:0:0:root:/root:/bin/bash
+@admins::::::
-user::::::
+

records / STATE     root only
directives          +@admins, -user, +      (verbatim, with line numbers)
remote scope        detected
remote enumeration  none
PARTIAL             no, when every directive is syntactically valid
```

A directive is valid when its name field is `+`, `+NAME` or `-NAME`, or `+@NETGROUP` /
`-@NETGROUP` in `/etc/passwd` and `/etc/shadow` only (nsswitch.conf(5) defines no netgroup
form for groups and no bare `-`), and the line is either the bare name field or carries the
source file's field count. In `/etc/shadow` every override field must be empty or an integer.
A name must be a valid account or netgroup name (letters, digits, `.`, `_`, `-`, one optional
trailing `$`): `+alice$6$…` is a shadow line missing its first colon, and its text is a hash
(pass 2 #6). A malformed directive keeps **no field text**, not its name either: only the
name's length and each override field's shape.
Leading blanks do not hide a directive (glibc skips them, red team F5); they are an anomaly. Anything else starting with `+` or `-` is a malformed directive: retained, an
anomaly, `PARTIAL`. A malformed account line stays exactly what it was: retained, an
anomaly, `PARTIAL`.

**Redaction outranks "verbatim".** The password field passes through the same
`_password_state` redaction as any account (W1-D §7). Override TEXT is kept only for a valid
directive in `/etc/passwd` or `/etc/group`. For `/etc/shadow`, and for every malformed
directive, only each override field's shape (`EMPTY`, `INTEGER`, `OTHER`) is kept: a hash
placed in a shadow override field was retained verbatim (red team F6).

The parser decides from the line alone. Whether a directive is *effective* depends on the
NSS topology (`compat` for that database). **Owner ruling IQ-036 (2026-09-27) replaces
the side-by-side reading that stood here:** the collection layer receives the NSS mode of
each database explicitly (`accounts.acquire.compat_context`, derived from NSS evidence; the
parser never reads nsswitch.conf) and gives `+`/`-` lines their meaning from it. Under
compat they are directives; where compat is not established they are not reinterpreted and
the source is `PARTIAL` (`COMPAT_SYNTAX_WITHOUT_COMPAT`); where the mode cannot be
established it is `PARTIAL` (`NSS_MODE_NOT_ASSERTED`). In compat mode, fields are
interpreted according to the supported compat semantics: values that do not affect the
measured resolution are excluded from source identity, fields that do are represented
canonically, and secret-bearing fields are never retained as raw topology text. (The
earlier sentence here said that under `passwd: files` glibc lists such a line "with its
uid and gid blanked"; that holds only when those fields are empty - `+alice:x:1000:...` is
listed with uid 1000, measured.) A source carrying any INCLUDE directive, valid or malformed, supports no
absence claim (W1-D §11a): the NIS map may hold exactly the entries missing locally
(pass 3, F2). It never looks inside the NIS map.

## 6. Hostname — declared vs active

```text
DECLARED  /etc/hostname              ACTIVE  /proc/sys/kernel/hostname
```

| Rule | Treatment |
|---|---|
| trailing newline | stripped, one; recorded |
| leading or trailing whitespace otherwise | not stripped: retained, anomaly |
| comments | `#` lines skipped: hostname(5) "Comments (lines starting with a "#") are ignored" |
| more than one non-comment line | `MALFORMED`, `PARTIAL`, every line retained exactly (pass 2 #11) |
| an undecodable declared or active name | exact bytes retained as hex, never replaced; an active name read in full is `COLLECTED` (pass 2 #11) |
| not a regular file | `ERROR`, `SOURCE_NOT_REGULAR`, never opened (pass 2 #13) |
| file absent | `DECLARED` absent: a fact, not an error. systemd may take the name from `systemd.hostname=` or elsewhere |
| file empty | `DECLARED` empty, recorded as such |
| `?` in the declared name | a **template**: systemd substitutes hex derived from machine-id(5) when applying it. Not emulated: `NOT_COMPARABLE` |
| a character outside `[a-z0-9.-]` (upper case included) | hostname(5): "invalid characters will be filtered out" when applied. Filtering is not emulated: `NOT_COMPARABLE` |
| longer than 64 characters, or not a valid DNS name (an empty label, a label beginning or ending with `-`) | hostname(5) says such a name is cleaned when applied; not emulated: `NOT_COMPARABLE` (red team F10) |
| `#` | a comment only in column 0, as hostname(5) says "lines starting with a #" |
| file resolves outside the collection root | `NOT_TESTED`, `SOURCE_OUTSIDE_COLLECTION_ROOT`, refused at check time; not race-free (see §2) |
| short vs FQDN | **never equal.** `foo` and `foo.example.com` are different strings and this lane does not decide they name one host |

Comparison is exact, byte for byte, and yields `EQUAL`, `DIFFERENT`, or `NOT_COMPARABLE`
with its reason (declared absent, empty, malformed, templated or subject to filtering, or
active unreadable). No `EQUIVALENT` category exists, because no equivalence rule has been
authorized. The two apply-time transformations systemd documents are exactly the cases in
which an exact comparison would report a false difference, so they are named rather than
compared.

**Non-claims.** `DIFFERENT` is NOT "misconfigured": a hostname set at runtime and not yet
persisted is ordinary. Absent is NOT "unknown hostname".

## 7. Requirement → component → test

| Requirement | Component | Tests |
|---|---|---|
| `IDENT-040` no enumeration | NSS, accounts | no resolver or NSS call on any path; remote provider present, zero remote records |
| `IDENT-041` STATE is files-only | accounts, compat | directives never in `records`; `nss_source: "files"` only on real accounts |
| `CMP-020` / S-20 NSS in method identity | §4 | topology change moves the digest and leaves STATE bytes identical |
| `SCOPE-020`…`022` status truth | all | absent / empty / unreadable / malformed each map to a stated status with a reason |
| `SCOPE-045` classification | §2, §4, §6 | every emitted field carries a class; topology is never `STATE` |
| ruling F | acquisition | fixture root and `/` |

## 8. Adversarial cases, written before the collectors

```text
HOSTNAME   /etc/hostname == active · != active · absent · empty · two lines · template "?" ·
           trailing space · "foo" vs "foo.example.com" · upper case (filtered on apply)
NSS        passwd: files · files sss · sss files · files [NOTFOUND=return] sss ·
           [!NOTFOUND=return] · two pairs in one bracket · keyword case ·
           unknown service · unknown STATUS · bracket before any service ·
           duplicate database · database absent · file absent · comments and tabs
IDENTITY   remote provider added · removed · same users, topology changed ->
           STATE identical, digest changed
COMPAT     valid directives -> root only, not PARTIAL · malformed directive -> PARTIAL ·
           malformed account -> PARTIAL
NO LOOKUP  resolver / NSS entry points unreachable from every lane module
```

## 9. Non-claims

The lane does not claim the host's effective identity set, which may be broader than local
STATE. It claims three facts: local identity fully observed, remote identity provider or
scope detected, remote identities intentionally not enumerated. It does not claim which
directory a remote provider points at, whether it is reachable, or what it would return.

## 10. Open questions for the owner

1. **`source_id` spelling for an NSS source set.** CMP-020 (S-20) makes the resolved NSS
   source set part of `source_id`, and the frozen grammar (W-27) defines only `cmd:`,
   `file:` and `files:`. This lane supplies `identity_nss_topology_digest` as the canonical
   value to embed. The spelling is a frozen-grammar extension, needed before W1-C or the
   identity snapshot writes an identity `source_id`. It does not block this lane.

## 11. Independent adversarial pass 1 — findings and dispositions

An independent red team attacked this contract and the first implementation without the
implementer's reasoning. Where nsswitch.conf(5) is silent it asked the machine's own glibc,
with `getent` in an unprivileged private namespace against synthetic files, using only
`files` and a nonexistent service. Every finding below was reproduced before it was fixed,
and each has a regression test that failed first.

| # | Finding | Disposition |
|---|---|---|
| F6 | a hash in a shadow directive's override field was retained verbatim | fixed: shadow and malformed directives keep override shape only |
| F5 | `\t+alice` became a local account in STATE, `COLLECTED` | fixed: directives detected after leading blanks, which are an anomaly |
| F1 | `\f`, `\v`, `\r` split lines, hiding `sss` behind a `files` digest | fixed: lines end at `\n` only |
| F2 | two consecutive brackets shared a digest with one bracket | fixed: the second bracket is `UNSUPPORTED` |
| F3 | a line with no colon was dropped | fixed: retained as `UNSUPPORTED`; an earlier test asserting the opposite was corrected |
| F4 | `*_compat` and `netgroup` changes did not move the digest | fixed: §4 lists them as identity scope |
| F9 | a symlink escaped a fixture root to the live `/etc` and `/proc` | fixed: resolved-target containment |
| F7, F8 | crashes on an unreadable `/etc/hostname` and on non-UTF-8 bytes | fixed: `NOT_COMPARABLE`; exact hex |
| F10 | false `DIFFERENT` for over-length and invalid DNS names | fixed: `NOT_COMPARABLE` |
| F11 | spaced brackets falsely unsupported; `[! X=Y]` un-negated | fixed |
| F12, F13, F14 | contract text disagreed with the man page, SCOPE-022 wording, and an unimplemented claim | contract corrected |
| LOW | database reorder moved the digest; indented `#` taken as a comment | fixed |
| LOW | dangling-symlink `/etc/hostname` reported `ABSENT`; `subprocess` imported transitively through `hostio` (never called) | recorded, not changed |

Outside this lane, recorded for the owner and not fixed here: `accounts/acquire.py` has no
resolved-target containment check either (the F9 class), and a non-directive account line
with leading blanks keeps the blanks in its name.

## 12. Independent adversarial pass 2 — findings and dispositions

A second independent pass attacked the pass-1 fixes and looked for new defects, again with
glibc 2.43 as the oracle. It found that the pass-1 fix for `[! X=Y]` was itself wrong.

| # | Finding | Disposition |
|---|---|---|
| 2 | an invalid bracket on `hosts` breaks glibc identity lookups; the identity digest did not move | fixed: every `UNSUPPORTED` line enters the digest |
| 3 | `[! X=Y]` is rejected by glibc but digested as `[!X=Y]`; Unicode blanks likewise | fixed: blank after `!` and non-ASCII blanks are `UNSUPPORTED`; the pass-1 test was corrected |
| 4 | `passwd sss x:y` was dropped, hiding `sss`; an unclosed bracket hid later services | fixed |
| 6 | a hash in a directive's name field (shadow line missing its first colon) was retained | fixed: names validated; malformed directives keep no field text |
| 9, 10 | containment escaped by a `/proc/<pid>/root` magic link and by a symlink race | contract corrected: a check-time refusal, not race-free |
| 11 | hostname dropped MALFORMED lines and undecodable bytes | fixed |
| 12 | `\x1c` treated as a separator; NUL not ending a line | fixed |
| 13 | a FIFO hung the collector | fixed: non-regular files refused |

**Found here, not in this lane, and handed to `lane/accounts-hostio-hardening` by owner
decision (2026-09-24):** an account line behind a non-ASCII blank and `#` hidden as a comment
(a UID-0 account, `COLLECTED`); `+0` and ` 0` IDs parsed as `None` and not counted malformed;
`splitlines()` in the account parsers; hash text reaching `orphan_shadow_records` from a
malformed shadow line; and `hostio`'s silent 1 MiB truncation reported as `COLLECTED`.

## 13. Independent adversarial pass 3 — findings and dispositions

| # | Finding | Disposition |
|---|---|---|
| F1 | a hash in a passwd uid/gid or group gid override was kept verbatim; glibc discards such a line | fixed: numeric override positions must be empty or integers, otherwise malformed, shape only |
| F2 | **regression**: a valid `+` stopped forcing `PARTIAL`, and absence claims (orphans) returned over a domain the NIS map widens | fixed: any INCLUDE withdraws absence claims; collection status is unchanged (W1-D §11a) |
| F3 | `[X=return!Y=return]` digested as two pairs; glibc rejects the file | fixed: an action ends at a blank or the bracket's end |
| F4 | `passwd::sss` recorded service `:sss`, UNKNOWN | fixed: blanks and colons after the database name are skipped |
| F5 | ~1000 unclosed brackets raised `RecursionError` | fixed: iterative |
| F7 | the implicit `nis` source of `compat` was invisible | fixed: an undeclared `<db>_compat` is `DEFAULT_NOT_ASSERTED` |
| F8 | a malformed but glibc-effective include reported `detected: false` | fixed: any INCLUDE counts |
| F10 | `/etc/hostname` symlinked to the kernel file compared equal to itself | fixed: `NOT_COMPARABLE` |
| F11 | §5 misdescribed `files` mode | text corrected |
| F6 | `-alice`, or `+` before a local `alice`, can make a local account unresolvable while STATE, digest and status are unchanged | owner ruling: directive order enters a source digest, never STATE (below) |
| F9 | a bare valid directive name may itself be secret-shaped text (`+SEKRET$`) | recorded: a name cannot be told from a secret by syntax; residual |
| F12 | an invalid bracket on an unknown database moves the identity digest, though glibc ignores it | kept: conservative, per §4 |

**F6 — owner ruling, 2026-09-24: directive order is collection/method identity.** Under
`compat`, `-alice` before a local alice excludes her, and `+` before a local line can
shadow it. That changes resolution, not identity. The account collector therefore emits
`compat_directive_topology` and `compat_directive_topology_digest`, both `PROVENANCE`:
each file as ONE ordered sequence of its local records and directives up to its last
directive (pass 5 replaced a per-directive set of preceding names, which leaked name text,
grew quadratically and could not express duplicates), where a local record appears only
as its name when that is a valid account name and otherwise as a text-free marker; and for
each directive its kind, target, valid name, password-field state (not for group: glibc
ignores it), and the
overrides glibc 2.43 actually applies under `compat`: passwd home and shell (glibc ignores
uid and gid overrides; gecos is excluded as personal data), no group override (glibc
ignores them all), and for shadow the canonical ageing integers of a valid directive (owner
ruling M2) or field shapes otherwise (pass 4, L1). A bare `+bob` and `+bob::::::` are
the same in passwd and group. Password and hash text, gecos and malformed field text never
enter, and formatting does not move the digest.
Proven by test: moving a directive across a local line leaves the account STATE
projection byte-identical and moves the digest.

**Owner-approved clarifications of W1-D §9 from this pass (2026-09-24):**
1. A source carrying any INCLUDE directive, valid or malformed, supports no absence claim
   (§11a). Collection status is unaffected: collection status is not absence-claim support.
2. In a passwd directive the uid and gid override fields, and in a group directive the gid
   override field, must be empty or integers; otherwise the directive is malformed and keeps
   only field shapes.

## 14. Independent adversarial pass 4 — findings and dispositions

Nothing above MEDIUM. No crash, hang or secret leak. The central proof held with the FULL
STATE projection, and all six owner-specified edge cases held (one with the L3 mislabel).

| # | Finding | Disposition |
|---|---|---|
| M1 | directive `position` counted local lines, so a reorder around a directive that changes resolution kept the digest | fixed: `preceded_by`, the set of preceding local records |
| M2 | shadow ageing overrides (`max_days` 3 vs 99999) are invisible because shadow keeps shape only | owner ruling YES (2026-09-24): a *valid* shadow directive's ageing fields, already validated as empty or integers, enter the topology canonically (integers as integers, so `03` = `3`; empty as `""`, since the all-empty form clears fields the bare form leaves). Password and hash text never; non-integer values stay malformed and shape-only |
| L1 | glibc ignores passwd uid/gid and all group overrides, yet they moved the digest; bare vs all-empty differed | fixed |
| L2 | directives glibc accepts (4, 5 or 8 passwd fields; `+5`; non-ASCII names) force `PARTIAL` | kept: conservative; recorded for the owner |
| L3 | a malformed directive's target was mislabelled `ALL` | fixed |
| L4 | a superseded duplicate database line still lists its remote provider (glibc 2.43: the last line wins) | kept: "not asserted"; recorded |
| L5 | a malformed directive's `name_length` enters the digest | kept, per §5 |
| L6 | the proofs' STATE projection omitted `shadow.*` and `group.*` | fixed: full projection |
| I1 | bracket parsing is quadratic (3.6 s at the 1 MiB cap) | recorded |
| I2 | `initgroups: compat` records no implicit source (inference, needs NIS to verify) | recorded |

## 15. Independent adversarial pass 5 (targeted) — findings and dispositions

Targeted at the code changed after pass 4. It found three HIGH defects in that code, and the
design itself was the cause: a per-directive set of preceding local names.

| # | Finding | Disposition |
|---|---|---|
| H1 | a hash-shaped local name (shadow line missing its first colon) entered `preceded_by` | fixed: the topology holds a local name only when it is a valid account name, otherwise a text-free marker |
| H2 | a valid shadow directive with an ageing value outside int64 crashed `collect()` | fixed: outside int64 is malformed, checked by digit count before `int()` |
| H3 | the topology was quadratic: 90 KB of input took 39 s and 1.4 GiB | fixed: one linear sequence per file |
| M1, M2 | duplicate names and lines glibc rejects made different resolutions share a digest | fixed by the sequence, which records every relative order |
| M3 | the proof helper's "full STATE" carried PROVENANCE shadow fields | fixed: strict STATE |
| L-a | a nameless record keyed by line number let a comment move the digest | fixed |
| L-c | the group password override moved the digest; glibc ignores it | fixed |
| L-b | ageing forms glibc treats as equal (`""` and `-1`, 32-bit wrap) differ; `+3` is malformed | recorded: emulating glibc's copy rules is not this lane's claim |
| L-d, L-e | a passwd password override of the same class, and gecos, do not move the digest | by ruling |

Handed to `lane/accounts-hostio-hardening` as well: hash text reaching `orphan_shadow_records`
from a malformed shadow line (already listed in §12), and names printed with `%r` into
duplicate-anomaly details.

## 16. Independent adversarial pass 6 (targeted) — findings and dispositions

Five blockers under the owner's criteria. Two were this lane's own and are fixed. Three have
their root cause in the account parser disagreeing with glibc about what a line and a name
are, which is `lane/accounts-hostio-hardening` scope by owner decision. F6's claim that the
topology captures every resolution-relevant order cannot be true while the parser disagrees
with glibc, so **the F6 claim is blocked on the hardening lane**, not merely incomplete.

| # | Finding | Disposition |
|---|---|---|
| P6-1 | `'0'*4301+'5'` in an override crashed `collect()` (Python's 4300-digit `int()` limit) | fixed: signs and leading zeros stripped before any `int()`; glibc's `strtol` value (5) kept |
| P6-5 | DES-shaped hash text from a malformed shadow line entered the topology by name | fixed: a record the parser marked malformed appears only as the marker |
| P6-2 | the invalid-name marker let different shadow resolutions share a digest | **fixed after the rebase** (section 17): a name the topology may not print is `{"ref": "passwd:N"}`, the position of the local record with the same bytes (group names refer into group); no text, no hash |
| P6-3 | two different malformed `-NAME` directives of one length collide | **fixed after the rebase**: a malformed NAME directive carries `name_ref` to the local record with the same bytes, from an in-memory key table that is never serialized |
| P6-4 | `\f`, `\v`, CRLF split lines where glibc does not, hiding or inventing directives | **fixed by the hardening lane**: lines end at `\n` only |
| P6-6 | the shadow join trusts a line glibc rejects (occurs with no directive at all) | **fixed by the hardening lane** (F1, N2) |

Survived: linear time and memory up to the 1 MiB cap across ten input shapes; exact int64
boundaries; STATE never moved by directive moves (3000-case fuzz); formatting; no other leak
(4000-case fuzz).

## 17. Rebase onto the hardened parser, and owner ruling IQ-036

The lane was rebased onto `main` after the accounts/hostio hardening lane (13 commits
replayed; conflicts were additive on both sides and resolved keeping both). Two tests then
failed, and both were right to.

- **RT-F5** expected a blank-prefixed directive to be malformed. The hardened parser skips
  leading C-locale blanks as glibc does, so `\t+alice` is the valid directive `+alice`
  under compat. The stale expectation was updated (owner, 2026-09-27).
- **The glibc differential corpus** failed on every `+`/`-` line: it runs glibc under
  `passwd: files`, where such a line is a literal entry (a bare `+` enumerates as uid 0),
  while the lane read it as a directive and stayed `COLLECTED` - a confident result
  different from glibc's. Owner ruling IQ-036: the meaning depends on the resolved NSS mode
  (section 5). Every harness case now carries the nsswitch.conf it was measured under,
  both sides read the same bytes, and the corpus adds compat, mixed, ambiguous
  (`files compat`) and undeclared families.

The NSS-aware harness then found two more things, both measured:

| # | Finding | Disposition |
|---|---|---|
| IQ-036-a | `passwd: files compat` enumerates the file once per service that reads it | the comparison models this exactly (`file_passes`); nothing relaxed |
| IQ-036-b | under compat, a local line AFTER an INCLUDE is not resolved from the file: with the map unavailable glibc does not return it, and with it available the map can supply or shadow it | CONSERVATIVE: that record carries `RESOLUTION_AFTER_COMPAT_INCLUDE` and the source is `PARTIAL` (`COMPAT_LOCAL_AFTER_INCLUDE`). A local line before every INCLUDE is unaffected, so the classic NIS host with `+` last stays `COLLECTED`. (This row first said "or after only EXCLUDEs"; red team pass 7 disproved that, F2 in section 18.) For the owner's final W1-D clarification |

Measured after: the default seed (836 cases) and seeds 1-3 with 3000 random cases each,
0 failing. Four injections cover the boundaries (`IQ-036 ...`).

**P6-2 and P6-3, after the context boundary.** Both are fixed with text-free references,
each with a regression test that failed first and an injection. A reference is a
position, so reordering `/etc/passwd` moves the compat topology digest when such a
reference exists; an order-independent reference would need a name hash, which the owner's
N3 ruling excludes. The digest describes collection method, never STATE. A name with no
local record to refer to keeps the marker; for a malformed directive the source is already
`PARTIAL`.

## 18. Independent adversarial pass 7 (targeted, after the rebase) — findings and dispositions

Criterion not met: four HIGH findings. The NSS-aware harness passed all of them because it
compared enumeration only, never keyed lookups, and generated no `initgroups`, netgroup,
duplicate-nsswitch, or group/shadow-after-directive case (F6). The harness was extended
first and reproduced every class (112 of 1034 cases) before any code changed.

| # | Finding | Sev | Disposition |
|---|---|---|---|
| F1 | `group: compat` with `initgroups: files` (or `sss files`, `db files`): initgroups reads `+wheel:x:0:alice` literally and grants gid 0 while group was COMPAT and `COLLECTED` | HIGH | group is COMPAT only when `initgroups` is undeclared or itself compat without files; otherwise `NSS_MODE_NOT_ASSERTED` |
| F2 | under compat an EXCLUDE before a local line leaves it enumerated but unresolvable by name (`getpwnam`, `getspnam`, `getgrnam`); section 17 wrongly said "after only EXCLUDEs is unaffected" | HIGH | a local record after an EXCLUDE naming it, or after any netgroup or name-less EXCLUDE, carries `RESOLUTION_AFTER_COMPAT_EXCLUDE`; the source is `PARTIAL` (`COMPAT_LOCAL_AFTER_EXCLUDE`) |
| F3 | the shadow join ignored `RESOLUTION_AFTER_COMPAT_INCLUDE` | HIGH | a compat-uncertain record enters the shadow index as unknown, never a confident join |
| F5 | a non-UTF-8 override byte crashed `collect()` or canonical serialization (lossless reads plus kept override text) | HIGH | undecodable override text is kept exactly as `hex:<bytes>` |
| F4 | mode not established but glibc uses compat (last line wins, stacked brackets): records after `+`/`-` lines stayed per-record confident | MEDIUM | every record after the first `+`/`-` line carries `RESOLUTION_AFTER_UNINTERPRETED_COMPAT_SYNTAX` |
| F7 | valid group directives kept member override text glibc ignores | LOW | no group override text is kept, and none enters source identity |
| F6 | harness blind spots | LOW | keyed lookups compared for every confident account and group, group names looked up, crashes and unserializable evidence are failures, and a pass-7 family covers the NSS variants and layouts above |
| info | a database whose services never read the file (`passwd: sss`, `passwd: Compat`): glibc resolves nothing from it, the collector reports the file | — | owner ruling IQ-037 (section 19) |

Measured after: default seed 1016 cases and seeds 1-3 with 3000 random cases each (3616),
0 failing. Held (measured by the pass): case-sensitive database names, `compat [..]` and
`sss compat` as compat, `files compat` not asserted, every unreadable or odd nsswitch
not asserted, the classic `+`-last layouts `COLLECTED`, no key or name text in output
across 45k fuzz iterations, and no record whose name starts with `+` or `-` in any mode.

## 19. Owner ruling IQ-037 — file evidence and effective resolution are separate facts

Owner, 2026-09-27, option A. "Did ISEDRAF read /etc/passwd correctly?" and "will glibc use
/etc/passwd to resolve this identity?" are different questions, and the answer to the
second never weakens the first.

```text
FILE COLLECTION TRUTH        /etc/passwd read and parsed        -> COLLECTED, records confident
EFFECTIVE NSS APPLICABILITY  from the nsswitch topology         -> ACTIVE / INACTIVE / NOT_ASSERTED
  passwd: files | compat | sss files                             -> ACTIVE
  passwd: sss                                                    -> INACTIVE (remote source detected)
  passwd: Compat (unknown module), undeclared, duplicated,
  or an nsswitch glibc discards                                  -> NOT_ASSERTED
```

`nss_file_effectiveness` (PROVENANCE) carries the state and the configured services per
file, and for group also `initgroups_files_effective`, because supplementary groups come
from `initgroups` when it is declared. An identity-database line naming a service no class
covers makes the NSS topology `PARTIAL` (`UNKNOWN_IDENTITY_SERVICE`): what the module
contributes or shadows is not asserted, even beside `files`. W1-C later reads files to sss
as a source and effective-scope change, never as account additions or removals.

The differential harness compares the two dimensions separately: glibc's answers are held
against the file only where ISEDRAF says `ACTIVE`; `INACTIVE` must mean glibc lists nothing
from the file; and a plain files/compat configuration must come out `ACTIVE`, so
`NOT_ASSERTED` cannot become a hiding place. Four injections cover the rule.

## 20. Independent adversarial pass 8 (targeted) — findings and dispositions

Criterion not met: three HIGH and one MEDIUM. The pass-7 fixes held for their classes;
these are neighbouring holes. N2 and N4 exist on `main` as well. The harness was extended
first and reproduced every class (108 of 1356 cases).

| # | Finding | Sev | Disposition |
|---|---|---|---|
| N1 | `passwd_compat: files` (or group/shadow) makes the included map the local file read literally: a bare `+` became a uid-0 account named `+`, under `COLLECTED` | HIGH | a database is COMPAT only when its `<db>_compat` is undeclared or names no service reading the file (files, compat, unknown); otherwise `NSS_MODE_NOT_ASSERTED` |
| N2 | a same-name line glibc accepts but ISEDRAF rejects (`alice:x:0:0::/r`) comes first, so getpwnam returns uid 0 while a later clean alice stood confident; group likewise | HIGH | a passwd or group record whose name first appears on a malformed line carries `RESOLUTION_SHADOWED_BY_EARLIER_LINE`, as the shadow index already treated it |
| N4 | a non-UTF-8 byte in a record's gecos, home or shell made the evidence unserializable (common: Latin-1 gecos) | HIGH | such a field is `hex:<bytes>` (a field never contains `:`, so the form is unambiguous); the authorized_keys lane decodes a `hex:` home back to the exact path, so keys under a Latin-1 home are still found |
| N3 | the mirror of F1: `group: files` with `initgroups: compat` | MEDIUM | whenever `initgroups` reads /etc/group in a different mode from `group`, the group mode is not asserted |
| L2 | EXCLUDE override text entered the topology though glibc ignores it | LOW | EXCLUDE lines keep no override text |
| L1 | two valid lines of one name: the second is enumerated but never resolved by name, yet stays per-record confident | LOW | **owner question** (tension between IQ-037's "record confidence is about the bytes" and F2's "not resolvable by name is not confident") |

The harness also had an oracle defect, found by this pass's N1 case: under `*_compat:
files` glibc keeps the file open, and with a lazily detached mount a batch read the
PREVIOUS case's file - a mismatch passed in the batch and failed alone. Each case is now
answered in a fresh forked process, so no glibc state crosses cases; the 26 N1 cases give
identical answers batched and one at a time. Keyed lookup values (not only presence) are
compared against the first confident record, and confident memberships must be granted by
getgrouplist even when the group source is `PARTIAL`.

Measured after: default seed 1356 cases and seeds 1-3 with 3000 random cases each (3956),
0 failing. Five injections.
