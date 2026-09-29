<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Accounts and hostio hardening — lane record

Status: EXPERIMENTAL
Implements: SCOPE-022, IDENT-041, IDENT-060, GOV-002

Opened by owner decision on 2026-09-24. Independent red-team passes on the NSS and hostname
lane found defects in code already on `main`: the local account parser disagreed with glibc
about what a line, a comment, a name and a number are, and `hostio` truncated large files
silently. The NSS lane's directive-order claim depends on this parser, so this lane comes
first.

## Principle (owner)

> Match the evidence-relevant parsing semantics of the libc behaviour we claim to model. Do
> not broaden the parser merely because glibc accepts exotic input, unless that acceptance
> affects evidence claims.

| Tag | Meaning | Treatment |
|---|---|---|
| MODEL | glibc accepts it and it affects evidence | modelled exactly |
| REJECT | glibc rejects the line | the record is kept (W1-D §9) but counted malformed: never trustworthy identity, and the source is `PARTIAL` |
| CONSERVATIVE | ISEDRAF is stricter than glibc | explicit `PARTIAL` with an anomaly, never silently different while claiming complete evidence |

## Measured glibc 2.43 behaviour

Measured with `getent` in an unprivileged private namespace (`unshare -rm`) against
bind-mounted synthetic files, `files` service only. Nothing on the host was read or changed.

| Input | glibc | Tag | ISEDRAF now |
|---|---|---|---|
| `\xc2\xa0#evil:x:0:0` | an account, uid 0 | MODEL | an account (was skipped as a comment: a hidden UID-0 account) |
| `  #c`, `\t#c`, `\v#c` | a comment | MODEL | a comment |
| `  lead:x:9:0` | account `lead` | MODEL | `lead` |
| `\f`, `\v`, `\r`, `\x1c`, U+2028 inside a line | stay in the field; only `\n` ends a line | MODEL | split on `\n` only (was `splitlines()`) |
| NUL | ends the line | MODEL | ends the line |
| uid `+0`, ` 0`; gid `+10`; shadow `+3`, ` 3` | read as the number | MODEL | read as the number (was `None`) |
| uid `abc`, empty, `1e3`; shadow `5x` | line rejected | REJECT | malformed, `PARTIAL`; the no-op `malformed += 0` is gone |
| a shadow line glibc rejects, before a valid one | the valid one is returned | REJECT | a malformed shadow line never enters the join index |
| uid `-1`, `4294967296` | wrapped or clamped to 4294967295 | CONSERVATIVE | malformed, `PARTIAL`: ISEDRAF does not state an id glibc had to invent |
| passwd with 4 or 8 fields | accepted, fields shifted | CONSERVATIVE | malformed, `PARTIAL` (unchanged) |
| a 5000-digit id, or thousands of leading zeros | — | bound | no `int()` over 4300 digits; zeros stripped first |

## Leaks closed

- `orphan_shadow_records` listed the name field of a malformed shadow line, which can hold
  a password hash when the first colon is missing. Malformed shadow lines no longer enter
  the join index, so they are never orphans.
- Duplicate-anomaly details printed names with `%r`. A name is now written only when both
  records are well formed; otherwise the detail says `(malformed line)`.

## hostio: truncated input is never complete evidence (owner invariant)

`read_file` and `read_file_lossless` read up to `OUTPUT_LIMIT` (1 MiB) and returned what
they had as a successful read. A UID-0 account placed after the first MiB of `/etc/passwd`
disappeared while the source said `COLLECTED`. Both now read at most the limit, then try one
more byte: if it exists, the result is `TRUNCATED` with reason `SOURCE_TRUNCATED` and **no
value**. `TRUNCATED` is a coverage outcome. The account lane reports it as `ERROR` with
`SOURCE_TRUNCATED`. `read_file_lossless` now opens the file once; it used to open it twice.

## Verification

Regression tests were written first and failed before each fix: `tests/test_accounts.py`
(`GlibcParsingSemantics`) and `tests/test_hostio.py`. Seven falsification injections, one
per item, fire.

## Independent red-team pass 1 — findings and dispositions

Merge criterion (owner): no new false-complete path, and no open HIGH or CRITICAL. The pass
found the criterion not met. Verdicts per area: truncation broken (F7), numeric ids (F3),
shadow joins broken (F1); comment detection and NUL/newline parsing held. Each finding below
was fixed with a regression test that failed first.

| # | Finding | Tag | Fix |
|---|---|---|---|
| F1 | glibc validates shadow field 9 and rejects `...:::\r` (CRLF). ISEDRAF joined that line and reported an account with an active hash as locked, COLLECTED | REJECT | field 9 must be empty or a glibc number; otherwise malformed, never joined |
| F2 | group members kept leading blanks glibc strips: wrong wheel membership and false orphans | MODEL | leading C-locale blanks stripped; an empty member dropped |
| F3 | regression: `-0` is uid 0 to glibc; this lane made it null | MODEL | `-0` is 0 |
| F4 | shadow values glibc transforms (other negatives become -1; above 2**31-1 they wrap) were recorded as written | CONSERVATIVE | only -1 and 0..2**31-1 are exact; the rest are malformed |
| F5 | undecodable names: false ABSENT, missed duplicate, canonical crash on members | MODEL | joins and duplicates keyed on exact bytes; a member is `hex:<bytes>` when undecodable |
| F6 | a 9-field shadow line with its first colon missing makes the name crypt text, which reached `orphan_shadow_records` | leak | a crypt-shaped orphan is reported by length only |
| F7 | regression: an oversized `/etc/hosts` or `/proc/self/mounts` became silent absence in `inventory` | truncation | `PARTIAL` with `SOURCE_TRUNCATED` |
| F10 | a FIFO at a source path hung collection | availability | `O_NONBLOCK` and a type check; FIFOs and sockets refused |
| F8 | `+name` lines trusted as accounts | — | resolved by the NSS lane's compat directive handling at rebase |
| F9 | other callers label `TRUNCATED` as NOT_TESTED or IO_ERROR; none reports it complete | LOW | recorded |

## Targeted re-check — findings and dispositions

The re-check found the merge criterion still not met, and several findings were created by
the round-1 fixes: piecemeal emulation of glibc's parser opened neighbouring cases.

| # | Finding | Status |
|---|---|---|
| N4 | three more inventory callers turned a truncated read into absence (os-release fallback, DNS stub, cpuinfo) | fixed systemically: every inventory read is tracked per subdomain; a TRUNCATED or I/O-failed read makes it PARTIAL with the sources named; os-release never falls back past an unreadable `/etc/os-release`. Live statuses on a real host are unchanged |
| N5 | the number regex backtracked quadratically (64k zeros, 18 s) | fixed: linear scan |
| N6 | two undecodable groups shared one orphan entry | fixed: deduplicated on exact bytes |
| N7 | an unreadable `/etc/hosts` (a directory, a FIFO) read as "no FQDN" | fixed by the N4 tracker |
| N1 | glibc re-appends a line's tail when it has leading blanks and no final newline (or a NUL): a false PRESENT | fixed through the differential harness: such a line is untrusted (malformed), never a guess at glibc's result |
| N2 | a line ISEDRAF is stricter about than glibc was excluded from the join, so a later duplicate was joined while glibc uses the first | fixed through the harness: only a well-formed FIRST record for a name is joined; a malformed first record makes the relation unknown |
| N3 | crypt text as a name (missing first colon) escapes any pattern (DES, argon2) | fixed by owner ruling (2026-09-26): untrusted field text is never echoed into diagnostics. `orphan_shadow_records` are `{line, name_length}`; duplicate details give lines and byte length only, valid names included. No pattern-based detection, no name hashes |
| N8, N9 | conservative forms; undecodable gecos/home/shell not yet canonical-safe | recorded, LOW |

## Differential harness against glibc (owner ruling N1/N2, 2026-09-26)

Case-by-case fixes of libc corner cases twice opened neighbouring cases, so agreement with
glibc is now an executable property rather than a list of patches.

- `tests/glibc_oracle_driver.py` runs inside `unshare -rm`, an unprivileged private
  namespace. It bind-mounts each case's synthetic files and asks glibc itself:
  `getpwent`/`getgrent`/`getspent` enumeration and `getpwnam`/`getgrnam`/`getspnam` lookups.
  It is a TEST oracle only: no glibc code is copied, and nothing in ISEDRAF calls it.
- `tests/glibc_differential.py` generates cases deterministically. It varies each dimension
  on its own (C-locale and Unicode blanks, names, `+`/`-`, ids, trailers, members, every
  shadow ageing field, duplicates with each first-line form, missing final newline), then adds
  seeded random combinations. Each result is classified by the owner's table: a MATCH or an
  explicit PARTIAL/untrusted passes; glibc rejecting while ISEDRAF says PRESENT, or ISEDRAF
  confidently resolving something different, fails.
- `tests/fixtures/glibc_differential/corpus.json` records the default-seed cases (764
  since the final re-check) with glibc's answers.
  `tests/test_glibc_differential.py` replays it in `make check` in about half a second,
  needing no namespace.

**Measured.** The first sweep had 82 of 675 cases failing, which exposed N1, N2, the
(uid_t)-1 representation in Python's `pwd` (a harness artifact, normalized) and a new
class: glibc's lookups refuse `+`/`-` names in files mode while enumeration lists them,
so such a name's shadow relation is unknown here (the NSS lane gives them compat meaning).
After the fixes: the default seed plus six seeds of 3000 random cases each, 19,650 cases
in total, 0 failing.

## Final re-check — findings and dispositions

The final re-check found the merge criterion not met and the harness blind in two places:
it never asked glibc's initgroups path, and it skipped accounts with an empty name. The
harness was extended first; it then reproduced both findings (31 of 764 cases failing)
before any code changed.

| # | Finding | Tag | Disposition |
|---|---|---|---|
| R3-1 | glibc's getgrent skips `#wheel:x:10:alice`, but initgroups/getgrouplist reads it: alice holds gid 10 while `/etc/group` was COLLECTED without that membership | CONSERVATIVE | a `#` line in `/etc/group` holding a `:` is kept as a malformed record, so the source is `PARTIAL`; a prose comment without `:` stays a comment. The harness now compares every confident account's `getgrouplist` whenever the group source is COLLECTED |
| R3-2 | an empty name: glibc returns `:x:0:0:...` and `getspnam("")` joins it, while ISEDRAF reported the shadow relation ABSENT | CONSERVATIVE | an empty name field makes the record malformed in passwd, group and shadow; empty names are no longer skipped by the harness |
| R3-3 | orphan claims were built from malformed records, echoing their text | leak | malformed group lines yield no orphan members and malformed account lines no orphan primary gids |
| R3-5 | the oracle driver failed on the NULL fields glibc gives bare `+` lines | harness | NULL is carried as null; bare `+`, `-`, `+:` lines are generated cases. The oracle runs with a pinned `LC_ALL=C` |
| R3-4 | group-member and primary-gid orphans still name what they refer to | LOW | since R3-3 they come only from well-formed records; member text is not validated (see R4-4); recorded |
| R3-6 | `hostio.run` output truncation | LOW | backlog |

**Measured after the fixes.** The default seed (764 cases) and seeds 1 to 7 with 3000 random
cases each (3364 cases per seed): 24,312 cases, 0 failing. Four falsification injections
(`DIFF-R3-1`, `DIFF-R3-2`, `HARD-R3-3`, `HARD-R3-3b`) fire. `/etc/passwd` and `/etc/group`
on the development host are still `COLLECTED`.

## Re-check R4 — findings and dispositions

The independent re-check (glibc 2.43 oracle, the project harness plus its own fuzzer: 15,864
cases, 0 failing) returned **MERGE CRITERION: met** for the six areas: truncation, numeric
ids, shadow joins, comment detection, NUL/newline and redaction in diagnostics. It found two
leaks into STATE, one of them created by R3-1, and one false absence in inventory. All three
were fixed before merge, each with a regression test that failed first.

| # | Finding | Severity | Disposition |
|---|---|---|---|
| R4-1 | the R3-1 group record kept a comment's text as `name` and `explicit_members` (STATE) | MEDIUM, from this lane | fixed |
| R4-2 | a malformed passwd or group record kept its name field in STATE; with the first colon missing that field is the password field (on `main` too) | MEDIUM | fixed with R4-1: a malformed record keeps its line, numbers and anomalies, and its name, home, shell, gecos and members are replaced by `name_length` and `member_count` (OBSERVATION). W1-D §9 retention and PARTIAL are unchanged; well-formed records are unchanged |
| R4-3 | a permission-refused `/etc/hosts` (mode 000, MAC denial) read as "no FQDN" under COLLECTED (on `main` too) | MEDIUM | fixed: the inventory read tracker counts PERMISSION_DENIED as incomplete, so the subdomain is PARTIAL. Live statuses on the development host are unchanged |
| R4-4 | member text in well-formed groups is not validated and can appear in orphan claims | LOW | recorded; it is already in `explicit_members` STATE, so nothing new is exposed |
| R4-5 | the oracle is glibc 2.43 only; `compare` does not check duplicate-name lookups or locale-dependent blanks; under `group: compat` the R3-1 PARTIAL is conservative | LOW | recorded as harness limits |
| — | a permission-refused `/etc/os-release` gives PARTIAL with the reason "SOURCE_ABSENT" | LOW | recorded |
