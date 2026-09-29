<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# authorized_keys lane interface contract

Status: IMPLEMENTED
Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, IDENT-041, GOV-001, GOV-002

Declared by the coordinator BEFORE implementation, so the adversarial pass attacks a
specification rather than an implementation. A test written after the code tends to agree
with the code.

## Interface

    isedraf.authorizedkeys.acquire.collect(root, account_evidence, ssh_evidence)
        -> shared.result.Evidence

Both evidence arguments are REQUIRED. A default that collected them itself would hide the
dependency and make a second acquisition path easy to add by accident.

    lib/isedraf/authorizedkeys/model.py     vocabulary; no I/O
    lib/isedraf/authorizedkeys/sources.py   PURE parser; text in, records out
    lib/isedraf/authorizedkeys/acquire.py   the only module that touches the host

## Two evidence layers, never collapsed

    SSH DECLARED CONFIGURATION
        -> AuthorizedKeysFile declaration        (value, scope, match criteria)
        -> candidate / source-plan evidence
        -> account identity + home               (from account evidence)
        -> path expansion where semantically justified
        -> file observation
        -> authorized_keys records

The lane produces **candidate sources that were observed**. It does NOT produce "the files
sshd will use for this account". That statement needs connection context the lane does not
have, and resolved-state evidence that does not exist yet.

## Dependencies, and what may not be re-derived

**Account evidence** (`isedraf.accounts.acquire.collect`) supplies account identity and
home. The lane MUST NOT read, parse or interpret `/etc/passwd` again. There is one account
model and one acquisition path for it.

Each key record carries a REFERENCE into that evidence, not a copy of it:

    account_ref = {
        "source":        "LOCAL_ACCOUNT_FILES",
        "name":          <account name, or null when undecodable>,
        "name_bytes_hex":<lossless identity, always present>,
        "uid":           <integer>,
        "nss_source":    "files",
        "passwd_line":   <integer>,
    }

`name_bytes_hex` is the part that is always present and always lossless. An account whose
name did not decode still has an identity; it does not have a `name`.

**SSH evidence** (`isedraf.ssh.acquire.collect`) supplies `AuthorizedKeysFile`
declarations, already carrying `scope`, `match_index` and `match_criteria`. The lane MUST
NOT re-parse sshd_config.

## Three axes, not three states

The first draft of this contract printed the three names below as "three states". They
are not: they sit on three different axes, and the adversarial pass read them as one,
which is the contract's fault and not the reader's (IQ-016). A single axis cannot say
"unresolved **and** read", which is exactly what a Match-scoped file that exists is.

| Axis | Field | Values |
|---|---|---|
| what the record IS | `kind` | `DECLARED_CANDIDATE_SOURCE` — constant; a candidate stays a candidate |
| where the declaration SITS | `scope` | `GLOBAL` · `MATCH` |
| could the PATH be built | `resolution` | `PATH_DERIVED` · `UNEXPANDED_TOKEN` · `HOME_NOT_AVAILABLE` · `DECLARED_NONE` |
| does the declaration APPLY | `applicability` | `UNCONDITIONAL` · `UNRESOLVED_MATCH_SCOPED` |
| what happened when we LOOKED | `observation` | `FILE_READ` · `FILE_ABSENT` · `FILE_UNREADABLE` · `FILE_NOT_REGULAR` · `GLOB_NO_MATCH` · `FILE_OUTSIDE_COLLECTION_ROOT` |
| is the CANDIDATE set known to be all | `source_universe` | `UNIVERSE_COMPLETE` · `UNIVERSE_INCOMPLETE` |
| which sources sshd would CONSULT | `effective_source_universe` | `NOT_EVALUATED`, always |

The first draft had four of these on two axes. `RESOLVED_FROM_GLOBAL` meant both "the path
was built" and "nothing conditions it", which made a Match-scoped candidate that was
successfully read impossible to describe — the same collapse IQ-016 fixed one layer up.

`kind` does not change on a successful read. A field that changed identity when a file
turned out to exist would imply the lane had learned something about whether sshd uses
it, and it has not.

**This document prints CONSTANT NAMES.** Every name above exists in `model.py`, spelled
that way, and a test asserts it. One name per concept and no aliases — the first draft
printed values instead, and 22 of 119 adversarial tests failed on nothing but spelling.

`source_universe` is `COMPLETE` only when every observed declaration was expanded for this
account with no unresolved token, no Match-scoped declaration, and no glob whose expansion
could not be enumerated. Otherwise `INCOMPLETE`, with reasons.

**A file observed successfully does not make the universe complete.** Reading a
candidate file proves that file's content; it proves nothing about whether sshd would
consult it, or whether another source exists.

### No declaration observed

If no `AuthorizedKeysFile` declaration is in the SSH evidence, the universe is
`INCOMPLETE` with reason `NO_DECLARATION_OBSERVED` and **no candidate is invented**.

OpenSSH has a compiled-in default. That default is a property of a build, and this lane
has no evidence of which build the host under test runs. Inventing
`~/.ssh/authorized_keys` from absence would be manufacturing a declaration. Recovering the
default is a RESOLUTION question for a later layer with resolved-state evidence.

### Match-scoped declarations — IQ-014, owner ruling

A `Match` block's `AuthorizedKeysFile` applies only under connection context the inventory
does not have. **The file IS read** when its path can be built deterministically from
declared SSH evidence and frozen account evidence.

Discarding a safely observable host fact because a later layer cannot yet decide whether a
connection activates it would break the architecture this project runs on:

    COLLECT ONCE · NORMALIZE ONCE · INTERPRET LATER

For `Match User backup Address <range>` with `AuthorizedKeysFile .ssh/internal_keys`, the
lane can truthfully establish that the declaration exists, that the candidate path for
`backup` is X, whether X exists, and which key records X contains. What it cannot
establish is that sshd would consult X for an arbitrary authentication attempt. Those are
different facts and they get different fields.

The candidate therefore carries `scope = MATCH`, `applicability =
UNRESOLVED_MATCH_SCOPED`, its criteria verbatim, `applies_to_account = UNDETERMINED`, and
whatever `observation` the read produced. Every key record from it carries the same
applicability and `effective_source = NOT_EVALUATED`. A directive inside `Match` is never
flattened into global scope.

### Two completeness axes, never collapsed

    DECLARED CANDIDATE UNIVERSE   COMPLETE
        does NOT imply
    EFFECTIVE AUTHORIZED-KEY SOURCE UNIVERSE   COMPLETE

Every declared candidate may have been read perfectly while the effective universe stays
unknown, because a `Match` condition is unresolved. Collapsing the two would let "we read
every file we could name" be reported as "we know every file sshd uses" — the most
attractive false claim available to this lane, and the one it would make on the tidiest
hosts, where nothing fails.

`effective_source_universe` is `NOT_EVALUATED` on every host, always, in R1.5. It is a
constant with a reason rather than a value that happens to be unknown today, because
R1.5 does not ask the question at all.

### `none`

`AuthorizedKeysFile none` is a declaration that no file is consulted. It is
`DECLARED_NONE` — not a path, not an absence of a declaration, and not an empty universe
that was observed.

## Path expansion

Authoritative for the format: `sshd_config(5)`, TOKENS section, on the host that generated
the corpus. Record the OpenSSH version with the evidence; a token table is version
specific.

    %%   literal '%'
    %h   the account's home directory
    %u   the account name
    %U   the account's numeric uid

Any other `%X` leaves the candidate `UNEXPANDED_TOKEN`, unobserved, and the universe
`INCOMPLETE`. Guessing an unknown token is inventing a path.

After expansion a value is **absolute, or relative to the account's home**. `%h` expands
in HOST space and the result then goes through the same absolute-path rule as any other
value; substituting the already-rooted home would send it through the root twice and
produce a path that exists nowhere. The rooted home is what a RELATIVE value is anchored
to, through `isedraf.hostpath.beneath`. See `ROOTED_PATH_CONTRACT.md`.

**Lexical containment is not enough.** `hostpath` guarantees the path is lexically inside
the root; it cannot see a home that IS a symlink pointing out, where the path is contained
and `open()` reads the collector's own machine. Every candidate is therefore resolved and
checked against the root before it is read, and one that resolves outside is
`FILE_OUTSIDE_COLLECTION_ROOT` — an observation, never an absence, because the file may
well exist. `realpath` appears there and nowhere else, as a check and never as identity:
the path recorded in the evidence stays the lexical one, because that is what the host
declared. It is a check rather than a guarantee — resolve-then-open is racy against an
adversary rewriting the tree between the two calls, and ISEDRAF observes rather than
defends. With root `/` every path is inside and nothing changes.

A symlink whose target is inside the root is read normally and recorded as a symlink: an
authorized_keys file kept as a link to somewhere else in the tree is an ordinary
administrative arrangement, and refusing it would report a configured source as
unreadable.

Wildcards are permitted in a declaration. A glob is enumerated through `shared.bounded`
inside the collection root; a glob matching nothing is `NO_MATCH`, which is not the same
observation as a named file being absent.

An account with **no home in the account evidence** yields `HOME_NOT_AVAILABLE` for any
value that needs one, universe `UNIVERSE_INCOMPLETE`. It does not yield a guess. A home
that is declared but **absent on disk** is a different observation: the candidate expands
normally and is `FILE_ABSENT`.

An **undecodable** home is used exactly, byte for byte. It is a valid byte path on Linux
and `textbytes` exists so such paths survive losslessly; refusing it would hand an
attacker an evasion, since a non-UTF-8 home would make an account's keys invisible to
this tool while remaining entirely usable to sshd. The contract said `HOME_NOT_AVAILABLE`
here and was wrong (IQ-017).

## Key records

One record per usable line. The parser in `sources.py` is PURE.

    account_ref            reference into account evidence (above)
    source_path            the observed file
    source_line, ordinal   position, preserved
    key_type               as written, e.g. "ssh-ed25519" — never normalised away
    key_fingerprint        SHA-256 over the decoded blob, base64, padding stripped —
                           byte-for-byte the value `ssh-keygen -lf` prints, verified
                           against it rather than asserted (IQ-016 / RED Q6). A
                           fingerprint an operator cannot compare with their own tooling
                           would be a private number for no benefit.
    key_digest_algorithm   the algorithm that produced it
    options                list of {name, value_retention, value?}
    comment_retention      NOT_RETAINED by default
    parse_status           PARSE_OK · PARSE_MALFORMED_BASE64 · PARSE_NO_KEY_MATERIAL
                           PARSE_MALFORMED_OPTIONS · PARSE_UNDECODABLE
                           PARSE_NOT_A_KEY_BLOB   decodes, but names no algorithm
                           PARSE_KEY_TYPE_MISMATCH  the text and the blob disagree
                           PARSE_OPTIONS_ONLY     options and no key
    duplicate_of           ordinal of an earlier identical key, or null

### Privacy

Public keys are not secret. The material around them frequently is.

- **Comment**: `NOT_RETAINED` by default. Comments carry names, email addresses, hostnames
  and ticket references. `DIGESTED` only under an explicit retention decision.
- **Option values**: `command=`, `from=`, `environment=` carry operator data — command
  lines, network topology, environment content. Retention is an explicit decision per
  option, not a default, and follows `shared.result`'s retention policy.
- **Option NAMES are retained.** `no-pty`, `restrict`, `cert-authority` are the behavioural
  facts a later criterion needs, and they carry no operator data.

The `shared.result` warning applies: digesting a low-entropy value is not privacy.

### Options are facts, not findings

`command=`, `from=`, `no-pty`, `restrict`, `cert-authority` are key-entry facts. The lane
records them. It does not conclude that a key is restricted, confined, safe or dangerous.

## Out of scope — nothing here may be claimed

    this key is trusted
    this key belongs to <person>
    this account can log in remotely
    this account is exposed
    this key is secure / insecure / weak
    these are the files sshd will use

Those are resolution and criteria questions for a later layer. R1.5 records source facts.

## An algorithm this lane has never heard of

There is no list of key types. The wire format names its own algorithm inside the blob,
so a candidate type is accepted when the blob agrees — which means an algorithm invented
after this code was written still parses, and is recorded with the type the file gives.
A maintained list would mislabel exactly those keys, and would have to be updated forever.

`PARSE_KEY_TYPE_MISMATCH` is therefore **disagreement**, not unfamiliarity:
`ssh-rsa <ed25519 blob>` is an RSA key the host does not have and that sshd would reject.
An unrecognised but self-consistent algorithm is `PARSE_OK`, with its type recorded
verbatim and nothing claimed about whether anyone knows it.

## Required adversarial coverage

Grammar: valid key · malformed base64 · unknown key type · multiple keys · duplicate keys ·
options before the key type · quoted option value · comma inside a quoted option value ·
malformed option quoting · arbitrary comment content · blank lines and comment lines.

Acquisition: missing file · unreadable file · partially readable file · symlinked path ·
symlinked home · fixture/live-host escape · undecodable bytes in a path or account name.

Declarations: multiple `AuthorizedKeysFile` declarations · relative-to-home value ·
absolute value · `none` · Match-scoped value · unknown token · glob matching nothing ·
glob matching several files · no declaration at all · account with missing or partial home
evidence · account evidence that is itself PARTIAL.

And the invariant that ties them together: **a file observed successfully must not imply
that all effective authorized-key sources were observed.**
