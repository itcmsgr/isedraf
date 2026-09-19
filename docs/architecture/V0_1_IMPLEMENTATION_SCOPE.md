# ISEDRAF — v0.1 Implementation Scope

Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0


## 1. Scope tiers

**SCOPE-001 (D-66, A14) SHALL** Prototype domains: host identity · identity and privilege (users, groups,
local sudo, `authorized_keys` fingerprints) · password and account ageing · SSH resolved state · mounts
declared/resolved/active · audit and journald recording coverage including time-sync quality.

**SCOPE-002 (D-66) SHALL** v0.1 release adds: kernel and platform facts · mandatory access control state ·
services · timers and cron.

**SCOPE-003 (D-66) SHALL** Later, explicitly **not now**: software inventory · listeners · hardware
inventory · privilege-surface scan · export signing · framework mappings.

**SCOPE-004 (D-08, D-49) SHALL NOT** Out of scope permanently: firewall assessment · AV · EDR/XDR ·
IDS/IPS · WAF · SIEM · cloud and network controls · external backup · remote patch availability · CVE
matching · whole-filesystem FIM · remote attestation · REST API · fleet server · database connector ·
automatic remediation apply · network egress.

**SCOPE-005 (D-64) SHALL** Platforms for v0.1: Debian 12 · Ubuntu 24.04 · Rocky Linux 9 · AlmaLinux 9.
Alpine, Arch, SUSE and any BSD are out of scope.

## 2. Domain specifications

### 2.1 Host identity

| | |
|---|---|
| Facts | app-specific `host_id` from machine-id; HMAC-SHA256 hardware serials/UUIDs; composite anchors; confidence score |
| Source | `/etc/machine-id`, DMI via sysfs |
| Privilege | unprivileged for most; some DMI fields root-only |
| Dimensions | active only |
| State | per `IDENT-002` — `confidence` is `PROVENANCE`, not state (W-20) |
| Observations | collection timestamp, run id |
| Pitfalls | cloned VMs share machine-id; containers may lack DMI; a rolled-back snapshot reuses identity |

**IDENT-002 (X-08, W1-A) SHALL** **The complete W1-A `host_identity` STATE object is:**

```json
{"host_id":"sha256:<64 lowercase hex>"}
```

Nothing else. No confidence score, no DMI UUID, no root-filesystem UUID, no virtualization, no timestamps,
no collection diagnostics enter the state hash in W1-A. Optional anchors are **not collected in W1-A**;
they are introduced with the requirements that need them.

**IDENT-003 (X-08, W1-A) SHALL** **The required source has exactly one frozen parser.** Generic trimming
is forbidden — `value.strip()` is how one host produced four different hashes from four conforming
readings.

| | |
|---|---|
| Source | `file:/etc/machine-id` |
| Read | **at most exactly 4096 bytes**, one bounded read (Z-21). `≤ 4 KiB` left the bound to the implementer while a golden vector pins behaviour across it; a threshold a vector depends on is part of the specification. A source longer than the bound is `IDENT-004` row 2 |
| Accepted syntax | **exactly 32 characters from `[0-9a-fA-F]`**, optionally followed by **exactly one LF**. Uppercase is **accepted** and lowercased by normalization (Y-14) |
| Normalization | remove that optional single LF; ASCII-lowercase the hex |
| Rejected | any other whitespace · CR or CRLF · embedded newline · non-hex · wrong length · the all-zero value · systemd first-boot `uninitialized` |

**IDENT-004 (X-07, W1-A) SHALL** **Section status is a total, ordered decision list**, evaluated top-down;
the first matching row wins. `PARTIAL` does not occur for `host_identity` in W1-A.

The rows are **mutually exclusive and exhaustive**; earlier phrasing let a missing file and
`uninitialized` each match two rows (Y-09).

| Order | Condition | Status | `reason` |
|---|---|---|---|
| 1 | `ENOENT` on `/etc/machine-id` — the source does not exist | `NOT_TESTED` | `SOURCE_ABSENT` |
| 2 | any other I/O error, including `EACCES` and over-long read | `ERROR` | `SOURCE_UNREADABLE` |
| 3 | read succeeded, content **rejected** by `IDENT-003` — wrong length, non-hex, CR/CRLF, embedded newline, all-zero, or the systemd first-boot literal `uninitialized` | `ERROR` | `SYNTAX_REJECTED` |
| 4 | read succeeded and content **accepted** by `IDENT-003` | `COLLECTED` | `null` |
| 5 | any other, unanticipated failure — the **catch-all** | `ERROR` | `INTERNAL_ERROR` |

Row 5 resolves Z-04. `SNAP-022` froze `INTERNAL_ERROR` while the four preceding rows could not emit it, so
two frozen requirements contradicted. A catch-all **ordered last** restores reachability *and* preserves
the exhaustiveness claim — a total list needs a final row that matches everything remaining. In a trust
tool an unhandled failure must become a named `ERROR`, never a silent pass.

`PARTIAL` does not occur for `host_identity` in W1-A.

**IDENT-005 (X-08, OD-02 RESOLVED) SHALL** `host_id` is derived from the **normalized** source bytes:

```text
host_id = "sha256:" + lowercase_hex( HASH_FRAME_V1("ISEDRAF:HOST-ID:V1",
                                     utf8(normalized_machine_id)) )
```

`identity_scheme` is the literal `"machine-id-sha256-v1"` and lives in **provenance**, not in state, so a
future change of derivation is visible as a scheme change rather than an unexplained comparison failure.

**IDENT-006 (X-09, W1-A) SHALL** **`source_id` is per field, never one compound literal for a section**, so
that a field's method identity cannot change because an unrelated optional source became unavailable:

| Field | `source_id` |
|---|---|
| `host_id` | `file:/etc/machine-id` |

Grammar: `file:<absolute path>` · `cmd:<absolute path>`. W1-A uses only the first.

**IDENT-001 (D-74) SHALL** All identity views derive from **one** canonical identity collection. A second
audit SHALL NOT be run to render a different view. Quick and detailed views SHALL be provably derived from
the same normalized evidence (acceptance test 17: hash-equal source).

### 2.2 Identity and privilege

**IDENT-010 (D-74) SHALL** `isedraf identity users` exposes, where collected: username · UID · account
class (human/service/system) · login state · password state · **absolute** password-expiry date/state ·
**absolute** account-expiry date/state · privilege class · concise flags.

**IDENT-011 (D-74, D-36) SHALL NOT** Relative values such as "63 days remaining" are renderer observations
only and SHALL NEVER be stored as canonical state.

**IDENT-012 (D-74) SHALL** `isedraf identity user <name>` exposes, where available: identity source ·
UID/GID · primary and supplementary groups · shell · home path, ownership and relevant permissions ·
password state · last password change · minimum age · maximum age · warning period · inactive period ·
password expiry · account expiry · UID-0 state · root-group membership · local sudo indicators and
effective local sudo assessment · `NOPASSWD` state where safely assessable · `authorized_keys` presence,
count and fingerprints · activity observations · account-creation provenance · findings/change references.

**IDENT-013 (D-74) SHALL** `isedraf identity groups`, `identity group <name>` and `identity privileged`
are supported from the same evidence model.

| | |
|---|---|
| Source | `getent passwd/group/shadow`, `/etc/passwd`, `/etc/group`, `/etc/shadow`, `~/.ssh/authorized_keys`, `cvtsudoers -f json` |
| Privilege | `/etc/shadow` and other users' `authorized_keys` need root |
| Dimensions | declared (files) + resolved (`getent`, `cvtsudoers`) |
| State | accounts, groups, memberships, ageing fields, key fingerprints, resolved sudo privilege |
| Observations | last login, current "days remaining" |
| Pitfalls | **SSSD/LDAP/AD enumeration** — see `IDENT-040`; `lastlog` deprecation (OD-03); `cvtsudoers` availability (OD-04); `authorized_keys` may live outside the home directory via `AuthorizedKeysFile` |

**IDENT-020 (D-74) SHALL** A locked password combined with a valid SSH key, an interactive shell and a
`NOPASSWD` sudo rule SHALL be detected and explained as an effective-access path (acceptance test 9).

**IDENT-030 (D-47) SHALL** A newly privileged identity — a new UID 0, new root-group membership, or a new
local sudo grant — SHALL be classified `SECURITY_REGRESSION` and SHALL appear in `identity privileged`
(acceptance tests 8, 16).

**IDENT-040 (D-67, S-18) SHALL** SSSD, LDAP or AD presence is **detected**; effective remote identity state
is `NOT_TESTED` with a reason. `sudo -l -U` SHALL NEVER be run by default. Enumeration of a remote
directory SHALL NEVER be attempted — therefore the resolved source for canonical identity state is a
**source-restricted** lookup (`getent -s files`, or per-key lookup over locally declared names only).
A bare `getent passwd` fans out to every NSS module and **is** that enumeration; it SHALL NOT be used.

**IDENT-041 (S-19, NEW) SHALL** Canonical identity **state** contains only accounts whose NSS source is
`files`. Each entity records its `source` as a state field. A remote identity provider appearing or
disappearing between snapshots raises **one** explicit `COLLECTION_SCOPE_CHANGED` finding — never hundreds
of `ADDED` rows, never remote personal data in host state, and never a `SECURITY_REGRESSION` for a
directory account.

**IDENT-070 (S-45, NEW) SHALL** A `CONFUSABLE` / `NON_ASCII_IDENTIFIER` flag is computed by comparing a
normalized skeleton of each local account name against every other local account name, and is surfaced in
`identity users`, `identity privileged` and `explain`. The offending name is rendered with escaped code
points alongside. Canonical state itself is **never** normalized (`NORM-035`); the skeleton is stored
separately for detection only. A Cyrillic homoglyph impersonating an administrator is exactly the class of
fact a host-assurance tool exists to surface.

**IDENT-050 (D-75) SHALL** Account-creation provenance follows `EVID-020`: `EVENT_RECORDED` only from an
auditd `ADD_USER` record or trusted journal fields (`_UID=0` plus the real account-management binary in
`_EXE`); `ESTIMATED` with confidence `LOW` for home-directory birth time; otherwise `UNKNOWN`.

### 2.3 Password and account ageing

| | |
|---|---|
| Source | `/etc/shadow`, `getent shadow`, `chage`-equivalent fields |
| Privilege | root |
| State | absolute dates and integer ageing fields only |
| Observations | days remaining, computed at render time |
| Pitfalls | epoch-day vs date confusion; `-1`/empty/`99999` sentinels; a locked password (`!`/`*`) is not an expired password |

**IDENT-060 (D-36) SHALL** Only absolute dates and integers enter canonical state. Sentinel values are
normalized to explicit named states, never to a computed date.

### 2.4 SSH resolved state

| | |
|---|---|
| Source | `sshd -T` (resolved), `sshd_config` + `Include` (declared), running process |
| Privilege | `sshd -T` generally requires root |
| Dimensions | declared + resolved + active |
| State | resolved setting names and values from `sshd -T`; declared `Include` set |
| Observations | sshd PID, process start time, `POSSIBLE_STALE_DAEMON` |
| Pitfalls | **`Match` blocks** — `sshd -T` without `-C` reports only the global context; `Include` directives (Debian 12 / Ubuntu 24.04 ship `Include /etc/ssh/sshd_config.d/*.conf`); a running daemon may predate the on-disk config |

**SCOPE-020 (D-13, D-34) SHALL** SSH resolved state is taken from `sshd -T`. Because `sshd -T` reports the
global context only, `Match` blocks SHALL be recorded as **declared context** and the limitation SHALL be
stated in the report. A per-user resolved evaluation (`sshd -T -C`) is **out of prototype scope**; its
absence is reported as `NOT_TESTED`, never as "no Match restrictions exist".

**SCOPE-021 (D-34, R-02) SHALL** SSH has **declared and resolved dimensions only**. Linux exposes no
loaded-configuration interface: `sshd -T` re-parses the on-disk configuration and a running `sshd` does not
publish its loaded values, so a resolved-versus-active `MISMATCH` **cannot be substantiated** and SHALL NOT
be asserted. Instead a `POSSIBLE_STALE_DAEMON` **observation** is recorded when the newest effective
configuration file mtime is later than the sshd process start time, explicitly labelled as not proving that
the loaded values differ.

**SCOPE-022 (S-14, NEW) SHALL** Collection status is decided by a table, not by implementer choice:
privilege or MAC denial → `NOT_TESTED`; tool absent → `NOT_TESTED`; tool present and failed (non-zero exit,
timeout, unparseable output) → **`ERROR`**, carrying the exit status and a bounded, sanitized stderr
excerpt in the reason.

**SCOPE-023 (S-15, NEW) SHALL** *Resolution failed while the subsystem is active* is a first-class
**finding**, not merely a collection status: result `MANUAL_REVIEW`, operational risk
`POTENTIAL_LOCKOUT` (`DELTA-020`). An unparseable `sshd_config` means sshd will refuse to start or reload —
the administrator is told that, not `NOT_TESTED`.

**SCOPE-024 (S-22, NEW) SHALL** A **boot-settling precondition** is recorded (`systemd is-system-running`,
time since boot). Until the system reaches `running` or `degraded`, affected sections degrade to `PARTIAL`
or `NOT_COMPARABLE` and SHALL NEVER produce a change. The shipped timer carries `After=multi-user.target`
and a randomized delay, so a post-reboot run cannot fabricate a `DISABLED`, a `REMOVED`, or the audit
`MISMATCH` that acceptance test 10 makes release-blocking.

### 2.5 Mounts

| | |
|---|---|
| Source | `/etc/fstab` (declared), `systemctl show *.mount` (declared/resolved), `findmnt -J` (active) |
| Privilege | unprivileged suffices for most |
| State | target, source (normalized), fstype, normalized option set |
| Observations | **`id`, `parent-id`, `maj:min`**, device enumeration order, free space — these change across reboots and SHALL NEVER enter state (R-10) |
| Pitfalls | systemd **`tmp.mount`** may provide `/tmp` with no fstab entry; bind mounts; autofs; namespaces may hide mounts; option normalization (`rw` default vs explicit) |

**SCOPE-030 (D-34) SHALL** Mount options are normalized before comparison so that a default-implied option
and an explicitly stated identical option produce the **same** canonical state.

**SCOPE-031 (D-67) SHALL** Filesystem inspection covers local filesystem types only, SHALL NOT cross mount
points, and SHALL degrade to `PARTIAL` on exceeding a time budget.

### 2.6 Recording coverage

**REC-001 (D-76) SHALL** `isedraf recording` reports these classes: authentication · SSH
authentication/session · sudo/privilege use · account and group change · audit subsystem · journal
persistence · time-synchronization quality.

**REC-002 (D-76) SHALL** Per class: collection source · observable yes/no · persistence and volatility ·
declared/resolved/active where applicable · oldest and newest observable event times as **bounded
observations**.

**REC-003 (D-76) SHALL NOT** Not observing an event class SHALL NOT be reported as "not recorded" unless
configuration or state evidence proves it.

**REC-004 (D-76) SHALL** Remote forwarding success SHALL NEVER be claimed. Locally detected forwarding
configuration is inventory context only.

**REC-005 (S-40, NEW) SHALL** When `timedatectl` reports the clock unsynchronized, or a backwards step is
observed, **every** event-time observation carries a `CLOCK_UNSYNCHRONIZED` or `CLOCK_STEPPED` qualifier
and no ordering conclusion is drawn from it. Without this, "newest" can precede "oldest".

| | |
|---|---|
| Source | `auditctl -s`, `auditctl -l`, `journalctl --header`, `journald.conf`, `timedatectl show` |
| Privilege | `auditctl` runs in a launcher-originated privileged branch (`D-26`, `PRIV-005`); `setpriv` **reduces, never grants** |
| State | audit enabled/immutable flag, normalized rule set, journald storage mode and persistence, time-sync source and state |
| Observations | **journal cursors, file names, on-disk size**, oldest/newest observable event time, uptime — never state (R-10) |
| Pitfalls | audit immutable mode (`-e 2`) blocks rule changes; journald volatile storage loses history on reboot; rsyslog/syslog-ng are **detected only** (D-67); time skew invalidates event-time reasoning |

**REC-010 (D-34) SHALL** Audit persistent-and-immutable versus loaded-and-unlocked is a `MISMATCH`
(acceptance test 10).

### 2.7 Explain

**EXPL-001 (D-77) SHALL** `isedraf explain <id>` implements the full contract in `HLD-051`. It is a
product contract, not console polish, and is implemented in the prototype.

**EXPL-002 (D-77) SHALL NOT** `explain` SHALL NEVER turn uncertainty into certainty. Where confidence is
`LOW` or state is `UNKNOWN`, it says so.

## 3. Milestones

**SCOPE-045 (D-102, OD-15) SHALL** Every normalized field declares exactly one category — `STATE`,
`OBSERVATION`, `DERIVED` or `PROVENANCE` — with **no implicit default**. Only `STATE` participates in
section hashes and delta. An unclassified field is a schema and CI failure. `collection_status` and
`confidence` are `PROVENANCE`; `effective_sudo_assessment` is `DERIVED`.

**SCOPE-046 (D-102) SHALL** Annotation alone is insufficient, because it cannot catch a **mis**-annotation.
The **empirical invariant** is release-blocking: N idle runs on an unchanged host produce byte-identical
canonical section state and byte-identical section hashes, asserted **per section**, naming any field that
breaks it — not merely "the report said zero changes".

**SCOPE-047 (D-102, D-98) SHALL** A change to the field-classification table is itself a
`COLLECTION_METHOD_CHANGED`, so reclassifying a field cannot masquerade as host evolution.

**SCOPE-048 (R-21, NEW) SHALL** A section state hash does not by itself bind the host it came from; the
manifest SHALL bind `host_id`, so state hashes are not transplantable between hosts.

**SCOPE-077 (Y-10, W1-A) SHALL** **The W1-A exit set is `0`, `2`, `64`, `70`**, and every frozen W1-A
outcome maps to one:

| Code | W1-A outcome |
|---|---|
| `0` | snapshot committed, `host_identity` `COLLECTED` |
| `2` | snapshot committed with `collection_status` ≠ `COLLECTED` (incomplete evidence), **or** `SNAP-018` `STORE_DISCONTINUITY` |
| `64` | usage or engine error |
| `70` | root or sudo execution refused (`SCOPE-071`) |

Codes `1`, `3`, `4`, `5`, `6`, `65`, `66`, `67` are **not reachable in W1-A**: they belong to comparison,
baseline and privileged execution. `SNAP-018`'s frozen `exit 2` is inside this set.

**SCOPE-076 (W-15, NEW) SHALL** The W1 exit set is `0`, `1`, `2`, `4`, `6`, `65`, plus `64` as the single
pinned usage/engine code and `70` for `SCOPE-071` root refusal. `64+` is a range, not a code: two
implementers exiting `64` and `70` would both conform, so W1 pins them. W1 precedence is
`5 > 4 > 6 > 3 > 2/1 > 0` restricted to this set. Codes `3`, `5`, `66`, `67` are not reachable in W1.

**SCOPE-070 (owner directive, 2026-09-18) SHALL** **W1 is unprivileged only.** W1 SHALL NOT implement
`systemd-run`, Linux capability manipulation, `auditctl`, privileged collectors, or a sudo execution path.
It runs under `ISEDRAF_STATE_ROOT` with every artifact carrying **`PRIV-004`'s DEV marker** — the
spelling is `PRIV-004`'s and is not restated here (W-19, `NRM-001`).

**SCOPE-071 (owner directive) SHALL** If W1 is executed as root or through sudo it **REFUSES**, with the
message *"prototype W1 does not yet support privileged execution"*, exit `70` (`SCOPE-076`). This is temporary and explicit, not a
silent degradation.

**SCOPE-072 (owner directive) SHALL** The privileged execution model — sandbox, root supervisor, capability
ceiling, pre/post privileged collection, engine privilege reduction, SELinux enforcing — is
**`DEFERRED_TO_FREEZE_SET_2`** and SHALL be proven against real Linux behaviour in the VM corpus rather
than in another prose round. Round 4 finding U-04 (that `AmbientCapabilities=` grants rather than bounds)
remains **BLOCKED** against Freeze Set 2; it cannot block W1, because W1 exercises none of that
architecture.

**SCOPE-073 (owner directive, U-05, U-06) SHALL** W1 ships **exactly one internal profile**, not a profile
system:

The profile object is frozen **verbatim**, because `profile_hash` is half of `BL-000001` (W-05):

```json
{"optional_sections":[],"profile_id":"prototype-host-identity-v1","profile_version":1,
"required_sections":["host_identity"],"tracked_sections":["host_identity"]}
```

`profile_hash = HASH_FRAME_V1("ISEDRAF:PROFILE:V1", canonical_bytes(profile_object))`, computed over the
object **without** a `profile_hash` field — it is not an input to itself. The expected hex ships as a
golden vector (`NORM-039`).

`required_sections == tracked_sections == ["host_identity"]`. There is **no** `--profile`, no profile
editor, no untracking, no mutable tracking policy and no generic baseline-policy language in W1.
First approval is therefore decidable with no circularity:

Baseline approval is **W1-B** and is out of the W1-A freeze set entirely.

**SCOPE-074 (owner directive, U-06) SHALL** The W1 baseline revision is the minimal form:

```text
BL-000001 = HASH_FRAME_V1("ISEDRAF:BASELINE:V1",
                          approved_snapshot_manifest_hash, profile_hash)
```

No granular acceptance, no baseline-policy mutation, no rebind in W1. Those are Freeze Set 2.

**SCOPE-075 (owner directive, W-13) SHALL** The W1 ledger records exactly three event types —
`snapshot_committed`, `baseline_approved` and `ledger_recovered` (required by `STORE-016`) — hash-chained, starting in `ledger/segment-000001.jsonl`; segments roll on recovery per `STORE-016`. A torn final record recovers to
the last completely verified record and marks the damaged tail; it SHALL NEVER be silently claimed valid.
Pruning, compaction, checkpoints and acceptance history are **`DEFERRED_TO_FREEZE_SET_2`**, so the
checkpoint cumulative hash W1 does not compute needs no domain (U-03).

**SCOPE-050 (owner directive, 2026-09-17) SHALL** After W0, implementation SHALL NOT proceed by building
every prototype domain in parallel. The **first vertical slice** takes one fact through the complete
lifecycle and proves silence on an unchanged host. Breadth follows only after that.

| Milestone | Content | Exit criteria |
|---|---|---|
| **W0** — governance | `.claude/settings.json`; activate `git-hooks` incl. unconditional `pre-push`; governance + frozen manifests; `make check`; **centralized falsifiability harness** (`GOV-002`); local secret-pattern gate (defense in depth only — **not** equivalent to GitHub secret scanning); exit-code source + generated `EXIT_CODES`; requirements-trace generator; `CURRENT_STATE` generator; doc lint (`GOV-007`) | `make check` green on a feature-free repo, **and every injected defect fails it** |
| **W1** — vertical slice: host identity, **unprivileged only** (`SCOPE-070`); Mode A topology is `DEFERRED_TO_FREEZE_SET_2` (W-31) | safe exec · host identity collection → normalization → canonical serialization → **snapshot treated as immutable** → section/manifest hashes → **ledger record** → explicit baseline approval → second snapshot → comparability → derived evaluation → classified delta → console and JSON output | **acceptance tests 2, 6, 7, 13, 14, 19, 22 pass**; 10 unchanged runs → 0 changes; first snapshot never auto-approved; crash before ledger append → recoverable `ORPHANED_UNLEDGERED` |
| **W2** — identity breadth | users, groups, local sudo, `authorized_keys`, ageing; identity views (`users`, `user`, `groups`, `group`, `privileged`); creation provenance | tests 9, 15, 16, 17, 21 |
| **W3** — SSH and mounts | SSH resolved state; mounts declared/resolved/active; sandbox re-exec with exit-code propagation and network restriction | tests 5, 11, 12; `MISMATCH` reported |
| **W4** — recording and baseline maturity | `recording` view; audit via a launcher-originated privileged branch (`PRIV-005`); pre/post audit fingerprint; `baseline rebind`; `accept`; `prune`; `verify`; export | tests 1, 3, 4, 8, 10, 18, 20 |

**SCOPE-060 (D-66, test 1, R-16) SHALL** Against a **defined reference host** in the corpus (vCPU, RAM,
disk class, account count, mount count), a default run with no optional scans completes in under 10 s.
A release-blocking test SHALL NOT rest on a `SHOULD`. Assigned to W4.

**SCOPE-062 (R-15, NEW) SHALL** Acceptance test 11 reads: no writes outside `/var/lib/isedraf` **except**
journald-mediated log records (required by `EXEC-005`) and systemd transient-unit runtime state under
`/run/systemd`. The diff is filtered to that allowlist, which is justified in the test. As previously
written the test was false by construction against the architecture's own requirements.

**SCOPE-063 (R-17, NEW) SHALL** `EVID-013`'s composite anchors carry an explicit table: each anchor, its
weight, its stability class, and thresholds producing exactly one of `SAME_HOST`,
`SAME_HOST_HARDWARE_CHANGED` (diff proceeds; the hardware change is reported), `POSSIBLE_ROLLBACK`,
`POSSIBLE_CLONE`, `BASELINE_NOT_APPLICABLE`. The diff is suppressed only for the last two, so a NIC swap or
a live migration SHALL NOT permanently blind the tool. Acceptance test 7 is assigned to **W1** and pins the
clone method, including at least one UUID-preserving and one UUID-reassigning case.

**SCOPE-061 SHALL** No milestone is complete while a requirement it claims is untested. Requirements not
implemented are `UNIMPLEMENTED`; requirements that cannot be implemented as written are `BLOCKED` with an
`IQ-` entry (`GOV-006`).

## 4. Deferred, recorded as FUTURE

Software inventory · service inventory · timers/cron expansion · framework mappings · API · fleet ·
database · CVE matching · firewall assessment · remediation apply · BSD or any non-Linux provider.
These are recorded in `docs/roadmap/ROADMAP.md` and SHALL NOT be implemented opportunistically (`GOV-006`).
