<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.2 Full Audit — Design and Gap Audit

Status: PLANNING
Implements: D-118, D-120, D-115, D-117

This is the design input for v0.2, Evidence Authority (D-120). It measures each collector against
privileged collection, proposes the evidence-authority contract (IQ-042) and the status-registry
model (IQ-043), and sets out an implementation plan. It authorizes nothing. Every item marked
PROPOSAL or OWNER DECISION waits for the owner, and nothing here starts v0.3: no criterion, no
evaluation and no finding.

Audited at engineering `main` `c935468`. Labels follow `docs/development/DOCUMENTATION_POLICY.md`
§9. Every code statement is a REPOSITORY FACT with a path. Runtime tests for this work run only on
the lab VMs, never on a development workstation (CLAUDE.md §2).

## 1. The boundary between v0.2 and v0.3

```text
v0.2 guarantees, per source and per section     v0.3 adds, reading committed evidence only
  observation (field classes, SCOPE-045)          ISE-* criterion and applicability
  source                                          expected state
  collector identity and version (CMP-020)        evaluation result (D-121, CMP-003)
  privilege level and authority                   finding and severity
  completeness and evidence limits
  provenance
  integrity (D-115 binding, D-50 commit)
```

v0.2 knows nothing about controls. It produces generic evidence whose metadata lets v0.3 join it to
`ISE-*` criteria without a rewrite and without a second evidence model.

## 2. Per-collector gap table

These are the current behaviours. GA 0.1.0 refuses to start under root or `SUDO_USER`
(`lib/isedraf/stateroot.py` `resolve()`), and no collector has a root branch. Under root, the only
difference would be that more reads succeed. **No audit section records method identity**
(`lib/isedraf/audit.py` writes `{schema_version, section, collection_status, reason, evidence}`),
and **`isedraf audit` never writes `coverage/evidence_limits.json`**, because `cli._commit_run`
does not pass `coverage_manifest`. Both apply to every row.

| Collector | Current privilege | Data collected | Missing privileged data | Collection status on a privilege denial | Privilege attribution | Evidence limits | Full Audit work |
|---|---|---|---|---|---|---|---|
| identity | unprivileged | `/etc/machine-id` → `host_id`, `state_hash` | none | `ERROR SOURCE_UNREADABLE` (frozen, IDENT-004) | none needed | no coverage entry | NONE |
| inventory | unprivileged | `/proc`, `/sys`, os-release, `ip -json`, resolv.conf, time sources | DMI serials (excluded by privacy policy, not by privilege); hidepid `/proc/1`; `statvfs` on restricted mounts | `PARTIAL SOURCE_INCOMPLETE`, or `NOT_TESTED` (dns) | **under-claims**: several denials are recorded as `IO_ERROR` with `privilege_limited=false` | one entry per subdomain, in the section only | NONE (fix attribution, §6) |
| nss | unprivileged | `/etc/nsswitch.conf` | none | `NOT_TESTED SOURCE_UNREADABLE` | correct | one entry (a dict, not a list), section only | NONE |
| hostname | unprivileged | `/etc/hostname`, `/proc/sys/kernel/hostname` | none | `NOT_TESTED SOURCE_UNREADABLE` | correct | two entries, section only | NONE |
| accounts | unprivileged | passwd, group, shadow (classified, never retained) | **`/etc/shadow`**: password state, lock, scheme, ageing, orphan shadow. `gshadow` is excluded by scope | source `NOT_TESTED`, so the section is `PARTIAL` | correct | three entries, section only | SMALL: one fixed operation reading the shadow file |
| sudo | unprivileged | the sudoers include graph | **`/etc/sudoers` (0440) and `sudoers.d` (0750)**: the whole policy on a stock host | `NOT_TESTED SOURCE_UNREADABLE`; an unreadable include gives `PARTIAL` | correct per node; no entry for the includedir listing | section only | SMALL: one fixed operation reading the resolved sudoers graph |
| ssh | unprivileged | the `sshd_config` include graph with Match scope | `sshd_config` 0600 and `sshd_config.d` 0700 on the EL family; **effective configuration** (`sshd -T` needs host keys) on every family | `NOT_TESTED SOURCE_UNREADABLE`; `ERROR UNPARSEABLE` | correct per node | section only | MEDIUM: declared read plus effective configuration, a new RESOLVED dimension, and SCOPE-023 (§6) |
| pam | unprivileged | `pam.d` stacks with include/substack edges | effectively none (`pam.d` is world-readable) | listing `NOT_TESTED`; an unreadable service gives `PARTIAL INCOMPLETE_STACK` | per file; none when the listing fails | section only | NONE |
| loginpolicy | unprivileged | login.defs, pwquality, faillock.conf, limits | opasswd and the faillock tally (not attempted, and not declared as not collected) | per-file `NOT_TESTED`, section `PARTIAL` | correct per file | section only | SMALL: faillock state and an opasswd count or digest, never hashes (needs a scope ruling) |
| mounts | unprivileged | fstab, `/proc/self/mountinfo`, the mount-namespace link | other processes' mount namespaces | `NOT_TESTED SOURCE_UNREADABLE`; an ERROR on one side becomes section `PARTIAL` | correct; the cleanest of the ten | domain aggregate, section only | SMALL–MEDIUM: one mountinfo per distinct namespace |
| authorizedkeys | unprivileged | key fingerprints for each account and declared `AuthorizedKeysFile` | other users' keys behind 0700/0750 homes; `AuthorizedKeysCommand`; the effective declaration | **defect: an `lstat` denial is recorded as absent** (§6, IQ-044) | mostly wrong because of that defect | section only | MEDIUM: privileged per-account reads over the account set the operation derives itself; depends on the ssh effective configuration |

**Size of v0.2, from the table** (INFERENCE). Four collectors need nothing. Four need one small
fixed operation each, over a parser that already exists and is tested on fixtures. Two need
medium work: ssh, for the effective-configuration dimension and SCOPE-023, and authorizedkeys.
Most of the cost is not in the collectors. It is in the authority architecture of §5, which is
decided in outline (D-118) but blocked on open decisions.

## 3. IQ-042 — the evidence contract (PROPOSAL)

The contract can be built **unprivileged first**. Nothing in it needs root, and Full Audit then
fills the same fields with more `COLLECTED` sources.

1. **Method identity per section (CMP-020).** Each section gains a `method` object:
   `collector_id`, `collector_version`, `parser_version`, `classification_table_version` and
   source identifiers. The constants are declared beside each entry of `audit.COLLECTORS`, not in a
   second registry. `audit.SCHEMA_VERSION` is incremented. The object sits inside
   `sections/<name>.json`, so the D-115 auxiliary set does not change.
2. **Evidence Limits Manifest written by `isedraf audit`.** A pure helper aggregates the per-source
   coverage entries, which today come in three shapes: `evidence.coverage` as a list,
   `evidence.coverage` as one dict (nss), and `evidence.provenance.coverage` (the six
   `Evidence`-based collectors, mounts as a domain aggregate). It adds one explicit entry per
   crashed section, so the requested universe never shrinks silently. `cli._commit_run` passes the
   result as `coverage_manifest`. The file is then bound through `manifest_core` (D-115), and
   `state_hash` does not change.
3. **The report renders it.** `committed_run` loads the manifest, and the JSON, Markdown and HTML
   renderings show the evidence limits instead of `null`.
4. **Authority fields.** Each coverage source gains `authority` (§5.3), so an unprivileged source
   and a supervisor-acquired source can never be confused.
5. **Record corrections, for the owner.**
   - D-115 already binds `coverage/evidence_limits.json` "when produced". IQ-042 and
     `POST_GA_ARCHITECTURE_CHECKPOINT.md` wrongly said its amendment had not reached the register;
     IQ-042 is corrected in this change.
   - The 2026-09-21 auxiliary-binding row in `AMENDMENTS.md` still reads "step 2 not reached" although D-115 carries its
     substance. Closing that row is an owner act.
   - The manifest's field schema is frozen nowhere. Owner direction 2026-10-06: freeze it before
     any privileged implementation, machine-consumable and verifier-friendly, never free-form only,
     covering per source: section and source, collector identity, authority, collection status,
     omitted scope, reason, and impact on interpretation.
   - Today `R15P_PRIVILEGE_AND_EVIDENCE_CONTRACT.md` §5 is only indicative, and the fields
     `coverage.py` emits differ from it. One schema is frozen before the file becomes part of
     committed evidence.

## 4. IQ-043 — status-registry truth (PROPOSAL)

`scripts/ci/project_status.json` lists `users_groups`, `sudo_privilege`, `ssh_state`, `pam` and
`mounts` as `PLANNED`, while `isedraf audit` collects all of them. It has no entry for nss,
hostname, loginpolicy, authorizedkeys, the `audit` command or `report --html`. The cause is
structural: `scripts/docs/current_state.py` never compares a `PLANNED` entry with the code, so
understatement cannot be detected.

Proposed model, a closed vocabulary per capability:

```text
status                 IMPLEMENTED | CERTIFIED | PLANNED | DEFERRED | NOT_TESTED | FUTURE (closed)
reachable_from         commands that reach it, e.g. ["audit", "report"]
audit_section          its SECTION_NAMES member, when it is one
authority              UNPRIVILEGED | FULL_AUDIT
full_audit_gain        NONE | SMALL | MEDIUM | LARGE   (planning value, from §2)
```

Gate change: `current_state.py` derives the expected set from `snapshot.SECTION_NAMES` and the
`cli.py` subcommands. It fails when a section or command has no entry, or when its entry is not
`IMPLEMENTED`. Two falsification injections hold that: "an audit section has no registry entry" and
"a collected domain is PLANNED". The existing `audit_subsystem` entry means Linux auditd and must not
be reused for `isedraf audit`. IQ-035, which still says these domains are reachable from no command,
closes with IQ-043.

## 5. Full Audit authority

### 5.1 Already decided (FROZEN REQUIREMENT)

D-118 sets the outline: `sudo isedraf audit` → transient systemd sandbox (PRIV-007) → tiny root
supervisor (lock, preflight, tool-integrity level, PRE collectors) → engine as a dedicated non-login
`isedraf` identity, with the minimum validated privilege set, unable to regain root, writing only
run staging → POST collectors → validation and atomic promotion (D-50) → root-owned committed
evidence. The analysing component cannot rewrite committed evidence, and the root component holds
no analysis engine. The IPC is run-private and bounded: no socket, no daemon, no internal sudo
(PRIV-010). These must also hold:

- PRIV-001 to PRIV-012 and PRIV-020 to PRIV-022;
- EXEC-001 to EXEC-005 and EXEC-010 to EXEC-020;
- INTEG-001 to INTEG-004.

A model that fails in the corpus stops and is recorded under OD-06. Capabilities are never widened
(PRIV-012).

### 5.2 The privileged operations (PROPOSAL)

These follow the fixed-operation rule in `docs/roadmap/ROADMAP.md`: each operation has a fixed
identifier and performs one predefined acquisition. It returns bounded bytes and a status, and it
takes no path, no argument vector and no tool name. Where an operation needs a set of accounts, it
derives that set itself from the account database. The caller never supplies it.

| Operation | Serves | Notes |
|---|---|---|
| shadow file read | accounts | the existing parser classifies and never retains hashes |
| sudoers graph read, including the `sudoers.d` listing | sudo | the existing include-graph parser |
| sshd declared configuration read | ssh | the existing include-graph parser |
| sshd effective configuration | ssh, authorizedkeys | needs host keys; a new RESOLVED dimension |
| per-account authorized_keys read | authorizedkeys | account set derived in the operation |
| mountinfo per distinct namespace | mounts | namespace-set model needed |
| faillock state, opasswd count | loginpolicy | **deferred** (owner direction 2026-10-06): outside v0.2 until a scope ruling |
| audit status and rules fingerprint (EXEC-004) | supervisor | blocked: IQ-025 (`CAP_AUDIT_CONTROL` also grants rule changes) |

Recording, journald and time synchronization are not collected at all yet (Batch 4). **They are
outside v0.2** (owner direction 2026-10-06): v0.2 adds only the operations that turn a known
incomplete or ambiguous evidence path into an authoritative observation. Those are the shadow read,
the sudoers graph, the sshd declared and effective configuration, authorized_keys after ssh
resolution, and mount namespaces where needed.

### 5.3 Authority vocabulary (owner direction 2026-10-06; frozen only by the P4 amendment)

The frozen documents name "authority classes" (D-118) and a "tool-integrity level" without
defining either. `lib/isedraf/coverage.py` has a single `acquisition_mode`, `CURRENT_IDENTITY`, and
says there is deliberately no elevated value. Proposal:

- **Authority per source:** `UNPRIVILEGED` (the engine as itself) or `SUPERVISOR_FIXED_OPERATION`
  (acquired by a named operation of §5.2), recorded with the operation identifier.
- **Tool-integrity level:** the existing INTEG-002 levels, `LOCAL_CONSISTENT`, `PACKAGE_CONSISTENT`
  and `EXTERNAL_VERIFIED`, recorded by the supervisor. It is never a claim that the host or the
  tool is uncompromised.
- **Privilege level line:** `PRIVILEGE LEVEL: FULL_AUDIT`, beside the frozen
  `PRIVILEGE LEVEL: UNPRIVILEGED` (D-117).

**Owner direction.** Keep only the levels v0.2 needs, and keep four concepts independent:

```text
evidence source authority   UNPRIVILEGED | SUPERVISOR_FIXED_OPERATION   how one item was acquired
run privilege mode          unprivileged run | Full Audit run            how the whole audit ran
integrity                   INTEG-002 levels                             what is known about the tool
collection status           COLLECTED | PARTIAL | NOT_TESTED | ERROR     what was observed (CMP-001)

authority != integrity != collection status != run mode
```

The owner named the run modes `USER_PRODUCTION` and `FULL_AUDIT`. `USER_PRODUCTION` is already the
frozen `state_root` artifact class (D-116), and PRIV-005 names the modes A and B, so the P4 amendment
settles the run-mode spelling without making one literal mean two things.

### 5.4 What an authoritative snapshot means (PROPOSAL)

Root is not completeness (`R15P_PRIVILEGE_AND_EVIDENCE_CONTRACT.md` §2; HLD-041 judges evidence
completeness and artifact class, not euid). A snapshot is authoritative for a declared evidence
universe when all of these hold:

1. it is `SYSTEM_PRODUCTION`, produced in Mode A (PRIV-005);
2. every source in the declared universe is `COLLECTED`, or proven absent over a complete universe;
3. the tool-integrity level is recorded;
4. the evidence limits manifest is present, bound and shows no privilege-limited source.

Only such a snapshot could later be eligible for approval. BASE-003, BASE-021 and BASE-026 are
unchanged, and OD-16 stays open until the corpus shows that Full Audit produces such snapshots.

### 5.5 Failure semantics (PROPOSAL, within PRIV-008)

| Failure | Result |
|---|---|
| sandbox unit fails to start | its own reason, distinct from an engine crash (PRIV-008) |
| lock contention | exit 66; today it maps to 64 (`lib/isedraf/exitcodes.py` defines only 0, 2, 64, 70) |
| state root unwritable | exit 67 |
| a fixed operation refused or failing | that source is `NOT_TESTED` or `ERROR` with the operation identifier; never widened |
| a MAC denial | `NOT_TESTED`, "possible MAC denial" (PRIV-021) |
| supervisor or engine crash before ledger append | the staging is never promoted, and the run is recoverable as orphaned |

Exit codes propagate unchanged through `systemd-run` (OUT-003).

### 5.6 Blockers before implementation

| Blocker | Why it blocks |
|---|---|
| OD-06 | the capability recipe must survive SELinux on the supported distributions; if not, the lane stays blocked |
| IQ-024 | the worker language: compiled parts are a CLAUDE.md hard stop; a Python worker with fixed operations is allowed for v0.2 |
| IQ-025 | the audit-rules fingerprint needs a capability that also allows changing rules |
| IQ-026 | caller-built transient units versus packaged units, and systemd as a requirement (PRIV-005/006) |
| IQ-027 | socket activation and digest-pinned sudo versus "no socket, no internal sudo" (D-118) |
| SCOPE-072 U-04 | `AmbientCapabilities=` grants rather than bounds, which contradicts the "outer ceiling" wording |
| D-60, D-27, EXEC-020 | the `isedraf` account and the narrowed `ReadWritePaths` each need their own amendment (D-118 records this) |
| SCOPE-070 to SCOPE-072, SCOPE-076, SCOPE-077 | the GA refusal (exit 70) becomes the route into Mode A |
| exit-code source | `lib/isedraf/exitcodes.json` is planned and does not exist; 66 and 67 are unmapped |
| launcher hardening | `bin/isedraf` honours `ISEDRAF_PYTHON` and an inherited `PYTHONPATH` and runs `-B` without `-I`; EXEC-010 requires `-IB` and a root-owned install before any root path |
| terminology | "launcher" (D-26, PRIV-007) versus "supervisor" (PRIV-011, D-118); `sudo isedraf` versus `sudo isedraf audit` |

## 6. Evidence-truth defects found by this audit

Found while measuring, and recorded rather than fixed (DISCOVER → CLASSIFY → REGISTER). Each needs a
regression test before any fix. None depends on privilege.

| ID | Defect | Effect |
|---|---|---|
| IQ-044 | authorizedkeys: `filemeta.observe` sets `exists=False` on an `lstat` permission denial; `_observe_file` then records `FILE_ABSENT`, which adds no universe reason, so the section can be `COLLECTED` and coverage reports `NOT_FOUND` over a complete universe | **false confident absence**: another user's keys behind a 0750 home are reported as absent rather than unobserved, whenever an `AuthorizedKeysFile` declaration is readable |
| IQ-045 | SCOPE-023 is not implemented: an unparseable `sshd_config` gives `ERROR UNPARSEABLE`, with no active-service check and no `POTENTIAL_LOCKOUT` | a frozen requirement is unmet; the administrator is not told that sshd would refuse to reload |
| IQ-046 | sudo ignores the `sudoers.d` listing status; loginpolicy labels "every source refused" as `SOURCE_ABSENT` and drops an unlistable `.d` directory silently; inventory skips `statvfs` silently and records several denials as `IO_ERROR`; pam records no coverage entry when the `pam.d` listing fails; authorizedkeys reports `NO_DECLARATION_OBSERVED` where the cause is incomplete ssh evidence | wrong attribution or silent narrowing; mostly masked in unprivileged runs, and some become live under Full Audit |

IQ-044 is the one that matters now. In the GA vocabulary it is false confident evidence in a
released build. **Owner direction 2026-10-06: a 0.1.x correction release, not v0.2.** A regression
test proves the defect first, then the minimal fix makes the result unobserved (`PARTIAL`, with the
candidate not observed), never an authoritative absence. It is a separate change from this design.

## 7. Implementation plan (PROPOSAL)

No calendar. Each phase is re-estimated after the previous one.

| Phase | Content | Needs |
|---|---|---|
| P0 | owner decisions: freezing §5.3 (direction given 2026-10-06), the manifest schema freeze, the auxiliary-binding amendment row, the §5.2 operation list (direction given), the faillock/opasswd scope ruling (deferred) | owner |
| P1 | IQ-044 as a 0.1.x correction release (owner direction 2026-10-06), then IQ-046; regression test first | none |
| P2 | IQ-043 registry model and gate | none beyond approval |
| P3 | IQ-042 contract, unprivileged: method identity, evidence limits written and rendered, authority field | manifest schema (P0) |
| P4 | Full Audit design freeze: one owner amendment covering D-60, D-27, EXEC-020, SCOPE-070 to SCOPE-072, exit codes 66/67, the operation list and the authority vocabulary, resolving IQ-024 to IQ-027 and U-04 | owner, kit |
| P5 | launcher hardening, supervisor, the `isedraf` identity, fixed operations, staging and promotion | P4 |
| P6 | corpus validation on lab VMs (Debian 12, Ubuntu 24.04, Rocky 9, AlmaLinux 9, SELinux enforcing where the distribution defaults to it): authority, failure semantics, 10 unchanged runs, upgrade, reboot, no host mutation | P5; OD-06 result |
| P7 | v0.2 release | P6 |

P1 to P3 need no privilege and can proceed while P4 is decided. P5 does not begin before P4 lands.
