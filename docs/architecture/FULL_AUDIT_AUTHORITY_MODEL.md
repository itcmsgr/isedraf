<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Full Audit Authority Model

Implements: D-123, D-124, D-118, D-122, D-121, PRIV-005, PRIV-011, PRIV-012, INTEG-002

**Frozen by owner decision 2026-10-06 (`D-123`). Design only: nothing here is implemented, and no
runtime behaviour changes with it.** Section 10 adds the implementation-enabling semantics of
owner decision 2026-10-07 (`D-124`); they too change no runtime behaviour until the
v0.2 P5 route is built.

This document fixes the concepts the v0.2 Full Audit release (D-120) is built on, before any privileged
code exists. It settles four independent axes, three non-negotiable invariants, the meaning of
supervisor-acquired evidence and of a fixed privileged operation, the run-mode names, and the
capability semantics the supervisor depends on. Section 8 records the resolution of the open blockers
that D-118 left. `scripts/ci/privileged_operations.json` is the machine-readable operation registry,
and `scripts/ci/check_privileged_operations.py` holds it, and this document, to these rules.

```text
unprivileged core  ->  narrow supervisor boundary  ->  fixed privileged operations  ->  normalized evidence
```

## 1. Four independent axes

**AUTH-001 (D-123) SHALL** Four concepts describe a run and its evidence. Each has its own field and
its own vocabulary, and none is derived from another:

| Axis | Answers | Vocabulary | Recorded |
|---|---|---|---|
| source authority | how one evidence item was acquired | `acquisition_mode` (§3), with `operation_id` | per source, in the Evidence Limits Manifest (`ELIM-008`) |
| run mode | how the whole audit ran | `STANDARD_AUDIT`, `FULL_AUDIT` (§5) | per run |
| integrity level | what is known about the tool that ran | `INTEG-002`: `LOCAL_CONSISTENT`, `PACKAGE_CONSISTENT`, `EXTERNAL_VERIFIED` (§6) | per run, by the supervisor |
| collection status | what was observed | `CMP-001`: `COLLECTED`, `PARTIAL`, `NOT_TESTED`, `ERROR` | per source and per section |

**AUTH-002 (D-123) SHALL NOT** No axis is inferred from another. A `FULL_AUDIT` run still records
`CURRENT_IDENTITY` for every source the unprivileged engine read itself. A `COLLECTED` source is as
complete under `STANDARD_AUDIT` as under `FULL_AUDIT`. Running as root establishes no integrity
level, and no integrity level establishes completeness. Root is not completeness (`ELIM-012`).

**AUTH-013 (D-123) SHALL NOT** The run mode never stands for the authority or completeness of
an evidence item. `run_mode = FULL_AUDIT` does not imply that every source was acquired with
privilege or is complete: a `FULL_AUDIT` run can contain `PARTIAL`, `NOT_TESTED` and `ERROR`
sources and sources acquired as `CURRENT_IDENTITY`. A consumer reads each item's own authority and
status, never the run mode, to judge that item.

## 2. Non-negotiable invariants

**AUTH-003 (D-123) SHALL NOT** No arbitrary privileged command execution. No privileged component
accepts a path, an argument vector, a tool name, a shell fragment or any other caller-chosen action.
No privileged component runs a shell, loads a plugin or evaluates content.

**AUTH-004 (D-123) SHALL** Every privileged acquisition maps to exactly one registered fixed
operation, identified by its `operation_id` (§4). An acquisition without a registered operation is not
privileged. It runs as the engine's own identity and records `CURRENT_IDENTITY`, or it does not run.

**AUTH-005 (D-123, D-121) SHALL** Full Audit increases observation authority and changes nothing
else. Evaluation semantics (`D-121`, `CMP-003`), severity, the collection vocabulary and the meaning
of every existing field are identical in both run modes. Privilege makes more sources `COLLECTED`. It
never turns a result into a different kind of result.

**AUTH-006 (D-123, D-118) SHALL NOT** Full Audit is not "run ISEDRAF as root". The engine (collection
by the engine's own identity, parsing, normalization, evaluation, rendering) never runs as root and
holds no capability. Only the supervisor holds privilege, and only for the run. The supervisor
performs the fixed operations, returns bounded bytes and a status for each, and contains no parser,
normalizer, evaluator or renderer. The engine normalizes supervisor-acquired bytes exactly as it
normalizes bytes it read itself.

## 3. Source authority

**AUTH-007 (D-123, D-122) SHALL** `acquisition_mode` has two defined values:

```text
CURRENT_IDENTITY             the engine acquired the source as the identity it runs as and
                             elevated nothing (the existing coverage.py value)
SUPERVISOR_FIXED_OPERATION   the supervisor acquired the source by performing one registered
                             fixed operation (section 4) on the engine's behalf
```

`operation_id` is `null` exactly when `acquisition_mode` is `CURRENT_IDENTITY`. It is a registered
identifier exactly when `acquisition_mode` is `SUPERVISOR_FIXED_OPERATION`.

`SUPERVISOR_FIXED_OPERATION` is defined by this decision and **reserved**. It enters the admitted
vocabulary of `lib/isedraf/coverage.py`, and so of Evidence Limits schema 2 (`ELIM-008`), only when
the first operation in the registry is implemented. That follows the existing rule in `coverage.py`
that a value is admitted when a mechanism exists to produce it. Admission changes no existing
manifest and needs no further amendment. `check-privileged-operations` refuses the value in the code
while every operation is still `PLANNED`. `D-124` rewords `ELIM-008` so that the evidence-limits
schema states the same rule, and adds the run-mode coupling of `AUTH-017`.

## 4. Fixed privileged operations

**AUTH-008 (D-123) SHALL** A fixed operation is a stable, declared contract, not a command string.

- **Identifier grammar:** `^[a-z][a-z0-9_]*_v[1-9][0-9]*$`, for example `read_shadow_v1`. The suffix
  is the contract version. A change in what an operation reads, how it reads it, its bound or its
  output is a new version, never an edit of an existing one.
- **Contract fields:** `operation_id`, `purpose`, `serves` (the section that consumes it), `targets`
  (the fixed paths or kernel interfaces it reads, decided by the contract), `privilege_basis` (why the
  engine cannot do it itself), `fixed_executable` and `fixed_argv` (`null` and `[]` unless the
  contract runs one fixed executable with constant arguments), `caller_inputs` (always empty),
  `output_bound_bytes`, and `status` (`PLANNED`, `DESIGN_OPEN` or `IMPLEMENTED`).
- **Forbidden:** a caller-supplied path, argv, tool name or pattern; a target outside the contract; a
  shell; `CAP_SYS_ADMIN` as a privilege basis.

**AUTH-014 (D-123) SHALL** An operation contract freezes its whole execution policy, not only a
command name: `fixed_executable`, `fixed_argv`, `env_policy`, `cwd_policy`, `stdin_policy`,
`output_bound_bytes`, `timeout_seconds` and `exit_status_policy`. For a contract that runs a fixed
executable the policy is `CLEAN_FIXED` environment (empty apart from the fixed `PATH` and
`LC_ALL=C` of `EXEC-011`), working directory `/` (`ROOT_DIR`), stdin from `/dev/null` (`DEVNULL`),
and `ZERO_ONLY_SUCCEEDS` (any other exit is a failed operation, recorded with its exit code). For a
contract that runs no executable those four are `NOT_APPLICABLE`. Every contract has a timeout of 1
to 120 seconds. Nothing in the policy can be extended by a caller: no added option, path, user, host
or flag.

**AUTH-015 (D-123) SHALL** The supervisor's output for one operation has exactly these fields:
`operation_id`; `status` (`COMPLETED`, `FAILED`, `REFUSED` or `TRUNCATED`); `bytes`, bounded by the
contract; `stderr_bytes`, bounded or null; and `status_metadata`, holding only `exit_code`
(integer or null) and `byte_count`. The supervisor never returns parsed JSON, a normalized object, a
collection status, an evaluation result or a finding. The engine maps the supervisor status onto the
collection vocabulary, and only the engine parses.

**AUTH-016 (D-123) SHALL NOT** A completed operation proves only that the fixed acquisition
completed according to its contract. It never by itself establishes the collection status or the
completeness of the section it serves: `read_shadow_v1` `COMPLETED` does not make the accounts
section `COLLECTED` if another required source is missing. Section status is derived by the engine
from every source the section requires (`CMP-001`, `SCOPE-022`).

The initial registry, every entry `PLANNED` or `DESIGN_OPEN` (owner direction 2026-10-06):

| `operation_id` | Serves | Reads | Status |
|---|---|---|---|
| `read_shadow_v1` | accounts | `/etc/shadow` | PLANNED |
| `read_sudoers_graph_v1` | sudo | `/etc/sudoers`, its include graph, the `/etc/sudoers.d` listing | PLANNED |
| `read_sshd_declared_config_v1` | ssh | `/etc/ssh/sshd_config` and its include graph | PLANNED |
| `resolve_sshd_effective_config_v1` | ssh | `sshd -T` (fixed executable, constant arguments) | PLANNED |
| `inspect_mount_namespaces_v1` | mounts | one `mountinfo` per distinct mount namespace | PLANNED |
| `read_authorized_keys_v1` | authorizedkeys | per-account key files | DESIGN_OPEN |

`read_authorized_keys_v1` is `DESIGN_OPEN`. Its targets depend on the account set and on the effective
`AuthorizedKeysFile`, and deriving them inside the supervisor would put parsing there, which AUTH-006
forbids. It stays out of the implementable set until its contract states a target derivation that needs
neither caller input nor supervisor parsing. faillock and opasswd state, the audit-rules fingerprint
and the Batch 4 recording sources are outside v0.2 (§8).

## 5. Run mode

**AUTH-009 (D-123, PRIV-005) SHALL** The run modes are `STANDARD_AUDIT` and `FULL_AUDIT`, the
canonical labels of PRIV-005's Mode B and Mode A. `USER_PRODUCTION` is an artifact class (`STORE-026`)
and is never used as a run mode.

```text
run mode         PRIV-005   artifact classes it may write          report line
STANDARD_AUDIT   Mode B     DEV, USER_PRODUCTION                   PRIVILEGE LEVEL: UNPRIVILEGED   (frozen, D-117)
FULL_AUDIT       Mode A     SYSTEM_PRODUCTION                      PRIVILEGE LEVEL: FULL_AUDIT
```

`FULL_AUDIT` never writes `DEV` (PRIV-004 refuses `ISEDRAF_STATE_ROOT` under root) or
`USER_PRODUCTION`. The field that records the run mode in the snapshot is added by the Full Audit
implementation amendment, which extends `SNAP-020`.

## 6. Integrity level

**AUTH-010 (D-123, INTEG-002) SHALL** The integrity level is the `INTEG-002` trust level of the tool
that ran. In `FULL_AUDIT` the supervisor records it (D-118). It is never inferred from the run mode or
from privilege. It never becomes a claim that the host or the tool is uncompromised. TOOL INTEGRITY
and HOST BASELINE CONSISTENCY stay separate lines (`INTEG-001`).

## 7. Capability semantics

**AUTH-011 (D-123) SHALL** The supervisor is built on Linux and systemd semantics as they are, not as
"ceiling" wording suggested:

- **`CapabilityBoundingSet=` bounds.** It is the outer limit for every process in the unit. A
  capability outside it cannot be gained by any process in the unit, including one running as root.
  It is the only capability *bound* the unit has.
- **`AmbientCapabilities=` grants.** It adds capabilities to the ambient set, which a non-root
  program keeps across `execve`. It never limits anything and must not be described or relied on as a
  boundary. In the v0.2 design it is empty for the unit, and the engine's ambient set is cleared.
- **The engine is reduced explicitly.** The supervisor starts the engine as the dedicated
  non-login identity with no ambient, inheritable, permitted or effective capability, an empty
  bounding set and no-new-privileges. The concrete recipe is proven in the corpus before it is frozen
  (OD-06).
- **The supervisor's bounding set** is the union of what the registered operations need plus the
  minimum required to start the reduced engine, and is never `CAP_SYS_ADMIN`. The candidates
  (`CAP_DAC_READ_SEARCH` for reads past file permissions, `CAP_SYS_PTRACE` for other processes'
  namespace links, `CAP_SETUID`, `CAP_SETGID` and `CAP_SETPCAP` for the reduction) are measured in the
  corpus, not assumed. `CAP_CHOWN` was considered and is measured not required (`D-124`,
  `AUTH-027`): it is not a capability of the current design.

This corrects PRIV-009, EXEC-001 and SCOPE-072, which grouped `AmbientCapabilities=` with
`CapabilityBoundingSet=` as "the outer ceiling".

## 8. Blocker resolutions

**AUTH-012 (D-123) SHALL** The blockers D-118 and the v0.2 design recorded are resolved as follows.

| Blocker | Resolution |
|---|---|
| **OD-06** | Narrowed, not closed. The question becomes: does the AUTH-011 model, a root supervisor with a minimal bounding set and an engine reduced to no capability, hold on Debian 12, Ubuntu 24.04, Rocky 9 and AlmaLinux 9, with SELinux enforcing where the distribution defaults to it? It is answered by corpus evidence on the lab VMs (v0.2 phase P6). If any part fails, that operation or that platform stays `BLOCKED`; capabilities are never widened (PRIV-012). |
| **IQ-024** | Resolved for v0.2: the supervisor is Python standard library, started as `python3 -IB`, with the fixed-operation rule of `docs/roadmap/ROADMAP.md`. A compiled privileged component remains a later, measurement-gated amendment, and CLAUDE.md is not changed. |
| **IQ-025** | Resolved for v0.2: no audit capability. The `CAP_AUDIT_CONTROL` branch of D-26 and the audit-rules fingerprint of EXEC-004 are deferred until audit evidence (Batch 4) enters scope. The supervisor's bounding set therefore does not include `CAP_AUDIT_CONTROL`. |
| **IQ-026** | Resolved for v0.2: the transient `systemd-run` unit of D-27 and PRIV-007 is kept. Its properties are constants in the package's own code, never assembled from configuration or input. systemd is required for `FULL_AUDIT`, which is unsupported elsewhere and never degraded (PRIV-006). Packaged per-class units and non-systemd confinement backends stay with the R1.5-P2 planning contract. |
| **IQ-027** | Resolved: neither socket activation nor ISEDRAF-invoked sudo. The operator starts the run with `sudo isedraf audit`; sudo used by the operator is not internal sudo (PRIV-002). The run leaves no resident process. |
| **SCOPE-072 / U-04** | Resolved by AUTH-011. U-04 was correct: `AmbientCapabilities=` grants. PRIV-009 and EXEC-001 are reworded. SCOPE-072's deferral to corpus proof stands. |
| **D-60** | Amended: the package may declare the one `isedraf` system account through a systemd sysusers file, processed by the distribution's standard packaging mechanism: no shell, no home, no password, no login, never removed on uninstall. Maintainer scripts still never touch users in any other way. `DynamicUser=` was considered and rejected, because the supervisor must stay root while the engine runs as the dedicated identity inside the same unit. |
| **D-27** | Refined, not replaced: `ReadWritePaths=/var/lib/isedraf` stays the unit-level limit, because the supervisor promotes committed evidence. The engine's narrower limit is enforced by ownership. The run staging `tmp/<run_id>/` is owned by the `isedraf` identity, while `snapshots/`, `ledger/` and the lock are root-owned 0700, and the engine holds no capability that could override file permissions. |

Implementation items that are not blockers, and belong to the Full Audit implementation amendment:
exit codes 66 and 67 (OUT-001), the route from the SCOPE-071 refusal into Mode A, launcher hardening
(`-IB`, a root-owned install path, no `ISEDRAF_PYTHON` or inherited `PYTHONPATH` under root),
`lib/isedraf/exitcodes.json`, the run-mode field in `SNAP-020`, and `SYSTEM_PRODUCTION` store creation
(`STORE-025`). The Full Audit implementation decision is `D-124` (section 10). It settles all of
them except `lib/isedraf/exitcodes.json`, whose creation stays with `OUT-001` and is not needed to
reach Mode A.

## 9. Vocabulary

The gate requires this block to agree with `scripts/ci/privileged_operations.json` and with
`lib/isedraf/coverage.py` under the AUTH-007 admission rule.

```json full-audit-authority-vocabulary
{
  "acquisition_mode_defined": ["CURRENT_IDENTITY", "SUPERVISOR_FIXED_OPERATION"],
  "acquisition_mode_reserved": ["SUPERVISOR_FIXED_OPERATION"],
  "run_mode": ["STANDARD_AUDIT", "FULL_AUDIT"],
  "integrity_level": ["LOCAL_CONSISTENT", "PACKAGE_CONSISTENT", "EXTERNAL_VERIFIED"],
  "operation_id_pattern": "^[a-z][a-z0-9_]*_v[1-9][0-9]*$",
  "operation_status": ["PLANNED", "DESIGN_OPEN", "IMPLEMENTED"],
  "env_policy": ["CLEAN_FIXED", "NOT_APPLICABLE"],
  "cwd_policy": ["ROOT_DIR", "NOT_APPLICABLE"],
  "stdin_policy": ["DEVNULL", "NOT_APPLICABLE"],
  "exit_status_policy": ["ZERO_ONLY_SUCCEEDS", "NOT_APPLICABLE"],
  "timeout_seconds_max": 120,
  "supervisor_output_fields": ["operation_id", "status", "bytes", "stderr_bytes", "status_metadata"],
  "supervisor_status": ["COMPLETED", "FAILED", "REFUSED", "TRUNCATED"],
  "supervisor_status_metadata": ["exit_code", "byte_count"],
  "forbidden_output_fields": ["parsed", "normalized", "records", "collection_status", "result", "evaluation", "finding", "severity"],
  "forbidden_privilege_basis": ["CAP_SYS_ADMIN"],
  "capability_candidates": ["CAP_DAC_READ_SEARCH", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID",
                            "CAP_SYS_PTRACE"],
  "capability_measured_route": ["CAP_DAC_READ_SEARCH", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID"],
  "capability_required": ["CAP_DAC_READ_SEARCH", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID"],
  "capability_measured_not_required": ["CAP_CHOWN"],
  "capability_excluded": ["CAP_AUDIT_CONTROL", "CAP_KILL", "CAP_SYS_ADMIN"]
}
```

## 10. Implementation semantics (D-124)

Owner decision 2026-10-07 (`D-124`). These requirements are what the v0.2 P5 route is built
against. They enable the route; they add no operation, change no evaluation semantics (`AUTH-005`) and
widen no capability (`PRIV-012`).

**AUTH-017 (D-124, D-122) SHALL** Source authority and run mode are coupled in one direction only:

```text
acquisition_mode = SUPERVISOR_FIXED_OPERATION   requires all of
    run_mode     = FULL_AUDIT
    operation_id is not null
    operation_id is an identifier in the operation registry
    that operation's status is IMPLEMENTED

run_mode = STANDARD_AUDIT   never records
    acquisition_mode = SUPERVISOR_FIXED_OPERATION
    an operation_id that is not null
```

`operation_id` is the exact versioned contract identifier (`AUTH-008`), for example `read_shadow_v1`,
never an unversioned name such as `read_shadow`. "The operation registry" is the registry of the
ISEDRAF version that produced the evidence, as its supervisor contracts mirror it. The coupling does
not run backwards: `FULL_AUDIT` does not require any source to be `SUPERVISOR_FIXED_OPERATION`
(`AUTH-002`, `AUTH-013`). The ISEDRAF verifier refuses evidence that breaks either rule; it never
repairs it.

**AUTH-018 (D-124, SNAP-020, AUTH-009) SHALL** The snapshot records its run mode. `SNAP-020`'s
`manifest_core` gains the field `run_mode`, with the value `STANDARD_AUDIT` or `FULL_AUDIT`:

- It is set by the route that ran, never by an operator flag, configuration or environment: the
  unprivileged entry writes `STANDARD_AUDIT`; only the launcher route of `AUTH-019` writes
  `FULL_AUDIT`. The public command line has no option that selects or claims a run mode.
- `run_mode = FULL_AUDIT` exactly when `state_root = "SYSTEM_PRODUCTION"`; `STANDARD_AUDIT` exactly
  when `state_root` is `"DEV"` or `"USER_PRODUCTION"` (`AUTH-009`, `STORE-026`). The verifier refuses
  any other pairing.
- It enters `manifest_hash` through `manifest_core` and never `state_hash`. Host state is hashed
  identically in both run modes; the run mode is not host state.
- A snapshot committed before the field existed (every GA 0.1.x snapshot) has no `run_mode`. It reads
  as "run mode not recorded", is never read as `FULL_AUDIT`, and stays valid evidence of its own
  version. Its `state_hash` and `manifest_hash` are unchanged.
- Evaluation, comparison and reporting semantics do not change with the run mode (`AUTH-005`). The
  report's privilege line follows `AUTH-009`.

**AUTH-019 (D-124, SCOPE-071, PRIV-005) SHALL** The production route into Mode A is exactly:

```text
operator
   |
   v
sudo isedraf audit                      (the operator's sudo, PRIV-002, IQ-027)
   |
   v
trusted launcher, outer entry           (euid 0, unsandboxed, minimal)
   |  runs systemd-run with constant properties and relays its output
   |  (EXEC-001, EXEC-002, PRIV-007, PRIV-009)
   v
trusted launcher, in the unit           (root, bounded capability set)
   |-- whole-run lock, preflight, staging           (PRIV-007, PRIV-008, AUTH-021)
   |-- fixed-operation supervisor                    (isedraf.supervisor, AUTH-006, AUTH-015)
   '-- reduced engine                                (isedraf identity, no capability, AUTH-020)
          collect, parse, normalize, build the staged snapshot; request fixed operations
          by operation_id only
```

- Under euid 0 or with `SUDO_USER` set, the invocation `isedraf audit` with no further argument enters
  this route on a supported platform (Debian 12, Ubuntu 24.04, Rocky 9, AlmaLinux 9, with systemd).
  `isedraf report` enters the read-only report route of `AUTH-032`. Every other invocation under
  euid 0 or with `SUDO_USER` set is still refused with exit `70`, as `SCOPE-071` requires, with the
  message *"Under sudo or root, ISEDRAF runs only `sudo isedraf audit` (Full Audit) and `sudo
  isedraf report` (its report). Run other ISEDRAF commands as your normal user."*
- Without systemd, or on an unsupported platform, `sudo isedraf audit` is refused with exit `70` and
  the reason `FULL_AUDIT_UNSUPPORTED`. Nothing degrades to an unsandboxed privileged run (`PRIV-006`).
- `ISEDRAF_STATE_ROOT` stays refused under euid 0 (`PRIV-004`); the route never writes `DEV` or
  `USER_PRODUCTION`.
- The launcher is the only component that changes the privilege boundary. The engine never invokes
  `sudo`, the launcher, the supervisor or any privileged helper, no collector calls `sudo`, and the
  engine cannot ask for anything to run as root: its only privileged request is an `operation_id` on
  the channel the launcher gave it, answered or refused by the supervisor (`AUTH-003`, `AUTH-004`).

**AUTH-020 (D-124, EXEC-010, EXEC-011, AUTH-011) SHALL** The launcher is hardened and lives in
`lib/isedraf/launcher/`, the only package where `os.execv*` is allowed:

- **Outer entry.** Under euid 0, `bin/isedraf` ignores `ISEDRAF_PYTHON`, `PYTHONPATH` and every other
  `PYTHON*` variable and runs `/usr/bin/python3 -IB`. The install root `/usr/lib/isedraf` and every
  parent are verified root-owned and not group- or world-writable before they enter `sys.path`, else
  the run refuses with `ENGINE_UNSAFE_INSTALL` (`EXEC-010`). The outer entry accepts exactly the
  argument vector `audit`, passes no operator environment on, and runs `/usr/bin/systemd-run` with
  properties that are constants of the package. The unit name derives only from the `run_id`. The
  exit code propagates unchanged (`OUT-003`); a run ended by a signal is reported as 128 plus the
  signal.
- **The outer entry owns the transport (IQ-062).** systemd-run runs as the outer entry's child with
  stdin `/dev/null` and stdout and stderr on pipes the outer entry created; the caller's own
  descriptors never reach systemd-run, whatever they are - a terminal, a pipe or a regular file. The
  outer entry copies the bytes to the caller's stdout and stderr. If the caller's side cannot take
  them, the rest is drained and discarded, the run is not interrupted, one line on stderr says so,
  and the exit code is unchanged: after either caller-facing sink fails, the outer entry keeps
  consuming both of systemd-run's streams until end of file or until systemd-run has ended and a
  bounded silence has passed, so systemd-run never blocks on a full pipe.
- **An interrupted audit is never committed (IQ-063).** systemd-run runs in its own session, so a
  terminal's signals reach only the outer entry. On SIGTERM, SIGHUP or SIGINT the outer entry
  stops the audit unit - `/usr/bin/systemctl kill --kill-whom=all --signal=SIGUSR2` on the unit
  named by the run id, retried until systemd accepts it - and waits for systemd-run to report the
  unit's end. The unit's `KillSignal=` is `SIGUSR2`, so a `systemctl stop` and the `RuntimeMaxSec=`
  timeout stop it the same way; systemd counts a `SIGTERM` death as a clean exit, which systemd-run
  reports as `0`. The in-unit launcher records a stop: before the commit it promotes nothing,
  discards the staging and exits `143`, and the outer entry then returns 128 plus the signal and
  says nothing was committed. The commit - the rename and the ledger append - runs with the stop
  signals blocked, and they stay blocked once the run's outcome is decided: a snapshot committed
  before the stop is processed stays valid, the exit code is the audit's, and one line on stderr
  says it was committed. Any other end after a stop returns 128 plus the signal and claims nothing
  about what was committed.
- **Fixed paths and environment.** Every executable the launcher runs (`systemd-run`, `systemctl`,
  `setpriv`, `python3`) is a constant absolute path; every environment it passes is the `EXEC-011` environment;
  no path, argument, environment value or option comes from the operator, the engine or configuration.
- **Engine reduction.** The launcher starts the engine through `/usr/bin/setpriv` with a constant
  argument vector: the `isedraf` user and group, no supplementary groups, empty inheritable, ambient,
  permitted and effective capability sets, an empty bounding set, and no-new-privileges. The engine
  runs a fixed entry under the install root with a constant argument vector, stdin `/dev/null`, its
  staging directory as working directory (`AUTH-021`), and the supervisor channel on fixed
  descriptors. Before it collects anything the engine reads its own `/proc/self/status` and refuses,
  with `ENGINE_NOT_REDUCED`, unless its uid and gid are the `isedraf` account, all five capability
  sets are empty and `NoNewPrivs` is 1. The exact recipe is proven in the corpus before release
  (`OD-06`); a platform where it does not hold stays `BLOCKED` and nothing is widened (`PRIV-012`).
- A missing `isedraf` account (`D-60` as amended by `AUTH-012`) refuses the route with exit `70` and
  the reason `ENGINE_IDENTITY_MISSING`.

**AUTH-021 (D-124, D-27, SNAP-014, EXEC-020) SHALL** The engine builds; the launcher promotes. The
commit order of the snapshot is unchanged (private staging, collect, normalize, hashes, manifest,
fsync, atomic rename, ledger append and fsync, under the whole-run lock):

- The engine writes only inside its staging directory and holds no path to the rest of the state root.
- After the engine exits, the launcher promotes the staging mechanically: every entry is a declared
  name, a regular file or directory, never a link, owned by the `isedraf` account and within its size
  bound; the launcher reads the staged snapshot manifest, bounded, recomputes its hashes and the hashes
  of the files it lists with `isedraf.canonical`, and refuses on any mismatch. It never reads, parses
  or interprets host evidence content. It then completes the ownership transition the production
  ownership contract of `AUTH-022` requires, if any, renames the snapshot into `snapshots/`, and
  appends and fsyncs the ledger record.
- An engine that fails, is killed or produces a staging that fails the check is never promoted; the
  staging is cleaned as `EXEC-020` requires and the run exits with its engine error.

**AUTH-022 (D-124, STORE-001, STORE-025, STORE-026) SHALL** The `SYSTEM_PRODUCTION` store is written
as follows, within the `STORE-025` subset:

| Path under `/var/lib/isedraf/` | Owner, mode | Created by | Written by |
|---|---|---|---|
| (the root itself) | root:root 0700 | the package's maintainer script, only when nothing exists at the path (`AUTH-027`) | launcher |
| `.lock` | root:root 0600 | launcher | launcher (whole-run `flock`) |
| `snapshots/` | root:root 0700 | launcher | launcher, by promotion only |
| `ledger/`, each segment | root:root, directory 0700, segments 0600 | launcher | launcher, append only |
| `tmp/` | root:root 0700 | launcher | launcher |
| `tmp/<run_id>/`, which becomes the promoted snapshot | root:root; 0777 while the engine writes, 0700 before promotion (`AUTH-027`) | launcher, per run | engine, in its staging only |

Creation by ISEDRAF uses exclusive, no-follow operations. Package scripts neither create nor delete
`/var/lib/isedraf` and never remove the `isedraf` account.

**Declared by the package, validated by the launcher, repaired by no one (amended by D-124,
2026-10-07, `AUTH-027`).** The package declares the root as an empty directory entry of its payload,
root:root 0700. Inside the sandbox and under the whole-run lock, the launcher checks it before anything
else:

```text
root missing                                   the route cannot start safely; exit 67
root present, a directory, not a link,         accepted
  owner root, group root, mode 0700
anything else                                  exit 67; nothing is repaired, replaced or recreated
```

The same refusal applies to every entry of the table: an existing entry that is not of the stated
type, owner and mode, or that is a link, is refused with exit `67`, never repaired or relocated.

**The production ownership contract.** These properties are frozen, and `AUTH-027` freezes the
promotion route the corpus measured to meet them without an ownership transition:

- Only the reduced engine of a run writes that run's staging, and only during the run.
- After promotion, no identity other than root can modify, replace or remove a promoted snapshot or
  a ledger record. A root-owned 0700 ancestor that the engine identity cannot traverse may provide
  this without changing the ownership of the promoted files; if it cannot, promoted files become
  root-owned through an explicit ownership transition.
- The engine identity can never reach `snapshots/`, `ledger/` or `.lock`.
The other `STORE-001` entries are not created. Reading `SYSTEM_PRODUCTION` evidence through ISEDRAF
under root is the read-only `report` route of `AUTH-032` and nothing else; every other read command
stays refused by `SCOPE-071`, and the artifacts remain inspectable without ISEDRAF.

**AUTH-023 (D-124, OUT-001, PRIV-008) SHALL** Exit codes `66` and `67` each have one meaning, in every
run mode and state-root class from v0.2:

```text
66  RUN_IN_PROGRESS       the whole-run lock was not acquired within its bound; nothing was
                          collected and no evidence was written
67  STATE_ROOT_UNUSABLE   the state root cannot be used: it is missing and cannot be created, is not
                          a directory, is a link, has the wrong owner or mode, is not writable, or is
                          unsuitable storage (STORE-027); detected before any collection
```

Neither code is used for anything else: not for an engine failure, a refused or failed fixed operation,
a sandbox unit that fails to start (`PRIV-008` reports that distinctly from an engine crash, as `64`
with its own reason), or an integrity failure (`5`). Precedence and propagation are unchanged
(`OUT-002`, `OUT-003`).

**AUTH-024 (D-124, AUTH-004, AUTH-008) SHALL** `IMPLEMENTED` means reachable in production. An operation
is `IMPLEMENTED` only when all of these hold:

1. its supervisor contract equals its registry entry field for field;
2. the launcher route of `AUTH-019` exists and performs it in a `FULL_AUDIT` run;
3. the section it serves requests it by its exact identifier and records, for the source it read,
   `acquisition_mode = SUPERVISOR_FIXED_OPERATION` and that `operation_id`;
4. the `STANDARD_AUDIT` path of the same section is unchanged and still records `CURRENT_IDENTITY`.

A contract with a performer and unit tests and no production route is `PLANNED`.
`check-privileged-operations` holds conditions 1 and 3 and the existence of the launcher package; the
route itself is proven by tests and, before release, by the corpus (`OD-06`).

**AUTH-025 (D-124) SHALL** Privileged operations are admitted one vertical slice at a time.
Implementation state and validation are separate records: `scripts/ci/privileged_operations.json`
holds whether an operation is `IMPLEMENTED` (`AUTH-024`: reachable in production); the owner-controlled
admission block below holds which operations are validated and which one is the next candidate. A
new operation is admitted only when:

1. the previously admitted operation is validated;
2. the candidate is the explicitly approved next operation, `next_candidate`;
3. its fixed operation contract is already registered;
4. no capability outside the `AUTH-028` set has been granted for it without its own measurement and
   owner decision;
5. its implementation is one vertical slice only;
6. after implementation it may become `IMPLEMENTED`;
7. its own corpus proof through the `AUTH-019` route, on Debian 12, Ubuntu 24.04, Rocky 9 and
   AlmaLinux 9 with SELinux enforcing where the distribution defaults to it, is what the owner
   records as validated;
8. no further operation is admitted until that has happened;
9. no release includes an operation that is `IMPLEMENTED` but not validated.

The invariants are: at most one `IMPLEMENTED` operation is not validated; if one is, it is
`next_candidate`; `next_candidate` is the first operation in `order` that is not validated;
`validated` is a prefix of `order` and each of its operations is `IMPLEMENTED`; capability grants are
governed independently by `AUTH-028`; release mode requires that no `IMPLEMENTED` operation is
unvalidated. `check-privileged-operations` holds the invariants on every run, with a self-test of
fixed cases, and in release mode (`--release`) before the release workflow builds an artifact;
conditions 4, 5 and 7 are also held by review, the test suite and the corpus.

inspect_mount_namespaces_v1 does not imply or authorize CAP_SYS_PTRACE.

The order changed on 2026-10-09 (owner decision): `inspect_mount_namespaces_v1` moved from last to
next, because the first P6 run showed that the Full Audit sandbox cannot observe the host mount
namespace (IQ-053), so its mount sources are deliberately `NOT_TESTED` / `PARTIAL` until that
operation exists. `read_authorized_keys_v1` stays `DESIGN_OPEN` and outside the order. Until
2026-10-09 this requirement read: "No second operation becomes `IMPLEMENTED` before the first
vertical slice, `read_shadow_v1` through the `AUTH-019` route, has been validated end to end on the
lab corpus. The order after it is `read_sudoers_graph_v1`, `read_sshd_declared_config_v1`,
`resolve_sshd_effective_config_v1`, `inspect_mount_namespaces_v1`. `read_authorized_keys_v1` stays
`DESIGN_OPEN`."

The order changed again on 2026-10-09 (owner decision, after the step C measurement recorded as
IQ-055): `inspect_mount_namespaces_v1` left the admission order and `read_sudoers_graph_v1` is the
next candidate. On Debian 12, Ubuntu 24.04, Rocky 9 and AlmaLinux 9 (SELinux enforcing on EL9) the
reduced engine itself, with no capability and no-new-privileges, reads `/proc/1/mountinfo` inside the
Full Audit unit byte-identical to the host mount table; the ptrace check guards `/proc/<pid>/ns/mnt`
and `/proc/<pid>/root`, not `mountinfo`. Recovering the host mount table that IQ-053 needs is
therefore not a privileged operation: it is fixed in the engine, with no capability and no supervisor
operation. Inspecting the mount namespaces of other processes is a different capability; it returns
as a separate operation (renamed when its design is reopened, for example
`inspect_process_mount_namespaces_v1`) with its own threat model and capability measurement, and only
then enters the order. The order before this change was `read_shadow_v1`,
`inspect_mount_namespaces_v1`, `read_sudoers_graph_v1`, `read_sshd_declared_config_v1`,
`resolve_sshd_effective_config_v1`, with `inspect_mount_namespaces_v1` as next candidate.

```json full-audit-operation-admission
{
  "order": ["read_shadow_v1", "read_sudoers_graph_v1", "read_sshd_declared_config_v1",
            "resolve_sshd_effective_config_v1"],
  "validated": ["read_shadow_v1", "read_sudoers_graph_v1", "read_sshd_declared_config_v1",
                "resolve_sshd_effective_config_v1"],
  "next_candidate": null
}
```

`read_shadow_v1` is validated by the P6 rerun of 2026-10-08 (`AUTH-028`, OD-06 closed).
`read_sudoers_graph_v1` is validated by its four-platform lab proof of 2026-10-09 (`AUTH-029`; IQ-056,
engineering `217cd7c`; evidence held outside the repository, the sha256 of its checksum list
`16bc5a6b…650e`). `read_sshd_declared_config_v1` is validated by its four-platform lab proof of
2026-10-09 (`AUTH-030`; IQ-060, engineering `f15d6a3`; the sha256 of its checksum list
`b9c06566…e63e`). `resolve_sshd_effective_config_v1` is validated by its four-platform lab proof of
2026-10-09 (`AUTH-031`; IQ-061, engineering `fd05d38`; the sha256 of its checksum list
`10885b65…c9d4`). Every operation in the order is validated, so `next_candidate` is `null`. Only the owner
changes this block: recording an operation as validated, naming the next candidate, or changing the
order is an owner decision.

**AUTH-026 (D-124, PRIV-008, PRIV-012, AUTH-011) SHALL** Owner corrections of 2026-10-07 to the store
and the capability candidates:

- **No out-of-path mutation of the state root.** No ISEDRAF process creates, repairs, `chmod`s or
  `chown`s the production state root, or any entry under it, outside the sandboxed Full Audit
  execution path. The outer entry of `AUTH-019` does not touch it (`PRIV-008`).
- **Provisioning is not evidence mutation.** The package's declaration of the state root is
  provisioning. It happens before ISEDRAF writes any snapshot content, and it creates no evidence.
- **Candidate is not required is not granted.** A capability named as a candidate (`AUTH-011`) is
  neither required nor granted by being named. It enters the unit's `CapabilityBoundingSet=` only when
  the corpus measurement shows the registered operations or the engine reduction cannot work without
  it, and that evidence is recorded with OD-06. `CAP_CHOWN` was measured not required (`AUTH-027`).
- **No `CAP_KILL`.** The engine's lifetime and the whole run are bounded by the unit's
  `RuntimeMaxSec=`, a constant property: a timeout is unit lifecycle policy, not a reason to grant a
  process another capability.
- **Unit properties.** The constant properties of `EXEC-001` and `EXEC-002`, including
  `ReadWritePaths=/var/lib/isedraf`, are completed by `RuntimeMaxSec=` and `KillSignal=SIGUSR2`
  (IQ-063). The unit sets no `StateDirectory=` (`AUTH-027`).

**AUTH-027 (D-124, AUTH-022, AUTH-026, AUTH-011, OD-06) SHALL** The P5b measurement of 2026-10-07 on
Debian 12, Ubuntu 24.04, Rocky 9 and AlmaLinux 9 (SELinux enforcing on the last two) is recorded, and
the store and capability decisions follow it:

- **`StateDirectory=` is rejected for the production state root.** On every supported lab platform it
  repaired a pre-existing directory's owner, group and mode before any process of the unit could
  validate them, and changed a regular file's mode before failing; on a symlink it failed on systemd
  252 and followed the link on systemd 255, so it does not even fail the same way across platforms.
  This replaces the earlier choice because of measured behaviour, not because the architecture
  changed.
- **The package declares; the runtime validates; no one repairs** (refined by `D-124`,
  2026-10-08). The security invariant is that pre-existing state is never silently repaired, not that
  no script line exists. Package installation may create the root only when the path is absent; it
  never modifies, normalizes, replaces, removes, `chmod`s or `chown`s an existing path, and it is never
  relied on as a runtime repair mechanism. Neither format declares the root as payload: the
  rehearsal of 2026-10-08 measured `rpm` repairing an existing root's mode and owner, and `dpkg`
  replacing an existing regular file or dangling symlink at the path with the payload directory. Both
  formats therefore create it the same way, with one guarded maintainer-script line, the DEB
  `postinst` and the RPM `%post`:

  ```text
  if [ ! -e /var/lib/isedraf ] && [ ! -L /var/lib/isedraf ]; then mkdir -m 0700 /var/lib/isedraf || :; fi
  ```

  The RPM additionally lists the path as `%ghost %dir %attr(0700,root,root) /var/lib/isedraf`, which
  records ownership without making it payload truth. Neither package removes the root.

  "Absent" means no filesystem object at all: a directory, file, symlink (dangling or not) or any
  other object counts as present and is left untouched. `mkdir` is used, not `install -d`, because
  `mkdir` fails without changing anything if an object appears between the guard and the call. The
  maintainer script only distinguishes "nothing exists" from "something exists"; it never decides
  whether an existing object is acceptable. The launcher's validation inside the sandbox under the
  lock stays authoritative, and anything but a root:root 0700 directory exits `67`, untouched. The
  unit keeps `ReadWritePaths=/var/lib/isedraf` and sets no `StateDirectory=`.
- **Neither systemd nor the ISEDRAF runtime normalizes, repairs or replaces a pre-existing production
  state root.** Any mismatch in type, ownership, group or mode is fatal. A missing root means Full
  Audit cannot start safely; whatever form the failure takes (the unit cannot set up
  `ReadWritePaths=`, or the launcher finds no root), the external result is exit `67`, and the root
  is not created at runtime.
- **Package rehearsal.** The DEB and RPM rehearsals on the lab corpus verify that install, upgrade,
  reinstall and removal never silently change the type, owner, group or mode of an existing root, and
  that removal never deletes a non-empty root. A package format that does repair an existing root is
  `BLOCKED` until a declaration that does not repair is found; the problem is not moved from systemd
  into the packaging layer. The rehearsal covers, on Rocky 9 and AlmaLinux 9: a fresh install with
  the path absent (created root:root 0700); reinstall and upgrade over a correct directory, mode 0755,
  a foreign owner, a foreign group, a regular file, a symlink and a dangling symlink (each unchanged);
  erase with a non-empty root (preserved); Full Audit against each malformed or missing state (exit
  `67`, untouched); and the same cases on Debian 12 and Ubuntu 24.04.
- **The promotion route.** The launcher creates `tmp/<run_id>/` root-owned, with mode 0777 under the
  root-only 0700 `tmp/`, so only a process whose working directory it already is can reach it, and
  makes it the reduced engine's working directory. The engine writes the staged snapshot there as its
  own identity. The launcher reads the staged tree mechanically (`AUTH-021`), sets `tmp/<run_id>/` to
  0700 and renames it atomically into `snapshots/`. No file changes owner. After promotion the engine
  identity cannot stat, open, list or reach the snapshot. Before promotion the launcher confirms that
  no process of the engine identity remains in the unit.
- **`CAP_CHOWN`: measured not required.** All four platforms met the ownership contract by the route
  above without any ownership transition. It is recorded here as considered and rejected; it is not a
  candidate and not a capability of the current design.
- **The measured candidate bounding set** for the launcher route, not yet final production proof:
  `CAP_DAC_READ_SEARCH` (the launcher reads the reduced engine's staged tree), `CAP_SETUID` and
  `CAP_SETGID` (establishing the reduced engine's identity), `CAP_SETPCAP` (the capability
  transition and the dropped bounding set). The registered operations may add only candidates
  (`CAP_SYS_PTRACE` for `inspect_mount_namespaces_v1`, not yet measured). P6 proves each member is
  needed on the final route and packaging; a member that is not is removed.
- **OD-06 stays open.** This measurement supports the design; OD-06 closes only with the end-to-end
  Full Audit route on the corpus (v0.2 P6).

**AUTH-028 (D-124, AUTH-011, AUTH-026, AUTH-027, OD-06) SHALL** OD-06 is closed by corpus evidence
(2026-10-08), and the Full Audit capability set is frozen.

- **The set.** The unit's `CapabilityBoundingSet=` is exactly `CAP_DAC_READ_SEARCH`, `CAP_SETGID`,
  `CAP_SETPCAP` and `CAP_SETUID`, each REQUIRED **for the current frozen Full Audit implementation,
  not universally required by every future implementation**. A later launcher design that needs less
  changes this implementation contract by owner decision; it does not overturn a general rule.
- **Why each is required** (the final route on all four lab platforms, one capability removed at a
  time):

  ```text
  CAP_SETUID           setpriv: setresuid failed: Operation not permitted; the engine never starts
  CAP_SETGID           setpriv: setresgid failed: Operation not permitted; the engine never starts
  CAP_SETPCAP          the engine's bounding set cannot be emptied: setpriv fails on Ubuntu 24.04,
                       and on Debian 12 and EL9 setpriv leaves it in place and the engine's own
                       reduction check refuses (ENGINE_NOT_REDUCED); avoidable only by relaxing
                       AUTH-020's empty bounding set, which is not done
  CAP_DAC_READ_SEARCH  the launcher cannot read the engine's staged tree, so nothing is promoted
                       (all four); on EL9 the supervisor also cannot read /etc/shadow (mode 0000)
  ```

  The sets above `AUTH-011`, `AUTH-026` and `AUTH-027` call candidates or measured are superseded for
  the current implementation by this one. `CAP_CHOWN` stays measured not required; `CAP_KILL`,
  `CAP_SYS_ADMIN` and `CAP_AUDIT_CONTROL` stay excluded; `CAP_SYS_PTRACE` stays a candidate only.
- **The record of the proof.** The first P6 run found two false-confidence paths (the sandbox's mount
  table reported as the host's; a helper's SELinux transition denied under no-new-privileges with the
  loss unrecorded). They were fixed without weakening the sandbox or no-new-privileges, and the full
  P6 rerun then passed every acceptance criterion on Debian 12, Ubuntu 24.04, Rocky 9 and AlmaLinux 9
  (SELinux enforcing on the EL9 pair): determinism, lifecycle through upgrade and reboot, store and
  ledger integrity, no host mutation, a fail-closed store, the standard audit unchanged, and this
  capability matrix. The corpus could falsify the design, and did, before it accepted it.
- **What the closure does not do.** `AUTH-025` remains in force: no second operation becomes
  `IMPLEMENTED`, `inspect_mount_namespaces_v1` is not enabled, no capability is added and the operation
  registry is not opened by this decision. Each is a separate owner decision. (Written 2026-10-08.
  The owner decision of 2026-10-09 amended `AUTH-025` to admit further operations one at a time; it
  enabled no operation and added no capability.)

**AUTH-029 (D-124, AUTH-003, AUTH-006, AUTH-028, IQ-046) SHALL** The contract of
`read_sudoers_graph_v1` (owner decision 2026-10-09, after the step C measurement recorded as IQ-056).
It is a bounded acquisition primitive, not a privileged policy walker.

- **Fixed surface.** `/etc/sudoers`; the listing of `/etc/sudoers.d`; and each non-symlink regular
  directory entry directly enumerated in `/etc/sudoers.d`. Nothing else is read. The supervisor applies
  no filename rule: which entries sudo considers is decided by the engine.
- **Separate status.** The read of `/etc/sudoers`, the enumeration of `/etc/sudoers.d` and each entry's
  read each carry their own status. An enumeration that could not be made is never an empty directory
  (IQ-046).
- **No interpretation.** The supervisor parses nothing and interprets no include directive, and takes
  no caller-supplied path (`AUTH-003`, `AUTH-006`). The engine parses the returned bytes and builds the
  include graph.
- **Includes outside the surface.** An include target outside the fixed surface is `NOT_TESTED` as
  outside the operation's surface, and the section is `PARTIAL`; it is never reported absent.
- **Symlinks are not followed.** A symlink in `/etc/sudoers.d` is recorded as observed with its
  metadata; it is not dereferenced, its target's content is not collected, and the section is
  `PARTIAL`. Full Audit is deliberately more conservative than sudo, which follows such a link
  (measured, IQ-056): following one would take the privileged read outside the fixed surface. Fixture
  collection applies the same rule and never dereferences a symlink into the machine running it
  (IQ-057).
- **No capability.** On the measured platforms uid 0 alone reads the surface; the bounding set stays
  the `AUTH-028` set, and nothing in this contract adds a capability.
- **Framing within `AUTH-015`** (owner decision 2026-10-09). `AUTH-015`'s single opaque `bytes` may
  carry a fixed binary framing of several raw acquisitions that belong to this one registered
  operation. The framing carries only the acquisition facts this contract needs: each item's raw
  name, its raw `lstat` metadata, its raw bytes where this contract permits reading them, and a
  low-level acquisition outcome in a field named `acquisition_outcome`, one of `READ_OK`,
  `NOT_FOUND`, `PERMISSION_DENIED`, `SYMLINK`, `NON_REGULAR`, `TRUNCATED` and `IO_ERROR`. A
  privileged-side acquisition outcome is not an ISEDRAF collection status: the framing never carries
  `COLLECTED`, `PARTIAL`, `NOT_TESTED` or `ERROR`, and never a policy interpretation or normalization
  - not whether an include is valid, whether sudo ignores an entry, or whether the graph or the
  section is complete. Decoding and every semantic interpretation happen only in the engine. The
  supervisor's own `status` keeps its `AUTH-015` meaning for the operation as a whole.

**AUTH-030 (D-124, AUTH-003, AUTH-006, AUTH-015, AUTH-028, AUTH-029) SHALL** The contract of
`read_sshd_declared_config_v1` (owner decision 2026-10-09, after the step C measurement recorded as
IQ-060).

- **Declared configuration only.** `read_sshd_declared_config_v1` establishes declared configuration
  evidence only. It never invokes sshd, never resolves effective configuration, and does not subsume
  `resolve_sshd_effective_config_v1`.
- **Fixed privileged surface.** `/etc/ssh/sshd_config`; the listing of `/etc/ssh/sshd_config.d`; and
  each non-symlink regular directory entry directly enumerated in `/etc/ssh/sshd_config.d`. Nothing
  else is read with privilege. The surface is acquired as one deterministic contract even though, on
  the measured platforms, the root file and the listing are readable without privilege; nothing in it
  needs more than uid 0.
- **The supervisor acquires, nothing more.** The same fixed-tree acquisition and the same framing as
  `AUTH-029`: one `acquisition_outcome` per item from the frozen set, a separate status for the root
  file, the enumeration and each entry, symlinks recorded and never followed, no filename or `*.conf`
  rule, no Include parsing, no `Match` interpretation and no caller-supplied path.
- **The engine interprets.** It decodes the frame and applies sshd's grammar: the `*.conf`
  selection and order, Include directives and `Match` scoping, and it builds the declared-configuration
  graph.
- **Includes outside the surface.** For an include target outside the fixed surface the engine attempts
  its own read, as itself. A target it reads is collected and recorded `CURRENT_IDENTITY`; a target it
  cannot read or resolve is `NOT_TESTED` and the section is `PARTIAL`. The engine never asks the
  supervisor to read a discovered path: the operation stays fixed, and `AUTH-003` admits no path from
  the engine. A section whose required sources were all observed may be `COLLECTED` whatever mix of
  `SUPERVISOR_FIXED_OPERATION` and `CURRENT_IDENTITY` acquired them; every source states truthfully how
  it was acquired.
- **No capability.** On the measured platforms (Debian 12, Ubuntu 24.04, Rocky 9 and AlmaLinux 9)
  `/etc/ssh/sshd_config` is 0644 and `/etc/ssh/sshd_config.d` 0755, and the reduced engine reads and
  lists them; privileged acquisition is required for root-only drop-in files such as the measured 0600
  entries, and uid 0 is sufficient. The bounding set stays the `AUTH-028` set.
- **Not generalised.** This rule for out-of-surface includes is specific to this operation. `AUTH-029`
  is unchanged: an include outside the sudoers surface stays `NOT_TESTED`.

**AUTH-031 (D-124, AUTH-003, AUTH-006, AUTH-015, AUTH-025, AUTH-028, AUTH-030) SHALL** The contract of
`resolve_sshd_effective_config_v1` (owner decision 2026-10-09, after the step C measurement recorded as
IQ-061).

- **Global effective configuration only.** The operation establishes the OpenSSH server's *global*
  effective configuration: the values `sshd -T` computes from the configuration and the compiled
  defaults when no connection is known. It does **not** establish the effective configuration of any
  connection, and it does **not** resolve `Match` blocks: on every measured platform a `Match`-scoped
  value appeared only when sshd was given a connection context (`-C`), and without one sshd printed
  the global value without saying so. Every place that records, renders or explains this evidence
  names it the global effective configuration and states that `Match`-dependent values are not
  resolved; it is never presented as the effective SSH configuration for every possible connection.
  The declared configuration, the `Match` blocks included, stays with `read_sshd_declared_config_v1`
  (`AUTH-030`); neither operation subsumes the other.
- **Fixed command, no input.** The executable is `/usr/sbin/sshd` and the argv is exactly `-T`: no
  `-C`, `-f`, `-o`, `-h` or any other argument, and no caller-, engine-, host- or policy-derived
  argument (`AUTH-003`). The registry's clean fixed environment, working directory `/`, stdin
  `/dev/null`, timeout and output bound apply. The operation is not a general command runner: no other
  executable and no other argv are admitted under it. A connection context (`user=`, `host=`, `addr=`
  or any other `-C` value) is a different assurance question and is never added to this operation;
  if it is wanted, it is a separate future operation with its own decision, design and measurement.
- **Fail closed.** The acquisition succeeds only when sshd exits 0 and its stdout is non-empty. Any
  other exit status, an empty stdout, a timeout, a signal or stdout beyond the bound is a failed
  acquisition: stdout is not parsed, in whole or in part, and no configuration value is derived from
  it; bounded stderr is kept only as a diagnostic. In the measurement, sshd left stdout empty on
  failure, exiting 1 or 255 with stderr naming the file.
- **Raw evidence untouched.** A successful stdout is preserved byte-for-byte as evidence. The
  privileged side neither parses, filters, reorders nor normalizes it (`AUTH-015`); interpretation
  happens only in the engine.
- **Directive-specific normalization.** Canonical host state derived from the output does not treat the
  order of a repeated directive as semantically irrelevant unless that specific directive has been
  shown to be order-insensitive; a repeated directive not so shown keeps its order. No general rule
  sorts repeated keys. In the measurement, `listenaddress` was the only directive whose order changed
  with the execution environment (the unit's `RestrictAddressFamilies=` alone swapped its two lines);
  `hostkey`, and `acceptenv` on Debian and Ubuntu, repeated without changing order. Normalizing
  `listenaddress` requires its semantics to be confirmed and recorded first; this clause does not
  authorize it.
- **No capability.** On the measured platforms (Debian 12, Ubuntu 24.04, Rocky 9 and AlmaLinux 9) uid 0
  is required - the reduced engine is refused on root-only drop-ins and, without them, on the host
  keys - and sufficient: the output was identical with an empty bounding set. The bounding set stays
  the `AUTH-028` set. No change to sshd's process, the listening sockets, `/etc/ssh` or the host keys,
  no sshd or PAM journal entry and no AVC was observed.
- **Status.** The operation stays `PLANNED`; its implementation, lab proof and validation follow
  `AUTH-025`.

**AUTH-032 (D-124, SCOPE-071, AUTH-019, AUTH-021, AUTH-022, AUTH-026, AUTH-028) SHALL** The
read-only Full Audit report (owner decision 2026-10-10: v0.2 must be usable, and the primary feature's
evidence must not be readable only as root-owned files).

- **One more invocation, nothing else.** Under euid 0 or with `SUDO_USER` set, `isedraf report`, alone
  or with exactly one of `--json` or `--html`, enters this route on a supported platform. `--save`,
  `--profile` and every other option or argument are refused with exit `70`: nothing under root writes
  a report into the store or reads a path the operator names. Every other root invocation stays refused
  as `AUTH-019` states.
- **The same execution model.** The outer entry of `AUTH-019` runs `/usr/bin/systemd-run` with the
  constant properties of the audit unit except `ReadWritePaths=`, so the store is read-only in the
  unit by `ProtectSystem=strict`; the transport and interruption rules of `AUTH-020` apply unchanged.
  The unit name derives from a fresh run id. No daemon, socket, timer or persistent service is created.
  No capability beyond the `AUTH-028` set is granted, and the set the route needs is measured before it
  is fixed.
- **The fixed production store, read-only.** The in-unit report launcher opens only `/var/lib/isedraf`,
  validates it as `AUTH-022` requires and refuses with exit `67` on any deviation, never repairs,
  creates, chmods, renames, appends or removes anything, and takes the whole-run lock so that it never
  reads a store mid-promotion (a held lock is exit `66`). No alternate store path exists.
- **What the root side reads, and how.** Under the lock the launcher reads the ledger segments, bounded,
  and selects the latest committed snapshot by the `D-50` rule (the snapshot of the last ledger record);
  it reads that snapshot's manifest, bounded, and the files the manifest declares, each opened no-follow,
  a regular file within `AUTH-021`'s bounds, never a link. This is the same structural reading of
  ISEDRAF's own integrity metadata that promotion performs under `AUTH-021`; host evidence content is
  never parsed, interpreted or rendered on the root side, and nothing from the reduced side selects what
  is read - no identifier, path or request crosses back.
- **The renderer is reduced.** The launcher starts the renderer through `/usr/bin/setpriv` with the
  `AUTH-020` engine reduction (the `isedraf` user and group, no supplementary groups, every capability
  set empty, no-new-privileges), a fixed entry and a constant argument vector naming only the output
  format. It receives the ledger bytes and the snapshot's files in one bounded frame on a pipe; it holds
  no descriptor or path into the store, so the `AUTH-022` rule that the engine identity never reaches
  `snapshots/`, `ledger/` or `.lock` holds. It persists nothing and writes nothing to the
  store: it may hold the received bytes in a directory it creates, 0700 and inaccessible to
  other users, in the unit's private temporary space (`PrivateTmp=yes`), bounded by the frame,
  and removes it before it exits, whether it rendered or refused; when it is ended abruptly,
  the unit's private temporary space - discarded with the unit - provides the isolation and
  the cleanup. Its only output is the rendered report on its stdout.
- **Verified before rendered, unprivileged.** The renderer recomputes the ledger chain from the first
  record, the snapshot's manifest hash, every file hash the manifest lists and the binding of the last
  ledger record to that manifest hash. A mismatch, a malformed or over-bound frame, or a missing
  declared file renders no report and exits with an error that says why. The report states the scope
  of what was verified: the ledger chain and the reported snapshot; snapshots that are not reported are
  not re-verified by this route.
- **What the report says.** The renderer is the existing report renderer: no privileged renderer exists.
  The report states the run mode and the verification result and keeps the collection axes separate;
  native results, findings, scores and compliance percentages are not part of it (`D-79`, v0.3).

