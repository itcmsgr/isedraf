<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Full Audit Authority Model

Implements: D-123, D-118, D-122, D-121, PRIV-005, PRIV-011, PRIV-012, INTEG-002

**Frozen by owner decision 2026-10-06 (`D-123`). Design only: nothing here is implemented, and no
runtime behaviour changes with it.**

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
while every operation is still `PLANNED`.

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
  corpus, not assumed.

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
(`STORE-025`).

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
  "forbidden_privilege_basis": ["CAP_SYS_ADMIN"]
}
```
