# ISEDRAF — Evidence and Trust Model

Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0


## 1. Trust boundaries

```text
┌──────────────────────────────────────────────────────────────────┐
│ NOT TRUSTED — treated as hostile data, never as instructions     │
│   file contents · command stdout · usernames · GECOS · paths     │
│   log message text · authorized_keys comments · sudo rule bodies │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│ REPORTED — recorded as observed, with its source, no claim made  │
│   TPM/PCR · Secure Boot · kernel lockdown · listeners            │
│   interpreter identity · detected external agents                │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│ RESOLVED — a subsystem computed it, so it beats file-reading     │
│   sshd -T · cvtsudoers -f json · findmnt -J · systemctl show     │
│   timedatectl show · auditctl -s/-l · aa-status --json           │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│ VERIFIED WITHIN A STATED TRUST LEVEL — never "verified" bare     │
│   LOCAL_CONSISTENT · PACKAGE_CONSISTENT · EXTERNAL_VERIFIED      │
└──────────────────────────────────────────────────────────────────┘
```

**EVID-001 (D-13) SHALL** Where a subsystem can resolve its own configuration, the resolved value is
preferred over re-implementing the parse. Declared file values are recorded as context, not as the
effective state.

**EVID-002 (D-19, D-21, Q-17) SHALL** System-derived strings SHALL NEVER be interpolated into a command, a
shell, HTML, a format string, **or a filesystem path**. They are data.

**EVID-004 (Q-17, NEW) SHALL** A system-derived path SHALL NEVER become an executable path or a privileged
output path. Collector read paths pass an explicit path policy. ISEDRAF-owned writes use fixed trusted
roots, safe relative components, and no-follow/exclusive creation; an entity-derived path component is the
entity's hash or an allowlisted slug, **never the raw name**. Arbitrary host-derived path concatenation is
forbidden.

**EVID-003 (D-31, Q-14) SHALL NOT** In a **claim about host or tool evidence**, the word *verified*
SHALL NEVER appear without an accompanying trust level. Lifecycle state names (`HLD-063`'s mapping
`VERIFIED`), internal preconditions (`EXEC-010`'s "verified root-owned") and **ledger-chain internal
consistency** are exempt: the last is a statement about bytes agreeing with each other, not a claim about
host or tool evidence. `isedraf verify` nonetheless prints the trust level — *chain internally consistent
(`LOCAL_CONSISTENT`) from checkpoint `<id>`* — rather than a bare "verified" (T-18).

## 2. Privilege model

**PRIV-001 (D-22) SHALL** Sudo is recommended for full evidence, not mandatory. An unprivileged run is
supported. Root-only facts become `NOT_TESTED` with a reason. The report header states the privilege level.

**PRIV-002 (D-23) SHALL NOT** Never: internal sudo, password prompts, setuid, polkit, D-Bus helper, file
capabilities on Python, a daemon, or spawning a pager, editor or browser under euid 0.

**PRIV-003 (D-24) SHALL** Under `SUDO_USER`, output goes only to `/var/lib/isedraf/...` or stdout.
User-supplied paths are refused or treated as untrusted data. A sudoers example ships as documentation only.

**PRIV-004 (D-70) SHALL** `ISEDRAF_STATE_ROOT` is honoured **only** when euid ≠ 0 **and** `SUDO_USER` is
unset. It is refused under root or via sudo. Every artifact produced there is marked `"state_root": "DEV"`
and SHALL NEVER be approvable or mistakable for production evidence.

**PRIV-005 (D-26, T-01) SHALL** **This is the single normative definition of execution topology**
(`NRM-001`). There are exactly **two** execution modes, and the sandbox claim is scoped to the mode that
actually has it.

**Mode A — full privileged audit.** Required on v0.1 supported platforms (Debian 12, Ubuntu 24.04,
Rocky/Alma 9), where systemd is part of the full-audit execution requirement:

```text
sudo isedraf
      ↓  minimal re-exec entry
  systemd transient sandbox
      ↓
  ROOT SUPERVISOR (inside the sandbox)
      ├── acquire whole-run lock
      ├── state-root writability preflight
      ├── PRE privileged collectors      (fixed executable, fixed argv)
      ├── spawn ENGINE child             (reduced capability set; never regains privilege)
      │        … collect · normalize · evaluate · store … engine exits
      ├── POST privileged collectors     (e.g. audit post-fingerprint)
      ├── commit / finalize
      └── release lock
```

**Every privileged ISEDRAF process is inside the sandbox.**

**Mode B — unprivileged audit.**

```text
isedraf  →  unprivileged engine  →  no privileged collectors
          →  PARTIAL / NOT_TESTED where privilege was required
```

**PRIV-006 (T-01) SHALL NOT** Mode B SHALL NOT be described as having Mode A's root transient-unit
protections. A non-systemd environment does **not** receive an improvised privileged fallback: full audit
is **unsupported** there, reported as such, and never silently degraded.

**PRIV-011 (D-26, T-02, NEW) SHALL** A **tiny root supervisor** holds the lock and the minimal capability
ceiling for the **entire run**, so that both the pre- and post-audit collectors can execute. The engine is
a **child** with its own reduced set and can never reacquire the supervisor's privilege. This is what makes
`EXEC-004`'s post-run fingerprint reachable: dropping the audit capability before the engine would have
made `CHANGED_DURING_RUN` unproducible.

The supervisor's lifetime is the run; its capability set is declared, minimal, and `CAP_SYS_ADMIN`-free.
The exact `setpriv`/capability recipe is **not** frozen until the corpus proves it (OD-06).

**PRIV-012 (D-69, OD-06) SHALL** If the capability model cannot hold on a target platform, the lane stops
and evidence is recorded under OD-06. Capabilities SHALL NEVER be widened, setuid added, a privileged
daemon introduced, SELinux disabled, or the sandbox weakened to make a collector succeed.

**PRIV-007 (R-13, S-36, Q-01) SHALL** The sandbox is a `systemd-run --pipe --wait` **transient service** —
exec-context properties (`ProtectSystem=`, `PrivateTmp=`, `SystemCallFilter=`, `RestrictAddressFamilies=`,
`CapabilityBoundingSet=`, `AmbientCapabilities=`) are unavailable to `--scope` — with a unique unit name
per `run_id`. The whole-run `flock` is acquired by the **in-sandbox launcher as its first action**,
before any privileged branch, so the lock covers the entire run including collection (`SNAP-014`,
`STORE-015`).

**PRIV-009 (Q-01, Q-05, NEW) SHALL** `EXEC-001`'s unit properties SHALL include `CapabilityBoundingSet=`
and `AmbientCapabilities=` as the outer ceiling. Without them a root transient unit keeps the full
bounding set by default, and "the engine cannot grant a collector its capability" would be unenforced.
The concrete set is deferred to OD-06; its **presence** is not.

**PRIV-010 (Q-01, NEW) SHALL** Collector-to-engine transport freezes **security requirements only**, not
an implementation: private to the run · bounded in size · never executable · not user-selectable ·
no network · no untrusted pathname construction. The prototype MAY choose pipes or ISEDRAF-owned
temporary artifacts under `EXEC-020`'s run area. The transport implementation SHALL NOT be prematurely
frozen.

**PRIV-008 (R-12, S-35, T-28) SHALL** The state-root writability preflight runs **after** the lock is
acquired, inside the sandbox (`PRIV-005` step 2), never in the outer entry process — otherwise it touches
the state root unsandboxed and unlocked, creating a TOCTOU against the run that follows.
Concurrency and writability are defined, not implied: a bounded
`flock -w` then fail fast with a dedicated exit code; stale-lock handling defined; read-only subcommands
take a shared lock or read only committed, ledger-confirmed snapshots. A non-writable or read-only state
root is detected by preflight with its own reason code before any collection, and "the sandbox unit failed
to start" is reported distinctly from an engine crash.

**PRIV-020 (D-25) SHALL** SELinux and AppArmor are **observed only**. `setenforce`, `semanage`,
`setsebool`, `semodule`, relabelling and policy installation SHALL NEVER be invoked.

**PRIV-021 (D-25) SHALL** `EACCES` under an enforcing MAC becomes `NOT_TESTED` with reason "possible MAC
denial" and an `ausearch -m AVC` hint. It SHALL NEVER become `FAIL`.

**PRIV-022 (D-25) SHALL** ISEDRAF reports its own execution context (`id -Z`). Confined SELinux users are
documented; under a confined user, affected controls are `NOT_TESTED`, not `FAIL` (acceptance test 12).

## 4. Sandbox and residual risk

**EXEC-020 (R-11, NEW) SHALL** The snapshot build directory is `/var/lib/isedraf/tmp/` — the **same
filesystem** as `snapshots/`, mode 0700 — because `PrivateTmp` makes `/tmp` a tmpfs and `rename()` across
filesystems fails with `EXDEV`. Stale build directories are cleaned at start of run and are explicitly
excluded from the `ORPHANED_UNLEDGERED` rule.

**EXEC-001 (D-27, T-01) SHALL** In **Mode A** (`PRIV-005`) the run executes under `systemd-run` with
`ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=/var/lib/isedraf`, `PrivateTmp`,
`ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `ProtectClock`, **`CapabilityBoundingSet=`** and
**`AmbientCapabilities=`** (the outer ceiling, `PRIV-009`), and a
`SystemCallFilter` excluding `@mount @module @reboot @swap @raw-io @clock @cpu-emulation @obsolete`.
`NoNewPrivileges` is enabled only after corpus validation.

**EXEC-002 (D-85) SHALL** The sandbox adds `RestrictAddressFamilies=AF_UNIX AF_NETLINK` and
`IPAddressDeny=any`. The report states `NETWORK EGRESS: KERNEL_RESTRICTED` or `CODE_ONLY`.

**EXEC-003 (D-28) SHALL** Wording is exactly *"FILESYSTEM PROTECTION ENFORCED; KERNEL MUTATION
MINIMIZED"*. *"Read-only guaranteed"* SHALL NEVER be used.

**EXEC-004 (D-28, T-02) SHALL** Audit status and loaded rules are fingerprinted before and after the run
**by the root supervisor** (`PRIV-011`), which outlives the engine for exactly this purpose. A difference
is reported as `CHANGED_DURING_RUN` **without attributing a cause**. The report states only
*"no persistent difference observed between pre/post snapshots"* — never that no transient mutation
occurred.

**EXEC-005 (D-29, OD-13) SHALL** Run start and end are logged to the journal with a run ID and the
invoking user. OD-13 records how this interacts with `RestrictAddressFamilies`.

### Residual risk, stated plainly

| Control | What it actually achieves | What it does not |
|---|---|---|
| `ProtectSystem=strict` | the process cannot write outside declared paths | does not stop a root attacker outside the sandbox |
| capability bound | the engine cannot perform most privileged operations | does not prove nothing else on the host can |
| `IPAddressDeny=any` | kernel refuses IP egress from this unit | does not apply to a non-systemd host, where the claim degrades to `CODE_ONLY` |
| pre/post audit fingerprint | a change during the run is visible | does not attribute the change to ISEDRAF or to anything else |

## 5. Execution hygiene

**EXEC-010 (D-17) SHALL** Entry point is `#!/usr/bin/python3 -IB`; install root `/usr/lib/isedraf`; no
`.pyc` in the package. Before inserting the install root into `sys.path`, it and every parent SHALL be
verified root-owned and not group- or world-writable, else the run refuses with `ENGINE_UNSAFE_INSTALL`.

**EXEC-011 (D-18) SHALL** Every subprocess uses an argv list, `shell=False`, an empty environment plus
`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`, a timeout, bounded output, and `stdin=DEVNULL`. Bash is
invoked with `--noprofile --norc`.

**EXEC-012 (D-19, D-71) SHALL NOT** Forbidden: builtin `eval()`/`exec()`, `pickle`, dynamic imports from
content paths, shell interpolation of system-derived strings, unescaped HTML, `shell=True`, `os.system`,
`bash -c`/`sh -c` with a non-constant string. `os.execv*` is permitted **only** in
`lib/isedraf/launcher/` with fixed absolute paths.

**EXEC-013 (D-20) SHALL** `umask 077`; directories 0700; files 0600; creation with `O_NOFOLLOW|O_EXCL`;
symlinked or non-root-owned report paths refused.

**EXEC-014 (D-84) SHALL** Runtime imports are restricted by an explicit stdlib allowlist
(`lib/isedraf/runtime-imports.allow`). Anything else fails `make check`, covering at minimum `socket`,
`ssl`, `urllib`, `http`, `smtplib`, `ftplib`, `xmlrpc`, asyncio networking,
`multiprocessing.connection`, `sqlite3`, `dbm`, `shelve`. No subprocess to a network client
(`curl`, `wget`, `nc`, `ssh`, `scp`).

**EXEC-015 (D-86) SHALL** Syntax validation SHALL NEVER write bytecode. In-memory `compile()`/`ast.parse`,
or a disposable temporary build copy removed before the gate completes. `python -m py_compile` SHALL NEVER
be used — it writes `.pyc` even under `-B`.

**EXEC-016 (D-12, revised) SHALL** Runtime is Bash (only where a shell sequence is genuinely required)
plus Python **standard library only**.

**The floor is split, because two different questions were being answered by one number.** Code that runs
**on a target host** — the `isedraf` package — is written to a **Python 3.6 language and API level**.
Development, test and certification tooling is **not** constrained and may require a newer interpreter: it
never runs on a target host, and holding it to a 2016 language level would buy nothing.

ISEDRAF **SHALL NEVER install, bundle, pin or downgrade an interpreter.** It uses the one the host already
has, and prefers the newest suitable system interpreter whatever its version — 3.13 on Debian 13, 3.14 on
Ubuntu 26.04, the vendor 3.6 on EL8. `python3` on `PATH` is **not** the only place to look: EL8 ships no
`python3` by default yet always has a working vendor interpreter at `/usr/libexec/platform-python`,
because `dnf` itself requires one. A host with no suitable interpreter is reported as a missing
prerequisite; ISEDRAF installs nothing to make itself run.

**A support claim is narrower than the compatibility level.** `3.6` names the language and API level the
source is written to. Where a Python branch is **upstream end-of-life**, a support claim additionally
requires the interpreter to be **maintained by the operating-system vendor** as part of a supported
platform. A self-built 3.6 on an unsupported distribution carries no support claim, and the two concepts
SHALL NOT be conflated.

No Go, no compiled components, no third-party runtime modules, no plugin framework in v0.1. Development
and CI tools live in `requirements-dev.txt` and SHALL NEVER be imported by runtime code.

## 6. Tool integrity

**INTEG-001 (D-30) SHALL** `TOOL INTEGRITY` and `HOST BASELINE CONSISTENCY` are separate concepts and
separate report lines, always.

**INTEG-002 (D-31) SHALL** Trust levels: `LOCAL_CONSISTENT` (own manifest matches on-disk files),
`PACKAGE_CONSISTENT` (package manager verification agrees), `EXTERNAL_VERIFIED` (signature verified by a
tool outside ISEDRAF). Local verification detects **drift**, not a root adversary.

**INTEG-003 (D-31) SHALL** Signature verification occurs only via `apt`/`dnf` or an external `gpg`/`sqv`.
A documented external recipe SHALL exist that works **without ISEDRAF** (`sha256sum -c` plus the package
manager's own signature verification).

**INTEG-004 (D-31) SHALL** The interpreter identity is **reported, not verified**.

**INTEG-005 (D-32) MAY** Later, exports may be signed with `ssh-keygen -Y sign`. The only claims permitted
are: unchanged since signing, signed by a pinned host key. Non-repudiation, kernel-generated evidence and
trusted time SHALL NEVER be claimed.

## 7. Anti-deception facts

**EVID-010 (D-39) SHALL** Collected as facts: `/etc/ld.so.preload`, kernel taint, unsigned or out-of-tree
modules, package verification of executed binaries.

**EVID-011 (D-39) SHALL** The reporting phrase is *"no security-relevant change observed"*. *"Host
unchanged"* SHALL NEVER be used.

**EVID-012 (D-40) SHALL** TPM, PCR values, Secure Boot state and kernel lockdown are recorded as facts
only. No attestation claim is made.

**EVID-013 (D-38) SHALL** Host identity uses composite anchors. `host_id` is derived app-specifically from
machine-id; hardware serials and UUIDs are HMAC-SHA256 with a per-install key (mode 0600). A confidence
score accompanies it. Flags `POSSIBLE_CLONE` and `POSSIBLE_ROLLBACK` are raised; a mismatch yields
`BASELINE_NOT_APPLICABLE` and **no diff** (acceptance test 7).

**EVID-014 (D-38, D-51) SHALL NOT** Raw machine-id and raw hardware serials SHALL NEVER appear in canonical
or exported data.

## 8. Account-creation provenance

**EVID-020 (D-75) SHALL** Account creation time is provenance, never invention. Exactly three states:

| State | Requires |
|---|---|
| `EVENT_RECORDED` | an auditd `ADD_USER` record, **or** a journal entry whose **trusted fields** show `_UID=0` and the real account-management binary in `_EXE`. Message text alone SHALL NEVER be trusted. |
| `ESTIMATED` | e.g. home-directory birth time. Carries source, confidence `LOW`, and an explanation. |
| `UNKNOWN` | anything else, including rotated-away evidence. A guess SHALL NEVER be substituted. |

**EVID-021 (D-75) SHALL NOT** `EVENT_RECORDED` SHALL NEVER be claimed tamper-proof — root can rewrite local
logs. The record cites its source, record reference and retention context. The word `VERIFIED` SHALL NEVER
be used for this. Password last-change time SHALL NEVER be treated as creation time. Home-directory birth
time SHALL NEVER silently become the creation time (acceptance test 15).

**EVID-022 (D-75) SHALL** An unprivileged `logger -t useradd` spoof SHALL NEVER produce `EVENT_RECORDED`
(acceptance test 21). This is what the trusted-field requirement exists for.

## 9. Recording coverage

**EVID-030 (D-76) SHALL** `isedraf recording` answers: *if a relevant event occurred on this host, what
locally observable evidence would exist?* Event classes: authentication; SSH authentication/session;
sudo/privilege use; account and group change; audit subsystem state; journal persistence and volatility;
timestamp and time-synchronization quality.

**EVID-031 (D-76) SHALL** Per class: collection source; whether evidence is observable; persistence and
volatility; declared/resolved/active where applicable; oldest and newest observable event times **as
bounded observations only**.

**EVID-032 (D-76) SHALL NOT** Failure to observe an event class SHALL NOT be reported as "the event is not
recorded" unless configuration or state evidence proves that conclusion.

**EVID-033 (D-76, D-67) SHALL** External SIEM and log-forwarding effectiveness is outside the boundary.
Locally detected forwarding configuration MAY later be inventory context only. Successful remote delivery
SHALL NEVER be claimed (acceptance test 18).

## 10. Threat table

| Attacker / failure | Mitigation | Residual risk |
|---|---|---|
| Unprivileged local user reads reports | `umask 077`, 0700/0600, `O_NOFOLLOW\|O_EXCL`, refuse symlinked paths (`EXEC-013`) | a prior leak of an already-shared report is not undone |
| Unprivileged user forges a log line to fake account creation | trusted journal fields `_UID=0` + `_EXE`, never message text (`EVID-020`, `EVID-022`) | an attacker who is already root can write trusted fields |
| Administrator mistake — approving an incomplete baseline | incomplete/unprivileged snapshots are not approvable (`HLD-041`), first snapshot never auto-approved (`HLD-040`) | an administrator may still approve a genuinely bad but complete state — a baseline is *accepted*, not *secure* |
| Root attacker on the host | **not defeated.** Local verification detects drift only (`INTEG-002`) | ISEDRAF is not remote attestation; a root adversary can alter source data, logs and ISEDRAF itself |
| Malicious system strings (username, GECOS, key comment) | treated as untrusted data; never interpolated; HTML-escaped; CSV formula-guarded (`EVID-002`, `OUT-012`) | a rendering surface added later without the guard would reintroduce the risk |
| Supply chain — tampered ISEDRAF | tool integrity separate from host state; trust levels; external verification recipe independent of ISEDRAF (`INTEG-001`…`INTEG-003`) | `LOCAL_CONSISTENT` alone proves little; only `EXTERNAL_VERIFIED` involves a key outside the host |
| Collection failure silently read as a pass | collection status separate from evaluation result; `NOT_TESTED` never `PASS`; `NOT_COMPARABLE` with reason (`CMP-001`) | a domain nobody wrote a collector for is simply absent — mitigated by the requirements trace, not by runtime |
| Cloned or rolled-back VM | composite host anchors, `POSSIBLE_CLONE`/`POSSIBLE_ROLLBACK`, `BASELINE_NOT_APPLICABLE` (`EVID-013`) | a perfect clone including machine-id and the per-install key is indistinguishable |
| Egress introduced by a future change | import allowlist, no network subprocess, kernel address-family restriction (`EXEC-014`, `EXEC-002`) | on a non-systemd host the kernel restriction is unavailable and the claim degrades to `CODE_ONLY` |

## 11. Honest limitations, to appear in auditor-facing documents

**EVID-040 (D-43, D-30, D-79) SHALL** These statements SHALL appear in auditor documentation and SHALL NOT
be softened:

- A baseline is **accepted**, not secure.
- No observed delta does **not** prove the host is uncompromised.
- A local signature does **not** prove root did not manipulate the source data.
- Host technical evidence is **not** organizational compliance.
- `NOT_TESTED` is **not** `PASS`.
- Absence of local product evidence is **not** absence of an external control.
- ISEDRAF observes userspace and kernel-exposed state; it is **not** remote attestation.
- The ledger's hash chain uses **no secret and no external anchor**. It detects accidental corruption and
  truncation, not a local root adversary, and not a rollback of the whole state directory — only an
  externally retained checkpoint does that (`STORE-017`, `STORE-013`).
- A snapshot is **treated as immutable by ISEDRAF**; it is not protected against a local root adversary
  (`SNAP-010`).
- A **perfect clone**, including machine-id and the per-install key, is indistinguishable from the original
  (`EVID-013`).
- A **redacted export is not hash-verifiable** against the snapshot's section hashes (`OUT-022`).
- `host_id` is **pseudonymous, not anonymous**: a stable derivative, so any export shared outside the
  organization is a persistent correlator (`OUT-022`).
- A ledger **recovery** breaks uninterrupted integrity; the gap is recorded, not papered over (`STORE-016`).
- `verify` proves the chain only **from the last checkpoint**; earlier history is not locally verifiable
  (`STORE-018`).
- Exports are **unsigned** in v0.1 (`INTEG-005` is later-only).
- Exit `0` means *nothing unaccepted changed **in the tracked set***, not that the host was fully
  assessed. Coverage is defined by the baseline profile (`BASE-021`), not by the exit code (T-17).
- Truncation and rollback are **not** detected by the hash chain alone — a shorter chain is still
  internally perfect. They are detected by the store cross-check (`SNAP-015`) and by an externally
  retained checkpoint (`STORE-013`) (T-24).
