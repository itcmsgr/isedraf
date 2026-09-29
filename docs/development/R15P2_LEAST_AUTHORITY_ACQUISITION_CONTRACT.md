<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# R1.5-P2 — Verifiable Least-Authority Acquisition

Status: PLANNED
Implements: SCOPE-022, SCOPE-045, GOV-001, GOV-002

**DESIGN ONLY. Nothing here is built, and nothing here is authorized to be built.**
This is a clearly labelled architecture reservation under `DOCUMENTATION_POLICY.md` §6.
No collector was modified, no privileged code exists, no `sudo` call was added, and the
R1.5-P behaviour — collect what is visible, state plainly what cannot be proven — remains
the authoritative behaviour until and unless the owner freezes a successor.

Six owner decisions are required before any of this can be implemented. Four of them are
conflicts with *currently frozen* authority, not open design space. They are section 2,
deliberately placed before the design, because a design that reads as ready-to-build while
silently contradicting the register is the more expensive mistake.

## 1. Repository truth inspected

REPOSITORY FACT, measured in this checkout at `af41b67c`:

| Claim | Measured |
|---|---|
| `lib/isedraf/launcher/` — the D-26 root launcher | **does not exist** |
| Any `.service` or `.socket` unit in the tree | **none** |
| `security/` directory | **does not exist** |
| `packaging/` contents | `build.sh`, `deb/control.in`, `deb/copyright`, `rpm/isedraf.spec.in` — no MAC policy, no units |
| `lib/isedraf/hostio.py` outcome vocabulary | `READ_OK · NOT_FOUND · PERMISSION_DENIED · IO_ERROR` |
| `lib/isedraf/coverage.py` access vocabulary | includes `ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED`; no `CAP_*` or `root` names |
| Privileged execution anywhere in `lib/` | **none** |

So R1.5-P2 is not an adjustment to an existing privileged path. There is no privileged
path. Every privileged mechanism the register already describes (D-26, D-27) is decided
and unbuilt.

## 2. Conflicts with frozen authority — BLOCKING

These are not open questions. Each is a direct contradiction between this directive and a
higher tier of the authority chain, and under `CLAUDE.md` §1 they can only be resolved by
the owner through the internal amendments record.

### 2.1 A compiled worker is currently prohibited, and its language is NOT selected here

`CLAUDE.md` §2, Runtime, hard stop:

> No Go, compiled parts, plugins, third-party runtime modules.

Two separate questions were previously answered together, and only one of them can be
answered from evidence today.

**(i) May there be a compiled privileged worker at all?** Owner decision. The prohibition
stands until amended through `AMENDMENTS.md`; a direction given in conversation is not that
amendment. Proposed text is in IQ-024.

**(ii) Which language?** **WITHDRAWN.** An earlier revision of this document named Rust as
the proposed implementation. That was a selection made before any measurement, which is the
same error as picking Go would have been, and it is retracted. Rust is the **preferred
candidate**; Go is a **comparison candidate**; C may serve as an engineering baseline
without being a production candidate, because memory safety is part of the tradeoff being
measured. The choice is made in stage P2-B (§21) from the measurements listed there, and
not before.

What is language-independent, and is therefore safe to freeze early: operation IDs, the
operation contract, the IPC schema, the response schema, authority semantics, privilege
receipt semantics, negative-security semantics. What must **not** be frozen: any
Go-specific or Rust-specific runtime behaviour, and any libc assumption (P2-N7).

The security argument for compiling is unchanged and is not in dispute: an interpreter
carries `PYTHONPATH`, `sitecustomize`, `.pth` files and import-path search as a
code-injection surface *inside the privileged process*, and `python3 -I -S -E` reduces that
without removing the interpreter. That argument selects "compiled", not "compiled in a
particular language".

| Option | No runtime code-injection surface | Decided by |
|---|---|---|
| **(a)** amend the hard stop for ONE package-owned compiled worker | yes | owner (IQ-024) |
| **(b)** isolated-mode Python worker | **no** — weakness would have to be reported | owner (IQ-024) |
| **(c)** no privileged acquisition; R1.5-P semantics stand | not applicable | owner (IQ-024) |

### 2.2 D-26 freezes `auditctl` as a privileged external executable

D-26 (REVISED 2026-09-17, R-01) states that the audit collector receives
`CAP_AUDIT_CONTROL` from the launcher "with a fixed executable and fixed argv
(`auditctl -s` / `auditctl -l`)".

The directive states that privileged CLI wrappers are to be avoided where a bounded kernel
interface exists, naming `auditctl` specifically, and that any external executable is an
explicit architecture exception.

FROZEN REQUIREMENT versus directive. Fixed-executable/fixed-argv is **not** generic exec
and does not violate P2-N1 as written; it does conflict with the directive's stated
preference and with P2-N3's spirit, since executing any external binary under privilege
imports that binary's own behaviour, its dynamic loader, and its configuration surface into
the authority envelope. An owner decision is required either way, because leaving both
statements standing gives two different answers to the same question.

### 2.3 D-27 freezes a different confinement mechanism

D-27 specifies `systemd-run` — transient units constructed at run time — with a named set
of protections and `NoNewPrivileges` deferred until corpus validation. The directive
specifies packaged, operation-specific or class-specific units, with authority selected by
the endpoint rather than by the invoking process.

These are different mechanisms with different trust properties. A transient unit's
protections are chosen by the *caller* constructing the `systemd-run` command line; a
packaged unit's protections are owned by the package and are not caller-selectable. The
directive's model is the stronger one for P2-N5, and it is not what is frozen.

### 2.4 "Daemons" and "D-Bus helpers" are prohibited

`CLAUDE.md` §2, Privilege, hard stop:

> internal sudo, password prompts, setuid, polkit, D-Bus helpers, file capabilities,
> daemons, broader capabilities to make a collector succeed.

Socket activation with `Accept=yes` spawns one short-lived instance per connection and
leaves no resident privileged process, which is materially different from a daemon. Whether
it falls under this prohibition is an owner call, not mine. The directive's own mention of
"constrained D-Bus/API" for systemd operations is prohibited outright and is treated here
as out of scope rather than designed around.

Note also that `file capabilities` are prohibited: capabilities would have to arrive from
the unit (`AmbientCapabilities`), never from `setcap` on the binary. That constraint is
compatible with the design and is adopted.

### 2.5 The prototype scope does not include these domains

`CLAUDE.md` §7 places audit, services, listeners and packages outside the prototype. P2 is
therefore a design for a later milestone, and §17 sequences it accordingly.

## 3. Security objective

A skeptical administrator is not asked to trust ISEDRAF's own code to respect a privilege
boundary. If the privileged acquisition component contains a bug, the kernel is still the
thing that decides what that process can read, execute, call, connect to and change.

Everything that interprets evidence — criteria, comparison, snapshot semantics, reporting,
rendering, mapping — stays unprivileged and outside the boundary. Privilege buys exactly
one thing: bytes from a source the current identity cannot read. It never buys judgement.

## 4. Trust boundary

```
                        UNPRIVILEGED
                  +-----------------------+
                  |    ISEDRAF ENGINE     |
                  |  inventory · S3 ·     |
                  |  criteria · reports   |
                  +-----------+-----------+
                              |
                              | connect() to ONE endpoint
                              | no command string
                              | no path string
                              | bounded identifiers only
                              v
                    operation-class endpoint
                              |
  ===================== KERNEL AUTHORITY BOUNDARY =====================
                              |
                  +-----------v-----------+
                  |  ONE-SHOT EVIDENCE    |
                  |       WORKER          |
                  +-----------+-----------+
                              |
        +---------------------+---------------------+
        |                     |                     |
   systemd unit         MAC confinement        seccomp filter
   (capabilities,      (SELinux domain or     (syscall set)
    namespaces,         AppArmor profile)
    fs protection)
        |                     |                     |
        +---------------------+---------------------+
                              |
                        capability bound
                              |
                              v
                     EXACT EVIDENCE SOURCE
```

The engine chooses *which endpoint to connect to*. It does not describe what should happen
when it gets there.

## 5. Non-negotiable invariants

### P2-N1 — NO PRIVILEGED GENERIC EXEC

No privileged subprocess dispatcher, no `exec(command, args)` API, no caller-supplied
executable, no plugin entry point.

Prohibited counterexamples:

```
{"op": "RUN", "cmd": "/usr/sbin/auditctl", "args": ["-l"]}
{"op": "OP_X", "helper": "/usr/libexec/isedraf/collect-x"}
```

Fixed-executable/fixed-argv invocation is a separate question, unresolved — see §2.2.

### P2-N2 — NO PRIVILEGED ARBITRARY PATH

Inputs are bounded semantic identifiers. The worker derives every filesystem object itself,
from its frozen contract.

Prohibited:

```
{"op": "OP_READ", "path": "/etc/shadow"}          # even when the path is "correct"
{"op": "OP_READ", "path": "/proc/1/environ"}
{"op": "OP_ACCOUNT_SHADOW_READ_V1", "account": "../../NEVER-REACHABLE-CANARY"}
```

Permitted shape:

```
{"op": "OP_ACCOUNT_SHADOW_READ_V1"}               # parameterless
{"op": "OP_ACCOUNT_KEYS_READ_V1", "account_uid": 1001}
```

A correct path supplied by the caller is still forbidden. The point is not that the caller
might send a bad path; it is that the set of reachable objects must be a property of the
contract, not of the message.

### P2-N3 — NO PRIVILEGED SHELL

No `/bin/sh`, no `-c`, no command substitution, no shell interpretation, no
environment-selected executable, no `LD_PRELOAD`/`LD_LIBRARY_PATH` influence, no plugin or
module loading in the privileged process.

### P2-N4 — NO PRIVILEGED FILESYSTEM MUTATION

P2 acquires evidence. No write, `chmod`, `chown`, rename, unlink, package operation,
service change, firewall change, or temporary host modification — including "temporary"
ones that are reverted. `ProtectSystem=strict` with no `ReadWritePaths` is the intended
expression of this, so that it is enforced rather than merely intended.

### P2-N5 — NO APPLICATION-ONLY PRIVILEGE BOUNDARY

Assume the worker has a bug. Assume its parser has a bug. The design is acceptable only if
the kernel independently bounds what the resulting process can reach. Any control that
exists only as a check inside ISEDRAF code is not a boundary; it is a preference.

This applies to the launcher too (§2.3): a component that holds the union of authorities in
order to distribute subsets is itself a thing that can contain a bug.

### P2-N6 — NO SILENT UNION OF PRIVILEGED AUTHORITIES

A shadow read must not carry audit, netfilter, journal or any future authority. Authority
is per envelope, and an operation may only join an existing envelope when its requirements
are *demonstrably* identical — see §7.

Prohibited: one root broker whose policy is the union of every operation's needs, selecting
behaviour from a field in the request.

### P2-N7 — NO IMPLEMENTATION-LANGUAGE COUPLING

The operation contract, IPC schema, evidence schema, snapshot format, privilege receipt and
authority semantics are language-independent. A second implementation of the worker in
another language would have to satisfy the same contract and the same negative tests. The
language is not selected here (§2.1, P2-B); whichever is selected is an implementation, not
part of the specification.

Prohibited: a wire format that can only be produced by one language's serializer; a receipt
field whose meaning depends on a Rust or Python type; a contract that names a crate.

### P2-N8 — NO INIT-SYSTEM COUPLING

systemd is a confinement *backend*, not a requirement of the core. The core must be able to
run where the init system is procd, BusyBox init, OpenRC, or a Yocto/Buildroot minimal init.

Prohibited: an operation that cannot be expressed without a `.service` unit; a receipt that
cannot be produced without `systemctl`; a core code path that calls `systemctl`.

### P2-N9 — NO DISTRO COUPLING

No dependency on SELinux, AppArmor, `sudo`, glibc, a package manager, or a particular
filesystem layout in the core. Those are backends and packaging, selected per platform.

Prohibited: a core that fails to start when `sudo` is absent; an operation whose contract
names `/usr/lib/systemd`; an assumption that a shared libc is present.

### P2-N10 — CONFINEMENT CAPABILITY IS OBSERVED AND REPORTED, NEVER ASSUMED

The confinement actually obtained on this host is measured at run time and reported. A
platform that offers less is described as offering less.

Prohibited: reporting `MAC_ENFORCED` because a policy file is installed; treating a
platform's *intended* profile as the confinement obtained; presenting a generic-Linux
deployment as equivalent to a MAC-enforcing one.

This is the invariant that makes portability honest rather than a dilution:

```
PORTABILITY  !=  FALSE ASSURANCE
```

## 6. Authority selection must not live in the payload

Three candidate architectures:

| Architecture | P2-N6 | P2-N5 | Policy artifacts | Assessment |
|---|---|---|---|---|
| One generic privileged broker | **fails by construction** — the process holds the union | weak: a parser bug reaches every authority | fewest | rejected |
| Per-authority-class endpoint | holds | a bug reaches only that class | one set per class | **recommended** |
| Per-operation endpoint | holds | same as per-class where envelopes are equal | one set per operation | rejected as default; no additional enforcement when envelopes are identical, and more artifacts means more drift |

RECOMMENDATION: **per-authority-class endpoint**, the smallest design that satisfies
P2-N5 and P2-N6. Each class gets its own socket path, its own unit, its own MAC domain or
profile, and its own syscall filter. The `operation_id` still travels in the message and is
still validated, as a cross-check — never as the thing that selects authority.

The property being bought: a caller that modifies the request JSON cannot turn the shadow
endpoint into the audit endpoint, because the authority was already fixed by which socket
it connected to and by the unit behind that socket.

### 6.1 Authorization is not confinement

```
SUDO / SOCKET PERMISSION   =  WHO may invoke WHICH trusted executable
MAC / SECCOMP / CAPS / FS  =  WHAT that executable can then actually do
```

Both are needed. A digest-pinned sudo rule answers the first question well and does not
answer the second at all: once the process is root, sudo has no further opinion about which
objects it reads, whether it calls `mount`, or whether it opens a socket. P2-N5 is about the
second question.

### 6.2 Two authorization backends

**Backend A — socket activation (full-server platforms).** The operator is authorized to
connect to a per-class socket. systemd starts the confined worker. VERIFIED PREFERENCE, and
the reason is structural rather than stylistic: under this backend **the caller never
executes anything privileged**. The binary is named by the packaged unit, not supplied by
the caller, so binary identity is not something the authorization layer has to pin.
Runtime `sudo` becomes unnecessary.

Socket ownership and mode are declared in the socket unit (`SocketUser=`, `SocketGroup=`,
`SocketMode=`), so the authorization surface is owned by the package and is visible in
`systemctl cat`. A post-start `chmod`/`chown` of a path under `/run` is **not** the
architecture: it is a window during which the socket exists with the wrong mode, and it
puts the authorization decision in a script instead of in policy.

**Backend B — digest-pinned sudo (platforms without socket activation).**

```
operator ALL=(root) NOPASSWD: \
    sha256:<digest> /usr/libexec/isedraf/isedraf-evidence-shadow-read-v1 ""
```

Both mechanisms confirmed against `sudoers(5)` in this checkout: `Digest_Spec` supports
`sha224/256/384/512`, and *"if the command line arguments consist of `""`, the command may
only be run with no arguments"*. Without the `""`, a command entry permits **any**
arguments, which would be materially weaker than it looks.

### 6.3 Four challenges to Backend B

**(1) `""` pushes operation selection into stdin, which collides with P2-N6.** One binary,
no arguments, means the class can only be selected by the protocol on stdin — and sudo does
not confine stdin. That is precisely the union-authority broker §6 rejects. Two ways out:

- pin the class as a **literal argument in the rule** — `... isedraf-evidence-helper
  shadow-read-v1` — one sudoers line per class. The argument is fixed by policy, not chosen
  by the caller, and the caller can only select among classes an administrator enumerated.
- install **one executable path per class**, each with `""`.

**The second is required anyway where SELinux is the MAC backend.** INFERENCE from
documented SELinux behaviour, not measured here: a domain transition keys on the
*executable's* type label, labels live in the inode's extended attributes, and hardlinks
share an inode. So one binary at one path cannot enter two domains, and hardlinking it
under two names cannot give it two labels. Per-class MAC domains therefore imply per-class
installed executables, not one helper with a class argument.

**(2) Any sudo backend contradicts a current hard stop.** `CLAUDE.md` §2, Privilege,
prohibits "internal sudo, password prompts". ISEDRAF invoking a sudo-wrapped helper is
internal sudo, and a `PASSWD:` variant adds a password prompt. Backend A does not engage
this prohibition; Backend B needs an amendment. That is an argument for Backend A as
primary and Backend B as the explicitly amended fallback, on governance grounds
independent of the security comparison.

**(3) Digest pinning breaks on upgrade, silently and in the safe direction.** Every package
upgrade changes the helper's bytes, so the sudoers rule stops matching until it is updated.
The failure is a refusal rather than an over-permission, which is the right direction, but
an operator sees privileged acquisition stop working after a routine update. The package
must install the sudoers drop-in and the binary as one unit, and the trust report must
detect a digest/rule mismatch and report it as an **authorization limitation**, never as a
collection error.

**(4) Residual: the digest is computed and then the file is executed.** An adversary able
to replace the file between those two points defeats the pin. Such an adversary generally
already holds root-equivalent write access to a package-owned directory, so the residual is
modest — but it is residual, and it is not described here with any of the words `CLAUDE.md`
§2 prohibits.

### 6.4 Where neither backend exists

On a minimal platform with no systemd socket activation and no `sudo` — a plausible
OpenWrt or Buildroot image — there is **no acceptable authorization backend**. The honest
outcome is that privileged acquisition is unavailable on that platform and the evidence
stays incomplete, recorded exactly as R1.5-P records it today.

Portability does not mean every platform gets privileged acquisition. Inventing a weak path
so that every platform has one would trade the whole point of P2 for coverage.

## 7. Authority equivalence classes

Two operations may share a class only when their envelopes are identical on every axis:

```
object access · capability set · syscall set · address families
filesystem visibility · mutation policy
```

Administrative convenience is not an axis. "Both are account-related" is not an axis. If one
operation needs audit netlink and another needs a file descriptor on `/etc/shadow`, they are
two classes regardless of how adjacent they look in the product.

The class is not established by declaring it. It is established by the negative-test matrix
in §14: for each class, the operations in it must be shown to be denied the same things.

## 8. Canonical operation contract

PROPOSAL: one machine-readable file is the design authority, and the tables, documentation
and policy inventory are generated from it. Repository conventions place canonical CI data
under `scripts/ci/*.json` (`gate_coverage.json`, `framework_sources.json`,
`public_licensing_policy.json`, `project_status.json`), so the proposed location follows
that convention rather than inventing a top-level `security/` directory:

```
scripts/ci/privileged_operations.v1.json
```

Proposed entry shape:

```json
{
  "operation_id": "OP_ACCOUNT_SHADOW_READ_V1",
  "authority_class": "ACCOUNT_SHADOW_READ_V1",
  "effect": "READ_ONLY",
  "inputs": [],
  "source_family": "LOCAL_ACCOUNT_SHADOW",
  "object_scope": ["/etc/shadow"],
  "network_required": false,
  "address_families": [],
  "external_exec": false,
  "shell": false,
  "filesystem_mutation": false,
  "capability_contract": [],
  "mac_selinux_domain": "isedraf_shadow_read_t",
  "mac_apparmor_profile": "isedraf-shadow-read-v1",
  "systemd_unit": "isedraf-evidence-shadow-read-v1.service",
  "seccomp_profile": "shadow-read-v1",
  "response_max_bytes": 1048576
}
```

The generator/verifier rule learned in W1-A applies without exception: **the independent
verifier must not import the generated implementation.** A verifier that reads the same
table the worker reads certifies that two copies of one belief agree. The verifier must
re-derive expected policy from the contract and compare against what the *running system*
reports — unit settings from `systemctl show`, MAC context from `/proc/<pid>/attr/current`,
capability masks from `/proc/<pid>/status`.

## 9. Capability strategy

Design order, in this order:

```
dedicated unprivileged service identity
        -> specific capability, if that is sufficient
                -> UID 0 only where genuinely required, still fully confined
```

`CAP_DAC_READ_SEARCH` is not "permission to read `/etc/shadow`". It bypasses a broad part
of DAC read and search checking across the filesystem. If it is used, MAC is what narrows
the reachable object set, and the trust report must not describe the capability as if it
were file-scoped. The contract carries the minimum set *per operation*; there is no
shared default set.

Capabilities arrive from the unit (`AmbientCapabilities`, bounded by
`CapabilityBoundingSet`). File capabilities are prohibited by `CLAUDE.md` and are not used.

## 10. systemd confinement backend

This section describes ONE backend (P2-N8). The core does not require it.

Settings are derived **per authority class** and proved, not pasted. The candidate
directives are `NoNewPrivileges`, `CapabilityBoundingSet`, `AmbientCapabilities`,
`RestrictAddressFamilies`, `SystemCallFilter`, `SystemCallArchitectures=native`,
`ProtectSystem=strict`, `ProtectHome`, `ProtectKernelTunables`, `ProtectKernelModules`,
`ProtectKernelLogs`, `ProtectControlGroups`, `PrivateDevices`, `PrivateTmp`,
`LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`.

Why a universal template is wrong, with the repository's own examples:

| Class | Address families | Note |
|---|---|---|
| shadow read | none | `RestrictAddressFamilies=` empty; a socket of any kind is a defect |
| audit query | `AF_NETLINK` | needed; and the netlink *family* being permitted is not the same as the audit subsystem being authorized — MAC decides the latter |
| netfilter query | `AF_NETLINK` | different netlink protocol and different MAC object class from audit |

`systemd-analyze security` is inspection information for a human. It is not the acceptance
oracle, and a score is not evidence. The oracle is §14.

## 11. MAC confinement backends

Two backends (P2-N9). Neither is required by the core; a platform with neither is described in §17.

The two systems are not syntactically interchangeable and the documentation will not
present them as if they were.

**SELinux** (RHEL/Alma/Rocky/Fedora family) is type enforcement: the worker runs in a
domain such as `isedraf_shadow_read_t`, permitted the specific object types its class
requires and denied others. **AppArmor** (Ubuntu/Debian family) is profile- and
path-oriented: the profile names the bounded paths plus execution and network restriction.

Reporting rules, which matter more than the policy text:

```
MAC_SYSTEM    SELINUX
MAC_MODE      ENFORCING
MAC_CONTEXT   system_u:system_r:isedraf_shadow_read_t:s0

MAC_SYSTEM    APPARMOR
PROFILE       isedraf-shadow-read-v1
PROFILE_MODE  ENFORCE

MAC_SYSTEM    NONE_ACTIVE
```

A policy file being installed is not enforcement. `MAC_SYSTEM NONE_ACTIVE` is a legitimate
outcome and must propagate into the evidence-limits manifest as weaker confinement, not be
quietly omitted. Permissive mode is reported as observed and is never reported as
enforcing.

## 12. seccomp strategy

Seccomp bounds syscalls. It does not authorize pathnames. The design keeps that distinction
in the vocabulary, because a test that claims otherwise teaches the wrong model:

```
read a forbidden protected object      -> MAC DENIAL
execve("/bin/sh")                      -> SECCOMP DENIAL
mount(...)                             -> SECCOMP or CAPABILITY DENIAL
ptrace(...)                            -> SECCOMP or CAPABILITY DENIAL
write to a protected filesystem        -> MAC or filesystem-sandbox DENIAL
```

Candidates for denial in every class: `execve`/`execveat`, `ptrace`, `mount`/`umount2`,
`bpf`, module operations, namespace operations, and socket creation where the class needs
none. The syscalls the language runtime genuinely requires are derived per class and are
not assumed.

## 12a. Kernel-API operations: the read-only claim does not survive contact

The directive's suspicion is confirmed from documentation, not argued.

### 12a.1 CAP_AUDIT_CONTROL contradicts P2-N4

REPOSITORY FACT, `capabilities(7)` as installed on this workstation:

> **CAP_AUDIT_CONTROL** (since Linux 2.6.11) — Enable and disable kernel auditing; change
> auditing filter rules; retrieve auditing status and filtering rules.
>
> **CAP_AUDIT_READ** (since Linux 3.16) — Allow reading the audit log via a multicast
> netlink socket.

One capability bundles mutation and observation. Retrieving filter rules and *changing*
them are the same capability. `CAP_AUDIT_READ` does not help: it covers the audit **log**
via multicast netlink, not the filter rules.

So a worker holding `CAP_AUDIT_CONTROL` in order to list rules simultaneously holds the
authority to enable, disable and rewrite them. It satisfies P2-N4 only by choosing to —
which is exactly the application-only boundary P2-N5 forbids.

**This contradicts D-26 directly.** D-26 grants the audit collector `CAP_AUDIT_CONTROL`
with fixed argv `auditctl -s` / `auditctl -l`. The fixed argv is an application-layer
control. It does not reduce the capability the process holds.

### 12a.2 Can any layer separate them?

| Layer | Can it distinguish LIST from ADD/DEL? | Basis |
|---|---|---|
| capabilities | **no** | one capability covers both, quoted above |
| seccomp | **no** | both travel as netlink messages through the same `sendto`/`sendmsg` on one `AF_NETLINK` socket. The discriminator is `nlmsg_type` inside a user-space buffer, and seccomp cannot dereference user-space pointers — deliberately, to avoid TOCTOU. A filter can permit or deny `sendmsg`; it cannot read the message. |
| SELinux | **possibly yes** | the netlink socket classes carry distinct `nlmsg_read` / `nlmsg_readpriv` / `nlmsg_write` permissions, and the kernel's netlink hook maps `nlmsg_type` onto them. A domain could hold read-side access to `netlink_audit_socket` while being denied `nlmsg_write`. INFERENCE from documented SELinux netlink mediation — **not measured here**, and measuring it means authoring policy on a live host, which §0 forbids. |
| AppArmor | **probably no** | netlink mediation is by family and socket type, not by `nlmsg_type`. Unverified. |
| generic Linux | **no** | no object-level mediation exists to appeal to |

### 12a.3 Ruling

```
OP_AUDIT_ACTIVE_RULES_READ_V1        DESIGN_UNRESOLVED
```

It is not admitted to strict P2. Three outcomes remain open and P2-E decides between them
**after** proof, not before:

1. **SELinux-only admission** — permitted where `nlmsg_write` can be denied and proven
   denied by a negative test. That makes the operation platform-conditional, which collides
   with the one-assurance-model invariant unless P2-N10 reports it as unavailable
   elsewhere rather than silently degraded.
2. **A separately named authority class** — `AUDIT_CONTROL_AUTHORITY`, explicitly NOT
   read-only, admitted only under owner exception and reported as such.
3. **Exclusion** — audit rule state stays unavailable through P2, and R1.5-P records it
   exactly as it does today.

No answer is invented here. The same analysis is owed to every future netlink operation
before it is admitted, netfilter included:

```
READ-ONLY APPLICATION CODE   !=   READ-ONLY KERNEL AUTHORITY
```

For each kernel-API operation, three questions are answered before design: which capability
is required; what mutation authority that capability *also* grants; and whether any layer
can independently separate observation from mutation on that interface. An operation that
cannot answer the third stays unresolved.

## 12b. First operation: a protected file read

RECOMMENDATION: `OP_ACCOUNT_SHADOW_READ_V1`, and not audit, for the reason §12a just
demonstrated — a first operation must be one whose read-only authority can actually be
proven, or the architecture cannot be validated by building it.

`CAP_DAC_READ_SEARCH` is not "permission to read `/etc/shadow`". From `capabilities(7)`:
it bypasses file read permission checks and directory read and execute checks generally,
and it permits `open_by_handle_at(2)` and `linkat(2)` with `AT_EMPTY_PATH`. It is broad
DAC bypass. Where MAC is available it must be narrowed by the domain or profile; where MAC
is not available, that narrowing does not exist and P2-N10 reports the weaker envelope.

Whether UID 0 is required at all is not assumed. A dedicated service identity in the
`shadow` group reaches `/etc/shadow` on most distributions through ordinary DAC, with no
capability at all — a materially smaller envelope than `CAP_DAC_READ_SEARCH`. That is the
first thing P2-C measures per platform, because it may remove the capability entirely.

### 12b.1 Minimization happens inside the worker

The account contract already decides what shadow evidence *is*
(`W1D_ACCOUNT_SOURCE_CONTRACT.md` §4): `password_state.lock_prefix`,
`password_state.content`, `password_state.hash_scheme`, the `*_days` integers and named
states, plus provenance. On `hash_scheme` it says: *"the algorithm is configuration; the
verifier is not stored."* The password verifier is deliberately not retained.

So the operation's response schema is **derived from an existing frozen contract** rather
than invented, and the worker returns those fields — never the file, never a hash.

This forces a real tradeoff, stated rather than settled by preference:

| | Parse inside the worker | Return raw, parse in the engine |
|---|---|---|
| Privileged code | larger — a parser runs under privilege | smaller |
| Data crossing the boundary | minimized fields only | every hash in the file |
| If the caller is compromised | it obtains the minimized evidence | it obtains the verifiers |

PROPOSAL: parse inside the worker. Under P2-N5 a parser bug is assumed and the kernel
bounds it anyway; no kernel control can un-disclose a password verifier once it has been
handed to an authorized caller. Data minimization is part of the authority contract, not a
presentation concern.

## 13. Privilege plan, and the receipt

### 13.1 Plan — before anything privileged happens

The unprivileged engine produces a plan the operator can decline:

```
PRIVILEGE PLAN
  Unavailable evidence   local shadow account metadata
  Why it matters         password and ageing state cannot be observed
  Requested operation    OP_ACCOUNT_SHADOW_READ_V1
  Authority class        ACCOUNT_SHADOW_READ_V1
  Evidence source        /etc/shadow
  Generic exec           no
  Arbitrary path         no
  Network                no
  Mutation               no
  Confinement required   MAC · syscall filter · capability bounding
```

Declining stays a first-class outcome. `no privilege granted` is never rendered as
`collection failure`, and the evidence-limits manifest records the limitation exactly as it
does today.

### 13.2 Receipt — three provenance classes, never merged

```
KERNEL_OBSERVED              what the kernel reports about the process
POLICY_ARTIFACT_IDENTITY     digests of the contract, worker and policies
HELPER_REPORTED_ACQUISITION  what the worker says it did
```

`"network_access": false` because the worker said so is not kernel evidence. The separation
is the point, and two limits are stated in the design rather than discovered later:

- `Seccomp: 2` proves a filter is loaded. It does not prove **which** filter. That is why
  the seccomp policy digest sits in `POLICY_ARTIFACT_IDENTITY`, and why the receipt never
  claims the filter's content from the mode alone.
- `"source": "/etc/shadow"` is the worker's own statement. It is useful provenance. It is
  not an independent audit of every `openat()` the process made.

## 14. Negative-security acceptance

Following Z-20: an attempt that did not execute is not a denial, and `ENOENT` is not a
policy verdict. Every negative test must establish that the target exists and that the
intended mechanism produced the refusal.

| Attempt | Expected mechanism |
|---|---|
| read a protected object outside the class | MAC denial |
| write the permitted source | filesystem sandbox / MAC denial |
| write anywhere else | filesystem sandbox / MAC denial |
| `execve("/bin/sh")` | seccomp denial |
| `execve` any other binary | seccomp denial |
| create a socket the class does not need | seccomp / `RestrictAddressFamilies` denial |
| `ptrace` | seccomp / capability denial |
| `mount` | seccomp / capability denial |
| use a capability outside the contract | bounding-set denial |
| connect to another class's endpoint | endpoint and MAC denial |
| malformed protocol frame | worker refusal, bounded, no partial authority |
| arbitrary path in a bounded-identifier field | contract refusal AND MAC denial |
| authority-union regression | class envelope comparison |

### 14.1 The harness is not part of the privileged API

There is no `--test-negative-enforcement` flag, and no test mode reachable through the
production worker. Adding one would widen the privileged interface with an argument, which
contradicts the no-arbitrary-argument design and hands an attacker a second code path
inside the boundary.

Instead: **separate, deliberately malicious worker variants**, built and shipped only as an
install/CI qualification artifact, executed under the **same confinement profiles** as the
production worker. The ordinary operator is not authorized to invoke them — they are not in
the sudoers policy and not behind the production socket.

The property being tested is the *profile*, not the binary, so running a hostile binary
under the real profile is the correct experiment and a flag on the real binary is not.

Outcome vocabulary mirrors Z-20: `ATTEMPT_EXECUTED_AND_DENIED`,
`ATTEMPT_EXECUTED_BUT_ALLOWED`, `ATTEMPT_NOT_EXECUTED`, `HARNESS_ERROR`. Only the first is
a pass; the third is not a pass and never becomes one by retrying.

## 15. Snapshot integration

D-115 semantics are preserved exactly:

```
state_hash            host-state identity
coverage_digest       observation-capability identity
manifest auxiliary    bundle integrity
```

Privilege contract and receipt data are **acquisition-authority evidence**. They are bound
through `manifest_core` as auxiliary artifacts, following the D-115 pattern, and they do
**not** enter `state_hash`. Two runs of an unchanged host under different authority must not
produce a host-state delta.

This adds a third axis to the comparison vocabulary, alongside the two already frozen:

```
HOST STATE DELTA  !=  OBSERVATION VISIBILITY DELTA  !=  ACQUISITION AUTHORITY DELTA
```

## 16. Administrator independent verification

`isedraf privilege-plan` and `isedraf trust show` are proposed as operator interfaces. They
are interpretation, not proof, and the design requires each reported property to carry the
native command that checks it without trusting ISEDRAF — filtered to the detected platform,
because printing `sesearch` on a Debian host is noise that erodes the habit of checking.

| Reported property | Native check |
|---|---|
| unit settings | `systemctl cat` · `systemctl show` |
| running confinement | `/proc/<pid>/status` (`NoNewPrivs`, `Seccomp`, `Cap*`) |
| MAC context | `/proc/<pid>/attr/current` · `ps -eZ` |
| SELinux policy | `sesearch` · `semodule -l` |
| AppArmor profile | `aa-status` |
| worker identity | `sha256sum` on the package-owned binary |
| granted authority | `sudo -l` |

The product statement: ISEDRAF gives its interpretation, then gives the native evidence
needed to check that interpretation without trusting ISEDRAF.

## 17. Portability model

Portability is a first-class requirement, not a later optimization. The split:

```
        ISEDRAF APPLICATION / KNOWLEDGE LAYER        (existing, Python)
        inventory · S3 · snapshots · evidence
        criteria · reporting
                        |
        ============ stable protocol boundary ============
                        |
        ISEDRAF SYSTEMS SECURITY CORE                (language pending P2-B)
        privileged acquisition · kernel interfaces
        IPC · bounded file acquisition · netlink
                        |
        +---------------+----------------+
        |               |                |
   FULL SERVER     GENERIC LINUX    CONSTRAINED / IoT
   systemd         capabilities     procd · OpenWrt
   SELinux / AA    seccomp          Yocto · Buildroot
   sudo            namespaces       generic init
   deb / rpm
```

`OP_ACCOUNT_SHADOW_READ_V1` means the same thing on every row. What changes is the
enforcement backend and the assurance obtained, and the second of those is reported.

### 17.1 What "IoT" means here

Linux-capable IoT and edge systems on supported CPU architectures: SBCs, ARM gateways,
OpenWrt-class routers, Yocto and Buildroot appliances, industrial Linux controllers. A
Cortex-M microcontroller running an RTOS is a different product architecture and is
explicitly **out of scope** — claiming it would be the kind of support claim this
repository's gates exist to reject.

### 17.2 Backend matrix

| Platform | Init | Confinement backend | P2-N5 satisfied by |
|---|---|---|---|
| RHEL / Alma / Rocky / Fedora | systemd | SELinux + seccomp + capabilities | MAC type enforcement |
| Ubuntu / Debian | systemd | AppArmor + seccomp + capabilities | MAC profile |
| Generic Linux, no MAC | any | dedicated UID + seccomp + capabilities + namespaces | **partially** — see below |
| OpenWrt | procd | seccomp + capabilities + available MAC facilities | platform-dependent |
| Yocto / Buildroot | varies | derived per image | derived per image |
| Container | varies | reported as observed; no host-scope claim | host policy, not ours |

### 17.3 The tension this creates, stated rather than hidden

P2-N5 asks the kernel to bound object access independently of the application. On a
platform with no MAC system there is no independent object-access enforcement: capabilities,
seccomp, namespaces and a dedicated UID bound *what kind of thing* the process can do and do
not bound *which protected object* it reaches with the DAC authority it holds.

So on a MAC-less platform P2-N5 is approximated, not met. Two honest responses, and this
document does not pick one because it is a product decision:

1. run the operation and report the weaker confinement through P2-N10, or
2. refuse operations whose envelope depends on MAC for its bound, and record the evidence
   as unavailable exactly as R1.5-P already does.

OPEN DECISION, recorded as owner decision 9 in §22. Silently doing (1) while describing it as though it were
the MAC-enforcing case is the outcome P2-N10 exists to prevent.

## 18. Target build matrix

Qualification targets, in tiers. Tiers describe how much evidence exists, not preference.

```
Tier 1   x86_64-unknown-linux-gnu
         aarch64-unknown-linux-gnu

Tier 2   x86_64-unknown-linux-musl
         aarch64-unknown-linux-musl

Tier 3   armv7-unknown-linux-musleabihf

Future   riscv64gc-unknown-linux-gnu
         riscv64gc-unknown-linux-musl
```

The musl targets matter because they reduce dependence on one distro userspace, which is
what appliance and embedded images actually look like. They are to be **measured**, not
assumed: fully static linking interacts awkwardly with NSS, PAM, SELinux userspace
libraries and DNS resolution, and a build that links statically is not automatically a
build that behaves identically. The rule from §17 applies to libc as well:

```
portable core        MUST NOT depend on libc choice
packaging / backend  MAY
```

Per `CURRENT_STATE.md`, aarch64 and armhf are today recorded as **not tested** — zero
campaigns have run. This matrix is a plan for evidence that does not yet exist, and nothing
in it may be reported as support until a campaign produces it.

## 19. Constrained-Linux qualification

Footprint becomes a qualification property rather than a later optimization. The
methodology is defined now; **the numbers are not invented now**, because an acceptance
limit chosen before a measurement is a preference wearing a limit's clothing.

Measured per target, on representative hardware:

```
stripped binary size          thread count
idle RSS                      open FD count
peak RSS during acquisition   syscall inventory (observed, not declared)
startup latency               seccomp allowlist size
cold acquisition latency      dynamic dependencies
                              build reproducibility
```

Constrained profile properties, which are structural rather than numeric:

```
no resident database        no mandatory container runtime
no JVM                      no mandatory systemd
no resident privileged process
```

"No interpreter requirement" is listed in the directive and is **not** achievable for the
full product as it stands, because the evidence engine is Python. That is §20's first open
question, not something to quietly drop.

## 20. Product invariant

```
ONE EVIDENCE MODEL · ONE OPERATION CONTRACT
ONE SNAPSHOT MODEL · ONE ASSURANCE MODEL
```

across full and constrained Linux. Packaging may differ — an `isedraf-full` and an
`isedraf-edge` are reasonable — but they consume the same schemas and contracts. No forked
edge semantics, because an edge node that produces a different interpretation language
cannot be analysed alongside a server, and fleet analysis later is the whole reason the
schemas are frozen now.

Feature degradation runs through machinery that already exists and is already frozen:
`COLLECTED · PARTIAL · NOT_TESTED · ERROR` plus the Evidence Limits Manifest. A small
device with fewer services does not mean a broken ISEDRAF; it means a smaller applicable
evidence universe, measured and stated.

## 20a. Residual risk register

Risks that remain after everything above is built as designed. They are listed because a
design that names no residuals has not been examined.

| # | Residual | Why it remains |
|---|---|---|
| R1 | **Confidentiality of returned evidence** | Denying `AF_INET`/`AF_INET6` to the worker does not protect what the worker legitimately returns. The operation exists to hand bounded protected evidence to the unprivileged engine; a compromised engine discloses exactly what the operation returns. Network isolation of the worker is not a confidentiality control for the result. The mitigations are §12b.1's minimization, bounded responses, and never returning raw protected payload — not the socket policy. |
| R2 | **Digest pin race** | The digest is computed and the file is then executed; an adversary able to swap the file between those points defeats the pin. Such an adversary usually already holds root-equivalent write access to a package-owned path. |
| R3 | **Seccomp filter identity** | `Seccomp: 2` shows a filter is active and not which one. The policy digest narrows this and does not close it: the digest identifies the artifact shipped, not the bytes the kernel loaded. |
| R4 | **Helper-reported facts** | `"source": "/etc/shadow"` is the worker's statement, not an audit of every `openat()` it made. |
| R5 | **MAC-less platforms** | Capabilities and seccomp bound the kind of operation, not which protected object is reached with the DAC authority held. If owner decision 9 admits such operations, P2-N5 is approximated there and P2-N10 reports it; if it refuses them, the residual becomes evidence that is unavailable on those platforms. |
| R6 | **Policy drift on upgrade** | Unit, MAC policy and worker move together or the envelope is not what the receipt claims. Detected by comparing policy identities, which is a detection, not a prevention. |
| R7 | **Compromised renderer** | A report renderer that lies about a receipt is outside the kernel boundary entirely. The mitigation is §16 — the operator can check the native sources without ISEDRAF. |

## 21. Roadmap position and stages

**This lane does not change current engineering.** Batch 3 continues unprivileged, on the
R1.5-P semantics, exactly as it does today. P2 changes how *future* protected evidence
would be acquired; it does not invalidate mounts, S3, R1.5-P, the inventory collectors,
snapshots or any current evidence architecture.

```
CURRENT MAINLINE                        PARALLEL DESIGN LANE
-------------------------------         ------------------------------
D-83 governance reconciliation          P2-A  architecture + threat model
        |                                       |
mounts closure (af41b67)                owner freeze
        |                                       |
NSS / hostname          <---- unprivileged, no change from this lane
        |
Batch 3 closed
        |
Batch 4
        |
R1.5 inventory stabilized
        |
        +-------------------> P2-B  language qualification (Rust / Go / C baseline)
                                      |
                              P2-C  first protected-file operation
                                      |
                              P2-D  confinement backends
                                      |
                              P2-E  kernel-API operations (§12a)
                                      |
                              P2-F  privilege plan, receipt, D-115 auxiliary
                                      |
                              P2-G  adversarial + cross-architecture qualification
                                      |
                              P2-H  production freeze
                                      |
                              R2 may consume protected evidence
```

| Stage | Purpose | Implementation permitted |
|---|---|---|
| **P2-A** | threat model, authority model, portability requirements, invariants, trust claims | **documents only — this document** |
| P2-B | language qualification on amd64, arm64, constrained ARM | disposable prototypes only, never merged |
| P2-C | one protected file-read operation (§12b) | yes |
| P2-D | SELinux, AppArmor, generic Linux, systemd / procd / init integration | yes |
| P2-E | audit / netlink / netfilter research (§12a) | only after proof |
| P2-F | operator UX, auxiliary evidence, D-115 integration | yes |
| P2-G | OS-denial campaign, cross-architecture and packaging tests | required |
| P2-H | freeze supported operation classes and backends | release gate |

The sequencing rule, and the reason for it: **do not start with audit or netfilter.** Start
with a protected file read whose read-only authority can actually be proven. §12a shows
what happens otherwise — ten privileged operations built, then the discovery that the
authority model cannot demonstrate read-only behaviour for any of them.

When a language enters the repository: after inventory stabilization, in P2-B, from
measurements. Not before, and no rewrite of the existing engine in any case.

## 22. Owner decisions required

Only decisions that genuinely need a person. Anything measurable was left to P2-B or P2-C
rather than sent upward.

**Governance — these block P2-A freeze:**

| # | Decision | IQ |
|---|---|---|
| 1 | Permit ONE package-owned compiled privileged worker, or accept an interpreted worker with its stated weakness, or neither | IQ-024 |
| 2 | Reconcile D-26's `CAP_AUDIT_CONTROL` + `auditctl` grant with §12a, which shows it cannot demonstrate read-only authority | IQ-025 |
| 3 | Reconcile D-27's caller-constructed transient units with packaged per-class units and P2-N8 | IQ-026 |
| 4 | Rule on socket activation against the "daemons" prohibition, and on digest-pinned sudo against "internal sudo, password prompts" | IQ-027 |

**Architecture — these shape the design, and no evidence decides them:**

| # | Decision |
|---|---|
| 5 | Per-authority-class endpoints as the selected architecture (§6) |
| 6 | Operations that cannot demonstrate read-only kernel authority: excluded from strict P2, or admitted under a separately named authority class that is not claimed read-only (§12a.3) |
| 7 | Whether a constrained node runs the evidence engine, or acquires only and ships evidence for central interpretation (§23) |
| 8 | Which constrained ARM platform becomes the first reference target |
| 9 | On a platform with no MAC system, run MAC-dependent operations and report the weaker confinement through P2-N10, or refuse them and record the evidence as unavailable with `REQUIRED_CONFINEMENT_NOT_AVAILABLE` (§17.3). PROPOSAL: refuse, because running them makes P2-N5 hold only on some platforms |

**Deliberately not asked of the owner**, because measurement decides them: the
implementation language (P2-B); whether the first operation needs a capability at all or
reaches `/etc/shadow` through group membership (P2-C); the constrained-profile numeric
budgets (§19); whether SELinux can separate `nlmsg_readpriv` from `nlmsg_write` (P2-E).

## 23. Open questions

**Does a constrained node run the evidence engine at all?** The constrained profile in §19
lists "no interpreter requirement", and the engine is Python. Three shapes exist, and they
are materially different products:

1. the edge node runs the full engine, so Python is a hard requirement on every node;
2. the edge node runs only the compiled acquisition worker and ships evidence to a server that
   interprets it — no interpreter on the node, and a transport that does not exist yet and
   would cross the network-egress prohibition in `CLAUDE.md` §2;
3. the edge node runs a reduced engine, which is the forked edge semantics §20 forbids.

None is chosen here. This is the largest unresolved question in the portability direction,
and it is a product decision rather than an architecture detail. Recorded as owner decision 7.

**Other open questions:**

- Which operations exist at all in P2's first set. This document designs the envelope
  machinery and deliberately does not enumerate operations, because the operation list is a
  scope decision and enumerating it here would smuggle scope in as design.
- Whether the D-26 launcher topology survives under a per-class endpoint model or is
  superseded by it. The two solve the same problem differently and the register cannot keep
  both.
- How policy versioning interacts with package upgrade when a unit, a MAC policy and a
  worker binary must move together.
- Whether `armv7` remains Tier 3 or is dropped, once a measurement campaign exists. No
  architecture beyond x86_64 has been measured at all.
