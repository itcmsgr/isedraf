<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Architecture alignment — internal onboarding

Status: EXPERIMENTAL
Implements: D-87, D-88

An internal orientation for an engineer joining the project. It explains the frozen
architecture in plain words; it does not replace it. Where this page and a frozen document
disagree, the frozen document wins and this page is the defect.

Two labels mark what is not yet frozen or not yet code:

- **decided 2026-09-27, amendment pending** — the owner has decided it, but the frozen
  documents do not say it yet. Until the amendment lands, the frozen text is what binds.
- **not built yet** — no code on `main` does this today.

## The 60-second explanation

ISEDRAF is a command you run on a Linux host when you want evidence about that host. It
reads what the host exposes locally, records where each fact came from and whether it could
be collected at all, and commits the result as a hashed snapshot recorded in a local,
hash-chained ledger. It has no daemon, no database, no network connection and nothing to configure
remotely. It is built not to change the host it inspects.

Its principle is to measure the host honestly, preserve the evidence, and never claim more
certainty than the evidence supports. A fact it could not observe is reported as not
observed, never as absent. Collecting a fact and judging it are separate steps.

Today it runs only as an unprivileged development tool. The first general release (GA v0.1)
adds an unprivileged production mode and one `audit` command that collects, commits and
renders a report from what it committed. A privileged Full Audit, comparison against a
baseline, findings and framework mappings come later.

## 1. What ISEDRAF is

An on-demand, local evidence engine for one Linux host. It collects normalized host state,
keeps it as evidence an auditor can inspect without ISEDRAF, and — later — compares it with
a baseline an administrator has explicitly accepted.

It is not a firewall, an endpoint agent, a log collector, a vulnerability scanner or a
compliance engine. It does not assess network or cloud controls, match CVEs or check patch
availability. When a product outside the host would provide a control, the absence of that
product on the host is reported as absence of local evidence, never as absence of the
control.

The project's philosophy is *Measure once. Map everywhere. Fix only the delta.* ISEDRAF
does the measuring. Mapping to external frameworks is a later view over the same evidence.
Fixing is the operator's job: ISEDRAF never applies a change.

## 2. Core invariants

Every design choice in the repository serves these. Read them as "is never treated as".

```text
collection                     ≠  evaluation
incomplete evidence            ≠  "nothing found", ≠ PASS
file state                     ≠  effective system state
tool or collection-method change  ≠  host-state change
an accepted baseline           ≠  a host certified as secure
no observed delta              ≠  an uncompromised host
```

**Collection is not evaluation.** A collector records what it saw and whether it could see
it. It never says PASS or FAIL. Judgement happens later, in a separate, regenerable step.

**Incomplete stays visibly incomplete.** A source that was only partly read is `PARTIAL`;
one that could not be read is `NOT_TESTED`; a property the evidence cannot decide is
`NOT_ASSERTED`. None of these ever becomes "nothing found" or PASS.

**File state is not effective state.** ISEDRAF can read `/etc/passwd` completely and
correctly, and that read stays `COLLECTED`. Whether the system actually resolves accounts
from that file depends on NSS configuration (`passwd: files` versus, say, `passwd: sss`).
That is a second, separate fact. When files are not an effective source, the report says
"N local account records collected; /etc/passwd is not configured as an effective NSS
source" — never "users on this host".

**A tool change is not a host change.** A new ISEDRAF version or a different collection
method on an unchanged host must not look like drift. Method and provenance are recorded
outside the host-state hash for exactly this reason.

**A baseline is accepted, not certified.** An administrator can accept a complete but bad
state. Acceptance records a decision; it says nothing about security.

**No delta is not a clean bill of health.** ISEDRAF observes userspace and kernel-exposed
state. A root adversary can alter the sources, the logs and ISEDRAF itself.

## 3. Install footprint

```text
/usr/bin/isedraf          entry point, root-owned
/usr/lib/isedraf/         Python package, root-owned, no .pyc
```

- Delivered as DEB and RPM packages built from one install manifest.
- Runs on the host's own system Python, standard library only. ISEDRAF never installs,
  bundles or pins an interpreter.
- No bundled runtime, no database, no daemon, no network service, no telemetry.
- Package scripts create only ISEDRAF-owned directories. They never touch SSH, PAM, audit,
  sysctl, users, services or MAC policy.
- **Uninstall never deletes evidence.**
- GA v0.1 does **not** create an `isedraf` system account.

## 4. Execution modes and artifact classes

There are three artifact classes. Every artifact records which one produced it, and the
three must never be confusable.

```text
class              who runs it          where evidence lives               status
-----------------  -------------------  ---------------------------------  ----------------------
DEV                unprivileged user    $ISEDRAF_STATE_ROOT (any abs path) exists today (frozen)
USER_PRODUCTION    unprivileged user    $XDG_STATE_HOME/isedraf or         GA v0.1; decided
                                        ~/.local/state/isedraf             2026-09-27, amendment
                                                                           pending; not built yet
SYSTEM_PRODUCTION  root, via sudo       /var/lib/isedraf (root, 0700)      later Full Audit
                                                                           release; not built yet
```

**DEV — what exists today.** Every command needs `ISEDRAF_STATE_ROOT` set to an absolute
path. The variable is honoured only when the process is not root and `SUDO_USER` is unset.
Every artifact is marked `DEV` and can never be approved as a baseline or mistaken for
production evidence. Running as root or through sudo is refused with exit 70. There is no
production mode, and no default state root.

**USER_PRODUCTION — what GA v0.1 adds** (D-116, 2026-09-27; built). An unprivileged run as the invoking user, with no environment variable needed:

- Evidence goes to `$XDG_STATE_HOME/isedraf`, or `~/.local/state/isedraf` when that is unset.
- Facts that need root (for example `/etc/shadow` or sudoers) are `NOT_TESTED` with a reason.
- The report header states `PRIVILEGE LEVEL: UNPRIVILEGED`.
- The storage must be on a suitable local filesystem. If it is not, the production commit
  is refused. It fails closed; it never falls back to somewhere else.

The frozen schema currently spells the marker `DEV` or `PRODUCTION`. How the two production
classes are recorded is part of the pending amendment.

**SYSTEM_PRODUCTION** belongs to the later Full Audit release, described next.

## 5. The later Full Audit release

Decided as the future design (D-118); not built yet. It is the privileged path.

```text
operator runs:  sudo isedraf audit       (sudo is outside ISEDRAF; a sudoers
      │                                   example ships as documentation only)
      ▼
transient systemd sandbox, one unit per run
      │
      ▼
ROOT SUPERVISOR  — small, holds no analysis code
  ├── take the whole-run lock
  ├── preflight: state root, install-path safety
  ├── record the tool-integrity level that applies
  ├── PRE privileged collectors      (fixed program, fixed arguments)
  ├── start ENGINE ─────────────────────────────┐
  │                                             ▼
  │                  ENGINE as the non-login `isedraf` user
  │                    minimum validated privilege set
  │                    can never regain root
  │                    collect · normalize · hash
  │                    writes only /var/lib/isedraf/tmp/<run_id>/
  │                                             │ exits
  ├── POST privileged collectors  ◄─────────────┘
  ├── validate the staged run
  ├── promote atomically into root-owned evidence; append the ledger
  └── release the lock
```

The property this buys:

> The component that analyses evidence cannot rewrite committed evidence, and the
> component that has root does not contain the analysis engine.

Details that matter when you read or write code for it:

- The tool-integrity record is a trust level (local manifest, package manager, or an
  external signature). It never proves the host or ISEDRAF is uncompromised.
- The engine runs with the minimum privilege set the platform corpus validates. Do not
  describe it as having "no capabilities"; the exact set is not frozen until the corpus
  proves it.
- Supervisor and engine talk only through run-private, bounded pipes or inherited file
  descriptors, or through ISEDRAF-owned run artifacts. No socket, no daemon, no internal
  sudo, no password prompt, and no way to reacquire privilege.
- If the privilege model cannot hold on a platform, that work stops and is recorded. It is
  never made to pass by widening privilege.

## 6. Evidence and outputs

**Canonical artifacts are authoritative.** Canonical JSON and per-entity JSON Lines are the
evidence. Console, HTML and CSV output are renderers of those artifacts and nothing more.

**Commit order.** A snapshot becomes evidence in this order, under the whole-run lock:

```text
private temp dir → collect sections → hashes → manifest → fsync
      → atomic rename into snapshots/ → ledger append + fsync
```

The ledger append is the only commit boundary. A snapshot directory the ledger does not
record is `ORPHANED`, not evidence. ISEDRAF treats a committed snapshot as never to be
rewritten; that is not protection against a local root adversary.

**Three identities, never conflated.**

```text
state_hash                    what the host state is
coverage_digest               what ISEDRAF was able to observe
auxiliary artifact binding    that the bundle's supporting files belong to it
```

A coverage or provenance change can change the bundle's integrity binding without implying
any change in host state.

**Reports in GA v0.1** (D-115, D-117; built). `isedraf
audit` places each report section inside the snapshot bundle as a bound auxiliary artifact.
A report renders exactly one committed run - the last one the ledger records - and never
collects.

**Privacy.** Raw machine-id and hardware serials never appear in canonical or exported data;
only protected derivatives do. `host_id` is pseudonymous, not anonymous. Untrusted host text
(file contents, names, comments) is never echoed into diagnostics (owner ruling
2026-09-26), and every byte written to a console is escaped for control characters first.

## 7. Where we are and the path to GA

**Built today:** the certified evidence contract; `isedraf identity` (snapshot, ledger,
verification); `isedraf inventory`; `isedraf report`; nine further collectors (accounts,
NSS topology, hostname, sudo, SSH, PAM, authorized_keys, login policy, mounts) that no
command reaches yet. All of it runs as DEV only.

**GA release track** (owner directive, 2026-09-27), in order:

```text
1  CLI / command surface audit      install, run, collect, output, clear errors,
                                    no built module left unreachable
2  install / package audit
3  end-to-end factual audit run
4  first report                     factual JSON + readable HTML, coverage, limitations;
                                    no comparison engine or findings required
5  P0/P1 operational defects
6  supported-platform smoke tests
7  public documentation cleanup     the DOC-PUBLIC-01 gate
8  GA candidate                     publication stays a separate owner act
```

Step 1 is recorded in the GA CLI audit. It found that no production mode exists, that the
nine collectors are unreachable, and that `report` collects; the `audit` command and
USER_PRODUCTION answer those.

**What GA means.** ISEDRAF's principal failure is not a crash; it is evidence that claims
more certainty than the collection supports. GA is judged against six priorities:

| # | Priority | GA blocker if |
|---|---|---|
| 1 | Install and upgrade integrity | DEB or RPM install fails; an upgrade loses evidence or state; an upgrade on an unchanged host reports a security change; uninstall deletes the evidence under `/var/lib/isedraf` (it never may) |
| 2 | CLI truth | a command does not exist or does not do what it says; an exit code disagrees with the frozen contract; an error is silent or gives the operator nothing to act on |
| 3 | Do no harm | ISEDRAF changes the host it inspects, or makes a network connection |
| 4 | Run and snapshot lifecycle | the run lock fails; a snapshot is committed non-atomically; an interrupted run leaves evidence that looks valid; orphaned runs are not handled deterministically |
| 5 | Evidence truthfulness | a source is reported `COLLECTED` without complete evidence; something is reported absent that was not fully observed; a result passes without the evidence for it |
| 6 | Supported production paths | the supported distributions, unprivileged and privileged runs, or a human-readable first report do not work |

The table is copied from the roadmap. GA v0.1 is unprivileged only; privileged runs belong to
the later Full Audit release (D-117).

**Privacy is a blocker in every priority.** A secret, a password hash or other raw
sensitive material reaching output stops GA, however rare the input that causes it. GA
does not mean zero bugs; it means none of the above is known.

**For every new issue, first ask: does this stop GA? Yes or no.** Yes, when it breaks
install, run or report, gives wrong exit semantics, mutates the host or reaches the
network, corrupts a snapshot or the ledger, produces false confident evidence, crashes or
hangs on a supported path, or leaks sensitive material. No, when it can be contained as an
explicit `PARTIAL`, `NOT_TESTED` or `NOT_ASSERTED` without misleading the operator. A "no"
is registered and work continues; a "yes" gets the smallest correction that restores the
property.

```text
DISCOVER -> CLASSIFY -> CONTAIN (if needed) -> REGISTER
```

**Explicitly after GA v0.1:** comparison and delta against an accepted baseline;
findings and interpretation; framework mappings; the privileged Full Audit.

## Normative references

This page explains; these bind. Owner decisions marked "amendment pending" have no frozen
reference yet.

| Section | Frozen source | Requirement and decision IDs |
|---|---|---|
| 60-second explanation, 1 | `docs/architecture/ISEDRAF_HLD.md` §1–3 | HLD-001, HLD-003, HLD-010…HLD-015, D-03, D-04, D-07…D-09 |
| 2 Core invariants | `ISEDRAF_HLD.md` §5; `EVIDENCE_AND_TRUST_MODEL.md` §11; `SNAPSHOT_BASELINE_DELTA_MODEL.md` | HLD-031, CMP-001, CMP-002, EVID-001, EVID-040, SCOPE-045, D-13, D-35, D-43; IQ-037 (owner ruling 2026-09-27) |
| 3 Install footprint | `EVIDENCE_AND_TRUST_MODEL.md` §5; `DECISIONS_REGISTER.md` §11 | EXEC-010, EXEC-016, HLD-015, D-17, D-59, D-60, D-61 |
| 4 Execution modes | `EVIDENCE_AND_TRUST_MODEL.md` §2; `V0_1_IMPLEMENTATION_SCOPE.md` | PRIV-001, PRIV-004, SCOPE-070, SCOPE-071, SCOPE-077, STORE-001, D-22, D-70; USER_PRODUCTION: amendment pending |
| 5 Full Audit | `EVIDENCE_AND_TRUST_MODEL.md` §2, §4, §6 | PRIV-002, PRIV-003, PRIV-005, PRIV-007…PRIV-012, EXEC-001, EXEC-004, EXEC-020, INTEG-002, SCOPE-072, D-23, D-24, D-26, D-27, OD-06; dedicated engine user and staging-then-promote: amendment pending |
| 6 Evidence and outputs | `ISEDRAF_HLD.md` §9; `SNAPSHOT_BASELINE_DELTA_MODEL.md`; `EVIDENCE_AND_TRUST_MODEL.md` §7 | OUT-010, OUT-013, SNAP-010, SNAP-014, SNAP-015, SNAP-018, EVID-013, EVID-014, D-38, D-50, D-55, D-115; report sections as auxiliary artifacts: amendment pending |
| 7 GA path | `docs/roadmap/ROADMAP.md` (GA release track); `docs/development/GA_CLI_AUDIT.md` | SCOPE-072, SCOPE-077 |
