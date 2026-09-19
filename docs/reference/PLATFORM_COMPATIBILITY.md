<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Platform Compatibility

Status: EXPERIMENTAL · Canonical record of where ISEDRAF has actually been tested.

## The rule this page exists to enforce

**No row is filled in from expectation.** A support tier is a claim about a tested
OS/version/architecture combination, and "it should work" is not a tier. Everything below is
`NOT_TESTED` until a campaign record exists for it.

## Support tiers

| Tier | Means |
|---|---|
| `CERTIFIED` | that exact OS, version and architecture passed the complete campaign |
| `CONDITIONALLY_SUPPORTED` | works, with a documented prerequisite — typically installing a Python ≥ 3.9 the distribution ships but does not default to |
| `COMPATIBLE_BUT_NOT_CERTIFIED` | identity end-to-end passed; the full campaign did not run |
| `UNSUPPORTED` | a known runtime or architectural incompatibility prevents correct operation |
| `NOT_TESTED` | no claim, in either direction |

## The Python floor decides more tiers than anything else

The contract is **Python ≥ 3.9, standard library only** (`D-12`), and it is not lowered per
distribution. What varies is how a distribution reaches it:

| Situation | Tier ceiling |
|---|---|
| default `python3` is ≥ 3.9 | `CERTIFIED` possible |
| default is older, a suitable interpreter is packaged | `CONDITIONALLY_SUPPORTED` — an installation prerequisite, not a code change |
| no suitable interpreter available | `UNSUPPORTED` |

This is why `scripts/compat/probe.py` is **written for Python 3.6**, unlike everything else in the
repository: RHEL 8's default `python3` is 3.6, and a probe that cannot run there cannot report the one
fact that decides RHEL 8's tier.

## Primary matrix — enterprise families

Tiers below are measured, not expected. `COMPAT` abbreviates `COMPATIBLE_BUT_NOT_CERTIFIED`;
`COND` abbreviates `CONDITIONALLY_SUPPORTED`.

| Distribution | Version | Arch | python3 found | Tier | Campaign | Notes |
|---|---|---|---|---|---|---|
| RHEL | 8 · 9 · 10 | x86_64 | — | `NOT_TESTED` | — | `IMAGE_UNAVAILABLE`, subscription required |
| AlmaLinux | 8.10 | x86_64 | **none shipped** → 3.11.13 | `COND` | 2026-09-18 | needs `dnf install python3.11`; passed fully with it |
| AlmaLinux | 9.7 | x86_64 | 3.9.25 | `COMPAT` | 2026-09-18 | |
| AlmaLinux | 10 | x86_64 | — | `NOT_TESTED` | — | lab OVMF fault, UEFI-only image |
| Rocky Linux | 9.7 | x86_64 | 3.9.23 | `COMPAT` | 2026-09-18 | |
| Rocky Linux | 8 · 10 | x86_64 | — | `NOT_TESTED` | — | 8 unavailable; 10 blocked by lab OVMF |
| Oracle Linux | 8 · 9 · 10 | x86_64 | — | `NOT_TESTED` | — | `IMAGE_UNAVAILABLE` |
| Debian | 11 | x86_64 | 3.9.2 | `COMPAT` | 2026-09-18 | LEGACY — outside Debian LTS since 2026-08-31 |
| Debian | 12 | x86_64 | 3.11.2 | `COMPAT` | 2026-09-18 | |
| Debian | 13 | x86_64 | 3.13.5 | `COMPAT` | 2026-09-18 | |
| Ubuntu | 20.04 | x86_64 | — | `NOT_TESTED` | — | `IMAGE_UNAVAILABLE`; ESM/Pro only |
| Ubuntu | 22.04.5 | x86_64 | 3.10.12 | `COMPAT` | 2026-09-18 | |
| Ubuntu | 24.04.4 | x86_64 | 3.12.3 | `COMPAT` | 2026-09-18 | |
| Ubuntu | 26.04 | x86_64 | 3.14.4 | `COMPAT` | 2026-09-18 | |

## Secondary matrix

| Distribution | python3 found | Tier | Campaign | Notes |
|---|---|---|---|---|
| CentOS Stream 9 | 3.9.25 | `COMPAT` | 2026-09-18 | |
| CentOS Stream 10 | — | `NOT_TESTED` | — | lab OVMF fault, UEFI-only image |
| openSUSE Leap 15.6 | **3.6.15 only** | `UNSUPPORTED` | 2026-09-18 | below the floor; no ≥ 3.9 package reachable from the Minimal-VM image's repositories |
| SLES 15 · 16 · Amazon Linux 2023 · Fedora | — | `NOT_TESTED` | — | `IMAGE_UNAVAILABLE` |
| Alpine current | — | `NOT_TESTED` | — | musl and non-systemd; structurally furthest from the prototype's assumptions. Exploration, and it will not be promoted because one command happened to run |
| Arch current | — | `NOT_TESTED` | — | `IMAGE_UNAVAILABLE` |

## Architecture

| Architecture | Target class | Status | Notes |
|---|---|---|---|
| `x86_64` / `amd64` | **PRIMARY** | ten distributions measured | every result on this page |
| `aarch64` / `arm64` | **PRIMARY, second architecture** | **`NOT_TESTED`** | no campaign has run; reference targets are Raspberry Pi OS 64-bit **and** Debian 13 arm64 |
| `armhf` / ARMv7 32-bit | best effort | `NOT_TESTED` | no certification commitment; absence is a decision, not a gap |
| `armel`, older ARM | **OUT_OF_SCOPE** | — | high testing cost, negligible strategic value |

**Architectures are recorded separately and never inferred from each other.** Every row in the matrices
above is `x86_64`, and none of them says anything about ARM64.

The production package is Python standard library only, with no compiled component, no native extension
and no architecture-specific code; its collectors read `/proc`, `/sys` and standard Linux interfaces.
That makes ARM64 a low-risk expectation. It does not make it a result, and this page records results.

Two ARM64 targets are specified rather than one, so that "ARM support" cannot quietly come to mean
"Raspberry Pi support". The differences worth anticipating are ones the inventory model already handles
as `PARTIAL`: `/proc/cpuinfo` has a different layout on ARM, Raspberry Pi exposes no DMI at all, and
block-device naming differs.

## How a row gets filled

```bash
# read-only fingerprint — safe on any host, as any user, writes nothing, spawns nothing
python3 scripts/compat/probe.py

# full campaign on a disposable lab VM
scripts/compat/campaign.sh --profile lab --runs 10 --out record.json

# real fleet host: read-only with respect to the host, unprivileged account required
scripts/compat/campaign.sh --profile fleet --runs 10 --out record.json
```

A `PASS` requires **all** of: the independent verifier accepting every artifact; one identity across all
runs; one ledger record per run; a single exit code across runs; and, in `lab`, every frozen negative case
reaching its expected status and reason.

### Root cannot validate the identity slice

`SCOPE-071` makes W1 refuse privileged execution, so `isedraf identity` exits `70` under root or sudo —
on every host, by design. A root login can run the **probe**; it cannot certify a platform. Fleet
validation needs an unprivileged account.

## Host classification — read this before running anything

**A host's class decides what may be run on it, and no campaign profile may be chosen without checking
it first.** This is the safety boundary.

| Class | What may run |
|---|---|
| **LAB HYPERVISOR** | anything; the disposable guests are created and destroyed here |
| **NOT LIVE** — disposable lab VM | full campaign, `--profile lab`, negative cases, reboot, install and removal |
| **LIVE — production** | read-only only: `--profile probe`, or `--profile fleet` under an unprivileged account |

On a `LIVE` host: no configuration change, no machine-id mutation, no failure injection, no package
operation, no reboot, no stress test, no baseline approval, no remediation. The `lab` profile is
**forbidden** there — it exists to break things, which is why it belongs only on hosts that are meant to
be broken.

**If a host is not classified, it has no class, and nothing runs on it.** Absence is not permission.

**The classification of specific hosts is deliberately not in this repository.** It names a lab
hypervisor and production hostnames, and a public repository is not the place to publish the topology of
a live estate. It lives under `planning/`, which is gitignored. A reader outside this project needs the
rules above; they do not need our addresses.

## Lab and fleet evidence are not interchangeable

| | Answers |
|---|---|
| **Hyper-V lab** | "is this reproducibly correct on a known, clean OS?" |
| **Real fleet** | "does the same code behave on a real server with real history and configuration?" |

A production server passing a read-only run does not replace a controlled certification VM, and a lab VM
passing does not prove every production configuration. Both are required, and their records are reported
separately.

## Fleet validation is read-only

First fleet phase: no host configuration change, no machine-id mutation, no failure injection, no package
removal, no reboot, no stress test, no baseline approval, no remediation. These are operational systems,
not corpus fixtures. Destructive and negative testing belongs on disposable lab VMs, and even there the
negative cases run against **fixture files**, never the host's real `/etc/machine-id`.

## What a campaign record contains, and what it must never contain

Records carry the platform fingerprint, interpreter facts, run outcomes, verifier result and limitations.

They never carry the raw machine-id, and never a `host_id`: the compatibility record reports identity
**stability** (`identity_stable`) and **presence** (`identity_present`), because a portability report has
no business exporting a host identifier off the host it was measured on.

## Current results — lab campaign 2026-09-18

Raw records: `docs/compatibility/records/`. Every row below comes from one, and no row was written by
hand.

| VM | OS | kernel | arch | python | tier | status | runs/ledger | states | verifier | negative |
|---|---|---|---|---|---|---|---|---|---|---|
| `a8` | - | `-` | - | - | `UNSUPPORTED — interpreter` | **NO_PYTHON3** | —/— | — | — | 0/0 |
| `a8p` | AlmaLinux 8.10 (Cerulean Leopard) | `4.18.0-553.117.1.el8_10.x86_64` | x86_64 | 3.11.13 | `CONDITIONALLY_SUPPORTED` | **PASS** | 10/10 | 1 | ✓ | 7/7 |
| `a9` | AlmaLinux 9.7 (Moss Jungle Cat) | `5.14.0-611.45.1.el9_7.x86_64` | x86_64 | 3.9.25 | `COMPATIBLE_BUT_NOT_CERTIFIED` | **PASS** | 10/10 | 1 | ✓ | 7/7 |
| `cs9` | CentOS Stream 9 | `5.14.0-694.el9.x86_64` | x86_64 | 3.9.25 | `COMPATIBLE_BUT_NOT_CERTIFIED` | **PASS** | 10/10 | 1 | ✓ | 7/7 |
| `d11` | Debian GNU/Linux 11 (bullseye) | `5.10.0-39-amd64` | x86_64 | 3.9.2 | `COMPATIBLE_BUT_NOT_CERTIFIED` | **PASS** | 10/10 | 1 | ✓ | 7/7 |
| `d12` | Debian GNU/Linux 12 (bookworm) | `6.1.0-44-amd64` | x86_64 | 3.11.2 | `COMPATIBLE_BUT_NOT_CERTIFIED` | **PASS** | 10/10 | 1 | ✓ | 7/7 |
| `d13` | Debian GNU/Linux 13 (trixie) | `6.12.74+deb13+1-amd64` | x86_64 | 3.13.5 | `COMPATIBLE_BUT_NOT_CERTIFIED` | **PASS** | 10/10 | 1 | ✓ | 7/7 |
| `leap156` | openSUSE Leap 15.6 | `6.4.0-150600.23.100-default` | x86_64 | 3.6.15 | `UNSUPPORTED — interpreter` | **UNSUPPORTED_INTERPRETER** | —/— | — | — | 0/0 |
| `leapp` | openSUSE Leap 15.6 | `6.4.0-150600.23.100-default` | x86_64 | 3.6.15 | `UNSUPPORTED — interpreter` | **UNSUPPORTED_INTERPRETER** | —/— | — | — | 0/0 |
| `r9` | Rocky Linux 9.7 (Blue Onyx) | `5.14.0-611.5.1.el9_7.x86_64` | x86_64 | 3.9.23 | `COMPATIBLE_BUT_NOT_CERTIFIED` | **PASS** | 10/10 | 1 | ✓ | 7/7 |
| `u2204` | Ubuntu 22.04.5 LTS | `5.15.0-173-generic` | x86_64 | 3.10.12 | `COMPATIBLE_BUT_NOT_CERTIFIED` | **PASS** | 10/10 | 1 | ✓ | 7/7 |
| `u2404` | Ubuntu 24.04.4 LTS | `6.8.0-106-generic` | x86_64 | 3.12.3 | `COMPATIBLE_BUT_NOT_CERTIFIED` | **PASS** | 10/10 | 1 | ✓ | 7/7 |
| `u2604` | Ubuntu 26.04 LTS | `7.0.0-14-generic` | x86_64 | 3.14.4 | `COMPATIBLE_BUT_NOT_CERTIFIED` | **PASS** | 10/10 | 1 | ✓ | 7/7 |

### What the campaign established

**Zero distribution-specific code.** Ten distributions, three families, CPython **3.9.2 through 3.14.4**,
and identical behaviour throughout: ten runs produce one state object and ten chained ledger records, the
independent verifier accepts every artifact, and all seven frozen negative cases reach their expected
status and reason. No `if rhel / elif debian` was needed anywhere, which is the question W1-C existed to
answer.

**The interpreter is the only portability boundary found.** Not the filesystem, not permissions, not
systemd, not SELinux — every one of those varied across the matrix without consequence.

### Not measured, and why

| Distribution | Reason |
|---|---|
| AlmaLinux 10 · CentOS Stream 10 · Rocky 10 | `NOT_TESTED` — the EL10 generation is UEFI-only and the lab's OVMF build faults during firmware initialisation. A lab prerequisite, not an ISEDRAF result |
| RHEL 8 · 9 · 10 | `IMAGE_UNAVAILABLE` — subscription required |
| Oracle Linux · Rocky 8 · Ubuntu 20.04 · SLES · Amazon Linux 2023 · Fedora · Alpine · Arch | `IMAGE_UNAVAILABLE` in this lab |
| **every ARM64 target** | `NOT_TESTED` — x86_64 results are never extrapolated to another architecture |

### Why nothing is `CERTIFIED` yet

`CERTIFIED` requires the complete campaign, and two parts have not run: **reboot stability** and
**version-upgrade stability**. Everything that passed is therefore `COMPATIBLE_BUT_NOT_CERTIFIED` — it
behaved correctly on every check performed, and two checks were not performed.

### Lab infrastructure findings

Recorded because they cost time and will cost it again otherwise, and because none is an ISEDRAF defect:

1. **EL10 cloud images are UEFI-only.** Booted with SeaBIOS they emit *zero* serial output and never
   appear — no error, no lease, nothing to diagnose.
2. **cloud-init discards the entire configuration when user-data fails to parse, and still reports
   success.** A 50 KB base64 payload in `write_files` did exactly that: no user, no files, no `runcmd`,
   and a cheerful *"finished"* on the console. The payload now goes over SSH, which fails loudly.
3. **The serial console file is created `root:0600` by qemu**, so a poll loop running as the invoking
   user waits forever for a marker it cannot read.

### The Python floor is a declared constraint, not a technical one

A static scan of all ten production modules found **no language or library feature newer than Python
3.6**. `D-12`'s `≥ 3.9` floor is therefore a decision, not a limit the code imposes — and it is what
places AlmaLinux 8 in `CONDITIONALLY_SUPPORTED` and openSUSE Leap 15.6 in `UNSUPPORTED`, both of which
ship a working 3.6.

Lowering the floor would let both run on their **stock interpreter, with no installation and no root** —
which is the deployment model the project wants. It is an owner decision: `D-12` is in the decisions
register and the floor is stated in `EVIDENCE_AND_TRUST_MODEL.md`, which is inside `W1A_CORE.sha256`, so
changing it requires an amendment and a re-freeze. The evidence is static only; no runtime verification on
3.6 has been performed.
