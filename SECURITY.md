<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Security Policy

Status: IMPLEMENTED
Implements: D-30, D-31, D-35, D-46, §36

## Reporting

Report vulnerabilities privately to **`contact@itcms.gr`**.

**Do not open a public issue for a vulnerability**, and do not include a working exploit or a step-by-step
extraction path in any public channel. A dedicated ISEDRAF security contact will be established before
public release; until then this address is authoritative.

Include: affected version, platform and distribution, privilege level of the run, what you observed, what
you expected, and a minimal reproduction. **Redact before sending** — see `SUPPORT.md` and use `--redact`.

## What counts as a security-sensitive defect

ISEDRAF is a trust tool. A defect that makes it report something untrue is a security defect, even when
no memory is corrupted and no privilege is gained.

| Class | Why it is security-sensitive |
|---|---|
| **False `PASS` caused by collection failure** | The operator believes a control was verified when it was never observed. Treated as **particularly serious**. |
| `NOT_TESTED` rendered as an improvement or a removal | Missing evidence silently becomes good news. |
| Incorrect baseline comparison | A real change is hidden, or a non-change is reported as drift. |
| Incorrect delta or classification logic | A security regression is classified as informational. |
| Snapshot or evidence corruption | The evidence record is no longer trustworthy. |
| Integrity-verifier failure | Tool integrity reporting cannot be relied upon. |
| Unsafe privileged execution | Anything that runs with more privilege than the frozen model allows. |
| Privilege escalation | Local escalation through ISEDRAF or its installed files. |
| Unsafe guidance | Illustrative remediation that would lock out or disrupt a host. |
| Sensitive report disclosure | Identity data, key fingerprints, sudo rule bodies or GECOS leaking into a shared artifact. |
| Schema confusion | A consumer misreads exported evidence because versions or types are ambiguous. |
| Supply-chain issues | Package, update or build-provenance problems. |

## What is not a vulnerability

- ISEDRAF not detecting a change it never claimed to collect — check the evidence boundary first.
- The absence of a locally detectable external agent being reported as `NOT_TESTED` rather than a failure.
  This is intended behaviour (D-09).
- A local signature not proving that root did not manipulate source data. ISEDRAF does not claim this.

## Scope and honest limits

ISEDRAF observes userspace and kernel-exposed state on the local host. It is not remote attestation, and
local verification detects drift rather than defeating a root-level adversary on the same host. These
limits are documented, not defects.

## Handling

Acknowledgement is sent on receipt. Reports are triaged by severity, with false `PASS` and unsafe
privileged execution treated as highest. Fixes are developed privately and released with a
`CHANGELOG.md` entry. Reporters are credited unless they prefer otherwise.
