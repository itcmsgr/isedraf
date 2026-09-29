<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Security Policy

Status: IMPLEMENTED
Implements: D-30, D-31, D-35, D-46, §36

## Supported versions

| Version | Security fixes |
|---|---|
| 0.1.x (current release) | yes |
| pre-releases (0.1.0-alpha1 and release candidates) | no - upgrade to 0.1.x |

## Reporting a vulnerability

Report vulnerabilities **privately**, by either route:

- **GitHub private vulnerability reporting** (preferred): the repository's *Security* tab →
  *Report a vulnerability*. This opens a private security advisory visible only to you and the
  maintainer.
- **Email:** `contact@itcms.gr`.

**Do not open a public issue, discussion or pull request for a vulnerability**, and do not publish a
working exploit or a step-by-step extraction path while the issue is unresolved.

Include: affected version, platform and distribution, how ISEDRAF was run, what you observed, what you
expected, and a minimal reproduction. **Redact before sending:** ISEDRAF 0.1 has no automatic
redaction, so remove host names, account names, key fingerprints and sudo rule bodies by hand. See
`SUPPORT.md`.

## Response targets

These are targets the maintainer works to, not guarantees:

| Step | Target |
|---|---|
| Acknowledgement of your report | within **3 business days** |
| Initial assessment and severity triage | within **10 business days** |
| Coordinated public disclosure | normally within **90 days** of the report |

The disclosure date may be brought forward or extended by mutual agreement with the reporter where
there is a technical reason, for example a fix that needs more time or a vulnerability already being
exploited. Please do not disclose an unresolved vulnerability publicly before the coordinated date.

## How vulnerabilities are published

A confirmed vulnerability is fixed in a release and published through:

- a **GitHub Security Advisory** on this repository;
- a **CVE** record where the issue warrants one (not every report receives a CVE);
- the release notes and `CHANGELOG.md`.

Reporters are credited in the advisory unless they prefer otherwise.

## What counts as a security-sensitive defect

ISEDRAF is a trust tool. A defect that makes it report something untrue is a security defect, even when
no memory is corrupted and no privilege is gained.

| Class | Why it is security-sensitive |
|---|---|
| **Evidence reported as observed when it was not collected** | The operator believes something was checked that never was. Treated as **particularly serious**. |
| `NOT_TESTED` presented as a good result | Missing evidence silently becomes good news. |
| Snapshot or evidence corruption not detected | The evidence record is no longer trustworthy. |
| Integrity-verifier failure | Verification of committed evidence cannot be relied upon. |
| Unsafe privileged execution | Anything that runs with more privilege than documented, or changes the host. |
| Privilege escalation | Local escalation through ISEDRAF or its installed files. |
| Sensitive report disclosure | Identity data, key fingerprints, sudo rule bodies or GECOS leaking into a shared artifact. |
| Supply-chain issues | Package, build or provenance problems. |

## What is not a vulnerability

- ISEDRAF not detecting a change it never claimed to collect — check the evidence boundary first.
- A fact that needs elevated privilege being reported as `NOT_TESTED`. ISEDRAF 0.1 runs unprivileged by
  design.
- Local verification not defeating an administrator who alters both the evidence and its records.
  ISEDRAF does not claim this.

## Scope and honest limits

ISEDRAF observes userspace and kernel-exposed state on the local host. It is not remote attestation, and
local verification detects change rather than defeating a root-level adversary on the same host. These
limits are documented in `docs/SECURITY_AND_LIMITATIONS.md`; they are not defects.
