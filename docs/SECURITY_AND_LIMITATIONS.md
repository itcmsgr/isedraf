<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Security and limitations

This page states what ISEDRAF 0.2 does to a host, how its evidence is protected, what it
does not cover, and what it cannot conclude. It is meant to be read before relying on a
report.

## What a run does to the host

A run reads files under `/etc`, `/proc` and `/sys`, and may call a few standard read-only
tools when they are present: `ip`, `systemd-detect-virt`, `timedatectl` and `chronyc`. Tools
are run with fixed arguments and a clean environment, without a shell, with a time limit. A tool
that is missing makes the affected fact NOT_TESTED. Full Audit also runs `sshd -T`, with exactly
that one argument; it prints the configuration sshd would use and changes nothing.

ISEDRAF writes only inside its own evidence store. It is built not to change the host it
inspects: it does not edit configuration, restart services, create users, load kernel
modules or change audit, SSH, PAM or firewall settings.

It opens no network connection, sends no telemetry and checks for no updates. It runs no
daemon and leaves nothing running after a run. A Full Audit runs in a transient systemd unit
that ends with the run.

## Privilege

The standard audit runs as your own user. Facts it cannot read, such as `/etc/shadow` and
the sudo policy, are NOT_TESTED or PARTIAL, with the reason.

Under `sudo`, ISEDRAF runs only `audit` and `report`; every other command is refused with
exit 70. It never asks for a password and never calls `sudo` itself. In a Full Audit:

- a root launcher starts a sandboxed systemd unit with a fixed property set: the file
  system read-only except the evidence store, no network, four capabilities as its bound;
- the engine that collects and interprets runs as the `isedraf` account, with no
  capabilities and no way to gain any;
- a supervisor performs exactly four fixed reads for the engine: `/etc/shadow`, the sudo
  policy files, the SSH server configuration files and `sshd -T`. It accepts no path, no
  argument and no command from the engine, and interprets nothing.

`sudo isedraf report` reads the Full Audit store without changing it and renders through
an unprivileged renderer that verifies the evidence first.

## How the evidence is protected

The standard store is a directory owned by the user who ran ISEDRAF, mode 0700, with files
mode 0600. The Full Audit store is `/var/lib/isedraf`, owned by root with mode 0700; ISEDRAF
refuses it, and never repairs it, if it is anything else. ISEDRAF refuses to use a store that is a symlink, belongs to someone else, or has
wider permissions, and refuses network and FUSE filesystems, where an atomic commit cannot
be relied on.

Each run is bound by SHA-256 digests and a hash-chained ledger, which ISEDRAF checks after
every commit and before every report. This detects accidental or casual change. It does
not protect against someone with root on the host, who can rewrite the store and the
ledger together. Runs are not signed, and there is no off-host copy unless you make one.

## What the evidence contains

A run contains account names, home directories, group memberships, hostnames, mount
points, network addresses and configuration content. Treat it as sensitive, like the host
configuration it describes.

The host is identified by a pseudonymous digest of its machine-id. The raw machine-id is
never stored in a run or shown in a report. Password hashes are never copied into
evidence.

Do not attach evidence or reports to public issues.

## What ISEDRAF 0.2 does not include

These are not part of this release. Some are the direction of the project; none is
promised here.

- comparison between runs, approved baselines and change detection;
- findings, PASS/FAIL judgements or scores;
- mappings to any security framework or standard: none exists in this repository, none is
  bundled and none is licensed;
- connection-specific SSH settings: `sshd -T` gives the global effective configuration,
  and values that depend on `Match` blocks are reported as not resolved;
- other users' authorized_keys files that the `isedraf` account cannot read: Full Audit
  has no privileged read for them, and they stay NOT_TESTED;
- the mount tables of other processes and containers (the host's own is read);
- on SELinux-enforcing Rocky Linux and AlmaLinux, the time source details from `chronyc`
  in Full Audit: the tool is not run there, and the time area says so;
- signed evidence, exports and PDF reports;
- kernel parameters, mandatory access control, services, scheduled jobs and software
  inventory.

## Outside the scope of ISEDRAF

ISEDRAF describes the local host only. It does not assess firewall effectiveness,
antivirus or EDR products, intrusion detection, SIEM, web application firewalls, backup
systems, cloud or network controls, remote patch availability, or vulnerabilities and CVEs.

A product that is not present on the host is never reported as a missing control. The
control may exist elsewhere.

## What no run can prove

- NOT_TESTED is not PASS: it means not observed.
- A host with no observed change is not shown to be uncompromised.
- An accepted state, once baselines exist, will be a decision, not a security judgement.
- Host evidence is not organizational compliance.
- Local verification is not remote attestation.

The [Auditor guide](AUDITOR_GUIDE.md) explains each of these, and how to check a fact
by hand.

## Where ISEDRAF has been run

The runtime is Python standard library only, with no compiled code, so the same package
installs on any architecture. That is not the same as having been tested there. Only
x86_64 has been measured; ARM64 has not been tested. The distributions and versions
actually measured are listed in the
[Platform compatibility record](reference/PLATFORM_COMPATIBILITY.md).

## How the project checks itself

- Every change passes an automated check suite before it is committed, covering tests,
  documentation claims, privacy and licensing.
- Static analysis runs on the code and the build workflows. The project runs OpenSSF
  Scorecard but publishes no score.
- Build artifacts carry build provenance and an SBOM. The source tarball and the DEB have
  been rebuilt byte-for-byte on a different distribution. The RPM is not claimed to be
  byte-identical across rpm versions; its payload is consistent.
- Controls that are intended but not yet in force are recorded as such in the repository.
  Release signing and an SLSA level are not claimed.

## Reporting a security problem

Report vulnerabilities privately to contact@itcms.gr, not in a public issue.
[SECURITY.md](../SECURITY.md) explains what to include and what counts as a
security-sensitive defect. For ISEDRAF, a report that states something untrue, such as a
fact shown as observed when it was not, is a security defect.

## References

Normative sources, for readers who need them: the Full Audit authority model (AUTH-019 to
AUTH-032); store ownership and storage checks (STORE-026, STORE-027, AUTH-022); collector
execution rules (EXEC-011, D-13); scope boundary (D-09). Known gaps in
project controls: [Governance gaps](development/GOVERNANCE_GAPS.md). The frozen design is
under [docs/architecture](architecture/).
