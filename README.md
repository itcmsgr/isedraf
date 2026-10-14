# ISEDRAF (codename)

**Linux Host Assurance with Approved Baselines, State Delta & Verifiable Evidence**

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.2.0-lightgrey)](VERSION)
[![Status](https://img.shields.io/badge/status-general%20availability-green)](docs/CURRENT_STATE.md)
[![Platforms](https://img.shields.io/badge/platforms-11%20Linux%20distributions%20measured-informational)](docs/reference/PLATFORM_COMPATIBILITY.md)
[![Governance](https://github.com/itcmsgr/isedraf/actions/workflows/governance.yml/badge.svg)](https://github.com/itcmsgr/isedraf/actions/workflows/governance.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/itcmsgr/isedraf/badge)](https://scorecard.dev/viewer/?uri=github.com/itcmsgr/isedraf) [![OpenSSF Baseline](https://www.bestpractices.dev/projects/15010/baseline)](https://www.bestpractices.dev/en/projects/15010/baseline-1)

> **Current release: 0.2.0 — General Availability.** ISEDRAF 0.2 adds Full Audit: `sudo isedraf audit` reads, through four fixed operations,
> evidence your own user cannot see, without the engine ever running as root.

## What is ISEDRAF?

ISEDRAF is a command you run on one Linux host when you want evidence about that host.
It reads what the host exposes locally, records where each fact came from and whether it
could be read at all, and commits the result as a verifiable evidence run on local disk.

It runs two ways:

- **Standard audit**, `isedraf audit`, as your own user. What needs root is NOT_TESTED.
- **Full Audit**, `sudo isedraf audit`, on Debian 12, Ubuntu 24.04, Rocky Linux 9 and
  AlmaLinux 9 with systemd. A root launcher starts a sandboxed run in which the engine runs
  as the unprivileged `isedraf` account with no capabilities; a small supervisor performs
  four fixed reads for it - `/etc/shadow`, the sudo policy files, the SSH server
  configuration files and the output of `sshd -T` - and nothing else.

ISEDRAF uses the system Python 3 (3.6 or later) and its standard library, has no daemon,
database or network connection, and is built not to change the host it inspects.

## What does it collect?

One run reads ten areas of the host, once:

| Area | What is read |
|---|---|
| Host and platform | operating system, kernel, architecture, hardware and network inventory |
| Local accounts and groups | `/etc/passwd`, `/etc/group`; `/etc/shadow` in Full Audit |
| Name service (NSS) | which sources the system uses to look up accounts |
| Hostname | the declared hostname and the one the kernel is using |
| sudo | the sudo policy files; all of them in Full Audit |
| SSH server | the configuration files; in Full Audit also the global effective configuration (`sshd -T`) |
| PAM | the PAM configuration |
| Login policy | password ageing and login defaults |
| Mounts | declared and active mounts |
| SSH authorized keys | key files named by the SSH configuration, where readable |

Each area gets a status: **COLLECTED**, **PARTIAL**, **NOT_TESTED** or **ERROR**, with the
reason, and every source records how it was read.

## What it does not claim

- **NOT_TESTED is not a pass.** It means the fact was not observed.
- **It gives no verdicts.** There is no PASS/FAIL, no score and no findings.
- **`sshd -T` is the global effective configuration only.** Values that depend on `Match`
  blocks, for a given user or address, are not resolved and are reported as such.
- **Full Audit does not read other users' authorized_keys files** it cannot read as the
  `isedraf` account; those stay NOT_TESTED.
- **It is not a compliance tool, and not remote attestation.** A local root user can alter
  what ISEDRAF reads, its evidence and ISEDRAF itself.
- **It does not assess firewalls, antivirus, EDR, SIEM, backups, cloud or network
  controls, patch availability or CVEs.** A missing product is not a missing control.

The full list, with reasons, is in [Security and limitations](docs/SECURITY_AND_LIMITATIONS.md).

## Install

DEB and RPM packages are attached to each published release, with build provenance and
SBOM attestations. You can also build them from a clean checkout: `bash packaging/build.sh`.

```sh
sudo apt install ./isedraf_<version>_all.deb       # Debian, Ubuntu
sudo dnf install ./isedraf-<version>.noarch.rpm    # RHEL family
```

The package installs `/usr/bin/isedraf` and `/usr/lib/isedraf/`, declares the `isedraf`
system account (no home, no login shell) and creates `/var/lib/isedraf` only when nothing
exists there. It depends only on `python3` and starts no service.

## First run

```sh
isedraf audit                  # standard audit, as your own user
isedraf report --html --save   # render the last run as static HTML

sudo isedraf audit             # Full Audit
sudo isedraf report            # render the last Full Audit run (read-only)
```

Under `sudo`, ISEDRAF runs only `audit` and `report`; everything else is refused.

| Exit | Meaning |
|---|---|
| 0 | committed (or rendered), and every area was COLLECTED |
| 2 | committed (or rendered), but some areas are PARTIAL, NOT_TESTED or ERROR |
| 64 | usage or engine error; nothing was committed |
| 66 | another ISEDRAF run holds the lock; nothing was collected |
| 67 | the evidence store cannot be used; nothing was collected |
| 70 | refused under sudo or root, or Full Audit not supported here; nothing was collected |

Exit 2 is the normal result on a real host. An interrupted Full Audit (Ctrl-C, SIGTERM,
SIGHUP) commits nothing and exits 128 plus the signal.

## What output do I get?

- **Evidence**: one directory per run and a hash-chained ledger - in
  `~/.local/state/isedraf` for a standard audit, in `/var/lib/isedraf` (root only) for
  Full Audit.
- **A report** rendered from the last committed run, as Markdown, JSON (`--json`) or HTML
  (`--html`). It never collects. A Full Audit report states the run mode, how each source
  was acquired, and which evidence it re-verified.

Removing the package never deletes the evidence.

## Where to read next

| If you want to | Read |
|---|---|
| install, run, and fix a refused run | [Getting started](docs/GETTING_STARTED.md) |
| understand statuses, runs and verification | [Evidence model](docs/EVIDENCE_MODEL.md) |
| review a run as an auditor, and check a fact by hand | [Auditor guide](docs/AUDITOR_GUIDE.md) |
| read the report section by section | [Report guide](docs/REPORT_GUIDE.md) |
| know exactly what ISEDRAF cannot tell you | [Security and limitations](docs/SECURITY_AND_LIMITATIONS.md) |

Engineering and design documents live under [`docs/`](docs/README.md); implementation
status is in [Current state](docs/CURRENT_STATE.md).

## Security

Do not put host evidence or suspected vulnerabilities in public issues. See
[SECURITY.md](SECURITY.md). Contact: contact@itcms.gr.

## AI-assisted development

ISEDRAF is developed with AI assistance. AI systems help with design review,
implementation, testing and documentation; they hold no ownership or architectural
authority. Decisions, acceptance, releases and responsibility remain with Antonios
Voulvoulis / ITCMS. See [AI_ASSISTED_DEVELOPMENT.md](AI_ASSISTED_DEVELOPMENT.md).

## License

Mozilla Public License 2.0. Copyright © 2026 Antonios Voulvoulis / ITCMS. See [LICENSE](LICENSE).
