# ISEDRAF (codename)

**Linux Host Assurance with Approved Baselines, State Delta & Verifiable Evidence**

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.2-lightgrey)](VERSION)
[![Status](https://img.shields.io/badge/status-general%20availability-green)](docs/CURRENT_STATE.md)
[![Platforms](https://img.shields.io/badge/platforms-11%20Linux%20distributions%20measured-informational)](docs/reference/PLATFORM_COMPATIBILITY.md)
[![Governance](https://github.com/itcmsgr/isedraf/actions/workflows/governance.yml/badge.svg)](https://github.com/itcmsgr/isedraf/actions/workflows/governance.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/itcmsgr/isedraf/badge)](https://scorecard.dev/viewer/?uri=github.com/itcmsgr/isedraf) [![OpenSSF Baseline](https://www.bestpractices.dev/projects/15010/baseline)](https://www.bestpractices.dev/en/projects/15010/baseline-1)

> **Current release: 0.1.2 — General Availability.** ISEDRAF 0.1.2 provides production unprivileged
> Linux host evidence collection. Privileged full-audit execution is not included in this release.

## What is ISEDRAF?

ISEDRAF is a command you run on one Linux host when you want evidence about that host.
It reads what the host exposes locally, records where each fact came from and whether it
could be read at all, and commits the result as a verifiable evidence run on local disk.

ISEDRAF 0.1 is deliberately small and unprivileged:

- it runs as your own user, never as root;
- it uses the system Python 3 (3.6 or later) and its standard library, nothing else;
- it has no daemon, no database, no network connection and no remote control;
- it is installed from a DEB or RPM package;
- it is built not to change the host it inspects.

Approved baselines and state comparison, named in the subtitle above, are the direction of
the project. They are not part of 0.1.

## What does it collect?

One `isedraf audit` reads ten areas of the host, once:

| Area | What is read |
|---|---|
| Host and platform | operating system, kernel, architecture, hardware and network inventory |
| Local accounts and groups | `/etc/passwd`, `/etc/group`, and `/etc/shadow` when readable |
| Name service (NSS) | which sources the system uses to look up accounts |
| Hostname | the declared hostname and the one the kernel is using |
| sudo | the sudo policy files, when readable |
| SSH server | the SSH daemon configuration files |
| PAM | the PAM configuration |
| Login policy | password ageing and login defaults |
| Mounts | declared and active mounts |
| SSH authorized keys | key files named by the SSH configuration |

Each area gets a status: **COLLECTED**, **PARTIAL**, **NOT_TESTED** or **ERROR**.
Because 0.1 runs without root, anything that needs root (for example `/etc/shadow` or the
sudo policy) is reported as NOT_TESTED, with the reason.

## What it does not claim

- **NOT_TESTED is not a pass.** It means the fact was not observed.
- **It gives no verdicts.** There is no PASS/FAIL, no score and no findings in 0.1.
- **It is not a compliance tool.** Host evidence is not organizational compliance, and no
  framework mapping exists in this repository.
- **It does not prove a host is uncompromised.** A local root user can alter what ISEDRAF
  reads, and ISEDRAF itself.
- **It is not remote attestation.** Evidence is protected by file permissions on the host.
- **It does not assess firewalls, antivirus, EDR, SIEM, backups, cloud or network
  controls, patch availability or CVEs.** A product missing from the host does not mean
  the control is missing.

The full list, with reasons, is in [Security and limitations](docs/SECURITY_AND_LIMITATIONS.md).

## Install

No published packages exist yet. Build them from a clean checkout of this repository:

```sh
bash packaging/build.sh
```

The packages land in `dist/packages/`. Install the one for your distribution with the
system package manager, for example `apt install ./dist/packages/isedraf-latest_all.deb`
or `dnf install ./dist/packages/isedraf-latest.noarch.rpm`.
The package installs `/usr/bin/isedraf` and `/usr/lib/isedraf/`, and depends only on
`python3`. It creates no user and starts no service.

[Getting started](docs/GETTING_STARTED.md) covers building, installing, and running from
a checkout without installing.

## First run

Run it as your normal user. Do not use `sudo`: this release refuses to run as root.

```sh
isedraf audit          # collect once and commit one evidence run
isedraf report --html --save   # render that run as a static HTML file
```

`isedraf audit` prints one status line per area and exits:

| Exit | Meaning |
|---|---|
| 0 | the run was committed and every area was COLLECTED |
| 2 | the run was committed, but some areas are PARTIAL, NOT_TESTED or ERROR |
| 64 | usage or engine error, or the evidence store was refused |
| 70 | run as root or through sudo; refused, nothing was collected |

Exit 2 is the normal result of an unprivileged run on a real host.

## What output do I get?

- **Evidence** in `~/.local/state/isedraf` (or `$XDG_STATE_HOME/isedraf`): one directory
  per run, a hash-chained ledger, mode 0700, owned by you.
- **A report** rendered from the last committed run, as Markdown (default), JSON
  (`--json`) or static HTML (`--html`). `--save` writes it into the evidence store.
  A report never collects anything.

The HTML report opens with the privilege level and the overall evidence status, then one
section per area: its status, the reason when it is not COLLECTED, the facts observed,
and a reference to the evidence file and its digest.

Removing the package never deletes the evidence.

## Where to read next

| If you want to | Read |
|---|---|
| install, run, and fix a refused run | [Getting started](docs/GETTING_STARTED.md) |
| understand statuses, runs and verification | [Evidence model](docs/EVIDENCE_MODEL.md) |
| review a run as an auditor, and check a fact by hand | [Auditor guide](docs/AUDITOR_GUIDE.md) |
| read the report section by section | [Report guide](docs/REPORT_GUIDE.md) |
| know exactly what ISEDRAF cannot tell you | [Security and limitations](docs/SECURITY_AND_LIMITATIONS.md) |

The reader test for these pages: a new administrator or auditor should be able to say what
ISEDRAF is, what it collected and did not collect, what a report tells them and does not
prove, where a fact came from, and what to read next, without the internal engineering
documents. If they cannot, that is a documentation defect; please report it.

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
