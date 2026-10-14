<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Getting started

This page takes you from a checkout to your first report, and explains what to do when
ISEDRAF refuses to run. It assumes you administer Linux hosts; it does not assume you know
anything about how ISEDRAF is built.

## What you need

- A Linux host with Python 3.6 or later as `python3` (or a newer `python3.x`). ISEDRAF
  uses the interpreter the host already has and never installs one.
- A normal user account for the standard audit, and a home directory, or
  `XDG_STATE_HOME`, on a local filesystem such as ext4, XFS or btrfs.
- For Full Audit: `sudo`, systemd, and Debian 12, Ubuntu 24.04, Rocky Linux 9 or
  AlmaLinux 9. The package provides the rest.

Nothing else: no extra Python modules, no service, no network access.

## Build and install the package

The DEB and RPM packages are attached to each release on the project's releases page.
You can also build them yourself from a clean checkout. The build refuses a tree with
uncommitted changes, so the DEB and RPM always carry the same code.

```sh
git clone https://github.com/itcmsgr/isedraf.git
cd isedraf
bash packaging/build.sh
```

The results are in `dist/packages/`. The RPM is built only when `rpmbuild` is installed.

```sh
sudo apt install ./dist/packages/isedraf-latest_all.deb        # Debian, Ubuntu
sudo dnf install ./dist/packages/isedraf-latest.noarch.rpm     # RHEL family
```

Installing needs root, as any package does. The package installs `/usr/bin/isedraf` and
`/usr/lib/isedraf/`, declares the `isedraf` system account through systemd-sysusers (no
home, no login shell, never removed on uninstall) and creates `/var/lib/isedraf`, owned by
root with mode 0700, only when nothing exists at that path. It starts nothing.

To try ISEDRAF without installing, run it from the checkout: `./bin/isedraf audit`.

## Run it once

As your normal user:

```sh
isedraf audit
```

This reads the ten areas described in the [README](../README.md), commits them as one run
and prints a summary. On a small test host it looked like this (the evidence path is
shortened):

```text
ISEDRAF host identity
  collection status : COLLECTED
  host id           : sha256:e896539f9dd3b417d1fd5b8c327d8caeb02353d1c2714a2889d2593442d899fa
  snapshot          : SDS-20260928T140403Z-41a4d71af5303e60
  evidence root     : ~/.local/state/isedraf (USER_PRODUCTION)
  privilege level   : UNPRIVILEGED - evidence that needs root is
                      NOT_TESTED, never assumed
  audit             : PARTIAL
    inventory       PARTIAL
    nss             COLLECTED
    hostname        COLLECTED
    accounts        PARTIAL
    sudo            NOT_TESTED
    ssh             COLLECTED
    pam             COLLECTED
    loginpolicy     COLLECTED
    mounts          PARTIAL
    authorizedkeys  NOT_TESTED

Render it with: isedraf report
```

The exit code was 2: the run was committed, and some areas were not fully observed. On a
real host run without root, that is the expected result. [Evidence model](EVIDENCE_MODEL.md)
explains each status.

## Run a Full Audit

```sh
sudo isedraf audit
sudo isedraf report            # or --json, --html; nothing else is accepted under sudo
```

Full Audit runs in a sandboxed systemd unit. The engine runs as the `isedraf` account with
no capabilities; a supervisor in the unit performs four fixed reads for it and nothing
else: `/etc/shadow`, the sudo policy files, the SSH server configuration files, and
`sshd -T`. Every other source is read by the engine itself, and the evidence records which
way each source was read.

The run is committed to `/var/lib/isedraf`, readable only by root. `sudo isedraf report`
renders the last Full Audit run read-only: it changes nothing in the store, and the report
says which evidence it re-verified. Ctrl-C, SIGTERM or SIGHUP stops a Full Audit before it
commits; nothing is committed and the exit code is 128 plus the signal.

## Render the report

```sh
isedraf report                 # Markdown to the terminal
isedraf report --html --save   # static HTML file inside the evidence store
isedraf report --json          # the machine-readable report
```

`--save` prints the path of the file it wrote. The report is rendered from the last
committed run and never collects anything new. [Report guide](REPORT_GUIDE.md) explains
what each part means.

## Where the evidence lives

The evidence store is `$XDG_STATE_HOME/isedraf` when `XDG_STATE_HOME` is an absolute
path, and `~/.local/state/isedraf` otherwise. ISEDRAF creates it with mode 0700.

Inside it, each run is a directory under `snapshots/`, recorded in a ledger under
`ledger/`. Saved reports go to `reports/`. Back up the whole directory if you need to keep
the evidence. Uninstalling the package does not touch it; delete it yourself when you no
longer need it.

## When a run is refused

ISEDRAF never falls back to another location or quietly repairs anything. It stops and
says why.

| Message says | Exit | What to do |
|---|---|---|
| Under sudo or root, ISEDRAF runs only `sudo isedraf audit` ... and `sudo isedraf report` | 70 | run other commands as your normal user |
| FULL_AUDIT_UNSUPPORTED | 70 | Full Audit needs systemd and one of the four platforms above |
| ENGINE_IDENTITY_MISSING | 70 | reinstall the package, which declares the `isedraf` account |
| ENGINE_UNSAFE_INSTALL | 64 | `/usr/lib/isedraf` must be root-owned and not writable by others |
| the evidence store ... has mode ... it must be 0700 | 67 | `chmod 700` the directory yourself |
| is not a directory (a symlink or file is refused) | 67 | replace the link with a real directory |
| is owned by uid ..., not the invoking uid | 67 | use your own directory; stores are per user |
| STORAGE_UNSUITABLE ... nfs, cifs, fuse ... | 67 | point `XDG_STATE_HOME` at a directory on a local disk |
| STORAGE_NOT_ESTABLISHED | 67 | use a local ext4, XFS or btrfs directory |
| STATE_ROOT_UNUSABLE: /var/lib/isedraf ... | 67 | restore it as a root-owned 0700 directory; ISEDRAF never repairs it |
| neither XDG_STATE_HOME nor HOME is an absolute path | 64 | set one of them |
| another ISEDRAF run holds the lock | 66 | wait for the other run to finish |
| no committed audit run ... run `isedraf audit` first | 64 | run the audit, then report |

Nothing is collected or committed in any of these cases.

The last row also appears when the most recent run was made with `isedraf identity`, which
records host identity only. A report is always built from an audit run.

## Development runs

Setting `ISEDRAF_STATE_ROOT` to an absolute path sends evidence there instead. Everything
produced that way is marked `DEV`, and is never production evidence. It is meant for
development and testing, and it is refused under root and sudo.

## The other commands

| Command | What it does |
|---|---|
| `isedraf audit` | collect all ten areas once and commit one run |
| `isedraf report` | render the last committed run; `--json`, `--html`, `--save` |
| `sudo isedraf audit` | Full Audit; commits to `/var/lib/isedraf` |
| `sudo isedraf report` | render the last Full Audit run, read-only; `--json` or `--html` |
| `isedraf identity` | record host identity only, as its own committed run |
| `isedraf inventory` | print the host inventory now; commits nothing (`--json` for the data) |
| `isedraf --version` | print the version |

## References

Normative sources, for readers who need them: storage and store refusal
(STORE-026, STORE-027, D-116); the Full Audit route and its report (AUTH-019, AUTH-032);
exit codes (OUT-001, `lib/isedraf/exitcodes.json`); development state root (PRIV-004). Measured platforms:
[Platform compatibility](reference/PLATFORM_COMPATIBILITY.md).
