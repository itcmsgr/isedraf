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
- A normal user account. ISEDRAF 0.1 runs only unprivileged.
- A home directory, or `XDG_STATE_HOME`, on a local filesystem such as ext4, XFS or btrfs.

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

Installing needs root, as any package does. Running ISEDRAF does not, and must not.
The package installs `/usr/bin/isedraf` and `/usr/lib/isedraf/`. It has no install
scripts, creates no user and starts nothing.

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

| Message says | What to do |
|---|---|
| Privileged execution is not supported in ISEDRAF 0.1 (exit 70) | run as your normal user, without `sudo` |
| the evidence store ... has mode ... it must be 0700 | `chmod 700` the directory yourself |
| is not a directory (a symlink or file is refused) | replace the link with a real directory |
| is owned by uid ..., not the invoking uid | use your own directory; stores are per user |
| STORAGE_UNSUITABLE ... nfs, cifs, fuse ... | point `XDG_STATE_HOME` at a directory on a local disk |
| STORAGE_NOT_ESTABLISHED | the filesystem type is not known to be safe; use a local ext4, XFS or btrfs directory |
| neither XDG_STATE_HOME nor HOME is an absolute path | set one of them |
| another ISEDRAF run holds the lock | wait for the other run to finish |
| no committed audit run ... run `isedraf audit` first | run `isedraf audit`, then report |

These all exit 64, except the privilege refusal, and nothing is committed.

The last row also appears when the most recent run was made with `isedraf identity`, which
records host identity only. A report is always built from an audit run.

## Development runs

Setting `ISEDRAF_STATE_ROOT` to an absolute path sends evidence there instead. Everything
produced that way is marked `DEV`, and is never production evidence. It is meant for
development and testing. Root and sudo are refused in this mode too.

## The other commands

| Command | What it does |
|---|---|
| `isedraf audit` | collect all ten areas once and commit one run |
| `isedraf report` | render the last committed run; `--json`, `--html`, `--save` |
| `isedraf identity` | record host identity only, as its own committed run |
| `isedraf inventory` | print the host inventory now; commits nothing (`--json` for the data) |
| `isedraf --version` | print the version |

## References

Normative sources, for readers who need them: storage and store refusal
(STORE-026, STORE-027, D-116); unprivileged release scope (D-117, SCOPE-071, SCOPE-072);
exit codes (SCOPE-077); development state root (PRIV-004). Measured platforms:
[Platform compatibility](reference/PLATFORM_COMPATIBILITY.md).
