<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/commands.py
     Regenerate: python3 scripts/docs/cli_reference.py generate
     `make check` fails when this file and the command table disagree. -->

# Command reference

**GENERATED FILE — DO NOT EDIT MANUALLY**

This is the help the installed `isedraf` prints, rendered from the same command table. Exit
codes are defined once in `lib/isedraf/exitcodes.json`; their full meanings are in the README.

## Start page

`isedraf` with no arguments, and `isedraf help`:

```text
isedraf 0.6.0 - Linux host evidence and assurance tool.

ISEDRAF collects evidence about this Linux host, commits it as one run,
evaluates it against its native criteria and reports on it.

Standard Audit, as your normal user, into your personal store:
  isedraf audit        collect evidence; root-only facts are NOT_TESTED
  isedraf evaluate     evaluate the latest run against the native criteria
  isedraf report       show the report of the latest run

Full Audit, with root authority, into the system store:
  sudo isedraf audit   then sudo isedraf evaluate and sudo isedraf report

Approving a baseline is an explicit decision, never an automatic next step:
  sudo isedraf baseline approve   (the system store's latest Full Audit run)

More:
  isedraf help --all       every command, grouped
  isedraf help COMMAND     one command: what it does, writes and returns
  Documentation: /usr/share/doc/isedraf/docs/
```

## Help forms

Accepted on the user route and, before anything else is checked, under sudo or root (the same answer, exit 0; they read no evidence, open no store and start nothing). `isedraf help` naming anything else exits 64 and lists the valid commands.

`isedraf`, `isedraf help`, `isedraf help --all`, `isedraf help --help`, `isedraf help -h`, `isedraf --help`, `isedraf -h`, `isedraf --version`, `isedraf help help`, `isedraf help audit`, `isedraf help evaluate`, `isedraf help explain`, `isedraf help baseline`, `isedraf help baseline approve`, `isedraf help list`, `isedraf help report`, `isedraf help identity`, `isedraf help inventory`

## Native criteria

The criteria `isedraf explain` and `isedraf evaluate` know are listed one per row, with their applicability, collection requirements, results and limitations, in [`NATIVE_CRITERIA.csv`](NATIVE_CRITERIA.csv) - in the package at `/usr/share/doc/isedraf/docs/reference/NATIVE_CRITERIA.csv`, generated from the installed registry (D-130).

## Overview

```text
usage: isedraf <command> [options]

Linux host evidence and assurance tool.

Start here, as your normal user:
  isedraf audit        collect evidence into your personal store
  isedraf evaluate     evaluate it against the native criteria
  isedraf report       show the report
Full Audit, with root authority, into the system store:
  sudo isedraf audit   then sudo isedraf evaluate, sudo isedraf report
Approving a baseline is an explicit decision, never an automatic next step:
  sudo isedraf baseline approve

Getting started:
  help              show the start page, every command (--all) or one command

Collect evidence:
  audit             collect evidence from this host and commit it as one run

Evaluate and understand:
  evaluate          evaluate the latest committed run against the native
                    criteria
  explain           explain one native criterion

Approve a reference:
  baseline approve  approve committed evidence as the baseline, explicitly

View results:
  list              list committed runs, evaluations, the baseline and saved
                    reports
  report            show the report of the latest committed run

Developer:
  identity          collect the host identity only and commit it as a run
  inventory         read the host inventory now and print it

Options:
  --help     this list (also `isedraf help --all`); `isedraf help COMMAND` or
             `isedraf COMMAND --help` for one command
  --version  the installed version

Documentation: /usr/share/doc/isedraf/
```

## Getting started

### `isedraf help`

```text
usage: isedraf help [--all] [COMMAND]
       isedraf | isedraf --help | isedraf --version
       sudo isedraf help [--all] [COMMAND]

Show the start page, every command (--all) or one command.

What it does:   reads the installed definitions only; no evidence, no store
Who runs it:    anyone. Under sudo or root, `sudo isedraf`, `sudo isedraf
                help`, `sudo isedraf --help` and `sudo isedraf --version` are
                answered before anything else is checked: no evidence is read,
                no store is opened, nothing is collected and no unit is started
What it writes: nothing

Arguments:
  COMMAND        a command, for example audit or baseline approve

Options:
  --help         this help
  --all          every command, grouped

Exit codes:
  isedraf:
    0    the help was shown
  isedraf --help:
    0    the help was shown
  isedraf --version:
    0    the help was shown
  isedraf help:
    0    the help was shown
    64   the command named is unknown; the valid commands are listed
  sudo isedraf:
    0    the help was shown
  sudo isedraf --help:
    0    the help was shown
  sudo isedraf --version:
    0    the help was shown
  sudo isedraf help:
    0    the help was shown
    64   the command named is unknown; the valid commands are listed

Examples:
  isedraf
  isedraf help --all
  isedraf help audit
  isedraf --version
  sudo isedraf help
```

## Collect evidence

### `isedraf audit`

```text
usage: isedraf audit [--root DIR]
       sudo isedraf audit

Collect evidence from this host and commit it as one run.

What it does:   collects evidence from this host and commits it as one run
Who runs it:    your normal user: what an unprivileged user may read, the rest
                recorded as NOT_TESTED. `sudo isedraf audit` is Full Audit:
                root authority, the root-only system store
What it writes: one committed run (snapshot and ledger record) in the evidence
                store

Options:
  --help         this help
  --root DIR     filesystem root to collect from (testing)

Exit codes:
  isedraf audit:
    0    completed; every area was collected
    2    completed, but some area is incomplete (expected without root; not a
         security verdict)
    64   usage error or engine error; nothing was committed
    66   another ISEDRAF run holds the lock; nothing was collected or written
    67   the evidence store cannot be used; nothing was collected
    68   too little free space for the run; nothing was committed or deleted
    70   refused under root or sudo; nothing was collected
  sudo isedraf audit:
    0    completed; every area was collected
    2    completed, but some area is incomplete (expected without root; not a
         security verdict)
    64   usage error or engine error; nothing was committed
    66   another ISEDRAF run holds the lock; nothing was collected or written
    67   the evidence store cannot be used; nothing was collected
    68   too little free space for the run; nothing was committed or deleted
    70   refused under root or sudo; nothing was collected
    129  interrupted (SIGHUP) before the commit
    130  interrupted (SIGINT) before the commit
    143  interrupted (SIGTERM) before the commit
    255  the Full Audit unit ended abnormally; no claim about what was
         committed

Examples:
  isedraf audit
  sudo isedraf audit
```

## Evaluate and understand

### `isedraf evaluate`

```text
usage: isedraf evaluate [--snapshot SDS-ID]
       sudo isedraf evaluate

Evaluate the latest committed run against the native criteria.

What it does:   evaluates committed evidence and writes an evaluation; collects
                nothing
Who runs it:    your normal user, on your store. `sudo isedraf evaluate`
                evaluates the system store's latest Full Audit run
What it writes: one evaluation (evaluations/EVL-...); with a baseline in force,
                the comparison with it

Options:
  --help         this help
  --snapshot SDS-ID a committed snapshot ID (default: the latest committed run)

Exit codes:
  isedraf evaluate:
    0    the evaluation was written; it does not mean every criterion passed
    5    the baseline in force does not verify; nothing was written
    64   usage error or engine error; nothing was committed
    66   another ISEDRAF run holds the lock; nothing was collected or written
    67   the evidence store cannot be used; nothing was collected
    70   refused under root or sudo; nothing was collected
  sudo isedraf evaluate:
    0    the evaluation was written; it does not mean every criterion passed
    5    the baseline in force does not verify; nothing was written
    64   usage error or engine error; nothing was committed
    66   another ISEDRAF run holds the lock; nothing was collected or written
    67   the evidence store cannot be used; nothing was collected
    70   refused under root or sudo; nothing was collected
    129  interrupted (SIGHUP) before the commit
    130  interrupted (SIGINT) before the commit
    143  interrupted (SIGTERM) before the commit
    255  the Full Audit unit ended abnormally; no claim about what was
         committed

Examples:
  isedraf evaluate
  sudo isedraf evaluate
```

### `isedraf explain`

```text
usage: isedraf explain CRITERION_ID

Explain one native criterion.

What it does:   reads the installed definitions only; no evidence, no store
Who runs it:    your normal user
What it writes: nothing

Arguments:
  CRITERION_ID   a criterion ID, for example ISE-ACCOUNT-001

Options:
  --help         this help

Exit codes:
  isedraf explain:
    0    the criterion was explained
    64   usage error or engine error; nothing was committed
    70   refused under root or sudo; nothing was collected

Examples:
  isedraf explain ISE-ACCOUNT-001
```

## Approve a reference

### `isedraf baseline approve`

```text
usage: isedraf baseline approve SNAPSHOT_ID
       sudo isedraf baseline approve

Approve committed evidence as the baseline, explicitly.

What it does:   approves committed evidence as the baseline, explicitly;
                collects nothing
Who runs it:    two separate contexts, and nothing moves between them. In the
                system store, `sudo isedraf baseline approve` approves that
                store's latest Full Audit run (made by `sudo isedraf audit`)
                and takes no snapshot argument. In a development (DEV) store,
                `isedraf baseline approve SDS-ID` approves the named run. Your
                personal store holds no baseline, and approving under sudo
                never turns a personal-store run into production evidence
What it writes: baselines/BL-000001.json and its ledger record; on refusal,
                nothing

Arguments:
  SNAPSHOT_ID    the SDS-... run to approve (DEV store only)

Options:
  --help         this help

Exit codes:
  isedraf baseline approve:
    0    the baseline was approved
    5    the baseline in force does not verify; nothing was written
    64   usage error or engine error; nothing was committed
    65   approval refused, with the reason named; nothing was written
    66   another ISEDRAF run holds the lock; nothing was collected or written
    67   the evidence store cannot be used; nothing was collected
    70   refused under root or sudo; nothing was collected
  sudo isedraf baseline approve:
    0    the baseline was approved
    5    the baseline in force does not verify; nothing was written
    64   usage error or engine error; nothing was committed
    65   approval refused, with the reason named; nothing was written
    66   another ISEDRAF run holds the lock; nothing was collected or written
    67   the evidence store cannot be used; nothing was collected
    70   refused under root or sudo; nothing was collected
    129  interrupted (SIGHUP) before the commit
    130  interrupted (SIGINT) before the commit
    143  interrupted (SIGTERM) before the commit
    255  the Full Audit unit ended abnormally; no claim about what was
         committed

Examples:
  sudo isedraf baseline approve
  isedraf baseline approve SDS-20261113T101500Z-41a4d71af5303e60
```

## View results

### `isedraf list`

```text
usage: isedraf list [--all]
       sudo isedraf list
       sudo isedraf list --all

List committed runs, evaluations, the baseline and saved reports.

What it does:   lists what the evidence store holds from its committed
                metadata; collects, approves and writes nothing
Who runs it:    your normal user, on your store. `sudo isedraf list` lists the
                system store read-only: runs, the baseline and evaluation
                identities, from its metadata; it opens no evidence and writes
                nothing
What it writes: nothing

Options:
  --help         this help
  --all          every entry, not only the newest of each kind

Exit codes:
  isedraf list:
    0    the store was listed (an empty or absent store too)
    64   usage error or engine error; nothing was committed
    67   the evidence store cannot be used; nothing was collected
    70   refused under root or sudo; nothing was collected
  sudo isedraf list:
    0    the store was listed (an empty or absent store too)
    64   usage error or engine error; nothing was committed
    66   another ISEDRAF run holds the lock; nothing was collected or written
    67   the evidence store cannot be used; nothing was collected
    70   refused under root or sudo; nothing was collected
    129  interrupted (SIGHUP) before the commit
    130  interrupted (SIGINT) before the commit
    143  interrupted (SIGTERM) before the commit
    255  the Full Audit unit ended abnormally; no claim about what was
         committed

Examples:
  isedraf list
  isedraf list --all
  sudo isedraf list
```

### `isedraf report`

```text
usage: isedraf report [--json] [--html] [--profile FILE] [--save]
       sudo isedraf report
       sudo isedraf report --json
       sudo isedraf report --html

Show the report of the latest committed run.

What it does:   shows committed evidence; collects nothing and writes nothing
                unless asked to save
Who runs it:    your normal user, on your store. `sudo isedraf report` (also
                --json, --html) shows the system store's latest Full Audit run;
                it cannot save. Export it privately as your user: (umask 077;
                set -o noclobber; sudo isedraf report > ~/isedraf-report.md)
What it writes: nothing; with --save, one file under <evidence store>/reports/

Options:
  --help         this help
  --json         the machine-readable report model
  --html         a static HTML report
  --profile FILE an optional assessment profile file (JSON); personal details
                 belong in a file, not on the command line
  --save         write the report under <evidence store>/reports/ and print its
                 path

Exit codes:
  isedraf report:
    0    the report was shown; every area of the run was collected
    2    completed, but some area is incomplete (expected without root; not a
         security verdict)
    64   usage error or engine error; nothing was committed
    70   refused under root or sudo; nothing was collected
  sudo isedraf report:
    0    the report was shown; every area of the run was collected
    2    completed, but some area is incomplete (expected without root; not a
         security verdict)
    64   usage error or engine error; nothing was committed
    66   another ISEDRAF run holds the lock; nothing was collected or written
    67   the evidence store cannot be used; nothing was collected
    70   refused under root or sudo; nothing was collected
    129  interrupted (SIGHUP) before the commit
    130  interrupted (SIGINT) before the commit
    143  interrupted (SIGTERM) before the commit
    255  the Full Audit unit ended abnormally; no claim about what was
         committed

Examples:
  isedraf report
  isedraf report --html --save
  sudo isedraf report
```

## Developer

### `isedraf identity`

```text
usage: isedraf identity [--source FILE]

Collect the host identity only and commit it as a run.

What it does:   collects evidence from this host and commits it as one run
Who runs it:    your normal user
What it writes: one committed run in the evidence store

Options:
  --help         this help
  --source FILE  identity source path (testing)

Exit codes:
  isedraf identity:
    0    completed; every area was collected
    2    completed, but some area is incomplete (expected without root; not a
         security verdict)
    64   usage error or engine error; nothing was committed
    66   another ISEDRAF run holds the lock; nothing was collected or written
    67   the evidence store cannot be used; nothing was collected
    68   too little free space for the run; nothing was committed or deleted
    70   refused under root or sudo; nothing was collected

Examples:
  isedraf identity
```

### `isedraf inventory`

```text
usage: isedraf inventory [--json] [--root DIR]

Read the host inventory now and print it.

What it does:   reads this host now and prints what it found; commits nothing
Who runs it:    your normal user
What it writes: nothing

Options:
  --help         this help
  --json         the normalized inventory object
  --root DIR     filesystem root to read (testing)

Exit codes:
  isedraf inventory:
    0    completed; every area was collected
    2    completed, but some area is incomplete (expected without root; not a
         security verdict)
    64   usage error or engine error; nothing was committed

Examples:
  isedraf inventory
  isedraf inventory --json
```
