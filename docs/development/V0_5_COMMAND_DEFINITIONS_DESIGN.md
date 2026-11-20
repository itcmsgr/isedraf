<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.5 Command definitions, help and completion — design

Status: PLANNING

Batches B1 and B2 implemented 2026-11-13; B3 and B4 in an owner kit, 2026-11-14 (`D-129` point 10) (see section 3).

Design for the v0.5 register items H6 (one command-definition source), H4 (grouped help), H5
(per-command help), H7 (missing-argument guidance), H3 (start page) and C1 (bash completion), in
`docs/development/V0_5_OPERATOR_EXPERIENCE.md`. The register stays the one list of items and their
status; this page says how they are built and in which batch.

Implements: D-129

## 1. Facts (engineering main, 2026-11-13)

| # | Fact | Source |
|---|---|---|
| F1 | The whole user-route command surface is one argparse parser built inline in `main()`: `identity`, `inventory`, `audit`, `report`, `evaluate`, `baseline approve`, `explain`; help strings are argparse `help=` literals | `lib/isedraf/cli.py` (`main`) |
| F2 | `isedraf` with no command prints argparse help to stderr and exits 64; a usage error exits 64 (SCOPE-077) through `_Parser.error` | `lib/isedraf/cli.py` (`_Parser`, `main`) |
| F3 | `--help` and `--version` exit 0 and are tested | `tests/test_cli.py` |
| F4 | Exit codes have one source, with a row per command form, including the four `sudo isedraf` forms; it is owner-controlled | `lib/isedraf/exitcodes.json` (`subcommands`); CLAUDE.md §1 |
| F5 | Under root or sudo, `bin/isedraf` hands every invocation to `launcher/outer.py`, which admits exactly `audit`, `report` (`--json`, `--html`), `evaluate`, `baseline approve` and refuses everything else, `--help` and `--version` included, with exit 70 | `bin/isedraf`; `lib/isedraf/launcher/outer.py` (`main`, `REPORT_INVOCATIONS`, `EVALUATE_INVOCATION`, `BASELINE_INVOCATION`); AUTH-019, AUTH-032, AUTH-033, AUTH-034 |
| F6 | `outer.py` imports only `isedraf.ids` and `isedraf.exitcodes` from the package: the privileged entry is kept small | `lib/isedraf/launcher/outer.py` imports |
| F7 | The native catalog is packaged data read by `catalog.load()`; `explain` lists the admitted IDs only after an unknown ID; a missing ID is an argparse error | `lib/isedraf/catalog/`; `cli.py` (`cmd_explain`) |
| F8 | No completion file, man page or command reference exists; packaged documentation is installed by `packaging/build.sh` under `/usr/share/doc/isedraf/` | repository tree; `packaging/build.sh` |
| F9 | Generated documents are checked for freshness by `make check` (D-89) | `docs/development/DOCUMENTATION_POLICY.md` |
| F10 | Every runtime module must sit in a declared layer; pure modules are listed and may not do I/O | `scripts/ci/check_architecture.py` (`LAYERS`, `PURE`) |

## 2. Design

### 2.1 One definition table

A new pure data module, `lib/isedraf/commands.py`, holds one record per implemented command form:

| Field | Meaning |
|---|---|
| `path` | the words after `isedraf`, for example `("baseline", "approve")` |
| `group` | one of: Getting started · Collect evidence · Evaluate and understand · Approve a reference · View results · Developer |
| `summary` | one line, plain words |
| `effect` | one of COLLECTS (commits evidence) · EVALUATES (writes an evaluation) · APPROVES (writes a baseline) · RENDERS (shows committed evidence, writes nothing unless saving) · READS_DEFINITIONS (reads packaged definitions only) |
| `privilege` | what account runs it and what the sudo form does, if any |
| `writes` | what it writes, or "nothing" |
| `options`, `arguments` | name, help, whether a value follows, and the completion kind (none, file, criterion ID) |
| `examples` | complete command lines, always starting `isedraf` or `sudo isedraf` |
| `exits` | the `exitcodes.json` row key(s) whose codes this form can return |
| `missing` | the guidance shown when a required argument is absent (H7) |
| `sudo_form` | the `sudo isedraf ...` form the root route admits for this command, or none |

Only implemented forms are listed; the table never describes an option that the parser does not accept.
The module does no I/O and is listed as pure in `check_architecture.py`; it is a presentation-layer module.

### 2.2 Everything else is derived

- **Parser.** `cli.main()` builds argparse from the table; each record is bound to its handler by `path`
  in `cli.py`. Argument names, options and help come only from the table.
- **Per-command help (H5).** `isedraf <command> --help` renders: summary, effect in plain words,
  privilege, what it writes, options, exit codes with their meaning from `exitcodes.json`, examples.
  `isedraf baseline approve --help` names the DEV approval and `sudo isedraf baseline approve` as
  separate forms.
- **Grouped overview (H4).** `isedraf --help` lists the commands by group, developer commands last, one
  line each, and points to `isedraf <command> --help`.
- **Missing argument (H7).** A missing required argument prints the record's `missing` text and one
  complete example instead of the bare argparse message; `explain` lists the installed criterion IDs
  (packaged catalog, no evidence read). Exit stays 64 (SCOPE-077).
- **Command reference.** `docs/reference/CLI.md` (planned as generated in the documentation policy) is generated from the table
  by `scripts/docs/cli_reference.py generate|check`; `make check` fails when it is stale (D-89).
- **Completion (C1).** `packaging/completion/isedraf.bash` (batch B2) is generated from the table and the packaged
  catalog's criterion IDs by the same script family, committed, and checked for freshness. It is
  static: it never runs `isedraf`, never reads an evidence store and never offers snapshot IDs, so it
  cannot offer a snapshot argument to `sudo isedraf baseline approve`. Bash only. Installed to
  `/usr/share/bash-completion/completions/isedraf` by both packages (K1).

### 2.3 The root route

The operational routes stay closed constants in `outer.py`; a gate checks that the table's `sudo_form`
set equals the forms `outer.py` admits, and that each `sudo_form` has its `sudo isedraf ...` row in
`exitcodes.json`. Help is the one exception to F6, decided by the owner (Q3, 2026-11-14): `outer.py`
imports the pure command definitions and calls `commands.answer`, the same function the user route
calls, before any other check, so root `--version`, `--help`, `help` and bare `sudo isedraf` (H1) print
the same text from the installed definitions and version, read no evidence, open no store and start
nothing. The accepted help forms are listed explicitly (`HELP_FORMS`, and `help COMMAND` for each
command path and group); the gate runs every form through both routes and requires one answer.
`bin/isedraf` keeps no help text: without the installed package it only refuses, with the refusal of
`outer.py` line for line (H2), which the gate also checks. `AUTH-019` is amended for this (`D-129` point 10).

### 2.4 Consistency gate (H6)

`scripts/ci/check_commands.py`, in `make check` (exit codes are compared with `exitcodes.json`, which is not packaged, so the table carries its codes and the gate holds them equal):
1. every table record has a handler, and every parser command comes from the table;
2. every `exits` key exists in `exitcodes.json`, and every `exitcodes.json` command row except the usage
   row is named by some record;
3. the `sudo_form` set equals the root route's admitted forms (2.3);
4. every example parses with the real parser (the `sudo isedraf` examples against the root route's
   admitted forms);
5. the command reference and the completion file are current.
Each check has a falsification injection in `scripts/ci/falsifiable.sh`.

## 3. Batches

| Batch | Items | Writes | Owner-controlled parts |
|---|---|---|---|
| B1 | H6 table and gate, parser from the table, H4, H5, H7, generated command reference | `cli.py`, `commands.py`, gate, tests, `docs/reference/CLI.md`, GETTING_STARTED | none: exit behaviour unchanged |
| B2 | C1 completion and its packaging (part of K1), lab install check | completion file, `packaging/build.sh`, DEB/RPM | none |
| B3 | H3 start page and `isedraf help` | `cli.py` | new `exitcodes.json` rows (`isedraf help`, and `isedraf` without arguments if it changes from 64) |
| B4 | H1, H2 root help/version and short refusal | `bin/isedraf`, `outer.py` | AUTH-019 amendment; `exitcodes.json` rows |
| later | P1–P6, R1–R5, S1, H8, H9, D2, K1 rest | per register | per register |

B3 and B4 share one owner kit, so `exitcodes.json` changes once.

## 4. Open for the owner (B3/B4 only)

| # | Question | Recommendation |
|---|---|---|
| Q1 | Exit code of `isedraf` with no arguments once it prints the start page | DECIDED (owner, 2026-11-13): the start page, exit 0; it performs no collection, approval or evidence-store write; invalid commands or arguments keep their documented error exits |
| Q2 | `isedraf help <unknown>` | DECIDED (owner, 2026-11-14): exit 64; the unknown command is named and the valid commands are listed; no collection or store access |
| Q3 | Root `--version`, `--help`, `help`: printed by `bin/isedraf` without Python, or by `outer.py` before admission | DECIDED (owner, 2026-11-14): by `outer.py`, before operational-command admission, from the installed command definitions and version; no evidence read, store opened, collection or privileged unit; the accepted forms explicit and gate-checked; no separately maintained help text in `bin/isedraf` |
