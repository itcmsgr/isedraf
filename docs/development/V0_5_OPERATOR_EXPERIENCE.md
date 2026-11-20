<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.5 Operator experience — scope register

Status: PLANNING

The one register of v0.5 work items (`D-129` point 3). Each item appears once, with its acceptance
condition, implementation status and documentation impact. Release scope itself is the roadmap's; this
page details it. Recording an item here does not make it implemented. Findings of the junior-operator
walkthrough (lab host, Ubuntu 24.04, 0.4.0-rc1, from 2026-11-12) are folded in and marked with their
finding number (U-n).

Implements: D-129

Design and batches for H3–H7 and C1: `docs/development/V0_5_COMMAND_DEFINITIONS_DESIGN.md`. The batch plan for the remaining items: `docs/development/V0_5_REMAINING_BATCHES.md`. Release evidence: `docs/development/V0_5_RELEASE_ACCEPTANCE.md`. Batch B1 (2026-11-13): the command table, `isedraf --help` grouped, per-command `--help`, missing-argument guidance, the generated [command reference](../reference/CLI.md) and its gate. Batch B2 (2026-11-13): bash completion generated from the same table, installed by the DEB and RPM with the command reference; verified from the installed packages on Ubuntu 24.04 and Debian 12 (bash-completion present) and AlmaLinux 9.7 and 8.10 (absent), evidence `b2-completion-20261113`. Those four installations are development builds of commit `e35be2d` that display `0.4.0` because the version was not yet bumped: they are not validation of the published 0.4.0 packages. From 2026-11-14 development builds are versioned `0.5.0-dev` and carry their source commit in the package version and in `/usr/share/doc/isedraf/SOURCE`. Batches B3 and B4 (owner kit, 2026-11-14, `D-129` point 10): the start page for `isedraf` and `isedraf help`, `isedraf help --all`, `isedraf help <command>` (an unknown command exits 64), and under sudo or root the same help and version answered before admission (`AUTH-019` as amended for v0.5), with the refusal one command per line. Committed as `d9d0472` (tree `09297c66`). Verified from installed packages on Ubuntu 24.04, Debian 12 and AlmaLinux 9.7 (evidence `b34-help-20261114`): those packages were built from the dry-run commit `91517e7` of the same tree (development build `0.5.0~dev.20261114085644.g91517e7123d6`); packages rebuilt from `d9d0472` have byte-identical payloads apart from `/usr/share/doc/isedraf/SOURCE`, which names the commit. AlmaLinux 8.10: see H10.

Status values: DESIGN (to be designed before it is agreed) · PLANNED (agreed, not started) · IN PROGRESS · IMPLEMENTED (code, tests and documentation
committed) · VERIFIED (installed packages proven on the lab).

## Help

| ID | Item | Acceptance condition | Status | Documentation impact |
|---|---|---|---|---|
| H1 | Root `--version`, `--help`, `help` (U2) | Under root or sudo they print and exit 0, read no evidence, open no store and start no unit; every other unadmitted invocation is still refused with 70; an `AUTH-019` amendment admits them | VERIFIED (except stock AlmaLinux 8: H10) | AUTH-019 (owner kit); GETTING_STARTED refusal table |
| H2 | Short refusal text (U3) | The refusal lists what runs under sudo, one command per line, and says to run everything else as the normal user | VERIFIED | AUTH-019 message (owner kit); GETTING_STARTED |
| H3 | `isedraf` and `isedraf help`: a short start page (U4) | No arguments prints a start page: what ISEDRAF does, Standard Audit and Full Audit distinguished, the workflow with complete commands (`isedraf audit`, `isedraf evaluate`, `isedraf report`; `sudo isedraf audit`), baseline approval named as an explicit decision, never as an automatic next step; a pointer to `help --all` and to `/docs` | VERIFIED | README quick start; GETTING_STARTED |
| H4 | `isedraf help --all`, grouped | Every implemented command, grouped: Getting started · Collect evidence · Evaluate and understand · Approve a reference · View results; developer commands (`identity`, `inventory`, the DEV baseline) in their own group; only implemented options | VERIFIED | command reference generated from the command definitions |
| H5 | Per-command `--help` | Each command states its effect in plain words (collects evidence / writes an evaluation / approves a baseline / renders existing evidence), its privilege, what it writes, its exit meanings from `exitcodes.json`, and complete examples; `baseline approve --help` separates DEV approval from `sudo isedraf baseline approve` | IMPLEMENTED | command reference |
| H7 | Missing-argument guidance (U15) | A missing argument gives a short explanation and a complete valid example: `isedraf explain` lists the installed criterion IDs and shows `isedraf explain ISE-ACCOUNT-001`; `isedraf baseline approve` in a user store explains that baselines come from Full Audit (`sudo isedraf baseline approve`) and, in a DEV store, how to find a snapshot ID; a raw argparse error is never the only output | IMPLEMENTED | command reference |
| H8 | Refusals in operator language (U16) | Refusal text leads with plain words ("this is your personal store; production baselines come from Full Audit"); the stable reason token (for example `BASELINE_CLASS_NOT_ADMITTED`) stays, for diagnosis and automation, with requirement IDs as a trailing reference | IMPLEMENTED (B8: plain words, the reason token whole, what was written, the next command; approval, root-route and store refusals; `D-129` point 12) | GETTING_STARTED refusal table |
| H9 | Account switched through sudo (U10) | When `SUDO_USER` is set for a non-root user (for example `sudo -iu alice`), the refusal names the detected execution context (a session started through sudo) and the supported way to run (log in as the user, or `su - alice`); the SCOPE-071 rule is not weakened | IMPLEMENTED (B8: the refusal names the sudo-started session and the supported way; `SCOPE-071` unchanged) | GETTING_STARTED refusal table |
| H6 | One command-definition source | Help, the command reference and completion are derived from the same definitions; a gate fails when they disagree | IMPLEMENTED | DOCUMENTATION_POLICY note |
| H10 | Root help where `/usr/bin/python3` is absent (stock AlmaLinux 8, lab 2026-11-14) | OPEN compatibility decision for v0.5. Today, by `AUTH-020`, the root route runs only `/usr/bin/python3`; a stock AlmaLinux 8 host has only `platform-python`, so `sudo isedraf --help`, `--version` and `help` are refused there with 70 and a last line naming the missing interpreter, while `isedraf help` as the normal user works. Not to be worked around by widening the privileged interpreter route or by duplicate help text in `bin/isedraf` (owner, 2026-11-14) | DECIDED (owner 2026-11-16): `/usr/bin/python3` kept for v0.5; the refusal states the limitation; another interpreter is a separate topic (IQ-078 resolved) | GETTING_STARTED (stated); IQ-078 |

## Completion

| ID | Item | Acceptance condition | Status | Documentation impact |
|---|---|---|---|---|
| C1 | Bash completion (U5) | Tab completes commands, subcommands, options and criterion IDs from installed definitions and the installed catalog; it never reads an evidence store; it never offers a snapshot argument to `sudo isedraf baseline approve`; supported shells are stated (bash) | VERIFIED | GETTING_STARTED; packaged |

## Presentation

| ID | Item | Acceptance condition | Status | Documentation impact |
|---|---|---|---|---|
| P1 | Common compact header (U6) | Every human-readable output starts with one ASCII header: product, version, command; for evidence output also the mode, the snapshot and its collection time, taken from the evidence, never live host data; no header, colour or progress text in `--json` | IMPLEMENTED (B5, B6; reports keep their own title block - product, version, report ID, generation time - as their header) | REPORT_GUIDE; README sample |
| P2 | Audit summary (U7, U8, U9) | After a run: what happened (committed; complete or incomplete), coverage counts (COLLECTED / PARTIAL / NOT_TESTED / ERROR), one short reason per non-COLLECTED area with what would change it, where it is (snapshot and "your personal evidence store" or the system store), the next complete commands; states that exit 2 is expected without root and is not a security verdict | IMPLEMENTED (user route; the Full Audit route is P4, B6) | GETTING_STARTED; EVIDENCE_MODEL |
| P4 | Consistent summaries on both routes (U11, U13) | User and Full Audit routes show the same summary fields (snapshot, collection time, coverage counts, next complete commands; for evaluate, the baseline comparison line: baseline, applicability, per-section result) while naming their different store and authority (personal store, unprivileged / system store, Full Audit) | IMPLEMENTED (B6: the Full Audit engine prints the same summary, saying the run was collected, and the launcher states the commit; evaluate and approve name the next command) | GETTING_STARTED |
| P5 | Approval as an explicit, non-interactive decision (U12) | Owner decision 2026-11-13: no prompt and no `--yes`; `sudo isedraf baseline approve` is the decision. Before writing it shows the selected snapshot, its collection time, the profile, every required section with its status, and that it is the production (system) store, and states: "Approval records accepted state; it does not establish that the host is secure." On success it shows the approved revision and snapshot. On refusal it names every blocking section and confirms that nothing was written | IMPLEMENTED (B6: both routes show the run, its collection time, the store, the profile and every required section with its status before anything is written, and the "accepted state, not secure" statement; refusals already named every blocking section and that nothing was written) | GETTING_STARTED |
| P6 | Read-only baseline preview (design item) | If introduced: it shows what approval would select and why, and writes nothing; approval still selects and validates the latest run itself, independently, under the lock, so an earlier preview never implies that a different run was reviewed | DESIGN | GETTING_STARTED (if adopted) |
| P3 | Readable errors | Every refusal says what failed, whether anything was written, and the exact next command when one applies | IMPLEMENTED (B5 user route; B8 approval, root and listing refusals) | GETTING_STARTED refusal table |

## Reports

| ID | Item | Acceptance condition | Status | Documentation impact |
|---|---|---|---|---|
| R1 | Discover existing evidence and reports | A read-only way to list committed runs, saved reports and the baseline status, so no ID is copied by hand from directories | IMPLEMENTED (`isedraf list`; `sudo isedraf list` read-only under `AUTH-035`, B8) | GETTING_STARTED; REPORT_GUIDE |
| R2 | Save explicitly, show the path | Saving prints the exact absolute filename and how to view it; a normal user may choose a visible destination with private permissions; under root no user-chosen output path (CLAUDE.md) | IMPLEMENTED (`report --save`: absolute path on stdout, how to view it on stderr; choosing another visible destination is not implemented) | REPORT_GUIDE |
| R4 | Root report export (U14) | Under sudo, `--save` stays unavailable (no root-chosen output path); the refusal and the guide name the supported export through the operator's own shell, with private permissions and no silent overwrite, for example `(umask 077; set -o noclobber; sudo isedraf report > ~/isedraf-report.md)`, and explain why a plain `>` can create a file other users can read or replace an existing one | IMPLEMENTED (REPORT_GUIDE, the report help, the root refusal and the system listing show the private, no-overwrite export; B8) | REPORT_GUIDE; GETTING_STARTED |
| R5 | A report a junior can read (U17) | The report opens with coverage, the native results and the baseline comparison, then the evidence detail; hashes and internal terms follow in the technical part; every view (Markdown, HTML, JSON) shows the same canonical results | IMPLEMENTED (B10: Markdown and HTML open with coverage, the native results and the baseline comparison; target, evidence detail and digests follow; JSON is the same model) | REPORT_GUIDE; sample report |
| R3 | Explain private storage | Output and documentation explain that evidence lives in the user's private 0700 store (or the root-only system store) and why | IMPLEMENTED (the audit summary and `isedraf list` state it; EVIDENCE_MODEL says why the store is private and how to share deliberately; B10) | EVIDENCE_MODEL; GETTING_STARTED |

## Reliability

| ID | Item | Acceptance condition | Status | Documentation impact |
|---|---|---|---|---|
| S1 | Free-space preflight (`STORE-016`, `STORE-022`) | Before any commit the available space is checked with headroom for the commit and a recovery record; insufficient space refuses before collection with a named reason, writes nothing, and says how much is needed and what to do; never deletes anything | IMPLEMENTED (`D-129` point 11, commit `1ea391a`; lab: refusal and normal run on Ubuntu 24.04 and AlmaLinux 9.7, evidence `s1-space-20261115`). Open for v0.5 acceptance (owner, 2026-11-15): a lab check of the Full Audit refusal for space, and of space running out during the commit or a recovery; both are unit-tested only | GETTING_STARTED refusal table; exit-code registry if a code is assigned |

## Documentation and packaging

| ID | Item | Acceptance condition | Status | Documentation impact |
|---|---|---|---|---|
| D1 | One `/docs` tree, aligned as each item lands | Each item above updates its guides in the same commit; the v0.5 release gate checks command/reference/completion consistency, valid links, working examples and current generated files | IMPLEMENTED (B10: the command gate also checks every isedraf command in the guides' shell blocks; links, generated files and command/reference/completion consistency were already gated) | all |
| D2 | Install instructions (U1) | Install documentation shows `apt install ./isedraf_*_all.deb` and `dnf install ./isedraf-*.noarch.rpm` with the `./`, and the Tab tip | IMPLEMENTED (B10: README and GETTING_STARTED keep the `./` and say why; the Tab tip is in GETTING_STARTED) | README; GETTING_STARTED; release notes |
| K1 | Completion and offline docs in the packages | The DEB and RPM install the bash completion and the selected offline documentation; both formats ship the same set; installation and upgrade from 0.4 verified on the lab | IN PROGRESS | packaging notes |

## Preserve

Existing helpful behaviour is kept and improved, never duplicated by a second mechanism: the absolute path
printed by `report --save`, and the next-command hints (`Render it with: isedraf report`, `run isedraf
explain <criterion>`).

## Not in v0.5 (assigned elsewhere, `D-129`)

Pruning, retention and checkpoints (deferred, registered); delegated reporting and groups; package
repositories; report delivery beyond export (export-only); framework integrations (v0.8 onwards).

## Walkthrough log

| Finding | Where folded |
|---|---|
| U1 `apt install` needs `./`; `~rc1` hard to type | D2 |
| U2 root cannot run `--version` / `help` | H1 |
| U3 the root refusal is one long line | H2 |
| U4 bare `isedraf` prints raw usage, developer commands first | H3, H4 |
| U5 no tab completion (`audit` typed alone) | C1 |
| U6 audit output headed "host identity" | P1 |
| U7 PARTIAL / NOT_TESTED without reason or next step | P2 |
| U8 internal class names (`USER_PRODUCTION`) | P2, R3 |
| U9 exit 2 reads as failure | P2 |
| reports "hidden" in the private store | R1, R2, R3 |
| U10 a user entered through `sudo -iu` is refused as if root (SUDO_USER set) | H9 |
| U11 `sudo isedraf audit` prints coverage only: no snapshot, store or next step | P4 |
| U12 `sudo isedraf baseline approve` approves at once, without showing what | P5 (decided: summary, no prompt), P6 |
| U13 `sudo isedraf evaluate` shows no comparison line | P4 |
| U14 `sudo isedraf report --save` refused with the generic message | R4 |
| U15 `explain` / `baseline approve` without an argument: raw argparse errors | H7 |
| U16 refusals in requirement IDs and class names | H8 |
| U17 the report is long and hash-heavy before its results | R5 |

Walkthrough evidence: lab host Debian 12 (fresh accounts and a fresh system store, 0.4.0-rc1 from
`a1910d7`), owner lab evidence store `ux-walkthrough-20261113`; and the owner's session on an Ubuntu
24.04 host. A bounded RPM walkthrough (Rocky Linux 9.7, SELinux enforcing, same build and steps) showed
no platform-specific interface difference: messages, refusals, exit codes, approval and evaluation output
are the same; only collection results differ (`pam`, and `inventory` under Full Audit).

**The walkthrough is closed (owner, 2026-11-13).** These findings finalize the v0.5 UX scope; the
implemented changes are validated during v0.5 acceptance. They do not reopen v0.4.

The walkthrough continues; new findings are added here once.
