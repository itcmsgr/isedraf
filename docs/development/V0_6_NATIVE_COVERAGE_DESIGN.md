<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.6 Native audit coverage — the coverage matrix and design proposal

Status: IMPLEMENTED, released in 0.6.0 (2026-11-24). A historical record of how v0.6 was built and accepted. The fifth fixed operation for authorized_keys is not part of it: V0_6_AUTHORIZED_KEYS_OPERATION_DESIGN.md, PLANNED.

Implements: D-129, D-111, D-125

`D-129` sets v0.6 as "ISE-\* collectors and criteria chosen against a finite coverage matrix
(`D-111`)". No such matrix exists yet; this document proposes it. It admits nothing: admitting a
criterion is an owner amendment, made in one commit with its evaluator (`NATIVE_CONTROL_CATALOG.md`,
"Current state"). Every statement is labelled.

## 1. Facts (engineering `main` `f22a4ed`, 0.5.0)

| # | Fact | Label | Source |
|---|---|---|---|
| F1 | An audit commits 10 sections: inventory, nss, hostname, accounts, sudo, ssh, pam, loginpolicy, mounts, authorizedkeys | REPOSITORY FACT | `snapshot.SECTION_NAMES` |
| F2 | The 8 admitted criteria read 3 of them: accounts (5), ssh (2), loginpolicy (1) | REPOSITORY FACT | `lib/isedraf/catalog/native_controls.json` |
| F3 | 14 families, the `ISE-*` namespace and its scope exclusions are frozen; no family is added for an excluded area | FROZEN REQUIREMENT | `D-111`, `NATIVE_CONTROL_CATALOG.md` |
| F4 | Prototype scope lists accounts, sudo, authorized_keys, password/account aging, SSH, mounts and a `recording` view (auth, SSH, sudo, account change, audit, journal persistence, time-sync quality); "not now": kernel/platform expansion, MAC, services, timers/cron, software, listeners, hardware inventory | REPOSITORY FACT (CLAUDE.md §7, owner-controlled) | `CLAUDE.md` |
| F5 | `isedraf recording` is not implemented; no audit, journal or time-sync section is committed | REPOSITORY FACT | `commands.py`, F1 |
| F6 | Full Audit, Ubuntu 24.04 lab host, 0.5.0: `pam` PARTIAL - "35 of 113 lines could not be read as PAM rules"; `authorizedkeys` PARTIAL - "UNRESOLVED_SOURCE_UNIVERSE for 37 of 37 account(s): CANDIDATE_NOT_OBSERVED" | OBSERVATION (one host) | lab store, sweep of 2026-11-20 |
| F7 | sudo records carry kind (`DEFAULTS`, `SPEC`), principals, hosts, run-as, and per command its tags (for example `NOPASSWD`) | OBSERVATION | same store |
| F8 | each local account's shadow record carries `max_days`, `min_days`, `last_change_days`, `inactive_days`, `expire_days`, each with a source (`OBSERVED`, `UNSPECIFIED`) | OBSERVATION | same store |
| F9 | ssh carries 91 `RESOLVED_SETTING` keywords (`sshd -T`) beside the declared `DIRECTIVE` records | OBSERVATION | same store |
| F10 | loginpolicy carries the declared `login.defs` keys, among them `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE`, `UMASK`, `LOGIN_RETRIES`, `ENCRYPT_METHOD` | OBSERVATION | same store |
| F11 | the active mount options are in `provenance.active.records[]` (`mount_options`, `super_options`) | OBSERVATION | same store |
| F12 | the inventory `time` subdomain records the NTP provider, whether NTP is enabled and whether the clock is synchronized | REPOSITORY FACT | `inventory/collectors.py`, `cli._render_inventory` |

## 2. The coverage matrix

One row per frozen family. *Evidence today* is what F1 commits; *criteria today* is F2; the last
column is a PROPOSAL.

| Family | In §7 scope (F4) | Evidence today | Criteria today | v0.6 proposal |
|---|---|---|---|---|
| ACCOUNT | yes | accounts, nss | 5 | aging facts per account (F8) - see Q2 |
| AUTH | yes | pam, loginpolicy | 1 | PAM: make the collector read the lines it now retains as UNSUPPORTED (F6), then criteria on authentication that always succeeds or accepts an empty password; login.defs aging - Q2 |
| PRIV | yes (local sudo) | sudo | 0 | first PRIV criteria: rules granting every command without authentication (F7); a `Defaults` that disables authentication |
| SSH | yes | ssh, authorizedkeys | 2 | more effective settings (F9): root login, host-based authentication, rhosts; authorized_keys: resolve F6 before any criterion uses it |
| STORAGE | yes (mounts) | mounts (options verified, section 4) | 0 | options of world-writable temporary mounts |
| TIME | yes (time-sync quality, via `recording`) | inventory `time` (F12) | 0 | Q3: whether a criterion may read the inventory section, or waits for a time section |
| LOG | yes (audit, journal persistence, via `recording`) | none (F5) | 0 | Q1 option B: a collector first |
| ASSET | host identity only | inventory, hostname | 0 | none: inventory is described, not judged |
| CRYPTO | not listed | ssh resolved algorithms (F9), `ENCRYPT_METHOD` | 0 (ENCRYPT_METHOD is AUTH-001) | none in v0.6 unless Q1 C |
| KERNEL, SVC, SW, NET | "not now" (F4) | none | 0 | only by Q1 option C, an owner amendment of §7 |
| UPDATE | patch availability excluded (D-09) | none | 0 | none |

## 3. Owner decisions (2026-11-21)

- **Q1 - scope A.** Criteria over the ten committed sections, with their evidence made complete
  enough to evaluate first. B (the `recording` collectors) needs a new decision after A closes. C is
  not in v0.6.
- **Q2 - no arbitrary thresholds.** Every criterion carries a documented interpretation and its
  applicability. Example: a missing password expiry means one thing for an interactive account and
  another for a service account, and the criterion must say which accounts it applies to.
- **Q3 - TIME later**, with the design of its own evidence contract.
- **Q4 - evidence first, then small batches per area.** The number of criteria is what can be
  evaluated correctly, not a target.
- **Documentation in every batch.** The guides, report explanations, CLI reference and status
  registry an operator uses describe the behaviour of that batch; v0.7 keeps the overall audit.

## 4. Evidence gaps, characterised (step 3)

Observed on a 0.5.0 Full Audit, Ubuntu 24.04 lab host (`F6`, `F11`). The classes are the owner's:
parser defect, access limitation, unknown applicability, genuinely incomplete data.

| Section | Observation | Cause | Class | Label |
|---|---|---|---|---|
| pam | 35 of 113 lines retained as `UNSUPPORTED`; status PARTIAL | Every one of the 35 is an `@include <file>` line (`@include common-auth`, `common-account`, `common-password`, ...), the Debian and Ubuntu form. The parser models `include` and `substack` as a control value and nothing else; neither the PAM lane contract nor the code mentions `@include` | **parser defect** (valid syntax never modelled) | REPOSITORY FACT (records, `pam/sources.py`, `PAM_LANE_CONTRACT.md`) |
| pam | which files `@include` reads and in what order | a Debian-family libpam patch, not upstream; verified in section 4a | resolved | EXTERNAL INFORMATION and OBSERVATION (section 4a) |
| authorizedkeys | PARTIAL: "UNRESOLVED_SOURCE_UNIVERSE for 37 of 37 account(s)"; 148 candidate files: 84 `PERMISSION_DENIED` (`/root/.ssh`, `/home/*/.ssh`, `/etc/ssh/keys`, all mode 0700), 64 `NOT_FOUND` | The Full Audit reads with privilege only through four fixed operations (`read_shadow_v1`, `read_sudoers_graph_v1`, `read_sshd_declared_config_v1`, `resolve_sshd_effective_config_v1`); no operation reads `authorized_keys`, so the engine reads them unprivileged | **access limitation** by the privilege model, reported honestly as `NOT_TESTED` | REPOSITORY FACT |
| mounts | `COLLECTED`; the active options are in `provenance.active.records[]` (`mount_options`, `super_options`, `fstype`, `mount_point`) | none: the evidence is complete | **no gap** (the options' location was unverified, now verified) | REPOSITORY FACT |

Consequences for scope A: PAM criteria wait for the `@include` parser change. authorized_keys
criteria under a Full Audit need a fifth fixed operation, a change of the frozen Full Audit authority
model (`AUTH-017` to `AUTH-027`) - an owner decision, never a widened capability. Until then any
authorized_keys criterion would be `NOT_EVALUATED` wherever keys sit under a private directory.

## 4a. PAM `@include`: verified semantics and the parser change

| # | Fact | Label |
|---|---|---|
| P1 | Upstream Linux-PAM (`libpam/pam_handlers.c`, `master`) has no `@include`; it has the `include` and `substack` control values only | EXTERNAL INFORMATION (upstream source, read 2026-11-21) |
| P2 | Debian's patch `031_pam_include` (bookworm `1.5.2-6+deb12u2`) adds `@include` in the **type** field, matched case-insensitively. The next token is the target: an absolute path is loaded directly, a name is resolved under the PAM configuration directory. The file is loaded for the type being parsed, so across libpam's per-type passes every type of the file is spliced in. A missing or unreadable file makes the entry must-fail: it fails closed, it is not skipped | EXTERNAL INFORMATION (Debian source) |
| P3 | Ubuntu 24.04 libpam `1.5.3-5ubuntu5.7` carries the handler (its binary contains the `@include` strings); 13 files in `/etc/pam.d` use it. Rocky 9.7 `pam-1.5.1-26.el9_6` has no handler and no file uses it | OBSERVATION (lab hosts) |
| P4 | A separate nesting limit for `@include` is not shown by the patch | not confirmed |

**Parser change (built, parser version 2, 2026-11-23).** An `@include <target>` line becomes an `EDGE` record with `edge` =
`AT_INCLUDE`, `type` = `ANY` (every type), and the target, resolved as P2 says. The stack resolution
follows it like `include`, for every type. A target that is missing or unreadable is recorded as a
must-fail edge, an observation of what libpam would do, never a silently empty stack. The syntax is
read only where the platform's libpam supports it: on a host whose libpam has no handler (P3, Rocky), an
`@include` line stays `UNSUPPORTED`, because there libpam itself would not include it. The PAM
collector reads the family from `/etc/os-release` itself (`ID`, `ID_LIKE`; never a binary) and records
the basis in its provenance (`at_include_basis`). Nesting is bounded by the existing edge depth limit
(16), with a reason. The section
gets its own `parser_version` (`"2"`). Tests (`tests/test_pam.py`, `AtInclude`): Debian and Ubuntu
(followed), the directive in capitals, Rocky (unsupported, with the reason), no os-release (not
established), a missing target, an absolute target (never read), a cycle through `@include`, a
malformed `@include` (no target, two targets), the parser version. An unreadable target takes the
existing `UNREADABLE_SERVICE` path; two injections prove the tests catch a regression.

## 5. Comparability before any collector change (step 4)

| Question | Answer | Label |
|---|---|---|
| Is a section file part of host-state identity? | No. `sections/*.json` are auxiliary artifacts bound by `manifest_hash`; `state_hash` covers host identity only (`snapshot.py`, SNAP-020, D-115) | REPOSITORY FACT |
| Does a PAM, sudo, mounts or authorized_keys change move a 0.5 baseline comparison? | No. The baseline profile `v0.4-default-1` projects host identity, accounts, ssh and loginpolicy only (`baseline/projection.py`) | REPOSITORY FACT |
| How is a collector or parser change recorded? | Every section records `collector_id`, `collector_version`, `parser_version`; today `audit.METHODS` gives every section `"1"` | REPOSITORY FACT |
| What the PAM change needs | its own `parser_version` (`"2"`) so a criterion can tell the two formats apart; old snapshots stay readable and verify unchanged (their own manifests bind them); a PAM criterion evaluates only the new format and gives `NOT_EVALUATED` with a reason on an old one, never a PASS or FAIL from a method it does not support | PROPOSAL |
| Upgrade on an unchanged host | `state_hash` and the baseline comparison stay identical; only the PAM section file differs, with the new `parser_version`: no security change is reported | PROPOSAL, to be proven in the acceptance (upgrade from published 0.5.0) |

A change to a baseline-profile section (accounts, ssh, loginpolicy) is different and follows the
comparability contract: a method change with identical state is silent, a different state is
`REVIEW_REQUIRED`, never drift.

## 6. Criteria, by evidence (step 5)

No candidate is admitted here. Each comes to the owner as a registry record with its evaluator and
tests, stating applicability, the evidence fields it reads, its results and their meaning, its
limitations, and how it treats context. The presence of a tag or a module is never a result by itself:
`NOPASSWD` matters by whom it is granted to and for what; `pam_permit.so` by its type, control and
place in the stack.

| Area | Evidence ready | Candidate subject (to be evaluated for sufficiency, not a list to fill) |
|---|---|---|
| PRIV | sudo: `SPEC` records with principals, hosts, run-as and per command the tags (F7) | delegation of every command without authentication; a `Defaults` that disables authentication |
| SSH | 91 resolved settings (F9) | root login, host-based and rhosts authentication, as effective global settings |
| STORAGE | active mount options (section 4) | protection options of world-writable temporary mounts |
| ACCOUNT | per-account aging with its source (F8) | per Q2: conditions that need no number, with interactive and service accounts told apart |
| AUTH | after the PAM parser change | authentication that always succeeds; empty passwords accepted |

## 6a. First PRIV batch: two criteria, for owner review (2026-11-23)

**Revised by the owner, 2026-11-23, and now held by the registry records** (`lib/isedraf/catalog/native_controls.json`,
the authority): an `/etc/sudoers` that is not found gives `NOT_EVALUATED` (never `NOT_APPLICABLE`, which
neither criterion produces); a negation that decides the answer gives `MANUAL_REVIEW`; an unresolved
candidate blocks `PASS`; ISE-PRIV-002 identifies a scope by its type and each member as written, orders
settings by line within one file only, and gives `MANUAL_REVIEW` for an alias or negated scope and for
settings that disagree across files. The tables below are the first proposal, kept for the record.

PROPOSAL. Nothing is admitted until the owner approves these definitions; then registry records,
evaluators, tests, the catalogue, explain pages and guides come as one owner kit with the frozen
admission text.

**What the evidence gives, and does not (REPOSITORY FACT, `sudo/model.py`).** Every `SPEC` record has
its principals (`USER`, `GROUP`, `USER_ID`, `GROUP_ID`, `NETGROUP`, `NONUNIX_GROUP`, `ALIAS_REFERENCE`,
`ALL`, each with a negation flag), the host, the run-as users and groups (absent means root), and per
command the tags in force (`NOPASSWD`, carried forward as sudo carries them). `DEFAULTS` records carry
their scope (global, user, run-as, host, command) and options with a negation flag. The evidence is the
**declared** policy: aliases are recorded, not resolved; group membership is not consulted; host and
command matching and sudo's last-match precedence are not applied. `/etc/sudoers` and its includes are
read only by a Full Audit (`read_sudoers_graph_v1`); a Standard Audit records them `NOT_TESTED`.
Neither criterion treats a tag or an option by itself as a result: each defines the context in which
it decides, and sends every other context to `MANUAL_REVIEW` or outside its scope.

New check type for the PRIV family: `local sudo delegation`.

### ISE-PRIV-001 - Every Command as Root Without Authentication

| Field | Proposal |
|---|---|
| Purpose | Detect rules in the declared local sudo policy that let a principal other than root run every command, as root, on any host, without authenticating. |
| Severity | high |
| Minimum run | Full Audit (the sudoers files are read only through `read_sudoers_graph_v1`) |
| Applicability | Every host with a local sudo policy. `NOT_APPLICABLE` only when the Full Audit's fixed read finds no `/etc/sudoers` (sudo not configured). |
| Evidence sufficient when | the sudo section is `COLLECTED`; the fixed operation's coverage for `/etc/sudoers` is `COLLECTED`; every include resolved; no `UNSUPPORTED` record |
| FAIL | a `SPEC` whose host is `ALL`, whose run-as is absent or includes `ALL` or `root`, and which carries the command `ALL` (not negated) with `NOPASSWD` in force, for a principal that is not exactly the user `root`, with no alias reference in its principals, host, run-as or commands. The result names each such principal and its file and line. |
| MANUAL_REVIEW | no FAIL, but a `SPEC` with `NOPASSWD` in force whose principal, host, run-as or command is an alias reference, or whose host is a named host: the declared policy may grant every command without authentication, and only a person resolving the alias or the host can say. |
| PASS | the evidence is sufficient and neither of the above. |
| NOT_EVALUATED | the evidence is not sufficient (Standard Audit, a refused or partial read, an unresolved include, an unsupported line). |
| Limitations | Declared policy only. sudo's last-match rule is not applied: a later rule may require a password for the same user, so FAIL states the declared grant, not sudo's decision for one user. A `%group` grant is reported for the group; its members are not resolved. `NOPASSWD` on a named command list is outside this criterion (it is not "every command"). `Defaults !authenticate` is ISE-PRIV-002. LDAP and SSSD sudo rules are not read. The user `root` is excluded: it needs no sudo. |

### ISE-PRIV-002 - Authentication Disabled by sudo Defaults

| Field | Proposal |
|---|---|
| Purpose | Detect `Defaults` settings in the declared local sudo policy that turn authentication off (`!authenticate`), for every rule or for a scope. |
| Severity | high |
| Minimum run | Full Audit |
| Applicability | as ISE-PRIV-001 |
| Evidence sufficient when | as ISE-PRIV-001 |
| FAIL | for some scope (the global one, or one user, run-as, host or command scope as written), the last `authenticate` option in the order sudo reads the files is negated. The result names the scope and the file and line. |
| PASS | the evidence is sufficient and no scope ends with `!authenticate`. |
| NOT_EVALUATED | as ISE-PRIV-001 |
| Never produced | `MANUAL_REVIEW` (an option either is or is not negated in a scope as written) |
| Limitations | Declared `Defaults` only. Scopes are compared as written: an alias used as a scope is not resolved, and precedence between scope types is not computed (a global `!authenticate` that a `Defaults:alice authenticate` re-enables for one user is still a FAIL for the global scope). `rootpw`, `targetpw` and `runaspw` are not assessed. |

On the lab hosts the lab account's own rule (`lab ALL=(ALL) NOPASSWD: ALL`) would give ISE-PRIV-001
`FAIL`: an expected result of the definition, recorded as such in the acceptance, never suppressed.

## 7. The native criteria catalogue (owner decisions, 2026-11-21; D-130)

`docs/reference/NATIVE_CRITERIA.csv`, generated by `scripts/docs/criteria_catalogue.py` from
`lib/isedraf/catalog/native_controls.json`: one row per criterion the release delivers. Candidates
are not in the registry, so they are never in the file.

**Format (decided).** UTF-8 **without** a byte-order mark; no ASCII-only restriction on the registry
(Excel imports UTF-8 through Data > From Text/CSV, choosing the encoding); RFC 4180 quoting; CRLF
line ends; one line per cell, lists joined with ` | `. A cell that a spreadsheet would run as a
formula (`=`, `+`, `-`, `@`) is refused by the gate, never escaped.

**The 15 columns (decided).**

| Column | From the registry |
|---|---|
| `criterion_id` | `criterion_id` |
| `family` | the ID's family, without `ISE-` (`ACCOUNT`, `AUTH`, `SSH`, ...) |
| `title` | `title` (new field) |
| `description` | `purpose` |
| `lifecycle` | `lifecycle` (new field; every criterion `EXPERIMENTAL`, D-80) |
| `criterion_version` | `version` - changes to the criterion itself |
| `introduced_in_release` | `introduced_in` (new field) - the ISEDRAF release that first delivered it, never the criterion's version |
| `default_severity` | `default_severity` |
| `check_type` | `check_type` |
| `evidence_sections` | the `sections/*.json` artifacts of `evidence_pointers` |
| `collection_requirements` | `minimum_run` (new field: route and reason), stated as **necessary, not sufficient**, followed by `evaluation_semantics.evidence_sufficient_when` |
| `applicability` | `applicability` |
| `result_meanings` | `evaluation_semantics.rules` (result: when) and `never_produced` |
| `limitations` | `limitations` |
| `documentation` | `isedraf explain <ID>` and `docs/reference/criteria/<ID>.md`, installed at the same relative path under `/usr/share/doc/isedraf/` |

**Held by** `check-native-catalog`: the file is regenerated byte for byte from the registry; its IDs
and row count equal the registry's; no byte-order mark; no formula cell. The package payload check
requires the file and every criterion page it links (fourteen in 0.6.0) in the package. Validated by a CSV parser round trip;
the 14-row file was also checked visually in a spreadsheet application by the owner (2026-11-24).

**Explain.** `isedraf explain` also shows the title, the release that introduced the criterion and the
minimum collection route. Its baseline and delta lines describe the capability - a baseline belongs
to an evidence store, shown by `evaluate` and the report - instead of the stale "not available:
baseline and delta are v0.4" (`EVAL-009` as amended by D-130).

The four fields change what a criterion contains (`NATIVE_CONTROL_CATALOG.md`, frozen): an owner kit
for D-130.

## 7a. Report additions (D-132, point 3)

Both read the committed sections of the reported run (`report/model.py`); neither is evaluated,
neither has a threshold, and the evaluation artifacts are not touched.

| Addition | Source | Shown | States |
|---|---|---|---|
| `pam_unix` `nullok` | PAM section: `RULE` records of type `auth` whose module's base name is `pam_unix.so` and whose arguments include exactly `nullok` | beside `ISE-ACCOUNT-002`, with service, file and line; also when the run has no evaluation | `OBSERVED`; `NOT_OBSERVED` (PAM area COLLECTED); `NOT_ESTABLISHED` (none found, PAM area incomplete); `NOT_COLLECTED` (no PAM evidence) |
| Maximum password age | accounts section: each local account's `shadow.max_days` and `max_days_source` | one row per account, `/etc/passwd` order | `NO_LIMIT` (field empty); `DAYS` (the number as written: 99999 and -1 are numbers, not reinterpreted); `NOT_COLLECTED` (no shadow record, shadow not read, or a malformed field, each named) |

The criterion's row keeps the result of the committed evaluation, `NOT_EVALUATED` included
(`tests/test_report_additions.py`). The report schema version is 5.

## 8. Order

1. Documentation alignment and CI reconciliation (step 1, 2) - done in `d1c83ec`.
2. Owner kit for D-130: the catalogue fields of section 7, the CSV, its gate and packaging, the explain correction; a second owner kit: the remaining "codename" in owner-controlled files (D-108).
3. PAM: confirm the `@include` semantics, then the parser change with its own `parser_version`,
   with normal, malformed, missing and permission fixtures.
4. Batches per area (section 6), each an owner commit with evaluators, tests and documentation.
5. Acceptance: installed DEB and RPM, upgrade from the published 0.5.0, evidence, evaluations and
   baselines preserved, both routes, the 80-column sweep; coverage stated per supported platform.
