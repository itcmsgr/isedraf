# ISEDRAF — Decisions Register (input to all prompts)

Owner: Antonios Voulvoulis / ITCMS · Frozen status is defined externally by membership in `FROZEN_MANIFEST.sha256`
Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0

Decisions marked **D-** are frozen. Items marked **OD-** are open decisions that documents must
carry forward, not silently resolve. Amendment IDs **A1–A19** refer to the final HLD challenge.

---

## 1. Identity and positioning

- **D-01** "ISEDRAF" is an internal codename. Public name pending GitHub/domain/EU trademark
  clearance (existing cybersecurity company uses the name).
- **D-02** License MPL-2.0. Copyright © 2026 Antonios Voulvoulis / ITCMS.
- **D-03** Philosophy: *Measure once. Map everywhere. Fix only the delta.*
- **D-04** Product: open-source Linux **host** assurance, state-delta and evidence bridge between
  sysadmins, security engineers, auditors and governance workflows. "360°" only as "host".
- **D-05** Not another OpenSCAP/ComplianceAsCode/Lynis/osquery/Wazuh. No XCCDF/OVAL internally,
  no 1000-rule catalog, no compliance-percentage calculator.
- **D-06** Differentiation = combination of: daemon-free one command; readable/auditable source;
  explicit evidence boundary; approved-baseline workflow; granular change acceptance;
  declared/resolved/active distinction; classified delta; separate collection vs evaluation truth;
  explicit NOT_TESTED; tool integrity verification; portable evidence; operator and auditor views
  from the same data. Never claim competitors "cannot" collect, export or track changes.

## 2. Evidence boundary

- **D-07** Core assesses only state directly observable on the local OS.
- **D-08** Permanently out of core: firewall products/rulesets (nftables, iptables, firewalld, ufw,
  CSF/LFD), AV, EDR/XDR, IDS/IPS, WAF, SIEM, cloud/network controls, external backup, remote
  repository patch availability, CVE matching, whole-filesystem FIM, remote attestation,
  organizational "required agent" checks.
- **D-09** Absence of a locally detectable external agent SHALL NOT be interpreted as absence of
  the control.
- **D-10** Local kernel network sysctls and listening sockets are in scope as local facts;
  listeners are inventory/drift only, never "exposed".
- **D-11** Framework reports (when added) must show coverage: host-assessed / partial /
  NOT_HOST_ASSESSABLE with reason class (NETWORK_CONTROL, ENDPOINT_PRODUCT, ORGANIZATIONAL,
  EXTERNAL_DEPENDENCY).

## 3. Runtime and code

- **D-12** *(revised 2026-09-18)* Bash only where a shell sequence is genuinely required. Python
  **standard library only** for orchestration, parsing, normalization, delta, hashing, rendering.
  **Two floors, because they answer different questions.** Production code that runs on a target host
  is written to a **Python 3.6 language and API level**; development, test and certification tooling is
  **not** constrained and may require a newer interpreter, because it never runs on a target host. The
  normative statement is `EXEC-016`; this register does not restate it (`NRM-001`). No Go, no compiled
  components, no third-party runtime Python packages, no plugin framework in v0.1.
- **D-13** Collectors collect, engine interprets. Prefer fixed-argv subsystem tools that resolve
  their own config: `sshd -T`, `cvtsudoers -f json`, `findmnt -J`, `systemctl show`,
  `timedatectl show`, `auditctl -s/-l`, `journalctl --header`, `aa-status --json`, `getenforce`.
  No PASS/FAIL in Bash. No `set -e` reliance in collectors.
- **D-14** Capability-driven, never distro-driven (e.g. SD-MAC-001, not SD-SELINUX-001).
- **D-15** Controls, mappings and profiles are JSON data, never sourced or executed. JSON Schema
  validation in CI; minimal structural check at runtime.
- **D-16** Engine size budget for prototype ~5k lines; one evaluator module per domain;
  `docs/AUDITING_ISEDRAF.md` explains how to audit the tool itself.

## 4. Execution hygiene

- **D-17** Entry `#!/usr/bin/python3 -IB`; install under `/usr/lib/isedraf`; no `.pyc` in package
  (byte-compile disabled, CI gate). Before inserting `/usr/lib/isedraf` into `sys.path`, verify it
  and all parents are root-owned and not group/world-writable, else refuse (`ENGINE_UNSAFE_INSTALL`).
- **D-18** Subprocess: argv list, `shell=False`, empty env + `PATH=/usr/sbin:/usr/bin:/sbin:/bin`,
  `LC_ALL=C`, timeout, bounded output, `stdin=DEVNULL`; Bash via `--noprofile --norc`.
- **D-19** Forbidden: `eval`, `exec`, `pickle`, dynamic imports from content paths, shell
  interpolation of system-derived strings, unescaped HTML. CI grep gate.
- **D-20** `umask 077`; directories 0700, files 0600; `O_NOFOLLOW|O_EXCL` creation; refuse
  symlinked or non-root-owned report paths.
- **D-21** Rendering: `html.escape` on all system strings; CSP meta in HTML; CSV formula-injection
  guard; `--redact` removes key fingerprints, sudo rule bodies, GECOS.

## 5. Privilege and MAC

- **D-22** Sudo recommended for full evidence, not mandatory. Unprivileged run supported;
  root-only facts → `NOT_TESTED` with reason. Header states privilege level.
- **D-23** Never: internal sudo, password prompts, setuid, polkit, D-Bus helper, file capabilities
  on Python, daemon, pager/editor/browser spawn under euid 0.
- **D-24** Under `SUDO_USER`: output only to `/var/lib/isedraf/...` or stdout; user-supplied paths
  refused or treated as untrusted data. Example sudoers file shipped as documentation only.
- **D-25** SELinux/AppArmor observed only. Never `setenforce`, `semanage`, `setsebool`, `semodule`,
  relabel, policy install. `EACCES` under enforcing MAC → `NOT_TESTED` "possible MAC denial" +
  `ausearch -m AVC` hint. Report own execution context (`id -Z`). Confined SELinux users documented.
- **D-26 (REVISED 2026-09-17, R-01)** Capability minimization by **launcher-originated branching**.
  A bounding set can only be reduced, never widened, so a collector's capability **cannot** be granted by
  the engine. Topology: the small, fixed, auditable **root launcher** holds the minimum superset needed to
  construct its branches and spawns each privileged collector *before* reducing to the engine. The audit
  collector receives `CAP_AUDIT_CONTROL` from the launcher with a fixed executable and fixed argv
  (`auditctl -s` / `auditctl -l`). The engine's capability set is reduced **independently** and it
  **SHALL NEVER regain privilege already removed**. `CAP_SYS_ADMIN` is absent everywhere. The exact
  `CapEff/CapPrm/CapBnd/CapAmb` recipe is **not** frozen here — the architecture freezes the topology and
  the invariants; the VM corpus proves the `setpriv`/systemd mechanics before they become frozen detail.
- **D-27** Sandbox (root, systemd hosts): `systemd-run` with ProtectSystem=strict,
  ProtectHome=read-only, ReadWritePaths=/var/lib/isedraf, PrivateTmp, ProtectKernelTunables,
  ProtectKernelModules, ProtectControlGroups, ProtectClock, SystemCallFilter excluding
  @mount @module @reboot @swap @raw-io @clock @cpu-emulation @obsolete. NoNewPrivileges only after
  corpus validation.
- **D-28** Wording: "FILESYSTEM PROTECTION ENFORCED; KERNEL MUTATION MINIMIZED". Never "read-only
  guaranteed". Pre/post fingerprint of audit status + loaded rules; `CHANGED_DURING_RUN` without
  attributing cause.
- **D-29** Run start/end logged to journal with run ID and invoking user.

## 6. Integrity

- **D-30** TOOL INTEGRITY and HOST BASELINE CONSISTENCY are separate concepts and report lines.
- **D-31** Trust levels: `LOCAL_CONSISTENT`, `PACKAGE_CONSISTENT`, `EXTERNAL_VERIFIED`. Local
  verification detects drift, not a root adversary. Signature verification only via apt/dnf or
  external `gpg`/`sqv`. Documented external recipe independent of ISEDRAF code
  (`sha256sum -c` + signature verify). Interpreter identity reported, not verified.
- **D-32** Optional later export signing via `ssh-keygen -Y sign`. Claim only: unchanged since
  signing, signed by pinned host key. Never non-repudiation, kernel-generated evidence, trusted time.

## 7. Host state model

- **D-33** Pipeline: collection → normalization → **comparability** → delta → interpretation →
  views/export. Frameworks are views over evidence.
- **D-34 (A8)** State dimensions: **declared** (per source file), **resolved** (subsystem-computed),
  **active** (loaded in kernel/process). `MISMATCH = resolved ≠ active`. Declaration conflicts are
  context. Not every domain has all three.
- **D-35** Collection status (`COLLECTED`, `PARTIAL`, `NOT_TESTED`, `ERROR`) is separate from
  evaluation result (`PASS`, `FAIL`, `PARTIAL`, `MISMATCH`, `NOT_APPLICABLE`, `MANUAL_REVIEW`,
  `NOT_EVALUATED`). Separate counters in every report.
- **D-36** Each section splits **state** (hashed, diffed) from **observations** (shown, never drive
  CHANGED): e.g. last login, PID, uptime, journal size, "days left". Relative values computed at
  render time from absolute facts.
- **D-37 (A16)** Canonical serialization before hashing: UTF-8, sorted keys, defined array ordering
  per entity, no insignificant whitespace, one timestamp format (UTC RFC 3339), types preserved,
  locale-independent. Section hash = hash of canonical normalized state.
- **D-38** Host identity: composite anchors; `host_id` derived app-specific from machine-id;
  hardware serials/UUIDs HMAC-SHA256 with per-install key (0600); confidence score. Flags
  `POSSIBLE_CLONE`, `POSSIBLE_ROLLBACK`; mismatch → `BASELINE_NOT_APPLICABLE`, no diff.
- **D-39** Anti-deception facts: `/etc/ld.so.preload`, kernel taint, unsigned/out-of-tree modules,
  package verification of executed binaries. Wording "no security-relevant change observed", never
  "host unchanged".
- **D-40** TPM/PCR/Secure Boot/lockdown recorded as facts only; no attestation claim.

## 8. Snapshot, baseline, delta

- **D-41 (A1, REVISED Q-13)** `snapshots/SDS-*/` treated as immutable by ISEDRAF and never rewritten by
  it; not protected against a local root adversary: manifest, `state/`, evidence refs only.
  `evaluations/EVL-*/` derived and regenerable: `changes.json`, `findings.json`, manifest; keyed by
  snapshot_id + baseline_revision + engine_version + rules/profile version.
- **D-42 (A19)** Every evaluation manifest records: snapshot manifest hash, baseline revision, engine
  version, collector and parser versions per section, evaluation rules version, schema versions,
  profile.
- **D-43 (A2, REVISED T-04)** Effective baseline = approved snapshot + ordered baseline events. First
  snapshot never auto-approved. Baseline = accepted, not secure.
  **Baseline revision computation — normative definition: `BASE-001`.** This register does not restate the
  equation (`NRM-001`).
- **D-44** Acceptance binds the exact accepted normalized state hash; any later change to that entity
  is a new change. `MISMATCH` may be acknowledged, never normalized.
- **D-45 (A3/A18)** Sections record collector_id, collector_version, parser_version. Version change →
  `COLLECTION_METHOD_CHANGED`; identical normalized values silent; differences `REVIEW_REQUIRED`.
  Command `isedraf baseline rebind` (not "recollect"): equivalent → `SAFE_REBIND`; different →
  `REVIEW_REQUIRED`; never auto-accepts new state.
- **D-46 (A4)** Delta only where both sides `COLLECTED`; else `NOT_COMPARABLE` + reason. NOT_TESTED
  never yields REMOVED or IMPROVEMENT. Unprivileged/incomplete snapshots cannot be approved.
- **D-47** Change primitives: ADDED, REMOVED, MODIFIED, ENABLED, DISABLED, MISMATCH.
  Interpretations: SECURITY_REGRESSION, SECURITY_IMPROVEMENT, EXPECTED_CHANGE, REVIEW_REQUIRED,
  INFORMATIONAL. EXPECTED only with correlating evidence (e.g. package ownership + transaction
  between snapshots). BIOS/firmware changes → REVIEW_REQUIRED.
- **D-48** Operational risk belongs to guidance, not the delta: NONE, SERVICE_RESTART,
  POTENTIAL_SERVICE_DISRUPTION, POTENTIAL_LOCKOUT, REBOOT_REQUIRED. Commands labelled
  `ILLUSTRATIVE` with context (source file, package ownership, dependencies). No exact revert, no
  apply in v0.1.

## 9. Storage and ledger

- **D-49** No database in v0.1 (no authoritative SQLite, no server, no API, no connectors, no
  credentials, **no network egress**). Root: `/var/lib/isedraf/` (0700).
  Layout: `host/ baselines/ snapshots/ evaluations/ acceptances/ reports/ exports/ tmp/ ledger/ .lock`,
  where `ledger/` holds `segment-NNNNNN.jsonl` (D-99). Normative storage definition: `STORE-001`.
- **D-50 (A5)** Snapshot built in private temp dir → sections → hashes → manifest → fsync → atomic
  rename → ledger append + fsync. Ledger authoritative. Unledgered snapshot → `ORPHANED`.
  Ledger/snapshot hash mismatch → integrity_failure. Whole-run exclusive `flock`.
- **D-51 (A17/A6, REVISED 2026-09-17, Q-06/Q-07)** `ledger/segment-NNNNNN.jsonl` — append-only **within a
  segment**, hash-chained (`prev_hash`), **IDs and hashes only**. Pre-checkpoint history is replaced only
  by an explicit checkpoint record carrying its cumulative hash; `verify` prints the verification horizon.
  Personal data only in snapshots and `acceptances/ACC-*.json` (actor, timestamp, reason,
  accepted_state_hash). Prune removes dirs and appends `pruned` event with IDs + manifest hashes.
  Compaction only via explicit checkpoint record.
- **D-52** Checkpoint hash emitted to journal/stdout (`ISEDRAF_CHECKPOINT=`) for external retention.
- **D-53** Retention default: baseline + last 30 snapshots; `isedraf prune`; configurable.
  Package remove/purge never deletes `/var/lib/isedraf`; only `isedraf purge-data`.
- **D-54 (A12)** `--reason` length-limited, escaped, CSV-guarded. Exports 0600; users/privileges
  stdout exports redacted by default.

## 10. Output and automation

- **D-55** Canonical JSON + per-entity JSON Lines (every row: schema_version, host_id, snapshot_id,
  collected_at, entity). Console, single-file HTML, CSV are renderers of canonical artifacts only.
- **D-56 (A11)** Per-entity schema versions, 0.x during prototype; minor = additive; major requires
  `baseline rebind` before comparison.
- **D-57 (A7)** Exit codes, precedence 5 > 4 > 6 > 3 > 2/1 > 0:
  `0` complete & comparable & nothing unaccepted · `1` unaccepted security-relevant change ·
  `2` incomplete / NOT_COMPARABLE in tracked sections · `3` = 1+2 · `4` baseline not applicable ·
  `5` tool integrity failure · `6` no approved baseline · `65` approval refused · `66` run in progress ·
  `67` state root unwritable · `64+` usage/engine. Normative source: `OUT-001` and
  `lib/isedraf/exitcodes.json` (`NRM-001`). Must propagate through
  systemd-run re-exec.
- **D-58** No daemon. Optional systemd timer shipped **disabled**, runs as root. ISEDRAF detects and
  emits; existing infrastructure delivers alerts.

## 11. Packaging and governance

- **D-59** DEB/RPM preferred install; signed tarball fallback; git for development; never `curl | bash`.
- **D-60** Maintainer scripts only create ISEDRAF-owned directories/permissions; never touch SSH, PAM,
  audit, sysctl, users, services, MAC. CI grep gate.
- **D-61** Single install manifest drives both DEB and RPM; CI payload parity.
- **D-62** File headers, SPDX gate, license integrity, provenance registry, schema validation,
  read-only immutability test, report-permission test — from the first commit, derived from the
  NFTBan crosswalk (principles, not copied code).
- **D-63** Clean room: upstream projects (ComplianceAsCode, OpenSCAP, Lynis, osquery, Wazuh, AIDE)
  only for understanding, interoperability and external validation; never copied rule source, text,
  mapping tables or remediation. No CIS/ISO/PCI prose; identifiers + independently written objectives.

## 12. Scope

- **D-64** Platforms v0.1: Debian 12, Ubuntu 24.04, Rocky/Alma 9. Alpine, Arch, SUSE, BSD out.
- **D-65 (A10)** Framework mapping views deferred to v0.2 (NIS2-IR-2024-2690 + NIST SP 800-53,
  NIST IR 8477 supportive relationships, all PROPOSED). v0.1 auditor view = evidence + change
  provenance + collection truth.
- **D-66 (A14)** Prototype: host identity; identity/privilege (users, groups, local sudo,
  authorized_keys fingerprints); password aging; SSH resolved state; mounts declared/resolved/active
  (fstab + systemd mount units); audit + journald recording (incl. time sync quality).
  v0.1 release adds: kernel/platform, MAC, services, timers/cron. Later: software inventory,
  listeners, hardware inventory, privilege-surface scan, export signing, mappings.
- **D-67** Provider bounds: journald deep; rsyslog/syslog-ng detected only; local identity deep;
  SSSD/LDAP/AD detected → effective state NOT_TESTED; `sudo -l -U` never by default; no
  `apt update` / `dnf check-update`; filesystem scans local fs types only, no mount crossing, time
  budget → PARTIAL.

## 13. Release-blocking acceptance tests (A15)

1. Default run < 10 s on a normal server (no optional scans).
2. Unchanged host × 10 runs → 0 changes.
3. ISEDRAF upgrade on unchanged host → 0 security changes.
4. Parser v1→v2 with identical normalized state → COLLECTION_METHOD_CHANGED metadata, 0 security changes.
5. Root baseline + unprivileged run → NOT_COMPARABLE, never REMOVED; exit ≥ 2.
6. Crash between snapshot rename and ledger append → ORPHANED, no corruption, next run correct.
7. Cloned VM → POSSIBLE_CLONE + BASELINE_NOT_APPLICABLE (exit 4).
8. New sudo user → SECURITY_REGRESSION (exit 1).
9. Locked password + valid SSH key + interactive shell + NOPASSWD → detected and explained.
10. Audit persistent immutable vs loaded unlocked → MISMATCH.
11. Filesystem diff shows no writes outside `/var/lib/isedraf` except journald-mediated records and systemd transient-unit runtime state — normative wording: `SCOPE-062` (T-13).
12. SELinux enforcing, unconfined root → all prototype controls COLLECTED; confined `staff_u` → NOT_TESTED, not FAIL.
13. No approved baseline → exit 6, never 0.
14. Only last-login changes → no identity-state drift.
15. Home birth time never reported as EVENT_RECORDED; missing evidence → UNKNOWN.
16. New sudo privilege appears in `identity privileged` and as SECURITY_REGRESSION.
17. Quick and detailed identity views derive from the same normalized evidence (hash-equal source).
18. Recording coverage for account changes present/absent represented without inventing remote state.
19. Edited CLAUDE.md / settings / hook copy → governance gate fails.
20. Runtime import of sqlite3 or a network client, or subprocess curl → `make check` fails; egress attempt in sandbox → blocked and reported.
21. Unprivileged `logger -t useradd` spoof → never EVENT_RECORDED.
22. Commit without `Assisted-by:` trailer → rejected by commit-msg hook.

## 15. Implementation governance (added before Prompt 04)

- **D-68** Frozen architecture documents and this register are copied into the repository under
  `docs/architecture/` with `FROZEN_MANIFEST.sha256`. This is the **only** repository copy of the register
  (no root copy). `make check` and the pre-commit hook fail on
  drift. Changes only through owner-written `docs/architecture/AMENDMENTS.md` (new manifest per amendment).
- **D-69** Blocked-work protocol: record in `docs/IMPLEMENTATION_QUESTIONS.md`, mark requirement
  BLOCKED in `docs/requirements-trace.md`, continue unrelated in-scope work, report in milestone.
  Never weaken requirements, tests or gates. Capability-model failures raise OD-06; capabilities are never widened.
- **D-70** Development state root: `ISEDRAF_STATE_ROOT` honoured only when euid ≠ 0 and `SUDO_USER`
  unset; refused under root; all artifacts marked `"state_root": "DEV"`.
- **D-71** Builtin `exec()`/`eval()` forbidden; `os.execv*` permitted only in `lib/isedraf/launcher/`
  with fixed absolute paths; `bash -c`/`sh -c` with non-constant strings forbidden. Grep gate scoped accordingly.
- **D-72** Exit codes defined once in `lib/isedraf/exitcodes.json`; `make check` verifies code and docs match.
- **D-73** Agent guardrails are mechanically enforced by `.claude/settings.json` deny rules, git
  `pre-commit` (frozen manifest + `make check`) and `pre-push` (always refuse), plus CI. Deny rules are
  defense in depth, not a security boundary. The agent never runs sudo, package installs or root
  ISEDRAF collection on the developer workstation.

## 16. Concept preservation (added before Prompt 04)

- **D-74** Identity views from one canonical collection: `identity users` (quick: username, UID, class,
  login state, password state, absolute password/account expiry, privilege class, flags), `identity user
  <name>` (detailed: source, UID/GID, groups, shell, home ownership/permissions, full aging fields,
  UID 0, root group, local sudo indicators/effective local assessment, NOPASSWD where assessable,
  authorized_keys count/fingerprints, activity observations, creation provenance, change refs),
  `identity groups`, `identity group <name>`, `identity privileged`. Relative values are render-time only.
- **D-75** Account creation time is provenance, never invention. `EVENT_RECORDED` only from an auditd
  ADD_USER record or a journal entry whose **trusted fields** show `_UID=0` and the real account-management
  binary (`_EXE`); message text alone is never trusted. The record cites source, record reference and
  retention context and is **not** claimed tamper-proof (root can rewrite local logs). `ESTIMATED` (e.g. home
  directory birth time) carries source, confidence LOW, explanation. Otherwise `UNKNOWN`. Password
  last-change is never creation time. Rotated evidence → UNKNOWN, never a guess. The word VERIFIED is not used.
- **D-76** Recording coverage view (`isedraf recording`) per event class: authentication, SSH
  authentication/session, sudo/privilege use, account/group change, audit subsystem, journal persistence,
  time-sync quality. Per class: source, observable yes/no, persistence, declared/resolved/active where
  applicable, oldest/newest event as bounded observations. Not observing an event ≠ not recorded unless
  configuration proves it. Forwarding success never claimed.
- **D-77** `isedraf explain <id>` is a product contract: collected sources, collection status, normalized
  state, baseline state, exact delta, classification reason, confidence/limitations, evidence refs, manual
  verification steps, illustrative guidance, operational risk. Never turns uncertainty into certainty.
- **D-78** Canonical concepts are outcome/fact oriented and provider-neutral; providers are evidence
  details. Enables future Unix-like providers; this is not BSD support.
- **D-79** Facts are separate from criteria. FACT → canonical evidence; CRITERION → independent
  evaluation; REPORT → fact + criterion + result + explanation. Scope classes: HOST_TECHNICAL,
  HOST_SUPPORTING_EVIDENCE, MANUAL_ORGANIZATIONAL, NOT_HOST_ASSESSABLE. Never a claim of organizational
  compliance.
- **D-80** Control lifecycle DRAFT, EXPERIMENTAL, STABLE, DEPRECATED, RETIRED (prototype = EXPERIMENTAL).
  Mapping lifecycle PROPOSED, VERIFIED, DISPUTED, SUPERSEDED, RETIRED; VERIFIED needs provenance + review.
  Retired IDs are never reused.
- **D-81** External tools (ComplianceAsCode, OpenSCAP, Lynis, osquery, Wazuh, AIDE, others) may later
  supply comparison, validation or adapter-imported evidence with explicit provenance; never canonical state.
- **D-82** Future modules (software, hardware, listeners, services) reuse the same collection → state/
  observation → snapshot → baseline → comparability → delta → export engine. Software: native version
  comparison, local origin/signature facts, no CVE or remote patch analysis, full inventory at baseline,
  delta routinely; exports must allow "which hosts have package X version Y" in the consumer's own database.

## 17. Enforcement of guardrails, egress and documentation (added before Prompt 04)

- **D-83** `docs/development/GOVERNANCE_MANIFEST.sha256` covers CLAUDE.md, `.claude/settings.json`,
  `git-hooks/*`, frozen-manifest verifier, `lib/isedraf/exitcodes.json`, runtime module allowlist, doc
  lint config. `make check` verifies it and compares installed `.git/hooks/*` with repo copies. Milestone
  reports include `git diff --stat` of governance paths since the bootstrap commit; owner review is the control.
- **D-84** Runtime Python imports restricted by an explicit **stdlib allowlist** (`lib/isedraf/
  runtime-imports.allow`); anything else fails `make check` (covers socket, ssl, urllib, http, smtplib,
  ftplib, xmlrpc, asyncio networking, multiprocessing.connection, sqlite3, dbm, shelve). No subprocess to
  network clients.
- **D-85** Sandbox adds `RestrictAddressFamilies=AF_UNIX AF_NETLINK` and `IPAddressDeny=any`; report states
  `NETWORK EGRESS: KERNEL_RESTRICTED` or `CODE_ONLY`. Validated per distro in corpus (sshd -T, getent, journal).
- **D-86** Syntax validation never writes bytecode: in-memory `compile()`/`ast.parse` or a temporary
  build copy removed before the gate ends.
- **D-87** Documentation authority: frozen requirements > register > CLAUDE.md > `/docs` > README.
  `/docs` is canonical. **No GitHub Wiki** until an owner amendment; future navigation publishes `/docs`
  (e.g. GitHub Pages) from the same reviewed tree. Coexistence policy: no "vs", "replaces", "better than",
  rankings or unverified claims about other projects; neutral boundary descriptions only; comparative
  results only as reproducible scenario-level corpus data. NFTBan and ISEDRAF are independent projects.
- **D-88** Feature statements carry status IMPLEMENTED / EXPERIMENTAL / PLANNED / FUTURE / OUT_OF_SCOPE;
  README describes implemented behaviour only; future items only in `docs/roadmap/ROADMAP.md`. Stubs are
  headings + `Status: STUB` only; doc lint fails on behavioural prose in stubs.
- **D-89** Generated, never hand-maintained: `docs/CURRENT_STATE.md`, `docs/development/
  requirements-trace.md` (UNIMPLEMENTED/IMPLEMENTED/TESTED/BLOCKED from `Implements:` tags),
  `docs/reference/CLI.md`, `docs/operator/EXIT_CODES.md`, man page `isedraf.8`. `make check` fails when stale.
  Doc lint: broken links, unknown requirement IDs/statuses/exit codes, forbidden claims (with exemption list
  for policy/style docs and an inline quote marker), frozen/governance hash integrity.
- **D-90** Provenance of contributions: REUSE specification (`REUSE.toml`, `reuse lint` CI-only) for
  licensing incl. JSON; AI disclosure per D-91…D-94; owner reviews all generated code;
  DCO `Signed-off-by` required before external contributions. Public release blocked until OD-01 (name)
  resolved; README says "codename" until then.


## 18. AI-assistance transparency (nothing hidden)

- **D-91** AI assistance is disclosed openly. The convention is adapted from NFTBan (inspected in prompt 01,
  never guessed). Root `AI_ASSISTED_DEVELOPMENT.md` names every AI tool that contributed and its role — e.g. ChatGPT
  (design discussion, leading architecture direction), Claude (architecture challenge/review, prompt pack,
  implementation via Claude Code), Gemini (proposal reviewed and challenged) — the human owner's role
  (scope, decisions, approvals, final responsibility), how contributions are marked, and what is never
  accepted without human review. **(REVISED 2026-09-17)** The project does **not** assign titles such as
  *architect*, *lead architect*, *maintainer*, *author* or *owner* to any AI system; the table records
  **use in the project**, not a role or rank. Model versions are recorded only where materially relevant to
  reproducibility; there is **no** standing obligation to enumerate every historical model interaction.
- **D-92** Copyright and responsibility remain with Antonios Voulvoulis / ITCMS. AI tools are credited
  contributors, not copyright holders or licensors.
- **D-93 (REVISED 2026-09-17, R-07)** Commit disclosure is **`Assisted-by:` only**.
  Every commit carries `Assisted-by: <tool> (<role>)` or `Assisted-by: none`.
  A `Co-Authored-By:` trailer naming an AI tool or provider (Claude/Anthropic, ChatGPT/OpenAI,
  Gemini/Google or equivalent) **SHALL be rejected by the `commit-msg` hook**, so that human authorship and
  ownership remain unambiguous. Human `Co-Authored-By:` trailers are unaffected. Historical AI trailers, if
  any, are legacy metadata only and history is not rewritten. `Assisted-by` is **disclosure**;
  `Co-Authored-By` is an **authorship claim**, and AI tools hold no rights (D-92). The PR template carries
  an AI-assistance field. The hook enforces **both** halves: a missing `Assisted-by:` and a present AI
  `Co-Authored-By:` each reject.
- **D-94** `docs/development/DESIGN_PROVENANCE.md` records design phases, which AI-assisted discussions
  produced which decision IDs, external proposals reviewed and their outcome, and human approval points.
  Raw chat transcripts are not committed (may contain sensitive data).
- **D-95** Repository path `<repo-root>` (planning under `planning/`); NFTBan reference
  `<nftban-checkout>`, verified by prompt 01 before use.

## 14. Open decisions (carry forward, do not silently resolve)

- **OD-01 (RESOLVED 2026-09-18 → D-108)** Public project name: **ISEDRAF**.
- **OD-02** `host_id` stable (app-specific machine-id) vs keyed per install. Lean: stable host_id, HMAC serials only.
- **OD-03** Last-login source: lastlog / lastlog2 / wtmpdb per distro.
- **OD-04** `cvtsudoers -f json` availability/version per target distro; fallback strategy.
- **OD-05** `aa-status --json` privilege requirements per kernel.
- **OD-06** setpriv bounding-set behaviour under SELinux enforcing per distro.
- **OD-07** Repository hosting and signing-key custody for packages.
- **OD-08** Framework text licensing (CIS terms) before any CIS mapping pack.
- **OD-09** Release signing approach (reuse NFTBan's if proven).
- **OD-10** Per-entity array ordering keys for canonical serialization.
- **OD-11** Future docs publishing (GitHub Pages) — only after OD-01.
- **OD-12** Trusted journal field set per distro for D-75 (useradd/usermod/groupadd binary paths, shadow-utils logging behaviour).
- **OD-13** How run start/end journal logging (D-29) works under `RestrictAddressFamilies` (AF_UNIX journal socket vs stdout capture).
- **OD-14 (RESOLVED 2026-09-17 → D-101)** Definition of a *tracked* section for the exit-`2` trigger.
- **OD-15 (RESOLVED 2026-09-17 → D-102)** Whether the state/observation split is a fixed list or a
  mandatory per-field classification.


## 19. Decisions incorporated from owner amendments and the Prompt 03 review (2026-09-17)

Amendments are **historical provenance only**. Current authority lives here. Frozen documents cite these
decision IDs, never an `A-0xx` amendment number.

- **D-96** Private GitHub bootstrap may precede Prompt 04. The complete private repository
  governance and documentation shell is created before implementation; Prompt 04 clones/fetches the
  existing private `itcmsgr/isedraf` rather than initialising a second repository, and never rewrites its
  history. This does **not** authorize prototype implementation before architecture freeze. Publication
  remains prohibited while OD-01 is unresolved.
- **D-97 (REVISED U-02, U-07)** Canonical hashing is **SHA-256**, written `sha256:<lowercase-hex>`.
  **Canonical serialization — normative definition: `NORM-035`. Hash framing and domains: `NORM-038`.
  Golden vectors: `NORM-039`.** This register does not restate the specification (`NRM-001`): the previous
  restatement permitted "a defined decimal form" that `NORM-034` forbids, so two authority tiers described
  different canonical bytes.

- **D-98** (R-24, S-24, S-20) **Collection method identity is source-aware.** It comprises
  `collector_id`, `collector_version`, `parser_version`, **`source_id`**, the source/executable identity,
  and the source version where available. Switching runtime source — lastlog/lastlog2/wtmpdb,
  `cvtsudoers` vs fallback, `aa-status --json` vs text, `getent` vs file — is a
  `COLLECTION_METHOD_CHANGED` **even when no ISEDRAF version changed**.
- **D-99** (R-08, S-31, S-32) The ledger is **segmented** (`ledger/segment-NNNNNN.jsonl`) and
  crash-recoverable. Append-only SHALL NOT mean one torn write destroys the product. A torn tail is
  **preserved as forensic evidence**, the chain is recovered only to the last fully verified record, and a
  new segment opens with an explicit recovery/checkpoint event referencing the damaged segment. Bytes are
  never silently discarded, and uninterrupted integrity is never claimed across a recovery. A free-space
  preflight precedes commit; the parent directory is fsynced after the atomic rename.
- **D-100** (S-21, R-27) **`EXPECTED_CHANGE` is not emitted automatically in v0.1.** No trustworthy
  correlating source exists while package facts are out of scope. Routine package or kernel change is
  `INFORMATIONAL` or `REVIEW_REQUIRED` according to the evidence. ISEDRAF does not invent intent. The
  classification is reserved for a later evaluator once package/change correlation exists.
- **D-101** (OD-14, REVISED T-04) **Tracked sections are part of the baseline revision.**
  Computation — normative definition: `BASE-001`; policy object: `BASE-005`; storage and verification:
  `BASE-007`/`BASE-008`. Not restated here (`NRM-001`).
  A section is `TRACKED` when its comparable stable evidence was explicitly accepted as **required
  evidence** in the effective baseline revision. A tracked section that becomes unavailable is
  `NOT_COMPARABLE` → incomplete → exit `2`. A newly supported collector becomes **available coverage**, not
  tracked, until explicit baseline-policy adoption. Changing a section's tracked status is itself a
  baseline-policy event: attributed, timestamped, reasoned, hash-chained, producing a new revision — so
  exit `2` **cannot** be silenced by editing a flag.
- **D-102 (OD-15, REVISED U-07)** **Mandatory per-field classification, no implicit default.**
  **Normative definition: `SCOPE-045`** (`NRM-001`). Intent: exactly one category per normalized field;
  only `STATE` enters the section hash and the delta.
  An unclassified normalized field is a schema/CI failure. Annotation alone is insufficient: the
  **empirical invariant** is that N idle runs on an unchanged host produce byte-identical canonical section
  state and byte-identical section hashes, checked **per section**, not merely "the report says zero
  changes". A change to the classification table is itself a `COLLECTION_METHOD_CHANGED` (D-98).
- **D-103** (CHALLENGE-02) **Explicit runtime validation contract.** Every schema/entity enumerates the
  subset the runtime MUST enforce — required fields, field types, enum membership, unknown critical fields,
  supported schema major, field-classification presence, basic structural constraints. CI JSON Schema MAY
  enforce more. The same positive and negative corpus runs through both; for any constraint inside the
  declared contract, **disagreement is a CI failure**. The runtime SHALL NOT shrink its claimed contract
  without a requirement/schema change, and SHALL NOT reimplement JSON Schema.
- **D-104** (CHALLENGE-01) The ~5k-line engine figure is an **advisory complexity budget, never a CI or
  release gate**. It is reported as a metric in every milestone report. Negative tests, error handling,
  validation, provenance and failure semantics SHALL NEVER be removed to satisfy it. Correctness and
  auditability win.
- **D-105** (R-14, R-23) **Requirement-reference integrity.** A W0 gate proves: every referenced
  requirement ID exists; every defined ID is unique; every superseded ID resolves explicitly; and no frozen
  document cites an undefined `D-`/`OD-`/requirement ID. The gate is falsifiable by injecting a fake
  reference. This is D-83/GOV-001 applied to the architecture itself.
- **D-106** (R-22) The register at `docs/architecture/DECISIONS_REGISTER.md` is the **single** repository
  copy and the authoritative current statement of every decision. `planning/prompts/DECISIONS_REGISTER.md`
  is replaced by a pointer. `docs/architecture/AMENDMENTS.md` records history only — what changed, when,
  why, and which current decision ID supersedes it — and implementation SHALL NEVER need it to discover
  current truth.

- **D-108 (owner decision, 2026-09-18) — FINAL PROJECT NAME. Resolves OD-01.**
  Display name **ISEDRAF**; CLI and package identifier **`isedraf`**; environment prefix `ISEDRAF_`;
  state root `/var/lib/isedraf/`. Expansion: **I**ntegrity · **S**tate · **E**vidence · **D**elta ·
  **R**eporting · **A**nalysis · **F**acts. Public descriptor: *Linux Host Assurance & Evidence Engine*.
  Philosophy unchanged: *Measure once. Map everywhere. Fix only the delta.*
  **This amendment changes project identity only.** It does not alter frozen technical architecture,
  evidence semantics, security controls, product scope or requirement IDs — those are architecture
  identifiers, not branding, and `SNAP-*`/`DELTA-*`/`NORM-*` and every other prefix are unchanged.
  Preliminary technical and brand clearance passed; the near-name `ISEDRA` (a Cyprus company with no
  observed software or security activity, and a fashion product name) is recorded here rather than
  ignored. **Formal EUIPO / WIPO / USPTO clearance is still required before public release**, so
  `NAME_STATUS` is `FINALIST — CLEARED FOR PROJECT USE`, not `CLEARED_FOR_PUBLIC_RELEASE`.

- **D-109 (owner decision, 2026-09-18) — Hash-domain rename is safe now and only now.**
  The project name is an ASCII component of every `HASH_FRAME_V1` domain (`NORM-038`), so renaming it
  changes **every** digest: `host_id`, `state_hash`, `manifest_hash`, `record_hash`. Verified before
  acting: there is **no production state root, no committed evidence artifact and no freeze manifest** —
  the only artifacts bound to the old domains are golden vectors generated today, which are regenerable
  test fixtures, not host evidence. The rename is therefore free today and would be a **breaking evidence
  migration** after W1-A ships. Domains become `ISEDRAF:HOST-ID:V1`, `ISEDRAF:STATE:V1`,
  `ISEDRAF:SNAPSHOT-MANIFEST:V1`, `ISEDRAF:LEDGER-RECORD:V1`. **No host-observed state changes** — the
  digests move because the domain constant moved, which is product metadata, not host fact.

  **The distinction that must remain documented:**

  | | |
  |---|---|
  | normalized host facts / state semantics | **unchanged** |
  | product-domain separation constant | **changed** |
  | resulting cryptographic digests | **intentionally changed** |
  | historical production evidence requiring migration | **none existed** |

  **Second instance, recorded deliberately:** the reserved canonical-state key
  `__secdelta_encoding` → `__isedraf_encoding` (`NORM-036`) was safe **only** because no bound artifact
  used it — W1-A produces no tagged field. Two independent places where the brand name had reached into
  byte-level evidence semantics. A future brand rename after W1-A ships **SHALL NOT** be treated as a
  textual rename; it is an evidence-format migration and requires migration semantics, versioning and a
  compatibility decision.

  **No backward compatibility** is added for the old hash domain unless a real historical-artifact
  requirement later appears. There is none today, and inventing one would mean carrying a dead constant
  in every preimage.

- **D-107 (owner decision, 2026-09-18)** **Staged freeze.** The ISEDRAF architecture MAY be frozen and
  implemented **incrementally, by reviewed freeze set**. A verified freeze set authorizes implementation of
  **that set only**. **No global architecture manifest is required** for staged prototype implementation,
  and none is created. Freeze sets live at `docs/architecture/freeze/<SET>.sha256`; `check-freeze` is the
  sole authority on whether a manifest is valid, and `check-scope` consumes that verdict rather than
  testing for a historical filename. Each set's scope document names the requirements normative for it.

### Open decision revised

- **OD-06 (REVISED)** No longer "will SELinux break the capability design?" but: *can the D-26
  launcher → collector privilege reductions be demonstrated correctly on Debian 12, Ubuntu 24.04 and
  Rocky/Alma 9, including SELinux enforcing?* If not, that lane stays `BLOCKED`. Capabilities are **never**
  widened to make a test pass.
