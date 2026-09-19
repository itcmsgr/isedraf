# CLAUDE.md — ISEDRAF repository guardrails

<!-- Copy to repo root at Prompt 04. Short hard-stop contract; rationale lives in docs/architecture/.
     Enforced mechanically by .claude/settings.json, git hooks and `make check` — not by this file alone. -->

ISEDRAF (codename) — Linux Host Assurance, State Delta & Evidence Bridge
Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0

## 1. Authority and change control
1. `docs/architecture/` — frozen docs + requirement IDs (hash-locked by `FROZEN_MANIFEST.sha256`)
2. `docs/architecture/DECISIONS_REGISTER.md` (the only repository copy)
3. This file
4. `docs/IMPLEMENTATION_QUESTIONS.md` — assumptions only, never authority

Frozen docs, the register, open decisions and governance files (CLAUDE.md, `.claude/`, `git-hooks/`,
`docs/development/GOVERNANCE_MANIFEST.sha256`, `lib/isedraf/exitcodes.json` *(PLANNED — not yet created)*, `lib/isedraf/runtime-imports.allow`) are **read-only** for you. Only the owner amends them,
via `docs/architecture/AMENDMENTS.md`. Never weaken a requirement, test or gate to make work pass.

**When blocked** (conflict, ambiguity, or requirement not implementable as written):
record in IMPLEMENTATION_QUESTIONS.md → requirement IDs, affected code, safest behaviour chosen,
proposed clarification → mark the requirement `BLOCKED` in `docs/requirements-trace.md` *(PLANNED — not yet created)* →
continue other in-scope work → list it in the milestone report.
Specifically: if the D-26/D-27 capability model (launcher, setpriv, CAP_AUDIT_CONTROL, SELinux)
fails in the corpus, raise OD-06 — **never widen capabilities**.

**Reading order for every session:** this file → register → `FROZEN_MANIFEST.sha256` → relevant frozen
docs → `docs/CURRENT_STATE.md` → `docs/REPOSITORY_MAP.md` → `docs/development/requirements-trace.md` *(PLANNED — not yet created)* →
module → tests → IMPLEMENTATION_QUESTIONS.md. Never infer architecture from code. Label claims as
REPOSITORY FACT / FROZEN REQUIREMENT / OPEN DECISION / INFERENCE / PROPOSAL / EXTERNAL INFORMATION.

## 2. Hard stops — never
**Publication:** push, add remotes, tag, publish, create GitHub repos, change settings, upload, enable external services.

**Clean room:** copy code, rules, tests, prose, mappings or remediation from NFTBan, ComplianceAsCode,
OpenSCAP, Lynis, osquery, Wazuh, AIDE, CIS, ISO, PCI DSS or any external product.

**Runtime:** add dependencies beyond Bash, Python ≥3.9 stdlib, coreutils, util-linux, and optional
subsystem tools discovered at runtime. No Go, compiled parts, plugins, third-party runtime modules.
Dev/CI deps stay in `requirements-dev.txt` and are never imported by runtime code.

**Code constructs:** builtin `exec()`/`eval()`, `pickle`, `shell=True`, `os.system`, `bash -c`/`sh -c`
with non-constant strings, sourcing or importing content files, executable metadata, user-controlled
executable paths, interpolating system-derived strings into commands.
`os.execv*` is allowed **only** in `lib/isedraf/launcher/` with fixed absolute paths.

**Privilege:** internal sudo, password prompts, setuid, polkit, D-Bus helpers, file capabilities,
daemons, broader capabilities to make a collector succeed.
Under euid 0: no pager, editor, browser, `$PAGER`/`$EDITOR`, or user-chosen output paths.

**Your own actions on this workstation:** run `sudo`, install packages, run root/full ISEDRAF
collection, or touch host security configuration. Full collection only in corpus VMs.

**Git bypass:** `git commit --no-verify`, changing `core.hooksPath`, editing `.git/hooks/`.

**Scope:** network egress, telemetry, update checks, API client/server, database (incl. authoritative
SQLite), SIEM/webhook connectors, remediation apply; assessing firewalls, AV/EDR/XDR, IDS/IPS, WAF,
SIEM, cloud/network controls, backups, patch availability, CVEs. Absence of a local product never
means absence of a control. Future domains → IMPLEMENTATION_QUESTIONS.md as `FUTURE`, not code.

**Host-changing commands in code:** `apt update`, `dnf check-update`, `sudo -l -U`, `setenforce`,
`semanage`, `setsebool`, `semodule`, or anything modifying PAM, SSH, audit, sysctl, users, services,
MAC, mounts or packages. Audit is observation only.

**Imports:** any runtime module not in `lib/isedraf/runtime-imports.allow` *(PLANNED — not yet created)* (no socket, ssl, urllib, http,
sqlite3, dbm, shelve, xmlrpc, smtplib, asyncio networking; no subprocess to curl/wget/nc/ssh/scp).
Never `python -m py_compile` (writes .pyc, D-86).

**Docs:** GitHub Wiki; "vs"/"replaces"/"better than"/rankings about any project (incl. NFTBan);  <!-- doclint:allow-framing: this line STATES the prohibition -->
present-tense FUTURE features; hand-editing generated docs; updating docs to match a bug.
Follow `docs/development/DOCUMENTATION_POLICY.md`.

**Claims:** compliant, guaranteed, tamper-proof, non-repudiable, host unchanged, kernel-generated,
read-only guaranteed. Use: observed, collected, not tested, no security-relevant change observed,
locally/package consistent, filesystem protection enforced, kernel mutation minimized.

## 3. Evidence invariants — never break
- NOT_TESTED / ERROR / incomplete / method-incompatible → never PASS, FAIL, REMOVED or IMPROVEMENT; use `NOT_COMPARABLE` + reason.
- Collection status and evaluation result are separate fields and counters.
- Fields carry one of `STATE`/`OBSERVATION`/`DERIVED`/`PROVENANCE` (`SCOPE-045`); only `STATE` is hashed and diffed.
- Completed `snapshots/SDS-*` are **treated as immutable by ISEDRAF** and never contain changes/findings; those live in regenerable `evaluations/EVL-*`. They are not protected against a local root adversary.
- First snapshot never auto-approved; unprivileged/incomplete snapshots never approvable.
- Acceptance binds the exact normalized state hash; MISMATCH may be acknowledged, never normalized.
- Collector/parser version change with identical state → silent; different → REVIEW_REQUIRED; `baseline rebind` never accepts new state.
- `ledger/segment-*.jsonl`: IDs, hashes, chain only; append-only **within a segment**; a verified record is never rewritten; pre-checkpoint history is replaced only by an explicit checkpoint carrying its cumulative hash.
- No raw machine-id or hardware serials in canonical/export data.
- Package scripts never delete `/var/lib/isedraf` or enable scheduled audits.
- TOOL INTEGRITY and HOST BASELINE CONSISTENCY are always reported separately.
- Account creation is `EVENT_RECORDED` only from trusted evidence (auditd ADD_USER or journal trusted fields), never claimed tamper-proof; home birth time is `ESTIMATED` (LOW); otherwise `UNKNOWN`. Never the word VERIFIED.
- Identity quick, detailed, group and privileged views render one canonical collection; no second audit.
- Facts are separate from criteria; never a claim of organizational compliance.

## 4. Always
- Approved header on every eligible file; provenance registry updated.
- Collectors collect, engine interprets: argv list, shell=False, clean env, fixed PATH, LC_ALL=C, timeout, bounded output, stdin=DEVNULL.
- Snapshot commit order: private temp dir → collect → normalize → hashes → manifest → fsync → atomic rename → ledger append + fsync, under the whole-run lock. Unledgered dirs are ORPHANED.
- umask 077, dirs 0700, files 0600, no-follow/exclusive creation.
- `Implements: <REQ-ID>` in code and tests; regenerate `docs/development/requirements-trace.md` *(PLANNED — not yet created)*.
- Every parser: normal, malformed, missing-data and permission/failure fixtures. Every bug: regression test first.
- `make check` before every commit (pre-commit hook enforces). Never commit failing checks.
- Transparency (D-91…D-93): add `Assisted-by: Claude (<role>)` to every commit you make. **Never add a
  `Co-Authored-By:` trailer naming an AI tool or provider** — the `commit-msg` hook rejects it (D-93).
  `Assisted-by` is disclosure; `Co-Authored-By` is an authorship claim, and AI tools hold no rights (D-92).
  Record your role in the milestone report; never omit or minimize AI involvement.

## 5. Development state root
Unprivileged smoke runs may use `ISEDRAF_STATE_ROOT=<dir>` only when euid ≠ 0 and `SUDO_USER` is
unset. Code must refuse it under root, and every artifact produced must carry `"state_root": "DEV"`.

## 6. Product contracts to preserve
Identity quick + detailed + groups + privileged views from one collection (D-74) · creation time
EVENT_RECORDED/ESTIMATED/UNKNOWN (D-75) · `isedraf recording` (D-76) · `isedraf explain` contract
(D-77) · provider-neutral concepts (D-78) · facts separate from criteria (D-79) · controls EXPERIMENTAL (D-80) ·
external tools never canonical (D-81) · future modules reuse the engine (D-82).

## 7. Prototype scope (only)
Host identity · identity views (users, user, groups, group, privileged) · account-creation provenance · local sudo · authorized_keys fingerprints · password/account aging ·
SSH resolved state · mounts declared/resolved/active · `recording` view (auth, SSH, sudo, account change,
audit, journal persistence, time-sync quality) · `explain <id>` full contract · execution context/MAC denial handling needed for honest NOT_TESTED.
Not now: kernel/platform expansion, MAC assessment, services, timers/cron, software, listeners,
hardware inventory, mappings, fleet/API, signing, remediation.

## 8. Exit codes (source: `lib/isedraf/exitcodes.json` *(PLANNED — not yet created)*; `make check` verifies code matches)
Precedence 5 > 4 > 6 > 3 > 2/1 > 0 · 0 clean · 1 unaccepted security change · 2 incomplete / NOT_COMPARABLE ·
3 = 1+2 · 4 baseline not applicable · 5 tool integrity failure · 6 no approved baseline ·
65 approval refused · 66 run in progress · 67 state root unwritable · 64+ usage/engine.
Must propagate unchanged through systemd-run re-exec.

## 9. Prototype fails unless
10 unchanged runs → 0 changes · ISEDRAF upgrade on unchanged host → 0 security changes ·
NOT_TESTED never REMOVED · incomplete snapshot never approvable · snapshots never rewritten ·
new privileged identity detected · method change never masquerades as drift · no host mutation ·
artifacts inspectable without ISEDRAF · no runtime egress path · governance files unchanged without owner manifest update ·
every commit discloses AI assistance.
