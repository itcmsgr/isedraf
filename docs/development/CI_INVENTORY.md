# ISEDRAF — Target CI / Validation Inventory

Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0
Status: IMPLEMENTED
Implements directive: §19, §20, §21, §22, §23, §24, §25, §26, §27

<!-- doclint:exempt-forbidden-terms -->

**Nothing here is implemented.** This is the target contract. Gates are built at Prompt 04 W0
(governance/source/runtime safety) and Prompt 05 (corpus/product invariants).

**Principles.** No unexplained CI. No badge-driven engineering. Every gate has a reason, a requirement ID,
a local command and a defined failure behaviour. Every mechanically enforceable frozen invariant should
become a mechanical gate. `make check` is **the** authoritative local pre-commit entry point (§13); CI
invokes the same targets rather than re-implementing them in YAML — this is what prevents a gate silently
degrading to a warning.

**Blocking tiers.** `W0` = must pass from the bootstrap commit · `W-n` = milestone · `v0.1` = before
release · `LATER` = deferred with a recorded reason. There is **no warning tier**.

---

## 1. Governance (directive §20)

| Gate | Purpose | Req IDs | Local command | CI job | When | Failure | Tier | Source |
|---|---|---|---|---|---|---|---|---|
| G-01 frozen manifest | frozen architecture unchanged without owner amendment | D-68 | `make check-frozen` | `ci-governance / frozen` | pre-commit, PR | fail | **W0** | `ci-architecture.yml` (ADAPT) |
| G-02 governance manifest | CLAUDE.md, `.claude/settings.json`, `git-hooks/*`, frozen verifier, `exitcodes.json`, `runtime-imports.allow`, doc-lint config unchanged without owner update | D-83 | `make check-governance` | `ci-governance / guardrails` | pre-commit, PR | fail | **W0** | new |
| G-03 installed-hook parity | `.git/hooks/*` identical to `git-hooks/*` | D-83, D-73 | `make check-governance` | — (local only) | pre-commit | fail | **W0** | new |
| G-04 register presence | `docs/architecture/DECISIONS_REGISTER.md` is the **only** repository copy | D-68 | `make check-frozen` | `ci-governance / frozen` | PR | fail | **W0** | new |
| G-05 repo authority | repo path is canonical; **no remote configured** during prototype | D-95, §8 | `make check-repo` | `ci-governance / authority` | pre-commit | fail | **W0** | `check-repo-authority.sh` (ADAPT) |
| G-06 delete guard | protected paths not deleted without an authorization marker | D-83 | `make check-delete-guard` | `ci-governance / delete` | PR | fail | **W0** | `shell-delete-guard.sh` (PORT) |
| G-07 test/requirement floor | test and requirement-ID population never silently shrinks | D-69, §39 | `make check-floor` | `ci-governance / floor` | PR | fail | W1 | `check-test-count-floor.sh` (PORT) |
| G-08 requirements trace freshness | generated trace matches `Implements:` tags | D-89, §39 | `make docs-check` | `ci-docs / generated` | PR | fail | W1 | `test-authority.py` (ADAPT) |
| G-09 current-state freshness | `docs/CURRENT_STATE.md` regenerates identically | D-89, §38 | `make docs-check` | `ci-docs / generated` | PR | fail | W1 | same |
| G-10 requirement binding | every requirement ID has a test or is `BLOCKED` in the trace | §39, D-69 | `make check-binding` | `ci-governance / binding` | PR | fail | W2 | `check-producer-signal-binding.sh` (ADAPT) |
| G-11 control lifecycle | `DRAFT/EXPERIMENTAL/STABLE/DEPRECATED/RETIRED` valid; retired IDs never reused | D-80 | `make check-lifecycle` | `ci-governance / lifecycle` | PR | fail | W2 | `check-control-enforcement.sh` (ADAPT) |
| G-12 AI disclosure trailer | every commit carries `Assisted-by:` | D-93 | `commit-msg` hook | `ci-governance / trailers` | commit, PR | fail | **W0** | new |

## 2. Licensing and ownership (directive §21)

| Gate | Purpose | Req IDs | Local command | CI job | When | Failure | Tier | Source |
|---|---|---|---|---|---|---|---|---|
| L-01 file classification | every tracked file in exactly one class; `UNCLASSIFIED` = failure | D-62, D-90 | `make check-headers` | `ci-governance / headers` | PR | fail | **W0** | `check-license-identity.sh` (ADAPT) |
| L-02 header presence | `OWNED_HEADER_APPLICABLE` compliance = 100% | D-62 | `make check-headers` | same | PR | fail | **W0** | same |
| L-03 **`meta:owner` canonical value** | value is exactly `Antonios Voulvoulis / ITCMS`; any other value rejected | §2, §21 | `make check-headers` | same | PR | fail | **W0** | new — closes NFTBan's drift |
| L-04 SPDX identifier | `MPL-2.0` on every eligible file | D-02 | `make check-headers` | same | PR | fail | **W0** | `check-license-identity.sh` |
| L-05 SPDX copyright | canonical holder string verbatim (`grep -F`) | D-62 | `make check-headers` | same | PR | fail | **W0** | same |
| L-06 no generated stamping | generated files are not header-stamped | D-89 | `make check-headers` | same | PR | fail | **W0** | same |
| L-07 no JSON mutation | JSON is `NON_HEADER_FORMAT`; adding a synthetic `_license`/`_owner` key fails | §6, D-15 | `make check-headers` | same | PR | fail | **W0** | new |
| L-08 fixture byte safety | `FIXTURE_BYTE_SENSITIVE` files unmodified by header tooling | D-37 | `make check-headers` | same | PR | fail | **W0** | `check-license-identity.sh` |
| L-09 REUSE | `reuse lint` clean incl. JSON | D-90 | `make check-reuse` | `ci-governance / reuse` | PR | fail | **W0** | `ci-reuse.yml` (PORT) |
| L-10 LICENSE integrity | `LICENSE` is the exact MPL-2.0 text | D-02 | `make check-license` | same | PR | fail | **W0** | new |
| L-11 contact canon | `contact@itcms.gr`; no `nftban.com` address anywhere | §1, §36 | `make check-headers` | same | PR | fail | **W0** | new |

## 3. Source safety — Python (directive §22)

| Gate | Purpose | Req IDs | Local command | CI job | When | Failure | Tier | Source |
|---|---|---|---|---|---|---|---|---|
| P-01 forbidden constructs | builtin `eval()`/`exec()`, `pickle`, `shell=True`, `os.system`, dynamic import from content paths | D-19, D-71 | `make check-constructs` | `ci-python / constructs` | PR | fail | **W0** | `semgrep.yml` (ADAPT) |
| P-02 scoped `os.execv*` | permitted **only** in `lib/isedraf/launcher/` with fixed absolute paths | D-71 | `make check-constructs` | same | PR | fail | **W0** | new |
| P-03 bytecode-free syntax | in-memory `ast.parse`/`compile` on 3.9 **and** 3.12; **never** `python -m py_compile` | D-86 | `make check-syntax` | `ci-python / syntax` | PR | fail | **W0** | `check-build-provenance.sh` (ADAPT) |
| P-04 no `.pyc` | no `.pyc`/`__pycache__` in tree or package | D-17, D-86 | `make check-syntax` | same | PR | fail | **W0** | same |
| P-05 runtime import allowlist | every runtime import in `lib/isedraf/runtime-imports.allow` *(PLANNED — not yet created)* | D-84 | `make check-imports` | `ci-python / imports` | PR | fail | **W0** | new |
| P-06 no third-party runtime | dev/CI deps in `requirements-dev.txt`, never imported by runtime | D-12 | `make check-imports` | same | PR | fail | **W0** | new |
| P-07 Python pin parity | 3.9 floor and 3.12 both green | D-12 | `make check-pin` | `ci-python / matrix` | PR | fail | W1 | `check-toolchain-pin-parity.sh` (ADAPT) |
| P-08 subprocess hygiene | argv list, `shell=False`, clean env, fixed `PATH`, `LC_ALL=C`, timeout, bounded output, `stdin=DEVNULL` | D-18 | `make check-constructs` | `ci-python / constructs` | PR | fail | W1 | new |
| P-09 static analysis | CodeQL Python pack | D-19 | — | `ci-python / codeql` | PR, schedule | fail | W1 | `codeql.yml` (ADAPT) |

## 4. Source safety — Shell (directive §23)

| Gate | Purpose | Req IDs | Local command | CI job | When | Failure | Tier | Source |
|---|---|---|---|---|---|---|---|---|
| S-01 syntax | `bash -n` on every tracked `.sh` | D-12 | `make lint-shell` | `ci-shell / syntax` | PR | fail | **W0** | `ci-bash.yml` (PORT) |
| S-02 ShellCheck | defect linting (dev/CI tool only) | D-13 | `make lint-shell` | `ci-shell / shellcheck` | PR | fail | **W0** | `shellcheck.yml` (PORT) |
| S-03 heredoc safety | unescaped backticks, `$( )`, arithmetic in heredocs | D-19 | `make check-shell-safety` | `ci-shell / safety` | PR | fail | **W0** | `test-heredoc-safety.sh` (PORT) |
| S-04 no dynamic `bash -c` | `bash -c`/`sh -c` with non-constant strings forbidden | D-71 | `make check-shell-safety` | same | PR | fail | **W0** | new |
| S-05 pipefail / EPIPE | masked pipeline failures; no `set -e` reliance in collectors | D-13 | `make check-shell-safety` | same | PR | fail | W1 | `check-pipefail-epipe-shortcircuit.sh` (PORT) |
| S-06 collector metadata | every collector declares `meta:privilege` and `meta:mutates` | D-13, §23 | `make check-headers` | `ci-governance / headers` | PR | fail | W1 | new |
| S-07 `meta:mutates="none"` | no collector mutates host state | D-13, D-25 | `make check-collectors` | `ci-shell / collectors` | PR | fail | W1 | new |
| S-08 no host-changing commands | `apt update`, `dnf check-update`, `sudo -l -U`, `setenforce`, `semanage`, `setsebool`, `semodule` absent from runtime | D-25, D-67 | `make check-collectors` | same | PR | fail | **W0** | `check-nft-writes.sh` (pattern) |

## 5. Runtime architecture — no egress / no database (directive §24)

| Gate | Purpose | Req IDs | Local command | CI job | When | Failure | Tier | Source |
|---|---|---|---|---|---|---|---|---|
| N-01 import allowlist | rejects `socket ssl urllib http smtplib ftplib xmlrpc sqlite3 dbm shelve`, asyncio networking, `multiprocessing.connection` | D-84 | `make check-imports` | `ci-python / imports` | PR | fail | **W0** | new (inverse of `check-comms-direct-send.sh`) |
| N-02 no network subprocess | no subprocess to `curl wget nc ssh scp` | D-84 | `make check-imports` | same | PR | fail | **W0** | new |
| N-03 no API server | no listening socket, no HTTP server | D-49 | `make check-imports` | same | PR | fail | **W0** | new |
| N-04 no embedded DB | no authoritative SQLite, no DB client | D-49, D-84 | `make check-imports` | same | PR | fail | **W0** | new |
| N-05 sandbox address families | `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any` present and effective | D-85 | — | corpus | Prompt 05 | fail | W2 | new |
| N-06 egress attempt blocked | an egress attempt inside the sandbox is blocked **and reported** | D-85, test 20 | — | corpus | Prompt 05 | fail | W2 | new |
| N-07 report wording | report states `NETWORK EGRESS: KERNEL_RESTRICTED` or `CODE_ONLY` | D-85 | `make docs-check` | `ci-docs` | PR | fail | W2 | new |

## 6. Path, privilege and data safety

| Gate | Purpose | Req IDs | Local command | CI job | When | Failure | Tier | Source |
|---|---|---|---|---|---|---|---|---|
| X-01 path safety | `O_NOFOLLOW|O_EXCL`; refuse symlinked or non-root-owned report paths | D-20 | `make check-paths` | `ci-python / paths` | PR | fail | **W0** | new (NFTBan gap) |
| X-02 permissions | `umask 077`; dirs 0700, files 0600 | D-20 | `make check-paths` | same | PR | fail | W1 | new |
| X-03 install path safety | refuse `/usr/lib/isedraf` if not root-owned / group- or world-writable → `ENGINE_UNSAFE_INSTALL` | D-17 | — | corpus | Prompt 05 | fail | W2 | new |
| X-04 no internal privilege escalation | no internal sudo, setuid, polkit, D-Bus helper, file capabilities, daemon | D-23 | `make check-constructs` | `ci-python / constructs` | PR | fail | **W0** | new |
| X-05 capability bound | engine bounding set `CAP_DAC_READ_SEARCH` only; no `CAP_SYS_ADMIN` anywhere | D-26 | `make check-constructs` | same | PR | fail | W2 | new |
| X-06 privacy scan | no real hostnames, IPs, usernames or key fingerprints in docs/fixtures | D-54 | `make check-privacy` | `ci-security / privacy` | PR | fail | **W0** | `privacy-scan.py` (ADAPT) |
| X-07 identifier leakage | no raw machine-id or hardware serial in canonical/export data | D-38, D-51 | `make check-privacy` | same | PR | fail | W1 | `private-identifier-gate.py` (ADAPT) |
| X-08 render escaping | `html.escape` on system strings; CSP meta; CSV formula-injection guard | D-21 | `make check-render` | `ci-python / render` | PR | fail | W4 | new |
| X-09 secret scan | no committed credentials | — | `make check-secrets` | `ci-security / gitleaks` | PR | fail | **W0** | `gitleaks.yml` (PORT) |

## 7. Snapshot / delta invariants (directive §25)

All corpus-level; built at Prompt 05. Failure is always a hard fail.

| Gate | Purpose | Req IDs | Tier |
|---|---|---|---|
| D-01 canonical serialization | UTF-8, sorted keys, defined array order, one timestamp format, locale-independent; byte-stable | D-37, OD-10 | W1 |
| D-02 snapshot immutability | completed `snapshots/SDS-*` never modified; contain no changes/findings | D-41 | W1 |
| D-03 evaluation separation | `evaluations/EVL-*` regenerable, keyed by snapshot + baseline revision + engine + rules version | D-41, D-42 | W3 |
| D-04 baseline revision | `BL-n = hash(approved snapshot hash + acceptance records)` | D-43 | W3 |
| D-05 acceptance binds hash | acceptance binds the exact accepted normalized state hash | D-44 | W3 |
| D-06 `NOT_TESTED` never `REMOVED` | — | D-46, test 5 | W3 |
| D-07 `NOT_TESTED` never improvement | — | D-46 | W3 |
| D-08 incomplete → `NOT_COMPARABLE` | delta only where both sides `COLLECTED` | D-46 | W3 |
| D-09 method change ≠ drift | collector/parser version change with identical state is silent | D-45, test 4 | W3 |
| D-10 orphan recovery | crash between rename and ledger append → `ORPHANED`, no corruption | D-50, test 6 | W3 |
| D-11 ledger consistency | append-only, hash-chained, IDs and hashes only, never rewritten | D-51 | W3 |
| D-12 whole-run lock | exclusive `flock` for the whole run | D-50 | W1 |
| D-13 crash ordering | temp → fsync → atomic rename → ledger append + fsync | D-50 | W1 |
| D-14 observations never drive CHANGED | state hashed/diffed; observations shown only | D-36, test 14 | W1 |

## 8. Product invariants (directive §26)

Release-blocking acceptance tests 1–22 (register §13). **Never weakened to make an implementation pass**
(D-69, §41). Selected:

| Test | Assertion | Tier |
|---|---|---|
| 2 | unchanged host × 10 runs → 0 changes | W3 |
| 3 | ISEDRAF upgrade on unchanged host → 0 security changes | W3 |
| 5 | root baseline + unprivileged run → `NOT_COMPARABLE`, never `REMOVED`, exit ≥ 2 | W3 |
| 7 | cloned VM → `POSSIBLE_CLONE` + `BASELINE_NOT_APPLICABLE`, exit 4 | W3 |
| 8 | new sudo user → `SECURITY_REGRESSION`, exit 1 | W3 |
| 11 | filesystem diff proves zero writes outside `/var/lib/isedraf` | W2 |
| 13 | no approved baseline → exit 6, never 0 | W1 |
| 14 | only last-login changes → no identity-state drift | W1 |
| 15 | home birth time never `EVENT_RECORDED`; missing evidence → `UNKNOWN` | W1 |
| 16 | new sudo privilege in `identity privileged` **and** `SECURITY_REGRESSION` | W3 |
| 17 | quick and detailed identity views hash-equal at source | W1 |
| 18 | account-change recording present/absent without inventing remote state | W2 |
| 19 | edited CLAUDE.md / settings / hook copy → governance gate fails | **W0** |
| 20 | runtime `sqlite3`/network import, or subprocess `curl` → `make check` fails | **W0** |
| 21 | unprivileged `logger -t useradd` spoof → never `EVENT_RECORDED` | W2 |
| 22 | commit without `Assisted-by:` → rejected | **W0** |

Plus ISEDRAF's added lifecycle invariant (no NFTBan equivalent): **package upgrade must not invalidate an
existing baseline** — a schema or collector-version change across an upgrade is `COLLECTION_METHOD_CHANGED`
+ `baseline rebind`, never silent drift.

## 9. Documentation (directive §27)

| Gate | Purpose | Req IDs | Local command | CI job | When | Failure | Tier | Source |
|---|---|---|---|---|---|---|---|---|
| C-01 internal links | no broken internal links | D-89 | `make docs-check` | `ci-docs / lint` | PR | fail | **W0** | `lychee` (PORT, offline) |
| C-02 requirement IDs | no unknown requirement IDs | D-89 | `make docs-check` | same | PR | fail | **W0** | new |
| C-03 status values | no unknown status/enum names | D-89 | `make docs-check` | same | PR | fail | **W0** | new |
| C-04 exit codes | documented codes match `lib/isedraf/exitcodes.json` *(PLANNED — not yet created)* | D-72, §40 | `make docs-check` | same | PR | fail | **W0** | new |
| C-05 forbidden claims | `compliant`, `guaranteed`, `tamper-proof`, `non-repudiable`, `host unchanged`, `best`, `beats`, `replaces`, `revolutionary`, `military-grade`, `100% secure` — except files marked `doclint:exempt-forbidden-terms` or spans marked `<!-- doclint:quote -->` | D-87, §34 | `make docs-check` | same | PR | fail | **W0** | new |
| C-06 coexistence framing | no `X vs Y`, rankings, or unverified claims about another project | D-87, §34 | `make docs-check` | same | PR | fail | **W0** | new |
| C-07 STUB discipline | `Status: STUB` docs carry headings only, no behavioural prose | D-88 | `make docs-check` | same | PR | fail | **W0** | new |
| C-08 status labels | every feature statement is `IMPLEMENTED`/`EXPERIMENTAL`/`PLANNED`/`FUTURE`/`OUT_OF_SCOPE`; present tense only for the first two | D-88 | `make docs-check` | same | PR | fail | W1 | new |
| C-09 generated freshness | `CURRENT_STATE.md`, `requirements-trace.md`, `CLI.md`, `EXIT_CODES.md`, `isedraf.8` regenerate identically | D-89 | `make docs-check` | `ci-docs / generated` | PR | fail | W1 | `test-authority.py` (ADAPT) |
| C-10 platform truth | supported-platform statement matches corpus coverage | D-64 | `make docs-check` | same | PR | fail | v0.1 | new |
| C-11 schema/version consistency | schema docs match emitted artifacts | D-56 | `make docs-check` | same | PR | fail | W4 | `check-config-format-coverage.sh` (ADAPT) |
| C-12 version coherence | `VERSION` ↔ `CHANGELOG` ↔ release date | §40 | `make check-version` | `ci-docs / version` | PR | fail | **W0** | `check-version-date-coherence.sh` (PORT) |
| C-13 no wiki | no GitHub Wiki content or wiki-only architecture | D-87, §37 | `make docs-check` | same | PR | fail | **W0** | new |

## 10. Packaging and lifecycle

| Gate | Purpose | Req IDs | Tier | Source |
|---|---|---|---|---|
| K-01 payload parity | one install manifest drives DEB and RPM; payloads match | D-61 | W4 | `build-packages.yml` (ADAPT) |
| K-02 maintainer-script safety | scripts only create ISEDRAF-owned dirs/permissions; never touch SSH, PAM, audit, sysctl, users, services, MAC | D-60 | W4 | new |
| K-03 evidence survival | remove/purge never deletes `/var/lib/isedraf`; only `isedraf purge-data` does | D-53 | W4 | `check-uninstall-firewall-safety.sh` (pattern) |
| K-04 conffile stability | shipped config not silently mutated; RPM `%config(noreplace)` / DEB conffile parity | D-53 | W4 | `check-conffile-mutation.sh` (ADAPT) |
| K-05 honest upgrade test | upgrade scenarios run **without** `--force-confold --force-confdef` | test 3 | W4 | lesson from `ci-update-canonization.yml` |
| K-06 no `.pyc` in package | byte-compile disabled | D-17 | W4 | new |
| K-07 timer disabled | systemd timer ships disabled; install never enables recurring auditing | D-58 | W4 | new |
| K-08 unit path resolution | unit `Exec*` paths resolve to shipped artifacts | D-58 | W4 | `test-systemd-execstart-payload-resolution.sh` (ADAPT) |
| K-09 namespace guard | install writes nothing outside declared paths | test 11 | W4 | `ci-fresh-install-namespace-guard.yml` (ADAPT) |

## 11. Repository security (directive §17)

| Gate | Purpose | Tier |
|---|---|---|
| R-01 action SHA pinning | 100% of `uses:` pinned to a 40-hex SHA; **no tag exceptions** | **W0** |
| R-02 least-privilege tokens | top-level `permissions: {}`; minimal per job | **W0** |
| R-03 per-job timeouts | `timeout-minutes` on **every** job | **W0** |
| R-04 no secrets on `pull_request` | fork PRs never see secrets | **W0** |
| R-05 concurrency groups | superseded runs cancelled | **W0** |
| R-06 artifact trust | consumed artifacts hash-verified | W4 |
| R-07 third-party action budget | prefer `run:` over an action; each action justified | **W0** |
| R-08 workflow lint | workflows parse and declare required fields | **W0** |

## 12. Release engineering (directive §16)

**Publication remains disabled.** Local build verification only; no tags, no releases, no remote.

| Item | Status |
|---|---|
| Version source of truth (`VERSION`) | W0 |
| CHANGELOG discipline | W0 |
| Local DEB/RPM build verification | W4 |
| Checksums for local artifacts | W4 |
| Tags, releases, signing, SBOM, repository publication | **DEFER** — blocked by OD-01, OD-07, OD-09 |

## 13. Falsifiability harness (directive §19; NFTBan P1)

A single `make check-falsifiable` target proves each gate **discriminates**, by injecting each defect class
into a disposable copy of the tree and asserting the gate fails. Consolidated into one harness rather than
one twin per gate (INV-04).

W0 injection set (from Prompt 04's exit criteria, made standing):
missing header · junk `meta:owner` · edited frozen doc · builtin `exec()` · `os.execv` outside the launcher ·
`bash -c` with a variable · mismatched exit-code constant · committed `.pyc` · `import socket` ·
`import sqlite3` · subprocess `curl` · edited `CLAUDE.md` · edited `.claude/settings.json` ·
`.git/hooks/pre-push` *(PLANNED — not yet created)* differing from the repo copy · STUB doc containing behavioural prose ·
commit message without `Assisted-by:` · forbidden claim in a non-exempt doc · broken internal link ·
stale generated doc · unpinned action · workflow job without a timeout · symlinked output path.

> A gate that has never been observed to fail is not a gate.

---

## Totals

| Category | Gates | W0-blocking |
|---|---|---|
| Governance | 12 | 8 |
| Licensing / ownership | 11 | 11 |
| Python safety | 9 | 6 |
| Shell safety | 8 | 5 |
| No egress / no DB | 7 | 4 |
| Path / privilege / data | 9 | 4 |
| Snapshot / delta invariants | 14 | 0 |
| Product invariants | 22 | 4 |
| Documentation | 13 | 9 |
| Packaging | 9 | 0 |
| Repository security | 8 | 7 |
| Release | 5 | 2 |
| **Total** | **127** | **60** |

Every gate above cites a requirement ID and a source. None is implemented yet.
