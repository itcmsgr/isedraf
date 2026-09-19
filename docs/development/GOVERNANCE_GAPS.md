<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Known Governance Gaps

Status: IMPLEMENTED
Implements: D-96, D-83

Controls that are **intended but not currently in force**. Recorded here so that no reader — human or
LLM — assumes protection that does not exist. A gap is never compensated for by weakening a different
control.

## KGG-001 — `main` is not branch-protected

**State:** `NOT_AVAILABLE_CURRENT_PLAN`

Repository rulesets and classic branch protection both return
*"Upgrade to GitHub Pro or make this repository public"* for a private repository on a personal account.

**What is therefore possible on the remote:** force-push to `main`, deletion of `main`, merging without a
pull request, and merging with the four governance checks red. The checks run and report, but cannot be
*required*.

**Not compensated by:** making the repository public. `OD-01` (the public project name is not cleared)
blocks that, and D-90 blocks public release. Visibility is not traded for branch protection.

**Mitigations actually in force:** the prototype `pre-push` hook (activated at Prompt 04) refuses every
push locally; push authorization is a separate owner amendment; a single human owner holds the only
credential; the four gates run on every push and pull request and their results are visible.

**Resolution:** apply the prepared ruleset when the plan permits, or when the repository becomes public
after OD-01. Requires: block force-push, block deletion, require pull request, require linear history,
require the four checks, bypass limited to owner emergency use.

## KGG-002 — GitHub secret scanning and push protection unavailable

**State:** `NOT_AVAILABLE_CURRENT_PLAN`

**Mitigation:** a deterministic local secret-pattern gate is added to `make check` and CI at Prompt 04 W0.
It is **defense in depth and is not equivalent to GitHub secret scanning** — it matches obvious private-key,
token and credential patterns only, has no partner-token feed, no historical scan of existing history, and
no push-time enforcement on the server.

## KGG-003 — Private vulnerability reporting unavailable

**State:** `NOT_AVAILABLE` — the feature applies to public repositories.

**Mitigation:** `SECURITY.md` directs reports privately to `contact@itcms.gr` and away from public issues.
The issue-template `config.yml` surfaces the same route before an issue can be opened.

## KGG-004 — Private forking cannot be disabled

**State:** `NOT_AVAILABLE_ACCOUNT_TYPE` — the setting exists only for organization-owned private
repositories; `itcmsgr` is a personal account.

**Exposure:** low while the repository has a single collaborator, since only accounts with access can fork.

## KGG-005 — Dependabot action upgrade deferred

**State:** `DEFERRED` by owner decision (D-96 bootstrap phase).

PR #1 (`actions/checkout` 4.2.2 → 7.0.1) is closed, not rejected. An unrelated major Action upgrade should
not move beneath the first implementation CI milestone. Revisit when the governance workflow is reviewed
as a whole. Pinning policy is unchanged: every third-party action is pinned to a full commit
SHA, enforced by `check-action-pins` rather than asserted (KGG-009 closed 2026-09-18).

## KGG-006 — The requirement-ID half of D-105 is inert until Prompt 04

**State:** `PARTIALLY_ENFORCED`

`check_requirement_refs.py` proves three things: decisions cited resolve, requirement IDs are unique, and
no amendment is cited as authority. All three run everywhere.

Its fourth check — *every cited requirement ID resolves to a definition* — needs the frozen architecture
documents, which live under `planning/` (untracked) until Prompt 04 installs them at
`docs/architecture/`. In a CI checkout they are absent, so the check runs in **decisions-only** mode and
reports which mode it used.

This is recorded rather than hidden because **GOV-001** requires exactly that: an invariant is either
enforced, or documented as not currently enforceable. The falsifiability harness makes the same statement
mechanically — it **skips** that injection with an explicit message rather than reporting a pass it did
not earn.

**Closes at:** Prompt 04, when the frozen architecture is installed under `docs/architecture/`. The gate
then runs in `full` mode in CI with no change to its code, and the harness injection activates
automatically.

**Meanwhile:** the check runs in `full` mode on the owner's workstation, where `planning/` is present, and
it has already caught two real defects — two dangling requirement references in the Round 1 review, and a forward reference
introduced during the repair pass itself.

## KGG-007 — Historical name references intentionally retained

**State:** `RETAINED_BY_DESIGN`

Per D-108, `planning/` is **not** renamed. It holds the prompt pack, the NFTBan engineering inventory and
five rounds of adversarial review findings, all of which legitimately record the earlier working name.
Falsifying that history would be worse than an inconsistent string.

| Location | Class | Why retained |
|---|---|---|
| `planning/prompts/**` | `HISTORICAL_RECORD` | the original prompt pack as delivered |
| `planning/blueprint/00_nftban/**` | `HISTORICAL_RECORD` | read-only NFTBan inventory, quotes the old name |
| `planning/blueprint/20_review/**` | `HISTORICAL_RECORD` | review findings quote the text they reviewed |
| `planning/bootstrap/**` | `HISTORICAL_RECORD` | superseded bootstrap staging |
| `docs/architecture/AMENDMENTS.md` | `HISTORICAL_RECORD` | amendment history is provenance (D-106) |

Active instructions never treat the old name as current product identity, and `check-refs`/`check-paths`
scan only the active tree. The earlier name was an internal codename; ISEDRAF is the project name (D-108).

## KGG-008 — Trademark clearance outstanding

**State:** `NOT_CLEARED`

`NAME_STATUS = FINALIST — CLEARED FOR PROJECT USE`. Preliminary technical and brand clearance passed with
no exact software, company, package, domain or obvious trademark collision. The near-name **ISEDRA** — an
active Cyprus company with no observed software or security activity, and a fashion product name — is
recorded rather than ignored, because one letter of distance deserves a formal opinion rather than an
assumption.

**Formal EUIPO / WIPO / USPTO / TMview clearance is required before public release.** D-90 already blocks
public release; this is the remaining condition on it.

## KGG-009 — `actions/setup-python` pinned by tag — CLOSED 2026-09-18

**State:** `CLOSED`

The action was pinned to the mutable tag `v5` because the session that added it could not
resolve a commit digest offline, and writing an unverified 40-hex string that merely *looks* pinned
would have been worse than an honest tag.

The digest was resolved from the forge's own API — `a26af69be951a213d495a4c3e4e4022e16d87065`, which
is `v5.6.0` — and the workflow now pins it, with the human-readable version as a trailing comment so
the pin stays reviewable.

Closed for a second reason: `README.md` asserted *"pinned to a full commit SHA — no tag exceptions"*
while this gap existed, so the documentation was false for as long as the gap was open. The claim is
now true, and `check-action-pins` keeps it true.

## KGG-010 — Cross-version determinism is not demonstrable on a single-interpreter host

**State:** `CI_ONLY`

`scripts/vectors/crossversion.sh` compares canonical output across every Python interpreter present. A
developer workstation with one interpreter cannot demonstrate anything, and the script **says so and
skips** rather than reporting a pass it did not earn.

`NORM-039`'s cross-version obligation is therefore met by the **CI matrix**, not by `make check` locally.
The matrix declaration is itself gated (`check-gate-coverage`) and falsifiable (two injections: removing
the 3.9 lane, and a lane that boots an interpreter without running the vectors), so the obligation cannot
be silently dropped — but a local green `make check` is **not** evidence for it.

## KGG-011 — CodeQL, Scorecard and artifact attestations are written and have never run

**State:** `WRITTEN_NEVER_RUN`

Three workflows exist in the repository and none of them has executed once:

| Workflow | Requires | Observed |
|---|---|---|
| `.github/workflows/codeql.yml` | a public repository, or Advanced Security | never run |
| `.github/workflows/scorecard.yml` | a public repository | never run |
| `.github/workflows/release-candidate.yml` | artifact attestations, which need a public repository on this plan | never run |

Each job carries `if: github.event.repository.visibility == 'public'`. A skipped job reports
**green**, which is the exact failure mode this project keeps finding — so each workflow also
carries an unconditional `guard` job that **fails** if the repository is public (the analysis was
therefore due) and the analysis did not run. The skip is attributed, never silent.

**What may therefore be displayed:** nothing. No CodeQL badge, no Scorecard score, no provenance
or attestation claim, and no SLSA level. `docs/CURRENT_STATE.md` lists all three under
*Written, never run*, which is a status the generator understands rather than a note a reader
has to find.

**What is genuinely proven today, and is separate from this gap:** the SBOM. It is generated by
`scripts/ci/generate_sbom.py` from the **final artifact** on every local build, and
`make check-sbom` checks each document against the package it names — for the RPM, against
`rpm`'s own recorded per-file SHA-256 digests, which is an independent second account of the same
bytes. Three defect injections in `make check-falsifiable` prove that gate can fail.

**The attestation is the weaker half and is honest about it.** `scripts/ci/check_attestation_falsifiable.sh`
exists to prove an attestation refuses a forgery — it verifies the genuine artifact, flips one byte in a
copy, and requires the verifier to reject it. It has **never executed**, for the same reason as the
workflow that calls it. Until it has, "attested" is not a word this project may use.

**Closes when:** the public repository exists, the three workflows run for the first time, and their
runs are linked from the status page. Not before.

## KGG-012 — The falsifiability sandbox had no commit, so no injection could reach a completed build

**State:** `CLOSED 2026-09-18`

`inject()` built its disposable tree with `git init` and `git add -A` and never committed. Any gate
downstream of `packaging/build.sh` was therefore unreachable: `git archive HEAD` failed, the build
died at the tarball, and nothing was ever packaged inside the sandbox.

The two package injections that existed were **not** false passes — both are caught during staging,
before `git archive` — and that is precisely why the hole stayed invisible. It surfaced only when the
first injection that needed a *finished artifact* was added (the SBOM cases), which reported
`MUTATION_TOOL_CRASHED` rather than a pass, exactly as the Z-20 contract requires.

**Fix:** the sandbox now makes one commit. A fresh `git init` inherits no hooks, so nothing is
bypassed. Injection count 53 → 56, all firing.

**Lesson recorded:** the harness is a gate, and a gate needs its own falsification. `Z-20`'s
self-test caught the symptom correctly; what it could not catch is a *reachability* limit, because
an unreachable gate and a passing gate look identical from outside.

## KGG-013 — The rpm and the deb shipped different documentation — CLOSED 2026-09-19

**State:** `CLOSED`

`packaging/build.sh` stages four documents into `/usr/share/doc/isedraf`. The RPM spec's own
`%install` section — a **second implementation** of the same payload, assembling from the source
tarball rather than from the staged tree — installed two of them. An EL user therefore received
half the documentation a Debian user did, and nothing in either tree was wrong.

Found while writing an unrelated defect injection, not by review. That is the point: two
implementations of "what goes in the package" drift silently, because each is internally
consistent.

**Fix:** the spec installs the same four documents, and `check_package_payload.sh` now compares
the deb and rpm documentation sets **against each other**. A defect injection removes one document
from the spec and requires the gate to fail.

**Owner decision 2026-09-19 recorded in the same gate:** `CLAUDE.md` is public — it documents the
contributor and AI-assisted guardrails, and there is no security benefit in hiding rules such as
*do not weaken a gate to make work pass*. It ships in the git repository and the source tarball,
and it is **excluded from the runtime payload**: a package installs what the tool needs to run
plus the documentation a user was meant to read, and contributor guardrails are neither. Verified
absent, then gated so it stays absent, with its own injection.

`planning/` remains private and is never exported, under the same decision.
