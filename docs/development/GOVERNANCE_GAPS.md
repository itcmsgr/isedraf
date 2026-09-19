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

## KGG-001 — `main` is not branch-protected — CLOSED for the public repository 2026-09-19

**State:** `CLOSED (public)` · `NOT_AVAILABLE_CURRENT_PLAN (private)`

A ruleset is active on `itcmsgr/isedraf` (public): deletion blocked, force-push blocked, linear
history required, and seven required status checks — `make check`, `make check-falsifiable`,
`make check-gate-coverage`, both W1-A vector lanes, and both CodeQL language lanes.

**Observed to fire, not assumed:** a force-push of a rewritten commit was attempted against `main`
and was **refused** — *"push declined due to repository rule violations"*. A rule that has never
been observed to refuse anything is not protection.

**Consequence, stated rather than discovered later:** required checks apply to every push including
a fast-forward, and a commit cannot have passing checks before it exists on the forge. Updates to
the public repository therefore go through a pull request.

**Not enabled, deliberately:** `required_signatures`. No signing key is configured on the
workstation that maintains this repository, so the rule would block every push by anyone. Enabling
a rule nobody can satisfy is an outage, not protection. It is recorded here instead of quietly
omitted, and it closes when commit signing is set up.

`itcmsgr/isedraf-dev` (private) still cannot be protected — rulesets and classic branch protection
both require GitHub Pro or a public repository — and the original text below still describes it.

### The private engineering repository


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

**State:** `NOT_AVAILABLE_CURRENT_PLAN` · **an external scanner was found inside the trust surface, see below**

### An unapproved external service was observing both repositories

Found 2026-09-19. A **GitGuardian** GitHub App produced a check on every pull request. Nobody in this
project installed it for ISEDRAF; it arrived through an account-level installation.

**It was measured, not assumed.** The credentials available here cannot enumerate App installations
(`user/installations` → 403). The first experiment pushed a branch to the private repository, saw no
check, and was **discarded as invalid**: the same push to the *public* repository also produced no
check, so the method could not detect the thing it was looking for. A negative result from a method
with no positive control is not evidence.

The second experiment opened a pull request in each repository, with the public one as the positive
control:

| Repository | Visibility | GitGuardian check |
|---|---|---|
| `itcmsgr/isedraf` | public | **yes** — control fires |
| `itcmsgr/isedraf-dev` | **private** | **yes** |

Both probes were closed and their branches deleted immediately.

**Declared permissions** (public App manifest, owner `GitGuardian`, app id `46505`): `contents: read`,
and **write** on `checks`, `issues` and `pull_requests`. Scanning happens on the provider's
infrastructure, so repository content leaves GitHub.

**It cannot block a merge today** — the ruleset requires seven checks and GitGuardian is not one of
them. That is a property of our ruleset, not of the App.

**Verdict: RESTRICT.** Not because the service behaved badly — every check it produced passed — but
because `isedraf-dev` is the source of truth this project deliberately does not publish, and its
contents were being sent to a third party nobody chose for that purpose. The rule is that an external
service does not appear silently inside the trust surface.

**Owner action required, and it is a release blocker until done.** An App installation cannot be
modified with the credentials available to this project. GitHub → Settings → Applications → Installed
GitHub Apps → GitGuardian → Configure → *Only select repositories* → remove `itcmsgr/isedraf-dev`.
The account-level installation may stay if it is used elsewhere; only the repository selection needs
to change.

Keeping it on the **public** repository afterwards is defensible and would be recorded here as
`APPROVED_PUBLIC_ONLY`: nothing leaves that was not already published, and a second independent
scanner beside `check-privacy` — which is our own code checking our own rules — is genuinely useful.

### The local gate, which is not equivalent


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
| `docs/architecture/INTERNAL_RECORDS.md` | `HISTORICAL_RECORD` | amendment history is provenance (D-106) |

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

## KGG-011 — CodeQL, Scorecard and artifact attestations are written and have never run — CLOSED 2026-09-19

**State:** `CLOSED`

All three ran for the first time on 2026-09-19, on the public repository, and passed:

| Control | First observed run |
|---|---|
| CodeQL `python` and `actions`, security-extended | both language lanes analysed and passed |
| OpenSSF Scorecard | ran; results go to code scanning, **not** to the public Scorecard API, so no score is displayed |
| Build provenance | created for 6 subjects |
| SBOM attestation | one per versioned artifact (deb, rpm, source tarball) |
| **The attestation is binding** | each artifact verified, then a copy with one flipped byte was **refused** — `ATTESTATION_REJECTED_TAMPERED` at 6/6 artifacts |

The last row is the one that matters. An attestation only ever run against a good artifact has
demonstrated nothing; this one has now been observed to refuse a forgery.

Still not claimed: any SLSA level, and no release is published.

The text below records the state before that first run, because it is the reasoning that
produced the `WRITTEN_NEVER_RUN` status and the guard jobs, both of which remain in force.

### Before the first run

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

## KGG-014 — The RPM could not be built on the runner that builds the release — CLOSED 2026-09-19

**State:** `CLOSED`

Two defects in `packaging/rpm/isedraf.spec.in`, both invisible on the author's Fedora workstation
and both fatal on `ubuntu-latest`, which is the runner the release workflow uses:

| Defect | Why it passed locally | Why it failed on the runner |
|---|---|---|
| `BuildRequires: coreutils` | Fedora's rpm database contains a package by that name | a Debian/Ubuntu rpm database has never heard of it → `error: Failed build dependencies` |
| `%changelog` dated `Thu Sep 18 2026` | 2026-09-18 was a **Friday**; `rpmbuild` only **warns** | the warning was in a log nobody read |

Nothing in this package is compiled, so the correct number of build dependencies is zero.

**How it was found, which matters more than the defects:** it was invisible until the falsifiability
sandbox learned to commit (KGG-012) and the harness learned to print what a crashed gate actually
said. Before that, `MUTATION_TOOL_CRASHED` hid the gate's output behind `FALSIFIABLE_DEBUG=1` — so a
crash that happens **only on a CI runner** was undiagnosable from the CI log, the one place it
occurs. The harness now always prints it, and the very next run named the cause in one line.

**Fix:** `make check-packaging` (`scripts/ci/check_packaging.py`) checks the packaging metadata as
**text**, with no rpm, no dpkg and no builder, so it runs inside `make check` on any machine before a
commit instead of after a release. It rejects any `BuildRequires`, any `%changelog` entry whose
weekday does not match its date, a missing `BuildArch: noarch` and a missing `Architecture: all`.
Two injections prove it fails. Gates 14 → 15, injections 59 → 61.

**Lesson recorded:** *a package that builds on the author's distribution is not a package.* The same
sentence is in the gate's failure message, so the next person meets it at the point of failure rather
than in a document.

## KGG-015 — The packages were not reproducible, and leaked the builder's UID — CLOSED 2026-09-19

**State:** `CLOSED`

Two builds of an identical tree produced **different** `.deb` and `.rpm` bytes. The source tarball
was already reproducible; the two packages were not.

| Cause | Effect |
|---|---|
| `ar rc` (no `D`) | every member header carried the current time **and the builder's numeric uid and gid** |
| rpm `BUILDTIME` from the clock | a new digest on every build |

The uid was a **disclosure leak** as well as non-determinism: every `.deb` built before this date
carried the build account's UID to everyone who downloaded it. The privacy gate could not see it —
it reads the repository and the publication surface, not the inside of an `ar` member header.

Nothing in the documentation claimed reproducibility, so no statement was false. But the two-file
checksum design (`SHA256SUMS.build` local ground truth vs `SHA256SUMS` from downloaded assets)
invites a reader to rebuild and compare, and that was not something a user could actually do.

**Fix:** `ar rcD`, and `SOURCE_DATE_EPOCH` taken from the **commit being built** rather than from
the clock, with `use_source_date_epoch_as_buildtime` and `clamp_mtime_to_source_date_epoch`. Build
time is now a property of the source, not of the moment someone happened to run the build.

`make check-reproducible` builds twice and requires identical bytes, with an injection that removes
the `D` flag. Injections 61 → 62.

**Found by** attempting to verify a locally built artifact against the published attestation and
noticing the digests could not match — not by review.

**A second thing the runner taught us, twice.** The first version of the injection simply dropped
the `D` flag, and it **did not fire on CI**. Whether plain `ar rc` is deterministic depends on how
the local binutils was *compiled*: Ubuntu enables deterministic archives by default, Fedora does
not. The second version forced `U` — and **also passed silently on the runner**, so forcing
non-determinism through `ar` is not portable either.

Both versions fired on the workstation and passed on the runner, which is the worst possible
failure mode: a green injection that proves nothing, on the machine that builds the release.

This is precisely why the build writes `D` explicitly and never relies on a default. The injection
now stamps a **nanosecond clock reading** into the package instead. The property under test is
*"does this gate detect a non-reproducible build"*, so the experiment must **make** one, on every
platform, rather than hope the environment provides it.

## KGG-016 — Reproducible on one machine is not reproducible across machines

**State:** `PARTIALLY_CLOSED` — tarball and `.deb` closed, `.rpm` open by toolchain

`make check-reproducible` builds twice and compares, which proves the build is **deterministic**.
It says nothing about whether a different machine gets the same bytes — and that is the property a
user actually needs, because "rebuild it yourself and compare" is done on *their* machine.

Measured 2026-09-19 by rebuilding the public commit on a Fedora workstation and comparing against
the artifacts `ubuntu-latest` produced from the same commit:

| Artifact | Across machines | Why |
|---|---|---|
| source tarball | **identical** (`dd43822d75091ea7…`) | `git archive` + `gzip -n9`, no machine-dependent input |
| `.deb` | differed, **now fixed** | `Installed-Size` came from `du -sk`, which reports **disk** usage: 224 KiB on btrfs, 260 KiB on ext4. The package carried a property of the builder's *filesystem*. It is now summed from file sizes, which depend only on the payload. |
| `.deb` (second cause) | differed, **now fixed** | `DEBIAN/sha256sums` was generated with `find … -exec sha256sum`, which returns **directory order** — a property of the filesystem. The same 24 lines came out in a different sequence on btrfs and on ext4, so the control archive differed while the payload was byte-identical. This is **`NORM-037` in the packaging rather than in the engine**: a set-like field entered an artifact unordered. The engine has had a gate and an injection for exactly that since W1-A; the package build had neither. `make check-deb-ordering` now does, with its own injection. |
| `.rpm` | differs, **not fixable here** | rpm 6.0.2 writes a **zstd** payload, rpm 4.18.2 writes **gzip**, and their cpio framing differs. This is a property of rpm, not of this build. |

`BUILDTIME` was **identical** on both machines (`1789794254`), so `SOURCE_DATE_EPOCH` taken from the
commit works exactly as intended across toolchains.

**Measured again after both fixes, on 2026-09-19, and this is the result that matters:** the public
commit was rebuilt on a Fedora 44 / btrfs / rpm 6.0.2 workstation and compared against what
`ubuntu-latest` / ext4 / rpm 4.18.2 produced from the same commit.

| Artifact | Cross-machine | Verified against the published attestation |
|---|---|---|
| source tarball | **bit-identical** | **yes** — `gh attestation verify` accepts the locally rebuilt file |
| `.deb` | **bit-identical** | **yes** — same |
| `.rpm` | differs | **correctly refused** — no attestation exists for the digest this machine produces |

An independent rebuild on a different distribution produces bytes that GitHub's own attestation
accepts. The `.rpm` refusal is the honest outcome, not a failure: the artifact genuinely differs, and
the verifier says so rather than being lenient.

**What may be said, and what may not.** The source tarball is reproducible across machines and
distributions — observed. The `.deb` is expected to be, now that the filesystem dependency is
removed. The `.rpm` is reproducible **for a given rpm major version** and is not reproducible
across rpm major versions; pinning a builder image would be the only way to change that, and it is
not attempted. No artifact may be described as "reproducible" without saying which of these it is.

**Note on the `du` defect:** neither the privacy gate nor the payload gate could have caught it.
Both read the repository, the publication surface and the payload file list — not a metadata field
whose value is a property of the machine that computed it.

## KGG-017 — The public/private documentation split, and what measurement corrected

**State:** `IMPLEMENTED`

Owner decision, 2026-09-19: the public repository publishes the **specification**; the internal
**change control** stays in the engineering repository.

| Stays public | Moved private |
|---|---|
| `ISEDRAF_HLD.md`, `EVIDENCE_AND_TRUST_MODEL.md`, `SNAPSHOT_BASELINE_DELTA_MODEL.md`, `NORMATIVE_SOURCES.md`, `V0_1_IMPLEMENTATION_SCOPE.md` | `DECISIONS_REGISTER.md`, `OPEN_DECISIONS.md`, `AMENDMENTS.md`, `W1A_CORE_FREEZE_SCOPE.md`, `MASTER_INDEX.md`, `CLAUDE.md` |

**One document changed sides on evidence, not on opinion.** `V0_1_IMPLEMENTATION_SCOPE.md` was
classified as lane planning and excluded. Measuring the references showed it **defines 54 requirement
IDs that 52 published files cite** — `lib/isedraf/identity.py`, `cli.py`, `inventory/model.py` and the
production tests among them. Every `Implements: SCOPE-045` in the shipped source would have pointed
at a document the reader cannot open. A specification the published code cites is not internal
change control, and it was published again.

## Three gates had to learn the difference between absent and wrong

None of them was weakened; each was taught to distinguish *"this does not exist"* from *"this is
missing"*, and to say which.

**`check-index`** skips where `MASTER_INDEX.md` is not published, and states that a skip is not a
pass. Freshness is enforced where the document can be edited.

**`check-refs`** first tried prefix families — resolve `IDENT-*` if any `IDENT-nnn` is defined here.
That was wrong: `IDENT-001` is defined in a published document and `IDENT-003` was not, so the family
looked resolvable while half of it was not. The honest test is whether **every defining document is
present**. It now names the absent ones, counts what it could not resolve, and reports the mode. In
the public checkout all 244 IDs resolve; the mode still says `reduced`, because the decisions
register is absent and one defining document is not published.

**`check-gate-coverage`** called `CLAUDE.md` a *stale declaration* because it matches no file
publicly. It is not stale — the path is real and in scope where the gate can act on it.
`unpublished_paths` now declares that class. Anything **not** in that list which matches nothing is
still stale, so the check did not lose its teeth.

## An injection whose subject is not published cannot fire there

Seven injections attack documents the public repository deliberately does not carry — the decisions
register, the master index, `CLAUDE.md`. In that checkout they mutated something the gate genuinely
cannot see and reported `MUTATION_EXECUTED_BUT_NOT_DETECTED`: technically accurate, and the wrong
verdict. A control that has no subject has not failed.

`next_requires <path>` now precedes those injections. When the path is absent the injection is
**skipped and said to be skipped**, counted separately from both firing and failing:

```text
engineering repository   71 injections detected, 0 not counted as firing
public repository        64 injections detected, 0 not counted as firing,
                         7 skipped (subject not published in this checkout)
```

It cannot hide a real failure: in the engineering repository every subject exists, so nothing skips,
and each skip prints the path that caused it.

**Why it is a declaration before the call, not a sixth argument.** A sixth positional argument was
the obvious design and broke twice — several injections carry a heredoc or a trailing comment, so
"after the last argument" is not a place a tool can reliably append. The first attempt landed the
argument *inside a heredoc*, silently disabling the mutation it was meant to guard.

**The pattern worth keeping:** a gate that cannot run must say so. A gate that silently passes on an
absent subject teaches the reader that the subject was checked.


## KGG-018 — `CI_EXECUTED_AND_DETECTED` is required for release-critical gates

**State:** `IMPLEMENTED (as an invariant)` · owner decision 2026-09-19

> `local mutation works` **≠** `CI mutation proven`

For a release-critical gate, `MUTATION_EXECUTED_AND_DETECTED` on a workstation is **not sufficient
evidence**. The injection must also be observed firing in the environment that **builds the release**,
because the release environment is part of the proof.

This came out of the `ar -D`/`-U` finding, and the finding matters more than the bug it exposed. A
reproducibility injection dropped `ar`'s deterministic flag and fired locally; on `ubuntu-latest` it
passed **silently**, because whether plain `ar rc` is deterministic depends on how the local binutils
was *compiled*. Forcing `U` also fired locally and also passed silently there. Two green injections
that proved nothing, on the exact machine that produces the released artifacts.

**What is already true:** `make check-falsifiable` runs in CI on every push and a non-firing injection
fails that job, so the second observation does exist for every injection that runs there — and it is
what caught both failures.

**What this records:** that it *must* exist, and that an environment-dependent mutation is not
evidence until it has been seen to fire where the release is built. New release/build injections
declare which observations they have. The harness is **not** redesigned for this now.
