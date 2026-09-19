# ISEDRAF — High-Level Design

Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0


## 1. Product definition

**HLD-001 (D-04) SHALL** ISEDRAF is an open-source Linux **host** assurance, state-delta and evidence
bridge. It collects normalized local host state, establishes approved baselines, detects and classifies
meaningful state changes, gives administrators concise operational visibility, preserves evidence for
auditors, and exports machine-readable data for organizational governance workflows.

**HLD-002 (D-04) SHALL** "360°" is qualified as **host** in every context. Unqualified claims of complete
security, enterprise security or complete infrastructure assurance are forbidden.

**HLD-003 (D-03) SHALL** Philosophy: *Measure once. Map everywhere. Fix only the delta.*

**HLD-004 (D-01, OD-01) SHALL** "ISEDRAF" is a codename. Public-facing material states this until OD-01
is resolved. No public release occurs before then (D-90).

**HLD-005 (D-04) SHALL** One canonical host state serves three views — administrator, auditor,
organization. Three separate truths SHALL NOT be built.

## 2. Non-goals and the host evidence boundary

**HLD-010 (D-07) SHALL** ISEDRAF assesses only state directly observable on the local operating system.

**HLD-011 (D-08) SHALL NOT** The following are permanently out of core: firewall products and rulesets
(nftables, iptables, firewalld, ufw, CSF/LFD), AV, EDR/XDR, IDS/IPS, WAF, SIEM, cloud and network
controls, external backup, remote repository patch availability, CVE matching, whole-filesystem file
integrity monitoring, remote attestation, organizational "required agent" checks.

**HLD-012 (D-09) SHALL** Absence of a locally detectable external agent SHALL be reported as absence of
**local evidence**, never as absence of the control.

**HLD-013 (D-10) SHALL** Local kernel network sysctls and listening sockets are in scope as local facts.
Listeners are inventory and drift only; the word "exposed" SHALL NOT be used.

**HLD-014 (D-11) SHALL** When framework views exist, coverage is reported as host-assessed / partial /
`NOT_HOST_ASSESSABLE` with a reason class (`NETWORK_CONTROL`, `ENDPOINT_PRODUCT`, `ORGANIZATIONAL`,
`EXTERNAL_DEPENDENCY`).

**HLD-015 (D-49, D-84) SHALL NOT** No network egress, no daemon, no database, no API client or server, no
connectors, no credentials, no telemetry, no update check.

## 3. Position, stated honestly

**HLD-020 (D-05, D-06) SHALL** ISEDRAF does not implement SCAP, XCCDF or OVAL internally, ships no
thousand-rule catalog, and calculates no compliance percentage.

**HLD-021 (D-06, D-87) SHALL NOT** No document frames ISEDRAF against another project. No "vs",
"replaces", "better than", rankings, scores or winners. Neutral scope descriptions only. Claims about
another project's capabilities SHALL NOT be made without verification against that project's own
documentation.

**HLD-022 (D-06) SHALL** What distinguishes ISEDRAF is a *combination*, stated as description not
ranking: daemon-free single command · readable auditable source · explicit evidence boundary ·
approved-baseline workflow · granular change acceptance · declared/resolved/active distinction ·
classified delta · collection truth separate from evaluation truth · explicit `NOT_TESTED` · tool
integrity separate from host consistency · portable evidence · operator and auditor views from the same
data.

## 4. Architecture

> **Normative topology: `PRIV-005`** (`NRM-001`). The diagram below is illustrative data flow only and
> deliberately omits privilege and locking, which the diagram previously restated incorrectly (T-01).

```text
collection → normalization → snapshot (immutable) → comparability
           → delta → interpretation → evaluation (regenerable) → views / export
```

**HLD-030 (D-33) SHALL** The pipeline order is collection → normalization → comparability → delta →
interpretation → views/export. Frameworks, when they exist, are **views over evidence**, never a
collection stage.

**HLD-031 (D-13) SHALL** Collectors collect; the engine interprets. A collector SHALL NOT emit PASS or
FAIL, SHALL NOT rely on `set -e`, and SHALL declare `meta:privilege` and `meta:mutates`.

**HLD-032 (D-41, Q-13) SHALL** Snapshots are **treated as immutable by ISEDRAF**, never rewritten by
it, and contain observed state only. They are not protected against a local root adversary (`EVID-040`). Changes and findings
live exclusively in regenerable evaluations. A snapshot directory SHALL NOT contain `changes.json` or
`findings.json`.

**HLD-033 (D-16) SHOULD** The prototype engine stays near a ~5k line budget, one evaluator module per
domain.

## 5. The five invariants this architecture exists to hold

These are the outcomes every requirement below ultimately serves. Each is testable; none is claimed absolute.

The authoritative invariant → requirement → acceptance-test mapping is **`MASTER_INDEX.md` §"The five
invariants"**, which is the single source (finding R-14). It is not duplicated here.

| # | Invariant |
|---|---|
| **I-1** | An unchanged host stays quiet |
| **I-2** | Incomplete evidence never creates a false delta |
| **I-3** | Tool evolution never masquerades as host evolution |
| **I-4** | Snapshots are treated as immutable by ISEDRAF; evaluations stay regenerable |
| **I-5** | The host evidence boundary stays strict |

## 6. User journeys (prototype)

| # | Command | Precondition | Behaviour | Exit |
|---|---|---|---|---|
| J-1 | `sudo isedraf` | no baseline | collect, snapshot, report observed state, **state plainly that no baseline exists**; never a clean-baseline claim | `6` |
| J-2 | `isedraf baseline approve <SDS-id>` | snapshot complete per `REQUIRED_FOR_BASELINE` | refuse `INCOMPLETE_FOR_BASELINE`, unprivileged or `DEV` snapshots; create `BL-0` | `0` / `65` |
| J-3 | `sudo isedraf` | baseline exists | collect → comparability → delta → interpretation; silent when nothing security-relevant changed | `0` / `1` / `2` / `3` |
| J-4 | `isedraf accept <change-id> --reason "..."` | change exists | bind the exact accepted state hash; new baseline revision | `0` |
| J-5 | `isedraf verify` | any | report **tool integrity** and **host baseline consistency** as separate lines | `0` / `5` |

**HLD-040 (D-43) SHALL** The first snapshot SHALL NEVER be auto-approved.
**HLD-041 (D-46, X-02) SHALL** An **incomplete** snapshot SHALL NEVER become an eligible baseline. A
snapshot produced under `ISEDRAF_STATE_ROOT` SHALL NEVER become a **production** baseline. The security
property is **evidence completeness and artifact class**, not whether EUID happened to be non-zero —
"unprivileged" was an overbroad proxy that forbade the unprivileged W1 lifecycle outright. Development
baseline semantics are governed separately by the W1-B requirements.
**HLD-042 (D-30) SHALL** Tool integrity and host baseline consistency SHALL always be reported as
separate concepts and separate lines.

## 7. Prototype CLI surface

`isedraf` · `isedraf identity users|user <name>|groups|group <name>|privileged` (D-74) ·
`isedraf recording` (D-76) · `isedraf explain <id>` (D-77) · `isedraf baseline approve [--profile <id>]` · `isedraf baseline rebind` ·
`isedraf baseline track <section> --reason` · `isedraf baseline untrack <section> --reason` ·
`isedraf baseline profile <id> --reason` · `isedraf acknowledge <id> --reason` ·
`isedraf resolve-rollback --reason` · `isedraf checkpoint` ·
`isedraf export [--redact]` · `isedraf report [--redact]` ·
`isedraf accept <id> --reason` · `isedraf verify` · `isedraf prune` · `isedraf purge-data`.

**HLD-050 (D-74) SHALL** Quick and detailed identity views SHALL derive from **one** canonical identity
collection. A second audit SHALL NOT be run merely to render a different view.

**HLD-051 (D-77) SHALL** `explain <id>` is a product contract, not console polish. For a control, finding
or change it SHALL be able to state: what was collected; collection status; normalized state; baseline
state; the exact delta; why ISEDRAF classified it so; confidence and limitations; evidence references;
how an administrator can verify the fact manually; illustrative guidance; and the operational risk of
acting on that guidance. It SHALL NOT turn uncertainty into certainty.

**HLD-052 (D-58) SHALL** No daemon. An optional systemd timer ships **disabled** and runs as root.
ISEDRAF detects and emits; existing infrastructure delivers alerts.

## 8. Exit codes

**OUT-001 (D-57, D-72) SHALL** Exit codes are defined once in `lib/isedraf/exitcodes.json`. Code,
documentation and tests derive from or validate against it; `make check` verifies consistency.

| Code | Meaning |
|---|---|
| `0` | complete, comparable, nothing unaccepted |
| `1` | unaccepted security-relevant change |
| `2` | incomplete / `NOT_COMPARABLE` in tracked sections |
| `3` | `1` + `2` |
| `4` | baseline not applicable |
| `5` | tool integrity failure |
| `6` | no approved baseline |
| `65` | approval refused (`BASE-021`) — SHALL NOT reuse `2` |
| `66` | another run in progress (`PRIV-008` lock contention) |
| `67` | state root unwritable (`PRIV-008`) |
| `64+` | usage / engine error |

**OUT-002 (D-57) SHALL** Precedence is `5 > 4 > 6 > 3 > 2/1 > 0`.
**OUT-003 (D-57) SHALL** The exit code SHALL propagate unchanged through `systemd-run` re-exec.

## 9. Output surfaces

**OUT-010 (D-55) SHALL** Canonical JSON and per-entity JSON Lines are the authoritative artifacts. Every
JSONL row carries `schema_version`, `host_id`, `snapshot_id`, `collected_at`, entity. Console, single-file
HTML and CSV are **renderers of canonical artifacts only**.

**OUT-011 (D-56) SHALL** Per-entity schema versions, 0.x during prototype. Minor is additive; major
requires `baseline rebind` before comparison.

**OUT-012 (D-21, D-54) SHALL** All system-derived strings are HTML-escaped per context (text, attribute,
URL) in HTML output; a CSP meta tag is present, with its stated limits over `file://`; CSV carries a
formula-injection guard; `--redact` removes key fingerprints, sudo rule bodies and GECOS; exports are mode
0600; users/privileges exports to stdout are redacted by default.

**OUT-013 (S-26, T-10) SHALL** **Every byte written to any console surface** — including error and
diagnostic output, and every subcommand without exception — passes a control-character sanitizer first.
The rule is universal; naming surfaces would repeat the enumeration defect the threat table predicts.
Illustrative, non-exhaustive: the five identity views, `recording`, `explain`, `verify`, `baseline`,
`accept`, and collector stderr excerpts. Sanitization **escapes** to `\xNN`/`\uNNNN`, never strips — a
stripped name can collide with another account, the collision `IDENT-070` exists to surface. The set is
defined by character class (`Cc`, `Cf`) plus the ANSI escape grammar, not by enumeration (T-22): C0 and C1 controls,
`DEL`, `\r`, ANSI CSI/OSC sequences (including OSC-8 hyperlinks) and bidi/format controls
(U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) are stripped or escaped as `\xNN`/`\uNNNN`. The console is
the **default** surface of a one-command tool and exists from W1; it is not a later concern.

**OUT-014 (S-27, NEW) SHALL** **Command text handed to a human is an artifact, not prose.** Entity names
interpolated into `ILLUSTRATIVE` guidance (`DELTA-021`) or manual-verification steps (`HLD-051`) are
shell-quoted. A name containing characters outside a conservative allowlist is **refused and replaced** by
a placeholder plus the entity's state hash, never emitted raw. `EVID-002` covers commands ISEDRAF runs;
this covers commands an administrator pastes.

**OUT-015 (S-29, X-17) SHALL** A JSONL row is exactly one physical line. C0 and C1 characters SHALL be
escaped: U+0008, U+0009, U+000A, U+000C and U+000D use the frozen short escapes `\b`, `\t`, `\n`, `\f`,
`\r`; all remaining C0 controls and all of U+007F–U+009F use the `\uXXXX` form. U+2028 and U+2029 are
escaped per `NORM-035`. A string containing U+0000 is handled by `NORM-036`, not "rejected" — the two
requirements previously prescribed different outcomes for the same input. Canonical JSON is **not** HTML-safe and
SHALL NEVER be embedded in a page without re-escaping.

**OUT-016 (S-28, NEW) SHALL** The CSV guard is specified, not named: a field whose first character is
`=`, `+`, `-`, `@`, TAB or CR is prefixed with an apostrophe; the transformation is documented and
round-trip tested.

**OUT-017 (R-19, NEW) SHALL** Exit semantics are defined **per subcommand**, not only for the default run,
and all of them derive from `lib/isedraf/exitcodes.json`. "Approval refused" has its own code and SHALL
NOT reuse `2`.

## 10. Provider neutrality and the separation of facts from criteria

**HLD-060 (D-78) SHALL** Canonical concepts describe security **outcomes or host facts**, not particular
Linux technologies — *authentication brute-force resistance*, not *PAM faillock enabled*; *mandatory
access control state*, not *SELinux control*. Provider-specific implementations are collection and
evidence details. v0.1 remains Linux-only on the frozen distributions; this is **not** BSD support.

**HLD-061 (D-79) SHALL** `FACT` (canonical evidence) is separate from `CRITERION` (independent
evaluation). A `REPORT` is fact + criterion + result + explanation. One observed state MAY legitimately
evaluate differently under different criteria. Assessment scope classes: `HOST_TECHNICAL`,
`HOST_SUPPORTING_EVIDENCE`, `MANUAL_ORGANIZATIONAL`, `NOT_HOST_ASSESSABLE`.

**HLD-062 (D-79) SHALL NOT** ISEDRAF SHALL NEVER convert host technical evidence into a claim of
complete organizational compliance.

**HLD-063 (D-80) SHALL** Control content carries a lifecycle: `DRAFT`, `EXPERIMENTAL`, `STABLE`,
`DEPRECATED`, `RETIRED`. Prototype controls are `EXPERIMENTAL` unless explicitly promoted. Mappings carry
an independent lifecycle: `PROPOSED`, `VERIFIED`, `DISPUTED`, `SUPERSEDED`, `RETIRED`; `VERIFIED` requires
provenance and review. Retired IDs SHALL NEVER be reused.

**HLD-064 (D-81) SHALL** External projects MAY later supply comparison evidence, validation or
adapter-imported evidence with explicit external provenance. They SHALL NEVER become the canonical source
of ISEDRAF host state.

**HLD-065 (D-82) SHALL** Future modules (software, hardware, listeners, services) SHALL reuse this same
engine — collection → state/observation split → snapshot → baseline → comparability → delta → export —
and SHALL NOT become separate scanners or databases.

## 10a. Personal data map

**OUT-020 (R-06, NEW) SHALL** Personal data locations are enumerated exhaustively and this list is the
data map an auditor or DPO may rely on:

| Location | Contains | `--redact` applies | Retention |
|---|---|---|---|
| `snapshots/` | usernames, UIDs, GECOS, home paths, key fingerprints, sudo rule bodies | on render/export | `STORE-014` |
| `acceptances/ACC-*.json` | actor, timestamp, reason | no — reason is chained into `BASE-001` | life of the baseline |
| `reports/` | rendered identity and privilege content | yes | defined per surface |
| `exports/` | canonical JSON/JSONL entity rows | yes, by default on stdout | defined per surface |
| journal run records (`EXEC-005`) | invoking user, run id | no | host journal policy |
| `ISEDRAF_CHECKPOINT=` stdout | IDs and hashes only | n/a | external |

`isedraf purge-data` is the **only** complete erasure path; regenerating an evaluation recreates its data.
| `ledger/segment-*.jsonl` | **IDs and hashes only — no personal data** | n/a | compacted at checkpoint (`STORE-018`); pre-checkpoint records replaced |

**OUT-021 (R-24, NEW) SHALL** `--reason` carries a content-hygiene rule: it records *why*, not *who else* —
ticket references rather than third-party names, since the actor is already recorded and the record is
chained into the baseline revision and cannot be selectively erased.

**OUT-022 (R-24, NEW) SHALL** A redacted export is **not** hash-verifiable against the snapshot's section
hashes and SHALL be labelled as such. `host_id` is **pseudonymous, not anonymous**: it is a stable
derivative and any export shared outside the organization is a persistent correlator. Both statements
appear in `EVID-040`.

## 11. Governance appendix

**GOV-001 (NEW — owner directive, 2026-09-17) SHALL** *Policy text is not enforcement.* Where a frozen
invariant is mechanically enforceable, ISEDRAF SHALL either enforce it with a gate, or **explicitly
document why it cannot be mechanically enforced**, in `docs/development/GOVERNANCE_GAPS.md`. An invariant
that is neither enforced nor documented as unenforceable is a defect.

> Rationale, evidenced: the Prompt 01 audit measured a project with 61 CI gates in which the one rule that
> had no gate — its own AI-attribution policy — was violated in 40 of the last 100 commits, in good faith,
> including at HEAD. Documented intent decays; gates do not.

**GOV-002 (NEW) SHALL** Every critical gate SHALL have a known injected defect in a **single centralized
falsifiability harness** (`make check-falsifiable`) which asserts the gate fails. **That failure is itself
CI-tested.** Standalone falsification scripts are kept only where a gate needs complex setup.

**GOV-003 (D-83) SHALL** A governance manifest covers `CLAUDE.md`, `.claude/settings.json`, `git-hooks/*`,
the frozen-manifest verifier, `lib/isedraf/exitcodes.json`, the runtime import allowlist and the doc-lint
configuration. `make check` verifies it and compares installed `.git/hooks/*` against the repository
copies. Agent deny rules and hooks are defense in depth, **not a security boundary**.

**GOV-004 (D-68) SHALL** Frozen architecture changes **only** through an owner-written
`docs/architecture/AMENDMENTS.md` entry plus a regenerated `FROZEN_MANIFEST.sha256`.

**GOV-005 (D-93) SHALL** Every commit carries `Assisted-by: <tool> (<role>)` or
`Assisted-by: none`. A `Co-Authored-By:` trailer naming an AI tool or provider (Claude/Anthropic,
ChatGPT/OpenAI, Gemini/Google, or equivalent) **SHALL be rejected** by the `commit-msg` hook, so that human
authorship and ownership remain unambiguous. Human `Co-Authored-By:` trailers are unaffected. AI tools are
credited contributors in `AI_ASSISTED_DEVELOPMENT.md`, never authors, copyright holders or licensors
(D-92). AI transparency is specified in D-91…D-94 and is not re-specified here.

**GOV-006 (D-69) SHALL** Blocked work is recorded in `docs/IMPLEMENTATION_QUESTIONS.md`, the requirement is
marked `BLOCKED` in the generated trace, unrelated in-scope work continues, and the milestone report lists
it. A requirement SHALL NOT disappear because no source file implements it. Requirements, tests and gates
SHALL NEVER be weakened to clear a blockage.

**GOV-007 (D-89) SHALL** Documentation whose output is consumed as a gate is generated and
freshness-verified from **W0**: the canonical exit-code source and generated exit-code documentation, the
requirements-trace generator, the `CURRENT_STATE` generator, and the documentation lint. Broader CLI and
reference generation MAY follow later.
