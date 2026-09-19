# ISEDRAF — Open Decisions

Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0


Each entry: question · options · trade-offs · recommendation · what evidence decides it · deadline.
An `OD-` is resolved only by an owner amendment (`GOV-004`).

## OD-01 — Public project name
**Question.** What is the public name? "ISEDRAF" is a codename; an existing cybersecurity company uses it.
**Options.** (a) new name, cleared for GitHub, domain and EU trademark; (b) keep and accept risk.
**Trade-offs.** (b) risks a forced rename after publication, breaking package names, repository URLs and
any signing identity.
**Recommendation.** (a). Treat as blocking.
**Evidence.** Trademark and domain search; GitHub namespace availability.
**Deadline.** Before any public release. **Blocks:** D-90, OD-07, OD-09, OD-11.

## OD-02 — **RESOLVED 2026-09-18 → `IDENT-005`**
**Question.** Stable app-specific machine-id derivative, or keyed per install?
**Options.** (a) stable app-specific `host_id`, HMAC only for hardware serials; (b) fully keyed.
**Trade-offs.** (b) makes a host unrecognizable across a key loss, defeating baseline applicability.
**Recommendation.** (a) — as recorded in the register.
**Evidence.** Corpus scenarios 7 (clone) and rollback.
**Deadline.** W1.

## OD-03 — Last-login source
**Question.** `lastlog`, `lastlog2` or `wtmpdb` per distribution?
**Trade-offs.** `lastlog` is deprecated/removed in newer releases; sources disagree.
**Recommendation.** Detect at runtime; record the source in the section; treat last login strictly as an
**observation** (`NORM-020`), so divergence cannot cause drift.
**Evidence.** Behaviour on all four target platforms.
**Deadline.** W2.

## OD-04 — `cvtsudoers -f json` availability
**Question.** Is it present and consistent across the four platforms, and what is the fallback?
**Trade-offs.** Parsing `sudoers` directly re-implements a complex grammar and risks disagreeing with the
real policy — the failure mode D-13 exists to avoid.
**Recommendation.** Require `cvtsudoers`; where absent, report local sudo as `NOT_TESTED` with reason
rather than parsing by hand.
**Evidence.** Package availability and version per platform; corpus.
**Deadline.** W2.

## OD-05 — `aa-status --json` privilege requirements
**Question.** What privilege does it need per kernel?
**Recommendation.** Probe; degrade to `NOT_TESTED` rather than widening privilege.
**Evidence.** Ubuntu 24.04 and Debian 12 corpus.
**Deadline.** v0.1 (MAC is not prototype scope).

## OD-06 — `setpriv` bounding-set behaviour under SELinux enforcing
**Question.** Does the D-26 capability model hold on Rocky/Alma 9 with SELinux enforcing?
**Trade-offs.** If it does not, the temptation is to widen capabilities. **This is forbidden** (`PRIV-006`).
**Recommendation.** If it fails, stop that lane, record objective evidence here, and continue unrelated
work. Never add `CAP_SYS_ADMIN`, setuid, a privileged daemon, or disable SELinux.
**Evidence.** Corpus scenarios 12, 16, 17.
**Deadline.** W4. **This is the most likely architecture-breaking open decision.**

## OD-07 — Repository hosting and package signing-key custody
**Recommendation.** Defer; blocked by OD-01.
**Deadline.** Before v0.1 packaging.

## OD-08 — Framework text licensing
**Question.** Do CIS terms permit the mapping pack we would ship?
**Recommendation.** No CIS mapping pack until reviewed. Identifiers plus independently written objectives
only (D-63).
**Deadline.** v0.2.

## OD-09 — Release signing approach
**Recommendation.** Defer; blocked by OD-01 and OD-07.
**Deadline.** Before v0.1 release.

## OD-10 — **RESOLVED 2026-09-18 → `NORM-037`**
**Question.** Exact ordering keys for canonical serialization.
**Resolution.** Ordering is a schema property and must be total; normative source `NORM-037`. For W1 the
`anchors[]` key is `anchor_id` ascending (`IDENT-002`).
**Evidence.** Golden fixtures must be byte-stable across runs, platforms and locales.
**Deadline.** W1 — this blocks `NORM-030` and every golden fixture.

## OD-11 — Documentation publishing
**Recommendation.** Publish `/docs` itself (for example GitHub Pages) from the same reviewed tree. No wiki
(D-87). Blocked by OD-01.
**Deadline.** Before public release.

## OD-12 — Trusted journal field set for D-75
**Question.** Which `_UID`/`_EXE` values and shadow-utils logging behaviours are trustworthy per platform?
**Trade-offs.** Too narrow → `UNKNOWN` everywhere; too broad → a spoofable `EVENT_RECORDED`, which is a
security defect (acceptance test 21).
**Recommendation.** Start narrow. `UNKNOWN` is an acceptable answer; a false `EVENT_RECORDED` is not.
**Evidence.** Real `useradd`/`usermod`/`groupadd` invocations per platform; the `logger` spoof test.
**Deadline.** W2.

## OD-13 — Journal logging under `RestrictAddressFamilies`
**Question.** Does D-29 journal logging survive `RestrictAddressFamilies=AF_UNIX AF_NETLINK`?
**Recommendation.** `AF_UNIX` should permit the journal socket; verify, and fall back to stdout capture.
**Evidence.** Corpus on all four platforms.
**Deadline.** W3.

---

## New open decisions raised by Prompt 02

## OD-14 — **RESOLVED 2026-09-17 → D-101, `BASE-020`…`BASE-025`**
**Question.** When only an untracked section is `NOT_COMPARABLE`, is the exit code `2`?
**Trade-offs.** Always `2` produces alert fatigue and trains operators to ignore it — which would defeat
`DELTA-010`. Never `2` hides real evidence loss.
**Recommendation.** Exit `2` only when a **tracked** section is `NOT_COMPARABLE`; others are reported but
do not raise the code. D-57 says "in tracked sections"; this needs an explicit definition of *tracked*.
**Evidence.** Corpus with a deliberately missing optional tool.
**Deadline.** W3.

**OWNER POSITION — now frozen as a decision; retained here as rationale.** *Tracked* is defined **relative to the
approved baseline**, never globally. A section is baseline-tracked only when (a) the approved baseline
recorded comparable stable state for it, and (b) baseline metadata marks that section as required for
future comparison.

```text
APPROVED BASELINE            current run                      exit-2 effect
  identity    TRACKED          audit unavailable   → NOT_COMPARABLE → contributes to exit 2
  privilege   TRACKED          optional-X missing  → reported       → no exit-2 effect
  mounts      TRACKED
  audit       TRACKED
  optional-X  NOT_TRACKED
```

A section never collected or unsupported in the approved baseline SHALL NOT force every future run to
exit 2. A capability newly available after a ISEDRAF upgrade SHALL NOT silently become mandatory: it
enters as **new coverage** and requires deliberate `baseline rebind` or acceptance before becoming tracked.

This gives exit `2` an operationally meaningful definition: *evidence we previously relied upon has been
lost.*

## OD-15 — **RESOLVED 2026-09-17 → D-102, `SCOPE-045`…`SCOPE-047`**
**Question.** Is the state/observation split a fixed list per section, or a per-field annotation?
**Trade-offs.** A fixed list is auditable and greppable but rigid. A per-field annotation is flexible but
a single mis-annotation silently reintroduces drift — breaking invariant I-1, the hardest failure to
notice.
**Recommendation.** Per-field annotation in the normalizer **plus** a gate asserting that every known
volatile field name is annotated as an observation. Belt and braces.
**Evidence.** Acceptance test 14 plus a deliberate mis-annotation injected into the falsifiability harness.
**Deadline.** W1.

**OWNER POSITION — now frozen as a decision; retained here as rationale.** **Per-field classification with no
implicit default.** Every normalized field SHALL declare exactly one frozen category:

| Category | Participates in state hash and delta |
|---|---|
| `STATE` | **yes — only this category** |
| `OBSERVATION` | no |
| `DERIVED` | no |
| `PROVENANCE` | no |

```text
last_login_time      OBSERVATION
failed_login_count   OBSERVATION
uid                  STATE
shell                STATE
account_expiry       STATE
collector_version    PROVENANCE
```

An **unclassified** normalized field SHALL fail schema and CI validation. This is safer than maintaining a
loose list of volatile field names, because the failure mode of a missing list entry is silent drift,
whereas the failure mode of a missing annotation is a red gate.

---

## Challenges to frozen decisions

Recorded as required by Prompt 02. **Both decisions are documented and followed as frozen**; these are
observations for the owner, not deviations.

### CHALLENGE-01 — **RESOLVED → D-104** — D-16 engine size budget (~5k lines)
**Observation.** The prototype must deliver safe exec, capability probe, privilege detection, host
identity with HMAC, canonical serialization, snapshot store with locking and a hash-chained ledger,
comparability, delta, interpretation, five identity views, the `recording` view, the full `explain`
contract, and JSON/JSONL export. A ~5k-line budget across all of that is tight, and the risk is that it
pressures the **wrong** economies — fewer negative tests, thinner error handling, a shortcut in
canonicalization.
**Evidence that would settle it.** Measured line count at the end of W1's vertical slice, extrapolated.
**Recommendation.** Keep D-16 as a **budget signal, not a gate**. If W1 shows the trajectory exceeds it,
raise an amendment rather than trimming tests. Do not gate `make check` on line count.

**OWNER POSITION (2026-09-17).** The ~5k figure is an **advisory engineering budget, never a release
gate**. It is reported as a metric in every milestone report. Where correctness, error handling, negative
tests or auditability require exceeding it, **correctness wins**.

### CHALLENGE-02 — **RESOLVED → D-103** — D-12 stdlib-only and JSON Schema validation
**Observation.** D-15 requires JSON Schema validation in CI while D-12 forbids third-party runtime
modules. These are compatible only because `jsonschema` is a **CI-only** dependency — but the boundary is
easy to erode, since a runtime "minimal structural check" and a CI schema validation can drift apart and
disagree.
**Evidence.** A fixture valid under the runtime check but invalid under the CI schema.
**Recommendation.** Keep both, and add a gate asserting that every runtime structural check has a
corresponding CI schema case. Recorded for W4, when schemas exist.

**OWNER POSITION (2026-09-17).** A **conformance gate** is required. The runtime stdlib-only structural
validator and the richer CI JSON Schema validator SHALL both process the **same fixture corpus**:

```text
VALID fixture                          runtime → ACCEPT   schema → ACCEPT
INVALID fixture within runtime contract runtime → REJECT   schema → REJECT
disagreement                                            → CI FAIL
```

The runtime SHALL NOT attempt to reimplement JSON Schema. The gate covers only constraints the runtime
**claims** to enforce; outside that contract, the schema may legitimately be stricter.

---

## Register inconsistencies found

| # | Finding | Status |
|---|---|---|
| 1 | Register §13 is titled "Release-blocking acceptance tests" and lists 22 items, but section numbering runs §13 → §15 → §16 → §17 → §18 → §14 (open decisions last). Cosmetic ordering defect only; no content is lost or duplicated. | Cosmetic; no amendment needed |
| 2 | D-93 required keeping AI `Co-Authored-By:` trailers; superseded by **D-93 (revised)** after the Prompt 01 audit. | Resolved by amendment |
| 3 | D-91 required "no contributing tool is omitted". | Revised in the register |
| 4 | Prompt 01's CI lane list names `python3 -m py_compile`, which D-86 forbids. | Resolved: D-86 governs; recorded in `02_…CROSSWALK.md` |
| 5 | Prompt 04's original precondition assumed a fresh `git init`. | Superseded by D-96 |
| 6 | D-57's *tracked* was undefined. | Defined by **D-101** / `BASE-020`…`BASE-025` |
