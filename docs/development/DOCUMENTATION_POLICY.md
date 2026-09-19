# ISEDRAF — Documentation & Repository Knowledge Policy

Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0
Canonical location after Prompt 04: `docs/development/DOCUMENTATION_POLICY.md` (governance-manifest covered)
Implements: D-87, D-88, D-89, D-90, D-91…D-94

<!-- doclint:exempt-forbidden-terms — this file must name the terms it forbids -->

## 1. Authority
1. Frozen requirements (`docs/architecture/`) 2. `docs/architecture/DECISIONS_REGISTER.md`
3. `CLAUDE.md` 4. `/docs` 5. `README.md` 6. issues, discussions, articles.
A lower layer never contradicts a higher one. On conflict: keep the higher statement, record it in
`docs/IMPLEMENTATION_QUESTIONS.md`, mark the lower document stale. Never update docs to match a bug.

## 2. Surfaces
- **`/docs` is canonical.** Everything important lives here and is reviewed like code.
- **README** is the front door (≤ ~150 lines): what it is, why, what it assesses and deliberately does not,
  who it is for, install, first run, snapshot → baseline → delta in one paragraph, verify ISEDRAF itself,
  report security issues, links into `/docs`. Says "codename" until OD-01 is resolved.
- **No GitHub Wiki** until an owner amendment. Future navigation publishes `/docs` itself (OD-11).
- **Installed docs:** man page `isedraf.8` and `/usr/share/doc/isedraf/` for offline servers.

## 3. Positioning
Canonical description: *ISEDRAF is an open-source Linux host assurance, state-delta and evidence bridge.
It collects normalized local host state, establishes approved baselines, detects and classifies meaningful
state changes, gives system administrators concise operational visibility, preserves evidence for security
auditors, and exports machine-readable data for organizational governance workflows.*
Philosophy: *Measure once. Map everywhere. Fix only the delta.* Always "host", never unqualified "360°".

## 4. Coexistence, not competition
ISEDRAF is not framed against any project. Forbidden framing: "ISEDRAF vs X", "replaces X",
"better/more advanced/best", "X cannot do Y", rankings, scores, winners.
Allowed: neutral boundary statements, e.g.
- *ISEDRAF does not implement SCAP internally; environments using OpenSCAP may continue to do so.*
- *osquery provides broad queryable host telemetry; ISEDRAF focuses on accepted baselines, classified delta and evidence semantics. They can coexist.*
- *AIDE performs file integrity monitoring; ISEDRAF does not attempt whole-filesystem FIM.*
- *NFTBan provides runtime network protection; ISEDRAF does not assess firewall effectiveness. They are independent projects.*
Never describe another project's current capabilities without verifying them against its own docs.
Comparative testing is published only as scenario-level corpus data (versions, fixture, commands,
expected state, observed results, limitations, reproduction) and never generalized into superiority claims.

## 5. Clean room
No copied wording, tables, rules, remediation, mappings or descriptions from NFTBan, ComplianceAsCode,
OpenSCAP, Lynis, osquery, Wazuh, AIDE, CIS, ISO, PCI DSS or commercial products. Reference identifiers and
authoritative sources; write ISEDRAF prose independently.

## 6. Status discipline
Every feature statement is one of IMPLEMENTED · EXPERIMENTAL · PLANNED · FUTURE · OUT_OF_SCOPE.
Present tense only for IMPLEMENTED/EXPERIMENTAL. PLANNED/FUTURE only in `docs/roadmap/ROADMAP.md` or
clearly labelled architecture reservations. Stubs contain headings and `Status: STUB` only.

## 7. Tree (create only what the current milestone needs; the rest stays in this list)
```
docs/
├── README.md  CURRENT_STATE.md* REPOSITORY_MAP.md  STYLE_GUIDE.md  IMPLEMENTATION_QUESTIONS.md
├── architecture/   HLD, EVIDENCE_AND_TRUST_MODEL, SNAPSHOT_BASELINE_DELTA_MODEL, V0_1_IMPLEMENTATION_SCOPE,
│                   OPEN_DECISIONS, DECISIONS_REGISTER, AMENDMENTS, FROZEN_MANIFEST.sha256
├── getting-started/ INSTALLATION, QUICKSTART, FIRST_BASELINE, PACKAGE_VERIFICATION
├── operator/       OPERATOR_GUIDE, IDENTITY_AND_PRIVILEGE, RECORDING_COVERAGE, BASELINES_AND_DELTA,
│                   CHANGE_ACCEPTANCE, EXPLAIN, EXIT_CODES*, TROUBLESHOOTING
├── auditor/        AUDITOR_GUIDE, EVIDENCE_MODEL, COLLECTION_STATUS, TRUST_AND_LIMITATIONS,
│                   DATA_PROVENANCE, AUDITING_ISEDRAF_ITSELF
├── integration/    EXPORT_FORMATS, JSON_SCHEMA, JSONL_SCHEMA, INGESTION_GUIDANCE, SCHEMA_VERSIONING
├── security/       THREAT_MODEL, PRIVILEGE_MODEL, EXECUTION_SANDBOX, INTEGRITY_VERIFICATION,
│                   DATA_SENSITIVITY, PRIVACY_AND_RETENTION
├── development/    DEVELOPMENT, TESTING, CORPUS, requirements-trace*, DOCUMENTATION_POLICY,
│                   GOVERNANCE_MANIFEST.sha256, RELEASE_PROCESS
├── reference/      CLI*, STATUS_VALUES, GLOSSARY, FILESYSTEM_LAYOUT, SUPPORTED_PLATFORMS
└── roadmap/        ROADMAP
```
`*` = generated; `make check` fails if stale (D-89).

Root: `README.md LICENSE REUSE.toml SECURITY.md CONTRIBUTING.md SUPPORT.md CODE_OF_CONDUCT.md CHANGELOG.md
VERSION CLAUDE.md` · `.github/ISSUE_TEMPLATE/` · `.github/pull_request_template.md` *(PLANNED — not yet created)*.

## 8. Required content of governance files
- **SECURITY.md:** private reporting path; security-sensitive classes include false PASS from collection
  failure, NOT_TESTED shown as improvement, wrong baseline comparison, snapshot/evidence corruption,
  integrity-verifier failure, unsafe privileged execution, privilege escalation, unsafe guidance, sensitive
  report disclosure, schema confusion, supply chain. No exploit details in public issues.
- **SUPPORT.md:** supported/experimental/unsupported platforms; what is safe to share; use `--redact`;
  never post unredacted identity or evidence bundles.
- **CONTRIBUTING.md:** evidence boundary, read-only invariant, clean room, runtime dependency policy,
  traceability, negative tests, canonical serialization, snapshot immutability, collection vs evaluation,
  NOT_TESTED semantics, no scope expansion without amendment, DCO sign-off, AI disclosure (§14), owner
  review of AI-generated code.
- **Issue templates:** bug, false positive, false negative (false PASS flagged as serious), collection
  failure, platform compatibility, interpretation, documentation, feature proposal; security → SECURITY.md.
- **PR template:** requirement IDs; domain; behaviour change; collector/parser/schema changes; negative
  tests; corpus fixtures; privilege/capability impact; data sensitivity impact; docs updated; AI tools and
  roles used (or none); and
  **"Does this change alter normalized state for an unchanged host? If yes, describe comparability/rebind handling."**

## 9. LLM repository-reading protocol
Before any change read, in order: `CLAUDE.md` → `docs/architecture/DECISIONS_REGISTER.md` →
`FROZEN_MANIFEST.sha256` → relevant frozen documents → `docs/CURRENT_STATE.md` →
`docs/REPOSITORY_MAP.md` → `docs/development/requirements-trace.md` *(PLANNED — not yet created)* → VERSION/CHANGELOG → relevant module
→ tests/corpus → `docs/IMPLEMENTATION_QUESTIONS.md`. Never infer architecture from code; code may be
incomplete. Before changing a domain, list requirement IDs, canonical schema, collector/parser versions,
comparability effect, existing negative tests, related open decisions.

Label statements as REPOSITORY FACT · FROZEN REQUIREMENT · OPEN DECISION · INFERENCE · PROPOSAL ·
EXTERNAL INFORMATION. Never present inference as behaviour. Interesting ≠ in scope: out-of-scope ideas go to
IMPLEMENTATION_QUESTIONS.md as FUTURE.

## 10. Evidence standard and lint
Behaviour statements cite requirement ID, command, test or schema where practical
(e.g. *DELTA-004 — verified by tests/unit/test_not_comparable.py*).
Doc lint checks: broken internal links; unknown requirement IDs, status values, exit codes; stale generated
files; forbidden claims (compliant, guaranteed, tamper-proof, non-repudiable, host unchanged, best, beats,
replaces, revolutionary, military-grade, 100% secure) except in files marked
`doclint:exempt-forbidden-terms` or text inside `<!-- doclint:quote -->` spans; behavioural prose in STUB docs.

## 11. Auditor honesty statements (must appear in auditor docs)
Baseline = accepted, not secure · No observed delta ≠ uncompromised host · Local signature ≠ proof root did
not manipulate data · Host technical evidence ≠ organizational compliance · NOT_TESTED ≠ PASS · Absence of a
local product ≠ absence of an external control · ISEDRAF observes userspace/kernel-exposed state; it is not
remote attestation.

## 12. Three readers, one truth
Administrator: *What changed and what needs attention?* Auditor: *What was observed, how, what is provable,
what is not?* Organization: *How do I ingest this evidence into existing workflows?* Three views over the same
canonical state — never three separate truths.

## 13. Release documentation gate
README describes released behaviour only · platform statement accurate · limitations current · CLI examples
execute in corpus · schema docs match emitted artifacts · new statuses/exit codes documented ·
comparability/migration notes present · SECURITY.md current · CHANGELOG complete · AI_ASSISTANCE.md and
DESIGN_PROVENANCE.md current · no FUTURE item in present tense.

## 14. AI-assistance transparency (D-91…D-94)
ISEDRAF is built with AI assistance under human ownership, and says so plainly. Nothing is hidden.

- **`AI_ASSISTANCE.md`** (root): structure adapted from NFTBan's existing convention (prompt 01 findings).
  Lists every contributing AI tool with provider, role and phase; the owner's role (scope, decisions,
  approvals, responsibility, copyright); how contributions are marked; what always requires human review
  (architecture, security claims and limitations, privilege/capability changes, licensing/provenance,
  release notes, governance files). Model versions only when known. Credits are factual, not promotional.
- **Commits:** keep tooling `Co-Authored-By:` trailers; add `Assisted-by: <tool> (<role>)`, or
  `Assisted-by: none`. Enforced by `commit-msg`.
- **PRs:** AI tools/roles field is mandatory.
- **`docs/development/DESIGN_PROVENANCE.md` *(PLANNED — not yet created)*:** design phases → decision IDs → AI tools involved → reviewed
  external proposals and outcome → human approval point. Summaries only; no raw transcripts.
- **README:** one short "AI assistance" line linking to `AI_ASSISTANCE.md`.
- Wording: "developed with AI assistance", "reviewed and approved by the maintainer". Never imply AI output
  is unreviewed-authoritative, and never hide or minimize AI involvement.
