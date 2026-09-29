<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Trust and Assurance Doctrine

Status: PLANNING
Implements: GOV-001, GOV-002, C-06

How ISEDRAF establishes credibility, and how it does not.

```
ISEDRAF does not establish trust through comparison. It establishes verifiable facts
about itself and leaves the trust decision to the operator.
```

## 0. What this document does NOT restate

REPOSITORY FACT, measured across 71 tracked documents: the competitor-neutrality rules
**already exist and are already enforced**, in two canonical places and one gate.

| Rule | Canonical home | Enforcement |
|---|---|---|
| No "vs", "replaces", "better than", rankings, scores, winners — about any project including NFTBan | `docs/STYLE_GUIDE.md` §103-104, `docs/development/DOCUMENTATION_POLICY.md` §31-32 | C-06 in `check_docs_truth.py`, including **negated** comparisons | <!-- doclint:allow-framing: this line STATES the prohibition -->
| Forbidden superlatives and absolute claims | `STYLE_GUIDE.md`, `DOCUMENTATION_POLICY.md`, `CI_INVENTORY.md` C-05 | `make check-public-claims`, doc lint |
| Neutral coexistence phrasing, with worked examples | `STYLE_GUIDE.md` §106-110, `DOCUMENTATION_POLICY.md` §34-37 | review |
| Clean room — never copy from another project | `CLAUDE.md` §2, `CONTRIBUTING.md`, `LLM_PROTOCOL.md` | review |

This document therefore **cites** those rules and does not copy them. A third copy of the
forbidden-word list would be a third thing to drift, which is the failure the operation
contract section of the P2 directive warned about: *do not manually maintain five divergent
representations.*

What follows is only the material that has no canonical home yet.

## 1. Scan result — the doctrine is already met

Measured across all 71 tracked documents outside `planning/`, searching for superlatives,
comparative constructions, overstated security claims and named third-party products:

```
raw hits                          80
doctrine violations                0
```

Classification of every hit:

| Class | Count | Examples |
|---|---|---|
| The doctrine being STATED or ENFORCED | 31 | `STYLE_GUIDE.md:35` lists `best`/`revolutionary` as forbidden; `CI_INVENTORY.md:166` is the C-05 forbidden-claims gate row; `CLAUDE.md:68` states the prohibition |
| FACTUAL REFERENCE, required | 27 | clean-room lists naming ComplianceAsCode, OpenSCAP, Lynis, osquery, Wazuh, AIDE; `D-05`; `D-81` external-tool policy |
| ACCEPTABLE SELF-DESCRIPTION | 14 | the neutral coexistence examples, which describe another project's scope without ranking it |
| HISTORICAL TEXT | 5 | `planning/blueprint/00_nftban/` marked `HISTORICAL_RECORD`; header-policy notes on inherited conventions |
| Ordinary English, false positive | 3 | "safest behaviour implemented", "best effort" in the platform matrix, "replaces" used of a file |
| **COMPETITOR COMPARISON** | **0** | — |
| **UNSUPPORTED SUPERIORITY CLAIM** | **0** | — |
| **OVERSTATED SECURITY CLAIM** | **0** | — |

No drift to report and nothing to edit. The doctrine is not a correction to this
repository; it is a formalization of what it already does.

## 2. Two corrections to the submitted analysis

**(a) The "defensible comparison" table cannot be adopted either.** A dimension-by-dimension
table with an "Existing tools" column is a vendor comparison matrix. §2 of the submitted
doctrine forbids vendor comparison matrices, so the table contradicts the doctrine it
accompanies, and C-06 would reject it on the next commit regardless.

The content of that table is not wrong — it is notably more accurate than the analysis it
corrects, particularly that several established tools do document non-root operation with
reduced coverage. But its accuracy is not what makes it inadmissible. Its shape is.

What survives is the half that describes ISEDRAF without a comparison column: an
unprivileged base engine, explicit bounded acquisition operations, per-authority-class
envelopes, a first-class evidence-limits model, and early maturity stated plainly.

**(b) The three rejections are correct and one of them is already repository policy.**
"All incumbents run unrestricted root" is unresearched. "SLSA L3 = reproducible build" is
wrong — these are two proofs against two threats, recorded in §4. "TPM/IMA is required for
trust" would exclude most of the portability target matrix.

## 3. Trust is not a product claim

```
CLAIM       what we assert
SCOPE       where it applies
MECHANISM   what enforces it
METHOD      how anyone checks it
EVIDENCE    the artifact
LIMITS      residual risk and what is not proven
```

Any material security claim missing one of these is labelled `CLAIM_NOT_YET_PROVEN`. This
applies identically to the README, the website, release notes, badges, the HLD and
administrator documentation.

Preferred forms: *the following controls are implemented* · *this release demonstrated* ·
*this property is verifiable using* · *this limitation remains* · *this operation was not
evaluated* · *this authority is not available on this platform*.

Trust belongs to the operator. Evidence belongs to ISEDRAF.

## 4. Badges are indexes, never proof

```
BADGE     = pointer, navigation, presentation
EVIDENCE  = authority
```

A badge is permitted when it resolves to a machine-verifiable artifact in the release. A
badge that resolves to nothing is removed rather than explained.

| Badge | Must resolve to |
|---|---|
| Reproducible | the independent-rebuild record, per artifact |
| Falsification | the harness output with its own summary line |
| Negative security | the signed machine-readable qualification result |
| SBOM | the exact release SBOM |
| Provenance | the `.intoto.jsonl` |
| Supported architectures | the platform matrix, with `NOT_TESTED` shown as `NOT_TESTED` |

CI is part of the evidence chain and is not a security certificate. *All required release
gates completed* is accurate; *CI proves ISEDRAF is secure* is not. An external signal such
as OpenSSF Scorecard is genuinely useful as an outside check and remains one signal, not an
authority.

**Provenance and reproducibility are separate properties against separate threats**, and
the claim must not merge them:

```
SUPPLY-CHAIN PROVENANCE   hardened builder, protected signing    "it came from our build"
ARTIFACT REPRODUCIBILITY  independent rebuild, identical bytes   "it matches the source"
```

Per-artifact reproducibility is reported per artifact. One global "reproducible" badge over
a mixed set of `deb`, `rpm`, container and compiled artifacts would be a claim about the
weakest member presented as a claim about all.

## 5. Distinguish fact from target

Every substantial statement is recognizable as one of `IMPLEMENTED` · `VERIFIED` ·
`QUALIFIED` · `PLANNED` · `DESIGN TARGET` · `UNRESOLVED` · `NOT SUPPORTED`.

Concretely, and currently:

```
WRONG    "ISEDRAF uses per-operation kernel-constrained workers."
RIGHT    "R1.5-P2 defines a target architecture for per-operation kernel-constrained
          privileged acquisition. It is not implemented."
```

A limitation is not a defect to manage. `NOT_PROVEN`, `NOT_TESTED`, `PARTIAL`,
`UNAVAILABLE` and `DESIGN_UNRESOLVED` are correct results and are published as such.

## 6. External review reporting

An audit is evidence about a defined scope at a point in time, never a certification of the
project. Published: auditor, date, version or SHA reviewed, exact scope, methodology where
publishable, findings by severity, remediation status, and **excluded areas**. Not
published as *"auditor X proves ISEDRAF is secure."* Exploit-level detail may be withheld
where disclosure would create attack surface; the scope and the findings summary are not.

## 7. Performance is measured against ourselves

Benchmarks run against project requirements, previous ISEDRAF versions, frozen resource
budgets, target architectures and regression baselines. Another product is never the
acceptance oracle.

## 8. Trust and Assurance track

Cross-cutting, alongside R1.5 / P2 / R2. It does not block current unprivileged work.

| Stage | Contents | Depends on |
|---|---|---|
| TA-1 source and governance | `SECURITY.md`, disclosure process, protected release process, dependency policy | none — startable now |
| TA-2 build identity | signed tags, artifact signing, verification bundles, provenance | `signing` leaving PLANNED |
| TA-3 reproducibility | independent rebuild, amd64 and arm64, result per artifact | TA-2 |
| TA-4 software content | SBOM per artifact, dependency locking, vulnerability disposition | none |
| TA-5 runtime trust | P2 confinement, operation contracts, privilege receipts | **P2-D** |
| TA-6 adversarial testing | fuzzing of the IPC parser, response parser, contract decoder and privileged file parsers; malformed-IPC and authority-confusion campaigns | **P2-C** |
| TA-7 offline verification | verifier, trust bundle, no network dependency | TA-2 |
| TA-8 independent review | external audit of the privileged component, policies, authorization and update path | **P2-G** |
| TA-9 optional high assurance | IMA measurement, TPM-backed measurement, remote verification | TA-8, and never required of constrained targets |

Acceptance criteria come from ISEDRAF's own frozen contracts and target requirements. This
track contains no competitive ranking of any kind.

**Vulnerability management is part of TA-1, not an afterthought**: private disclosure
channel, advisory process, CVE handling where applicable, supported-version policy, patch
expectations, release revocation procedure, signing-key compromise procedure, dependency
emergency procedure. Without these, technically sound code is still difficult to
operationalize.

## 9. Position

```
WE STATE.
WE MEASURE.
WE PROVE WHAT WE CAN.
WE LABEL WHAT WE CANNOT.
WE EXPOSE THE EVIDENCE.
THE OPERATOR DECIDES.
```

Where ISEDRAF falls short of its own targets, it says so. Years of production exposure,
large deployed fleets and accumulated external scrutiny arrive only with time; none of
that is manufactured with badges, and this project does not claim what it has not yet
accumulated. What it can offer now is being unusually easy to inspect and
independently verify — source, architecture, threat model, known limitations, falsification
methodology, build provenance, negative tests, downloadable release evidence, public
advisories and published review status.

That is the whole argument, and it needs no one else in it.
