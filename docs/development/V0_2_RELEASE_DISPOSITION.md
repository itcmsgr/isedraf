<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.2 release disposition of open implementation questions

Status: PLANNING
Implements: D-118, D-120, D-124

Owner direction 2026-10-10: classify every implementation question that is not closed into one of
three classes, with evidence, and reopen nothing that is not a present defect.

- **v0.2 blocker** - a reproducible security or correctness failure, or a frozen release contract not
  met, shown by concrete evidence.
- **v0.2 required (documentation)** - no defect in the product, but a published statement that is false
  for v0.2; fixed with the public documentation (IQ-051).
- **Post-v0.2** - legitimate future scope with no present release-contract violation.
- **Historical / administrative** - stale wording or a question already settled; closed in the record.

This register is the disposition; `docs/IMPLEMENTATION_QUESTIONS.md` keeps each question's history.
State as of engineering `d09f59d`.

## Disposition

| IQ | Class | Evidence (REPOSITORY FACT unless marked) | Action |
|---|---|---|---|
| IQ-031 | v0.2 blocker - **closed** | Owner decision 2026-10-10: satisfy D-83 before v0.2. The manifest and `check_governance.py` exist (D-83 register entry, extension 27). | None. |
| IQ-051 | v0.2 required (documentation) | The public documents describe 0.1.x: `docs/GETTING_STARTED.md` lists the 0.1 refusal; README's exit table gives `64` the 0.1.x meaning "or the evidence store was refused" (IQ-067). | The v0.2 public documentation pass: `sudo isedraf audit` and `sudo isedraf report`, their requirements and limits, the exit codes from `exitcodes.json`, the authorized-keys limitation. |
| IQ-047 | v0.2 required (documentation) - **wording fixed** | The false statement is corrected (2026-10-10); per-section map rows are post-v0.2 documentation. | None for v0.2. |
| IQ-033 | Post-v0.2 | The docs-truth gate skips a backticked name with no `/` and treats a planned marker anywhere on a line as covering every path on it (`scripts/ci/check_docs_truth.py` lines 92 and 119); seen 2026-10-10, when CLAUDE.md line 16's marker also covered `GOVERNANCE_MANIFEST.sha256`. A weakness of a gate, not of the product. | Fix after v0.2, or before the documentation pass if the owner wants that pass held to a stricter gate. |
| IQ-009 | Post-v0.2 | There is no standalone `isedraf verify`; verification failure inside a run or report exits `64`. `5 TOOL_INTEGRITY_FAILURE` is frozen and not reachable (`exitcodes.json`, `SCOPE-077`). | With the comparison and baseline work (v0.4), where `5` becomes reachable. |
| IQ-015 | Post-v0.2 | `openssh_version` is `null` with a stated reason; `sshd -T` prints no version. Honest absence, no contract violation. | Later, with a fixed source of the version. |
| IQ-030 | Post-v0.2 | `check_lane_scope.sh` is wired to no gate; the lane workflow it served is not in use for v0.2 closure. | Governance tooling after v0.2. |
| IQ-032 | Post-v0.2 (owner) | Tier-1 authority covers `docs/architecture/`; only part of it is in a freeze manifest. No product effect. | Owner governance decision after v0.2. |
| IQ-042 (3) | Post-v0.2 | Items (1) and (2) released in 0.1.2; (3) is marked FUTURE. | As recorded. |
| IQ-045 | Post-v0.2 | `SCOPE-023`'s lockout warning is a finding; findings are v0.3 (D-120). v0.2 records a failed `sshd -T` as `ERROR` with its exit status and stderr (`AUTH-031`). | v0.3. |
| IQ-059 | Post-v0.2 | The test-isolation invariant is recorded; the one incident read nothing. The test-inclusion gate (2026-10-10) is a different check. | A test-suite self-check after v0.2. |
| IQ-058 | Historical / administrative | Fixed in engineering, so v0.2 ships the fix; open only as a 0.1.3 candidate. | Closes with the v0.2 release unless the owner orders a 0.1.3. |
| IQ-001 | Historical / administrative | The `setpriv` / SELinux evidence it asked for is the OD-06 measurement, closed 2026-10-08 (`AUTH-028`); `CAP_AUDIT_CONTROL` is not in the v0.2 set. | Close: superseded by `AUTH-028`. |
| IQ-004 | Historical / administrative | The `INIT/` directory it concerned no longer exists. | Close. |
| IQ-006 | Historical / administrative | The frozen behaviour (`SCOPE-062`: journal records, no `/var/log/isedraf/`) is what is implemented; the conflict was with an owner sketch, not a requirement. | Close: frozen text governs. |
| IQ-008 | Historical / administrative | The lock is at `/var/lib/isedraf/.lock` as `STORE-001` requires; the sketch's `/run` location was not adopted. | Close: frozen text governs. |
| IQ-038 | Historical / administrative | Bytecode written by pre-release (alpha1, rc1) launchers on hosts that ran them; no released package writes it (`-B` since rc2, held by a test and falsification). | Close: affects only pre-release installs, as registered. |

The questions closed or fixed in their own rows (IQ-048, IQ-053, IQ-054, IQ-062, IQ-063 and the
others marked CLOSED, FIXED or IMPLEMENTED) need no disposition.

## Deferred privileged operations (owner decision 2026-10-10)

The four validated operations are the complete v0.2 privileged-operation scope (`AUTH-025`, the
admission order complete). Two registered operations are **post-v0.2 candidates**, not unfinished v0.2
work. Their registry states are unchanged and true:

| Operation | Registry state | Why it is not v0.2 |
|---|---|---|
| `inspect_mount_namespaces_v1` | `PLANNED` | The host mount table is read by the engine with no privilege (IQ-055). What remains is other processes' and containers' namespaces, which needs `CAP_SYS_PTRACE` and its own threat model. |
| `read_authorized_keys_v1` | `DESIGN_OPEN` | Its per-account targets cannot be derived without supervisor parsing (`AUTH-006`); no contract exists. |

Consequence to disclose in the v0.2 release notes and public documentation: **Full Audit does not
collect other users' `authorized_keys`**; those files stay `NOT_TESTED` where the engine identity
cannot read them.
