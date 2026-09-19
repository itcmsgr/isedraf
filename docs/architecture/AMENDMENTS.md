<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Owner Amendments — Historical Provenance

Implements: D-68, D-106

**This file is history, not authority.** Every accepted amendment has been incorporated into a numbered
decision in `DECISIONS_REGISTER.md`. Frozen documents cite the **decision ID**, never an `A-0xx` number.
Implementation SHALL NEVER need this file to discover current truth (D-106).

Recorded per amendment: what changed · when · why · **which current decision supersedes it**.

| Amendment | Date | What changed | Why | Superseded by |
|---|---|---|---|---|
| **A-001** | 2026-09-17 | AI `Co-Authored-By:` trailers forbidden; `Assisted-by:` becomes the sole disclosure mechanism | `Co-Authored-By` asserts authorship; AI tools hold no rights (D-92). The Prompt 01 audit measured a project whose identical policy was documented but ungated and violated in 40 of its last 100 commits — documented intent decays, gates do not | **D-93 (revised)** |
| **A-004** | 2026-09-17 | No authority titles for AI systems; the "no contributing tool is omitted" obligation removed | Assigning a directing role to a tool misstates who owns and directs the architecture; an exhaustive model inventory is authorship accounting, not transparency | **D-91 (revised)** |
| **A-005** | 2026-09-17 | The unconditional `pre-push` refusal remains for the whole prototype; possessing a key is not authorization to push | Capability and authorization are separate. Holding a write key while the repository declares pushes permanently forbidden is the kind of contradiction resolved by quietly deleting the hook | **D-96** (bootstrap carve-out), D-73 |
| **A-006** | 2026-09-17 | Private GitHub bootstrap may precede Prompt 04; Prompt 04 clones the existing repository instead of `git init` | Building the GitHub surface twice wastes effort; the governance shell is useful before implementation and does not authorize implementation | **D-96** |
| **A-007** | 2026-09-18 | Production runtime Python floor lowered from ≥ 3.9 to a **3.6 language and API level** for `lib/isedraf/` only; development, test and certification tooling stay unconstrained | W1-C measured the interpreter as the **only** portability boundary in the whole matrix. On vendor Python 3.6 — AlmaLinux 8.10's `/usr/libexec/platform-python` 3.6.8 and openSUSE Leap 15.6's stock 3.6.15 — the production implementation reproduced all 13 certified vector cases byte for byte, passed the full campaign, and held host identity across a real reboot. Both hosts needed **nothing installed**, which is the deployment model the project exists to have | **D-12 (revised)**, `EXEC-016` |
| **A-002** | 2026-09-17 | Documentation generators whose output is consumed as a gate move to W0 | A doc-lint gate required at W0 while its generators arrive at W4 is hollow for four milestones | **GOV-007** (in the HLD), D-89 |
| **A-003** | 2026-09-17 | `INIT/files.zip` archived outside the working repository | Prompt 04's precondition expects only `planning/` at the root | closed; no decision needed |

## Amendment procedure (D-68, D-106)

1. The owner writes the amendment here with its rationale.
2. The change is **incorporated into a numbered decision** in `DECISIONS_REGISTER.md`.
3. `FROZEN_MANIFEST.sha256` is regenerated.
4. Frozen documents are updated to cite the decision ID.
5. This table records which decision superseded the amendment.

An amendment that has not reached step 2 is **not yet authority** and SHALL NOT be cited by any frozen
document or by implementation.

## Note on numbering

`A-0xx` amendments are distinct from the `A1`–`A19` series in the register, which refers to the original
HLD challenge items. The two series SHALL NOT be conflated (finding R-23).
