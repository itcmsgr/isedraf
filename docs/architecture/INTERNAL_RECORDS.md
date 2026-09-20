<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Internal records that are not published

Implements: D-88, D-90, GOV-001

Some documents referenced by this project are **change-control records**, not specification. They are
kept in the private engineering repository and are deliberately not part of the public repository.
This page exists so that a reference to one of them leads somewhere that answers you, instead of to a
missing file.

| Record | What it is | Why it is not published |
|---|---|---|
| `DECISIONS_REGISTER.md` | 124 numbered project decisions (`D-01`…) with their reasoning | Internal decision history. A reader of the published project is served by what the tool guarantees, not by the order in which the author decided things. |
| `OPEN_DECISIONS.md` | Questions that are still open, with deadlines | Unresolved internal questions read as commitments once published. Several carry dates that would become promises. |
| `AMENDMENTS.md` | The owner's change-control record for frozen documents | It governs how the frozen set may be altered. It is authority over this repository, not documentation of the product. |
| `W1A_CORE_FREEZE_SCOPE.md` | Which artifacts entered the first freeze set, and why | Internal process record. |
| `MASTER_INDEX.md` | Generated index of requirement-ID ranges per document | Internal navigation over the full set, including the documents above. |

## What this does not mean

**It is not a hidden specification.** Everything the tool promises is in the published documents:
`ISEDRAF_HLD.md`, `EVIDENCE_AND_TRUST_MODEL.md`, `SNAPSHOT_BASELINE_DELTA_MODEL.md`,
`V0_1_IMPLEMENTATION_SCOPE.md` and `NORMATIVE_SOURCES.md`. Every requirement ID cited anywhere in this
repository — including the `Implements:` lines in the shipped source — is defined in one of them.

`V0_1_IMPLEMENTATION_SCOPE.md` was briefly on the list above, as planning. It is not: it defines 54
requirement IDs that 52 published files cite, `lib/isedraf/identity.py` among them. A specification
the published code points at cannot be unpublished, and the measurement is what corrected the
classification.

**The published specification is frozen and verifiable.** `docs/architecture/freeze/W1A_CORE_PUBLIC.sha256`
holds the digests of the published frozen subset. Those digests are **copied** from the full freeze set
in the engineering repository rather than recomputed, so both repositories verify the same bytes:

```sh
sha256sum -c docs/architecture/freeze/W1A_CORE_PUBLIC.sha256
```

**A decision reference in a public document is still a real reference.** When a public document cites
`D-07`, that decision exists and was recorded; its full text is in the internal register. The public
specification states the resulting requirement, which is the part that constrains the software.

## Gate behaviour in a public checkout

Two checks have less to work on here than in the engineering repository, and both **say so** rather
than reporting a pass they did not earn:

- `make check-index` skips, because `MASTER_INDEX.md` is not present. Freshness is enforced where the
  document can actually be edited.
- `make check-refs` runs in a reduced mode when the internal register is absent, and prints which mode
  it used.

This is the same rule the project applies to its own evidence: a check that could not run reports that
it could not run.
