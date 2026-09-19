<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Framework source registry

Status: IMPLEMENTED
Implements: D-84, D-90, GOV-001, GOV-002

The authority is `scripts/ci/framework_sources.json`. This page explains it; the JSON decides.

## Current contents

**Zero sources.** No third-party framework source has been reviewed, registered or bundled.

That is the accurate state of the project, not a placeholder awaiting content. The gate does not
treat an empty registry as a pass by omission: it separately proves that no framework content exists
anywhere in the tree, so "nothing registered" and "nothing present" have to agree.

## Deny by default

> Unknown framework licensing state means NOT DISTRIBUTABLE.

The build and the public export **fail closed**. Content not recorded as `BUNDLED_OPEN` does not
enter the public repository, the export, the packages or the SBOM. No source becomes `BUNDLED_OPEN`
by assumption, by being publicly downloadable, or by being free of charge — only by a recorded
review with evidence.

## Dispositions

| Disposition | Meaning |
|---|---|
| `BUNDLED_OPEN` | Redistribution and commercial use verified in writing. May ship publicly. |
| `REFERENCE_ONLY` | May be named and cited. Content is **not** reproduced or bundled. |
| `PRIVATE_RESEARCH_ONLY` | Owner may study it privately. Never enters the export, packages, SBOM, fixtures or docs. |
| `LICENSE_REQUIRED` | Distribution needs a provider agreement that does not yet exist. |
| `PROHIBITED` | Determined not redistributable under any current model. |
| `UNDER_REVIEW` | Licensing not yet established. **Treated as `PROHIBITED` until it is.** |

## What every record must state

A record is incomplete — and the gate fails — unless it carries all of these:

```text
provider                                  framework            framework_version
official_source                           license              review_date
commercial_redistribution_allowed         derivatives_allowed  review_evidence
machine_readable_redistribution_allowed   attribution_required
trademark_restrictions                    disposition
```

`review_evidence` is the field that keeps this honest. A disposition without evidence behind it is
someone's recollection of a licence page.

## Where restricted content may not go

A separate distribution surface is required for anything not `BUNDLED_OPEN`. Restricted content must
**not** be placed in the public repository, the public DEB, the public RPM or the source tarball and
then hidden behind a runtime boolean or a licence key. Shipping the bytes and gating the display is
not a distribution boundary — the bytes were still distributed.

## Private research is separate

Owner-downloaded framework material may be studied privately for gap analysis, collector planning and
provider discussions. It lives outside the public export, under a path that is gitignored and that
the gate refuses to see tracked:

```text
planning/licensed-framework-research/
```

Nothing from there is copied into public documentation, samples, fixtures, packages or source
tarballs.
