<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Maintainers and roles

Status: IMPLEMENTED
Implements: D-91, D-92, D-93, D-110

## People with access to sensitive resources

| Person | GitHub | Access |
|---|---|---|
| Antonios Voulvoulis (ITCMS) | `@itcmsgr` | repository administration, release publication, security advisories, repository and security settings |

Nobody else holds write, administration or release access to this repository, and there are no
deploy keys. `.github/CODEOWNERS` routes every review to the maintainer.

## Roles and responsibilities

**Project owner and maintainer.** Sets project direction and scope, reviews and merges changes, owns the
architecture decisions, and administers the repository and its security settings.

**Release authority.** The maintainer alone creates tags and GitHub Releases. Release artifacts are
built by the repository's release workflow, which attaches build provenance and an SBOM to each one.

**Security response.** The maintainer receives private vulnerability reports, triages them, prepares
fixes privately and publishes advisories, following [`SECURITY.md`](SECURITY.md).

**Contributors.** Anyone may propose changes through a pull request under
[`CONTRIBUTING.md`](CONTRIBUTING.md). Every commit carries a Developer Certificate of Origin sign-off,
and a pull request is merged only after the required checks pass and the maintainer has reviewed it.

## AI assistance

AI tools are used as development assistants. They hold no maintainer role, no repository access of
their own, and no authorship, ownership or copyright in the project. Work they assisted with is
reviewed and committed by a person, and disclosed on each commit with an `Assisted-by:` trailer, as
described in [`AI_ASSISTED_DEVELOPMENT.md`](AI_ASSISTED_DEVELOPMENT.md).

## Contact

Security: see [`SECURITY.md`](SECURITY.md). Everything else: `contact@itcms.gr`.
