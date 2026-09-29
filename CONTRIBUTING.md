<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Contributing to ISEDRAF

Status: IMPLEMENTED
Implements: D-63, D-69, D-90, D-91, D-93, §13

ISEDRAF is a trust tool. Its value is that what it reports is true and that its limits are stated. Most
of the rules below exist to protect that property, not to protect a coding style.

## What contributions are welcome

Pull requests are welcome for bug fixes, regression tests, parser fixtures from real systems (redacted),
platform compatibility evidence and documentation corrections. For a new feature or a change of
behaviour, open an issue first: scope is deliberately narrow (see below), and a feature outside it will
not be merged however well it is written.

Security vulnerabilities are **not** reported through issues or pull requests. See
[`SECURITY.md`](SECURITY.md).

## Development prerequisites

- Linux, `git`, `make`, `bash` and GNU coreutils.
- Python 3. The product runs on Python **3.6 or later**, including vendor-maintained 3.6 such as
  `platform-python` on Enterprise Linux 8, so product code must stay within the 3.6 language and
  standard library. `make check` enforces that floor.
- Optional, for packaging and some checks: `dpkg-deb`, `rpmbuild`, `rsync`, `shellcheck`.

There are no third-party Python packages to install, for the product or for development. See
[`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md).

## Before you open a pull request

```sh
make check
```

`make check` is the single local entry point, and CI runs the same targets. There is no warning tier: a
check either passes or fails. Install the repository hooks once, so `make check` runs before each
commit:

```sh
hooks="$(git rev-parse --git-path hooks)"
cp git-hooks/* "$hooks"/ && chmod 0755 "$hooks"/*
```

Never bypass them with `git commit --no-verify`.

**Tests.** Every change comes with tests appropriate to it. Every bug gets a regression test that fails
before the fix. Every parser needs normal, malformed, missing-data and permission-failure fixtures.

**Required CI.** A pull request can be merged only when these checks pass on it: `make check`,
`make check-falsifiable`, `make check-gate-coverage`, the W1-A vector lanes, CodeQL and the DCO
check. The branch is protected: no force-push, no deletion, linear history.

## Signing off your commits (DCO)

Every commit must carry a Developer Certificate of Origin sign-off. By adding it you certify the
statements at <https://developercertificate.org/>, in particular that you have the right to submit the
change under the project's licence (MPL-2.0).

```sh
git commit -s            # adds: Signed-off-by: Your Name <you@example.com>
```

The name and email must match the commit's author. To sign off commits you already made on your branch:

```sh
git commit --amend -s --no-edit            # the last commit
git rebase --signoff origin/main           # every commit on the branch
```

The DCO check fails a pull request that contains any commit without a matching sign-off, and says which
commit. A sign-off is a personal legal statement: nobody may add one on another person's behalf, and an
AI tool cannot make one.

## Disclosing AI assistance

Separately from the DCO, every commit states whether AI tools assisted, with an `Assisted-by:` trailer.
The `commit-msg` hook enforces it:

```
Assisted-by: Claude (implementation via Claude Code)
Assisted-by: none
```

`Assisted-by:` is disclosure. It does not replace your sign-off, and AI tools are never credited as
authors: a `Co-Authored-By:` trailer naming an AI tool is rejected. See
[`AI_ASSISTED_DEVELOPMENT.md`](AI_ASSISTED_DEVELOPMENT.md).

## The invariants

**Host evidence boundary.** ISEDRAF assesses state directly observable on the local operating system.
Firewalls, AV, EDR, IDS/IPS, WAF, SIEM, cloud and network controls, CVE matching and whole-filesystem
integrity monitoring are out of scope. The absence of a locally detectable agent is never the absence
of the control.

**Read-only.** ISEDRAF never modifies host state. Collectors collect; the engine interprets.

**Runtime dependencies.** Python standard library only, with a checked import allowlist. No compiled
components, no plugins, no network access, no embedded database.

**Clean room.** Never copy code, rules, tests, prose, tables, mappings or remediation from another
product or standard. Reference identifiers and authoritative sources; write ISEDRAF text independently.

**`NOT_TESTED` is not a pass.** Evidence that was not collected never becomes a good result, a removal
or an improvement.

**Committed evidence is immutable.** A committed snapshot is never modified.

**Traceability.** Code that implements a requirement cites it, for example `Implements: SNAP-012`.

## Security-sensitive changes

Changes to evidence collection, hashing and verification, the evidence store, the launcher, packaging
or the CI workflows need extra care. Say so in the pull request, explain the effect on what ISEDRAF
reports, and add a test that fails if the protection is removed. A change that weakens a check to make
work pass is not accepted.

## Pull requests

The template asks what the change does, which tests cover it, whether it changes what ISEDRAF reports
for an unchanged host, and which AI tools were used. Keep one concern per pull request.

## Documentation

Documentation is reviewed like code. Describe only what exists: a planned feature is never written in
the present tense. Follow [`docs/STYLE_GUIDE.md`](docs/STYLE_GUIDE.md).
