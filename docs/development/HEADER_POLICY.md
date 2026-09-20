# ISEDRAF — File Header and Ownership Policy

Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0
Status: IMPLEMENTED
Implements directive: §1, §2, §3, §4, §5, §6, §21
Destination at Prompt 04: `docs/development/HEADER_POLICY.md` (governance-manifest covered)

<!-- doclint:exempt-forbidden-terms -->

## 1. Canonical identity — frozen

| Field | Value |
|---|---|
| Copyright holder | `Antonios Voulvoulis / ITCMS` |
| Contact | `contact@itcms.gr` |
| SPDX licence | `MPL-2.0` |
| Copyright year (new files) | `2026` |
| Public name | `ISEDRAF (codename)` until **OD-01** is resolved |

These strings are matched **verbatim** (`grep -F`) by gate L-05. Do not reformat, abbreviate, reorder or
localize them. Do not inherit NFTBan's `2024-2026` range, its `contact@nftban.com` address, or the bare
`Antonios Voulvoulis` holder form.

## 2. `meta:owner` — immutable project ownership

```
meta:owner="Antonios Voulvoulis / ITCMS"
```

**Semantics: project/source ownership identity. Nothing else.**

It does **not** represent: subsystem · maintainer · module · component · collector · development team ·
package · runtime responsibility.

Forbidden values include `metrics`, `identity`, `audit`, `collector`, `security`, `botscan`, `update`,
`ddos`, `suricata` — and every other value that is not the canonical string.

Gate **L-03** validates the exact value. Any other value fails `make check`.

**Why this rule exists.** In NFTBan, `meta:owner` began as a person field and drifted into subsystem
labels. The repair script for that repository states the holder string is *"FIXED … and is NEVER parsed
from `meta:owner` — several `meta:owner` values are junk … and parsing would propagate those errors into
legal metadata."* The test-authority schema then moved governance fields into a separate `ta.` namespace
*"to avoid colliding"*, which worked around the drift without repairing it.

ISEDRAF does not need that workaround, because the value is immutable and machine-validated from the
first commit. **Legal and project ownership is never derived from `meta:owner`** — it is defined by SPDX
headers, `COPYRIGHT`, `NOTICE`, `REUSE.toml` and repository governance. `meta:owner` is a consistency
assertion, not a source of truth.

If per-component labelling is ever required, it uses a **separate namespaced field** (e.g. `meta:sd.module`)
under its own controlled vocabulary. `meta:owner` is never repurposed.

## 3. Bash — executable / collector

```bash
#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Emit raw identity source material for the engine to normalize.
# Implements: IDENT-010, D-13
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:collector_id="identity.sources"
# meta:collector_version="1"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="getent,stat"
# =============================================================================
```

### Field contract

| Field | Required | Values | Validated by |
|---|---|---|---|
| `Purpose:` | yes | one concise human line | presence |
| `Implements:` | yes where a requirement applies | comma-separated requirement / decision IDs | G-08, C-02 |
| `meta:type` | yes | `collector` `engine` `ci-gate` `test` `generator` `launcher` `schema` `doc` | enum |
| `meta:owner` | yes | the canonical string, exactly | **L-03** |
| `meta:stability` | yes | `DRAFT` `EXPERIMENTAL` `STABLE` `DEPRECATED` `RETIRED` (D-80) | G-11 |
| `meta:collector_id` | collectors | stable dotted id | uniqueness |
| `meta:collector_version` | collectors | integer; bump changes comparability (D-45) | D-09 |
| `meta:parser_version` | parsers | integer | D-09 |
| `meta:privilege` | collectors, gates | `unprivileged` `root` | S-06 |
| `meta:mutates` | collectors, gates | `none` — anything else must be justified by a frozen requirement | **S-07** |
| `meta:binaries` | where invoked | comma-separated argv binaries | D-18 cross-check |

**Deliberately absent:** `meta:name`, `meta:description`, `meta:input`, `meta:output`. They duplicate
`Purpose:` and documentation, drift silently, and have no machine-readable semantics. They may be added
only if a future frozen requirement gives them one.

`meta:mutates` and `meta:privilege` are the two ISEDRAF-specific additions: they turn D-13's
"collectors collect, engine interprets" and D-60's "never touch host security configuration" from prose
into a grep gate.

## 4. Python — the same grammar, not a second one

**Machine-readable governance metadata has exactly the same syntax in Bash and Python.** A docstring
explains the code; it is **never** the canonical governance metadata source. Two syntaxes would mean two
CI parsers for no reason.

Library modules take **no shebang** and are non-executable; only the approved entry point uses
`#!/usr/bin/python3 -IB` (D-17). Everything else is identical to §3, including the banner — so that a
sysadmin or auditor opening **any** ISEDRAF-controlled source file sees the same project identity.

```python
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Canonical serialization and section hashing.
# Implements: NORM-031, D-37
#
# meta:type="engine"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:parser_version="1"
# =============================================================================

"""Canonical serialization and section hashing."""
```

**HDR-001 SHALL** All eligible ISEDRAF Bash and Python source files use the **same** canonical governance
metadata keys and syntax. Language-specific docstrings and comments MAY provide additional documentation
but **SHALL NOT redefine** ownership, stability, privilege or mutation metadata.

**HDR-002 SHALL NOT** `Owner:`, `Maintainer:`, `Copyright-Owner:` and `meta:owner=` SHALL NOT be used
interchangeably. There is exactly **one** canonical ownership field — `meta:owner="Antonios Voulvoulis /
ITCMS"` — plus the legal SPDX line. A governance key inside a docstring is a gate failure.

### Frozen header grammar

Required, in this order:

```
SPDX-License-Identifier
SPDX-FileCopyrightText
Purpose:
Implements:
meta:type=
meta:owner=
meta:stability=
meta:privilege=
meta:mutates=
meta:binaries=        # when the file spawns external executables
```

Domain-specific fields follow **only where relevant** — not every file needs every field:

```
meta:collector_id=      meta:collector_version=
meta:parser_id=         meta:parser_version=
meta:source_id=         # D-98 source-aware method identity
```

### `meta:binaries` — what it actually means

**HDR-003 SHALL** `meta:binaries` lists **external executables the file itself invokes**, not tools
involved in running or testing it. A Python gate that imports `re` and `pathlib` and spawns only `git`
declares `meta:binaries="git"` — **not** `"git,grep,python3"`. Python is the interpreter, not a spawned
dependency; `grep` belongs there only if the program actually executes `/usr/bin/grep`.

This keeps the field genuinely useful, because it later becomes a gate in its own right:

```
declared external executables   vs   actual subprocess calls
```

## 5. Markdown

Published `/docs/*.md` use an **invisible** SPDX comment; licensing is not repeated visually on every page.

```markdown
<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Identity and Privilege

Status: STUB
Implements: D-74, D-75
```

`Status:` is one of `STUB` `IMPLEMENTED` `EXPERIMENTAL` `PLANNED` `FUTURE` `OUT_OF_SCOPE` (D-88, gate C-08).
A `STUB` document contains headings and the status line only — behavioural prose in a stub fails gate C-07.

Planning and blueprint documents under `planning/` keep their existing visible metadata style. They are
local-only and not part of the published surface.

## 6. JSON

JSON has no comment syntax. **Do not** add synthetic `_license`, `_owner`, `$comment` or equivalent fields
to satisfy file licensing — gate **L-07** rejects it, because it corrupts strict schema validation and
D-15 requires control/rule/profile JSON to stay semantically clean.

JSON is licensed through `REUSE.toml` (D-90). This is the `NON_HEADER_FORMAT` class in §7 below.

## 7. File classification — the denominator

"Header coverage = all tracked files" is the wrong metric and drives the wrong work. Every tracked file
lands in exactly **one** class. `UNCLASSIFIED` is itself a failure (gate L-01).

| Class | Meaning | ISEDRAF examples |
|---|---|---|
| `OWNED_HEADER_APPLICABLE` | first-party source that can and must carry identity | `lib/isedraf/**/*.py`, `collectors/*.sh`, `scripts/**` |
| `GENERATED_BY_AUTHORITY` | identity is the generator's job; a stamp is erased on regeneration | `docs/CURRENT_STATE.md`, `requirements-trace.md`, `CLI.md`, `EXIT_CODES.md`, `isedraf.8` |
| `NON_HEADER_FORMAT` | an inline header is illegal or unsafe | `*.json`, `schemas/**`, `debian/control`, `debian/changelog`, `*.sha256` |
| `FIXTURE_BYTE_SENSITIVE` | bytes are asserted by a test; a header invalidates the authority it protects | `tests/fixtures/**`, `tests/golden/**`, `corpus/**` expected outputs |
| `THIRD_PARTY` | not authored here | `LICENSE` (MPL-2.0 text), `CODE_OF_CONDUCT.md` (Contributor Covenant) |
| `VENDORED` | dependency tree committed in-tree | none — D-12 forbids third-party runtime code |

**Acceptance:** `OWNED_HEADER_APPLICABLE` compliance 100% · `UNCLASSIFIED` 0 ·
`GENERATED_FILES_STAMPED_DIRECTLY` 0 · `NON_HEADER_FORMAT_MUTATIONS` 0 · `FIXTURE_BYTE_SENSITIVE` untouched
by header tooling.

`FIXTURE_BYTE_SENSITIVE` matters more for ISEDRAF than for most projects: the corpus asserts canonical
serialization byte-for-byte (D-37), so a header inserted into a golden file would silently invalidate the
very test that proves comparability.

## 8. Third-party text

`LICENSE` (MPL-2.0) and `CODE_OF_CONDUCT.md` (Contributor Covenant) are `THIRD_PARTY`: reproduced verbatim,
never re-stamped, and declared with their own licence in `REUSE.toml` (D-90).

## 9. Falsification

Gate L-03 and its neighbours are only real if they have been observed to fail. `make check-falsifiable`
injects, at minimum: `meta:owner="identity"` · a missing SPDX line · a reformatted holder string ·
a `contact@nftban.com` address · a header stamped into a generated file · a `_license` key added to JSON ·
a header inserted into a golden fixture. Each must fail.
