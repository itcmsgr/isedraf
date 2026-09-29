<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# SSH lane interface contract

Status: PLANNING
Implements: SCOPE-022, SCOPE-045, SCOPE-020, SCOPE-021

Declared before either lane starts.

```
isedraf.ssh.acquire.collect(root="/") -> shared.result.Evidence
```

## DECLARED only

`sshd_config` and everything it includes. **Not** `sshd -T`. Resolved and active state are
a separate acquisition source that will later meet S3, and conflating them here would
make a declared value look like a running one.

## Scope is structural, not a bag of pairs

A directive inside a `Match` block is **not** the same fact as the same directive in
global scope:

```
PasswordAuthentication no

Match User backup
    PasswordAuthentication yes
```

Flattening those into two `PasswordAuthentication` values loses the only thing that
distinguishes them. Every declaration therefore carries its enclosing context.

## Records

| kind | fields |
|---|---|
| `DIRECTIVE` | `keyword`, `keyword_raw`, `value`, `scope`, `match_index`, `match_criteria` |
| `MATCH` | `criteria` `[{keyword, values, negated}]`, `match_index` |
| `UNSUPPORTED` | `raw_digest`, `reason` |

`scope` is `GLOBAL` or `MATCH`. `match_index` is null in global scope and otherwise the
ordinal of the enclosing block, so block order is recoverable.

All records carry `source_path`, `source_line`, `ordinal`, in include-expansion order.

## Duplicate semantics are recorded, not applied

sshd takes the **first** value for most keywords — the opposite of the last-wins families
in login-policy. That rule is recorded in provenance; no value is resolved here.

## Out of scope

No "effective SSH security". No claim that a setting is safe, hardened or weak.
`PermitRootLogin yes` is a declaration, not a finding.
