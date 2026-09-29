<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# PAM lane interface contract

Status: PLANNING
Implements: SCOPE-022, SCOPE-045

```
isedraf.pam.acquire.collect(root="/") -> shared.result.Evidence
```

## Grammar

`/etc/pam.d/<service>`, one rule per line:

```
type  control  module  [arguments...]
```

`type` is `auth`, `account`, `password` or `session`, optionally prefixed `-` meaning
"do not complain if the module is missing".

`control` is a simple keyword — `required`, `requisite`, `sufficient`, `optional`,
`include`, `substack` — **or** a bracketed expression:

```
[success=done default=bad]
[default=bad success=ok user_unknown=ignore]
[success=1 default=ignore]
```

Bracketed controls are parsed into `{condition, action}` pairs with numeric jumps kept
numeric. Collapsing them to `CUSTOM` would destroy exactly the evidence a later criterion
needs.

## `include` is not `substack`

Both name another service, and they are **not the same edge**. `include` splices the
target's rules into the current stack, so a `done`/`die` there ends the whole stack.
`substack` evaluates the target as a self-contained sub-stack, so a jump inside it cannot
escape past the substack boundary. S2 owns traversal; PAM owns what the edge means, and
the normalized model keeps them distinct.

## Targets are service names, not paths

`include password-auth` names a service resolved inside the `pam.d` directory. It is not
an arbitrary filesystem path, so the rooted-path mapping sudo and SSH both needed is
expected **not** to apply here. If the implementation shows otherwise, report it.

## Out of scope

No verdicts. Module presence is evidence. Nothing here concludes that login is secure,
lockout is configured, password policy is effective, MFA is enabled, or that
authentication would succeed.
