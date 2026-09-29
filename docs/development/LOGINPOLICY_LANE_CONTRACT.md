<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Login-policy lane interface contract

Status: PLANNING
Implements: SCOPE-022, SCOPE-045

Declared by the coordinator before either lane starts, so the adversarial pass attacks a
specification rather than an implementation.

```
isedraf.loginpolicy.acquire.collect(root="/") -> shared.result.Evidence
```

## Four families, four grammars — not one "Linux config profile"

| Family | Source | Grammar |
|---|---|---|
| `LOGIN_DEFS` | `/etc/login.defs` | `KEY value`, whitespace-delimited, `#` comments |
| `PWQUALITY` | `/etc/security/pwquality.conf` + `.conf.d/*.conf` | `key = value`, `#` comments |
| `FAILLOCK` | `/etc/security/faillock.conf` | `key = value` and bare boolean keys |
| `LIMITS` | `/etc/security/limits.conf` + `limits.d/*.conf` | **four positional fields**, not key/value |

`limits.conf` is `<domain> <type> <item> <value>` — for example `* hard nofile 65535`.
It has no key and no delimiter. Forcing it through S1 would mean inventing a key for
something that has none, which is the mistake sudoers avoided. **The lane is expected to
use S1 for the three key/value families and a domain parser for limits.**

## Records

Every record carries `family`, `source_path`, `source_line`, `ordinal`, and the
`grammar_digest` of the profile that parsed it.

Key/value families: `key`, `key_raw`, `value`, `retention`, `duplicate_of`.
Limits: `domain`, `domain_negated`, `limit_type`, `item`, `value`.

## Out of scope for this lane

No effective policy. `login.defs PASS_MAX_DAYS` and a per-account `/etc/shadow` max-age
are two pieces of evidence at different layers, and collapsing them into one "effective
password expiry" needs PAM, account state and distribution behaviour. Three tiers exist
and only the first two belong here:

```
DECLARED VALUE              this lane
SOURCE-SPECIFIC RESOLUTION  this lane, only where the format itself defines override
CROSS-SOURCE EFFECTIVE      NOT this lane
```
