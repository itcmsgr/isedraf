<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Support

Status: IMPLEMENTED
Implements: D-64, D-54, §12

## Before anything else: redact

ISEDRAF reports describe your host's identity and privilege state. They can contain usernames, UIDs,
home paths, SSH key fingerprints, sudo rule bodies and GECOS fields.

**Never post an unredacted identity or evidence bundle in a public issue, discussion or chat.**

Use `--redact`, which removes key fingerprints, sudo rule bodies and GECOS. Review what remains before
sharing. When in doubt, send it privately to `contact@itcms.gr` instead.

## Safe to share

Version and platform · exit code · collection status counters · evaluation result counters · requirement
or control IDs · the shape of a delta (how many changes, of which classes) · redacted output ·
sanitized parser input showing the format, not the values.

## Not safe to share publicly

Full snapshots · full evaluations · the ledger · acceptance records (they contain actor and reason) ·
`authorized_keys` fingerprints · sudo rule bodies · real usernames, hostnames or IP addresses.

## Supported platforms

| Tier | Platforms |
|---|---|
| **Supported** (v0.1 target) | Debian 12 · Ubuntu 24.04 · Rocky Linux 9 · AlmaLinux 9 |
| **Experimental** | none yet |
| **Unsupported** | Alpine · Arch · SUSE · any BSD · macOS · Windows · containers as an assessment target |

Running on an unsupported platform is not a bug. Behaviour there is undefined, and collection failures are
expected to surface as `NOT_TESTED`, not as a passing result.

## Product bug vs unsupported environment

It is a **product bug** if: ISEDRAF reports a passing result for something it could not collect ·
a real change is not detected in a supported domain on a supported platform · an unchanged host produces
drift · ISEDRAF writes outside `/var/lib/isedraf` · it modifies host state.

It is an **unsupported environment** if: the distribution is outside the supported tier · a required
subsystem tool is absent and the result is honestly reported as `NOT_TESTED` · the host uses an identity
provider whose effective state ISEDRAF explicitly does not resolve (SSSD, LDAP, AD).

## Getting help

Questions and usage: open a discussion or an issue using the documentation template.
Vulnerabilities: `SECURITY.md`. Everything else: `contact@itcms.gr`.
