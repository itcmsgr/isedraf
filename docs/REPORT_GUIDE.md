<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Report guide

This page explains how to produce a report and how to read one, part by part.

## Producing a report

A report describes the last run committed by `isedraf audit`. It reads that run from the
evidence store, checks it, and renders it. It never collects anything, so rendering the
same run twice describes the same evidence.

```sh
isedraf report                       # Markdown, to the terminal
isedraf report --html > report.html  # static HTML
isedraf report --json                # the report model, for other tools
isedraf report --html --save         # write it into the store under reports/
```

`--save` writes `reports/<year>/<month>/RPT-<time>-<random>.<ext>` inside the evidence
store, readable only by you, and prints the path.

The command exits 0 when every part of the run was COLLECTED and 2 when anything was not.
It exits 64 when there is no audit run to report on.

## The three formats

| Format | Best for | Contents |
|---|---|---|
| HTML | people | the full layout described below: banner, run panel, one section per area, limitations |
| JSON | tools | the same facts as data; the per-area results are under `audit_sections` |
| Markdown | a terminal or a ticket | host identity and inventory in detail, a completeness table and the limitations |

The HTML page is a single static file with no scripts and no external resources. All host
text in it is escaped, so a hostile hostname or account comment cannot run as code.

## The HTML report, top to bottom

The excerpt below is the text of a real report from a small test host, made with a
pre-release build and shortened. The digests are real; `web01` is the test host.

```text
ISEDRAF Host Evidence Report
PRIVILEGE LEVEL: UNPRIVILEGED · OVERALL EVIDENCE: PARTIAL
This run had no elevated privilege. Facts that need it were NOT_TESTED. NOT_TESTED does
not mean those controls passed; it means they were not observed.

Run
  Host                    web01
  Host id (pseudonymous)  sha256:e896539f9dd3b417d1fd5b8c327d8caeb02353d1c2714a2889d2593442d899fa
  Snapshot                SDS-20260928T140403Z-41a4d71af5303e60
  Run                     RUN-20260928T140403Z-baa8cafa71007650
  Collected at            2026-09-28T14:04:03Z
  Report generated        2026-09-28T14:04:16Z
  Engine version          0.1.0-alpha1
  Evidence class          USER_PRODUCTION
  Evidence verification   verified: hashes, bindings and ledger chain hold

Local accounts and groups                          PARTIAL
  etc/shadow: SOURCE_ABSENT: etc/shadow does not exist on this host.
  Local account records (/etc/passwd)   3
  Accounts with uid 0                   1
  Local group records (/etc/group)      4
  /etc/passwd consulted by NSS          ACTIVE
  evidence: sections/accounts.json · sha256:b78bea64006d0219e1abc0c87a3fa6c9d3023cb4668c0c72ee5450d8d879f8c3

Hostname                                           COLLECTED
  Declared (/etc/hostname)   web01.example.test
  Active (kernel)            web01
  Declared vs active         DIFFERENT
  evidence: sections/hostname.json · sha256:2583cf34c3d31e227cfeba04c1cc4c16c94ff3b3970c779ae4d2107e91aeaecc

SSH authorized keys                                NOT_TESTED
  NO_DECLARATION_OBSERVED: the declared sshd configuration carries no AuthorizedKeysFile,
  and a compiled-in default is not evidence this collection holds.
  Records observed   0
  evidence: sections/authorizedkeys.json · sha256:eaf5fc4354d205dd8b84d3adaf33c0346f811cac1f67def192c362fdc3cd13bd
```

## The banner

The first line you see states the privilege level and the overall evidence status, and
the sentence under it says what NOT_TESTED means. Read it before anything else: it tells
you how much of the host this report could see.

## The run panel

The run panel identifies exactly which evidence the report describes.

- **Host** is the hostname as observed; **Host id** is the pseudonymous identifier, not
  the machine-id.
- **Snapshot** is the run directory in the evidence store; **Run** is the run identifier.
- **Collected at** is when the run was made; **Report generated** is when it was rendered.
- **Engine version** is the ISEDRAF version that collected it.
- **Evidence class** is USER_PRODUCTION for a normal run, DEV for a development run.
- **Evidence verification** is the result of re-checking the run's digests and the ledger
  chain at render time.

## One section per area

The ten areas appear in a fixed order: host and platform, accounts, name service,
hostname, mounts, SSH server, PAM, sudo, SSH authorized keys, login policy. Each has:

1. **Status**: COLLECTED, PARTIAL, NOT_TESTED or ERROR.
2. **Reason**, when the status is not COLLECTED. It names the source and what went wrong.
3. **Facts**: a short summary, such as counts or declared values. It is a summary, not
   the whole evidence; areas without a tailored summary show how many records were
   observed.
4. **Evidence reference**: the file in the run and its digest. This is where every fact in
   the section comes from, and what an auditor checks. See
   [Checking one observation by hand](AUDITOR_GUIDE.md#checking-one-observation-by-hand).

A count of zero under a NOT_TESTED or PARTIAL status means nothing was observed. It does
not mean nothing exists.

## Limitations

The report ends with the limitations that apply to this run, for example that host
identity is not remote attestation, and that clock synchronization could not be
determined when that was the case. They belong to the report; do not detach them.

## Adding assessor details

`--profile <file>` adds declared details, such as who prepared the report and for whom,
from a small JSON file. They are shown as declared, not verified: the report is not signed.
Keeping them in a file keeps personal details out of shell history.

## References

Normative sources, for readers who need them: reports render committed evidence only
(OUT-013, D-115); unprivileged release and its report (D-117). How the statuses are
defined: [Evidence model](EVIDENCE_MODEL.md).
