<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# ARCH-02 — Batch 2 structural, semantic and oracle review

Status: IMPLEMENTED
Implements: GOV-001, GOV-002, SCOPE-022, SCOPE-045

Reviewed `e14ad54d` — sudo, login-policy, SSH and PAM as a system, against ARCH-01.

## Blockers found and fixed

### 1. login-policy: a refused source dropped from completeness

`/etc/login.defs` **present and permission-denied**, `pwquality.conf` readable → the
aggregate reported **`COLLECTED` with no reason**. Absent and refused were collapsed into
one `NOT_TESTED`, and `NOT_TESTED` sources were excluded from the aggregate entirely.

This is Defect A in a new domain: one readable source satisfying completeness for one
that could not be read. A family that is *not configured* is an ordinary state; a file
that *exists and was refused* is evidence we do not have.

Both answers now coexist correctly — the source is still `NOT_TESTED` per `SCOPE-022`,
and the aggregate is `PARTIAL` with a reason.

## Should-fix, fixed

| | |
|---|---|
| **`surrogateescape` duplicated in three new domains** | ARCH-01 created `textbytes` precisely to stop three copies of this; sudo, ssh and pam each wrote their own. Routed through the existing helper. `ACCIDENTAL_DUPLICATION`. |
| **Unparsed content retained in login-policy only** | For a malformed line S1 keeps the whole line as `key_raw`. sudo, ssh and pam digest unparsed content; a mistyped `pwquality` entry would have retained its `dictpath` verbatim. Now consistent across all four. |
| **7 text-grep test assertions** | `assertIn("filemeta.observe", inspect.getsource(...))` matches a mention in a comment as readily as a call. PAM's `assertNotIn("include_graph", source)` was one clarifying sentence from failing for the wrong reason — its own header discusses why S2 is unused. All converted to AST. |
| **Envelope scans** | Nine assertions searched `json.dumps(ev.as_dict())`, which includes limitation prose that names the concepts it denies. Narrowed to `ev.records`. |
| **Two falsification blind spots** | login-policy had no fixture-escape mutation and PAM no redaction mutation, while sudo and SSH had both. Added; both fire. |

## False positives, recorded

The duplication scanner flagged five things that were comments or substring matches:
`lstat` in a sudo comment, `glob`/`listdir` in ssh and pam comments, and `COLLECTED = "`
matching `RECORD_SOURCE_NOT_COLLECTED`. Only `surrogateescape` was real. Recorded so the
next reviewer does not re-investigate them.

## ARCH-01 delta

12 new modules, 4 domains. **0 cycles · 0 layer inversions · 0 shared→domain edges ·
0 network paths · 0 parser I/O · 0 renderer acquisition.** Architecture artifacts
deterministic and current.

## Semantic oracle matrix

| Domain | Behaviour | Level | Basis |
|---|---|---|---|
| SSH | `Include` inside `Match` inherits scope; child does not clobber parent | **1** | `sshd -T -C`, OpenSSH 10.2p1, run before the fix |
| SSH | dual `Keyword value` / `Keyword=value` form | **2** | `sshd_config(5)` |
| SSH | no inline comments; first-wins duplicates | **2** | `sshd_config(5)` |
| PAM | bracketed control forms, numeric jumps | **2** | real forms from `/etc/pam.d` on a running host + `pam.conf(5)` |
| PAM | `include` splices, `substack` contains a jump | **2** | `pam.conf(5)` |
| PAM | cycle ≠ diamond | **3** | independent adversarial reasoning; no external oracle |
| sudo | `#include` / `#includedir`, filename eligibility | **2** | `sudoers(5)` |
| sudo | tag scope applies onward; negation; runas absence | **2** | `sudoers(5)` |
| login-policy | four families, four grammars | **2** | `login.defs(5)`, `pwquality.conf(5)`, `limits.conf(5)` |
| login-policy | absent ≠ refused | **2** | `SCOPE-022` + the frozen account contract |
| all | completeness and absence invariants | **2** | frozen project requirements |

**No `LEVEL_4` on any security-significant semantic.** One `LEVEL_3` — PAM cycle-versus-diamond
— which is a structural property of graph traversal rather than a claim about PAM's
documented behaviour, and is protected by tests and a mutation in both directions.

Per the ruling, no executable oracle was manufactured where none suitable exists. `sudo -l`
and `cvtsudoers` would mutate or require privilege; nothing was shelled out for a score.

## Rooted-path disposition

**`SHARED_ABSTRACTION_CANDIDATE`, `consumer_count = 2`. Not extracted.**

sudo and SSH agree field-by-field: input is an absolute filesystem path · production root
`/` is the identity · a fixture root rebases lexically · `realpath` forbidden · no symlink
resolution · live-host fallback impossible · provenance preserved.

PAM is **not** a third consumer. A PAM target is a service name joined to an
already-rooted directory; no absolute path ever appears. Same shape, different
abstraction. Two implementations that resemble each other are not yet a correctness risk.

## Shared-primitive reuse

| Domain | S1 | S2 | S3 | S4 | S5 | hostio |
|---|---|---|---|---|---|---|
| sudo | declined | ✓ | — | ✓ | ✓ | via S2 |
| login-policy | **✓** | — | — | ✓ | ✓ | ✓ |
| SSH | declined | ✓ | — | ✓ | — | via S2 |
| PAM | declined | declined | — | ✓ | ✓ | ✓ |

**Four declines, four different reasons**, each verified rather than repeated: sudoers has
no key; `limits.conf` is four positional fields; sshd accepts two delimiter forms that no
one profile expresses; PAM is positional with `=` legal in later fields. All
`REQUIRED_DOMAIN_GRAMMAR`. S3 has no consumer yet — it was built for declared-versus-active
comparison, which arrives with resolved state.

**S1–S5 are byte-unchanged since Batch 1.**

## Completeness reconciliation

| Scenario | sudo | ssh | pam | login-policy |
|---|---|---|---|---|
| primary source absent | `NOT_TESTED` | `NOT_TESTED` | `NOT_TESTED` | `NOT_TESTED` |
| minimal valid source | `COLLECTED` | `COLLECTED` | `COLLECTED` | `COLLECTED` |
| empty optional drop-in | `COLLECTED` | `COLLECTED` | `COLLECTED` | `COLLECTED` |
| named target missing | `PARTIAL` | `PARTIAL` | `PARTIAL` | n/a — no named targets |
| one malformed among good | `PARTIAL` | `PARTIAL` | `PARTIAL` | `PARTIAL` |
| source refused | `NOT_TESTED` | `NOT_TESTED` | `PARTIAL` | `PARTIAL` *(fixed)* |

No domain reports complete because useful partial evidence was retained, and an expected
empty optional source never becomes incomplete.

## Field lineage

66 new fields across four domains, **all classified**, none unclassified. No provenance
field bound to `STATE`. No field name carries a verdict word.

## Lane reconciliation

`lane/loginpolicy`, `lane/ssh`, `lane/pam`, `lane/redteam` — **all clean**. The pilot's
`lane/sudo` violation predates the control and stays in the historical record; no
unauthorized ownership remains in the integrated content.

## Falsification

**187 executed and detected · 0 declared skips · 0 unexpected non-firing.** By domain:
sudo 6 · login-policy 8 · SSH 6 · PAM 6 · accounts 17 · S1–S5 24 · architecture 9.

## ARCH-02 = PASS
