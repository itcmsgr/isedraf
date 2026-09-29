<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Inventory coverage matrix — R1.5

Status: PLANNING
Implements: SCOPE-022, SCOPE-045, GOV-001

What ISEDRAF collects today, what it could collect from local evidence, and what may not be
built without an owner amendment. Produced before implementation so the expensive Linux
acquisition work happens once, feeds every later consumer, and is not discovered to be
out of scope after it is written.

## 0. Scope — owner ruling, 2026-09-20

The R1.5 expansion originally collided with two governance texts: `CLAUDE.md` §2 listed
"assessing firewalls" and "patch availability" among the hard stops, and §7 deferred
services, timers/cron, listeners, kernel/platform expansion, MAC assessment, software and
hardware inventory. §7 was also already stale — it deferred *hardware inventory* while
`isedraf inventory` shipped `compute`, `memory`, `storage` and `machine`.

The owner has ruled (`IQ-013`). **Exact text for `AMENDMENTS.md`, which only the owner
writes:**

> R1.5 inventory expansion is authorized for local services, kernel/platform security facts,
> Linux Security Module state, installed software and packages, local listeners, local
> packet-filter state, and update-state observations. These domains are observational. They
> do not authorize configuration changes, network enforcement, vulnerability scanning,
> firewall effectiveness certification, or automatic patching. Normal collection remains
> network-independent. Any future network-dependent enrichment requires explicit operator
> authorization and must remain distinguishable from locally observed host state.

PAM and login/password policy are `IN SCOPE` as fundamental local authentication evidence.
§7's "hardware inventory" deferral is superseded by the same amendment.

### The firewall boundary

The old prohibition conflated two different things. Observing that a host has a packet-filter
ruleset is host assurance evidence. Judging whether that ruleset protects anything is not
something local state can support — NAT, routing, cloud security groups, upstream appliances,
namespaces and containers all sit between a chain policy and reachability.

| In scope | Out of scope |
|---|---|
| backend detected — nftables, iptables, firewalld, ufw, unknown | adding, deleting or reloading rules |
| service enabled / active state | enabling or disabling the firewall |
| tables, chains, hooks, priorities, chain policies, rule counts, address families | deciding network policy |
| normalized ruleset digest, and its change over time | "firewall insecure", "host exposed", "port 22 protected" |

Baseline/delta may legitimately report *input policy changed from drop to accept*. It may not
report *the host became exposed*.

A later **local correlation** — a listener exists, and the local ruleset contains a matching
accept rule — is evidence and may be stated as such. External exposure is a different
question and is not answered here.

### The update boundary — offline first

Three facts are routinely collapsed into one and must not be:

```
INSTALLED STATE      what is installed right now          local, always available
REPOSITORY/CACHE     what metadata this machine holds     local, may be absent or old
REMOTE CURRENT       what upstream offers right now       needs network
```

Only the third needs the network, and ISEDRAF must stay useful on air-gapped, DMZ,
egress-restricted, proxied and temporarily disconnected hosts. **Ordinary `collect` and
`report` make zero network requests**, and repositories are never refreshed during ordinary
collection — `apt update` and `dnf makecache` write cache state, so they are not
observational and cannot live inside a collector.

Update observations therefore carry an explicit **freshness** label rather than a bare
number:

| `metadata_source` | `LOCAL_CACHE` · `NETWORK_REFRESH` |
| `metadata_timestamp` | when the local metadata was produced |
| `metadata_age_seconds` | `DERIVED` fact — **not** a judgement |
| `freshness` | `CURRENT_BY_EXPLICIT_REFRESH` · `CACHED` · `UNKNOWN` |

No global definition of "stale". The age is the fact; whether 24 hours or 7 days is too old
is a criterion with a configurable threshold, later. Absent metadata is `NOT_TESTED` with a
reason — never `FAIL`, and never a fabricated zero.

The wording discipline matters as much as the data: the report says *"12 updates are known
from the locally available repository metadata"*, never *"12 updates are currently
available"*, unless freshness supports that claim.

### A new invariant this produced

> **External-world changes must not masquerade as host-state changes.**

`openssl` being upgraded on the host is a host state change. A newer `openssl` appearing
upstream is not — the machine has not changed at all. Classifying available-update
information as `STATE` would make every upstream publication a security delta on every
monitored host, which would destroy baseline/delta the same way a `queue_rotational` guess
would have destroyed storage evidence. Installed versions and repository configuration are
`STATE`; known-available updates and metadata freshness are `OBSERVATION` and `DERIVED`.

## 1. What exists today

| Module | Fields classified | Sources |
|---|---|---|
| `inventory/` — host, platform, machine, compute, memory, storage, network, dns, time | 40 | `/etc/os-release`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/localtime`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/self/mounts`, `/proc/uptime`, `/proc/1/comm`, `/proc/sys/kernel/hostname`, `/sys/block`, `/sys/class/dmi/id`, `/sys/hypervisor/type`, `ip`, `timedatectl`, `chronyc`, `systemd-detect-virt` |
| `accounts/` — local account files | 38 | `/etc/passwd`, `/etc/group`, `/etc/shadow` |
| `identity.py` — host identity | 1 (`host_id`) | `/etc/machine-id` |

**Overlap audit: none.** Only `accounts/` reads `passwd`/`group`/`shadow`; only `identity.py`
reads `machine-id`; only `inventory/collectors.py` reads the rest. No fact is collected twice.
The one shared read path is `_exec.read_file`, which is the intended shape.

## 2. The matrix

Status vocabulary: `IMPLEMENTED` · `PARTIAL` · `CONTRACT_READY` (design settled, not written)
· `NEEDS_DECISION`. After the owner ruling in §0 nothing remains `DEFERRED` or `BLOCKED`.

Priv = privilege required. Vol = volatility. Priv-cy = privacy sensitivity.
Base = baseline/delta eligible.

| # | Domain | Primary sources | Status | Priv | Vol | Priv-cy | Base |
|---|---|---|---|---|---|---|---|
| A | local accounts / groups | passwd, group, shadow | **IMPLEMENTED** (contract `PLANNING`) | shadow needs root | low | med (GECOS, names) | yes, `gecos` excluded |
| B | sudo / privilege source | sudoers, sudoers.d | `CONTRACT_READY` | root | low | high (rule bodies) | yes |
| C | SSH server | sshd_config, Include, Match | `CONTRACT_READY` | partial | low | low | yes, declared+resolved |
| D | authorized_keys | per-account paths, `AuthorizedKeysFile` | `NEEDS_DECISION` | other users need root | low | **high** — fingerprints only | fingerprints only |
| E | PAM stack | `/etc/pam.d/*` | `CONTRACT_READY` — **IN SCOPE**, owner ruling | no | low | low | yes |
| F | login / password policy | login.defs, pwquality*, faillock, limits* | `CONTRACT_READY` — **IN SCOPE**, owner ruling | no | low | low | yes |
| G | services | systemd units | `CONTRACT_READY` — **ADMITTED** | no | med | low | declared yes, active no |
| H | timers / cron | timers, crontab, cron.d | `CONTRACT_READY` — **ADMITTED** | user crontabs need root | med | med (command lines) | declared yes |
| I | listeners / processes | `/proc/net/*`, `ss` | `CONTRACT_READY` — **ADMITTED**, no reachability claim | PID/exe needs root | **high** | med | no — `VOLATILE_OBSERVATION` |
| J | mounts / filesystems | fstab, `/proc/self/mounts` | **PARTIAL** — active only, fstab missing | no | low | low | yes |
| K | block topology | `/sys/block/*/{holders,slaves,partition}` | `NEEDS_DECISION` — must not widen D-114 silently | no | low | low | yes |
| L | kernel / boot / sysctl | cmdline, `/proc/sys`, modules, lockdown, taint | `CONTRACT_READY` — **ADMITTED** | some need root | mixed | low | configured yes, runtime split |
| M | MAC / LSM | `/sys/kernel/security/lsm`, SELinux, AppArmor | `CONTRACT_READY` — **ADMITTED** as facts; no compliance verdict | no | low | low | yes |
| N | audit policy analysis | rules.d, audit.rules, `auditctl -l/-s` | `CONTRACT_READY` — **expanded, see §2a** | root | low | med | declared yes |
| O | journal / logging | journald.conf, rsyslog | `CONTRACT_READY` — journal persistence in scope | no | low | med (remote targets) | yes |
| P | time | timedatectl, chrony, timesyncd | **PARTIAL** — sync quality in scope, peers missing | no | high | low | config yes, offset no |
| Q | network | `ip`, sysctls, bridges, bonds, VLANs | **PARTIAL** — addresses/routes done | some | mixed | **high** (addresses) | stable only |
| R | DNS / NSS resolution | resolv.conf, resolved, nsswitch | **PARTIAL** — nsswitch missing | no | low | med | yes |
| S | local packet filter | nft, iptables, firewalld, ufw | `CONTRACT_READY` — **ADMITTED as observed state**; no management, no reachability claim | root | low | med | — |
| T | packages | dpkg, rpm | `CONTRACT_READY` — **ADMITTED** | no | low | low | yes, bounded |
| U | update observation | local cache, reboot-required | `CONTRACT_READY` — **ADMITTED, offline-first**; freshness-labelled | no | med | low | — |
| V | repositories / trust | sources.list, deb822, yum repos | `CONTRACT_READY` — **ADMITTED**, credentials redacted | no | low | **high** — credentials in URLs | yes, redacted |
| W | crypto host facts | crypto-policies, FIPS indicators | `NEEDS_DECISION` | no | low | low | yes |
| X | certificates | explicitly configured paths only | `NEEDS_DECISION` — no filesystem crawl | mixed | low | med | yes |
| Y | targeted file metadata | the config files above | `CONTRACT_READY` — shared contract | mixed | low | low | yes |
| Z | containers / virtualization | detect-virt, runtime presence | **PARTIAL** — virt done, runtimes missing | no | low | low | yes |
| AA | hardware / firmware | DMI, board, BIOS | **PARTIAL** — expansion **ADMITTED** | no | low | med (serials forbidden) | yes |
| AB | hostname / NSS config | hostname, hosts, nsswitch | **PARTIAL** — nsswitch missing | no | low | med | yes |
| AC | file capabilities | bounded roots only | `NEEDS_DECISION` — defer unless bounded | root | low | low | yes |
| AD | setuid / setgid | package DB derived | `NEEDS_DECISION` — defer unless bounded | root | low | low | yes |
| AE | system limits | limits.conf, limits.d | `NEEDS_DECISION` | no | low | low | yes |
| AF | persistence surfaces | services, timers, cron | `CONTRACT_READY` — **ADMITTED** | mixed | med | med | — |
| AG | unix sockets | `/proc/net/unix` | `CONTRACT_READY` — **ADMITTED** | no | high | low | no |
| AH | per-collector limitations | every collector | **IMPLEMENTED** | — | — | — | `PROVENANCE` |

## 2a. Audit policy analysis — the richest domain, specified before it is written

Raw `auditctl -l` is evidence an auditor cannot read. Turning it into a precise, readable
policy description is exactly the value ISEDRAF should add, and it can be delivered before
any criterion exists.

```
/etc/audit/rules.d/*.rules   ->  declared source policy      (fragments, augenrules input)
/etc/audit/audit.rules       ->  generated/loaded artifact   (augenrules output)
auditctl -l                  ->  actual active kernel policy
auditctl -s                  ->  runtime status
```

**These three layers are recorded independently and never assumed identical.** `augenrules`
transforms the fragments into the aggregate, and the kernel holds whatever was last loaded.
A mismatch can arise at either step, and recording all three is what lets the report say
*where* it arose rather than merely that it exists.

| | Sub-domain | Delivers |
|---|---|---|
| A1 | subsystem status | enabled, failure mode, backlog limit, lost events, immutable flag |
| A2 | persistent rule acquisition | fragments + aggregate, with per-file provenance |
| A3 | active rule acquisition | kernel policy |
| A4 | normalized rule parser | the grammar, not strings |
| A5 | declared ↔ active comparator | `DECLARED_AND_ACTIVE` · `DECLARED_ONLY` · `ACTIVE_ONLY` · `NOT_COMPARABLE` |
| A6 | deterministic explanation | `explain.py` — a renderer, not a model |
| A7 | report view | the auditor-readable section |
| A8 | baseline/delta compatibility | ordering-aware digest |
| A9 | native `ISE-AUDIT` criteria | **later**, R2 |

**A1–A7 exist before any criterion.** That is what makes this worth doing early.

### The normalized grammar

Rules are represented, not stringified. Syscall rules carry `rule_kind`, `action`,
`filter_list`, `architecture`, `syscalls[]`, `fields[]` with their comparison operators,
`permissions[]` and `key`. Watch rules carry `rule_kind: WATCH`, `path`, `permissions`,
`key`. Control rules carry backlog, failure mode, rate limit and immutable state.

**Unknown constructs are never silently skipped.** An unrecognized rule yields `PARTIAL`
with `unsupported_construct`, a `raw_rule_digest` and its source location, and everything
safely parsed is retained. This is the account contract's malformed-record rule applied to a
different grammar.

### Ordering is part of the policy — a contract, not an implementation detail

> **Canonical representation preserves source and runtime rule order, and the semantic digest
> accounts for ordering. An unordered grouping may be produced for reporting, and may never
> be used to prove policy equivalence.**

Audit rule order is semantically load-bearing, particularly around `never` / exclude rules
and filter lists: the same set of rules in a different order is a different policy. Sorting
them alphabetically and comparing sets would produce a confident, wrong equivalence claim —
the same class of error as calling `queue_rotational=false` an SSD, except here it would
report a policy as unchanged when its meaning had inverted.

### Provenance per normalized rule

Every rule carries where it came from, so *"why are you telling me this rule is missing?"*
has an answer:

```json
{"source_kind": "PERSISTENT_RULE_FILE",
 "source_path": "/etc/audit/rules.d/50-identity.rules",
 "source_line": 12, "ordinal": 17}

{"source_kind": "ACTIVE_KERNEL_POLICY", "ordinal": 21}
```

### Deterministic explanation, and its limits

`explain.py` is a renderer with no model of its own. It says what a rule *does*, with
semantic exactness:

```
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged-exec

Rule type:   syscall          Action: always      Filter: exit
Architecture: b64             Syscall: execve     Condition: effective UID = 0
Key: privileged-exec

Meaning: records execve audit events for 64-bit syscalls where the effective
         UID is 0, evaluated at syscall exit.
```

**`always,exit` means evaluated at syscall exit, not "successful".** Success requires an
explicit `success=` filter. An explainer that wrote "successful execve" would be wrong, and
that precision is the reason this is a parser rather than string prettification.

Structural observations it may make, all evidence-derived: duplicate normalized rule ·
overlapping path watches · one key used by N rules · rule without a key · a `b64` rule whose
`b32` counterpart is absent · declared not active · active not declared · unsupported syntax
encountered · subsystem immutable · subsystem disabled · lost-event counter non-zero.

Phrasing it may **not** use: *coverage is sufficient* · *policy is secure* · *complies with
any framework* · *all privilege escalation is audited*. Where purpose is inferred it is
labelled **"likely observable purpose"**, never "satisfies control X".

### Extraction, later and deliberately

The parser imports no report code, no criteria, no framework vocabulary and no baseline
policy: `input -> normalized audit model`, nothing else. That is not speculative
generality — it is what makes a later extraction to a standalone
`linux-audit-policy-parser` a move rather than a rewrite. **No separate repository now**: a
second repo today buys a second release process, security policy, test matrix, packaging
story, API compatibility contract and documentation surface, for an API whose stability is
unproven. The question is asked again after real hosts and weird rules have exercised it.

## 3. Shared contracts that must be serialized before any fork

Five parsers would otherwise be written three times each, in three worktrees, with three
different answers. Each is a contract lane of its own, and each blocks the batches beneath it.

**S1 — key/value configuration parser.** `login.defs`, `pwquality.conf`, `faillock.conf`,
`limits.conf`, `journald.conf`, `resolved.conf`, `timesyncd.conf`, `crypto-policies` are all
"key value" with *different* comment markers, continuation rules, whitespace handling and
last-wins-versus-first-wins semantics. One parser with declared per-format options. Blocks
F, O, P, W, AE.

**S2 — include-graph resolution.** `sshd_config Include`, `sudoers #include/#includedir`,
PAM `include`/`substack`, `limits.d`, `pwquality.conf.d`, `sources.list.d`, `cron.d`. The
syntaxes differ; the *shape* is identical — a directive pulls in more files, with ordering,
globbing, depth limits and cycle risk. The failure modes are identical too, and they are
security-relevant: a missed include is a missed rule. One contract for the graph, its
ordering and its failure semantics. Blocks B, C, E, F, V.

**S3 — declared versus active.** `fstab` vs `/proc/self/mounts`; `sysctl.conf` vs
`/proc/sys`; audit rules on disk vs `auditctl -l`; unit files vs `systemctl show`. The state
dimension vocabulary already exists (`DECLARED`/`RESOLVED`/`ACTIVE`/`NOT_APPLICABLE`), but
nothing yet defines how a **mismatch** is represented or when one may be asserted. The
absence invariant from the account contract applies directly: a mismatch claim needs complete
evidence on both sides. Blocks J, L, N, Q.

**S4 — targeted file metadata.** Path, existence, type, owner, mode, size, optional digest —
needed by A, B, C, E, F, N, O, V and Y. Written once or eight times.

**S5 — bounded enumeration.** Packages, listeners, processes and certificates can each be
thousands of rows. Deterministic ordering, a bound, what the machine-readable evidence
contains versus what the human report shows, and what happens at the bound. Without this,
the first large host produces an unreadable report and a non-reproducible digest. Blocks
I, T, V, X.

## 4. Batch and worktree allocation

**The canonical execution sequence lives in
[`../roadmap/ROADMAP.md`](../roadmap/ROADMAP.md), not here.** This table is the domain
coverage detail — which domains sit in which batch, and what each depends on — and it
cites those milestones rather than defining them.

Until DOC-R15P, it was the other way round: the roadmap did not mention R1.5 at all and
this table was the only place the real order existed. Two documents defining execution
order independently is how they drift, and the first reader to notice would have had no
way to tell which was authority.

A row says `COMPLETE` only when a merged or frozen SHA proves it.

| Batch | Contents | Depends on | State |
|---|---|---|---|
| **0** | account contract; `IQ-012` closed by amending the requirement | — | **COMPLETE** `723459ad` frozen, `9db3de42` merged |
| **1** | S1 key/value · S2 include graph · S3 declared/active · S4 file metadata · S5 bounded enumeration — **one serialized lane, no forks** | — | **COMPLETE** |
| **ARCH-01** | structural and evidence-flow review | Batch 1 | **COMPLETE** |
| **2** | B sudo · C SSH · E PAM · F login policy | S1, S2, S4 | **COMPLETE** `ace82d58` frozen, `3235e7d1` merged |
| **ARCH-02** | architecture review with the semantic oracle matrix | Batch 2 | **COMPLETE** |
| **bridge** | D `authorized_keys`; moved out of Batch 2 because it consumes the frozen account contract and SSH declarations rather than standing beside them | Batch 0, Batch 2, `hostpath` | **COMPLETE** `79f885f7` frozen |
| **R1.5-P** | privilege and evidence acquisition contract. Authority `D-115`; contract in [`R15P_PRIVILEGE_AND_EVIDENCE_CONTRACT.md`](R15P_PRIVILEGE_AND_EVIDENCE_CONTRACT.md) | bridge | **COMPLETE** `f256c9ce` frozen |
| **DOC-R15P** | repository-wide documentation reconciliation against the frozen architecture. **REQUIRED.** Originally a precondition for Batch 3; the owner re-sequenced it on 2026-09-23 to run in parallel with Batch 3 | R1.5-P freeze | **ACTIVE** |
| **3** | J fstab / mounts declared-vs-active · R nsswitch · AB — S3's first natural consumer | S3 | **ACTIVE** — mounts lane merged `ded73ec` (182 tests), awaiting owner closure, not yet reachable from any command; nsswitch not started |
| **4** | **N audit policy analysis** · O journald / logging · P time | S1, S3, S4 | `PLANNED` |
| **5** | G services · H timers/cron · L kernel · M LSM · I listeners | S1, S3, S5 | `PLANNED` — **governance-dependent**, see below |
| **6** | T packages · V repositories · U offline update observation · W crypto policy | S1, S5 | `PLANNED` — **governance-dependent**, see below |
| **7** | Q network · R DNS · S local packet-filter state | S3, S5 | `PLANNED` — **governance-dependent**, see below |
| **8** | X certificates · Y targeted files · AC/AD capabilities and setuid, if boundable | S4, S5 | `PLANNED` |
| **ARCH-03** | after Batches 3-4. **Carries one mandatory question:** which collection-root-sensitive paths have only fixture-root coverage? `authorizedkeys` read nothing at the production root while 191 tests passed, because no fixture root can be `/` | Batch 4 | `PLANNED` |
| **ARCH-04** | at full R1.5 completion, before any `ISE-*` criterion | Batch 8 | `PLANNED` |

**Governance dependency for Batches 5-7.** The `IQ-013` owner ruling admits services,
kernel, LSM, listeners, packages, repositories, offline update observations, crypto,
network, DNS and local packet-filter facts into R1.5. The exact amendment text is prepared
in §0 of this document, and `AMENDMENTS.md` is owner-controlled. Until the owner records it
there, those batches have a ruling and not an amendment, and a worker opening one would be
acting on a draft. `PLANNED` in the table above is not authorization.

### ARCH-01 — structural and evidence-flow review, MANDATORY between batch 1 and batch 2

Batch 1 is not frozen and no batch-2 worker forks until this passes. The timing is the
point: before batch 1 completes the shared architecture is still moving, and after batch 2
starts, SSH, sudo, PAM and the rest multiply the consumers of every primitive. Coupling, a
cycle, hidden I/O, duplicated acquisition or a wrong status path found here costs one fix;
found after the fan-out it costs five.

ARCH-01 inspects **the repository**, not the documentation, and prefers AST, registries and
configuration over anything hand-maintained. Ten artifacts: module/import dependency graph ·
critical call trees · evidence-flow graph · collection-status state flow · S1–S5
consumer graph · source→field lineage matrix · filesystem/subprocess/network/clock
side-effect map · trust-boundary graph · CI/gate dependency graph · falsification coverage
by subsystem.

Call trees are **bounded and rooted in security-critical entry points** — `collect`,
`report`, `verify`, identity→snapshot→manifest→ledger, account acquisition, and each of
S1–S5. One enormous whole-project graph is useless on the day it is produced.

The diagrams describe. **The architecture assertions are what is authoritative**, because a
diagram cannot fail a build:

```
pure parser        -> no network, no subprocess, no live-host fallback
renderer           -> no acquisition
shared primitive   -> no domain dependency
framework layer    -> no influence over collectors
fixture root       -> no live-host escape
ordinary collect   -> no network
```

That last one is the reason this matters commercially: *ordinary collection makes zero
network requests* should be machine-checked, not asserted in prose.

If ARCH-01 exposes a cycle, duplicated acquisition, a hidden side effect or domain coupling,
batch 2 does not start. Later reviews are deltas — ARCH-02 after batch 2, ARCH-03 after
batches 3–4, ARCH-04 as the full review at R1.5 before any native criterion — plus an
`ARCH-DELTA` before each release answering what edges, network paths, subprocesses,
filesystem mutations or unclassified fields appeared since the last one.

Online update enrichment is **outside R1.5**. Offline update observation is built and proven
first; the network-enabled path is designed explicitly afterwards, as a separate operation
that records that the network was used.

**Batch 1 is the only lane that must not be parallelized.** Every batch-2 domain consumes
S1, S2 and S4, so forking before they are frozen produces exactly the
three-parsers-for-one-fact outcome this matrix exists to prevent. From batch 2 onward the
worktrees are genuinely independent — one per domain, each owning
`lib/isedraf/<domain>/` and `tests/test_<domain>.py`, plus the adversarial-fixture worker,
with the coordinator holding the shared contracts and the merge order.

Batch 0 was **blocked on `IQ-012`** and did not block batch 1, so batch 1 started while the
`CONFUSABLE` ruling was outstanding. `IQ-012` has since been closed and Batch 0 is COMPLETE.

## 5. Module layout

One directory per evidence source, each with the same three files, as `accounts/` already
demonstrates:

```
lib/isedraf/<domain>/
    model.py      vocabulary, SCOPE-045 classification, stated limitations
    sources.py    pure parsers: text in, records out, no I/O, no policy
    acquire.py    filesystem access, SCOPE-022 status, joins
```

`inventory/collectors.py` is ~500 lines covering nine subdomains and is already at the limit
of what one file should hold. Adding twenty domains to it would make every worktree collide
on the same file, which is the practical argument for the split as much as the readability
one.

## 6. Field admission rule

The seven questions are answered per field before it is added, and a field that cannot answer
them is not added:

exact Linux source · `SCOPE-045` category · baseline stability · privacy sensitivity ·
whether absence is provable · whether the claim needs complete source coverage · declared or
active.

## 7. What is not built, in any batch

Guessed account creation dates · guessed SSD/HDD · guessed transport · guessed
human/service classification · guessed sudo privilege · CVE or vulnerability scanning ·
malware classification · EDR behaviour · network IDS · remote attestation · framework
compliance conclusions · automatic remediation · remote discovery · cloud inventory ·
recursive whole-filesystem crawling.

And, from the §0 boundaries specifically: firewall rule management or reload · any claim
that a host is protected, exposed or reachable · repository refresh during ordinary
collection · any pending-update count presented without its freshness label · treating an
upstream package publication as a host state change.
