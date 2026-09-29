<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# ARCH-01 — structural and evidence-flow review

Status: IMPLEMENTED
Implements: GOV-001, GOV-002, SCOPE-022, SCOPE-045

Reviewed branch `b56bd2a`, after Batch 1 and before any Batch 2 worker forks. The question
was not whether the five shared primitives are individually defensible — they passed their
own tests — but whether they compose into the architecture the project claims.

**They did not, on the first run.** The corrections are below.

## Blockers found and fixed

### 1. `shared` → `domain` dependency inversion

`shared/result.py` imported `isedraf.inventory.model` for four status constants, and
`shared/include_graph.py` imported `isedraf.inventory` for a file reader. Because
`inventory/__init__.py` does `from . import collectors`, **a generic include-graph
primitive transitively pulled in all nine inventory collectors.**

Nothing failed. Nothing would have failed until a Batch-2 worker asked why the SSH lane
depended on the storage collector — by which point four more domains would have inherited
the same edge.

Fixed by moving the concepts down rather than documenting the dependency as acceptable:

- `isedraf/status.py` — the SCOPE-022 vocabulary, defined once. `inventory/model.py`
  re-exports it, so no caller changed.
- `inventory/_exec.py` → `isedraf/hostio.py`. Reading a file and running a fixed argv are
  not inventory concepts; the module depends on nothing but the standard library, which is
  what makes it safe underneath everything. It is also now the single host-I/O boundary
  outside a domain, which is what makes the side-effect map meaningful.

Result: **0 layer inversions, 0 cycles**, across 30 modules.

### 2. Duplicated semantics

| Concept | Was | Now |
|---|---|---|
| "is this text undecodable" | three identical copies in `accounts/sources`, `shared/bounded`, `shared/keyvalue` | `isedraf/textbytes.py` |
| "a non-COLLECTED status requires a reason" | two copies, and a helper neither used | `status.requires_reason()`, called by both |

Three copies of a rule do not drift on the day they are written. They drift on the day one
of them is fixed.

### 3. Falsification blind spot

The coverage map showed **architecture: 0 injections** — a gate had been added and never
proven to fire. Five injections added; all fire.

## False positives, recorded so they are not rediscovered

- `accounts.sources` appeared to use `os.path.join`. It uses `"".join`. The instrument
  matches attribute names and cannot tell them apart.
- `realpath` appeared in `inventory/collectors.py`. It is in a comment explaining why
  `realpath` is *not* used.

Both are limitations of AST attribute matching, not defects. The gate checks semantics —
imports and call targets — rather than grepping for words.

## Reconciliations

**Status:** one vocabulary in `isedraf.status`, re-exported. `hostio.Outcome.detail`
refines rather than competes. `shared.compare` coverage is deliberately a *different*
vocabulary because it answers a different question, and maps onto collection status
explicitly. See `generated/05_status_semantics.md`.

**Path identity:** three distinct notions, kept distinct. Lexical provenance
(`normpath`, never `realpath` — resolving symlinks could consult a target outside a
fixture root); observed object identity (`lstat` only, never `stat`, plus `st_dev`/`st_ino`
for digest coherence); and symlink target *text*, recorded and never followed. No module
mixes them.

**Completeness policy:** S2 and S5 follow the same shape — the engine records a
deterministic event, the adapter or universe decides whether it invalidates completeness.
Both have tests proving a domain can reverse the default without touching shared code.
S3 applies the rule per direction.

**Determinism:** every input to canonical or report bytes is pinned — S1 grammar digest,
S2 expansion order, S3 comparator digest, S5 filename-byte ordering, surrogateescape
handling throughout. Locale is excluded by construction: S5 sorts on bytes, and a test
changes `LC_COLLATE` and asserts the order is unmoved.

**Fields:** 112 classified. No emitted field is unclassified, and `password_hash`,
`created_at`, `physical_medium`, `transport` and `is_aggregate` appear in no table.

**Legacy `collectors.py`:** isolated debt, not a bypass. It imports `..hostio` like
everything else, returns `model.subdomain()` with the shared vocabulary, and reaches no
shared primitive. It does not undermine status, path or determinism semantics. Left alone;
new domains use the package-per-domain structure.

## The authoritative outcome

`scripts/ci/check_architecture.py`, wired into `make check`, with a self-test proving it
detects four planted violations and five injections proving it fires in the harness:

```
no upward imports          no shared -> domain inversion
no I/O in pure modules     no network path anywhere in lib/isedraf
no renderer acquisition    one status vocabulary
```

The generated diagrams under `generated/` describe. This gate decides.

## ARCH-01 = PASS
