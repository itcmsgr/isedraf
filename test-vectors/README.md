<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Test vectors — check our hashes without running our code

Status: IMPLEMENTED
Implements: NORM-039, GOV-002

This is roughly half the files in the repository, and it is here on purpose.

ISEDRAF's central claim is that its evidence can be verified **independently of the tool that
produced it**. A claim like that is worth nothing if the only way to check it is to run the tool and
believe what it prints. So the inputs and the expected outputs are published as bytes.

## What a case contains

```text
test-vectors/w1a/v1/01-valid-machine-id/
    input/                 the exact bytes fed in
    expected/
        host-id.txt        sha256:… the derived host identifier
        state.sha256       sha256:… the canonical state hash
        manifest-hash.txt  sha256:… the snapshot manifest hash
        state.canonical    the canonical serialization, byte for byte
        status.txt         COLLECTED / ERROR / NOT_TESTED
        reason.txt         present only when the status requires one
```

Sixteen cases: valid input, trailing newline handling, case normalization, a missing source, an
invalid length, non-hex input, the all-zero identity, and the boundary conditions the frozen
requirements name.

## Checking them yourself

```sh
python3 scripts/vectors/verify.py
```

The verifier re-derives every hash from the stored preimages. It does not import the collector, and
it does not ask ISEDRAF whether ISEDRAF is right. You can also do it by hand — the hash construction
is specified in `docs/architecture/EVIDENCE_AND_TRUST_MODEL.md`, and the canonical bytes are sitting
in the files.

`EXPECTED.sha256` is part of the frozen set in `docs/architecture/freeze/W1A_CORE_PUBLIC.sha256`, so
the vectors cannot be quietly adjusted to match a change in behaviour.

## Why this matters more than it looks

These same bytes were produced identically by CPython 3.6.8 through 3.14.4 across eleven Linux
distributions. That is the property the whole evidence model rests on: if canonical bytes drift
between interpreters or distributions, then two snapshots of an unchanged host can differ, and every
"change detected" becomes untrustworthy.

The corpus is also what the defect injections attack. `make check-falsifiable` mutates one byte of a
vector, deletes the corpus entirely, and replaces the canonical serializer with a naive one — and
requires the gates to fail each time.
