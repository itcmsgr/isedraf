#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Prove the artifact attestation can REFUSE a tampered artifact.
# Implements: GOV-002, D-86
#
# An attestation that has only ever been run against a good artifact proves nothing.
# "A gate that has never been observed to fail is not a gate." The whole value of a
# provenance attestation is the case it rejects, and that case had never been
# exercised - so this exercises it, on a COPY, by flipping exactly one byte.
#
# Three outcomes are distinguished, and only one of them is a pass:
#   ATTESTATION_REJECTED_TAMPERED  - genuine verification failure. The only pass.
#   ATTESTATION_ACCEPTED_TAMPERED  - the attestation is not binding. Hard fail.
#   HARNESS_ERROR                  - could not run the experiment. NOT a pass;
#                                    an unusable harness must never read as green.
#
# A verifier that fails for the wrong reason (no network, no gh, unauthenticated)
# would otherwise look exactly like a verifier that correctly refused the forgery.
# That is why the control first requires the UNMODIFIED artifact to VERIFY.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none (operates on a copy in a temporary directory)"
# meta:binaries="git,gh,mktemp,dd,cp"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2

ARTIFACT="${1:?usage: check_attestation_falsifiable.sh <artifact> <owner/repo>}"
REPO="${2:?usage: check_attestation_falsifiable.sh <artifact> <owner/repo>}"

outcome() { echo "  $1  $2"; }

[ -f "$ARTIFACT" ] || { outcome HARNESS_ERROR "no such artifact: $ARTIFACT"; exit 2; }
command -v gh >/dev/null 2>&1 || { outcome HARNESS_ERROR "gh not available"; exit 2; }

TMP="$(mktemp -d)" || { outcome HARNESS_ERROR "mktemp failed"; exit 2; }
trap 'rm -rf "$TMP"' EXIT

# --- Control 1: the genuine artifact MUST verify. -----------------------------
# Without this, a failure below cannot be attributed to the tampering.
if ! gh attestation verify "$ARTIFACT" --repo "$REPO" >"$TMP/good.log" 2>&1; then
    outcome HARNESS_ERROR "the UNMODIFIED artifact did not verify - the experiment"
    echo "                 cannot attribute a later failure to tampering. Verifier said:" >&2
    sed 's/^/                 /' "$TMP/good.log" >&2
    exit 2
fi
outcome OK "unmodified artifact verifies against $REPO"

# --- Control 2: one flipped byte MUST be refused. -----------------------------
TAMPERED="$TMP/$(basename "$ARTIFACT")"
cp -- "$ARTIFACT" "$TAMPERED" || { outcome HARNESS_ERROR "copy failed"; exit 2; }

# Flip a single bit in the middle of the file. Not a truncation, not an appended
# byte: the size is unchanged, so only the digest can reveal it.
OFFSET=$(( $(wc -c <"$TAMPERED") / 2 ))
ORIG=$(dd if="$TAMPERED" bs=1 skip="$OFFSET" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
printf "$(printf '\\x%02x' $(( ORIG ^ 0x01 )))" |
    dd of="$TAMPERED" bs=1 seek="$OFFSET" count=1 conv=notrunc 2>/dev/null ||
    { outcome HARNESS_ERROR "could not modify the copy"; exit 2; }

cmp -s -- "$ARTIFACT" "$TAMPERED" && { outcome HARNESS_ERROR "copy is byte-identical - nothing was tampered"; exit 2; }

if gh attestation verify "$TAMPERED" --repo "$REPO" >"$TMP/bad.log" 2>&1; then
    outcome ATTESTATION_ACCEPTED_TAMPERED "the attestation ACCEPTED an artifact with one flipped byte"
    sed 's/^/                 /' "$TMP/bad.log" >&2
    exit 1
fi
outcome ATTESTATION_REJECTED_TAMPERED "one flipped byte at offset $OFFSET was refused"
echo "  PASS  attestation is binding: it verifies the genuine artifact and refuses a forgery"
