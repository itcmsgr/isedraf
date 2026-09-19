#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Prove the vector verifier REJECTS corrupted artifacts (finding Z-14).
# Implements: NORM-039, GOV-002
#
# Each case corrupts one artifact in a mirror of the corpus, REGENERATES EXPECTED.sha256 so
# the digest list cannot be what catches it, and runs the NORMAL verifier entry point. A
# verifier that passes here is certifying its own input.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3,mktemp"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
PASS=0; FAIL=0
C="01-valid-machine-id"

# corrupt <name> <relative path under the case> <python expression writing new bytes>
corrupt() {
    local name="$1" rel="$2" mutate="$3"
    local t; t="$(mktemp -d)"
    cp -r test-vectors "$t/tv"
    ( cd "$t" && python3 - "$rel" <<PY
import pathlib,sys
p = pathlib.Path("tv/w1a/v1/$C") / sys.argv[1]
$mutate
PY
      # Regenerate the digest list so EXPECTED.sha256 cannot be the thing that catches it.
      python3 - <<'PY'
import hashlib, pathlib
v = pathlib.Path("tv/w1a/v1")
lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(v)}"
         for f in sorted(v.rglob("*")) if f.is_file() and f.name != "EXPECTED.sha256"]
(v / "EXPECTED.sha256").write_text("\n".join(sorted(lines)) + "\n")
PY
    )
    sed "s|ROOT / \"test-vectors\"|pathlib.Path(\"$t/tv\")|" scripts/vectors/verify.py > "$t/v.py"
    if python3 "$t/v.py" >/dev/null 2>&1; then
        echo "  FAIL verifier ACCEPTED: $name" >&2; FAIL=$((FAIL+1))
    else
        echo "  OK   verifier rejected: $name"; PASS=$((PASS+1))
    fi
    rm -rf "$t"
}

echo "=== Z-14 negative tests: the verifier must reject corrupted artifacts ==="

corrupt "method.canonical wrong collector_id" "expected/method.canonical" \
  'p.write_bytes(b"{\"classification_table_version\":1,\"collector_id\":\"WRONG\",\"collector_version\":1,\"identity_scheme\":\"machine-id-sha256-v1\",\"parser_version\":1,\"source_id\":\"file:/etc/machine-id\"}\n")'

corrupt "method.canonical wrong identity_scheme" "expected/method.canonical" \
  'p.write_bytes(p.read_bytes().replace(b"machine-id-sha256-v1", b"machine-id-md5-v9"))'

corrupt "method.canonical wrong source_id" "expected/method.canonical" \
  'p.write_bytes(p.read_bytes().replace(b"file:/etc/machine-id", b"cmd:/bin/false"))'

corrupt "reason.txt fabricated for a COLLECTED case" "expected/reason.txt" \
  'p.write_bytes(b"TOTALLY_MADE_UP\n")'

corrupt "normalized-machine-id.bin corrupted" "expected/normalized-machine-id.bin" \
  'p.write_bytes(b"ffffffffffffffffffffffffffffffff")'

corrupt "manifest.json embeds a contradicting manifest_core" "expected/manifest.json" \
  'p.write_bytes(p.read_bytes().replace(b"\"engine_version\":\"0.0.0-pre\"", b"\"engine_version\":\"9.9.9\""))'

corrupt "status.txt disagrees with the manifest" "expected/status.txt" \
  'p.write_bytes(b"NOT_TESTED\n")'

# ---- Z-01: exactly one canonical byte representation per semantic value -------------
corrupt "reason.txt spelled 'null' (NORM-041)" "expected/reason.txt" \
  'p.write_bytes(b"null\n")'

corrupt "reason.txt spelled 'None' (NORM-041)" "expected/reason.txt" \
  'p.write_bytes(b"None\n")'

corrupt "reason.txt empty (NORM-041)" "expected/reason.txt" \
  'p.write_bytes(b"\n")'

corrupt "reason.txt present for a COLLECTED case (NORM-040)" "expected/reason.txt" \
  'p.write_bytes(b"SOURCE_ABSENT\n")'

corrupt "reason.txt missing its trailing LF (NORM-040)" "expected/reason.txt" \
  'p.write_bytes(b"SOURCE_ABSENT")'

# ---- Z-07: ledger chaining, exercised with a two-record chain ------------------------
chain() {
    local name="$1" mutate="$2"
    local t; t="$(mktemp -d)"
    cp -r test-vectors "$t/tv"
    ( cd "$t" && python3 - <<PY
import json, pathlib
e = pathlib.Path("tv/w1a/v1/$C/expected")
r1 = json.loads((e / "record.json").read_bytes())
core2 = dict(r1["record_core"])
core2["sequence"] = 2
core2["previous_record_hash"] = r1["record_hash"]
core2["event_id"] = "EVT-20260918T142244Z-1122334455667788"
$mutate
(e / "record.json").rename(e / "record-001.json")
(e / "record-002.json").write_text(json.dumps(
    {"record_core": core2, "record_hash": "sha256:" + "a" * 64},
    sort_keys=True, separators=(",", ":")) + "\n")
PY
      python3 - <<'PY'
import hashlib, pathlib
v = pathlib.Path("tv/w1a/v1")
lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(v)}"
         for f in sorted(v.rglob("*")) if f.is_file() and f.name != "EXPECTED.sha256"]
(v / "EXPECTED.sha256").write_text("\n".join(sorted(lines)) + "\n")
PY
    )
    sed "s|ROOT / \"test-vectors\"|pathlib.Path(\"$t/tv\")|" scripts/vectors/verify.py > "$t/v.py"
    if python3 "$t/v.py" >/dev/null 2>&1; then
        echo "  FAIL verifier ACCEPTED: $name" >&2; FAIL=$((FAIL+1))
    else
        echo "  OK   verifier rejected: $name"; PASS=$((PASS+1))
    fi
    rm -rf "$t"
}

chain "record 2 previous_record_hash breaks the chain (STORE-024)" \
  'core2["previous_record_hash"] = "sha256:" + "b" * 64'

chain "record 2 sequence is not predecessor + 1 (STORE-024)" \
  'core2["sequence"] = 7'

# --- Z-10: the domain-separation artifact must also be non-forgeable -------------------
# The falsifiability injection proves the PROPERTY is enforced when spec, generator and
# verifier all move together. These prove the ARTIFACT cannot be edited into agreement:
# domains.txt is checked against the requirement and against the domains the verifier
# frames with, so no rewrite of it alone can produce a pass.
d1() {
    local name="$1" mutate="$2"
    local t; t="$(mktemp -d)"
    cp -r test-vectors "$t/tv"
    ( cd "$t" && python3 - <<PYD
import hashlib, pathlib
p = pathlib.Path("tv/w1a/v1/D1-domain-separation/expected/domains.txt")
$mutate
v = pathlib.Path("tv/w1a/v1")
lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(v)}"
         for f in sorted(v.rglob("*")) if f.is_file() and f.name != "EXPECTED.sha256"]
(v / "EXPECTED.sha256").write_text("\n".join(sorted(lines)) + "\n")
PYD
    )
    sed "s|ROOT / \"test-vectors\"|pathlib.Path(\"$t/tv\")|" scripts/vectors/verify.py > "$t/v.py"
    if python3 "$t/v.py" >/dev/null 2>&1; then
        echo "  FAIL verifier ACCEPTED: $name" >&2; FAIL=$((FAIL+1))
    else
        echo "  OK   verifier rejected: $name"; PASS=$((PASS+1))
    fi
    rm -rf "$t"
}

d1 "domains.txt drops a domain NORM-038 freezes (Z-10)" \
  'p.write_text("".join(l + "\n" for l in p.read_text().splitlines()[1:]))'

d1 "domains.txt adds a domain NORM-038 does not freeze (Z-10)" \
  'p.write_text(p.read_text() + "ISEDRAF:INVENTED:V1\n")'

d1 "domains.txt made prefix-colliding (Z-10)" \
  'p.write_text(p.read_text().replace("ISEDRAF:STATE:V1", "ISEDRAF:HOST-ID"))'

d1 "domains.txt deleted entirely (Z-10)" \
  'p.unlink()'

# --- Z-08 / SNAP-023: host_id, with the WHOLE corpus kept self-consistent --------------
# The mutation rewrites manifest_core, recomputes manifest_hash, propagates it into the
# ledger record and recomputes record_hash, then regenerates EXPECTED.sha256. Nothing is
# left to catch it by checksum: the only thing that can fail is SNAP-023 itself.
hostid() {
    local name="$1" case="$2" mutate="$3"
    local t; t="$(mktemp -d)"
    cp -r test-vectors "$t/tv"
    ( cd "$t" && python3 - <<PYH
import hashlib, json, pathlib
e = pathlib.Path("tv/w1a/v1/$case/expected")

def ser(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8") + b"\n"

def frame(dom, c):
    return "sha256:" + hashlib.sha256(
        dom.encode("ascii") + len(c).to_bytes(8, "big") + c).hexdigest()

core = json.loads((e / "manifest-core.canonical").read_bytes())
$mutate
cc = ser(core)
mh = frame("ISEDRAF:SNAPSHOT-MANIFEST:V1", cc)
(e / "manifest-core.canonical").write_bytes(cc)
(e / "manifest-hash.txt").write_text(mh + "\n")
(e / "manifest.json").write_bytes(ser({"manifest_core": core, "manifest_hash": mh}))
rc = json.loads((e / "record-core.canonical").read_bytes())
rc["manifest_hash"] = mh
rcc = ser(rc)
rh = frame("ISEDRAF:LEDGER-RECORD:V1", rcc)
(e / "record-core.canonical").write_bytes(rcc)
(e / "record-hash.txt").write_text(rh + "\n")
(e / "record.json").write_bytes(ser({"record_core": rc, "record_hash": rh}))
v = pathlib.Path("tv/w1a/v1")
lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(v)}"
         for f in sorted(v.rglob("*")) if f.is_file() and f.name != "EXPECTED.sha256"]
(v / "EXPECTED.sha256").write_text("\n".join(sorted(lines)) + "\n")
PYH
    )
    sed "s|ROOT / \"test-vectors\"|pathlib.Path(\"$t/tv\")|" scripts/vectors/verify.py > "$t/v.py"
    if python3 "$t/v.py" >/dev/null 2>&1; then
        echo "  FAIL verifier ACCEPTED: $name" >&2; FAIL=$((FAIL+1))
    else
        echo "  OK   verifier rejected: $name"; PASS=$((PASS+1))
    fi
    rm -rf "$t"
}

hostid "COLLECTED with host_id null (SNAP-023)" "01-valid-machine-id" \
  'core["host_id"] = None'

hostid "COLLECTED with the host_id key absent (SNAP-023)" "01-valid-machine-id" \
  'del core["host_id"]'

hostid "COLLECTED with host_id empty string (SNAP-023)" "01-valid-machine-id" \
  'core["host_id"] = ""'

hostid "COLLECTED with a well-formed but wrong host_id (SNAP-023)" "01-valid-machine-id" \
  'core["host_id"] = "sha256:" + "c" * 64'

hostid "ERROR carrying a host_id string (SNAP-023)" "05-invalid-length" \
  'core["host_id"] = "sha256:" + "d" * 64'

hostid "NOT_TESTED carrying a host_id string (SNAP-023)" "04-missing-source" \
  'core["host_id"] = "sha256:" + "e" * 64'

echo "--- $PASS rejected, $FAIL wrongly accepted ---"
[ "$FAIL" -eq 0 ] || exit 1
