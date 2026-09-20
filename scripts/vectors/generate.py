# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Generator A — produce the W1-A golden-vector corpus from the frozen requirements.
# Implements: NORM-034, NORM-035, NORM-038, NORM-039, IDENT-002, IDENT-003, IDENT-004,
#             IDENT-005, IDENT-006, NORM-031, SNAP-020, SNAP-021, SNAP-022, STORE-024
#
# This tests the specification; it does NOT become the specification. Where the frozen text
# permits two behaviours the correct action is to STOP and report a blocking ambiguity, not
# to pick whichever is convenient.
#
# meta:type="generator"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Generator A. Every volatile input is fixed by the fixture: no clock, no RNG, no hostname,
no environment, no filesystem metadata."""
import hashlib
import json
import pathlib
import subprocess
import sys

# Resolve the repo root from git, not from this file's location: a mutation harness copies
# this script elsewhere, and parents[2] then resolves to "/" (found during the Z-02 lane).
ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
)
OUT = ROOT / "test-vectors" / "w1a" / "v1"

# ---- NORM-035: the escape alphabet, written out rather than delegated -------------------
_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def _esc(s):
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif cp in _SHORT:
            out.append(_SHORT[cp])
        elif cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            out.append("\\u%04x" % cp)
        elif cp in (0x2028, 0x2029):
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _ser(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if not (-(2**63) <= v <= 2**63 - 1):
            raise ValueError("INTEGER_OUT_OF_RANGE")
        return str(v)
    if isinstance(v, str):
        return _esc(v)
    if isinstance(v, list):
        return "[" + ",".join(_ser(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v)                      # NORM-035: sorted by Unicode code point
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate key")
        return "{" + ",".join(_esc(k) + ":" + _ser(v[k]) for k in keys) + "}"
    raise TypeError(f"type not permitted in canonical state: {type(v).__name__}")


def canonical_bytes(v):
    """NORM-035: UTF-8, no BOM, exactly one trailing LF, which IS hashed."""
    return _ser(v).encode("utf-8") + b"\n"


def frame(domain, *components):
    """NORM-038: ASCII(domain) || uint64_be(len) || bytes, per component."""
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    for c in components:
        h.update(len(c).to_bytes(8, "big"))
        h.update(c)
    return h.digest()


def rendered(d):
    return "sha256:" + d.hex()


# ---- IDENT-003: the one frozen parser --------------------------------------------------
HEX = set("0123456789abcdefABCDEF")


def parse_machine_id(raw):
    """Returns (normalized_str, None) or (None, reason). IDENT-003 / IDENT-004."""
    if raw is None:
        return None, "SOURCE_ABSENT"
    if len(raw) > 4096:
        return None, "SOURCE_UNREADABLE"
    body = raw[:-1] if raw.endswith(b"\n") else raw
    if b"\n" in body or b"\r" in body:
        return None, "SYNTAX_REJECTED"
    try:
        t = body.decode("ascii")
    except UnicodeDecodeError:
        return None, "SYNTAX_REJECTED"
    if len(t) != 32 or any(c not in HEX for c in t):
        return None, "SYNTAX_REJECTED"
    t = t.lower()                              # IDENT-003 / Y-14
    if t == "0" * 32 or t == "uninitialized":
        return None, "SYNTAX_REJECTED"
    return t, None


def build(fx, raw):
    norm, reason = parse_machine_id(raw)
    status = "COLLECTED" if norm else (
        "NOT_TESTED" if reason == "SOURCE_ABSENT" else "ERROR")

    art = {"normalized": norm, "reason": reason, "status": status}
    if norm:
        host_id = rendered(frame("ISEDRAF:HOST-ID:V1", norm.encode("utf-8")))
        state = {"host_id": host_id}                       # IDENT-002: nothing else
        state_c = canonical_bytes(state)
        state_hash = rendered(frame("ISEDRAF:STATE:V1", state_c))
        art.update(host_id=host_id, state=state, state_canonical=state_c,
                   state_hash=state_hash)
    else:
        host_id, state_hash = None, None                   # SNAP-022

    method = {"classification_table_version": 1, "collector_id": "host_identity",
              "collector_version": 1, "identity_scheme": "machine-id-sha256-v1",
              "parser_version": 1, "source_id": "file:/etc/machine-id"}
    art["method"], art["method_canonical"] = method, canonical_bytes(method)

    core = {
        "schema_version": 1, "host_id": host_id, "snapshot_id": fx["snapshot_id"],
        "run_id": fx["run_id"], "created_at": fx["created_at"],
        "state_root": fx["state_root"], "engine_version": fx["engine_version"],
        "sections": {"host_identity": {
            "collection_status": status, "state_hash": state_hash, "reason": reason,
            "collector_id": "host_identity", "collector_version": 1,
            "parser_version": 1, "classification_table_version": 1,
            "source_id": "file:/etc/machine-id"}},
    }
    core_c = canonical_bytes(core)
    mh = rendered(frame("ISEDRAF:SNAPSHOT-MANIFEST:V1", core_c))
    art.update(manifest_core=core, manifest_core_canonical=core_c, manifest_hash=mh,
               manifest=canonical_bytes({"manifest_core": core, "manifest_hash": mh}))

    rc = {"ledger_schema_version": 1, "sequence": 1, "event": "snapshot_committed",
          "event_id": fx["event_id"], "occurred_at": fx["occurred_at"],
          "previous_record_hash": "sha256:" + "0" * 64,
          "snapshot_id": fx["snapshot_id"], "manifest_hash": mh,
          "state_root": fx["state_root"]}
    rc_c = canonical_bytes(rc)
    rh = rendered(frame("ISEDRAF:LEDGER-RECORD:V1", rc_c))
    art.update(record_core=rc, record_core_canonical=rc_c, record_hash=rh,
               record=canonical_bytes({"record_core": rc, "record_hash": rh}))
    return art


CASES = {
    # Z-06: the all-zero / uninitialized identity rejection (IDENT-003).
    "10-all-zero":                  b"0" * 32 + b"\n",
    "11-uninitialized":             b"uninitialized\n",
    # Z-03: over-long read -> SOURCE_UNREADABLE (IDENT-004 row 2), distinct from a
    # syntactically bad but readable file, which is row 3.
    "12-over-long":                 b"7f8e9a0b1c2d3e4f5061728394a5b6c7" + b"\n" + b"x" * 5000,
    "01-valid-machine-id":          b"7f8e9a0b1c2d3e4f5061728394a5b6c7",
    "02-valid-with-lf":             b"7f8e9a0b1c2d3e4f5061728394a5b6c7\n",
    "03-uppercase-normalized":      b"7F8E9A0B1C2D3E4F5061728394A5B6C7\n",
    "04-missing-source":            None,
    "05-invalid-length":            b"7f8e9a0b1c2d3e4f5061728394a5b6\n",
    "06-invalid-hex":               b"7f8e9a0b1c2d3e4f5061728394a5b6zz\n",
    "07-extra-whitespace":          b"7f8e9a0b1c2d3e4f5061728394a5b6c7 \n",
    "08-embedded-newline":          b"7f8e9a0b1c2d\n3e4f5061728394a5b6\n",
    "09-double-lf":                 b"7f8e9a0b1c2d3e4f5061728394a5b6c7\n\n",
    # Z-13: exactly 32 bytes, no CR/LF, not over-long - so it reaches the DECODING step
    # and fails only there. NORM-036 could represent it; NORM-042 says IDENT-003 decides.
    "13-non-utf8":                  b"7f8e9a0b1c2d3e4f5061728394a5b6\xff\xfe" + b"\n",
}

FIXTURE = {"snapshot_id": "SDS-20260918T142233Z-3f9a1c0b7d2e4a68",
           "run_id": "RUN-20260918T142233Z-a1b2c3d4e5f60718",
           "event_id": "EVT-20260918T142233Z-99aa88bb77cc66dd",
           "created_at": "2026-09-18T14:22:33Z", "occurred_at": "2026-09-18T14:22:33Z",
           "engine_version": "0.0.0-pre", "state_root": "DEV"}


def serializer_conformance(dest):
    """Z-02. Serialize the semantic object with the CANONICAL serializer and write it.

    The committed expected/canonical.bytes is hand-written, so this is a comparison against
    an independent authority, not against ourselves. A naive serializer diverges on DEL, C1
    and U+2028/9, and a UTF-16-ordering one diverges on key order.
    """
    d = dest / "S1-serializer-conformance"
    (d / "expected").mkdir(parents=True, exist_ok=True)
    (d / "input").mkdir(parents=True, exist_ok=True)
    src = OUT / "S1-serializer-conformance" / "input" / "object.json"
    obj = json.loads(src.read_text())
    (d / "input" / "object.json").write_text(src.read_text())
    (d / "CASE.md").write_text((OUT / "S1-serializer-conformance" / "CASE.md").read_text())
    (d / "expected" / "canonical.bytes").write_bytes(canonical_bytes(obj))


def domain_separation(dest):
    """Z-10. NORM-038's frozen domain table, materialized as a golden artifact.

    Derived from the REQUIREMENT, never from this generator's own literals: a vector
    built from the code it certifies asserts only that the code equals itself. The
    verifier re-parses the same requirement independently and must agree with both this
    file and the domains it frames with.
    """
    d = dest / "D1-domain-separation"
    (d / "expected").mkdir(parents=True, exist_ok=True)
    src = (ROOT / "docs" / "architecture" /
           "SNAPSHOT_BASELINE_DELTA_MODEL.md").read_text()
    block = src.split("Domains frozen for W1-A", 1)[1]
    doms = []
    for line in block.splitlines():
        if line.startswith("|"):
            cell = line.split("|")[1].strip()
            if len(cell) > 2 and cell[0] == "`" and cell[-1] == "`":
                doms.append(cell[1:-1])
        elif doms:
            break
    if not doms:
        raise ValueError("NORM-038 domain table not found in the frozen requirement")
    (d / "expected" / "domains.txt").write_text("\n".join(sorted(doms)) + "\n")
    (d / "CASE.md").write_text((OUT / "D1-domain-separation" / "CASE.md").read_text())


def main():
    dest = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    lines = []
    for name, raw in sorted(CASES.items()):
        d = dest / name
        (d / "input").mkdir(parents=True, exist_ok=True)
        (d / "expected").mkdir(parents=True, exist_ok=True)
        if raw is not None:
            (d / "input" / "machine-id.bin").write_bytes(raw)
        (d / "input" / "fixture.json").write_text(
            json.dumps(FIXTURE, indent=2, sort_keys=True) + "\n")
        a = build(FIXTURE, raw)
        e = d / "expected"
        (e / "status.txt").write_text(a["status"] + "\n")
        # NORM-040: the sidecar is present ONLY when a reason exists, mirroring
        # state.canonical. There is deliberately no byte string spelling "no reason".
        if a["reason"] is not None:
            (e / "reason.txt").write_text(a["reason"] + "\n")
        if a["normalized"]:
            (e / "normalized-machine-id.bin").write_bytes(a["normalized"].encode())
            (e / "host-id.txt").write_text(a["host_id"] + "\n")
            (e / "state.canonical").write_bytes(a["state_canonical"])
            (e / "state.sha256").write_text(a["state_hash"] + "\n")
        (e / "method.canonical").write_bytes(a["method_canonical"])
        (e / "manifest-core.canonical").write_bytes(a["manifest_core_canonical"])
        (e / "manifest-hash.txt").write_text(a["manifest_hash"] + "\n")
        (e / "manifest.json").write_bytes(a["manifest"])
        (e / "record-core.canonical").write_bytes(a["record_core_canonical"])
        (e / "record-hash.txt").write_text(a["record_hash"] + "\n")
        (e / "record.json").write_bytes(a["record"])
        for f in sorted(e.rglob("*")):
            if f.is_file() and f.name != "EXPECTED.sha256":
                lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  "
                             f"{f.relative_to(dest)}")
    serializer_conformance(dest)
    domain_separation(dest)
    for conformance in ("S1-serializer-conformance", "D1-domain-separation"):
        e = dest / conformance / "expected"
        for f in sorted(e.rglob("*")):
            if f.is_file():
                lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  "
                             f"{f.relative_to(dest)}")
    (dest / "EXPECTED.sha256").write_text("\n".join(sorted(lines)) + "\n")
    print(f"  generated {len(CASES)} cases into {dest}")


if __name__ == "__main__":
    main()
