# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Verifier B — independently reconstruct the W1-A vectors and check structure.
# Implements: NORM-039
#
# Structurally independent of generate.py: it imports nothing from it and re-derives every
# byte. It also asserts STRUCTURAL properties rather than only comparing digests, because a
# verifier that merely calls the generator certifies nothing.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Verifier B.

Z-14 trust model. A field is only "verified" if the verifier constrains it by something
OTHER than the artifact itself. Each check below is classified:

  SPECIFICATION_CONSTANT  compared against a literal frozen in a requirement
  INDEPENDENTLY_DERIVED   recomputed from the case INPUT, not from the expected output
  CROSS_CHECKED           must agree with a different artifact that is itself constrained
  STRUCTURALLY_VALIDATED  shape/grammar asserted from the frozen text

Recomputing a value from the same file that supplies it is self-certification, not
verification. That was the defect: six of seven corrupted artifacts were accepted.
"""

# SNAP-021 freezes this object verbatim. SPECIFICATION_CONSTANT.
METHOD_LITERAL = (
    b'{"classification_table_version":1,"collector_id":"host_identity",'
    b'"collector_version":1,"identity_scheme":"machine-id-sha256-v1",'
    b'"parser_version":1,"source_id":"file:/etc/machine-id"}\n'
)
# SNAP-022 freezes the reason vocabulary. SPECIFICATION_CONSTANT.
REASONS = {"SOURCE_ABSENT", "SOURCE_UNREADABLE", "SYNTAX_REJECTED",
           "INTEGER_OUT_OF_RANGE", "INTERNAL_ERROR"}
# IDENT-003 bounds the read. SPECIFICATION_CONSTANT.
READ_BOUND = 4096
# Z-10. Every domain this verifier frames with. Declared once so the set it PROVES
# non-prefixing over is provably the set it USES - otherwise the proof is about a list
# nothing reads.
D_HOST = "ISEDRAF:HOST-ID:V1"
D_STATE = "ISEDRAF:STATE:V1"
D_MANIFEST = "ISEDRAF:SNAPSHOT-MANIFEST:V1"
D_RECORD = "ISEDRAF:LEDGER-RECORD:V1"
DOMAINS_USED = {D_HOST, D_STATE, D_MANIFEST, D_RECORD}
import hashlib
import json
import pathlib
import re
import subprocess
import sys

# Z-20: resolved from git, never from __file__. A tool that silently relocates its own
# idea of the repository root can die instead of reporting, and a harness reading only
# the exit code cannot tell the two apart.
ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
)
VEC = ROOT / "test-vectors" / "w1a" / "v1"
fails = []


def bad(m):
    fails.append(m)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def unframe_check(domain, component, expect_hex, where):
    """Rebuild HASH_FRAME_V1 from first principles: ASCII domain, uint64 BE length, bytes."""
    pre = domain.encode("ascii") + len(component).to_bytes(8, "big") + component
    got = sha(pre)
    if got != expect_hex:
        bad(f"{where}: HASH_FRAME_V1 mismatch (domain={domain})")
    # length prefix must be exactly 8 bytes big-endian
    off = len(domain)
    if int.from_bytes(pre[off:off + 8], "big") != len(component):
        bad(f"{where}: length prefix is not uint64 big-endian")


def canon_structural(b, where):
    """Assert the canonical-form properties directly from NORM-035."""
    if not b.endswith(b"\n"):
        bad(f"{where}: missing the single trailing LF")
    if b.count(b"\n") != 1:
        bad(f"{where}: more than one LF — canonical form is one line")
    if b.startswith(b"\xef\xbb\xbf"):
        bad(f"{where}: BOM present")
    body = b[:-1].decode("utf-8")
    if ", " in body or ": " in body:
        bad(f"{where}: insignificant whitespace in separators")
    # Keys sorted by code point WITHIN EACH OBJECT. Re-parse the bytes (independent of the
    # generator's serializer) and check every nesting level separately.
    def _pairs(ps):
        ks = [k for k, _ in ps]
        if ks != sorted(ks):
            bad(f"{where}: object keys not sorted by code point: {ks}")
        if len(set(ks)) != len(ks):
            bad(f"{where}: duplicate keys in one object: {ks}")
        return dict(ps)
    try:
        json.loads(body, object_pairs_hook=_pairs)
    except ValueError as exc:
        bad(f"{where}: not valid JSON text: {exc}")
    # no escape outside the frozen alphabet
    for m in re.finditer(r"\\u([0-9a-fA-F]{4})", body):
        cp = int(m.group(1), 16)
        if not (cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F or cp in (0x2028, 0x2029)):
            bad(f"{where}: \\u escape outside the frozen alphabet: U+{m.group(1)}")
        if m.group(1) != m.group(1).lower():
            bad(f"{where}: \\u escape not lowercase hex")
    if "\\/" in body:
        bad(f"{where}: '/' escaped, which the frozen text forbids")


def rd(p):
    return p.read_bytes() if p.exists() else None


# --- Z-02: S1 serializer conformance, checked INDEPENDENTLY of any serializer ---------
s1 = VEC / "S1-serializer-conformance" / "expected" / "canonical.bytes"
if s1.exists():
    b = s1.read_bytes()
    canon_structural(b, "S1/canonical.bytes")
    # NORM-035 requires these four to be ESCAPED. A naive serializer emits them raw, and
    # that is exactly the divergence the case exists to force.
    for esc, raw, label in ((b"\\u007f", b"\x7f", "U+007F DEL"),
                            (b"\\u0085", b"\xc2\x85", "U+0085 C1"),
                            (b"\\u2028", b"\xe2\x80\xa8", "U+2028"),
                            (b"\\u2029", b"\xe2\x80\xa9", "U+2029")):
        if esc not in b:
            bad(f"S1: {label} is not escaped as required by NORM-035")
        if raw in b:
            bad(f"S1: {label} appears RAW; NORM-035 requires the escape")
    # Escaped-but-not-required forms would also violate "nothing else is escaped".
    for forbidden, label in ((b"\\u00e9", "U+00E9 must stay raw UTF-8"),
                             (b"\\/", "'/' is never escaped")):
        if forbidden in b:
            bad(f"S1: {label} (NORM-035)")

# --- Z-10: NORM-038 domain separation, asserted rather than claimed -------------------
# NORM-038 says the domains "SHALL be mutually non-prefixing; the golden vectors assert
# it". Until now nothing did. Three sets must coincide and then satisfy the property:
#   SPEC      parsed out of the frozen requirement - the authority
#   VECTOR    D1-domain-separation/expected/domains.txt - the golden artifact
#   USED      the literals this verifier actually frames with
# Proving the property over any one of them alone proves nothing about the other two.
def spec_domains():
    """Parse NORM-038's frozen domain table. SPECIFICATION_CONSTANT."""
    src = (ROOT / "docs" / "architecture" / "SNAPSHOT_BASELINE_DELTA_MODEL.md").read_text()
    i = src.find("Domains frozen for W1-A")
    if i < 0:
        bad("NORM-038: the frozen domain table could not be located in the requirement")
        return set()
    out, started = set(), False
    for line in src[i:].splitlines():
        if line.startswith("|"):
            started = True
            m = re.match(r"\|\s*`([^`]+)`\s*\|", line)
            if m:
                out.add(m.group(1))
        elif started and not line.strip():
            break
    return out


SPEC = spec_domains()
d1 = VEC / "D1-domain-separation" / "expected" / "domains.txt"
if not d1.exists():
    bad("NORM-038: no golden vector asserts domain separation (D1-domain-separation missing)")
else:
    vector = set(d1.read_text().splitlines())
    if not d1.read_text().endswith("\n"):
        bad("D1/domains.txt: missing the trailing LF")
    if vector != SPEC:
        bad(f"D1/domains.txt {sorted(vector)} != NORM-038's frozen table {sorted(SPEC)}")
    if DOMAINS_USED != SPEC:
        bad(f"verifier frames with {sorted(DOMAINS_USED)}, NORM-038 freezes {sorted(SPEC)}")
    # The property itself, over ordered pairs, with the offending pair named.
    for a in sorted(vector):
        for b in sorted(vector):
            if a != b and b.startswith(a):
                bad(f"NORM-038 VIOLATED: domain {a!r} is a prefix of {b!r} — "
                    f"HASH_FRAME_V1 preimages are then ambiguous")
        if not a.isascii():
            bad(f"NORM-038: domain {a!r} is not ASCII")

for case in sorted(d for d in VEC.iterdir() if d.is_dir()):
    name = case.name
    if name.startswith("S1-") or name.startswith("D1-"):
        continue          # conformance cases, not snapshot cases
    e = case / "expected"
    raw = rd(case / "input" / "machine-id.bin")
    status = (e / "status.txt").read_text().strip()

    # --- independently re-derive the parse outcome (IDENT-003 / IDENT-004) -------------
    # IDENT-004 is a TOTAL ORDERED decision list, so the verifier walks it in order and
    # derives the reason too. Deriving only the status was how case 12 could have been
    # given the wrong reason token and still verified: the byte-compare would have caught
    # a regenerated corpus, but nothing asserted WHICH row IDENT-004 selects.
    exp_status, exp_reason, norm = "ERROR", "SYNTAX_REJECTED", None
    if raw is None:                                   # row 1: source does not exist
        exp_status, exp_reason = "NOT_TESTED", "SOURCE_ABSENT"
    elif len(raw) > READ_BOUND:                       # row 2: over-long read (IDENT-003)
        exp_status, exp_reason = "ERROR", "SOURCE_UNREADABLE"
    else:
        body = raw[:-1] if raw.endswith(b"\n") else raw
        # NORM-042: IDENT-003's grammar decides, and it decides on the BYTES. Whether the
        # input failed on encoding or on shape does not reach the result.
        decodes = True
        try:
            body.decode("utf-8")
        except UnicodeDecodeError:
            decodes = False
        ok = (len(body) == 32 and b"\n" not in body and b"\r" not in body
              and all(chr(c) in "0123456789abcdefABCDEF" for c in body))
        if ok:
            t = body.decode("ascii").lower()
            if t not in ("0" * 32, "uninitialized"):  # row 4: accepted
                exp_status, exp_reason, norm = "COLLECTED", None, t
        if not decodes and status == "COLLECTED":
            bad(f"{name}: NORM-042 VIOLATED — input is not valid UTF-8 and IDENT-003 "
                f"rejects it, yet it became COLLECTED identity state. NORM-036 does not "
                f"override a field-specific grammar.")
    if status != exp_status:
        bad(f"{name}: status {status} but independent parse says {exp_status}")

    if norm:
        host_id = (e / "host-id.txt").read_text().strip()
        unframe_check(D_HOST, norm.encode(), host_id[7:], f"{name}/host_id")
        sc = rd(e / "state.canonical")
        canon_structural(sc, f"{name}/state")
        if sc.decode() != '{"host_id":"%s"}\n' % host_id:
            bad(f"{name}: state object is not IDENT-002's literal single-key form")
        unframe_check(D_STATE, sc,
                      (e / "state.sha256").read_text().strip()[7:], f"{name}/state_hash")
    else:
        if (e / "state.canonical").exists():
            bad(f"{name}: state written although status is {status} (SNAP-022)")

    # --- SPECIFICATION_CONSTANT: method.canonical is frozen verbatim by SNAP-021 ---------
    meth = rd(e / "method.canonical")
    if meth != METHOD_LITERAL:
        bad(f"{name}: method.canonical does not match SNAP-021's frozen literal")
    canon_structural(meth, f"{name}/method")

    # --- SPECIFICATION_CONSTANT + CROSS_CHECKED: NORM-040 / NORM-041 --------------------
    rf = e / "reason.txt"
    rtxt = rf.read_bytes() if rf.exists() else None
    if rtxt is not None:
        # NORM-040: exactly the token then one LF. NORM-041: anything else is rejected,
        # never normalized - including every language's rendering of nothingness.
        if not rtxt.endswith(b"\n") or rtxt.count(b"\n") != 1:
            bad(f"{name}: reason.txt is not exactly one token followed by one LF (NORM-040)")
        tok = rtxt[:-1].decode("utf-8", "replace")
        if tok not in REASONS:
            bad(f"{name}: reason.txt {tok!r} is not a SNAP-022 vocabulary token (NORM-041)")

    # --- INDEPENDENTLY_DERIVED: normalized bytes come from the INPUT, not the output -----
    nb = rd(e / "normalized-machine-id.bin")
    if norm is not None:
        if nb != norm.encode("ascii"):
            bad(f"{name}: normalized-machine-id.bin does not match the parse of input/")
    elif nb is not None:
        bad(f"{name}: normalized bytes present although the input was rejected")

    mc = rd(e / "manifest-core.canonical")
    canon_structural(mc, f"{name}/manifest_core")
    mh = (e / "manifest-hash.txt").read_text().strip()
    unframe_check(D_MANIFEST, mc, mh[7:], f"{name}/manifest_hash")
    if b'"manifest_hash"' in mc:
        bad(f"{name}: manifest_hash present in its own preimage")

    rc = rd(e / "record-core.canonical")
    canon_structural(rc, f"{name}/record_core")
    rh = (e / "record-hash.txt").read_text().strip()
    unframe_check(D_RECORD, rc, rh[7:], f"{name}/record_hash")
    if b'"record_hash"' in rc:
        bad(f"{name}: record_hash present in its own preimage")
    if b'"previous_record_hash":"sha256:' + b"0" * 64 + b'"' not in rc:
        bad(f"{name}: genesis previous_record_hash is not sha256 + 64 zeros")
    if b'"event":"snapshot_committed"' not in rc:
        bad(f"{name}: event literal is not snapshot_committed")
    records = sorted(e.glob("record-*.json")) or [e / "record.json"]
    for rp in records:
        canon_structural(rd(rp), f"{name}/{rp.name}")
    canon_structural(rd(e / "manifest.json"), f"{name}/manifest.json")

    # --- CROSS_CHECKED: the envelopes must re-serialize to the hashed preimages ----------
    for env, core_file, core_key, hash_key, hv in (
            ("manifest.json", mc, "manifest_core", "manifest_hash", mh),
            (records[0].name, rc, "record_core", "record_hash", rh)):
        raw = rd(e / env)
        try:
            obj = json.loads(raw)
        except ValueError:
            bad(f"{name}/{env}: not valid JSON"); continue
        if obj.get(hash_key) != hv:
            bad(f"{name}/{env}: {hash_key} disagrees with {core_file and hash_key}.txt")
        # Re-serialize the embedded core and require it to equal the hashed preimage byte
        # for byte. This is what catches an envelope that contradicts its own core.
        emb = json.dumps(obj.get(core_key), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8") + b"\n"
        if emb != core_file:
            bad(f"{name}/{env}: embedded {core_key} does not re-serialize to "
                f"{core_key.replace('_','-')}.canonical")

    # --- Z-08 / SNAP-023: when manifest host_id is a string and when it is null ---------
    # INDEPENDENTLY_DERIVED: the expected shape comes from the parse of input/, not from
    # the manifest's own declaration. Reading manifest.host_id and accepting it would be
    # the artifact certifying itself.
    core_obj = json.loads(mc)
    if "host_id" not in core_obj:
        bad(f"{name}: SNAP-023 — manifest_core has no host_id key; it is mandatory and "
            f"present in every case, and absent is not an encoding of null (NORM-034)")
    else:
        mhid = core_obj["host_id"]
        if exp_status == "COLLECTED":
            want = "sha256:" + sha(D_HOST.encode("ascii")
                                   + len(norm.encode("utf-8")).to_bytes(8, "big")
                                   + norm.encode("utf-8"))
            if mhid is None:
                bad(f"{name}: SNAP-023 — COLLECTED with host_id null. That is an "
                    f"invariant violation, not a second valid representation")
            elif mhid != want:
                bad(f"{name}: SNAP-023 — COLLECTED host_id {mhid!r} is not the IDENT-005 "
                    f"derivation of the input")
            elif sc.decode() != '{"host_id":"%s"}\n' % mhid:
                bad(f"{name}: SNAP-023 — manifest host_id is not byte-identical to the "
                    f"state object's host_id")
        elif mhid is not None:
            bad(f"{name}: SNAP-023 — status is {exp_status} yet manifest host_id is "
                f"{mhid!r}; it SHALL be null for every non-COLLECTED outcome")

    # --- CROSS_CHECKED: the sidecars must agree with the manifest ------------------------
    sec = core_obj["sections"]["host_identity"]
    if sec["collection_status"] != status:
        bad(f"{name}: status.txt disagrees with manifest collection_status")
    mr = sec["reason"]
    # INDEPENDENTLY_DERIVED: IDENT-004's selected row, not merely a vocabulary member.
    if mr != exp_reason:
        bad(f"{name}: manifest reason {mr!r} but IDENT-004 selects {exp_reason!r} "
            f"for this input")
    # NORM-040: presence encodes presence. Absent sidecar <=> null reason.
    if (mr is None) != (rtxt is None):
        bad(f"{name}: reason.txt presence disagrees with manifest reason {mr!r} (NORM-040)")
    elif mr is not None and rtxt[:-1].decode() != mr:
        bad(f"{name}: reason.txt disagrees with manifest reason {mr!r}")

# --- Z-07: ledger chaining, wherever a case supplies more than one record -------------
for case in sorted(d for d in VEC.iterdir() if d.is_dir()):
    recs = sorted((case / "expected").glob("record-*.json"))
    if len(recs) < 2:
        continue
    prev = None
    for i, rp in enumerate(recs, start=1):
        obj = json.loads(rp.read_bytes())
        core, rh = obj["record_core"], obj["record_hash"]
        if core["sequence"] != i:
            bad(f"{case.name}/{rp.name}: sequence {core['sequence']} != {i} (STORE-024)")
        want = "sha256:" + "0" * 64 if prev is None else prev
        if core["previous_record_hash"] != want:
            bad(f"{case.name}/{rp.name}: previous_record_hash breaks the chain (STORE-024)")
        prev = rh

# --- metamorphic: the optional single LF must normalize away, a second LF must not ------
a = VEC / "01-valid-machine-id" / "expected"
b = VEC / "02-valid-with-lf" / "expected"
c = VEC / "03-uppercase-normalized" / "expected"
for f in ("host-id.txt", "state.canonical", "state.sha256", "manifest-hash.txt"):
    if rd(a / f) != rd(b / f):
        bad(f"metamorphic: trailing LF changed {f} — the LF must normalize away")
    if rd(a / f) != rd(c / f):
        bad(f"metamorphic: uppercase changed {f} — IDENT-003 lowercases")
if (VEC / "09-double-lf" / "expected" / "state.canonical").exists():
    bad("metamorphic: a second LF was accepted; the grammar permits exactly one")

# --- Z-13: NORM-042 applicability trigger, same treatment as Z-11 ---------------------
# W1-A has no field where the schema permits opaque bytes (IDENT-002 freezes the only
# state object as one hex-derived string), so NORM-036 has no positive W1-A surface. The
# premise is enforced rather than promised: any tagged-encoding object appearing in W1-A
# evidence means a field-specific grammar was bypassed.
for case in sorted(d for d in VEC.iterdir() if d.is_dir()):
    for art in sorted((case / "expected").rglob("*")):
        if art.is_file() and b"__isedraf_encoding" in art.read_bytes():
            bad(f"NORM-042 TRIGGER: {case.name}/{art.name} carries __isedraf_encoding. "
                f"W1-A declares no field permitting opaque bytes; a field-specific "
                f"grammar (IDENT-003) was bypassed.")

# --- Z-11: NORM-037 applicability trigger, not a manufactured coverage case -----------
# NORM-037 governs SET-LIKE fields: each needs a schema-defined TOTAL ordering, and
# "golden fixtures assert totality". W1-A's frozen objects contain no array-typed field,
# so there is nothing whose ordering could be asserted. Inventing one to make the test
# non-vacuous would be fabricating scope.
#
# What can be enforced honestly is the PREMISE. The day a set-like field enters W1-A, the
# claim "NORM-037 is not applicable" becomes false, and this fires rather than the
# statement quietly rotting in a coverage table.
def find_arrays(o, path, where):
    if isinstance(o, list):
        bad(f"NORM-037 TRIGGER: array-typed (set-like) field at {where}{path} — W1-A "
            f"declares none, so no ordering is asserted anywhere. Either give it a "
            f"schema-defined total ordering with a golden fixture, or it does not belong "
            f"in W1-A.")
    elif isinstance(o, dict):
        for k, v in o.items():
            find_arrays(v, f"{path}/{k}", where)


for case in sorted(d for d in VEC.iterdir() if d.is_dir()):
    for art in sorted((case / "expected").rglob("*")):
        if art.is_file() and (art.suffix == ".json" or art.name.endswith(".canonical")
                              or art.name.endswith(".bytes")):
            try:
                find_arrays(json.loads(art.read_bytes()), "", f"{case.name}/{art.name}")
            except ValueError:
                pass          # not a JSON artifact; the canon checks above cover those

# --- the committed digest list must match the files -----------------------------------
for line in (VEC / "EXPECTED.sha256").read_text().splitlines():
    dig, rel = line.split("  ", 1)
    p = VEC / rel
    if not p.exists():
        bad(f"EXPECTED.sha256 lists a missing file: {rel}")
    elif sha(p.read_bytes()) != dig:
        bad(f"EXPECTED.sha256 digest mismatch: {rel}")

if fails:
    print("=== W1-A vector verification FAILED ===", file=sys.stderr)
    for f in sorted(set(fails)):
        print(f"  FAIL  {f}", file=sys.stderr)
    sys.exit(1)
n = len([d for d in VEC.iterdir() if d.is_dir()])
print(f"  OK    {n} W1-A vector cases independently verified (bytes, framing, structure)")
