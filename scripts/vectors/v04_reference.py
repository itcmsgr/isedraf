#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Reference generator for the v0.4 vectors: profile hash, BL-000001, section STATE.
# Implements: NORM-039, SCOPE-073, SCOPE-074, SCOPE-045
#
# Written from D-127's text, not from lib/: it imports nothing from lib/isedraf. Canonical
# bytes and HASH_FRAME_V1 come from the W1-A reference generator (generate.py), which is
# itself independent of production. The classification tables are read from tables.json
# (see v04_tables.py for why they are the one input taken from the domain models).
#
# meta:type="generator"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="test-vectors/v04/v1/expected.json"
# meta:binaries=""
# =============================================================================
"""usage: v04_reference.py [--check]   (writes or checks test-vectors/v04/v1/expected.json)"""
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate as ref                                         # noqa: E402

VEC = HERE.parent.parent / "test-vectors" / "v04" / "v1"
LISTS = {"accounts": [("local_accounts", ""), ("local_groups", "group.")],
         "ssh": [("records", "")], "loginpolicy": [("records", "")]}


def _flatten(obj, prefix, table, out):
    """D-127 projection of one entity, written out independently."""
    containers = set()
    for name in table:
        parts = name.split(".")
        for i in range(1, len(parts)):
            containers.add(".".join(parts[:i]))
    for key in obj:
        name = prefix + key
        if name in table:
            if table[name] == "STATE":
                out[name] = obj[key]
        elif name in containers:
            if obj[key] is None:
                out[name] = None
            else:
                _flatten(obj[key], name + ".", table, out)
        else:
            raise ValueError("unclassified %s" % name)
    return out


def projection(name, section, table):
    lists = {}
    for key, prefix in LISTS[name]:
        lists[key] = [_flatten(e, prefix, table, {}) for e in section["evidence"][key]]
    return ref.canonical_bytes({"projection_version": 1, "section": name, "lists": lists})


def fingerprint(name, section, table):
    m = section["method"]
    obj = {"projection_version": 1, "section": name, "schema_version": section["schema_version"],
           "collector_id": m["collector_id"], "collector_version": m["collector_version"],
           "parser_version": m["parser_version"], "classification": table}
    return "sha256:" + hashlib.sha256(ref.canonical_bytes(obj)).hexdigest()


def compute():
    cases = json.loads((VEC / "cases.json").read_text())
    tables = json.loads((VEC / "tables.json").read_text())
    prof = cases["profile"]
    p_hash = ref.frame("ISEDRAF:PROFILE:V1", ref.canonical_bytes(prof))
    m_hash = cases["baseline"]["manifest_hash"]
    bl = ref.frame("ISEDRAF:BASELINE:V1", bytes.fromhex(m_hash[7:]), p_hash)
    out = {"profile_canonical": ref.canonical_bytes(prof).decode("utf-8"),
           "profile_hash": ref.rendered(p_hash),
           "baseline": {"manifest_hash": m_hash, "revision_hash": ref.rendered(bl)},
           "sections": []}
    for c in cases["sections"]:
        table = tables[c["name"]]
        data = projection(c["name"], c["section"], table)
        out["sections"].append({
            "case": c["case"], "projection_canonical": data.decode("utf-8"),
            "state_hash": ref.rendered(ref.frame("ISEDRAF:STATE:V1", data)),
            "method_fingerprint": fingerprint(c["name"], c["section"], table)})
    return json.dumps(out, indent=1, sort_keys=True) + "\n"


def main(argv):
    text = compute()
    target = VEC / "expected.json"
    if "--check" in argv:
        if target.read_text() != text:
            print("v04 vectors: expected.json does not reproduce")
            return 1
        print("v04 vectors: expected.json reproduces")
        return 0
    target.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
