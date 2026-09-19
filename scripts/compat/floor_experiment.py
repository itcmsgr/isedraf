# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Prove, or disprove, that the production implementation produces the CERTIFIED
#          canonical bytes under an interpreter below the declared floor.
# Implements: NORM-039, D-12, IDENT-002, IDENT-005, SNAP-020, SNAP-023, STORE-024
#
# THIS FILE IS PYTHON 3.6 COMPATIBLE, like scripts/compat/probe.py and unlike the rest of
# the repository. It exists to answer one question with evidence instead of opinion:
#
#     does lib/isedraf, run on a vendor Python 3.6, emit the SAME BYTES that the
#     certified W1-A corpus pins?
#
# The committed corpus is the pivot. CI already proves 3.9, 3.12 and 3.14 reproduce it
# exactly, so a 3.6 run that also reproduces it is byte-identical to all three without
# any result being copied between interpreters.
#
# It writes nothing outside a temporary directory and changes no host state.
#
# meta:type="tool"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Compare production output against the certified corpus, under any interpreter."""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "lib"))
VECTORS = os.path.join(ROOT, "test-vectors", "w1a", "v1")

try:
    from isedraf import canonical, identity, ledger, snapshot
except Exception as exc:                      # noqa: BLE001 - the answer, not a crash
    json.dump({"import_error": "%s: %s" % (type(exc).__name__, exc),
               "python": "%d.%d.%d" % sys.version_info[:3]}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


def compare_case(name, tmp):
    """Run the production pipeline over one vector input and diff every artifact."""
    case = os.path.join(VECTORS, name)
    expected = os.path.join(case, "expected")
    with open(os.path.join(case, "input", "fixture.json")) as fh:
        fx = json.load(fh)

    source = os.path.join(case, "input", "machine-id.bin")
    if os.path.exists(source):
        path = os.path.join(tmp, name)
        os.makedirs(path)
        path = os.path.join(path, "machine-id")
        with open(path, "wb") as fh:
            fh.write(read(source))
    else:
        path = os.path.join(tmp, "does-not-exist")

    ident = identity.collect(path)
    built = snapshot.build(ident, fx["snapshot_id"], fx["run_id"], fx["created_at"],
                           fx["state_root"], fx["engine_version"])
    core = {
        "ledger_schema_version": ledger.LEDGER_SCHEMA_VERSION,
        "sequence": 1,
        "event": ledger.EVENT_SNAPSHOT_COMMITTED,
        "event_id": fx["event_id"],
        "occurred_at": fx["occurred_at"],
        "previous_record_hash": ledger.GENESIS_PREVIOUS,
        "snapshot_id": fx["snapshot_id"],
        "manifest_hash": built["manifest_hash"],
        "state_root": fx["state_root"],
    }
    core_canonical = canonical.canonical_bytes(core)
    record_hash = canonical.rendered(
        canonical.hash_frame(canonical.DOMAIN_LEDGER_RECORD, core_canonical))

    produced = {
        "status.txt": (ident.status + "\n").encode("utf-8"),
        "method.canonical": built["method"],
        "manifest-core.canonical": built["manifest_core_canonical"],
        "manifest-hash.txt": (built["manifest_hash"] + "\n").encode("utf-8"),
        "manifest.json": built["manifest"],
        "record-core.canonical": core_canonical,
        "record-hash.txt": (record_hash + "\n").encode("utf-8"),
        "record.json": canonical.canonical_bytes(
            {"record_core": core, "record_hash": record_hash}),
    }
    if ident.reason is not None:
        produced["reason.txt"] = (ident.reason + "\n").encode("utf-8")
    if ident.collected:
        produced["normalized-machine-id.bin"] = ident.normalized.encode("ascii")
        produced["host-id.txt"] = (ident.host_id + "\n").encode("utf-8")
        produced["state.canonical"] = ident.state_canonical
        produced["state.sha256"] = (ident.state_hash + "\n").encode("utf-8")

    diffs = []
    for artifact, data in sorted(produced.items()):
        target = os.path.join(expected, artifact)
        if not os.path.exists(target):
            diffs.append("%s: produced but the corpus has no such artifact" % artifact)
        elif read(target) != data:
            diffs.append("%s: BYTES DIFFER" % artifact)
    # Artifacts the corpus has and we did not produce are equally a divergence.
    for artifact in sorted(os.listdir(expected)):
        if artifact not in produced:
            diffs.append("%s: in the corpus, not produced" % artifact)
    return diffs


def main():
    cases = sorted(d for d in os.listdir(VECTORS)
                   if os.path.isdir(os.path.join(VECTORS, d))
                   and not d.startswith("S1-") and not d.startswith("D1-"))
    tmp = tempfile.mkdtemp()
    result = {"python": "%d.%d.%d" % sys.version_info[:3],
              "executable": sys.executable, "cases": {}, "divergences": 0}
    for name in cases:
        try:
            diffs = compare_case(name, tmp)
        except Exception as exc:              # noqa: BLE001
            diffs = ["EXCEPTION %s: %s" % (type(exc).__name__, exc)]
        result["cases"][name] = diffs
        result["divergences"] += len(diffs)
    result["cases_checked"] = len(cases)
    result["byte_identical_to_certified_corpus"] = (result["divergences"] == 0
                                                    and len(cases) > 0)
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
