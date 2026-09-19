# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: One side of the reboot proof — run the real CLI, then report what is on disk.
# Implements: IDENT-005, SNAP-020, SNAP-023, STORE-024, PRIV-004
#
# PYTHON 3.6 COMPATIBLE, like probe.py and floor_experiment.py: on EL8 the only
# interpreter available is the vendor platform-python, and that is the host the proof is
# about.
#
# It exercises the PRODUCTION CLI entry point rather than reimplementing the pipeline,
# because a reboot proof that runs different code than an operator runs proves nothing.
#
# meta:type="tool"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="its own state root only"
# meta:binaries=""
# =============================================================================

"""Run `isedraf identity` once, then describe the resulting evidence store."""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "lib"))

from isedraf import cli, ledger, verify                       # noqa: E402


def describe(root):
    """Everything the comparison needs, and no raw identifier beyond host_id."""
    out = {"snapshots": [], "ledger": [], "verifier_problems": verify.verify_store(root)}
    base = os.path.join(root, "snapshots")
    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            manifest = os.path.join(base, name, "manifest.json")
            if not os.path.exists(manifest):
                continue
            with open(manifest, "rb") as fh:
                env = json.loads(fh.read().decode("utf-8"))
            core = env["manifest_core"]
            state_path = os.path.join(base, name, "state", "host_identity.json")
            state_bytes = None
            if os.path.exists(state_path):
                with open(state_path, "rb") as fh:
                    state_bytes = fh.read().decode("utf-8")
            out["snapshots"].append({
                "snapshot_id": name,
                "host_id": core.get("host_id"),
                "state_root": core.get("state_root"),
                "manifest_hash": env.get("manifest_hash"),
                "collection_status":
                    core["sections"]["host_identity"]["collection_status"],
                "state_hash": core["sections"]["host_identity"]["state_hash"],
                "state_canonical": state_bytes,
            })
    for row in ledger.read_records(root):
        core = row["record_core"]
        out["ledger"].append({"sequence": core["sequence"],
                              "previous_record_hash": core["previous_record_hash"],
                              "record_hash": row["record_hash"],
                              "snapshot_id": core["snapshot_id"],
                              "manifest_hash": core["manifest_hash"]})
    return out


def main():
    root = os.environ.get("ISEDRAF_STATE_ROOT")
    if not root:
        json.dump({"error": "ISEDRAF_STATE_ROOT is not set"}, sys.stdout)
        return 0
    out, err = io.StringIO(), io.StringIO()
    args = type("A", (), {"source": "/etc/machine-id"})()
    code = cli.cmd_identity(args, out=out, err=err)
    result = {"pass_label": sys.argv[1] if len(sys.argv) > 1 else "?",
              "python": "%d.%d.%d" % sys.version_info[:3],
              "executable": sys.executable,
              "exit_code": code,
              "cli_stderr": err.getvalue().strip()[:400],
              "raw_machine_id_in_output": "machine-id" in out.getvalue(),
              "store": describe(root)}
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
