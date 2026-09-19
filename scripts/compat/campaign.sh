#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Run the W1-C compatibility campaign ON ONE HOST and emit a test record.
# Implements: SCOPE-070, SCOPE-071, PRIV-004, NORM-039, IDENT-003, IDENT-004
#
# Copy the repository (or this directory plus lib/) to the target host and run it THERE.
# It deliberately performs no SSH and orchestrates nothing: a campaign runner that logs
# into machines is a deployment tool, and this is a measurement tool.
#
# Profiles:
#   probe   read-only fingerprint only. Safe on any host, as any user, including root.
#   fleet   probe + identity in an isolated state root under the invoking user. Read-only
#           with respect to the host. REFUSES root, because W1 itself refuses root.
#   lab     fleet + negative cases against FIXTURE files. Disposable hosts only.
#
# meta:type="tool"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="its own temporary state root only"
# meta:binaries="python3,mktemp,uname"
# =============================================================================
set -uo pipefail

PROFILE="fleet"
RUNS=10
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --profile) PROFILE="${2:-}"; shift 2;;
        --runs)    RUNS="${2:-}"; shift 2;;
        --out)     OUT="${2:-}"; shift 2;;
        -h|--help)
            echo "usage: campaign.sh [--profile probe|fleet|lab] [--runs N] [--out FILE]"
            exit 0;;
        *) echo "campaign: unknown argument $1" >&2; exit 64;;
    esac
done
case "$PROFILE" in probe|fleet|lab) ;; *) echo "campaign: unknown profile" >&2; exit 64;; esac

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${ISEDRAF_PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || { echo "campaign: no $PY on PATH" >&2; exit 64; }

# ---- the probe runs first and always: it is what tells us WHY anything else failed ----
PROBE_JSON="$("$PY" "$HERE/probe.py" 2>/dev/null)" || {
    echo "campaign: probe failed — reporting that rather than guessing" >&2
    PROBE_JSON='{"probe_error":"probe.py did not complete"}'
}

emit() {   # emit <status> <detail-json>
    local status="$1" detail="$2"
    "$PY" - "$status" "$detail" <<'PYX'
import datetime, json, os, sys
status, detail = sys.argv[1], json.loads(sys.argv[2])
probe = json.loads(os.environ.get("ISEDRAF_PROBE_JSON") or "{}")
record = {
    "record_version": 1,
    "test_run_id": "CMP-" + datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
    "collected_at": datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "profile": os.environ.get("ISEDRAF_PROFILE"),
    "floor_declared": os.environ.get("ISEDRAF_FLOOR_DECLARED"),
    "experimental_floor_override": os.environ.get("ISEDRAF_EXPERIMENTAL_FLOOR"),
    "isedraf_commit": os.environ.get("ISEDRAF_COMMIT"),
    "isedraf_version": os.environ.get("ISEDRAF_VERSION"),
    "platform": probe,
    "status": status,
    "results": detail,
}
out = os.environ.get("ISEDRAF_OUT")
text = json.dumps(record, indent=2, sort_keys=True) + "\n"
if out:
    with open(out, "w") as fh:
        fh.write(text)
    sys.stderr.write("campaign: record written to %s\n" % out)
else:
    sys.stdout.write(text)
PYX
}
export ISEDRAF_PROBE_JSON="$PROBE_JSON" ISEDRAF_PROFILE="$PROFILE" ISEDRAF_OUT="$OUT"
export ISEDRAF_COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
export ISEDRAF_VERSION="$(cat "$REPO/VERSION" 2>/dev/null || echo unknown)"

if [ "$PROFILE" = "probe" ]; then
    emit "PROBE_ONLY" '{"note":"read-only fingerprint; no ISEDRAF execution requested"}'
    exit 0
fi

# ---- refuse root, for the same reason the product does ---------------------------------
if [ "$(id -u)" -eq 0 ] || [ -n "${SUDO_USER:-}" ]; then
    echo "campaign: W1 refuses privileged execution (SCOPE-071), so a root or sudo run" >&2
    echo "  cannot validate the identity slice - every invocation would exit 70. Run the" >&2
    echo "  'probe' profile as root if you only need the fingerprint, or run this profile" >&2
    echo "  as an unprivileged account." >&2
    emit "REFUSED_PRIVILEGED" '{"reason":"SCOPE-071: identity validation requires an unprivileged account"}'
    exit 70
fi

# ---- the interpreter floor decides the tier, before anything is attempted ---------------
# ISEDRAF_EXPERIMENTAL_FLOOR lowers the floor FOR AN EXPERIMENT ONLY. It exists so the
# question "would a lower floor actually work?" can be answered with evidence instead of
# opinion, and any record produced under it says so, so no such result can later be
# mistaken for a run at the declared floor.
FLOOR="${ISEDRAF_EXPERIMENTAL_FLOOR:-3.9}"
export ISEDRAF_FLOOR_DECLARED="$FLOOR"
FLOOR_OK="$("$PY" -c "import sys;w=tuple(int(x) for x in '$FLOOR'.split('.'));print('yes' if sys.version_info[:2]>=w else 'no')" 2>/dev/null)"
if [ "$FLOOR_OK" != "yes" ]; then
    emit "UNSUPPORTED_INTERPRETER" "{\"reason\":\"the invoked interpreter is below the $FLOOR floor; see platform.python.suitable_installed for a CONDITIONALLY_SUPPORTED path\"}"
    exit 1
fi

STATE="$(mktemp -d)"; trap 'rm -rf "$STATE"' EXIT
export ISEDRAF_STATE_ROOT="$STATE/state"
export PYTHONPATH="$REPO/lib${PYTHONPATH:+:$PYTHONPATH}"

RESULT_FILE="$STATE/results.json"
"$PY" - "$REPO" "$RUNS" "$PROFILE" > "$RESULT_FILE" <<'PYX'
"""Drive the production CLI, then judge stability and verification."""
import io, json, os, subprocess, sys, time

repo, runs, profile = sys.argv[1], int(sys.argv[2]), sys.argv[3]
sys.path.insert(0, os.path.join(repo, "lib"))
from isedraf import cli, identity, ledger, verify            # noqa: E402

root = os.environ["ISEDRAF_STATE_ROOT"]
results = {"runs": [], "negative": [], "checks": {}}


def one_run(source=None):
    out, err = io.StringIO(), io.StringIO()
    args = type("A", (), {"source": source or identity.SOURCE_PATH})()
    started = time.time()
    code = cli.cmd_identity(args, out=out, err=err)
    return {"exit": code, "seconds": round(time.time() - started, 4),
            "stderr": err.getvalue().strip()[:400],
            "collected": "COLLECTED" in out.getvalue()}


# --- repeatability: a quiet host must not invent a change --------------------------------
for _ in range(runs):
    results["runs"].append(one_run())

state_objects, host_ids = set(), set()
snapshots = os.path.join(root, "snapshots")
if os.path.isdir(snapshots):
    for name in sorted(os.listdir(snapshots)):
        path = os.path.join(snapshots, name, "state", "host_identity.json")
        if os.path.exists(path):
            with open(path, "rb") as fh:
                raw = fh.read()
            state_objects.add(raw)
            host_ids.add(json.loads(raw)["host_id"])

results["checks"]["runs_executed"] = len(results["runs"])
results["checks"]["distinct_exit_codes"] = sorted({r["exit"] for r in results["runs"]})
results["checks"]["distinct_state_objects"] = len(state_objects)
# The identity is reported as PRESENT/ABSENT and never exported: a compatibility record
# has no business carrying a host identifier off the host.
results["checks"]["identity_stable"] = len(host_ids) <= 1
results["checks"]["identity_present"] = bool(host_ids)
results["checks"]["ledger_records"] = len(ledger.read_records(root))
problems = verify.verify_store(root)
results["checks"]["verifier_problems"] = problems
results["checks"]["verifier_pass"] = not problems

# --- lab only: the frozen negative semantics, against FIXTURES, never the host's file ----
if profile == "lab":
    import tempfile
    cases = [
        ("valid", b"7f8e9a0b1c2d3e4f5061728394a5b6c7\n", "COLLECTED", None),
        ("all-zero", b"0" * 32 + b"\n", "ERROR", "SYNTAX_REJECTED"),
        ("uninitialized", b"uninitialized\n", "ERROR", "SYNTAX_REJECTED"),
        ("non-utf8", b"7f8e9a0b1c2d3e4f5061728394a5b6\xff\xfe\n", "ERROR",
         "SYNTAX_REJECTED"),
        ("over-long", b"7f8e9a0b1c2d3e4f5061728394a5b6c7\n" + b"x" * 5000, "ERROR",
         "SOURCE_UNREADABLE"),
        ("invalid-length", b"7f8e9a0b1c2d3e4f5061728394a5b6\n", "ERROR",
         "SYNTAX_REJECTED"),
    ]
    fixtures = tempfile.mkdtemp()
    for name, data, want_status, want_reason in cases:
        path = os.path.join(fixtures, name)
        with open(path, "wb") as fh:
            fh.write(data)
        got = identity.collect(path)
        results["negative"].append({
            "case": name, "expected_status": want_status, "got_status": got.status,
            "expected_reason": want_reason, "got_reason": got.reason,
            "match": got.status == want_status and got.reason == want_reason})
    missing = identity.collect(os.path.join(fixtures, "absent"))
    results["negative"].append({
        "case": "missing-source", "expected_status": "NOT_TESTED",
        "got_status": missing.status, "expected_reason": "SOURCE_ABSENT",
        "got_reason": missing.reason,
        "match": missing.status == "NOT_TESTED" and missing.reason == "SOURCE_ABSENT"})

json.dump(results, sys.stdout)
PYX
RC=$?

if [ "$RC" -ne 0 ] || [ ! -s "$RESULT_FILE" ]; then
    emit "CAMPAIGN_ERROR" '{"reason":"the campaign driver did not complete"}'
    exit 1
fi

VERDICT="$("$PY" - "$RESULT_FILE" <<'PYX'
import json, sys
r = json.load(open(sys.argv[1]))
c = r["checks"]
ok = (c["verifier_pass"] and c["identity_stable"]
      and c["ledger_records"] == c["runs_executed"]
      and len(c["distinct_exit_codes"]) == 1
      and all(n["match"] for n in r["negative"]))
print("PASS" if ok else "FAIL")
PYX
)"
emit "$VERDICT" "$(cat "$RESULT_FILE")"
[ "$VERDICT" = "PASS" ]
