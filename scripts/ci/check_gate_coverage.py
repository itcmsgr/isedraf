# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Prove the governance gates are wired, not merely present.
# Implements: GOV-001, GOV-002, D-105
#
# Round 4 finding: gate_coverage.json declared gate scope and NOTHING read it, so
# check-paths and check-index existed locally and were never invoked by CI. One meta-gate
# that proves wiring beats ten more gates that might not be wired.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git"
# =============================================================================

"""For every declared gate: it exists, `make check` invokes it, CI reaches it, the
falsifiability harness injects against it, and its declared file class matches what is
actually on disk."""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
)
spec = json.loads((ROOT / "scripts" / "ci" / "gate_coverage.json").read_text())
makefile = (ROOT / "Makefile").read_text()
harness = (ROOT / "scripts" / "ci" / "falsifiable.sh").read_text()
wf_dir = ROOT / ".github" / "workflows"
workflows = "\n".join(p.read_text() for p in wf_dir.glob("*.yml")) if wf_dir.is_dir() else ""

fail = []

# `make check` must aggregate every declared gate.
m = re.search(r"^check:\s*(.+)$", makefile, re.M)
aggregate = set(m.group(1).split()) if m else set()
if not m:
    fail.append("Makefile has no `check:` aggregate target")

for name, g in spec["gates"].items():
    if name not in aggregate:
        fail.append(f"{name}: declared but not part of `make check` [U-26]")
    if not re.search(rf"^{re.escape(name)}:", makefile, re.M):
        fail.append(f"{name}: no Makefile target")
    script = ROOT / g["script"]
    if not script.exists():
        fail.append(f"{name}: script {g['script']} does not exist")
    if g.get("falsification"):
        if g["falsification"] not in harness:
            fail.append(f"{name}: no falsifiability injection {g['falsification']!r} [GOV-002]")
    else:
        fail.append(f"{name}: declares no falsification case; state one or mark it in GOVERNANCE_GAPS [GOV-001]")

# --- Z-12: the Python matrix must exist AND be load-bearing ---------------------------
# NORM-039 makes the golden vectors release-blocking on Python 3.9 and the current CI
# Python. A workflow that boots an interpreter and never runs the vectors satisfies the
# YAML and not the requirement, so the certification command must appear inside the SAME
# job that declares the matrix.
def job_blocks(text):
    """Split a workflow into its top-level job bodies."""
    parts, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            cur = m.group(1)
            parts[cur] = []
        elif cur is not None:
            parts[cur].append(line)
    return {k: "\n".join(v) for k, v in parts.items()}


pm = spec.get("python_matrix")
if not pm:
    fail.append("gate_coverage.json declares no python_matrix [NORM-039, Z-12]")
else:
    cmd = pm["certification_command"]
    lanes = None
    for job, body in job_blocks(workflows).items():
        m = re.search(r"python-version:\s*\[([^\]]*)\]", body)
        if m and cmd in body:
            lanes = set(re.findall(r"['\"]?([0-9]+\.[0-9]+)['\"]?", m.group(1)))
            break
    if lanes is None:
        fail.append(f"no CI job both declares a python-version matrix and runs "
                    f"{cmd!r}; an interpreter that never runs the vectors closes "
                    f"nothing [NORM-039, Z-12]")
    else:
        for v in pm["versions"]:
            if v not in lanes:
                fail.append(f"CI declares no Python {v} lane; NORM-039 requires the "
                            f"golden vectors to be exercised on it [Z-12]")

# CI must reach every declared entrypoint.
for entry in spec["ci_entrypoints"]:
    if entry not in workflows:
        fail.append(f"CI does not invoke {entry!r} [U-26]")

# Declared eligible classes must not be empty when files of that class exist.
#
# A path that is DELIBERATELY not published is absent by design, not a stale declaration.
# CLAUDE.md governs the engineering repository and is in scope for the path and reference
# gates there; in a public checkout it does not exist. Calling that stale would push
# someone to delete a correct declaration in order to make a public build go green.
# Anything not listed in unpublished_paths that matches nothing is still stale.
UNPUBLISHED = set(spec.get("unpublished_paths", {}).get("paths", []))
for name, g in spec["gates"].items():
    reason = g.get("eligible_may_be_empty_reason")
    for pat in g.get("eligible", []):
        if not any(ROOT.glob(pat)):
            if pat in UNPUBLISHED:
                print(f"  NOTE  {name}: scope {pat!r} is not present in this checkout - "
                      f"it is not published, and is in scope where it exists.")
            elif reason:
                print(f"  NOTE  {name}: scope {pat!r} is empty - {reason.split('.')[0]}.")
            else:
                fail.append(f"{name}: declared scope {pat!r} matches no files - stale declaration")

if fail:
    print("=== gate coverage FAILED ===", file=sys.stderr)
    for f in sorted(set(fail)):
        print(f"  FAIL  {f}", file=sys.stderr)
    sys.exit(1)
print(f"  OK    {len(spec['gates'])} gates: wired into make check, reached by CI, falsifiable")
