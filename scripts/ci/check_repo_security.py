# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The repository's security configuration and policy documents stay in force.
# Implements: D-88, D-90, D-91, D-93, GOV-002
#
# OpenSSF Baseline Level 2, 2026-09-29. Each property below was established once and then
# had nothing holding it: a workflow can regain a write-all token, Scorecard can stop
# publishing, a policy document can lose its response targets, and pre-release wording can
# return to a released project. These are file properties, so they are checked here, where
# every change passes. Settings that live only on the forge (private vulnerability
# reporting, secret scanning) are not files and are verified by API at release time.
#
#   workflows   top-level `permissions:` is empty or read-only; no write-all; no
#               pull_request_target; the DCO job runs on pull requests
#   scorecard   results are published and the job holds exactly its three permissions
#   documents   SECURITY.md, MAINTAINERS.md, CONTRIBUTING.md and docs/DEPENDENCIES.md
#               exist and state what OpenSSF Baseline asks of each
#   wording     at GENERAL_AVAILABILITY the front-door documents carry no pre-release
#               wording and no instruction to use an option 0.1 does not have
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git"
# =============================================================================
"""Repository security configuration and policy documents (OpenSSF Baseline Level 2)."""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                                            universal_newlines=True).strip())
fail = []


def bad(msg):
    fail.append(msg)


def read(rel):
    p = ROOT / rel
    return p.read_text(encoding="utf-8") if p.is_file() else None


# --- workflows ---------------------------------------------------------------------------
WF = ROOT / ".github" / "workflows"
workflows = sorted(WF.glob("*.yml")) if WF.is_dir() else []
if not workflows:
    bad("no workflows found under .github/workflows")
for wf in workflows:
    rel = wf.relative_to(ROOT)
    text = wf.read_text(encoding="utf-8")
    m = re.search(r"^permissions:[ \t]*(.*)\n((?:[ \t]+\S.*\n)*)", text, re.M)
    if not m:
        bad("%s: no top-level `permissions:`; the token would get the repository default" % rel)
    else:
        inline, block = m.group(1).strip(), m.group(2)
        if inline not in ("{}", "read-all", ""):
            bad("%s: top-level permissions %r are not empty or read-only" % (rel, inline))
        for scope, level in re.findall(r"^[ \t]+([a-z-]+):[ \t]*(\S+)", block, re.M):
            if level != "read":
                bad("%s: top-level permission %s: %s; grant write per job, not workflow-wide"
                    % (rel, scope, level))
    if re.search(r"write-all", text):
        bad("%s: `write-all` grants every scope" % rel)
    if re.search(r"^\s*pull_request_target\s*:", text, re.M):
        bad("%s: pull_request_target runs untrusted pull request code with a write token" % rel)

gov = read(".github/workflows/governance.yml") or ""
if not re.search(r"^\s*-?\s*run:\s*make check-dco-pr\s*$", gov, re.M):
    bad("governance.yml: no job runs `make check-dco-pr`, so pull requests are not DCO-checked")
if "github.event.pull_request.base.sha" not in gov:
    bad("governance.yml: the DCO job is not given the pull request's base commit")

# --- scorecard ---------------------------------------------------------------------------
sc = read(".github/workflows/scorecard.yml")
if sc is None:
    bad("scorecard.yml is missing: the README Scorecard badge would have nothing behind it")
else:
    if not re.search(r"^\s*publish_results:\s*true\s*$", sc, re.M):
        bad("scorecard.yml: publish_results is not true, so the README badge shows no result")
    for need in ("contents: read", "security-events: write", "id-token: write"):
        if need not in sc:
            bad("scorecard.yml: the job lacks `%s`" % need)
    if not re.search(r"upload-sarif@[0-9a-f]{40}", sc):
        bad("scorecard.yml: results are not uploaded to code scanning")

# --- documents ---------------------------------------------------------------------------
REQUIRED = {
    "SECURITY.md": [
        (r"private vulnerability reporting", "the private reporting route (VM-03.01)"),
        (r"3 business days", "the acknowledgement target (VM-01.01)"),
        (r"10 business days", "the assessment target (VM-01.01)"),
        (r"90 days", "the coordinated disclosure target (VM-01.01)"),
        (r"Security Advisor", "publication through security advisories (VM-04.01)"),
        (r"\bCVE\b", "CVE assignment where warranted (VM-04.01)"),
    ],
    "MAINTAINERS.md": [
        (r"access to sensitive resources", "who holds sensitive access (GV-01.01)"),
        (r"Roles and responsibilities", "roles and responsibilities (GV-01.02)"),
    ],
    "CONTRIBUTING.md": [
        (r"make check", "the local validation requirement (GV-03.02)"),
        (r"Signed-off-by", "the DCO sign-off (LE-01.01)"),
        (r"git commit -s", "how to sign off (LE-01.01)"),
        (r"Assisted-by", "AI disclosure, separate from the sign-off"),
        (r"SECURITY\.md", "where vulnerabilities go instead"),
    ],
    "docs/DEPENDENCIES.md": [
        (r"standard library only", "the runtime dependency policy (DO-06.01)"),
        (r"full commit SHA", "how CI dependencies are pinned (DO-06.01)"),
        (r"Dependabot", "how dependencies are monitored (DO-06.01)"),
    ],
}
for rel, needs in REQUIRED.items():
    text = read(rel)
    if text is None:
        bad("%s is missing" % rel)
        continue
    for pattern, what in needs:
        if not re.search(pattern, text, re.I):
            bad("%s no longer states %s" % (rel, what))

# --- wording at general availability -----------------------------------------------------
status = json.loads(read("scripts/ci/project_status.json") or "{}")
if status.get("project_stage") == "GENERAL_AVAILABILITY":
    FRONT = ["README.md", "SECURITY.md", "CONTRIBUTING.md", "MAINTAINERS.md", "SUPPORT.md",
             "docs/GETTING_STARTED.md", "docs/EVIDENCE_MODEL.md", "docs/AUDITOR_GUIDE.md",
             "docs/REPORT_GUIDE.md", "docs/SECURITY_AND_LIMITATIONS.md", "docs/DEPENDENCIES.md"]
    FRONT += [str(p.relative_to(ROOT)) for p in sorted((ROOT / ".github" / "ISSUE_TEMPLATE").glob("*.yml"))]
    STALE = [
        (r"technical preview", "calls the project a technical preview"),
        (r"no release has been published", "says no release exists"),
        (r"not accepting (external )?contributions", "says contributions are not accepted"),
        (r"before public release", "promises something for a release that has happened"),
        (r"--redact\b", "tells the reader to use --redact, which 0.1 does not have"),
    ]
    for rel in FRONT:
        text = read(rel)
        if text is None:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for pattern, why in STALE:
                if re.search(pattern, line, re.I):
                    bad("%s:%d %s at GENERAL_AVAILABILITY" % (rel, n, why))

if fail:
    print("=== repository security gate FAILED ===")
    for f in fail:
        print("  FAIL  " + f)
    sys.exit(1)
print("  OK    repository security: %d workflows least-privilege, Scorecard publishing, "
      "DCO wired, %d policy documents complete, no pre-release wording"
      % (len(workflows), len(REQUIRED)))
