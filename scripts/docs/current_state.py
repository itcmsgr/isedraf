# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Generate docs/CURRENT_STATE.md from the authoritative status registry.
# Implements: D-88, D-89, GOV-007
#
# CURRENT_STATE.md was hand-maintained and drifted until it announced that no product code
# existed while three commands worked — in the one page the README designates as the truth.
# Manual status is not authority; it is a copy that rots.
#
# This generator does NOT guess. It reads scripts/ci/project_status.json and a small number
# of mechanically countable facts, and it FAILS rather than choosing when two authorities
# disagree — because silently picking one is how the drift started.
#
# meta:type="generator"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="docs/CURRENT_STATE.md"
# meta:binaries="git"
# =============================================================================

"""`generate` writes the page; `check` fails when the committed page is stale."""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
REGISTRY = json.loads((ROOT / "scripts" / "ci" / "project_status.json").read_text())
TARGET = ROOT / "docs" / "CURRENT_STATE.md"
BANNER = "GENERATED FILE — DO NOT EDIT MANUALLY"


def contradictions():
    """Refuse to generate when two authorities disagree, instead of picking one."""
    problems = []
    for name, cap in REGISTRY["capabilities"].items():
        evidence = cap.get("evidence")
        # WRITTEN_NEVER_RUN is a state this project needs a word for: the code exists
        # and is committed, and it has never executed once. It is not IMPLEMENTED,
        # because nothing has been observed; it is not PLANNED, because the file is
        # right there. Collapsing it into either one would be a claim the evidence has
        # not earned. Its evidence path must exist, exactly like an implemented one.
        if cap["status"] in ("IMPLEMENTED", "CERTIFIED", "WRITTEN_NEVER_RUN"):
            if not evidence:
                problems.append("%s is %s with no evidence path" % (name, cap["status"]))
            elif not evidence.startswith(("SCOPE-", "D-")) and not (ROOT / evidence).exists():
                problems.append("%s is %s but its evidence %s does not exist"
                                % (name, cap["status"], evidence))
        elif evidence and not evidence.startswith(("SCOPE-", "D-")) \
                and (ROOT / evidence).exists():
            problems.append("%s is %s yet %s exists — one of the two is wrong"
                            % (name, cap["status"], evidence))
        # `design` is deliberately NOT `evidence`. A document describing what is intended
        # is not evidence that it was built - and a PLANNED capability whose design is
        # written down is the honest case, not a contradiction. Recording them under the
        # same key made writing the design read as having implemented it.
        if cap.get("design") and not (ROOT / cap["design"]).exists():
            problems.append("%s names a design document that does not exist: %s"
                            % (name, cap["design"]))
        if cap.get("design") and cap["status"] in ("IMPLEMENTED", "CERTIFIED"):
            problems.append("%s is %s but carries a `design` path; an implemented "
                            "capability is recorded with `evidence`"
                            % (name, cap["status"]))
    floor = REGISTRY["runtime"]["production_python_floor"]
    gate = (ROOT / "scripts" / "ci" / "check_python_floor.py").read_text()
    m = re.search(r"FLOOR = \((\d+), (\d+)\)", gate)
    if m and "%s.%s" % m.groups() != floor:
        problems.append("registry floor %s disagrees with the enforced floor %s.%s"
                        % (floor, m.group(1), m.group(2)))
    freeze = ROOT / "docs" / "architecture" / "freeze" / "W1A_CORE.sha256"
    certified = REGISTRY["capabilities"]["w1a_evidence_contract"]["status"] == "CERTIFIED"
    if certified and not freeze.exists():
        problems.append("W1-A is recorded CERTIFIED but no freeze manifest exists")
    return problems


def counted():
    """Facts counted from the repository, never asserted."""
    def count(cmd):
        try:
            return int(subprocess.check_output(cmd, cwd=str(ROOT), shell=True,
                                               text=True).strip())
        except (subprocess.CalledProcessError, ValueError):
            return None
    gates = json.loads((ROOT / "scripts" / "ci" / "gate_coverage.json").read_text())
    return {
        "gates": len(gates["gates"]),
        "injections": count("grep -c '^inject ' scripts/ci/falsifiable.sh"),
        "vector_cases": count("ls -d test-vectors/w1a/v1/*/ | wc -l"),
        "frozen_artifacts": count("grep -c . docs/architecture/freeze/W1A_CORE.sha256"),
        "test_files": count("ls tests/test_*.py | wc -l"),
    }


def by_status(status):
    return sorted(n for n, c in REGISTRY["capabilities"].items()
                  if c["status"] == status)


def render():
    r, facts = REGISTRY, counted()
    out = ["<!--", "SPDX-License-Identifier: MPL-2.0",
           "SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS",
           "-->", "<!-- %s." % BANNER,
           "     Source: scripts/ci/project_status.json",
           "     Regenerate: python3 scripts/docs/current_state.py generate",
           "     `make check` fails when this file and the registry disagree. -->",
           "", "# Current State", "",
           "**%s**" % BANNER, "",
           "This page exists so that no reader — human or model — mistakes the roadmap or the "
           "architecture", "for shipped functionality. It is generated from one registry, because "
           "the hand-maintained", "version drifted until it announced that no product code "
           "existed while three commands worked.", "",
           "| | |", "|---|---|",
           "| Project stage | **%s** |" % r["project_stage"],
           "| Public release | **%s** |" % r["public_release"],
           "| Production Python floor | %s |" % r["runtime"]["production_python_floor"],
           "| Tooling Python floor | %s |" % r["runtime"]["tooling_python_floor"],
           "| Execution model | %s |" % r["runtime"]["execution_model"],
           "| Runtime dependencies | %s |" % r["runtime"]["dependencies"],
           ""]

    out += ["## Implemented", "",
            "What exists and runs today. Nothing else on this page does.", "",
            "| Capability | Evidence | Command |", "|---|---|---|"]
    for name in by_status("CERTIFIED") + by_status("IMPLEMENTED"):
        cap = r["capabilities"][name]
        out.append("| `%s` | `%s` | %s |"
                   % (name, cap["evidence"] or "—",
                      "`%s`" % cap["command"] if cap.get("command") else "—"))
    out += [""]

    for status, heading, note in (
            ("PLANNED", "Planned", "Designed, not built. No part of this runs."),
            ("DEFERRED", "Deferred", "Deliberately postponed to a later freeze set."),
            ("WRITTEN_NEVER_RUN", "Written, never run",
             "The code is committed and has never executed. Nothing may be displayed "
             "for these: an unexecuted control has produced no evidence in either "
             "direction. See docs/development/GOVERNANCE_GAPS.md."),
            ("NOT_TESTED", "Not tested", "No evidence exists in either direction."),
            ("FUTURE", "Future", "Beyond the current roadmap horizon.")):
        names = by_status(status)
        if not names:
            continue
        out += ["## %s" % heading, "", note, ""]
        for name in names:
            cap = r["capabilities"][name]
            design = " (design: `%s`)" % cap["design"] if cap.get("design") else ""
            out.append("- `%s`%s%s" % (name,
                                       " — %s" % cap["note"] if cap.get("note") else "",
                                       design))
        out += [""]

    p = r["platforms"]
    out += ["## Platforms", "",
            "| | |", "|---|---|",
            "| Architectures measured | %s |" % ", ".join(p["architectures_measured"]),
            "| Architectures **not tested** | %s |"
            % ", ".join(p["architectures_not_tested"]),
            "| Distributions measured | %d: %s |"
            % (len(p["distributions_measured"]), ", ".join(p["distributions_measured"])),
            "| Certified | **none** — %s |" % p["none_certified_because"],
            ""]

    out += ["## Counted from the repository", "",
            "Not asserted. Each number is counted at generation time.", "",
            "| | |", "|---|---|",
            "| Gates | %s |" % facts["gates"],
            "| Falsification injections | %s |" % facts["injections"],
            "| Golden vector cases | %s |" % facts["vector_cases"],
            "| Frozen artifacts | %s |" % facts["frozen_artifacts"],
            "| Test files | %s |" % facts["test_files"],
            ""]

    blockers = r["release_blockers"]
    out += ["## Release blockers", ""]
    if blockers:
        out += ["The public repository is **not** authorized while any of these is open.", ""]
        out += ["- %s" % b for b in blockers]
    else:
        out += ["None recorded."]
    out += [""]
    return "\n".join(out)


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    problems = contradictions()
    if problems:
        print("=== CURRENT_STATE generation REFUSED ===", file=sys.stderr)
        for p in problems:
            print("  FAIL  %s" % p, file=sys.stderr)
        print("  Two authorities disagree. Choosing one silently is how the page drifted.",
              file=sys.stderr)
        return 1
    rendered = render()
    if action == "generate":
        TARGET.write_text(rendered)
        print("  generated %s" % TARGET.relative_to(ROOT))
        return 0
    current = TARGET.read_text() if TARGET.exists() else ""
    if current != rendered:
        print("=== CURRENT_STATE.md is stale ===", file=sys.stderr)
        print("  run: python3 scripts/docs/current_state.py generate", file=sys.stderr)
        return 1
    print("  OK    CURRENT_STATE fresh: %d capabilities, %d release blockers"
          % (len(REGISTRY["capabilities"]), len(REGISTRY["release_blockers"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
