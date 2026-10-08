# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
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
import ast
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

# --- registry truth (IQ-043, IQ-035) -------------------------------------------------------
# The registry is derived truth, not a status page someone remembers to update. Every
# capability carries four closed fields, and the gate compares them with the code in both
# directions: a surface or section the code exposes must have an IMPLEMENTED entry, and an
# entry that names a surface or section must name one that exists.
TRUTH_FIELDS = ("reachable_from", "audit_section", "authority", "full_audit_gain")
IMPLEMENTED_STATES = ("IMPLEMENTED", "CERTIFIED")
NOT_APPLICABLE = "NOT_APPLICABLE"
#: full_audit_gain is derived from scripts/ci/privileged_operations.json (D-123): what the
#: registered fixed operations serving the section would add. Never narrative.
GAIN = ("NONE", "PLANNED_FIXED_OPERATION", "DESIGN_OPEN_OPERATION", NOT_APPLICABLE)
#: Output flags that make a distinct public surface of a command.
OUTPUT_FLAGS = ("--json", "--html")
#: The snapshot core is a section too, though it is not one of the audit sections.
CORE_SECTIONS = ("host_identity",)


def audit_sections():
    sys.path.insert(0, str(ROOT / "lib"))
    from isedraf import snapshot
    return tuple(snapshot.SECTION_NAMES) + CORE_SECTIONS


def acquisition_modes():
    """The source authorities the code admits today (coverage.MODES, D-122/D-123)."""
    sys.path.insert(0, str(ROOT / "lib"))
    from isedraf import coverage
    return tuple(coverage.MODES)


def privileged_operations():
    path = ROOT / "scripts" / "ci" / "privileged_operations.json"
    return json.loads(path.read_text())["operations"]


def cli_surfaces(source=None):
    """Public surfaces read from the argument parser in lib/isedraf/cli.py, not listed by
    hand: every subcommand, and every output flag a subcommand declares."""
    if source is None:
        source = (ROOT / "lib" / "isedraf" / "cli.py").read_text()
    commands, surfaces = {}, set()
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
            continue
        call = node.value
        if (isinstance(call.func, ast.Attribute) and call.func.attr == "add_parser"
                and call.args and isinstance(call.args[0], ast.Constant)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    commands[target.id] = call.args[0].value
            surfaces.add(call.args[0].value)
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in commands and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in OUTPUT_FLAGS):
            surfaces.add("%s %s" % (commands[node.func.value.id], node.args[0].value))
    return surfaces


def _gain(section, operations):
    serving = [o for o in operations if o["serves"] == section]
    if any(o["status"] in ("PLANNED", "IMPLEMENTED") for o in serving):
        return "PLANNED_FIXED_OPERATION"
    if any(o["status"] == "DESIGN_OPEN" for o in serving):
        return "DESIGN_OPEN_OPERATION"
    return "NONE"


def registry_truth(capabilities, sections, surfaces, operations, modes):
    """Both directions, against the code. Returns problems; empty means true."""
    problems = []
    authorities = tuple(modes) + (NOT_APPLICABLE,)
    covered_sections, covered_surfaces = {}, set()
    for name, cap in sorted(capabilities.items()):
        missing = [f for f in TRUTH_FIELDS if f not in cap]
        if missing:
            problems.append("%s lacks %s" % (name, ", ".join(missing)))
            continue
        reach, section = cap["reachable_from"], cap["audit_section"]
        implemented = cap["status"] in IMPLEMENTED_STATES
        if not isinstance(reach, list) or reach != sorted(set(reach)):
            problems.append("%s reachable_from is not a sorted unique list" % name)
            reach = []
        for surface in reach:
            if surface not in surfaces:
                problems.append("%s names surface %r, which the CLI does not expose"
                                % (name, surface))
        if section is not None and section not in sections:
            problems.append("%s names audit section %r, which does not exist"
                            % (name, section))
        if (reach or section) and not implemented:
            problems.append("%s is %s but is reachable (%s); a reachable capability is "
                            "IMPLEMENTED" % (name, cap["status"], reach or section))
        if cap["authority"] not in authorities:
            problems.append("%s authority %r is not one of %s"
                            % (name, cap["authority"], authorities))
        if section is not None and cap["authority"] not in modes:
            problems.append("%s acquires section %s but its authority is %r"
                            % (name, section, cap["authority"]))
        expected_gain = (_gain(section, operations) if section is not None
                         else "NONE" if reach else NOT_APPLICABLE)
        if cap["full_audit_gain"] != expected_gain:
            problems.append("%s full_audit_gain is %r; the operation registry gives %r"
                            % (name, cap["full_audit_gain"], expected_gain))
        if implemented:
            covered_surfaces.update(reach)
            if section is not None:
                covered_sections.setdefault(section, []).append(name)
    for section in sections:
        owners = covered_sections.get(section, [])
        if len(owners) != 1:
            problems.append("audit section %s has %d IMPLEMENTED registry entries (%s); "
                            "exactly one is required" % (section, len(owners),
                                                         ", ".join(owners) or "none"))
    for surface in sorted(surfaces - covered_surfaces):
        problems.append("public surface %r is reachable but no IMPLEMENTED registry entry "
                        "names it" % surface)
    return problems


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
    problems += registry_truth(REGISTRY["capabilities"], audit_sections(), cli_surfaces(),
                               privileged_operations(), acquisition_modes())
    floor = REGISTRY["runtime"]["production_python_floor"]
    gate = (ROOT / "scripts" / "ci" / "check_python_floor.py").read_text()
    m = re.search(r"FLOOR = \((\d+), (\d+)\)", gate)
    if m and "%s.%s" % m.groups() != floor:
        problems.append("registry floor %s disagrees with the enforced floor %s.%s"
                        % (floor, m.group(1), m.group(2)))
    # Either manifest satisfies this: the full set exists only in the engineering
    # repository, the public subset in both, and their digests are the same bytes.
    # Requiring the full one made the page ungeneratable in a public checkout, which is
    # a statement about which repository you are in, not about whether W1-A is certified.
    freeze_dir = ROOT / "docs" / "architecture" / "freeze"
    freeze = [m for m in ("W1A_CORE.sha256", "W1A_CORE_PUBLIC.sha256")
              if (freeze_dir / m).exists()]
    certified = REGISTRY["capabilities"]["w1a_evidence_contract"]["status"] == "CERTIFIED"
    if certified and not freeze:
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
        # Anchored at the line start this undercounted by one: a single injection is
        # indented inside a next_requires guard, so the page published 194 while the
        # harness executed 195. An undercount is a smaller lie than an overcount and
        # still a lie.
        "injections": count(
            "grep -cE '^[[:space:]]*inject ' scripts/ci/falsifiable.sh"),
        "vector_cases": count("ls -d test-vectors/w1a/v1/*/ | wc -l"),
        # The PUBLISHED freeze set, deliberately - this page describes the published
        # project, and counting the engineering set would make the same page generate
        # two different numbers in two checkouts of the same commit. The full set is
        # one artifact larger; the extra one is internal and is listed in
        # docs/architecture/INTERNAL_RECORDS.md.
        "frozen_artifacts": count(
            "grep -c . docs/architecture/freeze/W1A_CORE_PUBLIC.sha256"),
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
