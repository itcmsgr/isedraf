# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The ARCH-01 artifacts that were produced inline and could not be regenerated.
# Implements: GOV-001
#
# Seven of the ten ARCH-01 artifacts were written by throwaway inline scripts. They were
# therefore unreproducible: nothing could tell whether a committed diagram still described
# the code, and nothing stopped someone editing a diagram to match an architecture they
# wished existed. Both halves matter, which is why the prose artifacts are generated from
# here too rather than only the derived ones.
#
# DERIVED artifacts are computed from the code. AUTHORED artifacts hold prose that lives
# in this file; gating them means an edit must happen at the source, not in the output.
#
# meta:type="analysis"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="docs/development/architecture/generated"
# meta:binaries="git,python3"
"""The remaining ARCH-01 artifacts, with one authoritative source each."""
import csv
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as C                                          # noqa: E402

OUTPUTS = ("03_critical_call_trees.md", "04_evidence_flow.mmd",
           "05_status_semantics.md", "06_field_lineage.csv",
           "08_trust_boundaries.mmd", "09_gate_ci_graph.mmd",
           "10_falsification_coverage.md")

HEADER = ("<!--\nSPDX-License-Identifier: MPL-2.0\n"
          "SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS\n-->\n")

PROSE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arch01_prose")


def _out_dir():
    target = os.path.join(C.ROOT, "docs/development/architecture/generated")
    for index, arg in enumerate(sys.argv):
        if arg == "--out" and index + 1 < len(sys.argv):
            target = sys.argv[index + 1]
    if not os.path.isdir(target):
        os.makedirs(target)
    return target


def field_lineage(out):
    """DERIVED from the real CLASSIFICATION tables, not from a written-down copy."""
    sys.path.insert(0, os.path.join(C.ROOT, "lib"))
    from isedraf.accounts import model as accounts_model
    from isedraf.inventory import model as inventory_model
    from isedraf.shared import filemeta, result as shared_result

    rows = []

    def add(table, origin, module, privacy):
        for field, category in sorted(table.items()):
            rows.append({"field": field, "origin": origin, "module": module,
                         "scope_045": category,
                         "hashed_if_state": "yes" if category == "STATE" else "no",
                         "privacy": privacy})

    add(accounts_model.CLASSIFICATION, "/etc/passwd,/etc/group,/etc/shadow",
        "accounts.model", "medium")
    add(filemeta.CLASSIFICATION, "lstat(2)", "shared.filemeta", "low")
    add(shared_result.CLASSIFICATION, "shared primitives", "shared.result", "low")
    for field in sorted(inventory_model.CLASSIFICATION):
        rows.append({"field": "inventory." + field, "origin": "inventory collectors",
                     "module": "inventory.model",
                     "scope_045": "(domain sub-classification)",
                     "hashed_if_state": "n/a - outside the snapshot (SNAP-021)",
                     "privacy": "low"})

    # A prohibited field reaching a classification table would mean it is emitted.
    blob = " ".join(row["field"] for row in rows)
    for forbidden in ("password_hash", "raw_password", "created_at", "creation_time",
                      "physical_medium", "transport", "is_aggregate"):
        if forbidden in blob:
            raise SystemExit("prohibited field %r is classified, and therefore emitted"
                             % forbidden)

    path = os.path.join(out, "06_field_lineage.csv")
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["field", "origin", "module",
                                                    "scope_045", "hashed_if_state",
                                                    "privacy"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)


def falsification_coverage(out):
    """DERIVED from the harness. A large total is not coverage if it attacks one area."""
    harness = open(os.path.join(C.ROOT, "scripts/ci/falsifiable.sh")).read()
    names = re.findall(r'^inject "([^"]+)"', harness, re.M)
    buckets = [
        ("W1-A / canonical", ("NORM-", "Z-1", "Z-2", "SNAP-", "STORE-", "IDENT-")),
        ("inventory / storage D-114", ("D-114",)),
        ("accounts W1-D", ("W1D",)),
        ("S1 key/value", ("S1 ",)), ("S2 include graph", ("S2 ",)),
        ("S3 comparison", ("S3 ",)), ("S4 file metadata", ("S4 ",)),
        ("S5 enumeration", ("S5 ",)), ("architecture", ("ARCH",)),
        ("privacy / disclosure", ("D-90", "PUBLIC-OPS")),
        ("licensing / framework", ("D-84", "D-111", "C-0")),
        ("packaging / release", ("D-86", "D-17", "EXEC-016")),
        ("governance / gates", ("GOV-", "D-93", "D-96", "U-2", "IQ-011")),
        ("docs truth", ("C-05", "C-06", "D-87", "D-88", "D-89", "D-113")),
    ]
    assigned, rows = set(), []
    for label, prefixes in buckets:
        hits = [n for n in names
                if any(n.startswith(p) for p in prefixes) and n not in assigned]
        assigned.update(hits)
        rows.append((label, len(hits)))
    rows.append(("other / cross-cutting", len([n for n in names if n not in assigned])))

    with open(os.path.join(out, "10_falsification_coverage.md"), "w") as handle:
        handle.write(HEADER + "# Falsification coverage by subsystem\n\n"
                     "Status: IMPLEMENTED\n\nGENERATED from `scripts/ci/falsifiable.sh`. "
                     "A large total is not coverage if most of it attacks one "
                     "subsystem.\n\n| Subsystem | Injections |\n|---|---|\n")
        for label, count in rows:
            handle.write("| %s | %d |\n" % (label, count))
        handle.write("| **total** | **%d** |\n" % len(names))
    return len(names)


def gate_graph(out):
    """DERIVED from the Makefile and the workflows, never hand-drawn."""
    makefile = open(os.path.join(C.ROOT, "Makefile")).read()
    aggregate = re.search(r"^check:\s*(.+)$", makefile, re.M).group(1).split()
    workflow_dir = os.path.join(C.ROOT, ".github/workflows")
    lines = ["```mermaid", "graph LR", '    MC["make check"]']
    for gate in aggregate:
        lines.append('    MC --> %s["%s"]' % (gate.replace("-", "_"), gate))
    for name in sorted(os.listdir(workflow_dir)):
        if not name.endswith(".yml"):
            continue
        text = open(os.path.join(workflow_dir, name)).read()
        key = re.sub(r"\W", "_", name)
        lines.append('    %s(["%s"])' % (key, name))
        for run in sorted(set(re.findall(
                r"run:\s*(make [a-z-]+|bash scripts/ci/[a-z_]+\.sh)", text))):
            lines.append('    %s --> %s["%s"]' % (key, re.sub(r"\W", "_", run), run))
    lines.append("```")
    with open(os.path.join(out, "09_gate_ci_graph.mmd"), "w") as handle:
        handle.write("\n".join(lines) + "\n")
    return len(aggregate)


def prose(out):
    """AUTHORED here, emitted from here.

    Gating these means a correction must be made at the source. Editing a committed
    diagram to describe an architecture someone wished existed would otherwise be
    invisible, which is a different failure from staleness and just as bad.
    """
    count = 0
    for name in ("03_critical_call_trees.md", "04_evidence_flow.mmd",
                 "05_status_semantics.md", "08_trust_boundaries.mmd"):
        source = os.path.join(PROSE, name)
        with open(source) as handle:
            body = handle.read()
        with open(os.path.join(out, name), "w") as handle:
            handle.write((HEADER + body) if name.endswith(".md") else body)
        count += 1
    return count


def main():
    out = _out_dir()
    fields = field_lineage(out)
    injections = falsification_coverage(out)
    gates = gate_graph(out)
    authored = prose(out)
    print("  field lineage rows: %d" % fields)
    print("  injections classified: %d" % injections)
    print("  gates in make check: %d" % gates)
    print("  authored artifacts emitted: %d" % authored)
    return 0


if __name__ == "__main__":
    sys.exit(main())
