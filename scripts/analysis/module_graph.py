# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Import graph, cycles and layer inversions, from the code itself.
# Implements: GOV-001
#
# meta:type="analysis"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="docs/development/architecture/generated"
# meta:binaries="git,python3"
"""Who imports whom, and whether the arrows point the way the architecture claims."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as C                                          # noqa: E402

#: The artifacts this generator owns. The freshness gate reads this rather
#: than keeping a second list that could disagree with reality.
OUTPUTS = ('01_module_dependencies.mmd', '02_module_dependencies.json')

# Layers, lowest first. An import may point DOWN or sideways, never up.
LAYERS = [
    ("core", ("isedraf.canonical", "isedraf.ids", "isedraf.stateroot")),
    ("acquisition", ("isedraf.inventory._exec",)),
    ("shared", ("isedraf.shared",)),
    ("domain", ("isedraf.accounts", "isedraf.inventory", "isedraf.identity",
                "isedraf.snapshot", "isedraf.ledger", "isedraf.verify")),
    ("presentation", ("isedraf.report",)),
    ("entrypoint", ("isedraf.cli",)),
]


def layer_of(module):
    best = None
    for index, (name, prefixes) in enumerate(LAYERS):
        for prefix in prefixes:
            if module == prefix or module.startswith(prefix + "."):
                if best is None or len(prefix) > best[2]:
                    best = (index, name, len(prefix))
    return best[:2] if best else (None, "external")


def build():
    graph, findings = {}, []
    for relative in C.python_files("lib"):
        module = C.module_name(relative)
        targets = [i for i in C.imports(C.parse(relative), relative)
                   if i.startswith("isedraf")]
        # Keep only edges to modules that exist as files.
        graph[module] = sorted(set(targets))
    known = set(graph)
    for module, targets in graph.items():
        src_index, src_layer = layer_of(module)
        for target in targets:
            resolved = target if target in known else ".".join(target.split(".")[:-1])
            if resolved not in known or resolved == module:
                continue
            dst_index, dst_layer = layer_of(resolved)
            if src_index is None or dst_index is None:
                continue
            if dst_index > src_index:
                findings.append({
                    "kind": "LAYER_INVERSION", "from": module, "to": resolved,
                    "detail": "%s (%s) imports %s (%s), which is a higher layer"
                              % (module, src_layer, resolved, dst_layer)})
    return graph, findings, known


def cycles(graph, known):
    found, state = [], {}

    def visit(node, stack):
        state[node] = "OPEN"
        for target in graph.get(node, []):
            resolved = target if target in known else ".".join(target.split(".")[:-1])
            if resolved not in known or resolved == node:
                continue
            if state.get(resolved) == "OPEN":
                found.append(stack[stack.index(resolved):] + [resolved]
                             if resolved in stack else [node, resolved])
            elif resolved not in state:
                visit(resolved, stack + [resolved])
        state[node] = "DONE"

    for node in sorted(graph):
        if node not in state:
            visit(node, [node])
    return found


def _out_dir():
    """Where to write. The gate points this at a temp dir and diffs."""
    target = os.path.join(C.ROOT, "docs/development/architecture/generated")
    for index, arg in enumerate(sys.argv):
        if arg == "--out" and index + 1 < len(sys.argv):
            target = sys.argv[index + 1]
    if not os.path.isdir(target):
        os.makedirs(target)
    return target


def main():
    graph, findings, known = build()
    found_cycles = cycles(graph, known)
    out = _out_dir()

    lines = ["```mermaid", "graph TD"]
    for module in sorted(graph):
        for target in graph[module]:
            resolved = target if target in known else ".".join(target.split(".")[:-1])
            if resolved in known and resolved != module:
                lines.append("    %s --> %s" % (module.replace(".", "_"),
                                                resolved.replace(".", "_")))
    lines.append("```")
    with open(os.path.join(out, "01_module_dependencies.mmd"), "w") as handle:
        handle.write("\n".join(sorted(set(lines[2:-1]))).join(["```mermaid\ngraph TD\n",
                                                               "\n```\n"]))
    with open(os.path.join(out, "02_module_dependencies.json"), "w") as handle:
        json.dump({"edges": graph, "layer_inversions": findings,
                   "cycles": found_cycles}, handle, indent=2, sort_keys=True)

    print("  modules: %d" % len(graph))
    print("  cycles: %s" % (found_cycles or "NONE"))
    print("  layer inversions: %d" % len(findings))
    for finding in findings:
        print("    %s" % finding["detail"])
    return 1 if findings or found_cycles else 0


if __name__ == "__main__":
    sys.exit(main())
