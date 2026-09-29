# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Enforce the architecture, because a diagram cannot fail a build.
# Implements: GOV-001, GOV-002, SCOPE-022, SCOPE-045
#
# ARCH-01 produced generated diagrams and this file. The diagrams describe; this decides.
# The first run of the dependency analysis found a real shared -> domain inversion:
# shared/result.py imported isedraf.inventory.model for four status constants, and
# shared/include_graph.py imported isedraf.inventory for a file reader - and because
# inventory/__init__.py does `from . import collectors`, a generic include-graph
# primitive transitively pulled in all nine inventory collectors. Nothing failed. Nothing
# would have failed until a domain worker wondered why the SSH lane depended on the
# storage collector.
#
# The rules below are semantic, not conventions about filenames. Each one states a thing
# that must be true of the evidence pipeline:
#
#   SOURCE -> ACQUISITION -> PARSER -> NORMALIZED EVIDENCE -> COMPARISON -> REPORT
#
# and forbids the reverse edges that would make the pipeline a lie.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================

"""usage: check_architecture.py [--self-test]"""
import ast
import os
import subprocess
import sys

ROOT = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()

# Layers, lowest first. An import may point down or sideways, never up.
#
# EVERY production module must appear here (rule 7). It did not always: the four Batch 2
# domain lanes - ssh, sudo, pam, loginpolicy - matched no prefix, so `layer_of` returned
# "external" and rule 1 skipped them in silence. Four domains were exempt from the
# layering rule for the whole of Batch 2 and nothing said so. An unlisted module being
# exempt rather than refused is the failure mode where adding a file quietly removes it
# from the gate, so the list is now closed and a new module must be placed deliberately.
#
# The package root is placed by EXACT name. As a prefix, "isedraf" would match every
# module in the project and classify anything unlisted as core by accident - which is the
# same silent-exemption defect in a new costume.
CORE_EXACT = ("isedraf",)

LAYERS = [
    ("core", ("isedraf.canonical", "isedraf.ids", "isedraf.status",
              "isedraf.stateroot", "isedraf.hostio", "isedraf.hostpath",
              "isedraf.coverage",
              "isedraf.textbytes", "isedraf.exitcodes")),
    ("shared", ("isedraf.shared",)),
    ("domain", ("isedraf.accounts", "isedraf.inventory", "isedraf.identity",
                "isedraf.snapshot", "isedraf.ledger", "isedraf.verify",
                "isedraf.ssh", "isedraf.sudo", "isedraf.pam",
                "isedraf.loginpolicy", "isedraf.authorizedkeys",
                "isedraf.mounts", "isedraf.nss", "isedraf.hostname",
                # GA track: orchestrates the domain collectors for one audit run; it
                # collects, never renders, so it sits below presentation.
                "isedraf.audit")),
    ("presentation", ("isedraf.report",)),
    ("entrypoint", ("isedraf.cli",)),
]

# Modules that must perform NO host I/O at all: they take data and return data.
PURE = ("isedraf.shared.keyvalue", "isedraf.shared.compare", "isedraf.shared.result",
        "isedraf.accounts.sources", "isedraf.canonical", "isedraf.status",
        "isedraf.hostpath", "isedraf.textbytes", "isedraf.coverage",
        "isedraf.ssh.sources",
        "isedraf.sudo.sources", "isedraf.pam.sources",
        "isedraf.loginpolicy.sources", "isedraf.authorizedkeys.sources",
        "isedraf.authorizedkeys.model",
        "isedraf.mounts.sources", "isedraf.mounts.model",
        "isedraf.nss.sources", "isedraf.nss.model",
        "isedraf.hostname.sources", "isedraf.hostname.model")

IO_MARKERS = ("open", "listdir", "lstat", "scandir", "readlink", "Popen",
              "check_output", "system", "execv", "socket", "urlopen")
NETWORK_MARKERS = ("socket", "urlopen", "create_connection", "getaddrinfo",
                   "HTTPConnection", "HTTPSConnection", "gethostbyname", "urlretrieve")

# The presentation layer renders committed evidence. It may READ the evidence store; it
# may not collect. Rendering that re-collected would describe something the ledger never
# saw, which is the whole argument in report/model.py's docstring.
ACQUISITION = ("isedraf.hostio", "isedraf.inventory.collectors",
               "isedraf.accounts.acquire", "isedraf.shared.bounded",
               "isedraf.shared.filemeta", "isedraf.shared.include_graph",
               "isedraf.authorizedkeys.acquire", "isedraf.mounts.acquire",
               "isedraf.nss.acquire", "isedraf.hostname.acquire")

FAIL = []


def bad(msg):
    FAIL.append(msg)
    print("  FAIL  %s" % msg)


def files():
    out = subprocess.check_output(["git", "ls-files", "lib"], cwd=ROOT, text=True)
    return [f for f in out.splitlines() if f.endswith(".py")]


def module_of(relative):
    return relative[4:-3].replace("/", ".").replace(".__init__", "")


def imports_of(tree, module):
    current = module.split(".")
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = current[:-node.level] if node.level <= len(current) else []
                prefix = ".".join(base + ([node.module] if node.module else []))
                if prefix:
                    out.append(prefix)
                for alias in node.names:
                    out.append((prefix + "." + alias.name) if prefix else alias.name)
            else:
                out.append(node.module or "")
    return sorted(set(n for n in out if n.startswith("isedraf")))


def layer_of(module):
    if module in CORE_EXACT:
        return 0, LAYERS[0][0]
    best = None
    for index, (name, prefixes) in enumerate(LAYERS):
        for prefix in prefixes:
            if module == prefix or module.startswith(prefix + "."):
                if best is None or len(prefix) > best[2]:
                    best = (index, name, len(prefix))
    return best[:2] if best else (None, "external")


def names_used(node):
    used = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute):
            used.add(child.attr)
        elif isinstance(child, ast.Name):
            used.add(child.id)
    return used


def check(paths):
    known = set(module_of(p) for p in paths)
    for relative in paths:
        module = module_of(relative)
        with open(os.path.join(ROOT, relative), "rb") as handle:
            tree = ast.parse(handle.read(), filename=relative)
        targets = imports_of(tree, module)
        used = names_used(tree)
        index, layer = layer_of(module)

        # --- 1. no upward imports -------------------------------------------------
        for target in targets:
            resolved = target if target in known else ".".join(target.split(".")[:-1])
            if resolved not in known or resolved == module:
                continue
            target_index, target_layer = layer_of(resolved)
            if index is None or target_index is None:
                continue
            if target_index > index:
                bad("%s (%s) imports %s (%s): a lower layer must not depend on a "
                    "higher one" % (module, layer, resolved, target_layer))

        # --- 2. shared must not reach a domain -------------------------------------
        if module.startswith("isedraf.shared"):
            for target in targets:
                for _, prefixes in LAYERS[2:]:
                    for prefix in prefixes:
                        if target == prefix or target.startswith(prefix + "."):
                            bad("%s imports the domain module %s; shared primitives "
                                "must not know their consumers" % (module, target))

        # --- 3. pure modules perform no host I/O ------------------------------------
        if module in PURE:
            for marker in IO_MARKERS:
                if marker in used:
                    bad("%s is a pure module but uses %r: its results must depend only "
                        "on its arguments" % (module, marker))

        # --- 4. nothing anywhere reaches the network --------------------------------
        for marker in NETWORK_MARKERS:
            if marker in used:
                bad("%s uses %r: ordinary collection and reporting make no network "
                    "requests" % (module, marker))

        # --- 5. presentation does not acquire ---------------------------------------
        if module.startswith("isedraf.report"):
            for target in targets:
                if target in ACQUISITION:
                    bad("%s imports %s: a renderer must describe committed evidence, "
                        "never collect new evidence" % (module, target))

    # --- 7. every production module is placed in a layer ----------------------------
    # An unlisted module must be a failure, not an exemption. See LAYERS.
    for relative in paths:
        module = module_of(relative)
        if layer_of(module) == (None, "external"):
            bad("%s belongs to no layer: an unclassified module is silently exempt "
                "from the layering rule, so it must be placed deliberately" % module)

    # --- 6. one status vocabulary, defined once -------------------------------------
    definers = []
    for relative in paths:
        with open(os.path.join(ROOT, relative), "rb") as handle:
            tree = ast.parse(handle.read(), filename=relative)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Name) and target.id == "COLLECTED"
                            and isinstance(node.value, ast.Constant)):
                        definers.append(module_of(relative))
    if len(set(definers)) > 1:
        bad("the collection status vocabulary is defined in more than one place: %s"
            % ", ".join(sorted(set(definers))))
    elif definers and set(definers) != {"isedraf.status"}:
        bad("the collection status vocabulary is defined in %s, not isedraf.status"
            % ", ".join(sorted(set(definers))))


def self_test():
    """A gate that has never been observed to fail is not a gate."""
    import tempfile
    checks = [
        ("shared importing a domain",
         "isedraf/shared/x.py", "from ..accounts import model\n"),
        ("a pure module opening a file",
         "isedraf/shared/compare.py", "def f():\n    return open('/etc/passwd')\n"),
        ("a network call",
         "isedraf/shared/y.py", "import socket\ndef f():\n    return socket.socket()\n"),
        ("a renderer acquiring",
         "isedraf/report/z.py", "from .. import hostio\n"),
        ("a module belonging to no layer",
         "isedraf/brandnew/thing.py", "VALUE = 1\n"),
    ]
    global FAIL
    errors = 0
    for label, relative, source in checks:
        base = tempfile.mkdtemp()
        full = os.path.join(base, "lib", relative)
        os.makedirs(os.path.dirname(full))
        with open(full, "w") as handle:
            handle.write(source)
        saved_root = globals()["ROOT"]
        globals()["ROOT"] = base
        FAIL = []
        try:
            check([os.path.join("lib", relative)])
        finally:
            globals()["ROOT"] = saved_root
        if not FAIL:
            print("  SELFTEST FAIL  not detected: %s" % label)
            errors += 1
    FAIL = []
    if errors:
        print("=== architecture self-test FAILED ===")
        return 1
    print("  OK    architecture self-test: %d violations detected, 0 missed"
          % len(checks))
    return 0


def main():
    if "--self-test" in sys.argv:
        return self_test()
    paths = files()
    if not paths:
        bad("no production files were analysed; the gate cannot have verified anything")
    check(paths)
    if FAIL:
        print("=== architecture gate FAILED ===")
        print("  The evidence pipeline is SOURCE -> ACQUISITION -> PARSER -> NORMALIZED")
        print("  EVIDENCE -> COMPARISON -> REPORT. Each failure above is an edge that")
        print("  points the wrong way along it.")
        return 1
    print("  OK    architecture: %d modules, no upward imports, no shared/domain "
          "inversion," % len(paths))
    print("        no I/O in pure modules, no network path, no renderer acquisition, "
          "one status vocabulary,")
    print("        every module placed in a layer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
