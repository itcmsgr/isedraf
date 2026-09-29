# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Shared AST helpers for the ARCH-01 analysis tools.
# Implements: GOV-001
#
# Analysis tooling may use a modern interpreter; the Python 3.6 production floor
# constrains lib/isedraf, not the instruments pointed at it.
#
# meta:type="analysis"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="docs/development/architecture/generated"
# meta:binaries="git,python3"
"""AST helpers: the code is the authority, never a hand-drawn diagram."""
import ast
import os
import subprocess

ROOT = subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                               text=True).strip()


def python_files(*relative_roots):
    for relative in relative_roots:
        base = os.path.join(ROOT, relative)
        for directory, _dirs, names in os.walk(base):
            if "__pycache__" in directory:
                continue
            for name in sorted(names):
                if name.endswith(".py"):
                    yield os.path.relpath(os.path.join(directory, name), ROOT)


def parse(relative):
    with open(os.path.join(ROOT, relative), "rb") as handle:
        return ast.parse(handle.read(), filename=relative)


def module_name(relative):
    """lib/isedraf/shared/compare.py -> isedraf.shared.compare"""
    path = relative
    if path.startswith("lib/"):
        path = path[4:]
    return path[:-3].replace("/", ".").replace(".__init__", "")


def imports(tree, relative):
    """Absolute module names this file imports, resolving relative imports."""
    current = module_name(relative).split(".")
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = current[:-node.level] if node.level <= len(current) else []
                prefix = ".".join(base + ([node.module] if node.module else []))
                for alias in node.names:
                    out.append(prefix + "." + alias.name if prefix else alias.name)
                    out.append(prefix)
            else:
                out.append(node.module or "")
    return sorted(set(n for n in out if n))


def functions(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def called_names(node):
    """Every attribute and bare name used, for side-effect detection."""
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute):
            names.add(child.attr)
        elif isinstance(child, ast.Name):
            names.add(child.id)
    return names


def docstrings(tree):
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            text = ast.get_docstring(node, clean=False)
            if text:
                out.add(text)
    return out
