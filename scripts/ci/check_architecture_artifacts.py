# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The committed architecture artifacts must still describe the code.
# Implements: GOV-001, GOV-002
#
# ARCH-01 produced ten artifacts and, during merge verification, one of them was already
# stale: the I/O side-effect map predated the very gate it was supposed to record. It was
# caught by regenerating and diffing by hand. Nothing would have caught it otherwise, and
# ARCH-02 would have reviewed a diagram of an architecture that no longer existed.
#
# Two failures are gated here, not one:
#
#   STALENESS   the code moved and the artifact did not
#   FICTION     the artifact was edited directly to describe a wished-for architecture
#
# Both are detected the same way - regenerate, compare bytes - which is why the prose
# artifacts are generated too rather than only the derived ones.
#
# The file list is NOT maintained here. Each generator declares OUTPUTS, and this gate
# reads that, so a new artifact cannot be added without being covered.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================

"""usage: check_architecture_artifacts.py"""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
ANALYSIS = os.path.join(ROOT, "scripts", "analysis")
COMMITTED = os.path.join(ROOT, "docs", "development", "architecture", "generated")
FAIL = []


def bad(message):
    FAIL.append(message)
    print("  FAIL  %s" % message)


def generators():
    """Every module under scripts/analysis that declares OUTPUTS."""
    found = []
    for name in sorted(os.listdir(ANALYSIS)):
        if not name.endswith(".py") or name.startswith("_"):
            continue
        path = os.path.join(ANALYSIS, name)
        spec = importlib.util.spec_from_file_location("gen_" + name[:-3], path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:                          # pragma: no cover
            bad("%s could not be imported: %s" % (name, exc))
            continue
        if hasattr(module, "OUTPUTS"):
            found.append((name, tuple(module.OUTPUTS)))
    return found


def run(name, out):
    result = subprocess.run(
        [sys.executable, os.path.join(ANALYSIS, name), "--out", out],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        bad("%s failed to run: %s" % (name, result.stdout.decode("utf-8", "replace")[-300:]))
    return result.returncode == 0


def main():
    found = generators()
    if not found:
        # Z-18: a gate that passes over an empty input is not a gate.
        bad("no generator declares OUTPUTS; nothing was verified")
        print("=== architecture artifact freshness gate FAILED ===")
        return 1

    declared = []
    for _name, outputs in found:
        declared.extend(outputs)
    duplicates = sorted(set(a for a in declared if declared.count(a) > 1))
    if duplicates:
        bad("two generators claim the same artifact: %s" % ", ".join(duplicates))

    first = tempfile.mkdtemp()
    second = tempfile.mkdtemp()
    try:
        for name, _outputs in found:
            run(name, first)
            run(name, second)

        # 1. Deterministic: two runs of the same code produce the same bytes. Without
        #    this, a drift failure could not be distinguished from a flaky generator.
        for artifact in sorted(declared):
            a, b = os.path.join(first, artifact), os.path.join(second, artifact)
            if not os.path.exists(a):
                bad("%s was declared but not produced" % artifact)
                continue
            if open(a, "rb").read() != open(b, "rb").read():
                bad("%s is not deterministic: two consecutive generations differ"
                    % artifact)

        # 2. Current: the committed bytes are what the generator produces today.
        for artifact in sorted(declared):
            fresh = os.path.join(first, artifact)
            committed = os.path.join(COMMITTED, artifact)
            if not os.path.exists(fresh):
                continue
            if not os.path.exists(committed):
                bad("%s is generated but not committed" % artifact)
                continue
            if open(fresh, "rb").read() != open(committed, "rb").read():
                bad("%s no longer matches its generator: the committed artifact "
                    "describes something the code does not do" % artifact)

        # 3. Nothing extra: an artifact nobody generates cannot be trusted.
        for name in sorted(os.listdir(COMMITTED)):
            if name not in declared:
                bad("%s is committed but no generator produces it" % name)
    finally:
        shutil.rmtree(first, ignore_errors=True)
        shutil.rmtree(second, ignore_errors=True)

    if FAIL:
        print("=== architecture artifact freshness gate FAILED ===")
        print("  run: %s" % " && ".join(
            "python3 scripts/analysis/%s" % n for n, _ in found))
        return 1
    print("  OK    architecture artifacts: %d from %d generators, deterministic and "
          "current" % (len(declared), len(found)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
