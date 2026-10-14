#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: D-83 - the governance files are unchanged unless the owner updated the manifest.
# Implements: D-83, GOV-001, GOV-002
#
# docs/development/GOVERNANCE_MANIFEST.sha256 (sha256sum format, owner-controlled) lists the
# files D-83 names, as they exist in this repository:
#   CLAUDE.md                          CLAUDE.md
#   git-hooks/*                        every tracked file under git-hooks/
#   the frozen-manifest verifier       scripts/ci/check_freeze.sh
#   lib/isedraf/exitcodes.json         lib/isedraf/exitcodes.json
#   the runtime module allowlist       lib/isedraf/runtime-imports.allow
#   the doc lint config                scripts/docs/doclint.py (the rules live in it; there is
#                                      no separate configuration file)
#   .claude/settings.json              NOT PRESENT in the repository; recorded absent, and this
#                                      gate fails if it appears without being added
# The gate fails when the manifest lists any other set, when a digest differs, or when an
# installed .git/hooks/<name> differs from git-hooks/<name>. Where no hook is installed (CI, a
# fresh clone) parity is not checked and the gate says so (G-03 is local only).
#
# The public release export (D-110) deliberately omits CLAUDE.md, which the manifest lists. The
# absence of a listed file alone NEVER changes the rule: deleting CLAUDE.md from an engineering
# checkout fails exactly as before. A tree is judged a release export only when it carries the
# export marker docs/development/PUBLIC_EXPORT.sha256, written by scripts/ci/release_export.sh,
# and all of these hold (D-83, IQ-069):
#   - every path scripts/ci/release_surface.txt excludes from publication (its `!` lines) is
#     absent, so a marker in an engineering checkout is itself a failure;
#   - the marker is a regular file, not a symlink, whose two sha256sum lines bind this tree's
#     governance manifest and release surface, byte for byte;
# Then, and only then, a listed file that the release surface excludes may be absent; every
# other listed file is still required and digest-checked, and the listed set is unchanged.
# This guards against accidental or casual change, like the rest of D-83, not against someone
# who rewrites the tree and the marker together.
#
# meta:type="gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""D-83 governance manifest."""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = "docs/development/GOVERNANCE_MANIFEST.sha256"
FIXED = ("CLAUDE.md", "scripts/ci/check_freeze.sh", "lib/isedraf/exitcodes.json",
         "lib/isedraf/runtime-imports.allow", "scripts/docs/doclint.py")
ABSENT = (".claude/settings.json",)
EXPORT_MARKER = "docs/development/PUBLIC_EXPORT.sha256"
SURFACE = "scripts/ci/release_surface.txt"


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unpublished_paths(root):
    surface = root / SURFACE
    if not surface.is_file():
        return []
    return [line.strip()[1:] for line in surface.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("!")]


def export_marker_text(root):
    """The marker release_export.sh writes: it binds the manifest and the release surface."""
    return "".join("%s  %s\n" % (sha256_file(root / rel), rel) for rel in (MANIFEST, SURFACE))


def export_context(root):
    """(paths a release export may omit, problems). No marker: the engineering rule, nothing omitted."""
    marker = root / EXPORT_MARKER
    if not (marker.exists() or marker.is_symlink()):
        return set(), []
    problems = []
    if marker.is_symlink() or not marker.is_file():
        problems.append("%s is not a regular file" % EXPORT_MARKER)
    excluded = unpublished_paths(root)
    if not excluded:
        problems.append("%s exists, but %s excludes nothing from publication" % (EXPORT_MARKER, SURFACE))
    for rel in excluded:
        if (root / rel).exists() or (root / rel).is_symlink():
            problems.append("%s exists, but %s is present: the export marker is valid only in a "
                            "release export, never in the engineering repository" % (EXPORT_MARKER, rel))
    if not problems:
        try:
            bound = marker.read_text(encoding="utf-8") == export_marker_text(root)
        except (OSError, UnicodeDecodeError):
            bound = False
        if not bound:
            problems.append("%s does not bind this tree's %s and %s" % (EXPORT_MARKER, MANIFEST, SURFACE))
    return (set() if problems else set(excluded)), problems


def expected_set(root):
    hooks = sorted(str(p.relative_to(root)) for p in (root / "git-hooks").iterdir() if p.is_file())
    return set(FIXED) | set(hooks)


def parse(text):
    entries, problems = {}, []
    for number, line in enumerate(text.splitlines(), start=1):
        digest, sep, path = line.partition("  ")
        if not sep or len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest) or not path:
            problems.append("manifest line %d is not a sha256sum line" % number)
            continue
        if path in entries:
            problems.append("manifest lists %s twice" % path)
        entries[path] = digest
    return entries, problems


def check(root, manifest_text, hooks_dir):
    entries, problems = parse(manifest_text)
    omissible, context_problems = export_context(root)
    problems.extend(context_problems)
    unpublished = 0
    wanted = expected_set(root)
    for path in sorted(wanted - set(entries)):
        problems.append("%s is a D-83 governance file the manifest does not list" % path)
    for path in sorted(set(entries) - wanted):
        problems.append("the manifest lists %s, which D-83 does not name" % path)
    for path, digest in sorted(entries.items()):
        target = root / path
        if path in omissible and not (target.exists() or target.is_symlink()):
            unpublished += 1
        elif not target.is_file():
            problems.append("%s is listed but missing" % path)
        elif hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            problems.append("%s changed without an owner update of the manifest" % path)
    for path in ABSENT:
        if (root / path).exists():
            problems.append("%s now exists; D-83 names it, so the owner must add it to the manifest"
                            % path)
    checked = 0
    if hooks_dir is not None and hooks_dir.is_dir():
        for hook in sorted((root / "git-hooks").iterdir()):
            installed = hooks_dir / hook.name
            if installed.exists():
                checked += 1
                if installed.read_bytes() != hook.read_bytes():
                    problems.append("installed .git/hooks/%s differs from git-hooks/%s"
                                    % (hook.name, hook.name))
    return problems, len(entries), checked, unpublished


def self_test():
    """Each failure shape fires on a synthetic tree; a consistent one passes."""
    import tempfile
    base = pathlib.Path(tempfile.mkdtemp())
    try:
        for rel in FIXED + ("git-hooks/pre-commit",):
            (base / rel).parent.mkdir(parents=True, exist_ok=True)
            (base / rel).write_bytes(rel.encode())
        hooks = base / ".git" / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "pre-commit").write_bytes(b"git-hooks/pre-commit")

        def manifest(skip=None, extra=None, bad=None):
            lines = []
            for rel in sorted(expected_set(base)):
                if rel == skip:
                    continue
                digest = hashlib.sha256((base / rel).read_bytes()).hexdigest()
                lines.append("%s  %s" % ("0" * 64 if rel == bad else digest, rel))
            if extra:
                lines.append("%s  %s" % ("0" * 64, extra))
            return "\n".join(lines) + "\n"
        cases = [(manifest(), False), (manifest(skip="CLAUDE.md"), True),
                 (manifest(extra="README.md"), True), (manifest(bad="lib/isedraf/exitcodes.json"), True),
                 ("not a manifest\n", True)]
        wrong = [i for i, (text, bad) in enumerate(cases)
                 if bool(check(base, text, hooks)[0]) != bad]
        wrong += export_self_test(base, manifest)
        (hooks / "pre-commit").write_bytes(b"tampered")
        if not check(base, manifest(), hooks)[0]:
            wrong.append("hook parity")
        (hooks / "pre-commit").write_bytes(b"git-hooks/pre-commit")
        (base / ".claude").mkdir()
        (base / ".claude" / "settings.json").write_bytes(b"{}")
        if not check(base, manifest(), hooks)[0]:
            wrong.append("absent file appeared")
        return len(cases) + 2 + len(EXPORT_CASES), wrong
    finally:
        import shutil
        shutil.rmtree(str(base), ignore_errors=True)


EXPORT_CASES = (
    "engineering tree: CLAUDE.md deleted, no marker",
    "release export: marker binds, CLAUDE.md unpublished",
    "release export: a listed file the surface does not exclude is missing",
    "release export: a listed digest differs",
    "marker in a tree that still has an excluded path",
    "marker that binds an older manifest",
    "marker that is a symlink",
    "marker in a tree whose surface excludes nothing",
)


def export_self_test(base, manifest):
    """Each export-context case on the synthetic tree; returns the names judged wrongly."""
    (base / "scripts" / "ci").mkdir(parents=True, exist_ok=True)
    surface, register = base / SURFACE, base / "docs" / "architecture" / "AMENDMENTS.md"
    register.parent.mkdir(parents=True, exist_ok=True)
    marker, claude = base / EXPORT_MARKER, base / "CLAUDE.md"
    marker.parent.mkdir(parents=True, exist_ok=True)
    text = manifest()
    (base / MANIFEST).parent.mkdir(parents=True, exist_ok=True)
    (base / MANIFEST).write_text(text, encoding="utf-8")
    surface.write_text("*.md\n!CLAUDE.md\n!docs/architecture/AMENDMENTS.md\n", encoding="utf-8")
    exitcodes = base / "lib" / "isedraf" / "exitcodes.json"
    original = exitcodes.read_bytes()

    def judged(expect_fail, name):
        failed = bool(check(base, text, None)[0])
        return [] if failed == expect_fail else [name]

    def make_export():
        if claude.exists():
            claude.unlink()
        if register.exists():
            register.unlink()
        marker.write_text(export_marker_text(base), encoding="utf-8")

    wrong = []
    claude.unlink()
    wrong += judged(True, EXPORT_CASES[0])
    make_export()
    wrong += judged(False, EXPORT_CASES[1])
    exitcodes.unlink()
    wrong += judged(True, EXPORT_CASES[2])
    exitcodes.write_bytes(b"tampered")
    wrong += judged(True, EXPORT_CASES[3])
    exitcodes.write_bytes(original)
    register.write_bytes(b"register")
    wrong += judged(True, EXPORT_CASES[4])
    make_export()
    (base / MANIFEST).write_text(text + "# later\n", encoding="utf-8")
    wrong += judged(True, EXPORT_CASES[5])
    (base / MANIFEST).write_text(text, encoding="utf-8")
    real = base / "marker.real"
    real.write_text(export_marker_text(base), encoding="utf-8")
    marker.unlink()
    marker.symlink_to(real)
    wrong += judged(True, EXPORT_CASES[6])
    marker.unlink()
    real.unlink()
    surface.write_text("*.md\n", encoding="utf-8")
    marker.write_text(export_marker_text(base), encoding="utf-8")
    wrong += judged(True, EXPORT_CASES[7])
    for path in (marker, surface, base / MANIFEST):
        path.unlink()
    claude.write_bytes(b"CLAUDE.md")
    return wrong


def main():
    cases, wrong = self_test()
    if wrong:
        print("  FAIL  governance self-test: case(s) %s judged wrongly" % wrong)
        return 1
    path = ROOT / MANIFEST
    if not path.is_file():
        print("  FAIL  %s does not exist (D-83)" % MANIFEST)
        return 1
    problems, listed, checked, unpublished = check(ROOT, path.read_text(encoding="utf-8"),
                                                   ROOT / ".git" / "hooks")
    if problems:
        for p in problems:
            print("  FAIL  %s" % p)
        print("=== governance manifest gate FAILED ===")
        return 1
    scope = ("%d files unchanged since the owner's last update" % listed if not unpublished else
             "release export: %d files unchanged since the owner's last update, %d listed file(s) "
             "intentionally unpublished (%s binds the manifest and the release surface)"
             % (listed - unpublished, unpublished, EXPORT_MARKER))
    print("  OK    governance manifest (D-83): %s; %s; .claude/settings.json absent as recorded; "
          "self-test %d cases"
          % (scope, ("%d installed hooks identical to git-hooks/" % checked) if checked
                     else "no installed hooks here (CI or a fresh clone): parity not checked", cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
