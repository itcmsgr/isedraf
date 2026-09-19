# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: MPL-2.0 is applied to what ISEDRAF owns, and nothing else is distributed.
# Implements: D-84, D-90, GOV-001, GOV-002
#
# Two separate obligations, both licensing, both previously unchecked.
#
# 1. EVERY tracked file carries a licence statement, inline or through REUSE.toml.
#    182 files carried none at all - the golden vectors, the measured compatibility
#    records, the freeze manifests, the gate registries. File format is not a reason for
#    a published file to have no licence.
#
# 2. THIRD-PARTY FRAMEWORK CONTENT IS NOT RELICENSED BY PROXIMITY. Nothing becomes
#    MPL-2.0 because it sits in this repository or is processed by this engine. The
#    registry in framework_sources.json is DENY BY DEFAULT: content whose licensing state
#    is not recorded as BUNDLED_OPEN does not enter the public tree, the export, the
#    packages or the SBOM.
#
# The second check deliberately also fails when a framework is merely CLAIMED as supported
# in public documentation. A mapping that does not exist is still a claim to a reader, and
# naming a restricted provider as supported is the assertion that needed authorisation.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================

"""usage: check_licensing.py [tree-root]"""
import fnmatch
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
REGISTRY = json.loads((ROOT / "scripts" / "ci" / "framework_sources.json").read_text())
POLICY = json.loads((ROOT / "scripts" / "ci" / "public_licensing_policy.json").read_text())
FAIL = []


def bad(msg):
    FAIL.append(msg)
    print("  FAIL  %s" % msg)


def tracked():
    out = subprocess.check_output(["git", "ls-files"], cwd=str(ROOT), text=True).split()
    return [p for p in out if not p.startswith("planning/")]


print("--- licensing (D-84, D-90) ---")

# --- 1. every tracked file has a licence statement -------------------------------------
reuse = (ROOT / "REUSE.toml")
globs = []
if reuse.exists():
    for chunk in re.findall(r"path = \[(.*?)\]", reuse.read_text(), re.S):
        globs += re.findall(r'"([^"]+)"', chunk)
else:
    bad("REUSE.toml is missing; nothing declares the licence of files without headers")

files = tracked()
# Z-18: count the input before judging it.
if not files:
    bad("no tracked files found — nothing was checked")
    sys.exit(1)

unlicensed = []
for rel in files:
    p = ROOT / rel
    if not p.is_file():
        continue
    try:
        if "SPDX-License-Identifier" in p.read_text(errors="replace")[:2000]:
            continue
    except OSError:
        pass
    if any(fnmatch.fnmatch(rel, g) or rel.startswith(g.replace("**", "")) for g in globs):
        continue
    unlicensed.append(rel)
for rel in unlicensed[:20]:
    bad("%s carries no licence statement, inline or in REUSE.toml" % rel)
if len(unlicensed) > 20:
    bad("... and %d more files with no licence statement" % (len(unlicensed) - 20))
if not unlicensed:
    print("  OK    %d tracked files: every one carries a licence statement" % len(files))

# --- 2. registry integrity, deny by default --------------------------------------------
allowed = set(REGISTRY["policy"]["public_export_allows"])
known = set(REGISTRY["policy"]["dispositions"])
required = set(REGISTRY["policy"]["record_fields"])
for i, src in enumerate(REGISTRY["sources"], 1):
    missing = required - set(src)
    if missing:
        bad("framework source %d is missing required fields: %s"
            % (i, ", ".join(sorted(missing))))
    d = src.get("disposition")
    if d not in known:
        bad("framework source %d has unknown disposition %r" % (i, d))

# --- 3. no framework content in the tree, registered or not ----------------------------
# A pack directory is the only place bundled framework content may live. If one appears,
# every pack in it must be registered AND carry a disposition the public export allows.
PACK_ROOT = ROOT / "frameworks"
if PACK_ROOT.is_dir():
    registered = {s.get("framework"): s.get("disposition") for s in REGISTRY["sources"]}
    for pack in sorted(PACK_ROOT.iterdir()):
        name = pack.name
        if name not in registered:
            bad("frameworks/%s is present and NOT registered in framework_sources.json "
                "— unknown licensing state means NOT DISTRIBUTABLE" % name)
        elif registered[name] not in allowed:
            bad("frameworks/%s is registered as %s, which the public export does not "
                "allow (%s)" % (name, registered[name], ", ".join(sorted(allowed))))

# --- 4. private research material never reaches this tree ------------------------------
for rel in files:
    if "licensed-framework-research" in rel:
        bad("%s is private licensing research and must never be tracked" % rel)

# --- 5. no framework support CLAIMED in public documentation ---------------------------
# A mapping that does not exist is still a claim to a reader.
# The policy is the single authority for WHO is restricted and WHAT counts as a claim.
# A provider token alone is not a finding: "do not copy from CIS" and "no CIS mapping"
# name a provider in order to FORBID it, which is the opposite of claiming it. A finding
# needs the token, a claim word, and no negation on the same line.
RESTRICTED = [(v, k) for k, v in POLICY["restricted_providers"].items()
              if not k.startswith("$")]
CLAIM = re.compile(POLICY["claim_context"]["positive"], re.I)
NEGATION = re.compile(POLICY["claim_context"]["negation"], re.I)
ALLOWED_CTX = set(POLICY["allowed_context_paths"]["paths"])
ALLOW_MARK = "<!-- licensing:allow-framework-name -->"

# Every text surface, not only markdown and not only README: a claim in CLI help text or
# in a package description reaches a user just as directly as one in a document.
TEXT_EXT = (".md", ".py", ".sh", ".json", ".yml", ".yaml", ".in", ".txt", ".toml")
text_surfaces = [r for r in files
                 if r.endswith(TEXT_EXT) and r not in ALLOWED_CTX]
for rel in text_surfaces:
    try:
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    for n, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARK in line or not CLAIM.search(line) or NEGATION.search(line):
            continue
        for pattern, label in RESTRICTED:
            if re.search(pattern, line):
                bad("%s:%d CLAIM about %s — no framework mapping is licensed, reviewed "
                    "or bundled (public_framework_mappings is empty). Remove the claim, "
                    "or record an authorization in public_licensing_policy.json. Line: %r"
                    % (rel, n, label, line.strip()[:70]))
                break

# --- 5b. the policy must still describe the state it claims to describe ---------------
for key in ("public_framework_mappings", "licensed_framework_packs",
            "provider_partnerships", "bundled_third_party_framework_content"):
    if POLICY[key]:
        bad("public_licensing_policy.json declares %s=%r. Nothing is authorized; if this "
            "changed, it changed deliberately and needs an owner decision recorded."
            % (key, POLICY[key]))

# --- 5c. restricted document formats never enter the public tree ----------------------
allowed_bin = set(k for k in POLICY["allowed_binary_artifacts"] if not k.startswith("$"))
for rel in files:
    if rel in allowed_bin:
        continue
    if any(rel.lower().endswith(ext) for ext in POLICY["restricted_document_formats"]):
        bad("%s is a document/archive format that may carry restricted provider material "
            "(standards, control matrices, exports). Unknown binary artifacts fail "
            "closed: allowlist it by path in public_licensing_policy.json with a reason, "
            "or remove it." % rel)

# --- 5d. nothing reaches the tree through a symlink -----------------------------------
# Restricted content does not have to live here to be published: a symlink or an external
# build input is enough. A path leaving the repository is a licensing boundary failure
# whatever it points at.
for rel in files:
    f = ROOT / rel
    if f.is_symlink():
        target = os.readlink(str(f))
        resolved = (f.parent / target).resolve()
        try:
            resolved.relative_to(ROOT)
        except ValueError:
            bad("%s is a symlink pointing OUTSIDE the repository (%s). Public artifacts "
                "must not be assembled from external paths." % (rel, target))

# --- 5e. MPL-2.0 is actually applied where the packages claim it ----------------------
exp = POLICY["package_license_expectations"]
lic = ROOT / exp["license_file"]
if not lic.exists():
    bad("%s is missing" % exp["license_file"])
elif not lic.read_text(encoding="utf-8").lstrip().startswith(exp["license_first_line"]):
    bad("%s does not begin with %r — the canonical licence text may have been altered"
        % (exp["license_file"], exp["license_first_line"]))

spec = ROOT / "packaging" / "rpm" / "isedraf.spec.in"
if spec.exists():
    m = re.search(r"^License:\s*(\S+)", spec.read_text(), re.M)
    if not m:
        bad("the rpm spec declares no License field")
    elif m.group(1) != exp["rpm_license_field"]:
        bad("the rpm spec declares License: %s, the policy expects %s"
            % (m.group(1), exp["rpm_license_field"]))

# Debian expresses a licence in /usr/share/doc/<pkg>/copyright, not in `control`. The
# package shipped no copyright file at all, so the RPM declared MPL-2.0 in its metadata
# while the DEB stated it nowhere machine-readable.
cpy = ROOT / exp["deb_copyright_file"]
if not cpy.exists():
    bad("%s is missing — a .deb states its licence in a DEP-5 copyright file, and "
        "without one the package declares no licence anywhere a tool can read"
        % exp["deb_copyright_file"])
else:
    ctext = cpy.read_text(encoding="utf-8")
    if "License: %s" % exp["deb_copyright_license"] not in ctext:
        bad("%s does not declare License: %s"
            % (exp["deb_copyright_file"], exp["deb_copyright_license"]))
    if not ctext.startswith("Format: https://www.debian.org/doc/packaging-manuals/"):
        bad("%s is not in DEP-5 machine-readable format" % exp["deb_copyright_file"])

# --- 6. the ARTIFACTS, not the templates that produced them ---------------------------
# A clean source tree is not a clean package. Everything above reads the repository; this
# reads what a user actually receives, which is the only thing a licensing complaint would
# ever be about.
DIST = ROOT / "dist"
if (DIST / "packages").is_dir():
    import subprocess as sp
    import tarfile
    import tempfile
    import shutil

    def listing(artifact):
        """Paths inside the artifact, without extracting more than necessary."""
        name = artifact.name
        if name.endswith(".rpm"):
            if not shutil.which("rpm"):
                return None
            return sp.check_output(["rpm", "-qlp", str(artifact)], text=True,
                                   stderr=sp.DEVNULL).split()
        tmp = pathlib.Path(tempfile.mkdtemp())
        try:
            if name.endswith(".deb"):
                (tmp / "d.tgz").write_bytes(
                    sp.check_output(["ar", "p", str(artifact), "data.tar.gz"]))
                src = tmp / "d.tgz"
            else:
                src = artifact
            with tarfile.open(src) as tf:
                return tf.getnames()
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)

    checked = 0
    for artifact in sorted((DIST / "packages").iterdir()):
        if "latest" in artifact.name or not artifact.name.endswith(
                (".deb", ".rpm", ".tar.gz")):
            continue
        names = listing(artifact)
        if names is None:
            continue
        checked += 1
        for n in names:
            low = n.lower()
            if any(low.endswith(ext) for ext in POLICY["restricted_document_formats"]):
                bad("%s contains %s — a document/archive format that may carry restricted "
                    "provider material" % (artifact.name, n))
            if "PROVIDERS_LICENSE" in n or "licensed-framework-research" in n:
                bad("%s contains private licensing research: %s" % (artifact.name, n))
        if artifact.name.endswith(".rpm") and shutil.which("rpm"):
            lic = sp.check_output(["rpm", "-qp", "--qf", "%{LICENSE}", str(artifact)],
                                  text=True, stderr=sp.DEVNULL).strip()
            if lic != exp["rpm_license_field"]:
                bad("%s declares License=%r, the policy expects %r"
                    % (artifact.name, lic, exp["rpm_license_field"]))
        if artifact.name.endswith(".deb"):
            if not any(n.endswith("usr/share/doc/isedraf/copyright") for n in names):
                bad("%s ships no /usr/share/doc/isedraf/copyright — the package declares "
                    "no licence anywhere a tool can read it" % artifact.name)
    if checked:
        print("  OK    %d built artifacts: licence declared, no restricted document "
              "format, no private research" % checked)

# --- 7. the SBOM says what the project actually knows ----------------------------------
sbom_dir = DIST / "sbom"
if sbom_dir.is_dir():
    n_sbom = 0
    for s in sorted(sbom_dir.glob("*.spdx.json")):
        doc = json.loads(s.read_text())
        n_sbom += 1
        for pkg in doc.get("packages", []):
            if pkg.get("SPDXID") == "SPDXRef-Package-isedraf":
                for field in ("licenseConcluded", "licenseDeclared"):
                    if pkg.get(field) != exp["sbom_declared_license"]:
                        bad("%s declares %s=%r for the ISEDRAF package; the project knows "
                            "it is %s and the format can say so"
                            % (s.name, field, pkg.get(field), exp["sbom_declared_license"]))
            elif pkg.get("SPDXID") == "SPDXRef-Package-cpython":
                # NOASSERTION is CORRECT here: the interpreter is an external prerequisite
                # whose licence this project does not determine. Claiming MPL-2.0 for it
                # would be a manufactured conclusion, which is the opposite error.
                if pkg.get("licenseDeclared") == exp["sbom_declared_license"]:
                    bad("%s declares the external Python runtime as %s — this project does "
                        "not license the interpreter and must not claim to"
                        % (s.name, exp["sbom_declared_license"]))
    if n_sbom:
        print("  OK    %d SBOM documents: first-party licence declared, external runtime "
              "not misattributed" % n_sbom)

if FAIL:
    print("=== licensing gate FAILED ===")
    print("  MPL-2.0 licenses what ISEDRAF owns. Unknown licensing state means")
    print("  NOT DISTRIBUTABLE — for a file with no statement, and for a framework alike.")
    sys.exit(1)
print("  OK    framework registry: %d sources, deny-by-default, no bundled framework "
      "content, no support claimed" % len(REGISTRY["sources"]))
