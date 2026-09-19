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
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
REGISTRY = json.loads((ROOT / "scripts" / "ci" / "framework_sources.json").read_text())
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
RESTRICTED = [
    (r"\bCIS\s+(?:Controls?|Benchmark)", "CIS"),
    (r"\bISO[/ ]?IEC\s*27\d{3}", "ISO/IEC 27000 series"),
    (r"\bISO\s*27001\b", "ISO 27001"),
    (r"\bSCF\b", "Secure Controls Framework"),
    (r"\bUCF\b", "Unified Compliance Framework"),
    (r"\bNIS2\b", "NIS2"),
    (r"\bDORA\b", "DORA"),
    (r"\bPCI[- ]?DSS\b", "PCI DSS"),
]
SUPPORT_CLAIM = re.compile(
    r"\b(support(s|ed|ing)?|compliant|compatible|certified|mapped to|coverage of|"
    r"aligned (?:to|with)|conforms? to)\b", re.I)
ALLOW_MARK = "<!-- licensing:allow-framework-name -->"
public_docs = [r for r in files if r.endswith(".md")
               and not r.startswith(("docs/development/", "docs/licensing/"))]
for rel in public_docs:
    text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    for n, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARK in line:
            continue
        for pattern, label in RESTRICTED:
            if re.search(pattern, line) and SUPPORT_CLAIM.search(line):
                bad("%s:%d claims support for or alignment with %s. No framework "
                    "mapping is licensed, reviewed or bundled: %r"
                    % (rel, n, label, line.strip()[:70]))

if FAIL:
    print("=== licensing gate FAILED ===")
    print("  MPL-2.0 licenses what ISEDRAF owns. Unknown licensing state means")
    print("  NOT DISTRIBUTABLE — for a file with no statement, and for a framework alike.")
    sys.exit(1)
print("  OK    framework registry: %d sources, deny-by-default, no bundled framework "
      "content, no support claimed" % len(REGISTRY["sources"]))
