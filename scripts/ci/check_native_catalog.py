# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The native control catalog is ISEDRAF's own, and stays that way.
# Implements: D-78, D-79, D-84, D-111, GOV-002
#
# D-111 freezes the layering: LINUX FACT -> NATIVE CONTROL -> EVIDENCE -> OPTIONAL MAPPING.
# An invariant with no gate is a sentence, and this project has learned what those are
# worth. Four things are checked, and the first is the one that keeps the namespace honest.
#
#   1. The registry and the architecture document must AGREE on the families. Two
#      authorities that can disagree are how a namespace drifts - the same defect class as
#      the rpm spec staging two documents while build.sh staged four.
#   2. Every criterion ID matches the frozen namespace pattern and a declared family.
#   3. No criterion may cite a framework as its source. The control is ours or it is not a
#      native control.
#   4. No production module may be named after a framework provider. There is no
#      cis_collector.py, and the gate is what makes that a fact rather than an intention.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================

"""usage: check_native_catalog.py"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True).strip())
REG = json.loads((ROOT / "scripts" / "ci" / "native_controls.json").read_text())
DOC = ROOT / "docs" / "architecture" / "NATIVE_CONTROL_CATALOG.md"
FAIL = []


def bad(msg):
    FAIL.append(msg)
    print("  FAIL  %s" % msg)


print("--- native control catalog (D-111) ---")

families = REG["families"]
# Z-18: count the input before judging it. A namespace with no families is not a pass.
if not families:
    bad("the registry declares no control families")
    sys.exit(1)

# --- 1. the registry and the document agree ------------------------------------------
if not DOC.exists():
    bad("the catalog document is missing: %s" % DOC.relative_to(ROOT))
else:
    text = DOC.read_text(encoding="utf-8")
    in_doc = set(re.findall(r"`(ISE-[A-Z]+)-\*`", text))
    declared = set(families)
    reserved = set(REG.get("reserved_families", {}))
    for f in sorted(declared - in_doc):
        bad("%s is in the registry and not in the catalog document" % f)
    for f in sorted(in_doc - declared - reserved):
        bad("%s is in the catalog document and not in the registry" % f)
    for f in sorted(reserved):
        if f not in text:
            bad("%s is reserved but the document does not explain why" % f)
    if not (declared - in_doc) and not (in_doc - declared - reserved):
        print("  OK    %d families: registry and catalog document agree" % len(declared))

# --- 2. criterion IDs hold to the frozen namespace -----------------------------------
pattern = re.compile(REG["namespace_pattern"])
required = set(REG["required_criterion_fields"])
seen = set()
for c in REG["criteria"]:
    cid = c.get("criterion_id", "<missing>")
    if not pattern.match(cid or ""):
        bad("%r does not match the frozen namespace %s" % (cid, REG["namespace_pattern"]))
        continue
    if cid in seen:
        bad("%s is defined more than once" % cid)
    seen.add(cid)
    fam = cid.rsplit("-", 1)[0]
    if fam not in families:
        bad("%s belongs to family %s, which is not declared" % (cid, fam))
    missing = required - set(c)
    if missing:
        bad("%s is missing required field(s): %s" % (cid, ", ".join(sorted(missing))))

# --- 3. a native control is not derived from a framework -----------------------------
RESTRICTED = re.compile(
    r"\b(CIS|ISO[/ ]?IEC|ISO\s*27\d{3}|SCF|HITRUST|COBIT|PCI[- ]?DSS|NIS2|DORA|CCM)\b")
for c in REG["criteria"]:
    blob = json.dumps(c)
    m = RESTRICTED.search(blob)
    if m:
        bad("%s names %s in the criterion itself. A native control is authored from Linux "
            "behaviour; a framework reference belongs in a mapping, which is a separate "
            "layer." % (c.get("criterion_id", "<unnamed>"), m.group(0)))
if REG["criteria"]:
    print("  OK    %d criteria: namespace, fields and independence hold" % len(seen))
else:
    print("  OK    catalog is empty — no native criterion is authored yet (W1-D), and the "
          "registry says so rather than implying otherwise")

# --- 4. no production module named after a framework provider ------------------------
PROVIDER_NAME = re.compile(r"(^|[_/-])(cis|iso27\d*|iso|scf|hitrust|cobit|pci|nist|ccm)"
                           r"([_/-]|\.py$)", re.I)
tracked = subprocess.check_output(["git", "ls-files", "lib/"], cwd=str(ROOT), text=True).split()
if not tracked:
    bad("no production files found under lib/ — nothing was checked")
else:
    offenders = [p for p in tracked if PROVIDER_NAME.search(pathlib.Path(p).name)]
    for p in offenders:
        bad("%s is named after a framework provider. Collectors describe the host, not a "
            "framework: there is no cis_collector.py." % p)
    if not offenders:
        print("  OK    %d production files: none named after a framework provider"
              % len(tracked))

if FAIL:
    print("=== native control catalog gate FAILED ===")
    print("  The control is ISEDRAF's, or it is not a native control.")
    sys.exit(1)
