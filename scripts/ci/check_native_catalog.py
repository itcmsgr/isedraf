# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The native control catalog is ISEDRAF's own, and stays that way.
# Implements: D-78, D-79, D-84, D-111, D-125, GOV-002
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
#   7. (D-125) Each admitted criterion has a generated page, and it is current.
#   6. (D-125) One registry: lib/isedraf/catalog/native_controls.json, installed with the
#      package, and no other tracked file with that name - the former CI-only registry
#      in particular. A build-time copy would be a second record that can drift.
#   5. (D-111 extended 2026-10-14) Every criterion field the registry requires or allows is
#      named in the catalog document; check types are declared per family, exactly for the
#      declared families; a criterion's check_type is one declared for its family; a retired
#      ID matches the namespace, is retired once, and never reappears among the criteria.
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
REGISTRY = "lib/isedraf/catalog/native_controls.json"
REG = json.loads((ROOT / REGISTRY).read_text())
DOC = ROOT / "docs" / "architecture" / "NATIVE_CONTROL_CATALOG.md"
FAIL = []


def bad(msg):
    FAIL.append(msg)
    print("  FAIL  %s" % msg)


print("--- native control catalog (D-111) ---")

# --- 6. one registry (D-125) -----------------------------------------------------------
_named = [p for p in subprocess.check_output(["git", "ls-files"], cwd=str(ROOT), text=True).split()
          if pathlib.PurePosixPath(p).name == "native_controls.json"]
_others = sorted(p for p in _named if p != REGISTRY)
if REGISTRY not in _named:
    bad("%s is not tracked: the one registry must be in the repository and the package" % REGISTRY)
for p in _others:
    bad("%s is a second native control registry; %s is the only record (D-125)" % (p, REGISTRY))
if REGISTRY in _named and not _others:
    print("  OK    one registry: %s, installed with the package" % REGISTRY)

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

    check_type = c.get("check_type")
    if "check_type" in c and check_type not in REG.get("check_types", {}).get(fam, []):
        bad("%s has check_type %r, which is not declared for %s in check_types"
            % (cid, check_type, fam))

# --- 5. extended criterion contract (D-111 extended 2026-10-14) -----------------------
check_types = REG.get("check_types")
if check_types is None:
    bad("the registry declares no check_types")
else:
    for f in sorted(set(families) - set(check_types)):
        bad("%s is a declared family with no check_types entry" % f)
    for f in sorted(set(check_types) - set(families)):
        bad("check_types names %s, which is not a declared family" % f)
    for f, names in sorted(check_types.items()):
        if len(set(names)) != len(names):
            bad("check_types for %s lists a name twice" % f)
if DOC.exists():
    text = DOC.read_text(encoding="utf-8")
    for field in sorted(set(REG["required_criterion_fields"]) | set(REG["optional_criterion_fields"])):
        if "`%s`" % field not in text:
            bad("criterion field %s is in the registry and not named in the catalog document" % field)
retired = set()
for r in REG.get("retired_criteria", []):
    rid = r.get("criterion_id", "<missing>")
    if not pattern.match(rid or ""):
        bad("retired %r does not match the frozen namespace" % rid)
    if rid in retired:
        bad("%s is retired more than once" % rid)
    retired.add(rid)
    if not isinstance(r.get("last_version"), int) or not r.get("retired_on"):
        bad("retired %s needs last_version (integer) and retired_on" % rid)
for rid in sorted(retired & seen):
    bad("%s is retired and also an active criterion: a retired ID is never reused" % rid)
print("  OK    criterion contract: %d required and %d optional fields named in the document; "
      "check types declared for %d families; %d retired IDs"
      % (len(REG["required_criterion_fields"]), len(REG["optional_criterion_fields"]),
         len(check_types or {}), len(retired)) if not FAIL else
      "  ..    criterion contract checked")

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

# --- 7. generated criterion pages are current (D-125, EVAL-009) -----------------------
sys.path.insert(0, str(ROOT / "scripts" / "docs"))
import criteria_pages                                      # noqa: E402
stale = criteria_pages.problems()
for p in stale:
    bad("%s; run: python3 scripts/docs/criteria_pages.py generate" % p)
if not stale:
    print("  OK    %d generated criterion page(s) render the registry record"
          % len(REG["criteria"]))
if FAIL:
    print("=== native control catalog gate FAILED ===")
    print("  The control is ISEDRAF's, or it is not a native control.")
    sys.exit(1)
