# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Keep a retired inference from coming back as vocabulary.
# Implements: D-114, STORAGE-SEMANTICS-001, GOV-002
#
# D-114 removed a storage field named `type` whose value was one of ROTATIONAL,
# SOLID_STATE, OPTICAL, REMOVABLE, VIRTUAL or NVME. Every one of those was a guess
# dressed as an observation: Linux exposes `queue/rotational`, a subsystem symlink and
# a SCSI peripheral type, and none of them establishes the physical medium. The engine
# now records what the kernel exposes and names the source in the column header.
#
# The code change was the easy half. The word ROTATIONAL had also travelled into a
# published sample report, where it sat as an example of what ISEDRAF claims, three
# schema versions after the field was gone. Nothing failed, because no gate reads
# documentation for retired vocabulary — the sample was the last consumer anyone
# thought to check, and it was found by hand.
#
# So this gate reads the whole published surface, not just the source. A file may use
# the retired words only to STATE that they are retired; a file that uses one as a
# value, a column or a field is rejected and told which one.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================

"""usage: check_storage_vocabulary.py [--self-test]"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True).strip())

# The retired values. Word-bounded and upper-case: these were enum values, and matching
# them case-insensitively would flag the ordinary English words "optical" and "virtual".
RETIRED_VALUES = ("ROTATIONAL", "SOLID_STATE", "OPTICAL", "REMOVABLE", "VIRTUAL", "NVME")
VALUE_RE = re.compile(r"\bDEVICE_(?:%s)\b|[\"']\b(?:%s)\b[\"']"
                      % ("|".join(RETIRED_VALUES), "|".join(RETIRED_VALUES)))

# The retired FIELD, in the two shapes a storage device record can carry it: a JSON key,
# and a Markdown column header that means the same thing. `type` is far too common a word
# to match bare - `state_dimension`, `fstype` and `meta:type` are all legitimate - so the
# field check is anchored to a storage device record.
DEVICE_KEY_RE = re.compile(r"\"type\"\s*:\s*\"(?:%s)\"" % "|".join(RETIRED_VALUES))
DEVICE_COL_RE = re.compile(r"^\|\s*Device\s*\|.*\|\s*(?:Class|Type)\s*\|", re.M)

# Files that exist to RECORD the prohibition, and are therefore exempt from all three
# checks below. Each one must be able to write the retired vocabulary in every shape -
# as a value, as a device key, as a table column - because forbidding a shape means
# quoting it: the register and the amendment that retired it, the instruction file, the
# document that explains why the sample was withdrawn, the two tests that assert the
# words are ABSENT from rendered output, the harness that injects them to prove this
# gate fires, and this gate, whose self-test corpus is made of them.
#
# The risk this accepts is a real defect hiding in one of these ten files. It is small
# and bounded: none of them renders a device, none is a sample, and the four files that
# actually produce storage output - collectors.py, render.py, cli.py and the report
# model - are NOT on this list and are fully checked. The strength of the gate is the
# other 230 files, and the self-test proves each of the three checks independently of
# any file in the tree.
EXEMPT = {
    "CLAUDE.md",
    "scripts/ci/check_storage_vocabulary.py",
    "scripts/ci/falsifiable.sh",
    "docs/IMPLEMENTATION_QUESTIONS.md",
    "docs/architecture/DECISIONS_REGISTER.md",
    "docs/architecture/AMENDMENTS.md",
    "docs/architecture/INTERNAL_RECORDS.md",
    "docs/reference/CONTROL_EVIDENCE_MAP.md",
    "lib/isedraf/inventory/model.py",
    "tests/test_inventory.py",
    "tests/test_report.py",
}

SCANNED_SUFFIXES = (".py", ".md", ".json", ".sh", ".txt", ".in", ".yml", ".yaml")
FAIL = []


def bad(msg):
    FAIL.append(msg)
    print("  FAIL  %s" % msg)


def tracked_files():
    out = subprocess.check_output(["git", "ls-files"], cwd=str(ROOT), text=True)
    for line in out.splitlines():
        p = ROOT / line
        if p.suffix in SCANNED_SUFFIXES and p.is_file():
            yield line, p


def inspect(rel, text):
    """Return the findings for one file. Separated so --self-test can drive it."""
    found = []
    if rel in EXEMPT:
        return found
    if DEVICE_KEY_RE.search(text):
        found.append("carries a storage device `type` with a retired value")
    if DEVICE_COL_RE.search(text):
        found.append("renders a storage device table with a Class/Type column; the "
                     "column header must name the kernel source it came from")
    m = VALUE_RE.search(text)
    if m:
        found.append("uses the retired storage vocabulary %s as a value" % m.group(0))
    return found


def self_test():
    """A gate that has never been observed to fail is not a gate."""
    must_fail = [
        ('{"name": "sda", "type": "ROTATIONAL"}', "retired value in a device record"),
        ('{"name": "sr0", "type": "OPTICAL"}', "retired value in a device record"),
        ("| Device | Size | Class | Removable | Model |\n|---|---|---|---|---|",
         "device table with a Class column"),
        ("| Device | Size | Type | Model |\n|---|---|---|---|", "device table with a Type column"),
        ('status = DEVICE_SOLID_STATE', "retired enum constant"),
        ("medium = 'ROTATIONAL'", "retired value as a string literal"),
    ]
    must_pass = [
        '{"name": "sda", "kernel_subsystem": "scsi", "queue_rotational": true}',
        '{"name": "sr0", "scsi_peripheral_type": 5, "kernel_removable": true}',
        "| Device | Size | Kernel subsystem | Queue rotational | Vendor | Model |",
        '"state_dimension": "ACTIVE"',
        '{"fstype": "tmpfs", "type": "tmpfs"}',
        '# meta:type="ci-gate"',
        "The device is optical media in the ordinary English sense.",
        "queue_rotational is false; this does not establish a solid-state medium.",
        '{"type": "VIRTUAL_MACHINE_LABEL_UNRELATED_TO_STORAGE"}',
    ]
    errs = 0
    for text, why in must_fail:
        if not inspect("some/file.md", text):
            print("  SELFTEST FAIL  not detected (%s): %r" % (why, text[:60])); errs += 1
    for text in must_pass:
        f = inspect("some/file.md", text)
        if f:
            print("  SELFTEST FAIL  false positive: %r -> %s" % (text[:60], f)); errs += 1
    if errs:
        print("=== storage vocabulary self-test FAILED ==="); sys.exit(1)
    print("  OK    storage vocabulary self-test: %d rejected, %d accepted, 0 false positives"
          % (len(must_fail), len(must_pass)))


if "--self-test" in sys.argv:
    self_test()
    sys.exit(0)

scanned = 0
for rel, path in tracked_files():
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        continue
    scanned += 1
    for finding in inspect(rel, text):
        bad("%s %s" % (rel, finding))

if scanned == 0:
    # Z-18: a gate that passes over an empty input is not a gate.
    bad("no files were scanned; the gate cannot have verified anything")

if FAIL:
    print("=== storage vocabulary gate FAILED ===")
    print("  D-114 retired these words because the kernel does not support them.")
    print("  Record what /sys exposes - kernel_subsystem, queue_rotational,")
    print("  kernel_removable, scsi_peripheral_type - and name the source in the header.")
    sys.exit(1)
print("  OK    storage vocabulary: %d files, no retired D-114 device class on the surface"
      % scanned)
