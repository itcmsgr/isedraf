# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Render the published sample report from committed evidence bytes.
# Implements: IQ-011, D-88, D-89, GOV-002
#
# The previous sample was real output from a lab VM, and when the storage schema changed
# it could not be regenerated: the machine was gone, and the fields that replaced the
# retired ones had never been collected from it. It was withdrawn rather than corrected,
# because writing plausible values for a host nobody can re-observe is inventing evidence.
#
# This generator makes that failure impossible to repeat. The evidence is committed:
#
#   evidence/collected_inventory.json   verbatim `isedraf inventory --json` output
#   evidence/state-root/                the snapshot, manifest and ledger, as written
#   evidence/environment.txt            what produced them, and on what
#
# Regenerating re-runs the real report model and the real renderers over those bytes, and
# re-verifies the ledger chain while doing it. Anyone can reproduce the published sample
# from a clone. Nobody needs the VM, which is the point - it no longer exists.
#
# What this does NOT reproduce is the collection itself. Reading /sys and /proc requires
# the host, and no committed byte can stand in for it. The sample therefore reproduces
# the REPORT from captured evidence, not the act of collecting - and says so.
#
# meta:type="doc-generator"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="docs/reference/samples/SAMPLE_REPORT.{json,md}"
# meta:binaries="python3"
# =============================================================================

"""usage: sample_report.py [generate|check]"""
import json
import os
import subprocess
import sys

ROOT = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
sys.path.insert(0, os.path.join(ROOT, "lib"))

from isedraf.report import artifact                        # noqa: E402
from isedraf.report import model as report_model          # noqa: E402
from isedraf.report import render                          # noqa: E402

SAMPLES = os.path.join(ROOT, "docs", "reference", "samples")
EVIDENCE = os.path.join(SAMPLES, "evidence")
INVENTORY = os.path.join(EVIDENCE, "collected_inventory.json")

# Repo-relative, and resolved from the repository root, because the report records the
# evidence root it read. An absolute path would bake one machine's checkout location into
# a published document and make the sample regenerate differently on every clone - which
# is the opposite of the property this file exists to provide.
STATE_ROOT = os.path.join("docs", "reference", "samples", "evidence", "state-root")

# Pinned so the sample is stable. Both are recorded in NON_REPRODUCIBLE precisely because
# they MUST differ between two renderings of the same evidence; pinning them here is what
# lets the rest of the document be compared byte for byte. These are the real values from
# the collection that produced the committed evidence, not invented ones.
REPORT_ID = "RPT-20260920T171548Z-71072fdd5e6cd97e"
GENERATED_AT = "2026-09-20T17:15:48Z"

# The inventory artifact identity is stamped when a report is built, not when the
# inventory is collected, so rendering twice would otherwise produce two collection_ids
# and two artifact_digests for the same bytes. These are the real values from the
# collection that produced the committed evidence - taken from that run's own report,
# not chosen - and pinning them is what makes the digest a function of the evidence.
COLLECTION_ID = "INV-20260920T171548Z-11885ac7cb292572"
COLLECTED_AT = "2026-09-20T17:15:48Z"

HEADER = """<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE - DO NOT EDIT MANUALLY.
     Source: docs/reference/samples/evidence/ (committed evidence bytes)
     Regenerate: python3 scripts/docs/sample_report.py generate
     `make check` fails when this file and the evidence disagree.

     Real `isedraf report` output from a disposable Debian 12 VM, collected with the
     released 0.1.0-alpha1 package by an unprivileged user. The report identifier and
     generation timestamp are pinned to the values of that collection so the document is
     stable; nothing else is edited, and no value is supplied by hand. -->

"""


def build():
    os.chdir(ROOT)
    with open(INVENTORY, "rb") as fh:
        inventory = json.loads(fh.read().decode("utf-8"))
    art = artifact.build(inventory, collected_at=COLLECTED_AT,
                         collection_id=COLLECTION_ID)
    return report_model.build(STATE_ROOT, inventory, generated_at=GENERATED_AT,
                              report_id=REPORT_ID, inventory_artifact=art)


def rendered():
    m = build()
    return render.to_json(m) + "\n", HEADER + render.to_markdown(m)


def main(argv):
    action = argv[1] if len(argv) > 1 else "generate"
    js, md = rendered()
    paths = ((os.path.join(SAMPLES, "SAMPLE_REPORT.json"), js),
             (os.path.join(SAMPLES, "SAMPLE_REPORT.md"), md))
    if action == "generate":
        for path, text in paths:
            with open(path, "w") as fh:
                fh.write(text)
            print("  generated %s" % os.path.relpath(path, ROOT))
        return 0
    if action == "check":
        stale = []
        for path, text in paths:
            try:
                with open(path) as fh:
                    current = fh.read()
            except OSError:
                stale.append(os.path.relpath(path, ROOT) + " (missing)")
                continue
            if current != text:
                stale.append(os.path.relpath(path, ROOT))
        if stale:
            print("=== the published sample does not match the committed evidence ===")
            for s in stale:
                print("  FAIL  %s" % s)
            print("  The sample is generated from docs/reference/samples/evidence/.")
            print("  run: python3 scripts/docs/sample_report.py generate")
            return 1
        print("  OK    sample report regenerates byte-identically from committed evidence")
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
