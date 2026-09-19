# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Generate and verify the architecture MASTER_INDEX requirement inventory.
# Implements: D-89, D-105, GOV-007
#
# meta:type="generator"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git"
# =============================================================================

"""
Requirement counts and ID ranges are DERIVED from the documents, never hand-maintained.

Round 2 finding Q-15: the hand-written index drifted from reality after a repair pass and
claimed ranges that excluded real IDs. A projection that can go stale silently is the same
defect class as a gate that cannot fail.

Usage: master_index.py check | generate
"""
import collections
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
)
# D-106/T-27: docs/architecture/ is the single authoritative location.
ARCH = ROOT / "docs" / "architecture"

DEF_RE = re.compile(r"^\*\*([A-Z]{2,6})-(\d{3})\b", re.M)
CORE = [
    "ISEDRAF_HLD.md",
    "EVIDENCE_AND_TRUST_MODEL.md",
    "SNAPSHOT_BASELINE_DELTA_MODEL.md",
    "V0_1_IMPLEMENTATION_SCOPE.md",
]
# T-19: HDR-001..003 are SHALL requirements in a governance-manifest-covered document and
# were enforced entirely outside the authoritative index. The denominator now includes them.
EXTRA = [ROOT / "docs" / "development" / "HEADER_POLICY.md"]

rows, total = [], 0
for src in [ARCH / n for n in CORE] + EXTRA:
    name = src.name
    p = src
    if not p.exists():
        continue
    ids = collections.defaultdict(list)
    for m in DEF_RE.finditer(p.read_text(encoding="utf-8")):
        ids[m.group(1)].append(int(m.group(2)))
    n = sum(len(v) for v in ids.values())
    total += n
    ranges = " · ".join(
        f"`{pre}-{min(v):03d}`…`{pre}-{max(v):03d}`" for pre, v in sorted(ids.items())
    )
    rows.append(f"| `{name}` | FROZEN CANDIDATE | {ranges} | {n} |")

table = "\n".join(rows) + f"\n| **Total requirements** | | | **{total}** |"

idx = ARCH / "MASTER_INDEX.md"
text = idx.read_text(encoding="utf-8")
start = text.index("| Document | Status |")
end = text.index("\n\n", start)
head = text[start:].split("\n")[1]  # separator row
current = text[start:end]
fresh = f"| Document | Status | Requirement ID ranges | Count |\n{head}\n{table}"

if len(sys.argv) > 1 and sys.argv[1] == "generate":
    idx.write_text(text[:start] + fresh + text[end:])
    print(f"  generated MASTER_INDEX: {total} requirements across {len(rows)} documents")
    sys.exit(0)

if current.strip() != fresh.strip():
    print("=== MASTER_INDEX is stale (Q-15) ===", file=sys.stderr)
    print("  run: python3 scripts/docs/master_index.py generate", file=sys.stderr)
    sys.exit(1)
print(f"  OK    MASTER_INDEX fresh: {total} requirements")
