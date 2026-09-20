# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Hold the documentation to the same rule as the engine.
# Implements: GOV-001, GOV-002, C-01, C-06, D-88, D-90
#
# WHY. This project refuses to report confidence the evidence has not earned — and then
# shipped a README claiming actions were pinned with "no tag exceptions" while a mutable
# tag sat in the workflow, a certification matrix carrying two different corpus digests,
# and a CURRENT_STATE page announcing that no product code exists. Fourteen gates guarded
# the evidence and none guarded the prose.
#
# Four checks, each mechanical:
#   references    every repository path a document names must exist
#   pins          every third-party action must be pinned to a full commit SHA
#   framing       C-06: no competitive positioning, including NEGATED comparisons
#   digests       a digest quoted as authoritative must match the artifact
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git"
# =============================================================================

"""Documentation is an evidence surface. It is checked like one."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
REGISTRY = json.loads(
    (ROOT / "scripts" / "ci" / "docs_truth_registry.json").read_text())
failures = []


def tracked(pattern):
    out = subprocess.check_output(["git", "ls-files", pattern], cwd=str(ROOT), text=True)
    return [l for l in out.split() if l]


DOCS = [p for p in tracked("*.md") if not p.startswith("planning/")]

# docs/architecture/ is NORMATIVE SPECIFICATION: `SHALL` text describing what an
# implementation must do. A path inside a requirement is a design decision, not a claim
# that the file exists today — "exit codes are defined once in exitcodes.json" is the
# requirement, and annotating it "(not yet created)" would corrupt the specification to
# satisfy a linter. Reference checking applies to documents that describe the CURRENT
# state; specification documents are checked by check-refs and the freeze instead.
SPECIFICATION_PREFIXES = ("docs/architecture/",)
CURRENT_STATE_DOCS = [p for p in DOCS if not p.startswith(SPECIFICATION_PREFIXES)]

# --- 1. every repository path a document names must exist --------------------------------
# Backticked paths that look like repository paths. A doc that points at a file which does
# not exist sends its reader somewhere that does not answer them.
PATH_RE = re.compile(r"`([A-Za-z0-9_.\-/]+/[A-Za-z0-9_.\-/]*[A-Za-z0-9_\-]"
                     r"(?:\.(?:md|py|sh|json|yml|yaml|txt|sha256|allow|jsonl))?)`")
FUTURE_MARKERS = ("PLANNED", "FUTURE", "NOT_IMPLEMENTED", "does not exist",
                  "not yet", "will be", "would be", "no such", "PLANNED —")


def line_of(text, index):
    return text[:index].count("\n") + 1


for rel in CURRENT_STATE_DOCS:
    text = (ROOT / rel).read_text(encoding="utf-8")
    lines = text.splitlines()
    here = (ROOT / rel).parent
    for m in PATH_RE.finditer(text):
        candidate = m.group(1)
        if candidate in REGISTRY["reference_allowlist"] or "/" not in candidate:
            continue
        if candidate.startswith(("http", "/")):
            continue                      # absolute runtime paths are not repository paths
        # A reference is a REPOSITORY reference only if its first segment names something
        # that exists at the repository root, or it resolves beside the document. Without
        # this, "3.9/3.12/3.14", "CapEff/CapPrm/CapBnd" and "192.168.122.54/24" all look
        # like paths, and a gate that cries wolf 110 times teaches everyone to skip it.
        first = candidate.split("/", 1)[0]
        resolves_here = (here / candidate).exists()
        at_root = (ROOT / candidate).exists()
        if resolves_here or at_root:
            continue
        if not (ROOT / first).exists() and not (here / first).exists():
            continue                      # not addressing this repository at all
        n = line_of(text, m.start())
        context = lines[n - 1] if n - 1 < len(lines) else ""
        # A path introduced as planned is a plan, not a dangling reference.
        if any(marker in context for marker in FUTURE_MARKERS):
            continue
        failures.append(("DANGLING_REFERENCE", rel, n, candidate))

# --- 1b. every MARKDOWN LINK to a repository path must exist ------------------------------
# The check above only sees `backticked` paths. The public README linked a badge to
# docs/reference/SUPPORTED_PLATFORMS.md, which has never existed, and the gate could not
# see it because the target sat inside a markdown link rather than in backticks. A broken
# link in a published README sends a reader somewhere that does not answer them.
MDLINK_RE = re.compile(r"\]\(([^)\s#]+)(?:#[^)\s]*)?\)")
for rel in CURRENT_STATE_DOCS:
    text = (ROOT / rel).read_text(encoding="utf-8")
    here = (ROOT / rel).parent
    for m in MDLINK_RE.finditer(text):
        target = m.group(1)
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        if target in REGISTRY["reference_allowlist"]:
            continue
        if (here / target).exists() or (ROOT / target).exists():
            continue
        failures.append(("DANGLING_LINK", rel, line_of(text, m.start()), target))

# --- 2. third-party actions pinned to a full commit SHA -----------------------------------
USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.M)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
for rel in tracked(".github/workflows/*.yml") + tracked(".github/workflows/*.yaml"):
    text = (ROOT / rel).read_text(encoding="utf-8")
    for m in USES_RE.finditer(text):
        ref = m.group(1)
        if ref.startswith("./") or "@" not in ref:
            continue                     # a local action has no version to pin
        _action, _, version = ref.rpartition("@")
        if not SHA_RE.match(version):
            failures.append(("MUTABLE_ACTION_PIN", rel, line_of(text, m.start()), ref))

# --- 3. C-06 competitive framing ------------------------------------------------------------
# The previous gate matched "replaces <Name>" only, and missed "not developed as a
# replacement for <eight named projects>". A NEGATED comparison is still a comparison: it
# places this project on the same axis as the named ones and invites the reader to make it.
FRAMING = [
    (r"\breplacement for\b", "positions against an alternative"),
    (r"\breplaces\b", "claims to replace"),
    (r"\bbetter than\b", "ranks"),
    (r"\bsuperior to\b", "ranks"),
    (r"\bunlike\b", "compares"),
    (r"\bcompared (?:to|with)\b", "compares"),
    (r"\bcompetitive positioning\b", "competitive framing"),
    (r"\bvs\.?\b", "ranks"),
    (r"\bthan\s+(?:openscap|osquery|wazuh|lynis|aide)\b", "ranks"),
]
PROJECTS = [n.lower() for n in REGISTRY["external_projects"]["names"]]
for rel in DOCS:
    text = (ROOT / rel).read_text(encoding="utf-8")
    lines = text.splitlines()
    for pattern, why in FRAMING:
        for m in re.finditer(pattern, text, re.I):
            n = line_of(text, m.start())
            context = lines[n - 1] if n - 1 < len(lines) else ""
            if "doclint:allow-framing" in context:
                continue
            # A framing word is not the offence. Framing ABOUT A NAMED PROJECT is.
            # "declared vs resolved" is a technical distinction; so is a policy document
            # quoting the prohibition it enforces.
            named = [p for p in PROJECTS if p in context.lower()]
            if not named:
                continue
            failures.append(("COMPETITIVE_FRAMING", rel, n, "%s — %s %s"
                             % (m.group(0).strip(), why, "/".join(named))))

# --- 4. a digest quoted as authoritative must match the artifact ----------------------------
# Two different corpus digests coexisted in one certification document. An auditor who
# follows the repository's own verification recipe computes one value and finds the other
# printed a hundred lines away, in the file that certifies the corpus.
for name, spec in REGISTRY["authoritative_digests"].items():
    artifact = ROOT / spec["path"]
    if not artifact.exists():
        failures.append(("MISSING_DIGEST_SOURCE", spec["path"], 0, name))
        continue
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    prefix_len = spec.get("min_prefix", 16)
    for rel in DOCS:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for m in re.finditer(r"\b([0-9a-f]{%d,64})\b" % prefix_len, text):
            quoted = m.group(1)
            if actual.startswith(quoted):
                continue
            # Only complain about values that LOOK like this artifact's digest: same
            # length class, and the document says so nearby.
            n = line_of(text, m.start())
            line = text.splitlines()[n - 1]
            if not any(k in line for k in spec["context_keywords"]):
                continue
            # A superseded digest may stay, but ONLY when the text says so on its own
            # line. Two unlabelled digests in one certification document are two equally
            # authoritative-looking claims, and exactly one of them can be true. The
            # label is the whole exemption: without it, history is indistinguishable
            # from a current assertion.
            if any(k in line for k in ("Historical", "superseded", "not authoritative",
                                       "no longer exists", "pre-expansion")):
                continue
            failures.append(("STALE_DIGEST", rel, n,
                             "%s… does not match %s (label it historical, or fix it)"
                             % (quoted[:16], spec["path"])))

if failures:
    print("=== documentation truth gate FAILED ===", file=sys.stderr)
    for kind, rel, line, detail in sorted(set(failures)):
        print("  FAIL  %-20s %s:%s  %s" % (kind, rel, line or "-", detail),
              file=sys.stderr)
    print("  Documentation is an evidence surface. Fix the claim, or the thing it "
          "claims.", file=sys.stderr)
    sys.exit(1)
print("  OK    docs truth: %d documents, references/pins/framing/digests consistent"
      % len(DOCS))
