#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Prove every critical gate DISCRIMINATES, by injecting its prohibited
#          condition into a disposable tree copy and asserting the gate rejects it
#          AND says why.
# Implements: GOV-002, D-105, D-96, Z-20
#
# A gate that has never been observed to fail is not a gate; it is a comment.
# One centralized harness, not one twin script per gate (owner decision, OD-15).
#
# The contract lives in scripts/ci/falsifiable_lib.sh (Z-20): four distinguishable
# outcomes, and a gate that dies counts as a harness failure, never as a firing gate.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,bash,python3,mktemp"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2
# shellcheck source=scripts/ci/falsifiable_lib.sh
. "$ROOT/scripts/ci/falsifiable_lib.sh"

echo "=== GOV-002 falsifiability harness ==="

inject "L-03 junk meta:owner" \
  'bash scripts/ci/check_headers.sh' \
  'sed -i "s|meta:owner=\"Antonios Voulvoulis / ITCMS\"|meta:owner=\"identity\"|" scripts/ci/check_bootstrap_scope.sh' \
  'meta:owner is not the canonical value'

inject "L-11 foreign contact in an SPDX declaration" \
  'bash scripts/ci/check_headers.sh' \
  'sed -i "s|<contact@itcms.gr>|<contact@example.invalid>|" scripts/ci/check_bootstrap_scope.sh' \
  'declares a non-canonical contact'

inject "L-04 missing SPDX identifier" \
  'bash scripts/ci/check_headers.sh' \
  'sed -i "/SPDX-License-Identifier/d" scripts/ci/check_bootstrap_scope.sh' \
  'missing SPDX-License-Identifier'

inject "L-07 synthetic licence key in JSON" \
  'bash scripts/ci/check_headers.sh' \
  'printf "{\"_license\":\"MPL-2.0\"}\n" > schemas_probe.json && git add -A' \
  'synthetic licence key'

# D-96 is a PRE-freeze rule, so the injection removes the freeze manifests as well:
# post-freeze the gate is meant to permit implementation, and an injection that quietly
# stopped applying would be a gate reported as tested while testing nothing.
inject "D-96 product code with no verified freeze set" \
  'bash scripts/ci/check_bootstrap_scope.sh' \
  'rm -f docs/architecture/freeze/*.sha256 && mkdir -p lib/isedraf && touch lib/isedraf/engine.py && git add -A' \
  'D-96'

# IQ-018: the pattern that made the bytecode gate intermittent must not come back.
inject "IQ-018 an early-exit grep -q reader in a shell pipeline" \
  'make -s check-shell' \
  'printf "git ls-files %s grep -qE x && true\n" "|" >> scripts/ci/check_paths.sh' \
  'early-exit reader in a pipeline'

inject "D-84 network import in tooling" \
  'bash scripts/ci/check_bootstrap_scope.sh' \
  'printf "import socket\n" >> scripts/docs/doclint.py && git add -A' \
  'network/database import'

inject "D-17/D-86 committed bytecode" \
  'bash scripts/ci/check_bootstrap_scope.sh' \
  'mkdir -p scripts/__pycache__ && touch scripts/__pycache__/x.pyc && git add -f -A' \
  'committed bytecode'

inject "C-05 forbidden claim in a non-exempt document" \
  'python3 scripts/docs/doclint.py' \
  'printf "\nISEDRAF is tamper-proof.\n" >> docs/reference/GLOSSARY.md' \
  'forbidden claim'

inject "T-27 an architecture document declares its own status" \
  'python3 scripts/docs/doclint.py' \
  'printf "\nStatus: FROZEN\n" >> docs/architecture/NATIVE_CONTROL_CATALOG.md' \
  'declare status externally'

inject "C-06 competitive framing" \
  'python3 scripts/docs/doclint.py' \
  'printf "\nISEDRAF replaces Lynis.\n" >> docs/roadmap/ROADMAP.md' \
  'competitive framing'

inject "C-01 broken internal link" \
  'python3 scripts/docs/doclint.py' \
  'printf "\n[x](docs/NOPE.md)\n" >> docs/README.md' \
  'broken internal link'

next_requires "docs/architecture/DECISIONS_REGISTER.md"
inject "D-105 undefined DECISION cited" \
  'python3 scripts/ci/check_requirement_refs.py' \
  'printf "\nPer D-999 this holds.\n" >> docs/architecture/DECISIONS_REGISTER.md  # refs:test-fixture' \
  'cites undefined decision D-999'  # refs:test-fixture

# The requirement-ID half of D-105 can only be exercised once the frozen architecture is in
# the repository (Prompt 04). Until then it is INERT in a CI checkout, and GOV-001 requires
# that to be stated rather than silently assumed. Recorded as KGG-006.
if ls docs/architecture/*.md >/dev/null 2>&1 && grep -qlE '^\*\*[A-Z]{2,6}-[0-9]{3}' docs/architecture/*.md 2>/dev/null; then
    next_requires "docs/architecture/W1A_CORE_FREEZE_SCOPE.md"
    inject "D-105 undefined requirement ID cited" \
      'python3 scripts/ci/check_requirement_refs.py' \
      'printf "\nSee FAKE-999 for details.\n" >> docs/architecture/DECISIONS_REGISTER.md  # refs:test-fixture' \
      'cites undefined requirement ID FAKE-999'  # refs:test-fixture
else
    echo "  SKIP requirement-ID half of D-105: architecture not yet in the repository (KGG-006)"
fi

next_requires "docs/architecture/DECISIONS_REGISTER.md"
inject "D-106 amendment cited as authority" \
  'python3 scripts/ci/check_requirement_refs.py' \
  'printf "\nPer A-042 this is authoritative.\n" >> docs/architecture/DECISIONS_REGISTER.md  # refs:test-fixture' \
  'cites amendment A-042 as authority'  # refs:test-fixture

inject "D-99 singular ledger.jsonl path reintroduced" \
  'bash scripts/ci/check_paths.sh' \
  'printf "\nledger at /var/lib/isedraf/ledger.jsonl\n" >> CLAUDE.md' \
  "singular 'ledger.jsonl'"

next_requires "docs/architecture/W1A_CORE_FREEZE_SCOPE.md"
inject "D-105 dangling ID in a non-architecture authority tier" \
  'python3 scripts/ci/check_requirement_refs.py' \
  'printf "\nSee BOGUS-777 here.\n" >> docs/development/HEADER_POLICY.md  # refs:test-fixture' \
  'cites undefined requirement ID BOGUS-777'  # refs:test-fixture

next_requires "docs/architecture/MASTER_INDEX.md"
inject "D-89 stale MASTER_INDEX" \
  'python3 scripts/docs/master_index.py check' \
  'printf "\n**ZZZ-001 (test) SHALL** placeholder.\n" >> docs/architecture/ISEDRAF_HLD.md  # refs:test-fixture' \
  'MASTER_INDEX is stale'

# D-107: the index status column is read from the freeze manifests. It was once a constant,
# and taking a document out of every freeze set left the index reporting itself fresh.
next_requires "docs/architecture/MASTER_INDEX.md"
inject "D-107 MASTER_INDEX status survives a document leaving its freeze sets" \
  'python3 scripts/docs/master_index.py check' \
  'sed -i "\|docs/architecture/ISEDRAF_HLD.md|d" docs/architecture/freeze/W1A_CORE.sha256 docs/architecture/freeze/W1A_CORE_PUBLIC.sha256' \
  'MASTER_INDEX is stale'

# W1-B: the production tests must be able to fail the build. A pipe to tail would have
# handed make tail's exit status, which is a gate that can never fire.
inject "W1-B production golden-compatibility test broken" \
  'make check-tests' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/identity.py"); s = p.read_text()
old = "    text = text.lower()"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    text = text.upper()"))
PYX' \
  'FAILED|Error'

# D-86/D-90: a clean source tree is not a correct package. The DEB once staged the
# payload to /usr/isedraf, where the launcher does not look: it built, installed, and did
# nothing. Both injections mutate the BUILD, then inspect the artifact.
# Since packaging/build.sh builds only from a clean commit (GA-PKG-2), these gates first
# commit the mutation inside the sandbox; otherwise the build refuses the dirty tree
# before the check under test is reached (all nine crashed, found 2026-09-28).
inject "D-90 the package payload installs to the wrong prefix" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash packaging/build.sh 2>&1; bash scripts/ci/check_package_payload.sh' \
  'sed -i "s|install -D -m 0644 \"\$f\" \"\$STAGE/usr/\$f\"|install -D -m 0644 \"\$f\" \"\$STAGE/usr/\${f#lib/}\"|" packaging/build.sh' \
  'layout wrong|/usr/isedraf|missing from payload'

inject "D-86 bytecode reaches the package payload" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash packaging/build.sh 2>&1; bash scripts/ci/check_package_payload.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("packaging/build.sh"); s = p.read_text()
old = "find \"$STAGE\" -name '"'"'*.pyc'"'"' -delete 2>/dev/null"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "touch \"$STAGE/usr/lib/isedraf/cli.pyc\"", 1))
PYX' \
  'bytecode|forbidden content'

# D-90 owner decision 2026-09-19: CLAUDE.md is PUBLIC and ships in the repository and the
# source tarball, but never in the runtime payload. Staging it into the package must fail.
next_requires "CLAUDE.md"
inject "D-90 contributor documentation staged into the runtime payload" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash packaging/build.sh 2>&1; bash scripts/ci/check_package_payload.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("packaging/build.sh"); s = p.read_text()
old = "install -m 0644 README.md \"$STAGE/usr/share/doc/isedraf/README.md\""
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, old + "\ninstall -m 0644 CLAUDE.md \"$STAGE/usr/share/doc/isedraf/CLAUDE.md\"", 1))
PYX' \
  'development documentation in the runtime payload|CLAUDE.md'

# NORM-037/D-86. A set-like field must not enter an artifact in filesystem order. The
# engine has had this gate since W1-A; the package build did not, and DEBIAN/sha256sums
# went in unsorted - same 24 lines, different sequence on btrfs and on ext4.
# `ls -U` reproduces raw directory order, which is what `find` was doing.
inject "NORM-037 the deb sha256sums entered the package in filesystem order" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash packaging/build.sh 2>&1; bash scripts/ci/check_deb_ordering.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("packaging/build.sh"); s = p.read_text()
anchor = "| xargs -0 sha256sum > DEBIAN/sha256sums"
assert anchor in s, "mutation anchor miss"
head, _, tail = s.partition("( cd \"$DEBROOT\" && find usr -type f -print0")
_, _, rest = tail.partition(anchor)
p.write_text(head + "( cd \"$DEBROOT\" && find usr -type f -exec sha256sum {} + > DEBIAN/sha256sums" + rest)
PYX' \
  'not sorted|ordering gate FAILED'

# D-86. Two builds of the same tree must produce the same bytes.
#
# The injection stamps a nanosecond clock reading into the package, rather than removing
# the `ar` deterministic flag. Two earlier versions of this injection both passed
# SILENTLY on the CI runner while firing on the workstation: dropping `D` does nothing
# where binutils was COMPILED with deterministic archives on by default (Ubuntu), and
# forcing `U` did not restore non-determinism there either. Whether `ar` records the
# clock is a property of the local toolchain - which is exactly why the build writes `D`
# explicitly and never relies on a default.
#
# The property under test is "does this gate detect a non-reproducible build", so the
# experiment must MAKE one, on every platform, rather than hope the environment provides
# it. A nanosecond timestamp differs between two builds anywhere.
inject "D-86 a build stamps the clock into the package" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash scripts/ci/check_reproducible.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("packaging/build.sh"); s = p.read_text()
old = "INSTALLED_KB=$(find"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "echo \"X-Build-Stamp: $(date +%s%N)\" >> \"$DEBROOT/DEBIAN/control.stamp\"\n" + old, 1))
PYX' \
  'reproducible build gate FAILED|artifacts identical'

# PRODUCT-DESCRIPTOR-001 (D-113). "Evidence Bridge" is retired. The mixed states below
# are the realistic failure: not a wholesale revert, but one surface left behind after a
# rename — which is precisely what happened before the descriptor was canonicalized.
inject "PRODUCT-DESCRIPTOR-001 a retired descriptor survives in a public document" \
  'python3 scripts/ci/check_public_claims.py' \
  'printf "\nISEDRAF is an Evidence Bridge.\n" >> docs/reference/GLOSSARY.md' \
  'RETIRED product descriptor|public claims gate FAILED'

inject "PRODUCT-DESCRIPTOR-001 a source header is left behind after the rename" \
  'python3 scripts/ci/check_public_claims.py' \
  'sed -i "s|State Delta \& Evidence Engine|State Delta \& Evidence Bridge|" lib/isedraf/canonical.py' \
  'RETIRED product descriptor|public claims gate FAILED'

# The descriptor in prose case, and wrapped across a Markdown line. Both passed an
# exact-substring test, and the first was live in the canonical product description.
inject "PRODUCT-DESCRIPTOR-001 a retired descriptor written in lower case" \
  'python3 scripts/ci/check_public_claims.py' \
  'printf "\nISEDRAF is an evidence bridge.\n" >> docs/reference/GLOSSARY.md' \
  'RETIRED product descriptor|public claims gate FAILED'

inject "PRODUCT-DESCRIPTOR-001 a retired descriptor wrapped across a line" \
  'python3 scripts/ci/check_public_claims.py' \
  'printf "\nISEDRAF is an Evidence\nBridge.\n" >> docs/reference/GLOSSARY.md' \
  'RETIRED product descriptor|public claims gate FAILED'

inject "PRODUCT-DESCRIPTOR-001 the registry declares a retired descriptor as canonical" \
  'python3 scripts/ci/check_public_claims.py' \
  'python3 - <<'"'"'PYX'"'"'
import json, pathlib
p = pathlib.Path("scripts/ci/project_status.json"); d = json.loads(p.read_text())
d["identity"]["header"] = d["identity"]["header"].replace("Engine", "Bridge")
p.write_text(json.dumps(d, indent=2))
PYX' \
  'retired descriptor|absent from the header form|public claims gate FAILED'

# C-01/D-88. Five surfaces described the same product five different ways and nothing
# compared them, which is how "Evidence Bridge" and "Evidence Engine" both became true.
inject "C-01 an identity surface drifts from the declared canonical form" \
  'python3 scripts/ci/check_public_claims.py' \
  'sed -i "s|^DESCRIPTION=\".*\"$|DESCRIPTION=\"Something else entirely\"|" packaging/build.sh' \
  'package description is|public claims gate FAILED'

inject "C-01 the CLI describes the product differently from the packages" \
  'python3 scripts/ci/check_public_claims.py' \
  'sed -i "s|description=\"Linux host evidence and assurance tool\"|description=\"A Linux tool\"|" lib/isedraf/cli.py' \
  'CLI description is|public claims gate FAILED'

inject "C-01 the frozen header policy and the identity registry disagree on the noun" \
  'python3 scripts/ci/check_public_claims.py' \
  'sed -i "s|State Delta & Evidence Engine|State Delta \& Evidence Bridge|g" docs/development/HEADER_POLICY.md' \
  'does not carry the declared noun|README subtitle is|public claims gate FAILED'

# D-112. Platform breadth drifts upward on its own: the collectors have no architecture
# branches, which is a reason to EXPECT a platform to work and is not evidence that it
# does. The gap between those two is where "supports ARM" gets written by someone who is
# not lying.
inject "D-112 a document claims support for all Linux distributions" \
  'python3 scripts/ci/check_public_claims.py' \
  'printf "\n## Platforms\n\nISEDRAF supports all Linux distributions.\n" >> docs/reference/GLOSSARY.md' \
  'claims every Linux distribution|public claims gate FAILED'

inject "D-112 a document claims Raspberry Pi is supported" \
  'python3 scripts/ci/check_public_claims.py' \
  'printf "\n## Platforms\n\nRaspberry Pi is fully supported.\n" >> docs/reference/GLOSSARY.md' \
  'no ARM campaign has produced evidence|public claims gate FAILED'

inject "D-112 a document claims an unmeasured distribution is supported" \
  'python3 scripts/ci/check_public_claims.py' \
  'printf "\n## Platforms\n\nSLES is validated and supported.\n" >> docs/reference/GLOSSARY.md' \
  'not in distributions_measured|public claims gate FAILED'

inject "D-112 the mode invariant is removed from the product HLD" \
  'python3 scripts/ci/check_public_claims.py' \
  'sed -i "s|NEITHER B NOR C CAN CHANGE A|B and C may adjust A as needed|" docs/architecture/ISEDRAF_PRODUCT_HLD.md' \
  'no longer states the mode invariant|public claims gate FAILED'

# P0 LICENSING BOUNDARY. Each of these is a way the public release could ship a claim or
# a byte it has no right to. The gate is only worth the name if it refuses every one.
inject "D-90 README claims support for CIS Controls" \
  'python3 scripts/ci/check_licensing.py' \
  'printf "\nISEDRAF supports CIS Controls v8.\n" >> README.md' \
  'CLAIM about CIS|licensing gate FAILED'

inject "D-90 a document claims ISO 27001 compatibility" \
  'python3 scripts/ci/check_licensing.py' \
  'printf "\nISEDRAF is ISO 27001 compatible.\n" >> docs/roadmap/ROADMAP.md' \
  'CLAIM about ISO|licensing gate FAILED'

inject "D-90 a provider PDF enters the tracked tree" \
  'python3 scripts/ci/check_licensing.py' \
  'printf "%%PDF-1.4 fake\n" > docs/reference/benchmark.pdf && git add -f -A' \
  'document/archive format|licensing gate FAILED'

inject "D-90 a provider control matrix enters the tree" \
  'python3 scripts/ci/check_licensing.py' \
  'printf "PK fake\n" > docs/reference/controls.xlsx && git add -f -A' \
  'document/archive format|licensing gate FAILED'

inject "D-90 the public policy silently authorizes a framework mapping" \
  'python3 scripts/ci/check_licensing.py' \
  'python3 - <<'"'"'PYX'"'"'
import json, pathlib
p = pathlib.Path("scripts/ci/public_licensing_policy.json"); d = json.loads(p.read_text())
d["public_framework_mappings"].append("some-framework")
p.write_text(json.dumps(d, indent=2))
PYX' \
  'Nothing is authorized|licensing gate FAILED'

inject "D-90 the rpm declares a licence that is not MPL-2.0" \
  'python3 scripts/ci/check_licensing.py' \
  'sed -i "s|^License:        MPL-2.0|License:        Proprietary|" packaging/rpm/isedraf.spec.in' \
  'policy expects MPL-2.0|licensing gate FAILED'

inject "D-90 the deb ships no machine-readable copyright" \
  'python3 scripts/ci/check_licensing.py' \
  'rm -f packaging/deb/copyright' \
  'DEP-5 copyright file|is missing|licensing gate FAILED'

inject "D-90 the root LICENCE text is corrupted" \
  'python3 scripts/ci/check_licensing.py' \
  'printf "Not a licence.\n" > LICENSE' \
  'does not begin with|licensing gate FAILED'

inject "D-90 the SBOM misattributes the external interpreter to this project" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash packaging/build.sh 2>&1; python3 scripts/ci/check_licensing.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/ci/generate_sbom.py"); s = p.read_text()
old = "            \"licenseDeclared\": \"NOASSERTION\","
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "            \"licenseDeclared\": \"MPL-2.0\",", 1))
PYX' \
  'does not license the interpreter|licensing gate FAILED'

inject "D-90 a public artifact is assembled through a symlink leaving the repository" \
  'python3 scripts/ci/check_licensing.py' \
  'ln -s /etc/hostname docs/reference/external-input.txt && git add -f -A' \
  'symlink pointing OUTSIDE|licensing gate FAILED'

# STORAGE-SEMANTICS-001 (D-114). The retired inference must be provably dead, not
# merely absent. Each of these reintroduces it in a different disguise.
inject "STORAGE-SEMANTICS-001 non-rotational is inferred to be solid state" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/collectors.py"); s = p.read_text()
old = "                \"queue_rotational\": rot,"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, old + "\n                \"type\": \"SOLID_STATE\" if rot is False else None,", 1))
PYX' \
  'reappeared|SOLID_STATE|FAILED'

inject "STORAGE-SEMANTICS-001 a physical medium field is reintroduced" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/collectors.py"); s = p.read_text()
old = "                \"kernel_removable\": removable_flag,"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, old + "\n                \"physical_medium\": \"SOLID_STATE\",", 1))
PYX' \
  'reappeared|physical_medium|FAILED'

inject "STORAGE-SEMANTICS-001 the queue observation is deleted instead of the inference" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/collectors.py"); s = p.read_text()
old = "                \"queue_rotational\": rot,"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "", 1))
PYX' \
  'queue_rotational|FAILED'

# FIXTURE-CONFINEMENT-001.
#
# The first version of this injection mutated readlink() to realpath() and DID NOT FIRE.
# Measured, not assumed: with a RELATIVE link inside a fixture root, realpath resolves
# within that root, and basename() of either is the same string. The two implementations
# are indistinguishable at this call site, so that mutation had nothing to detect and
# reporting it as a control would have been a green check proving nothing.
#
# The real failure mode is an implementation that VALIDATES the target - exists(), stat(),
# listdir() - because a fixture link legitimately points at something that is not there.
# That is what this mutates, and the test's deliberately non-existent target answers it.
inject "FIXTURE-CONFINEMENT-001 the subsystem link target is validated before use" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/collectors.py"); s = p.read_text()
old = "                if os.path.islink(link):"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "                if os.path.islink(link) and os.path.exists(link):", 1))
PYX' \
  'example_fake_subsystem|FAILED'

# D-114 Defect A. An incomplete collection reported as complete is the one thing an
# evidence engine cannot be wrong about.
inject "SCOPE-022 DMI absent with virtualization present is reported COLLECTED" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/collectors.py"); s = p.read_text()
old = "    missing = [n for n, v in ((\"vendor\", vendor), (\"product\", product)) if v is None]"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    missing = [] if hypervisor else [n for n, v in ((\"vendor\", vendor), (\"product\", product)) if v is None]", 1))
PYX' \
  'PARTIAL|reason|FAILED'

# D-111. The native control catalog is authored first and is ISEDRAF's own. The invariant
# is frozen; these prove the gate enforcing it can refuse.
inject "D-111 a production module is named after a framework provider" \
  'python3 scripts/ci/check_native_catalog.py' \
  'cp lib/isedraf/identity.py lib/isedraf/cis_collector.py && git add -f -A' \
  'named after a framework provider|native control catalog gate FAILED'

inject "D-111 the namespace and the catalog document disagree" \
  'python3 scripts/ci/check_native_catalog.py' \
  'python3 - <<'"'"'PYX'"'"'
import json, pathlib
p = pathlib.Path("scripts/ci/native_controls.json"); d = json.loads(p.read_text())
d["families"]["ISE-GHOST"] = "a family the catalog document has never heard of"
p.write_text(json.dumps(d, indent=2))
PYX' \
  'registry and not in the catalog document|native control catalog gate FAILED'

inject "D-111 a native criterion is derived from a framework" \
  'python3 scripts/ci/check_native_catalog.py' \
  'python3 - <<'"'"'PYX'"'"'
import json, pathlib
p = pathlib.Path("scripts/ci/native_controls.json"); d = json.loads(p.read_text())
d["criteria"].append({f: "x" for f in d["required_criterion_fields"]})
d["criteria"][0]["criterion_id"] = "ISE-SSH-001"
d["criteria"][0]["purpose"] = "Implements CIS Controls safeguard 4.1"
p.write_text(json.dumps(d, indent=2))
PYX' \
  'names CIS in the criterion itself|native control catalog gate FAILED'

# D-84/D-90. Third-party framework content is not relicensed by sitting in this
# repository. The registry is deny-by-default, and "deny by default" is a claim that has
# to be shown to deny something.
inject "D-90 an unregistered framework pack enters the tree" \
  'python3 scripts/ci/check_licensing.py' \
  'mkdir -p frameworks/cis-controls-8 && echo "{}" > frameworks/cis-controls-8/pack.json && git add -f -A' \
  'NOT registered|licensing gate FAILED'

inject "D-90 a LICENSE_REQUIRED framework is bundled anyway" \
  'python3 scripts/ci/check_licensing.py' \
  'python3 - <<'"'"'PYX'"'"'
import json, pathlib
p = pathlib.Path("scripts/ci/framework_sources.json"); d = json.loads(p.read_text())
d["sources"].append({f: "x" for f in d["policy"]["record_fields"]})
d["sources"][0]["framework"] = "acme-framework"
d["sources"][0]["disposition"] = "LICENSE_REQUIRED"
p.write_text(json.dumps(d, indent=2))
pathlib.Path("frameworks/acme-framework").mkdir(parents=True)
pathlib.Path("frameworks/acme-framework/pack.json").write_text("{}")
PYX
git add -f -A' \
  'does not allow|licensing gate FAILED'

inject "D-90 private licensing research is committed into the tree" \
  'python3 scripts/ci/check_licensing.py' \
  'mkdir -p docs/licensed-framework-research && echo x > docs/licensed-framework-research/notes.md && git add -f -A' \
  'private licensing research|licensing gate FAILED'

inject "D-90 a public document claims support for a restricted framework" \
  'python3 scripts/ci/check_licensing.py' \
  'printf "\nISEDRAF supports CIS Controls v8.\n" >> docs/roadmap/ROADMAP.md' \
  'claims support for|licensing gate FAILED'

inject "D-84 a tracked file carries no licence statement at all" \
  'python3 scripts/ci/check_licensing.py' \
  'printf "amount,currency\n1,EUR\n" > pricing.csv && git add -f -A' \
  'no licence statement|licensing gate FAILED'

# C-01/D-88. A badge is a claim. On the day this repository went public, all four of its
# badges were wrong and its status line still said the project was private. Nothing
# checked them, so they aged while everything around them was gated.
inject "D-88 the README version badge disagrees with VERSION" \
  'python3 scripts/ci/check_public_claims.py' \
  'sed -i "s|badge/version-0.1.0-lightgrey|badge/version-9.9.9-lightgrey|" README.md' \
  'version badge says|public claims gate FAILED'

# OpenSSF Baseline Level 2 (2026-09-29): the repository's security configuration and policy
# documents are file properties, so each one is attacked here.
inject "L2-SEC-1 a workflow regains a write-all token" \
  'python3 scripts/ci/check_repo_security.py' \
  'sed -i "0,/^permissions: {}/s//permissions: write-all/" .github/workflows/governance.yml' \
  'write-all|repository security gate FAILED'

inject "L2-SEC-2 a workflow gains pull_request_target" \
  'python3 scripts/ci/check_repo_security.py' \
  'sed -i "s/^  pull_request:$/  pull_request_target:/" .github/workflows/governance.yml' \
  'pull_request_target|repository security gate FAILED'

inject "L2-SEC-3 Scorecard stops publishing its results" \
  'python3 scripts/ci/check_repo_security.py' \
  'sed -i "s/publish_results: true/publish_results: false/" .github/workflows/scorecard.yml' \
  'publish_results|repository security gate FAILED'

inject "L2-SEC-4 pull requests are no longer DCO-checked" \
  'python3 scripts/ci/check_repo_security.py' \
  'sed -i "s/run: make check-dco-pr/run: true/" .github/workflows/governance.yml' \
  'DCO-checked|repository security gate FAILED'

inject "L2-SEC-5 SECURITY.md loses its acknowledgement target" \
  'python3 scripts/ci/check_repo_security.py' \
  'sed -i "s/3 business days/a reasonable time/" SECURITY.md' \
  'acknowledgement target|repository security gate FAILED'

inject "L2-SEC-6 the maintainers and roles document disappears" \
  'python3 scripts/ci/check_repo_security.py' \
  'rm -f MAINTAINERS.md' \
  'MAINTAINERS.md is missing|repository security gate FAILED'

inject "L2-SEC-7 an issue template tells users to use --redact again" \
  'python3 scripts/ci/check_repo_security.py' \
  'sed -i "s/Output, redacted by hand./Redacted output (--redact)./" .github/ISSUE_TEMPLATE/bug.yml' \
  'redact|repository security gate FAILED'

inject "L2-SEC-8 technical-preview wording returns at general availability" \
  'python3 scripts/ci/check_repo_security.py' \
  'printf "\nThis is a technical preview.\n" >> SUPPORT.md' \
  'technical preview|repository security gate FAILED'

# The release export is the only route to a public release. It broke for a week when exported
# documents began citing files the export removes; `make check` now runs it on every commit.
# The export reads committed bytes, so the mutation is committed inside the sandbox first.
inject "EXP-1 an exported document cites a file the export removes" \
  'git add -A && git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation && d=$(mktemp -d) && bash scripts/ci/release_export.sh --no-build "$d/x"' \
  'printf "\nSee \`docs/architecture/AMENDMENTS.md\` for the history.\n" >> docs/GETTING_STARTED.md' \
  'DANGLING_REFERENCE|release export FAILED'

inject "L2-DCO-1 the DCO check accepts a sign-off by someone other than the author" \
  'python3 scripts/ci/check_dco.py --self-test' \
  'sed -i -e "s/m.group(\"name\").strip() == name.strip()/True/" -e "s/m.group(\"email\").lower() == email.lower()/True/" scripts/ci/check_dco.py' \
  'DCO self-test'

inject "L2-DCO-2 the DCO check accepts a commit with no sign-off" \
  'python3 scripts/ci/check_dco.py --self-test' \
  'sed -i "s/        if not ok:/        if False:/" scripts/ci/check_dco.py' \
  'DCO self-test'

inject "D-88 the README status badge still says technical preview at general availability" \
  'python3 scripts/ci/check_public_claims.py' \
  'sed -i "s|badge/status-general%20availability-green|badge/status-technical%20preview-orange|" README.md' \
  'status badge says|public claims gate FAILED'

inject "D-90 the README tells a public reader the project is private" \
  'python3 scripts/ci/check_public_claims.py' \
  'printf "\n> **Status:** Private pre-release development.\n" >> README.md' \
  'says the project is private|public claims gate FAILED'

inject "C-01 a public document links to a file that does not exist" \
  'python3 scripts/ci/check_docs_truth.py' \
  'printf "\n[platforms](docs/reference/SUPPORTED_PLATFORMS.md)\n" >> README.md' \
  'DANGLING_LINK|documentation truth gate FAILED'

# D-86/EXEC-016. Both of these got past a green local build and were caught only by a
# runner: BuildRequires resolved on Fedora and failed on Ubuntu, and rpmbuild merely
# WARNS about a bogus weekday. A warning in a build log nobody reads is not a control.
inject "D-86 the rpm spec declares a build dependency the release builder cannot resolve" \
  'python3 scripts/ci/check_packaging.py' \
  'sed -i "s|^%description|BuildRequires:  coreutils\n\n%description|" packaging/rpm/isedraf.spec.in' \
  'declares a build dependency|packaging metadata gate FAILED'

inject "D-86 the rpm changelog states a weekday the date never fell on" \
  'python3 scripts/ci/check_packaging.py' \
  'sed -i "s|^\* Fri Sep 18 2026|* Thu Sep 18 2026|" packaging/rpm/isedraf.spec.in' \
  'which was a|packaging metadata gate FAILED'

# S2 include graph. A missed include is a missed rule: an sshd_config whose Include was
# not followed reports whatever the main file said, confidently and wrongly. These three
# prove the engine cannot lose an include silently, cannot spin on a cycle, and cannot
# reorder a graph whose order decides which declaration wins.
# ARCH-01. These are the edges that make the evidence pipeline a lie. The gate exists
# because the first dependency analysis found a real one: shared/result.py imported a
# domain model for four status constants, and shared/include_graph.py imported the
# inventory package for a file reader - which, because inventory/__init__ imports
# collectors, meant a generic include-graph primitive pulled in all nine inventory
# collectors. Nothing failed. Nothing would have, until a domain worker asked why the SSH
# lane depended on the storage collector.
# PAM lane. Two edges that look alike and are not, and two questions that one visited-set
# cannot answer at once.
inject "PAM include and substack are recorded as the same edge" \
  'python3 tests/test_pam_adversarial.py' \
  'sed -i "s|^SUBSTACK = \"substack\"|SUBSTACK = \"include\"|" lib/isedraf/pam/model.py' \
  'FAILED|Error'

inject "PAM a cycle is treated as an ordinary repeated inclusion" \
  'python3 tests/test_pam.py' \
  'sed -i "s|        if service in in_progress:|        if False:|" lib/isedraf/pam/acquire.py' \
  'FAILED|Error'

inject "PAM a bracketed control is collapsed to a single token" \
  'python3 tests/test_pam_adversarial.py' \
  'sed -i "s|        return model.BRACKETED, actions, text\[close + 1:\].strip(), True|        return model.BRACKETED, None, text[close + 1:].strip(), True|" lib/isedraf/pam/sources.py' \
  'FAILED|Error'

inject "PAM a numeric jump is stringified, losing the distinction from a named action" \
  'python3 tests/test_pam_adversarial.py' \
  'sed -i "s|                            \"action\": int(action) if action.lstrip(\"-\").isdigit()|                            \"action\": action if action.lstrip(\"-\").isdigit()|" lib/isedraf/pam/sources.py' \
  'FAILED|Error'

inject "PAM a service target containing path separators is joined instead of refused" \
  'python3 tests/test_pam.py' \
  'sed -i "s|        if os.sep in service or service in (\"\", \".\", \"..\"):|        if False:|" lib/isedraf/pam/acquire.py' \
  'FAILED|Error'

# SSH lane. The defect that matters is structural: a parser returning correct
# keyword/value pairs while losing Match scope produces evidence that reads as
# authoritative and answers a question about no host.
inject "SSH Match scope is flattened into global declarations" \
  'python3 tests/test_ssh_adversarial.py' \
  'sed -i "s|                            scope=current_scope,|                            scope=model.GLOBAL,|" lib/isedraf/ssh/sources.py' \
  'FAILED|Error'

inject "SSH an included file is reset to GLOBAL instead of inheriting its Match" \
  'python3 tests/test_ssh_adversarial.py' \
  'sed -i "s|    current_scope, current_criteria, current_index = entry_scope|    current_scope, current_criteria, current_index = GLOBAL_SCOPE|" lib/isedraf/ssh/sources.py' \
  'FAILED|Error'

inject "SSH an include inherits the file's last Match rather than the scope at its own line" \
  'python3 tests/test_ssh_adversarial.py' \
  'sed -i "s|            entry = parent_map.get(node\[\"directive\"\]\[\"line\"\], sources.GLOBAL_SCOPE)|            entry = list(parent_map.values())[-1] if parent_map else sources.GLOBAL_SCOPE|" lib/isedraf/ssh/acquire.py' \
  'FAILED|Error'

inject "SSH an absolute Include escapes the collection root to the live host" \
  'python3 tests/test_ssh.py' \
  'sed -i "s|            return hostpath.under(self.root, target)|            return target|" lib/isedraf/ssh/acquire.py' \
  'FAILED|Error'

inject "SSH a hash inside a value is treated as an inline comment" \
  'python3 tests/test_ssh_adversarial.py' \
  'sed -i "s|    keyword, value = match.group(1), match.group(2).strip()|    keyword, value = match.group(1), match.group(2).split(\"#\")[0].strip()|" lib/isedraf/ssh/sources.py' \
  'FAILED|Error'

inject "SSH only the first of two duplicate directives is recorded" \
  'python3 tests/test_ssh_adversarial.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/ssh/acquire.py"); s = p.read_text()
s = s.replace("    status, reason = _status(graph, records, malformed)", "    seen = set()\n    records = [r for r in records if r.get(\"keyword\") is None or (r[\"keyword\"] not in seen and not seen.add(r[\"keyword\"]))]\n    status, reason = _status(graph, records, malformed)", 1)
p.write_text(s)
PYX' \
  'FAILED|Error'

# ARCH-02 blind spots. The coverage map showed login-policy with no fixture-escape
# mutation and PAM with no redaction mutation, while sudo and SSH had both. Tests existed
# for each; a test nobody has tried to break is a weaker claim than one that has been.
inject "LOGINPOLICY an unparsed line is retained verbatim instead of digested" \
  'python3 tests/test_loginpolicy_adversarial.py' \
  'sed -i "s|                record\[\"key_raw\"\] = None|                pass|" lib/isedraf/loginpolicy/acquire.py' \
  'FAILED|Error'

inject "LOGINPOLICY a source path escapes the collection root" \
  'python3 tests/test_loginpolicy_adversarial.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/loginpolicy/acquire.py"); s = p.read_text()
s = s.replace("    yield os.path.join(root, main)", "    yield os.path.join(root + \"-outside\", main)", 1)
p.write_text(s)
PYX' \
  'FAILED|Error'

inject "PAM an unparsed rule line is retained verbatim instead of digested" \
  'python3 tests/test_pam_adversarial.py' \
  'sed -i "s|reason=\"first field is not a PAM rule type\")|reason=text)|" lib/isedraf/pam/sources.py' \
  'FAILED|Error'

inject "LOGINPOLICY a refused source is dropped from completeness like an absent one" \
  'python3 tests/test_loginpolicy.py' \
  'sed -i "s|              and s.get(\"detail\") == hostio.NOT_FOUND\]|]|" lib/isedraf/loginpolicy/acquire.py' \
  'FAILED|Error'

# Login-policy lane. The defect this domain can produce is subtle: a correct parser
# applied to the wrong grammar yields well-formed, well-provenanced, wrong evidence.
inject "LOGINPOLICY one profile is applied to every source family" \
  'python3 tests/test_loginpolicy.py' \
  'sed -i "s|PROFILES = {LOGIN_DEFS: LoginDefs(), PWQUALITY: PwQuality(), FAILLOCK: Faillock()}|PROFILES = {LOGIN_DEFS: LoginDefs(), PWQUALITY: LoginDefs(), FAILLOCK: LoginDefs()}|" lib/isedraf/loginpolicy/model.py' \
  'FAILED|Error'

inject "LOGINPOLICY limits.conf is forced through the key/value parser" \
  'python3 tests/test_loginpolicy.py' \
  'sed -i "s|    if family == model.LIMITS:|    if False:|" lib/isedraf/loginpolicy/acquire.py' \
  'FAILED|Error'

inject "LOGINPOLICY a cross-source effective value is computed" \
  'python3 tests/test_loginpolicy_adversarial.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/loginpolicy/acquire.py"); s = p.read_text()
s = s.replace("    status, reason = _status(sources_meta)", "    for r in records:\n        r[\"effective\"] = r.get(\"value\")\n    status, reason = _status(sources_meta)", 1)
p.write_text(s)
PYX' \
  'FAILED|Error'

inject "LOGINPOLICY a fragment filename rule is decided by the enumerator" \
  'python3 tests/test_loginpolicy.py' \
  'sed -i "s|    return name.endswith(\".conf\")|    return True|" lib/isedraf/loginpolicy/model.py' \
  'FAILED|Error'

# Sudo lane. The adversarial worker found the first one on first contact: an absolute
# include path under a fixture root resolved against the LIVE filesystem, so a fixture run
# would have read the machine executing it. The rest are the silent simplifications - a
# dropped negation inverts a policy, a misplaced tag misreports which command needs a
# password, and a generic directory listing includes the .bak files sudoers ignores.
inject "SUDO an absolute include escapes the collection root to the live host" \
  'python3 tests/test_sudo.py' \
  'sed -i "s|            return hostpath.under(self.root, target)|            return target|" lib/isedraf/sudo/acquire.py' \
  'FAILED|Error'

inject "SUDO a negation is dropped, inverting the policy" \
  'python3 tests/test_sudo_adversarial.py' \
  'sed -i "s|        negated = not negated|        negated = False|" lib/isedraf/sudo/sources.py' \
  'FAILED|Error'

inject "SUDO a command tag is attached to every command instead of from its position" \
  'python3 tests/test_sudo_adversarial.py' \
  'sed -i "s|        commands.append({\"command\": item\[\"value\"\], \"negated\": item\[\"negated\"\],|        commands.append({\"command\": item[\"value\"], \"negated\": item[\"negated\"],|;s|                         \"tags\": list(active)})|                         \"tags\": []})|" lib/isedraf/sudo/sources.py' \
  'FAILED|Error'

inject "SUDO the generic enumerator decides includedir membership instead of sudoers" \
  'python3 tests/test_sudo_adversarial.py' \
  'sed -i "s|    return \".\" not in name and not name.endswith(\"~\")|    return True|" lib/isedraf/sudo/model.py' \
  'FAILED|Error'

inject "SUDO an unparsed policy line is retained verbatim instead of digested" \
  'python3 tests/test_sudo_adversarial.py' \
  'sed -i "s|    record\[\"reason\"\] = \"line does not match any known sudoers construct\"|    record[\"reason\"] = text|" lib/isedraf/sudo/sources.py' \
  'FAILED|Error'

inject "SUDO an absent runas is filled in with the root default" \
  'python3 tests/test_sudo_adversarial.py' \
  'sed -i "s|    runas_users = runas_groups = None|    runas_users, runas_groups = [{\"value\": \"root\", \"negated\": False}], None|" lib/isedraf/sudo/sources.py' \
  'FAILED|Error'

# ARCH-01 artifact freshness. One artifact was already stale when this gate was written -
# the I/O map predated the gate it records - and it was found by hand. Two failures are
# gated: the code moving without the artifact, and the artifact being edited to describe an
# architecture someone wished existed.
inject "ARCH-01 a committed architecture artifact drifts from the code" \
  'python3 scripts/ci/check_architecture_artifacts.py' \
  'printf "\nisedraf.invented,lib/invented.py,f,NETWORK,socket,no\n" >> docs/development/architecture/generated/07_io_side_effects.csv' \
  'no longer matches its generator|freshness gate FAILED'

inject "ARCH-01 a diagram is edited to describe an architecture that does not exist" \
  'python3 scripts/ci/check_architecture_artifacts.py' \
  'sed -i "s|REPORT - report.model|REPORT - collects its own evidence|" docs/development/architecture/generated/04_evidence_flow.mmd' \
  'no longer matches its generator|freshness gate FAILED'

inject "ARCH-01 a shared primitive imports a domain module" \
  'python3 scripts/ci/check_architecture.py' \
  'sed -i "s|^from . import result|from . import result\nfrom ..accounts import model as _domain|" lib/isedraf/shared/compare.py' \
  'must not know their consumers|architecture gate FAILED'

inject "ARCH-01 a pure module acquires from the host" \
  'python3 scripts/ci/check_architecture.py' \
  'printf "\ndef _leak(p):\n    return open(p).read()\n" >> lib/isedraf/shared/keyvalue.py' \
  'pure module|architecture gate FAILED'

inject "ARCH-01 a network path appears in production code" \
  'python3 scripts/ci/check_architecture.py' \
  'printf "\nimport socket\ndef _reach():\n    return socket.socket()\n" >> lib/isedraf/shared/bounded.py' \
  'no network requests|architecture gate FAILED'

inject "ARCH-01 the renderer acquires instead of rendering committed evidence" \
  'python3 scripts/ci/check_architecture.py' \
  'sed -i "s|^from .profile import IDENTITY_DISCLAIMER|from .profile import IDENTITY_DISCLAIMER\nfrom ..accounts import acquire as _acq|" lib/isedraf/report/model.py' \
  'never collect new evidence|architecture gate FAILED'

inject "ARCH-01 the status vocabulary is defined in a second place" \
  'python3 scripts/ci/check_architecture.py' \
  'printf "\nCOLLECTED = \"COLLECTED\"\n" >> lib/isedraf/shared/result.py' \
  'defined in more than one place|not isedraf.status|architecture gate FAILED'

# S3 comparison. Absence is directional: an incomplete side blocks claims AGAINST that
# side and nothing else. Getting this wrong produces an accusation manufactured from a gap
# in our own reading - a rule reported as "declared but not active" when it may simply sit
# in the part of the active policy we could not read.
inject "S3 a partial active side still permits a DECLARED_ONLY claim" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|                           DECLARED_ONLY if active_complete else COUNTERPART_UNKNOWN,|                           DECLARED_ONLY,|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 a partial declared side still permits an ACTIVE_ONLY claim" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|                ACTIVE_ONLY if declared_complete else COUNTERPART_UNKNOWN,|                ACTIVE_ONLY,|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 duplicates are collapsed by keying on identity" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|        groups\[key\].append(record)|        groups[key] = [record]|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 an ambiguous pairing is guessed instead of declared ambiguous" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|    if len(d_list) > 1 or len(a_list) > 1:|    if False:|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 an order-sensitive comparator is served by identity grouping" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|    if comparator.order_sensitive:|    if False:|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 comparator semantics change without changing the provenance digest" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|    SEMANTIC_FIELDS = (\"name\", \"version\", \"order_sensitive\", \"equivalence_contract\",|    SEMANTIC_FIELDS = (\"name\",  #|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

# S5 bounded enumeration. The distinction that matters is a requested boundary being
# obeyed versus a safety cap firing: one is the answer to the question asked, the other is
# a short answer presented as a complete one.
inject "S5 the safety cap fires but the result is reported complete" \
  'python3 tests/test_shared_bounded.py' \
  'sed -i "s|        LIMIT_REACHED: True,|        LIMIT_REACHED: False,|" lib/isedraf/shared/bounded.py' \
  'FAILED|Error'

# S3 tri-state. The mounts lane proved a boolean equal() forces an undecidable pair into
# MODIFIED - a confident mismatch manufactured from missing evidence. Each mutation below
# re-collapses one of the four uncertainty classes back into another.
inject "S3 ignores explicit universe completeness and reads status instead" \
  'python3 tests/test_shared_compare.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/compare.py"); s = p.read_text()
old = "    declared_complete = bool(declared_universe_complete)\n    active_complete = bool(active_universe_complete)\n"
assert old in s, "mutation anchor miss"
new = ("    declared_complete = declared.status == result.COLLECTED\n"
       "    active_complete = active.status == result.COLLECTED\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "S3 treats a NOT_TESTED source as always bounding an incomplete universe" \
  'python3 tests/test_shared_compare.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/compare.py"); s = p.read_text()
old = "    declared_complete = bool(declared_universe_complete)\n"
assert old in s, "mutation anchor miss"
new = ("    declared_complete = bool(declared_universe_complete) and (\n"
       "        declared.status != result.NOT_TESTED)\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "S3 treats a COLLECTED source as always bounding a complete universe" \
  'python3 tests/test_shared_compare.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/compare.py"); s = p.read_text()
old = "    declared_complete = bool(declared_universe_complete)\n"
assert old in s, "mutation anchor miss"
new = ("    declared_complete = bool(declared_universe_complete) or (\n"
       "        declared.status == result.COLLECTED)\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "S3 gives universe completeness a silent default again" \
  'python3 tests/test_shared_compare.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/compare.py"); s = p.read_text()
old = "            declared_universe_complete, active_universe_complete):\n"
assert old in s, "mutation anchor miss"
new = ("            declared_universe_complete=None, active_universe_complete=None):\n"
       "    if declared_universe_complete is None:\n"
       "        declared_universe_complete = declared.status == result.COLLECTED\n"
       "    if active_universe_complete is None:\n"
       "        active_universe_complete = active.status == result.COLLECTED\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "S3 the provenance-schema contract vanishes from the comparator digest" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|                       \"provenance_contract\")|                       )|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 the completeness contract vanishes from the comparator digest" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|\"completeness_contract\",|#|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 multiplicity groups are paired positionally with zip" \
  'python3 tests/test_shared_compare.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/compare.py"); s = p.read_text()
old = "    if len(d_list) > 1 or len(a_list) > 1:\n"
assert old in s, "mutation anchor miss"
new = ("    if False:\n"
       "        pass\n"
       "    if len(d_list) > 1 or len(a_list) > 1:\n"
       "        for _d, _a in zip(d_list, a_list):\n"
       "            items.append(_item(key, _d, _a,\n"
       "                               _relationship(comparator, _d, _a),\n"
       "                               declared_complete, active_complete))\n"
       "        return items\n")
p.write_text(s.replace(old, new, 1))
PYX' \
  'FAILED|Error'

inject "S3 multiplicity groups are sorted and then paired positionally" \
  'python3 tests/test_shared_compare.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/compare.py"); s = p.read_text()
old = "    if len(d_list) > 1 or len(a_list) > 1:\n"
assert old in s, "mutation anchor miss"
new = ("    if len(d_list) > 1 or len(a_list) > 1:\n"
       "        _k = lambda r: sorted(str(v) for v in r.values())\n"
       "        for _d, _a in zip(sorted(d_list, key=_k), sorted(a_list, key=_k)):\n"
       "            items.append(_item(key, _d, _a,\n"
       "                               _relationship(comparator, _d, _a),\n"
       "                               declared_complete, active_complete))\n"
       "        return items\n")
p.write_text(s.replace(old, new, 1))
PYX' \
  'FAILED|Error'

inject "S3 an ambiguous pairing degrades acquisition coverage" \
  'python3 tests/test_shared_compare.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/compare.py"); s = p.read_text()
old = "    if acquired:\n        coverage, reason = COMPLETE, None\n"
assert old in s, "mutation anchor miss"
new = ("    if acquired and not [\n"
       "            i for i in items if i[\"relationship\"] == AMBIGUOUS]:\n"
       "        coverage, reason = COMPLETE, None\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "S3 the pairing contract vanishes from the comparator digest" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|                       \"pairing_contract\",|                       |" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 an undecidable pair is reported as a mismatch" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|                    UNKNOWN: EQUIVALENCE_UNKNOWN}|                    UNKNOWN: MODIFIED}|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 an undecidable pair is reported as a match" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|                    UNKNOWN: EQUIVALENCE_UNKNOWN}|                    UNKNOWN: MATCHED}|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 equivalence uncertainty is collapsed into absence uncertainty" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|                    UNKNOWN: EQUIVALENCE_UNKNOWN}|                    UNKNOWN: COUNTERPART_UNKNOWN}|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S3 an undecidable pair degrades acquisition coverage to PARTIAL" \
  'python3 tests/test_shared_compare.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/compare.py"); s = p.read_text()
old = "    if acquired:\n        coverage, reason = COMPLETE, None\n"
assert old in s, "mutation anchor miss"
new = ("    if acquired and not [\n"
       "            i for i in items if i[\"relationship\"] == EQUIVALENCE_UNKNOWN]:\n"
       "        coverage, reason = COMPLETE, None\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "S3 a comparator verdict outside the contract is coerced instead of refused" \
  'python3 tests/test_shared_compare.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/compare.py"); s = p.read_text()
old = "    if verdict not in _RELATIONSHIP_OF:\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    if False:\n").replace(
    "    return _RELATIONSHIP_OF[verdict]\n",
    "    return _RELATIONSHIP_OF.get(verdict, MODIFIED)\n"))
PYX' \
  'FAILED|Error'

inject "S3 the equivalence contract vanishes from the comparator digest" \
  'python3 tests/test_shared_compare.py' \
  'sed -i "s|\"equivalence_contract\",|#|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "S5 obeying the requested depth is reported as incomplete" \
  'python3 tests/test_shared_bounded.py' \
  'sed -i "s|        DEPTH_BOUNDARY: False,|        DEPTH_BOUNDARY: True,|" lib/isedraf/shared/bounded.py' \
  'FAILED|Error'

inject "S5 undecodable filenames collapse into one identity" \
  'python3 tests/test_shared_bounded.py' \
  'sed -i "s|    return sorted(names, key=textbytes.original_bytes)|    return sorted(n.encode(\"utf-8\",\"replace\").decode(\"utf-8\") for n in names)|" lib/isedraf/shared/bounded.py' \
  'FAILED|Error'

inject "S5 a symlink is followed out of the requested universe" \
  'python3 tests/test_shared_bounded.py' \
  'sed -i "s|            if entry_type == \"DIRECTORY\" and not is_link:|            if entry_type == \"DIRECTORY\" or is_link:|" lib/isedraf/shared/bounded.py' \
  'FAILED|Error'

inject "S5 entries collected before a failure are discarded" \
  'python3 tests/test_shared_bounded.py' \
  'sed -i "s|                source_path=directory, event=kind))|                source_path=directory, event=kind)); del entries[:]|" lib/isedraf/shared/bounded.py' \
  'FAILED|Error'

# S4 file metadata. Following a symlink and reporting the target as though it were the
# requested object is the defect this primitive exists to prevent, and claiming a digest
# belongs to metadata it was not collected with is the second.
inject "S4 a symlink is followed and the target reported as the requested object" \
  'python3 tests/test_shared_filemeta.py' \
  'sed -i "s|        info = os.lstat(path)|        info = os.stat(path)|" lib/isedraf/shared/filemeta.py' \
  'FAILED|Error'

inject "S4 metadata is discarded when the content digest cannot be collected" \
  'python3 tests/test_shared_filemeta.py' \
  'sed -i "s|        record\[\"digest_status\"\] = DIGEST_UNREADABLE|        record.clear(); record[\"digest_status\"] = DIGEST_UNREADABLE|" lib/isedraf/shared/filemeta.py' \
  'FAILED|Error'

inject "S4 a replaced object is digested as though it were the one measured" \
  'python3 tests/test_shared_filemeta.py' \
  'sed -i "s|        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):|        if False:|" lib/isedraf/shared/filemeta.py' \
  'FAILED|Error'

inject "S4 a timestamp is collected and becomes available as a creation date" \
  'python3 tests/test_shared_filemeta.py' \
  'sed -i "s|        \"nlink\": info.st_nlink,|        \"nlink\": info.st_nlink, \"ctime\": info.st_ctime,|" lib/isedraf/shared/filemeta.py' \
  'FAILED|Error'

# S1 key/value. The framework preserves declarations; resolving them is the domain's job.
# Collapsing a duplicate here would leave a later resolver nothing to explain, and a
# retention policy applied after serialization is not a retention policy.
inject "S1 a duplicate declaration is silently collapsed" \
  'python3 tests/test_shared_keyvalue.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/keyvalue.py"); s = p.read_text()
s = s.replace("    _mark_duplicates(records, anomalies, source)", "    _mark_duplicates(records, anomalies, source)\n    records = list({(r.get(\"section\"), r.get(\"key\")): r for r in records}.values())", 1)
p.write_text(s)
PYX' \
  'FAILED|Error'

inject "S1 the retention policy is bypassed and the raw value is stored" \
  'python3 tests/test_shared_keyvalue.py' \
  'sed -i "s|        stored, retention = result.retained(value, profile.retention(|        stored, retention = (value, None) if True else result.retained(value, profile.retention(|" lib/isedraf/shared/keyvalue.py' \
  'FAILED|Error'

inject "S1 an unknown key is treated as a parse error" \
  'python3 tests/test_shared_keyvalue.py' \
  'sed -i "s|    if malformed and malformed == len(records):|    if True:|" lib/isedraf/shared/keyvalue.py' \
  'FAILED|Error'

inject "S1 inline comments are stripped regardless of the profile" \
  'python3 tests/test_shared_keyvalue.py' \
  'sed -i "s|    if not profile.inline_comments:|    if False:|" lib/isedraf/shared/keyvalue.py' \
  'FAILED|Error'

inject "S2 the engine decides completeness instead of the adapter" \
  'python3 tests/test_shared_include_graph.py' \
  'sed -i "s|                if a.get(\"event\") and adapter.affects_completeness(a)]|                if a.get(\"event\")]|" lib/isedraf/shared/include_graph.py' \
  'FAILED|Error'

inject "S2 a zero-match wildcard is conflated with a missing literal target" \
  'python3 tests/test_shared_include_graph.py' \
  'sed -i "s|                        event=NO_MATCH if glob else MISSING_TARGET))|                        event=MISSING_TARGET))|" lib/isedraf/shared/include_graph.py' \
  'FAILED|Error'

inject "S2 a missing include target is silently ignored" \
  'python3 tests/test_shared_include_graph.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/shared/include_graph.py"); s = p.read_text()
s = s.replace("""                if not matches:""", """                if False:""", 1)
p.write_text(s)
PYX' \
  'FAILED|Error'

inject "S2 an include cycle is not detected" \
  'python3 tests/test_shared_include_graph.py' \
  'sed -i "s|        if real in visiting:|        if False:|" lib/isedraf/shared/include_graph.py' \
  'FAILED|Error'

inject "S2 the graph is sorted, destroying expansion order" \
  'python3 tests/test_shared_include_graph.py' \
  'sed -i "s|    status, reason = _status(nodes, anomalies, adapter)|    nodes.sort(key=lambda n: n[\"path\"])\n    status, reason = _status(nodes, anomalies, adapter)|" lib/isedraf/shared/include_graph.py' \
  'FAILED|Error'

# The project-wide absence invariant, both directions. Violated three times in three
# shapes now - this join, PAM cycle-versus-diamond, login-policy dropping a refused
# family - so both failure modes are mutated here rather than only the obvious one.
inject "W1D a counterpart that exists but is refused is reported as an absence" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    if not _domain_complete(shadow_result):|    if shadow_result[\"status\"] == model.NOT_TESTED and not shadow_result[\"parsed\"]:|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "W1D a partially read counterpart supports an absence claim" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    if not _domain_complete(shadow_result):|    if shadow_result[\"status\"] in (model.ERROR,):|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

# Acquisition truth. An identifier that does not survive being read is the worst class of
# defect this tool can have: everything downstream - hash, baseline, delta, report - would
# be about a host that does not exist. These three cover the regression and both halves of
# the representation.
inject "W1D a lossy reader silently rewrites an undecodable account name" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    outcome = _exec.read_file_lossless(path)|    outcome = _exec.read_file(path)|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "W1D an undecodable identifier is guessed instead of reported as undecodable" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|        return None, model.NAME_UNDECODABLE, textbytes.hex_of(raw), True|        return raw.encode(\"utf-8\",\"replace\").decode(\"utf-8\"), model.NAME_UNDECODABLE, textbytes.hex_of(raw), True|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "W1D the exact identifier bytes are discarded" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|\"name_bytes_hex\": rec\[\"name_bytes_hex\"\],|\"name_bytes_hex\": None,|g" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

# W1-D contract review rulings. Five mutations, one per ruling, so a future change that
# quietly reverses an owner decision cannot pass. The absence invariant gets two: it is
# the one most likely to be "simplified" back into a nullable field.
inject "W1D a readable empty source is downgraded to PARTIAL" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|return {\"source\": relative, \"status\": model.COLLECTED, \"reason\": None,\n                \"detail\": outcome.detail, \"parsed\": parsed}|X|" lib/isedraf/accounts/acquire.py; python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/accounts/acquire.py"); s = p.read_text()
s = s.replace("""        return {"source": relative, "status": model.COLLECTED, "reason": None,
                "detail": outcome.detail, "parsed": parsed}

    if parsed.malformed_count:""", """        return {"source": relative, "status": model.PARTIAL, "reason": "SOURCE_EMPTY",
                "detail": outcome.detail, "parsed": parsed}

    if parsed.malformed_count:""", 1)
p.write_text(s)
PYX' \
  'FAILED|Error'

inject "W1D a partial counterpart source still yields an absence claim" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    if not _domain_complete(shadow_result):|    if shadow_result[\"status\"] in (model.NOT_TESTED, model.ERROR):|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "W1D an orphan is claimed from an incompletely read passwd source" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    passwd_complete = _domain_complete(passwd_result)|    passwd_complete = passwd_result[\"parsed\"] is not None|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "W1D GECOS is promoted to baseline-bound STATE" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    \"gecos\": OBSERVATION,|    \"gecos\": STATE,|" lib/isedraf/accounts/model.py' \
  'FAILED|Error'

inject "W1D an unrecognized hash scheme leaks raw password-field material" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|            scheme = model.HASH_SCHEMES.get(match.group(1),|            scheme = model.HASH_SCHEMES.get(match.group(1), match.group(1)) or (|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

# Hardening lane (owner, 2026-09-24): account files parsed as glibc reads them, and a
# truncated read is never complete evidence. One mutation per hardening item.
inject "HARD-1 a non-ASCII blank before # hides an account again" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|        line = raw.split(\"\\\\x00\", 1)\[0\].lstrip(_C_SPACE)|        line = raw.split(\"\\\\x00\", 1)[0].lstrip()|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "HARD-2 account files are split with splitlines again" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    segments = text.split(\"\\\\n\")|    segments = text.splitlines()|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "HARD-3 an id glibc rejects no longer forces PARTIAL" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|            # glibc drops a line whose uid or gid it cannot read, so the record is not|            rec[\"malformed\"] = True; malformed -= 1  # mutated|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "HARD-4 a signed id is no longer read as glibc reads it" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    if i < len(value) and value\[i\] in \"+-\":|    if i < len(value) and value[i] in \"-\":|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "HARD-5 a shadow line glibc rejects becomes the joined record" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|                    shadow_index\[key\] = _UNCERTAIN if uncertain else rec|                    shadow_index[key] = rec|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "HARD-6 a name is printed into a duplicate anomaly (owner ruling N3)" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|                    \"the same %s (%d bytes) appears at lines %d and %d\"|                    repr(rec.get(\"name\")) + \" the same %s (%d bytes) appears at lines %d and %d\"|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "HARD-N3 an orphan shadow record carries its name text" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|            ({\"line\": shadow_index\[k\]\[\"line\"\], \"name_length\": len(k) // 2}|            ({\"line\": shadow_index[k][\"line\"], \"name_length\": len(k) // 2, \"name\": shadow_index[k][\"name\"]}|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "HARD-7 a truncated read is returned as complete" \
  'python3 tests/test_hostio.py' \
  'sed -i "s|        if total >= limit and os.read(fd, 1):|        if False:|" lib/isedraf/hostio.py' \
  'FAILED|Error'

# Hardening red team: one mutation per finding fixed.
inject "HARD-F1 shadow field 9 is no longer validated" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|        if parts\[8\] != \"\":|        if False:|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "HARD-F2 group members keep the blanks glibc strips" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|            m = m.lstrip(_C_SPACE)|            m = m|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "HARD-F3 -0 is no longer uid 0" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    if (sign == \"-\" and number != 0) or number > UID_MAX:|    if sign == \"-\" or number > UID_MAX:|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "HARD-F5 the shadow join uses the decoded name again" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|            relation = _shadow_relation(rec\[\"name_bytes_hex\"\], shadow_result, shadow_index)|            relation = _shadow_relation(rec[\"name\"], shadow_result, shadow_index)|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "HARD-F10 a FIFO is read instead of refused" \
  'python3 tests/test_hostio.py' \
  'sed -i "s|        if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):|        if False:|" lib/isedraf/hostio.py' \
  'FAILED|Error'

inject "HARD-N4 an incomplete inventory read no longer makes the subdomain PARTIAL" \
  'python3 tests/test_inventory.py' \
  'sed -i "s|        if not outcome.ok and outcome.detail in (TRUNCATED, IO_ERROR, PERMISSION_DENIED):|        if False:|" lib/isedraf/inventory/collectors.py' \
  'FAILED|Error'

inject "HARD-N6 orphans of undecodable groups are deduplicated on the decoded name" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|(g\[\"name_bytes_hex\"\], member)|(g[\"name\"], member)|g" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

# Differential harness (owner ruling N1/N2): the recorded glibc corpus catches each class.
inject "DIFF-N1 a blank-prefixed line without its terminator is trusted again" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|        uncertain = raw\[:1\] in _C_SPACE and raw\[:1\] != \"\" and (|        uncertain = False and (|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "DIFF-N2 a later shadow line is joined past a malformed first one" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|                    shadow_index\[key\] = _UNCERTAIN if uncertain else rec|                    if not uncertain: shadow_index[key] = rec|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

# DIFF-PM (a "+"/"-" name joined to shadow) was removed with its guard at the Lane B rebase:
# the compat-aware parser never makes a record from a "+"/"-" line in any NSS mode, so no
# account name can start with one. W1D-9 and IQ-036 injections cover that boundary.

# Final re-check R3 (the harness now compares initgroups and empty names).
inject "DIFF-R3-1 a commented group entry initgroups still reads is skipped again" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|        if not line or (commented and not (entry_comments and \":\" in line)):|        if not line or commented:|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "DIFF-R3-2 an empty account name is trusted again" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|    if parts\[0\] != \"\":|    if True:|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

# Two layers since R4 (the guard, and a malformed group's members blanked): both removed.
inject "HARD-R3-3 a malformed group line yields orphan members" \
  'python3 tests/test_accounts.py' \
  'sed -i -e "s|            if g\[\"group_anomalies\"\]:|            if False:|" -e "s|                group\[\"explicit_members\"\] = \[\]|                pass|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "HARD-R3-3b a malformed account line yields an orphan primary gid" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|            if a\[\"passwd_anomalies\"\]:|            if False:|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

# Re-check R4: untrusted record text never reaches STATE; permission refusal is not absence.
inject "HARD-R4-1 a malformed group record keeps its text in STATE" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|                _redact_untrusted(group, ())|                pass|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "HARD-R4-2 a malformed account record keeps its text in STATE" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|                _redact_untrusted(account, (\"home\", \"shell\", \"gecos\"))|                pass|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "HARD-R4-3 an unreadable inventory source reads as absence again" \
  'python3 tests/test_inventory.py' \
  'sed -i "s|outcome.detail in (TRUNCATED, IO_ERROR, PERMISSION_DENIED):|outcome.detail in (TRUNCATED, IO_ERROR):|" lib/isedraf/inventory/collectors.py' \
  'FAILED|Error'

# Batch 3 NSS and hostname lane (NSS_HOSTNAME_LANE_CONTRACT.md). One mutation per
# boundary the contract freezes.
inject "NSS service order is lost to a sort" \
  'python3 tests/test_nss.py' \
  'sed -i "s|^        if not entries:$|        entries.sort(key=lambda e: e[\"service\"])\n        if not entries:|" lib/isedraf/nss/sources.py' \
  'FAILED|Error'

inject "NSS identity topology is classified as STATE" \
  'python3 tests/test_nss.py' \
  'sed -i "s|    \"identity_nss_topology\": PROVENANCE,|    \"identity_nss_topology\": STATE,|" lib/isedraf/nss/model.py' \
  'FAILED|Error'

inject "NSS an unclassified service is assumed to be local files" \
  'python3 tests/test_nss.py' \
  'sed -i "s|    return SERVICE_CLASS.get(service, UNKNOWN)|    return SERVICE_CLASS.get(service, LOCAL_FILES)|" lib/isedraf/nss/model.py' \
  'FAILED|Error'

inject "NSS identity digest covers presentation (line numbers)" \
  'python3 tests/test_nss.py' \
  'sed -i "s|        item = {\"database\": rec\[\"database\"\], \"entries\": rec\[\"entries\"\],|        item = {\"database\": rec[\"database\"], \"entries\": rec[\"entries\"], \"line\": rec[\"line\"],|" lib/isedraf/nss/acquire.py' \
  'FAILED|Error'

inject "HOSTNAME a short name is treated as equal to its FQDN" \
  'python3 tests/test_hostname.py' \
  'sed -i "s|    return (model.EQUAL if value == active\[\"value\"\] else model.DIFFERENT), None|    return (model.EQUAL if value.split(\".\")[0] == active[\"value\"].split(\".\")[0] else model.DIFFERENT), None|" lib/isedraf/hostname/sources.py' \
  'FAILED|Error'

inject "HOSTNAME a template is compared as if it were a name" \
  'python3 tests/test_hostname.py' \
  'sed -i "s|    if model.TEMPLATE_CHARACTER in value:|    if False:|" lib/isedraf/hostname/sources.py' \
  'FAILED|Error'

# Red-team pass 1 on the NSS and hostname lane: one mutation per reproduced finding.
inject "RT-F6 a shadow directive's override text is retained" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    keep_text = not problems and keep_override_text|    keep_text = True|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "RT-F5 leading blanks hide a compat directive again" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|        line = raw.split(\"\\\\x00\", 1)\[0\].lstrip(_C_SPACE)|        line = raw.split(\"\\\\x00\", 1)[0]|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "RT-F1 nsswitch.conf is split with splitlines again" \
  'python3 tests/test_nss.py' \
  'sed -i "s|    for number, line in enumerate(text.split(\"\\\\n\"), start=1):|    for number, line in enumerate(text.splitlines(), start=1):|" lib/isedraf/nss/sources.py' \
  'FAILED|Error'

inject "RT-F2 a second action bracket is merged into the first" \
  'python3 tests/test_nss.py' \
  'sed -i "s|                elif previous_bracket:|                elif False:|" lib/isedraf/nss/sources.py' \
  'FAILED|Error'

inject "RT-F4 the compat pseudo-databases leave identity scope" \
  'python3 tests/test_nss.py' \
  'sed -i "s|\"passwd_compat\", \"group_compat\", \"shadow_compat\", \"netgroup\")|)|" lib/isedraf/nss/model.py' \
  'FAILED|Error'

inject "RT-F9 the NSS collector follows a symlink out of the root" \
  'python3 tests/test_nss.py' \
  'sed -i "s|    if not _contained(root, path):|    if False:|" lib/isedraf/nss/acquire.py' \
  'FAILED|Error'

inject "RT-F10 an invalid DNS hostname is compared" \
  'python3 tests/test_hostname.py' \
  'sed -i "s|    if not _valid_dns_name(value):|    if False:|" lib/isedraf/hostname/sources.py' \
  'FAILED|Error'

# Red-team pass 2 on the NSS and hostname lane. (The FIFO fix, #13, has no injection: the
# harness has no timeout, so a reverted fix would hang it rather than fail it.)
inject "RT2-2 an invalid line elsewhere no longer moves the identity digest" \
  'python3 tests/test_nss.py' \
  'sed -i "s|             \"unsupported_anywhere\": _unsupported_anywhere(parsed.records)}),|             \"unsupported_anywhere\": []}),|" lib/isedraf/nss/acquire.py' \
  'FAILED|Error'

inject "RT2-3 a blank after ! is accepted again" \
  'python3 tests/test_nss.py' \
  'sed -i "s|(!?)(\[A-Za-z\]+)|(!?)[ ]*([A-Za-z]+)|" lib/isedraf/nss/sources.py' \
  'FAILED|Error'

inject "RT2-4 a line whose colon comes later is dropped again" \
  'python3 tests/test_nss.py' \
  'sed -i "s|        if not sep or any(c in database.strip(_WHITESPACE) for c in _WHITESPACE):|        if not sep:|" lib/isedraf/nss/sources.py' \
  'FAILED|Error'

inject "RT2-6 a directive name is no longer validated" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    elif raw_name and not _DIRECTIVE_NAME.match(raw_name):|    elif False:|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

# Red-team pass 3 on the NSS and hostname lane.
inject "RT3-F2 an include no longer withdraws absence claims" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    return result\[\"status\"\] == model.COLLECTED and not _includes(result)|    return result[\"status\"] == model.COLLECTED|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "RT3-F1 numeric directive overrides are no longer checked" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    if any(i < len(overrides) and _shape(overrides\[i\]) == \"OTHER\" for i in positions):|    if False:|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "RT3-F4 colons after the database name are kept as a service" \
  'python3 tests/test_nss.py' \
  'sed -i "s|        rest = rest.lstrip(_WHITESPACE + \":\")|        rest = rest|" lib/isedraf/nss/sources.py' \
  'FAILED|Error'

inject "F6 compat directive order no longer enters the source digest" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|        out\[rel\] = \[{\"local\": _local_key(item, index\[rel\], label\[rel\])} if kind == \"local\"|        out[rel] = [None if kind == \"local\"|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "M2 shadow ageing integers no longer enter the source digest" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    if d.get(\"ageing_values\") is not None:|    if False:|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "P5-H2 an out-of-range ageing integer is accepted as valid" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    elif any(i < len(overrides) and _shape(overrides\[i\]) == \"INTEGER\"|    elif False and any(i < len(overrides) and _shape(overrides[i]) == \"INTEGER\"|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "P6-5 a malformed local record enters the topology by name" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    if (name is not None and not record.get(\"malformed\")|    if (name is not None|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

# W1-D §9 clarification (owner, 2026-09-24): compat directives are not accounts. One
# mutation per boundary the ruling set.
inject "W1D-9 a compat directive is parsed as an account again" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    if line\[:1\] not in (\"+\", \"-\"):|    if True:|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "W1D-9 a valid compat directive forces PARTIAL" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|            malformed += 1 if directive\[\"malformed\"\] else 0|            malformed += 1|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "W1D-9 a compat directive retains its password field raw" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|        \"password_field_state\": _password_state(parts\[1\]) if len(parts) > 1 else None,|        \"password_field_state\": parts[1] if len(parts) > 1 else None,|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

# Owner ruling IQ-036: the meaning of "+"/"-" lines depends on the resolved NSS mode.
inject "IQ-036 files together with compat is taken as compat" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|if nss_model.LOCAL_FILES in classes|if False|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "IQ-036 no NSS context is guessed to be compat" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|context = dict({rel: model.NSS_MODE_NOT_ASSERTED for rel in _NSS_DATABASE},|context = dict({rel: model.NSS_COMPAT for rel in _NSS_DATABASE},|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "IQ-036 compat syntax is read as directives under every NSS mode" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|        if mode == model.NSS_COMPAT:|        if True:|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "IQ-036 a local record after a compat INCLUDE is trusted as resolved locally" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|    later = \[rec for rec in parsed.records if rec\[\"line\"\] > min(includes)\]|    later = []|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

# Red team pass 6, P6-2/P6-3: names the topology may not print keep text-free references.
inject "P6-2 unprintable topology names collapse to one marker again" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    return {\"ref\": ref} if ref is not None else \"INVALID_OR_UNDECODABLE_NAME\"|    return \"INVALID_OR_UNDECODABLE_NAME\"|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "P6-3 malformed NAME directives of one length collide again" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|                item\[\"name_ref\"\] = ref|                pass|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

# Red team pass 7: compat around the NSS topology and around local lines.
inject "P7-F1 initgroups reading /etc/group literally no longer withdraws compat" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|        if lines and (len(lines) != 1 or lines\[0\].get(\"semantics\") != nss_model.KNOWN|        if False and (len(lines) != 1 or lines[0].get(\"semantics\") != nss_model.KNOWN|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "P7-F2 a local line after an EXCLUDE naming it is confident again" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|            _local_after_exclude(r, rel, parsed)|            pass|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "P7-F3 the shadow join trusts a compat-uncertain record" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|                    shadow_index\[key\] = _UNCERTAIN if uncertain else rec|                    shadow_index[key] = _UNCERTAIN if rec[\"malformed\"] else rec|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "P7-F4 records after compat syntax in an unknown NSS mode are confident" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|        if mode == model.NSS_MODE_NOT_ASSERTED:|        if False:|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "P7-F5 undecodable override text is kept as text and breaks serialization" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|        overrides = \[\"hex:\" + textbytes.hex_of(v) if textbytes.has_surrogates(v) else v|        overrides = [v|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

# Owner ruling IQ-037: collection truth and effective-resolution truth are separate facts.
inject "IQ-037 an unknown identity service leaves NSS complete" \
  'python3 tests/test_nss.py' \
  'sed -i "s|        if unknown:|        if False:|" lib/isedraf/nss/acquire.py' \
  'FAILED|Error'

inject "IQ-037 a file NSS never reads is claimed effective" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|        state = model.FILES_INACTIVE|        state = model.FILES_ACTIVE|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "IQ-037 a plain files database hides behind NOT_ASSERTED" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|        state = model.FILES_ACTIVE|        state = model.FILES_NOT_ASSERTED|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "IQ-037 an unknown module beside files is inferred harmless" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    if nss_model.UNKNOWN in classes:|    if False:|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

# Red team pass 8.
inject "P8-N1 a compat map that is the local file is taken as compat" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|                         \& {nss_model.LOCAL_FILES, nss_model.COMPAT, nss_model.UNKNOWN}):|                         \& set()):|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "P8-N3 initgroups in a different mode from group is trusted" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|                      or _mode_of(lines\[0\]) != context\[GROUP\]):|                      or _mode_of(lines[0]) == model.NSS_COMPAT and False):|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "P8-N2 a later same-name record stands in for a line glibc resolves" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|        _shadowed_by_earlier_line(results\[rel\])|        pass|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "P8-N4 undecodable record text is kept as text and breaks serialization" \
  'python3 tests/test_glibc_differential.py' \
  'sed -i "s|    return \"hex:\" + textbytes.hex_of(value) if textbytes.has_surrogates(value) else value|    return value|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "P8-L2 EXCLUDE override text is kept" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    keep_text = not problems and keep_override_text and line\[:1\] == \"+\"|    keep_text = not problems and keep_override_text|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

# GA track, CLI truth (SCOPE-077): a usage error must never exit with INCOMPLETE's code.
inject "GA-CLI-1 a usage error exits 2 again" \
  'python3 tests/test_cli.py' \
  'sed -i "s|        self.exit(USAGE_OR_ENGINE, |        self.exit(2, |" lib/isedraf/cli.py' \
  'FAILED|Error'

# RC1 rehearsal: a refused `sudo isedraf` wrote root-owned bytecode into /usr/lib/isedraf.
inject "RC1-LAUNCH-1 the launcher lets the interpreter write bytecode again" \
  'python3 tests/test_launcher.py' \
  'sed -i "s|exec \"\$PY\" -B -c|exec \"\$PY\" -c|" bin/isedraf' \
  'FAILED|Error'

# GA track, `isedraf audit`: one committed run, reported only after the ledger commits it.
inject "GA-AUDIT-1 the report follows the newest directory, not the ledger" \
  'python3 tests/test_audit.py' \
  'sed -i "s|    name = records\[-1\]\[\"record_core\"\]\[\"snapshot_id\"\]|    name = sorted(os.listdir(os.path.join(root, \"snapshots\")))[-1]|" lib/isedraf/report/model.py' \
  'FAILED|Error'

inject "GA-AUDIT-2 audit sections are bound but never written into the bundle" \
  'python3 tests/test_audit.py' \
  'sed -i "s|            for name, data in sorted(built\[\"sections\"\].items()):|            for name, data in []:|" lib/isedraf/snapshot.py' \
  'FAILED|Error'

inject "GA-AUDIT-3 a collector exception text is recorded in its section" \
  'python3 tests/test_audit.py' \
  'sed -i "s|            reason = \"COLLECTOR_ERROR: %s raised %s\" % (name, type(exc).__name__)|            reason = \"COLLECTOR_ERROR: %s\" % exc|" lib/isedraf/audit.py' \
  'FAILED|Error'

inject "GA-AUDIT-4 a partial audit run is reported COMPLETE" \
  'python3 tests/test_audit.py' \
  'sed -i "s|    statuses += \[s.get(\"collection_status\") for s in (audit_sections or {}).values()\]|    statuses += []|" lib/isedraf/report/model.py' \
  'FAILED|Error'

# D-116 (STORE-026/027): the user-mode production store.
inject "A015-1 a remote filesystem is accepted for a production commit" \
  'python3 tests/test_stateroot.py' \
  'sed -i "s|    if fstype in UNSUITABLE_FILESYSTEMS or family in UNSUITABLE_FILESYSTEMS:|    if False:|" lib/isedraf/stateroot.py' \
  'FAILED|Error'

inject "A015-2 a filesystem of unknown semantics is accepted" \
  'python3 tests/test_stateroot.py' \
  'sed -i "s|    if fstype not in SUITABLE_FILESYSTEMS:|    if False:|" lib/isedraf/stateroot.py' \
  'FAILED|Error'

inject "A015-3 a permissive evidence store is used" \
  'python3 tests/test_stateroot.py' \
  'sed -i "s|    if stat.S_IMODE(info.st_mode) != 0o700:|    if False:|" lib/isedraf/stateroot.py' \
  'FAILED|Error'

inject "A015-4 the verifier accepts any state_root literal" \
  'python3 tests/test_stateroot.py' \
  'sed -i "s|    if core.get(\"state_root\") not in stateroot.STATE_ROOT_CLASSES:|    if False:|" lib/isedraf/verify.py' \
  'FAILED|Error'

# Report 0.1 (D-117): host text is data, never markup; the evidence boundary is stated.
inject "GA-HTML-1 the HTML report stops escaping host values" \
  'python3 tests/test_report_html.py' \
  'sed -i "s|    return (text.replace(\"&\", \"&amp;\").replace(\"<\", \"&lt;\").replace(\">\", \"&gt;\")|    return (text|" lib/isedraf/report/render.py' \
  'FAILED|Error'

inject "GA-HTML-2 the unprivileged banner no longer says NOT_TESTED is not a pass" \
  'python3 tests/test_report_html.py' \
  'sed -i "s|NOT_TESTED does not mean those controls passed; it means they were not |observed |" lib/isedraf/report/render.py' \
  'FAILED|Error'

# GA lifecycle proof: the package version and the evidence's engine_version agree.
inject "GA-PKG-2 packages are built from a tree with uncommitted changes" \
  'bash packaging/build.sh' \
  'echo "uncommitted" >> README.md' \
  'uncommitted changes; packages are built from a commit only'

inject "GA-PKG-1 VERSION is bumped without ENGINE_VERSION" \
  'python3 scripts/ci/check_packaging.py' \
  'echo 9.9.9-test > VERSION' \
  'ENGINE_VERSION in lib/isedraf/__init__.py'

# W1-D account source contract. Nine mutations, one per contract boundary that a later
# collector could quietly cross. Each targets a branch the contract exists to protect:
# the parser must stay pure, the join must keep "unread" distinct from "absent", and no
# policy label may be manufactured from a UID, a shell or a group name.
inject "W1D shadow that was never read is reported as COLLECTED" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|if all(s == model.COLLECTED for s in statuses):|if True:|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "W1D an unread shadow source is rendered as an absent shadow record" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|return model.RECORD_SOURCE_NOT_COLLECTED|return model.RECORD_ABSENT_FROM_COLLECTED_SOURCE|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "W1D the password hash is retained in the normalized record" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|return {\"lock_prefix\": lock, \"content\": content, \"hash_scheme\": scheme}|return {\"lock_prefix\": lock, \"content\": content, \"hash_scheme\": scheme, \"raw\": raw}|" lib/isedraf/accounts/sources.py' \
  'FAILED|Error'

inject "W1D a duplicate username is silently resolved by a dictionary" \
  'python3 tests/test_accounts.py' \
  'python3 - <<PYX
import re, pathlib
p = pathlib.Path("lib/isedraf/accounts/sources.py")
s = p.read_text()
s = s.replace("    _duplicates(records, \"name\", \"uid\", anomalies)\n    return ParsedSource(",
              "    _duplicates(records, \"name\", \"uid\", anomalies)\n    records = list({r[\"name\"]: r for r in records}.values())\n    return ParsedSource(", 1)
p.write_text(s)
PYX' \
  'FAILED|Error'

inject "W1D a UID threshold manufactures a system/human classification" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|\"shadow\": None,|\"shadow\": None, \"human\": (rec[\"uid\"] or 0) >= 1000,|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "W1D a nologin shell manufactures an inactive classification" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|\"shadow\": None,|\"shadow\": None, \"inactive\": rec[\"shell\"] == \"/usr/sbin/nologin\",|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "W1D a group named sudo manufactures a privilege verdict" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|\"group_anomalies\": rec\[\"anomalies\"\],|\"group_anomalies\": rec[\"anomalies\"], \"privileged\": rec[\"name\"] in (\"sudo\", \"wheel\", \"admin\"),|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "W1D a home directory timestamp becomes an account creation time" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|\"shadow\": None,|\"shadow\": None, \"created_at\": rec[\"line\"],|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

inject "W1D a fixture-root parser reaches the live /etc" \
  'python3 tests/test_accounts.py' \
  'sed -i "s|    path = os.path.join(root, relative)|    path = os.path.join(root, relative)\n    if not os.path.exists(path): path = os.path.join(\"/\", relative)|" lib/isedraf/accounts/acquire.py' \
  'FAILED|Error'

# ROOTPATH. The same live-host fallthrough as the injection above, reached from the other
# direction: not a reader that gives up and retries at "/", but a path expression that
# lets `..` walk out of the collection root. Both lanes carried the expression
# independently before it was extracted, and reverting either one must be observed.
inject "ROOTPATH containment is string-prefix arithmetic again" \
  'python3 tests/test_hostpath.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/hostpath.py"); s = p.read_text()
old = "    return candidate_parts[:len(root_parts)] == root_parts\n"
assert old in s, "mutation anchor miss"
new = ("    base = os.path.normpath(root)\n"
       "    return candidate.startswith(base + os.sep) or candidate == base\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "ROOTPATH containment accepts a sibling whose name extends the root" \
  'python3 tests/test_hostpath.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/hostpath.py"); s = p.read_text()
old = "    return candidate_parts[:len(root_parts)] == root_parts\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    return os.path.normpath(candidate).startswith(os.path.normpath(root))\n"))
PYX' \
  'FAILED|Error'

inject "ROOTPATH the host path is normalised after the join instead of before" \
  'python3 tests/test_hostpath.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/hostpath.py"); s = p.read_text()
old = ("    normalized = os.path.normpath(HOST_ROOT + host_path.lstrip(HOST_ROOT))\n"
       "    return os.path.normpath(os.path.join(root, normalized.lstrip(HOST_ROOT)))\n")
assert old in s, "mutation anchor miss"
new = "    return os.path.normpath(os.path.join(root, host_path.lstrip(HOST_ROOT)))\n"
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|escaped to'

inject "ROOTPATH containment is achieved by clamping, destroying the host meaning" \
  'python3 tests/test_hostpath.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/hostpath.py"); s = p.read_text()
old = "    return os.path.normpath(os.path.join(root, normalized.lstrip(HOST_ROOT)))\n"
assert old in s, "mutation anchor miss"
new = ("    joined = os.path.normpath(os.path.join(root, host_path.lstrip(HOST_ROOT)))\n"
       "    base = os.path.normpath(root)\n"
       "    if joined != base and not joined.startswith(base + os.sep):\n"
       "        return base\n"
       "    return joined\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "ROOTPATH the sudo lane returns to its own rooted-path arithmetic" \
  'python3 tests/test_sudo_adversarial.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/sudo/acquire.py"); s = p.read_text()
old = "return hostpath.under(self.root, target)"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "return os.path.join(self.root, target.lstrip(chr(47)))"))
PYX' \
  'FAILED|outside the collection root'

inject "ROOTPATH the ssh lane returns to its own rooted-path arithmetic" \
  'python3 tests/test_ssh_adversarial.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/ssh/acquire.py"); s = p.read_text()
old = "return hostpath.under(self.root, target)"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "return os.path.join(self.root, target.lstrip(chr(47)))"))
PYX' \
  'FAILED|outside the collection root'

inject "ROOTPATH a relative include target is allowed to climb out of the root" \
  'python3 tests/test_sudo_adversarial.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/sudo/acquire.py"); s = p.read_text()
old = ("        return hostpath.beneath(\n"
       "            self.root, os.path.join(os.path.dirname(parent), target))\n")
assert old in s, "mutation anchor miss"
new = "        return os.path.join(os.path.dirname(parent), target)\n"
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|outside the collection root'

# AUTHORIZED_KEYS. The lane's whole discipline is refusing to say more than it observed,
# so the injections attack the refusals rather than the parsing. Each one turns an honest
# "I do not know" into a confident answer, which is the only way this lane can be wrong in
# a way that matters.
# R1.5-P. The contract's whole content is that a machine can tell WHY coverage is
# incomplete without parsing English. Every mutation here restores a form of the defect
# that was measured: the distinction computed and then destroyed.
# D-115. The binding exists so that an auxiliary artifact cannot be swapped for another
# valid one. Each mutation removes one of the reasons it cannot.
inject "D-115 an auxiliary artifact is no longer opened during verification" \
  'python3 tests/test_auxiliary_binding.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/verify.py"); s = p.read_text()
old = "        if digest != snapshot_mod.auxiliary_digest(data):\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "        if False:\n"))
PYX' \
  'FAILED|Error'

inject "D-115 the auxiliary binding is dropped from manifest_core" \
  'python3 tests/test_auxiliary_binding.py' \
  'sed -i "s|        \"auxiliary_artifacts\": dict(auxiliary or {}),|        \"auxiliary_artifacts\": {},|" lib/isedraf/snapshot.py' \
  'FAILED|Error'

inject "D-115 method/host_identity.json goes back to being unbound" \
  'python3 tests/test_auxiliary_binding.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/snapshot.py"); s = p.read_text()
old = "    auxiliary = {\"method/host_identity.json\": auxiliary_digest(method)}\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    auxiliary = {}\n"))
PYX' \
  'FAILED|Error'

inject "D-115 an unbound artifact present in the bundle is silently ignored" \
  'python3 tests/test_auxiliary_binding.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/verify.py"); s = p.read_text()
old = "        if present:\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "        if False:\n"))
PYX' \
  'FAILED|is in the bundle and is not bound|Error'

inject "D-115 auxiliary content leaks into the host-state hash" \
  'python3 tests/test_auxiliary_binding.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/canonical.py"); s = p.read_text()
old = "DOMAIN_AUXILIARY_ARTIFACT = \"ISEDRAF:AUXILIARY-ARTIFACT:V1\"\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "DOMAIN_AUXILIARY_ARTIFACT = DOMAIN_STATE\n"))
PYX' \
  'FAILED|Error'

inject "D-115 the registry becomes a recursive directory walk" \
  'python3 tests/test_auxiliary_binding.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/snapshot.py"); s = p.read_text()
old = "AUXILIARY_ARTIFACTS = (\"coverage/evidence_limits.json\", \"method/host_identity.json\")\n"
assert old in s, "mutation anchor miss"
new = ("AUXILIARY_ARTIFACTS = (\"coverage/evidence_limits.json\",\n"
       "                       \"method/host_identity.json\", \"coverage/.nfs-swap\")\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "R15P an inventory command failure becomes a privilege limitation" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/inventory/__init__.py"); s = p.read_text()
old = "            outcome = (coverage.READ_OK if status == COLLECTED\n"
assert old in s, "mutation anchor miss"
new = "            outcome = (coverage.READ_OK if status == COLLECTED\n                       else coverage.PERMISSION_DENIED if status == ERROR\n"
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "R15P a missing inventory tool is reported as an authority problem" \
  'python3 tests/test_coverage.py' \
  'sed -i "s|else coverage.NOT_SUPPORTED if status == NOT_TESTED|else coverage.PERMISSION_DENIED if status == NOT_TESTED|" lib/isedraf/inventory/__init__.py' \
  'FAILED|Error'

inject "R15P NOT_SUPPORTED migrates into the file-io vocabulary" \
  'python3 tests/test_coverage.py' \
  'sed -i "s|^READ_OK = \"READ_OK\"|READ_OK = \"READ_OK\"\nNOT_SUPPORTED = \"NOT_SUPPORTED\"|" lib/isedraf/hostio.py' \
  'FAILED|Error'

inject "R15P an unproducible elevated acquisition mode returns to the vocabulary" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/coverage.py"); s = p.read_text()
old = "MODES = (MODE_CURRENT_IDENTITY,)\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "MODE_ELEVATED = \"ELEVATED\"\nMODES = (MODE_CURRENT_IDENTITY, MODE_ELEVATED)\n"))
PYX' \
  'FAILED|Error'

inject "R15P a completeness count starts reading the acquisition mode" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/coverage.py"); s = p.read_text()
old = "        \"complete_sources\": len([s for s in ordered\n                                 if not s[\"affects_completeness\"]]),\n"
assert old in s, "mutation anchor miss"
new = "        \"complete_sources\": (len(ordered) if acquisition_mode else len(\n            [s for s in ordered if not s[\"affects_completeness\"]])),\n"
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "CQ-1 the absence rule reads source status again" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/coverage.py"); s = p.read_text()
old = "def absence_claim_allowed(universe):\n"
assert old in s, "mutation anchor miss"
s = s.replace(old, "def absence_claim_allowed(universe, status=COLLECTED):\n")
s = s.replace("    return universe in (UNIVERSE_COMPLETE, UNIVERSE_NOT_APPLICABLE)\n",
              "    return status == COLLECTED and universe in (UNIVERSE_COMPLETE, UNIVERSE_NOT_APPLICABLE)\n")
s = s.replace("absence_claim_allowed(universe),", "absence_claim_allowed(universe, status),")
p.write_text(s)
PYX' \
  'FAILED|Error'

inject "CQ-1 the two absence authorities disagree again" \
  'python3 tests/test_coverage.py' \
  'sed -i "s|    return universe in (UNIVERSE_COMPLETE, UNIVERSE_NOT_APPLICABLE)|    return universe == UNIVERSE_NOT_APPLICABLE|" lib/isedraf/coverage.py' \
  'FAILED|Error'

inject "CQ-3 the S3 scalar reclaims the R1.5-P coverage key" \
  'python3 tests/test_coverage.py' \
  'sed -i "s|        \"comparison_input_coverage\": coverage,|        \"coverage\": coverage,|" lib/isedraf/shared/compare.py' \
  'FAILED|Error'

inject "CQ-3 an R1.5-P producer degrades its coverage list to a scalar" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/accounts/acquire.py"); s = p.read_text()
old = "        \"coverage\": [\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "        \"coverage\": \"COMPLETE\", \"coverage_entries\": [\n", 1))
PYX' \
  'FAILED|Error'

inject "R15P a refusal is reported without saying access was the cause" \
  'python3 tests/test_coverage.py' \
  'sed -i "s|    return outcome == PERMISSION_DENIED|    return False|" lib/isedraf/coverage.py' \
  'FAILED|Error'

inject "R15P an absent source invents a privilege requirement" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/coverage.py"); s = p.read_text()
old = "    if outcome != PERMISSION_DENIED:\n        return ACCESS_NONE\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    if outcome == READ_OK:\n        return ACCESS_NONE\n"))
PYX' \
  'FAILED|Error'

inject "R15P an incompletely observed source is allowed to support an absence claim" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/coverage.py"); s = p.read_text()
old = "    return universe in (UNIVERSE_COMPLETE, UNIVERSE_NOT_APPLICABLE)\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    return True\n"))
PYX' \
  'FAILED|Error'

inject "R15P a perfect read of an unresolved universe permits an absence claim" \
  'python3 tests/test_coverage.py' \
  'sed -i "s|    return universe in (UNIVERSE_COMPLETE, UNIVERSE_NOT_APPLICABLE)|    return universe in (UNIVERSE_COMPLETE, UNIVERSE_NOT_APPLICABLE, UNIVERSE_INCOMPLETE)|" lib/isedraf/coverage.py' \
  'FAILED|Error'

inject "R15P the shadow access outcome is dropped before serialization again" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/accounts/acquire.py"); s = p.read_text()
old = "                            coverage.OP_FILE_READ, reason=r[\"reason\"],"
assert old in s, "mutation anchor miss"
new = "                            coverage.OP_FILE_READ, reason=r[\"reason\"],"
s = s.replace("coverage.source(\"accounts\", rel, r[\"status\"], r[\"detail\"],",
              "coverage.source(\"accounts\", rel, r[\"status\"], coverage.NOT_FOUND,")
p.write_text(s)
PYX' \
  'FAILED|Error'

inject "R15P the coverage digest stops distinguishing two visibilities" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/coverage.py"); s = p.read_text()
old = "              \"access_outcome\": s[\"access_outcome\"],\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, ""))
PYX' \
  'FAILED|Error'

inject "R15P a coverage comparison starts asserting a host-state delta" \
  'python3 tests/test_coverage.py' \
  'sed -i "s|\"host_state_delta\": \"NOT_ESTABLISHED_BY_COVERAGE_COMPARISON\",|\"host_state_delta\": \"HOST_CHANGED\",|" lib/isedraf/coverage.py' \
  'FAILED|Error'

inject "R15P the report stops saying no mode makes an incomplete run complete" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/report/model.py"); s = p.read_text()
old = "    if manifest[\"limitations\"]:\n        out.append(\n            \"This collection is incomplete over its requested evidence universe. No \"\n"
assert old in s, "mutation anchor miss"
new = "    if False:\n        out.append(\n            \"This collection is incomplete over its requested evidence universe. No \"\n"
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "R15P the renderer goes back to parsing the English reason" \
  'python3 tests/test_coverage.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/report/model.py"); s = p.read_text()
old = "    limited = [s for s in manifest[\"limitations\"] if s[\"privilege_limited\"]]\n"
assert old in s, "mutation anchor miss"
new = "    limited = [s for s in manifest[\"limitations\"]\n               if \"permission denied\" in (s[\"reason\"] or \"\").lower()]\n"
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "AK the conventional path is invented when no declaration was observed" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/acquire.py"); s = p.read_text()
old = "        plan[\"universe_reasons\"].append(model.NO_DECLARATION_OBSERVED)\n        return plan\n"
assert old in s, "mutation anchor miss"
new = ("        declarations = [{\"value\": \".ssh/authorized_keys\", \"scope\": \"GLOBAL\",\n"
       "                         \"match_index\": None, \"match_criteria\": None,\n"
       "                         \"source_path\": None, \"source_line\": None,\n"
       "                         \"ordinal\": None}]\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "AK a Match-scoped declaration is flattened into global scope" \
  'python3 tests/test_authorizedkeys.py' \
  'sed -i "s|            \"scope\": record.get(\"scope\"),|            \"scope\": \"GLOBAL\",|" lib/isedraf/authorizedkeys/acquire.py' \
  'FAILED|Error'

inject "AK a successful read is allowed to make the source universe complete" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/acquire.py"); s = p.read_text()
old = "    plan[\"source_universe\"] = (model.UNIVERSE_COMPLETE if not ordered\n                               else model.UNIVERSE_INCOMPLETE)\n"
assert old in s, "mutation anchor miss"
new = ("    read = [c for c in plan[\"candidates\"]\n"
       "            if c.get(\"observation\") == model.FILE_READ]\n"
       "    plan[\"source_universe\"] = (model.UNIVERSE_COMPLETE if read or not ordered\n"
       "                               else model.UNIVERSE_INCOMPLETE)\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "AK an unknown token is guessed away instead of stopping the candidate" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/acquire.py"); s = p.read_text()
old = "        else:\n            unexpanded = \"%\" + token\n            break\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "        else:\n            out.append(account.get(\"name\") or \"\")\n"))
PYX' \
  'FAILED|Error'

inject "AK a key comment is retained in the evidence" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/sources.py"); s = p.read_text()
old = "    record[\"comment_present\"] = bool(comment and comment.strip())\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, old + "    record[\"comment\"] = comment\n"))
PYX' \
  'FAILED|Error'

inject "AK an option value is retained without a retention decision" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/sources.py"); s = p.read_text()
old = "            entry[\"value\"] = value if decision == RETAIN_VALUE else None\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "            entry[\"value\"] = value\n"))
PYX' \
  'FAILED|Error'

inject "AK a declared candidate escapes the collection root" \
  'python3 tests/test_authorizedkeys.py' \
  'sed -i "s|        candidate\[.path.\] = hostpath.under(root, expanded)|        candidate[chr(112)+chr(97)+chr(116)+chr(104)] = expanded|" lib/isedraf/authorizedkeys/acquire.py' \
  'FAILED|Error'

# AK. Found by the independent adversarial pass, not by the lane that wrote the code.
# hostpath is lexical and cannot see a home that IS a symlink out of the collection root:
# the path is contained and open() reads the collector's own machine.
# AK / IQ-014. The owner ruling permits a Match-scoped candidate to be READ and forbids
# it from becoming effective. These two mutations are the promotion it forbids: one turns
# a conditional candidate into an unconditional one, the other lets a run where every
# file happened to be readable answer a question R1.5 never asks.
inject "AK a conditional candidate is promoted to unconditional" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/acquire.py"); s = p.read_text()
old = ("        \"applicability\": (model.UNRESOLVED_MATCH_SCOPED\n"
       "                          if declaration.get(\"scope\") == \"MATCH\"\n"
       "                          else model.UNCONDITIONAL),\n")
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "        \"applicability\": model.UNCONDITIONAL,\n"))
PYX' \
  'FAILED|Error'

inject "AK complete candidate acquisition is reported as a known effective source set" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/acquire.py"); s = p.read_text()
old = "        \"effective_source_universe\": model.EFFECTIVE_NOT_EVALUATED,\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "        \"effective_source_universe\": model.UNIVERSE_COMPLETE,\n"))
PYX' \
  'FAILED|Error'

inject "AK the effectiveness axis is dropped from the evidence entirely" \
  'python3 tests/test_authorizedkeys_adversarial.py' \
  'sed -i "/record\[.effective_source.\] = model.EFFECTIVE_NOT_EVALUATED/d" lib/isedraf/authorizedkeys/acquire.py' \
  'FAILED|Error'

inject "AK a key record loses the applicability that conditions it" \
  'python3 tests/test_authorizedkeys_adversarial.py' \
  'sed -i "s|        record\[.declaration_applicability.\] = candidate\[.applicability.\]|        record[chr(100)+\"eclaration_applicability\"] = model.UNCONDITIONAL|" lib/isedraf/authorizedkeys/acquire.py' \
  'FAILED|Error'

inject "AK the containment check refuses everything at the production root" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/acquire.py"); s = p.read_text()
old = "    return hostpath.contains(os.path.realpath(root), os.path.realpath(path))\n"
assert old in s, "mutation anchor miss"
new = ("    _b = os.path.realpath(root)\n"
       "    return os.path.realpath(path).startswith(_b + os.sep)\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "AK a symlinked home escapes the collection root at open() time" \
  'python3 tests/test_authorizedkeys_adversarial.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/acquire.py"); s = p.read_text()
old = "    return hostpath.contains(os.path.realpath(root), os.path.realpath(path))\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    return True\n"))
PYX' \
  'FAILED|outside the collection root|leaked'

inject "AK the upstream reason is absorbed instead of carried" \
  'python3 tests/test_authorizedkeys_adversarial.py' \
  'sed -i "s|\"upstream_reason\": getattr(ssh_evidence, \"reason\", None)|\"upstream_reason\": None|" lib/isedraf/authorizedkeys/acquire.py' \
  'FAILED|Error'

inject "AK a declared type the blob contradicts is reported as OK" \
  'python3 tests/test_authorizedkeys_adversarial.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/sources.py"); s = p.read_text()
old = "        else model.PARSE_OK if blob_type == key_type\n        else model.PARSE_KEY_TYPE_MISMATCH)\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "        else model.PARSE_OK)\n"))
PYX' \
  'FAILED|Error'

inject "AK an undecodable home is repaired instead of used exactly" \
  'python3 tests/test_authorizedkeys_adversarial.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/acquire.py"); s = p.read_text()
old = "    return {\"host\": host, \"rooted\": hostpath.under(root, host)}\n"
assert old in s, "mutation anchor miss"
new = ("    host = host.encode(\"utf-8\", \"surrogateescape\").decode(\"utf-8\", \"replace\")\n"
       "    return {\"host\": host, \"rooted\": hostpath.under(root, host)}\n")
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

inject "AK the candidate loses the scope that conditions it" \
  'python3 tests/test_authorizedkeys_adversarial.py' \
  'sed -i "s|        \"scope\": declaration.get(\"scope\"),|        \"scope\": None,|" lib/isedraf/authorizedkeys/acquire.py' \
  'FAILED|Error'

inject "AK the lane grows a second passwd acquisition path" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/acquire.py"); s = p.read_text()
old = "from . import model, sources\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, old + "from ..accounts import sources as _passwd  # /etc/passwd\n"))
PYX' \
  'FAILED|Error'

inject "AK a comma inside a quoted option value splits it into two options" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/sources.py"); s = p.read_text()
old = "        if character == \",\" and not quoted:\n"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "        if character == \",\":\n"))
PYX' \
  'FAILED|Error'

inject "AK the key fingerprint stops matching what ssh-keygen prints" \
  'python3 tests/test_authorizedkeys.py' \
  'sed -i "s|    digest = hashlib.sha256(blob).digest()|    digest = hashlib.sha256(blob + b\"x\").digest()|" lib/isedraf/authorizedkeys/sources.py' \
  'FAILED|Error'

inject "AK a glob that matched nothing is reported as a missing file" \
  'python3 tests/test_authorizedkeys.py' \
  'sed -i "s|        candidate\[.observation.\] = model.GLOB_NO_MATCH$|        candidate[chr(111)+chr(98)+chr(115)+chr(101)+chr(114)+chr(118)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)] = model.FILE_ABSENT|" lib/isedraf/authorizedkeys/acquire.py' \
  'FAILED|Error'

inject "AK a malformed line is dropped instead of recorded" \
  'python3 tests/test_authorizedkeys.py' \
  'python3 - <<PYX
import pathlib
p = pathlib.Path("lib/isedraf/authorizedkeys/sources.py"); s = p.read_text()
old = "        if record[\"parse_status\"] != model.PARSE_OK:\n            malformed += 1\n        records.append(record)\n"
assert old in s, "mutation anchor miss"
new = "        if record[\"parse_status\"] != model.PARSE_OK:\n            malformed += 1\n            continue\n        records.append(record)\n"
p.write_text(s.replace(old, new))
PYX' \
  'FAILED|Error'

# GOV-001. layer_of() returned "external" for anything unlisted and rule 1 skipped it, so
# the four Batch 2 domain lanes were exempt from the layering rule for a whole batch and
# nothing said so. An unlisted module must be refused, not excused.
inject "GOV-001 a production module belongs to no layer" \
  'python3 scripts/ci/check_architecture.py' \
  'mkdir -p lib/isedraf/unplaced && printf "VALUE = 1\n" > lib/isedraf/unplaced/thing.py && git add -A' \
  'belongs to no layer'

# IQ-011. The previous sample described a retired storage schema for three versions and
# nothing noticed, because no gate compared a published document against the evidence it
# came from. These two prove the sample cannot drift from its evidence in either
# direction: the document edited by hand, and the evidence changed underneath it.
inject "IQ-011 the published sample drifts from the evidence it is generated from" \
  'python3 scripts/docs/sample_report.py check' \
  'sed -i "s/| Kernel subsystem |/| Class |/" docs/reference/samples/SAMPLE_REPORT.md' \
  'SAMPLE_REPORT.md|does not match the committed evidence'

inject "IQ-011 the committed evidence changes without the sample being regenerated" \
  'python3 scripts/docs/sample_report.py check' \
  'python3 - <<PYX
import json
p = "docs/reference/samples/evidence/collected_inventory.json"
d = json.load(open(p))
d["subdomains"]["storage"]["data"]["devices"][0]["queue_rotational"] = False
json.dump(d, open(p, "w"))
PYX' \
  'SAMPLE_REPORT|does not match the committed evidence'

# GOV-001. The coverage gate used to verify only what was DECLARED, so an undeclared
# gate passed by not being mentioned. These two prove it now reconciles the declaration
# against the directory in both directions.
inject "GOV-001 a gate script is added that nothing declares or runs" \
  'python3 scripts/ci/check_gate_coverage.py' \
  'printf "import sys\nsys.exit(0)\n" > scripts/ci/check_orphan_example.py && git add -A' \
  'does not account for|gate coverage FAILED'

inject "GOV-001 a declared gate script is deleted from the tree" \
  'python3 scripts/ci/check_gate_coverage.py' \
  'git rm -q --cached scripts/ci/check_sbom.py && rm -f scripts/ci/check_sbom.py' \
  'does not exist|gate coverage FAILED'

# D-114 / STORAGE-SEMANTICS-001. The retired storage vocabulary survived in a published
# sample report for three schema versions, because every gate read the source and none
# read the documentation. These three prove the gate now reads the whole surface: a
# device record carrying the retired value, a device table whose column hides the source,
# and the retired enum constant returning to the engine.
inject "D-114 a published document reports a storage device type of ROTATIONAL" \
  'python3 scripts/ci/check_storage_vocabulary.py' \
  'printf "%s\n" "{\"name\": \"sda\", \"type\": \"ROTATIONAL\"}" > docs/reference/PLATFORM_COMPATIBILITY.md' \
  'retired value|storage vocabulary gate FAILED'

inject "D-114 a storage table column says Class instead of naming its kernel source" \
  'python3 scripts/ci/check_storage_vocabulary.py' \
  'printf "%s\n%s\n" "| Device | Size | Class | Model |" "|---|---|---|---|" > docs/reference/PLATFORM_COMPATIBILITY.md' \
  'Class/Type column|storage vocabulary gate FAILED'

inject "D-114 the retired DEVICE_SOLID_STATE constant returns to the engine" \
  'python3 scripts/ci/check_storage_vocabulary.py' \
  'printf "%s\n" "DEVICE_SOLID_STATE = \"SOLID_STATE\"" >> lib/isedraf/inventory/collectors.py' \
  'retired storage vocabulary|storage vocabulary gate FAILED'

# D-86. The deb and the rpm are built by two different implementations. Dropping a
# document from one of them must be caught by comparing them, not by anyone remembering.
inject "D-86 the rpm and the deb ship different documentation" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash packaging/build.sh 2>&1; bash scripts/ci/check_package_payload.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("packaging/rpm/isedraf.spec.in"); s = p.read_text()
old = "install -m 0644 docs/operator/STORAGE_AND_OUTPUTS.md"
assert old in s, "mutation anchor miss"
head, sep, tail = s.partition(old)
p.write_text(head + tail.split("\n", 1)[1].split("\n", 1)[1])
PYX' \
  'ship DIFFERENT documentation'

# The comparison was by basename until the guides moved into docs/ (0.1.0, 2026-09-29): it
# failed identical payloads, and it could never see a guide installed in the wrong
# directory. It now compares paths relative to the doc directory.
inject "D-86 the rpm installs a guide outside docs/" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash packaging/build.sh 2>&1; bash scripts/ci/check_package_payload.sh' \
  'sed -i "s|%{_docdir}/isedraf/docs/\$guide.md|%{_docdir}/isedraf/\$guide.md|" packaging/rpm/isedraf.spec.in' \
  'ship DIFFERENT documentation'

# PUBLIC-OPS-001 structured. YAML sat outside the prose scan because prose patterns fire
# on every legitimate `permissions: contents: read`. But YAML carries exactly what the
# rule exists to prevent, so EXACT identifiers are scanned in every file type instead -
# no false positives by construction.
inject "PUBLIC-OPS-001 a private repository identifier appears in a workflow" \
  'python3 scripts/ci/check_privacy.py --scope release' \
  'printf "\n# mirror of itcmsgr/isedraf-dev\n" >> .github/workflows/governance.yml' \
  'forbidden operational identifier|PUBLIC-OPS-001'

inject "PUBLIC-OPS-001 a private registry path appears in a tracked file" \
  'python3 scripts/ci/check_privacy.py --scope release' \
  'printf "\nSee PROVIDERS_LICENSE for details.\n" >> docs/reference/GLOSSARY.md' \
  'forbidden operational identifier|PUBLIC-OPS-001'

# An exclusion must mean "absent from release artifacts", not "unscanned". Its subject is
# an excluded FILE, so in a public checkout - where those files do not exist - breaking the
# exclusion changes nothing and the injection cannot fire. Declared with next_requires so
# it is a stated SKIP there rather than an unexpected non-firing, which would fail public
# CI for doing exactly the right thing. This breaks
# the EXPORT's reading of the exclusion list while leaving the list itself intact - so
# the paths are still DECLARED excluded and are no longer REMOVED, which is the failure
# mode an exclusion list actually has.
next_requires "CLAUDE.md"
inject "PUBLIC-OPS-001 an excluded path is declared but no longer removed" \
  'bash scripts/ci/release_export.sh >/dev/null 2>&1; python3 scripts/ci/check_privacy.py --scope release' \
  'sed -i "s|sed -n .s/\^\!//p.|sed -n /__NEVER__/p|" scripts/ci/release_export.sh' \
  'excluded from the release surface|present in the export|privacy gate FAILED'

# PUBLIC-OPS-001. The public repository published an unresolved finding about its own
# private engineering environment: a vendor name, an App id with permissions, the private
# repository's attack surface and the remediation steps. Found at 0 views and 0 clones.
inject "PUBLIC-OPS-001 a public document names a private-repository weakness" \
  'python3 scripts/ci/check_privacy.py --scope release' \
  'printf "\nThe private engineering repository allows force-push to main.\n" >> docs/reference/GLOSSARY.md' \
  'protection weakness|PUBLIC-OPS-001'

inject "PUBLIC-OPS-001 a public document exposes private-repository integration scope" \
  'python3 scripts/ci/check_privacy.py --scope release' \
  'printf "\nAn external service has access to the private engineering repository.\n" >> docs/reference/GLOSSARY.md' \
  'access or integration scope|PUBLIC-OPS-001'

inject "PUBLIC-OPS-001 an external App identifier and its permissions are published" \
  'python3 scripts/ci/check_privacy.py --scope release' \
  'printf "\nThe app id 46505 requests contents: read on every repository.\n" >> docs/reference/GLOSSARY.md' \
  'App identifier or permission detail|PUBLIC-OPS-001'

inject "PUBLIC-OPS-001 remediation instructions for an integration are published" \
  'python3 scripts/ci/check_privacy.py --scope release' \
  'printf "\nGo to Settings -> Applications, then Installed GitHub Apps, to fix this.\n" >> docs/reference/GLOSSARY.md' \
  'remediation instructions|PUBLIC-OPS-001'

# D-90. The blocking privacy scope must cover everything the source tarball ships, which
# is every tracked file. Removing a tree from the surface list must fail, not silently
# shrink the scope that blocks - that is how scripts/ and tests/ went unguarded.
inject "D-90 a shipped tree is dropped from the blocking privacy surface" \
  'python3 scripts/ci/check_privacy.py --scope release' \
  'sed -i "/^scripts\/\*\*$/d" scripts/ci/release_surface.txt' \
  'UNCOVERED|privacy gate FAILED'

# D-86/GOV-002. An SBOM is a claim about bytes. These injections mutate the GENERATOR,
# not the document, so what is proven falsifiable is the pipeline a release actually runs.
# The rpm case is the sharp one: rpm's own recorded per-file digests are a second,
# independent account of the same package, so the gate is not grading its own homework.
inject "D-86 the SBOM omits a file that is in the package" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash packaging/build.sh 2>&1; python3 scripts/ci/check_sbom.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/ci/generate_sbom.py"); s = p.read_text()
old = "            if not path.is_file():"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "            if not path.is_file() or path.name == \"cli.py\":", 1))
PYX' \
  'does not list it|SBOM accuracy gate FAILED'

inject "D-86 the SBOM binds to a digest that is not the artifact" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash packaging/build.sh 2>&1; python3 scripts/ci/check_sbom.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/ci/generate_sbom.py"); s = p.read_text()
old = "    artifact_digest = sha256_file(artifact)"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    artifact_digest = \"0\" * 64", 1))
PYX' \
  'states artifact sha256|SBOM accuracy gate FAILED'

inject "D-86 the SBOM presents the interpreter as bundled rather than external" \
  'git add -A >/dev/null 2>&1; git -c user.name=falsifiable -c user.email=falsifiable@invalid commit -qm mutation >/dev/null 2>&1; bash packaging/build.sh 2>&1; python3 scripts/ci/check_sbom.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/ci/generate_sbom.py"); s = p.read_text()
old = "            \"filesAnalyzed\": False,"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "            \"filesAnalyzed\": True,", 1))
PYX' \
  'as if this package contained it|SBOM accuracy gate FAILED'

# D-89. The status page drifted until it said no product code existed while three
# commands worked. Two injections: a claim with no evidence behind it, and a page that
# stopped matching its own registry.
inject "D-89 the status registry claims a capability whose evidence is absent" \
  'python3 scripts/docs/current_state.py check' \
  'python3 - <<'"'"'PYX'"'"'
import json, pathlib
p = pathlib.Path("scripts/ci/project_status.json"); d = json.loads(p.read_text())
d["capabilities"]["report_pdf"] = {"status": "IMPLEMENTED", "evidence": "lib/isedraf/report/pdf.py"}
p.write_text(json.dumps(d, indent=2) + "\n")
PYX' \
  'evidence .* does not exist|generation REFUSED'

inject "D-89 the generated status page is edited by hand" \
  'python3 scripts/docs/current_state.py check' \
  'printf "\n\nISEDRAF is production ready.\n" >> docs/CURRENT_STATE.md' \
  'is stale'

# C-06 / C-01 / D-88. Fourteen gates guarded the evidence and none guarded the prose: the
# README claimed actions were pinned with "no tag exceptions" beside a mutable tag, a
# certification matrix carried two corpus digests, and the status page said no product
# code existed. Four injections, because the four failures look nothing alike.
inject "C-06 competitive framing naming an external project" \
  'python3 scripts/ci/check_docs_truth.py' \
  'printf "\nISEDRAF is a replacement for osquery in this role.\n" >> docs/reference/GLOSSARY.md' \
  'COMPETITIVE_FRAMING'

# C-01. The .git branch added for worktree support is a new code path, and a new code
# path in a gate is a new way for the gate to stop discriminating. A .git reference that
# genuinely does not exist must still fail, in a clone and in a worktree alike.
inject "C-01 a document names a git path that does not exist" \
  'python3 scripts/ci/check_docs_truth.py' \
  'printf "\nSee \140.git/no-such-thing\140 for details.\n" >> docs/roadmap/ROADMAP.md' \
  'DANGLING_REFERENCE'

inject "C-01 a document names a repository file that does not exist" \
  'python3 scripts/ci/check_docs_truth.py' \
  'printf "\nSee the guide in \`docs/reference/NO_SUCH_GUIDE.md\` for details.\n" >> docs/reference/GLOSSARY.md' \
  'DANGLING_REFERENCE'

inject "D-88 a third-party action is pinned to a mutable tag" \
  'python3 scripts/ci/check_docs_truth.py' \
  'sed -i "s|actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065|actions/setup-python@v5|" .github/workflows/governance.yml' \
  'MUTABLE_ACTION_PIN'

inject "D-88 a document quotes a stale corpus digest as authoritative" \
  'python3 scripts/ci/check_docs_truth.py' \
  'printf "\nThe corpus digest is \`deadbeefdeadbeefdeadbeef\`.\n" >> docs/reference/GLOSSARY.md' \
  'STALE_DIGEST'

# D-90: a pre-publication audit found an SSH fingerprint and a verbatim ssh_config stanza
# inside docs/ after two rounds of grepping had declared the tree clean. The answer to a
# missed leak is a gate, not more grepping.
inject "D-90 an operator identifier reaches the publication surface" \
  'python3 scripts/ci/check_privacy.py --scope release' \
  'printf "\nSee 172.31.255.7 for the internal host.\n" >> docs/reference/GLOSSARY.md  # privacy:planted-fixture' \
  'REAL_OPERATOR_IDENTIFIER'

inject "D-90 a private key path is committed into docs" \
  'python3 scripts/ci/check_privacy.py --scope release' \
  'printf "\nKey at ~/.ssh/id_ed25519_release for deploys.\n" >> docs/reference/GLOSSARY.md  # privacy:planted-fixture' \
  'SSH_PRIVATE_KEY_PATH'

# W1-C1 -> D-114. An optical drive reports rotational=0 exactly like an SSD, and
# classifying on that alone put a QEMU DVD-ROM in the first published sample as
# SOLID_STATE. The branch this used to mutate no longer exists: D-114 retired the whole
# classification chain. STORAGE-SEMANTICS-002 says such an injection is REPLACED by one
# protecting the corrected model, not deleted - the concern survives, the mechanism
# changed. The peripheral type is now the evidence, and it must be recorded and scoped.
inject "D-114 the SCSI peripheral type is dropped from the observation" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/collectors.py"); s = p.read_text()
old = "                \"scsi_peripheral_type\": peripheral,"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "                \"scsi_peripheral_type\": None,", 1))
PYX' \
  'scsi_peripheral_type|FAILED'

inject "D-114 the peripheral type leaks outside the SCSI family" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/collectors.py"); s = p.read_text()
old = "            if subsystem == \"scsi\" and scsi_type.ok:"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "            if scsi_type.ok:", 1))
PYX' \
  'leaked into|FAILED'

# W1-C1: the report tells its reader that incomplete observations explain themselves.
inject "SCOPE-022 an incomplete collection carries no reason" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/model.py"); s = p.read_text()
old = "    if requires_reason(status) and not reason:"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    if False:"))
PYX' \
  'ValueError not raised|requires a reason'

# W1-C2: the report must never claim the inventory is snapshot-bound. This is the one
# way a presentation layer can quietly manufacture an evidentiary claim.
inject "SNAP-021 report binds inventory to the frozen snapshot hash" \
  'python3 tests/test_report.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/report/model.py"); s = p.read_text()
old = "            \"collection_id\": art[\"core\"][\"collection_id\"],"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, old + "\n            \"manifest_hash\": identity.get(\"manifest_hash\"),\n            \"snapshot_id\": identity.get(\"snapshot_id\"),"))
PYX' \
  'manifest_hash|snapshot_id'

# W1-C2: assessment metadata is presentation. If it can reach evidence, the same
# collection rendered for two audiences stops being the same collection.
inject "report assessment metadata leaks into evidence" \
  'python3 tests/test_report.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/report/model.py"); s = p.read_text()
old = "    identity = identity_evidence(root)"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, old + "\n    if assessment:\n        identity[\"prepared_for\"] = assessment.get(\"customer\")"))
PYX' \
  'identity_evidence|AssertionError'

# W1-C1: the noise test is the acceptance condition for inventory. If a stable fact can
# drift between two immediate collections without the test failing, the whole
# state/observation classification is decorative.
inject "SCOPE-045 an inventory field is left unclassified" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/collectors.py"); s = p.read_text()
old = "    return reads.subdomain(model.COLLECTED, data, method=\"/proc/cpuinfo\","
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    data[\"unclassified_extra\"] = 1\n" + old))
PYX' \
  'unclassified inventory fields'

inject "SCOPE-063 a hardware observation is treated as stable state" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/model.py"); s = p.read_text()
old = "    \"time.uptime_seconds\": VOLATILE_OBSERVATION,"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    \"time.uptime_seconds\": HARDWARE_OBSERVATION,"))
PYX' \
  'non-volatile inventory fields changed|uptime_seconds'

# D-12: the production floor is worth nothing as a sentence. Two injections - one API
# the grammar cannot see, one syntax the grammar can - because they fail differently.
inject "D-12 production code uses an API newer than the runtime floor" \
  'python3 scripts/ci/check_python_floor.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/verify.py"); s = p.read_text()
old = "import json\nimport os"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "import json\nimport os\nimport subprocess\n\n\ndef _probe():\n    return subprocess.run([\"true\"], capture_output=True)\n"))
PYX' \
  'capture_output.*requires Python 3.7'

inject "D-12 production code uses syntax newer than the runtime floor" \
  'python3 scripts/ci/check_python_floor.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/identity.py"); s = p.read_text()
old = "def method_object():"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "def _walrus_probe(v):\n    if (n := len(v)) > 0:\n        return n\n    return 0\n\n\ndef method_object():"))
PYX' \
  'syntax is newer than Python 3.6'

inject "D-12 shell syntax error" \
  'make check-shell' \
  'printf "\nif then fi\n" >> scripts/ci/check_paths.sh' \
  'syntax error'

next_requires "docs/architecture/MASTER_INDEX.md"
inject "D-68 frozen artifact modified after manifest" \
  'bash scripts/ci/check_freeze.sh' \
  'mkdir -p docs/architecture/freeze && sha256sum docs/architecture/MASTER_INDEX.md > docs/architecture/freeze/TEST.sha256 && printf "\ndrift\n" >> docs/architecture/MASTER_INDEX.md' \
  'digest mismatch'

# IQ-029: the hook reverted to checking the working tree it was run from. The snapshot is
# still built and then ignored, which is the realistic regression: nothing looks removed.
inject "IQ-029 pre-commit validates the working tree instead of the committed content" \
  'bash scripts/ci/check_precommit_index.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("git-hooks/pre-commit"); t = p.read_text()
p.write_text(t.replace("cd \"$snapdir\" || exit 1", "cd \"$root\" || exit 1"))
PYX' \
  'the hook PASSED and git committed'

# IQ-034 / D-84: an allowlist, not a denylist. Each closure criterion is one injection.
inject "D-84 runtime imports a module that is not on the allowlist" \
  'python3 scripts/ci/check_runtime_imports.py' \
  'printf "\nimport ctypes\n" >> lib/isedraf/ids.py' \
  'not in the D-84 allowlist'

inject "D-84 runtime imports a forbidden network module" \
  'python3 scripts/ci/check_runtime_imports.py' \
  'printf "\nimport socket\n" >> lib/isedraf/ids.py' \
  'imports forbidden module'

inject "D-84 the allowlist permits a forbidden module" \
  'python3 scripts/ci/check_runtime_imports.py' \
  'printf "urllib\n" >> lib/isedraf/runtime-imports.allow' \
  'permits forbidden module'

inject "D-84 runtime import allowlist deleted" \
  'python3 scripts/ci/check_runtime_imports.py' \
  'rm -f lib/isedraf/runtime-imports.allow' \
  'failing closed'

inject "D-84 runtime import allowlist malformed" \
  'python3 scripts/ci/check_runtime_imports.py' \
  'printf "not a module\n" >> lib/isedraf/runtime-imports.allow' \
  'malformed allowlist line'

inject "D-84 dynamic import bypasses the allowlist" \
  'python3 scripts/ci/check_runtime_imports.py' \
  'printf "\n__import__(\"os\")\n" >> lib/isedraf/ids.py' \
  'dynamic import via __import__'

# Z-18: deleting the corpus must fail the gate, not silently disable it.
inject "NORM-039 golden corpus deleted entirely (Z-18)" \
  'bash scripts/vectors/check.sh' \
  'rm -rf test-vectors/w1a/v1' \
  'golden corpus is release-blocking'

inject "NORM-039 golden vector mutated by one byte" \
  'bash scripts/vectors/check.sh' \
  'printf "x" >> test-vectors/w1a/v1/01-valid-machine-id/expected/host-id.txt' \
  'regenerated vectors differ'

# D-115 gave the verifier a SECOND, independent path to a corrupted method object: the
# auxiliary binding recomputes method.canonical's digest from its bytes. Disabling the
# method-literal check alone therefore no longer causes acceptance - the redundancy is
# welcome, and it made this injection stop proving its claim. It now disables BOTH, so
# what is falsified is "the verifier detects a corrupted method object" rather than "this
# one line exists".
inject "Z-14 verifier accepts a corrupted artifact" \
  'bash scripts/vectors/negative_test.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p=pathlib.Path("scripts/vectors/verify.py"); s=p.read_text()
old = "    if meth != METHOD_LITERAL:"
assert old in s, "mutation anchor miss"
s = s.replace(old, "    if False:")
aux = "            unframe_check(D_AUXILIARY, rd(artifact), digest[7:],"
assert aux in s, "auxiliary anchor miss"
s = s.replace(aux, "            pass  # disabled\n            _skip(D_AUXILIARY, rd(artifact), digest[7:],")
p.write_text(s)
PYX' \
  'verifier ACCEPTED'

# ---- corpus certification mutations ---------------------------------------------------
# Each removes the governing behaviour from the reference implementation AND REGENERATES
# the corpus, so every digest, sidecar and envelope in the mutated tree is self-consistent.
# The byte-compare therefore passes and the only thing left that can fail is the semantic
# assertion named in the evidence pattern. A mutation caught by a checksum proves that the
# checksum works; it says nothing about whether the requirement is certified.
inject "NORM-035 canonical serializer replaced by a naive one (Z-02)" \
  'bash scripts/vectors/check.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/vectors/generate.py"); s = p.read_text()
old = "    return _ser(v).encode(\"utf-8\") + b\"\\n\""
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    import json as _j\n"
    "    return _j.dumps(v, ensure_ascii=False, sort_keys=True, separators=(\",\", \":\"),"
    " allow_nan=False).encode(\"utf-8\") + b\"\\n\""))
PYX
rm -rf test-vectors/w1a/v1/*/expected && python3 scripts/vectors/generate.py' \
  'NORM-035 requires the escape'

inject "IDENT-003 all-zero identity guard removed (Z-06)" \
  'bash scripts/vectors/check.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/vectors/generate.py"); s = p.read_text()
old = "if t == \"0\" * 32 or t == \"uninitialized\":"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "if t == \"uninitialized\":"))
PYX
rm -rf test-vectors/w1a/v1/*/expected && python3 scripts/vectors/generate.py' \
  'independent parse says ERROR'

inject "IDENT-004 over-long read guard removed (Z-03)" \
  'bash scripts/vectors/check.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/vectors/generate.py"); s = p.read_text()
old = "if len(raw) > 4096:"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "if False:"))
PYX
rm -rf test-vectors/w1a/v1/*/expected && python3 scripts/vectors/generate.py' \
  'IDENT-004 selects'

inject "NORM-038 one domain made a prefix of another (Z-10)" \
  'bash scripts/vectors/check.sh' \
  'grep -rl "ISEDRAF:STATE:V1" docs/architecture/SNAPSHOT_BASELINE_DELTA_MODEL.md scripts/vectors/generate.py scripts/vectors/verify.py | xargs sed -i "s|ISEDRAF:STATE:V1|ISEDRAF:HOST-ID|g" && rm -rf test-vectors/w1a/v1/*/expected && python3 scripts/vectors/generate.py' \
  'NORM-038 VIOLATED'

inject "NORM-037 set-like field enters W1-A unordered (Z-11)" \
  'bash scripts/vectors/check.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/vectors/generate.py"); s = p.read_text()
old = "    core = {"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    core = {\"aa_unordered_set\": [2, 1],\n", 1))
PYX
rm -rf test-vectors/w1a/v1/*/expected && python3 scripts/vectors/generate.py' \
  'NORM-037 TRIGGER'

# ---- Z-08: SNAP-023, the three ways the host_id rule can be broken --------------------
inject "SNAP-023 host_id null on a COLLECTED snapshot (Z-08)" \
  'bash scripts/vectors/check.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/vectors/generate.py"); s = p.read_text()
old = "\"schema_version\": 1, \"host_id\": host_id,"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "\"schema_version\": 1, \"host_id\": None,"))
PYX
rm -rf test-vectors/w1a/v1/*/expected && python3 scripts/vectors/generate.py' \
  'COLLECTED with host_id null'

inject "SNAP-023 host_id string on a non-COLLECTED snapshot (Z-08)" \
  'bash scripts/vectors/check.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/vectors/generate.py"); s = p.read_text()
old = "host_id, state_hash = None, None"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "host_id, state_hash = \"sha256:\" + \"b\" * 64, None"))
PYX
rm -rf test-vectors/w1a/v1/*/expected && python3 scripts/vectors/generate.py' \
  'SHALL be null for every non-COLLECTED'

inject "SNAP-023 host_id key omitted from manifest_core (Z-08)" \
  'bash scripts/vectors/check.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/vectors/generate.py"); s = p.read_text()
old = "    core_c = canonical_bytes(core)"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    core.pop(\"host_id\")\n    core_c = canonical_bytes(core)"))
PYX
rm -rf test-vectors/w1a/v1/*/expected && python3 scripts/vectors/generate.py' \
  'manifest_core has no host_id key'

# ---- Z-13: NORM-036-first precedence restored -----------------------------------------
# The mutated parser preserves non-UTF-8 bytes instead of letting IDENT-003 reject them,
# so the malformed machine-id becomes COLLECTED identity state - the exact second
# "conforming" outcome the frozen text used to permit.
inject "NORM-042 generic byte preservation overrides IDENT-003 (Z-13)" \
  'bash scripts/vectors/check.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/vectors/generate.py"); s = p.read_text()
old = "    except UnicodeDecodeError:\n        return None, \"SYNTAX_REJECTED\"\n"
assert old in s, "mutation anchor miss"
new = ("    except UnicodeDecodeError:\n"
       "        import base64 as _b64\n"
       "        return \"__isedraf_encoding:base64:\" + _b64.b64encode(body).decode(\"ascii\"), None\n")
p.write_text(s.replace(old, new))
PYX
rm -rf test-vectors/w1a/v1/*/expected && python3 scripts/vectors/generate.py' \
  'NORM-042 VIOLATED|NORM-042 TRIGGER'

# Z-12. Proves the matrix DECLARATION is load-bearing: delete the 3.9 lane and the
# coverage gate must refuse, rather than the absence being noticed by nobody.
inject "NORM-039 Python 3.9 lane removed from the CI matrix (Z-12)" \
  'python3 scripts/ci/check_gate_coverage.py' \
  "sed -i \"s|\\['3.9', '3.12'\\]|['3.12']|\" .github/workflows/governance.yml" \
  'CI declares no Python 3.9 lane'

# Z-12. And that a lane which boots an interpreter but never runs the vectors is refused.
inject "NORM-039 matrix lane no longer runs the certification command (Z-12)" \
  'python3 scripts/ci/check_gate_coverage.py' \
  'sed -i "s|make check-vectors check-vectors-negative|make help|" .github/workflows/governance.yml' \
  'no CI job both declares a python-version matrix'

inject "D-93 missing Assisted-by trailer" \
  'bash git-hooks/commit-msg /tmp/sd_msg_a' \
  'printf "subject\n\nbody\n" > /tmp/sd_msg_a' \
  'commit-msg: add' \
  external

inject "D-93 AI Co-Authored-By trailer present" \
  'bash git-hooks/commit-msg /tmp/sd_msg_b' \
  'printf "subject\n\nAssisted-by: none\nCo-Authored-By: Claude <x@anthropic.com>\n" > /tmp/sd_msg_b' \
  'remove the AI' \
  external

# DOC-PUBLIC-UX-001. The gate is REPORT-ONLY until DOC-PUBLIC-01, so its discriminating
# power lives in the self-test, which is never report-only. A disabled rule, an enforce
# mode that no longer fails, and a reused rule list that silently disappears must each
# be caught.
inject "DOC-PUBLIC-UX-001 paragraph-length rule disabled" \
  'python3 scripts/docs/public_ux.py --self-test' \
  'sed -i "s/if w > lim\[/if False and w > lim[/" scripts/docs/public_ux.py' \
  'public documentation UX self-test FAILED'

inject "DOC-PUBLIC-UX-001 enforce mode no longer fails on a finding" \
  'python3 scripts/docs/public_ux.py --self-test' \
  'sed -i "s/return 1, out/return 0, out/" scripts/docs/public_ux.py' \
  'enforce mode must exit 1'

inject "DOC-PUBLIC-UX-001 a reused framing term list disappears" \
  'python3 scripts/docs/public_ux.py' \
  'sed -i "s/^FORBIDDEN = /FORBIDDEN_TERMS = /" scripts/docs/doclint.py' \
  'cannot load its rules'

rm -f /tmp/sd_msg_a /tmp/sd_msg_b
harness_summary
