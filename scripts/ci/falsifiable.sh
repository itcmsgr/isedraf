#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
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
inject "D-90 the package payload installs to the wrong prefix" \
  'bash packaging/build.sh 2>&1; bash scripts/ci/check_package_payload.sh' \
  'sed -i "s|install -D -m 0644 \"\$f\" \"\$STAGE/usr/\$f\"|install -D -m 0644 \"\$f\" \"\$STAGE/usr/\${f#lib/}\"|" packaging/build.sh' \
  'layout wrong|/usr/isedraf|missing from payload'

inject "D-86 bytecode reaches the package payload" \
  'bash packaging/build.sh 2>&1; bash scripts/ci/check_package_payload.sh' \
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
  'bash packaging/build.sh 2>&1; bash scripts/ci/check_package_payload.sh' \
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
  'bash packaging/build.sh 2>&1; bash scripts/ci/check_deb_ordering.sh' \
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
  'bash scripts/ci/check_reproducible.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("packaging/build.sh"); s = p.read_text()
old = "INSTALLED_KB=$(find"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "echo \"X-Build-Stamp: $(date +%s%N)\" >> \"$DEBROOT/DEBIAN/control.stamp\"\n" + old, 1))
PYX' \
  'reproducible build gate FAILED|artifacts identical'

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
  'sed -i "s|badge/version-0.1.0--alpha1|badge/version-9.9.9|" README.md' \
  'version badge says|public claims gate FAILED'

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

# D-86. The deb and the rpm are built by two different implementations. Dropping a
# document from one of them must be caught by comparing them, not by anyone remembering.
inject "D-86 the rpm and the deb ship different documentation" \
  'bash packaging/build.sh 2>&1; bash scripts/ci/check_package_payload.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("packaging/rpm/isedraf.spec.in"); s = p.read_text()
old = "install -m 0644 docs/operator/STORAGE_AND_OUTPUTS.md"
assert old in s, "mutation anchor miss"
head, sep, tail = s.partition(old)
p.write_text(head + tail.split("\n", 1)[1].split("\n", 1)[1])
PYX' \
  'ship DIFFERENT documentation|package payload gate FAILED'

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
  'bash packaging/build.sh 2>&1; python3 scripts/ci/check_sbom.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/ci/generate_sbom.py"); s = p.read_text()
old = "            if not path.is_file():"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "            if not path.is_file() or path.name == \"cli.py\":", 1))
PYX' \
  'does not list it|SBOM accuracy gate FAILED'

inject "D-86 the SBOM binds to a digest that is not the artifact" \
  'bash packaging/build.sh 2>&1; python3 scripts/ci/check_sbom.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("scripts/ci/generate_sbom.py"); s = p.read_text()
old = "    artifact_digest = sha256_file(artifact)"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    artifact_digest = \"0\" * 64", 1))
PYX' \
  'states artifact sha256|SBOM accuracy gate FAILED'

inject "D-86 the SBOM presents the interpreter as bundled rather than external" \
  'bash packaging/build.sh 2>&1; python3 scripts/ci/check_sbom.py' \
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

# W1-C1: an optical drive reports rotational=0 exactly like an SSD. Classifying on that
# alone put a QEMU DVD-ROM in the first published sample as SOLID_STATE.
inject "optical device classified by the rotational flag alone" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/collectors.py"); s = p.read_text()
old = "            elif name.startswith((\"sr\", \"scd\")) or ("
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "            elif False and ("))
PYX' \
  'OPTICAL|DEVICE_OPTICAL'

# W1-C1: the report tells its reader that incomplete observations explain themselves.
inject "SCOPE-022 an incomplete collection carries no reason" \
  'python3 tests/test_inventory.py' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p = pathlib.Path("lib/isedraf/inventory/model.py"); s = p.read_text()
old = "    if status != COLLECTED and not reason:"
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
old = "    return model.subdomain(model.COLLECTED, data, method=\"/proc/cpuinfo\")"
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

# Z-18: deleting the corpus must fail the gate, not silently disable it.
inject "NORM-039 golden corpus deleted entirely (Z-18)" \
  'bash scripts/vectors/check.sh' \
  'rm -rf test-vectors/w1a/v1' \
  'golden corpus is release-blocking'

inject "NORM-039 golden vector mutated by one byte" \
  'bash scripts/vectors/check.sh' \
  'printf "x" >> test-vectors/w1a/v1/01-valid-machine-id/expected/host-id.txt' \
  'regenerated vectors differ'

inject "Z-14 verifier accepts a corrupted artifact" \
  'bash scripts/vectors/negative_test.sh' \
  'python3 - <<'"'"'PYX'"'"'
import pathlib
p=pathlib.Path("scripts/vectors/verify.py"); s=p.read_text()
old = "    if meth != METHOD_LITERAL:"
assert old in s, "mutation anchor miss"
p.write_text(s.replace(old, "    if False:"))
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

rm -f /tmp/sd_msg_a /tmp/sd_msg_b
harness_summary
