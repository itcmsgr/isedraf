# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# `make check` is THE authoritative local validation entry point (directive §13).
# CI invokes these same targets rather than re-implementing them in YAML, which is
# what prevents a gate silently degrading into a warning. There is no warning tier.

.PHONY: check check-reproducible check-sbom check-tests check-python-floor check-packaging check-privacy check-docs-truth check-current-state check-headers check-docs check-scope check-shell check-refs check-paths check-index check-freeze check-vectors check-vectors-negative check-vectors-crossversion check-gate-coverage check-falsifiable help

check: check-scope check-headers check-python-floor check-packaging check-privacy check-docs-truth check-current-state check-shell check-refs check-paths check-index check-freeze check-vectors check-vectors-negative check-vectors-crossversion check-tests check-docs
	@echo "make check: all gates passed"

## check-scope   D-96: no product implementation before architecture freeze
check-scope:
	@echo "--- bootstrap scope (D-96) ---"
	@bash scripts/ci/check_bootstrap_scope.sh

## check-headers L-01..L-11: SPDX, canonical holder, meta:owner, JSON licence keys
check-headers:
	@echo "--- header identity (D-62, D-90) ---"
	@bash scripts/ci/check_headers.sh

## check-shell   S-01: every tracked shell script parses
check-shell:
	@echo "--- shell syntax (D-12) ---"
	@set -e; for f in $$(git ls-files '*.sh' 'git-hooks/*'); do bash -n "$$f" || exit 1; done
	@echo "  OK    shell syntax clean"

## check-refs    D-105: every cited requirement/decision ID resolves; no amendment cited as authority
check-refs:
	@echo "--- requirement-reference integrity (D-105, D-106) ---"
	@python3 scripts/ci/check_requirement_refs.py

## check-gate-coverage  U-30: prove every gate is wired, CI-reachable and falsifiable
check-gate-coverage:
	@echo "--- gate coverage (GOV-001, GOV-002) ---"
	@python3 scripts/ci/check_gate_coverage.py

## check-falsifiable  GOV-002: every critical gate is proven able to fail
## The harness self-test runs FIRST (Z-20): injection results mean nothing until the
## harness is shown to distinguish a rejection from a crash.
check-falsifiable:
	@echo "--- falsifiability harness self-test (GOV-002, Z-20) ---"
	@bash scripts/ci/falsifiable_selftest.sh
	@echo "--- falsifiability harness (GOV-002) ---"
	@bash scripts/ci/falsifiable.sh

## check-paths   D-99/T-07: canonical on-disk paths consistent across every authority tier
check-paths:
	@echo "--- path consistency (D-99) ---"
	@bash scripts/ci/check_paths.sh

## check-vectors NORM-039: golden vectors reproduce byte-for-byte and verify independently
check-vectors:
	@echo "--- W1-A golden vectors (NORM-039) ---"
	@bash scripts/vectors/check.sh

## check-vectors-negative  Z-14: the verifier must REJECT corrupted artifacts
check-vectors-negative:
	@echo "--- vector verifier negative tests (Z-14) ---"
	@bash scripts/vectors/negative_test.sh

## check-vectors-crossversion  Z-12/NORM-039: byte determinism across supported Pythons
check-vectors-crossversion:
	@echo "--- cross-version byte determinism (NORM-039, Z-12) ---"
	@bash scripts/vectors/crossversion.sh

## check-freeze  D-68/W-28: per-set freeze manifests match the bytes on disk
check-freeze:
	@echo "--- freeze manifests (D-68) ---"
	@bash scripts/ci/check_freeze.sh

## check-index   D-89/Q-15: MASTER_INDEX counts are generated, never hand-maintained
check-index:
	@echo "--- master index freshness (Q-15) ---"
	@python3 scripts/docs/master_index.py check

## check-python-floor  D-12: production code holds to the runtime Python floor
check-python-floor:
	@echo "--- production Python floor (D-12) ---"
	@python3 scripts/ci/check_python_floor.py

## check-packaging  D-86/EXEC-016: packaging metadata, without needing every builder
check-packaging:
	@python3 scripts/ci/check_packaging.py

## check-privacy D-90: no real operator identifier reaches the publication surface
check-privacy:
	@echo "--- privacy / disclosure gate (D-90) ---"
	@python3 scripts/ci/check_privacy.py --scope release

## check-package-payload  D-86/D-90: what is INSIDE the built packages
check-package-payload:
	@echo "--- package payload (D-86, D-90) ---"
	@bash scripts/ci/check_package_payload.sh

## check-reproducible  D-86: build twice, require identical bytes
check-reproducible:
	@bash scripts/ci/check_reproducible.sh

## check-sbom  D-86/GOV-002: each SBOM describes the artifact it names
check-sbom:
	@python3 scripts/ci/check_sbom.py

## check-current-state  D-89: the status page is generated, never hand-maintained
check-current-state:
	@echo "--- current state freshness (D-89) ---"
	@python3 scripts/docs/current_state.py check

## check-docs-truth  C-01/C-06/D-88: documentation is an evidence surface
check-docs-truth:
	@echo "--- documentation truth (C-01, C-06, D-88) ---"
	@python3 scripts/ci/check_docs_truth.py

## check-tests   W1-B: production implementation tests, incl. golden-byte compatibility
check-tests:
	@echo "--- production tests (NORM-039 golden compatibility) ---"
	@out=$$(python3 tests/test_identity.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_inventory.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_report.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi

## check-docs    C-01..C-13: claims, framing, status labels, stubs, links, wiki
check-docs:
	@echo "--- documentation lint (D-87, D-88, D-89) ---"
	@python3 scripts/docs/doclint.py

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
