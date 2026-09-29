# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# `make check` is THE authoritative local validation entry point (directive §13).
# CI invokes these same targets rather than re-implementing them in YAML, which is
# what prevents a gate silently degrading into a warning. There is no warning tier.

.PHONY: check check-provider-alignment check-native-catalog check-licensing check-public-claims check-deb-ordering check-reproducible check-sbom check-tests check-python-floor check-architecture check-architecture-artifacts check-packaging check-storage-vocabulary check-native-catalog check-licensing check-public-claims check-privacy check-docs-truth check-current-state check-sample-report check-headers check-docs check-scope check-shell check-refs check-paths check-index check-freeze check-precommit check-imports check-vectors check-vectors-negative check-vectors-crossversion check-gate-coverage check-falsifiable check-public-ux help

check: check-scope check-headers check-python-floor check-architecture check-architecture-artifacts check-packaging check-storage-vocabulary check-native-catalog check-licensing check-public-claims check-privacy check-docs-truth check-current-state check-sample-report check-shell check-refs check-paths check-index check-freeze check-precommit check-imports check-vectors check-vectors-negative check-vectors-crossversion check-tests check-docs check-public-ux check-repo-security check-dco check-export
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
	@# IQ-018: `producer | grep -q` lets grep exit first; under pipefail the producer's
	@# SIGPIPE (141) fails the pipeline and the check is skipped. Measured on the bytecode
	@# gate: 0.1% idle, 6% under load. Capture first, then match a variable.
	@bad="$$(git ls-files '*.sh' 'git-hooks/*' | xargs grep -nE '^[^#]*[|][[:space:]]*grep[^|]*[[:space:]](-[A-Za-z]*q|--quiet)' || true)"; \
	if [ -n "$$bad" ]; then printf '%s\n' "$$bad" | sed 's/^/        /'; \
	  echo "  FAIL  early-exit reader in a pipeline: grep -q after | can skip a check under pipefail (IQ-018)"; exit 1; fi
	@echo "  OK    no early-exit reader in any shell pipeline (IQ-018)"

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

## check-precommit  IQ-029: the pre-commit hook validates the committed content, not the tree
check-precommit:
	@bash scripts/ci/check_precommit_index.sh

## check-imports  D-84: every runtime import is on the explicit allowlist; fail closed
check-imports:
	@python3 scripts/ci/check_runtime_imports.py

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

## check-sample-report  IQ-011: the published sample regenerates from committed evidence
check-sample-report:
	@python3 scripts/docs/sample_report.py check

## check-architecture  ARCH-01: the evidence pipeline has no reverse edges
check-architecture:
	@python3 scripts/ci/check_architecture.py --self-test
	@python3 scripts/ci/check_architecture.py

## check-architecture-artifacts  ARCH-01: the diagrams still describe the code
check-architecture-artifacts:
	@python3 scripts/ci/check_architecture_artifacts.py

## check-storage-vocabulary  D-114: a retired inference does not return as vocabulary
check-storage-vocabulary:
	@python3 scripts/ci/check_storage_vocabulary.py --self-test
	@python3 scripts/ci/check_storage_vocabulary.py

## check-native-catalog  D-111: the control catalog is ISEDRAF's own, and stays that way
check-native-catalog:
	@python3 scripts/ci/check_native_catalog.py

## check-provider-alignment  PRIVATE: the public tree vs the provider registry (not in CI)
check-provider-alignment:
	@python3 scripts/ci/check_provider_alignment.py

## check-licensing  D-84/D-90: MPL covers what we own; unknown licensing is not distributable
check-licensing:
	@python3 scripts/ci/check_licensing.py

## check-repo-security  OpenSSF Baseline L2: least-privilege workflows, Scorecard, policy documents
check-repo-security:
	@echo "--- repository security (OpenSSF Baseline, D-90) ---"
	@python3 scripts/ci/check_repo_security.py

## check-dco     D-91: the DCO checker tells signed from unsigned commits (self-test)
check-dco:
	@echo "--- DCO sign-off checker (D-91) ---"
	@python3 scripts/ci/check_dco.py --self-test

## check-export  D-110: the sanitized release export is publishable (gates pass on it);
## packages are built from it only by the release workflow, so --no-build here
check-export:
	@echo "--- release export (D-110) ---"
	@d="$$(mktemp -d)"; bash scripts/ci/release_export.sh --no-build "$$d/export"; rc=$$?; rm -rf "$$d"; exit $$rc

## check-dco-pr  CI, pull requests only: every added commit is signed off by its author.
## Reads DCO_BASE and DCO_HEAD from the environment; never part of `make check`.
check-dco-pr:
	@python3 scripts/ci/check_dco.py

## check-public-claims  C-01/D-88/D-90: a badge is a claim, and a claim must be backed
check-public-claims:
	@python3 scripts/ci/check_public_claims.py

## check-privacy D-90: no real operator identifier reaches the publication surface
check-privacy:
	@echo "--- privacy / disclosure gate (D-90) ---"
	@python3 scripts/ci/check_privacy.py --self-test
	@python3 scripts/ci/check_privacy.py --scope release

## check-package-payload  D-86/D-90: what is INSIDE the built packages
check-package-payload:
	@echo "--- package payload (D-86, D-90) ---"
	@bash scripts/ci/check_package_payload.sh

## check-deb-ordering  NORM-037/D-86: DEBIAN/sha256sums must not carry filesystem order
check-deb-ordering:
	@bash scripts/ci/check_deb_ordering.sh

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
	@out=$$(python3 tests/test_pam.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_pam_adversarial.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_ssh.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_ssh_adversarial.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_loginpolicy.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_loginpolicy_adversarial.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_sudo.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_sudo_adversarial.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_shared_compare.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_shared_bounded.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_shared_filemeta.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_shared_keyvalue.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_shared_include_graph.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_hostpath.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_authorizedkeys.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_authorizedkeys_adversarial.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_coverage.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_auxiliary_binding.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_accounts.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_hostio.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_glibc_differential.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_nss.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_hostname.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_report_html.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_stateroot.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_audit.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_cli.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_launcher.py 2>&1); rc=$$?; \
	 if [ $$rc -eq 0 ]; then echo "$$out" | tail -3; \
	 else echo "$$out"; exit $$rc; fi
	@out=$$(python3 tests/test_prepush.py 2>&1); rc=$$?; \
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

## check-public-ux  DOC-PUBLIC-UX-001: public documentation is written for a human reader
## REPORT-ONLY until milestone DOC-PUBLIC-01 (scripts/ci/public_layer.json "enforce").
## The self-test is never report-only: every rule must be shown to fire.
check-public-ux:
	@echo "--- public documentation UX (DOC-PUBLIC-UX-001, D-87, D-88) ---"
	@python3 scripts/docs/public_ux.py --self-test
	@python3 scripts/docs/public_ux.py

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
