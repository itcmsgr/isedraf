# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The first native criterion end to end - audit, evaluate, EVL, report, explain.
# Implements: D-121, D-125, CMP-003, SNAP-011, SNAP-012, EVAL-001, EVAL-002, EVAL-003,
#             EVAL-004, EVAL-005, EVAL-006, EVAL-007, EVAL-009, ISE-ACCOUNT-001
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================
"""v0.3 first slice: ISE-ACCOUNT-001 from verified committed evidence."""
import copy
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import catalog, cli, exitcodes, explain             # noqa: E402
from isedraf.evaluate import criteria, record, run                # noqa: E402

ROOT_ONLY = "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n"
FILES = {
    "etc/machine-id": "3f9a1c0b7d2e4a68b5c6d7e8f9a0b1c2\n",
    "etc/passwd": ROOT_ONLY,
    "etc/group": "root:x:0:\nalice:x:1000:\n",
    "etc/shadow": "root:*:19000:0:99999:7:::\nalice:!:19000::::::\n",
    "etc/nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\n",
    "etc/hostname": "fixturehost\n",
    "proc/sys/kernel/hostname": "fixturehost\n",
}
ID = criteria.ACCOUNT_001


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_json(path):
    return json.loads(read_bytes(path).decode("utf-8"))


class Slice(unittest.TestCase):
    """One fixture host, one DEV store, the CLI as an operator runs it."""

    def setUp(self):
        self.host = tempfile.mkdtemp()
        self.state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.host)
        self.addCleanup(shutil.rmtree, self.state)
        self.store = os.path.join(self.state, "root")
        patcher = mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.store})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("SUDO_USER", None)

    def write_host(self, **overrides):
        files = dict(FILES)
        files.update(overrides)
        for rel, text in files.items():
            path = os.path.join(self.host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            try:
                code = cli.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def audit(self, **overrides):
        self.write_host(**overrides)
        code, _out, err = self.run_cli(["audit", "--root", self.host])
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)

    def evaluations(self):
        base = os.path.join(self.store, "evaluations")
        return sorted(os.listdir(base)) if os.path.isdir(base) else []

    def evaluate(self, expect=exitcodes.OK):
        code, out, err = self.run_cli(["evaluate"])
        self.assertEqual(code, expect, out + err)
        return out, err

    def artifacts(self):
        (name,) = self.evaluations()
        base = os.path.join(self.store, "evaluations", name)
        return dict((n, read_json(os.path.join(base, n))) for n in sorted(os.listdir(base)))

    def result(self, criterion_id=ID):
        (only,) = [r for r in self.artifacts()["results.json"]["results"]
                   if r["criterion_id"] == criterion_id]
        return only

    def findings(self, criterion_id=ID):
        return [f for f in self.artifacts()["findings.json"]["findings"]
                if f["criterion_id"] == criterion_id]

    def snapshot_dir(self):
        snaps = os.path.join(self.store, "snapshots")
        (name,) = os.listdir(snaps)
        return os.path.join(snaps, name)


class Results(Slice):
    """Owner's list 2026-11-01: PASS, FAIL, NOT_EVALUATED - and nothing guessed."""

    def test_pass_when_root_is_the_only_uid_0_entry(self):
        self.audit()
        self.evaluate()
        r = self.result()
        self.assertEqual((r["result"], r["reason_code"]), ("PASS", "ONLY_ROOT_HAS_UID_0"))
        self.assertEqual(self.findings(), [])                                  # no PASS finding

    def test_fail_with_an_additional_uid_0_entry_is_a_high_finding_and_exits_0(self):
        self.audit(**{"etc/passwd": ROOT_ONLY + "toor:x:0:0::/root:/bin/sh\n"})
        out, _err = self.evaluate(expect=exitcodes.OK)        # EVAL-007: FAIL is a result
        r = self.result()
        self.assertEqual((r["result"], r["reason_code"]), ("FAIL", "ADDITIONAL_UID_0_ENTRY"))
        self.assertEqual([o["name"] for o in r["observations"]], ["root", "toor"])
        (finding,) = self.findings()
        self.assertEqual((finding["type"], finding["severity"]), ("SECURITY", "high"))
        self.assertIn("FAIL", out)

    def test_fail_when_the_uid_0_entry_is_not_root(self):
        self.audit(**{"etc/passwd": "root:x:5:5::/root:/bin/sh\ntoor:x:0:0::/root:/bin/sh\n"})
        self.evaluate()
        self.assertEqual(self.result()["reason_code"], "UID_0_NOT_ROOT")

    def test_fail_when_no_entry_has_uid_0(self):
        self.audit(**{"etc/passwd": "root:x:5:5::/root:/bin/sh\n"})
        self.evaluate()
        self.assertEqual((self.result()["result"], self.result()["reason_code"]),
                         ("FAIL", "NO_UID_0_ENTRY"))

    def test_partial_passwd_never_passes_and_an_extra_uid_0_is_only_observed(self):
        # A malformed line makes the source PARTIAL (W1-D section 9). The extra UID-0
        # entry is visible, and still is not a FAIL: the account set is incomplete.
        self.audit(**{"etc/passwd": ROOT_ONLY + "toor:x:0:0::/root:/bin/sh\nbroken-line\n"})
        self.evaluate()
        r = self.result()
        self.assertEqual((r["result"], r["reason_code"]), ("NOT_EVALUATED", "SOURCE_PARTIAL"))
        self.assertIn("toor", [o["name"] for o in r["observations"]])
        self.assertEqual(self.findings(), [])

    def test_unreadable_passwd_is_not_evaluated(self):
        self.write_host()
        os.chmod(os.path.join(self.host, "etc/passwd"), 0)
        self.addCleanup(os.chmod, os.path.join(self.host, "etc/passwd"), 0o644)
        if os.access(os.path.join(self.host, "etc/passwd"), os.R_OK):
            self.skipTest("the file stays readable for this user")
        code, _out, err = self.run_cli(["audit", "--root", self.host])
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)
        self.evaluate()
        r = self.result()
        self.assertEqual(r["result"], "NOT_EVALUATED")
        self.assertIn(r["reason_code"], ("SOURCE_NOT_TESTED", "SOURCE_ERROR"))

    def test_a_compat_include_is_a_real_model_state_and_is_not_evaluated(self):
        # nsswitch `passwd: compat` makes "+" an INCLUDE of the NIS map (IQ-036): the
        # collector records it in remote_identity_inclusion, a defined evidence state.
        self.audit(**{"etc/passwd": ROOT_ONLY + "+\n",
                      "etc/nsswitch.conf": "passwd: compat\ngroup: files\nshadow: files\n"})
        snap = read_json(os.path.join(self.snapshot_dir(), "sections", "accounts.json"))
        self.assertIn("etc/passwd",
                      snap["evidence"]["remote_identity_inclusion"]["via_compat_directives_in"])
        self.assertEqual(snap["evidence"]["sources"]["etc/passwd"]["status"], "COLLECTED")
        self.evaluate()
        r = self.result()
        self.assertEqual((r["result"], r["reason_code"]), ("NOT_EVALUATED", "SOURCE_NOT_TESTED"))

    def test_every_result_states_its_scope_and_limits(self):
        self.audit()
        self.evaluate()
        r = self.result()
        self.assertIn("passwd", r["scope"])
        self.assertTrue(any("does not establish" in s for s in r["limitations"]))


class MalformedIsRefusedNotEvaluated(unittest.TestCase):
    """Owner clarification: a value the evidence model does not define is refused."""

    def setUp(self):
        registry, _raw = catalog.load()
        self.record = catalog.criterion(registry, ID)
        self.section = {"schema_version": 2, "section": "accounts", "collection_status": "COLLECTED",
                        "evidence": {"sources": {"etc/passwd": {"status": "COLLECTED"}},
                                     "remote_identity_inclusion": {"via_compat_directives_in": []},
                                     "local_accounts": [{"uid": 0, "name": "root",
                                                         "name_bytes_hex": "726f6f74",
                                                         "passwd_line": 1}]}}
        self.digests = {"manifest.json": "m", "sections/accounts.json": "s"}

    def evaluate(self, section):
        return criteria.ise_account_001(section, self.record, self.digests)

    def test_the_well_formed_object_passes(self):
        self.assertEqual(self.evaluate(self.section)[0], "PASS")

    def test_a_duplicate_root_entry_fails(self):
        s = copy.deepcopy(self.section)
        s["evidence"]["local_accounts"].append(dict(s["evidence"]["local_accounts"][0], passwd_line=2))
        self.assertEqual(self.evaluate(s)[:2], ("FAIL", "DUPLICATE_ROOT_ENTRY"))

    def test_undefined_values_are_refused(self):
        mutations = [
            lambda s: s["evidence"]["sources"]["etc/passwd"].update(status="INCLUDE"),
            lambda s: s["evidence"]["remote_identity_inclusion"].update(via_compat_directives_in="etc/passwd"),
            lambda s: s["evidence"]["local_accounts"][0].update(uid="0"),
            lambda s: s["evidence"]["local_accounts"][0].update(uid=None),     # COLLECTED + no uid
            lambda s: s["evidence"]["local_accounts"][0].update(name_bytes_hex="ROOT"),
            lambda s: s["evidence"].pop("remote_identity_inclusion"),
            lambda s: s.update(collection_status="MAYBE"),
            lambda s: s.update(evidence=None),                                 # COLLECTED, no evidence
            lambda s: s.update(schema_version=1),
        ]
        for i, mutate in enumerate(mutations):
            s = copy.deepcopy(self.section)
            mutate(s)
            with self.assertRaises(criteria.MalformedEvidence, msg="mutation %d" % i):
                self.evaluate(s)

    def test_a_section_that_says_it_has_no_evidence_is_not_evaluated(self):
        s = dict(self.section, collection_status="ERROR", evidence=None)
        self.assertEqual(self.evaluate(s)[:2], ("NOT_EVALUATED", "SECTION_ERROR"))


class FailClosed(Slice):
    """EVAL-003: evidence that does not verify gives exit 64 and writes nothing."""

    def tamper(self, rel):
        path = os.path.join(self.snapshot_dir(), rel)
        os.chmod(path, 0o600)
        with open(path, "ab") as fh:
            fh.write(b" ")

    def test_a_modified_section_is_refused(self):
        self.audit()
        self.tamper("sections/accounts.json")
        _out, err = self.evaluate(expect=exitcodes.USAGE_OR_ENGINE)
        self.assertIn("nothing was written", err)
        self.assertEqual(self.evaluations(), [])

    def test_a_section_changed_after_verification_is_refused_as_it_is_read(self):
        # The section is checked against its binding as it is read, not only by the
        # verifier before: a change between the two (or a verifier that missed it) is
        # still refused. The verifier is made to pass to isolate the second check.
        self.audit()
        self.tamper("sections/accounts.json")
        with mock.patch.object(run.verify, "verify_snapshot", return_value=[]):
            _out, err = self.evaluate(expect=exitcodes.USAGE_OR_ENGINE)
        self.assertIn("does not match its binding", err)
        self.assertEqual(self.evaluations(), [])

    def test_a_modified_manifest_is_refused(self):
        self.audit()
        self.tamper("manifest.json")
        self.evaluate(expect=exitcodes.USAGE_OR_ENGINE)
        self.assertEqual(self.evaluations(), [])

    def test_a_damaged_catalog_record_is_refused(self):
        self.audit()
        registry, _raw = catalog.load()
        damaged = copy.deepcopy(registry)
        damaged["criteria"][0]["default_severity"] = "info"
        path = os.path.join(self.state, "catalog.json")
        with open(path, "w") as fh:
            json.dump(damaged, fh)
        with mock.patch.object(catalog, "REGISTRY", path), \
                mock.patch.object(run.build, "__defaults__", (None, path)):
            self.evaluate(expect=exitcodes.USAGE_OR_ENGINE)
        self.assertEqual(self.evaluations(), [])

    def test_no_committed_run_is_a_usage_error(self):
        self.evaluate(expect=exitcodes.USAGE_OR_ENGINE)


class Determinism(Slice):
    """EVAL-006: same snapshot, engine and catalog -> the same bytes, never an overwrite."""

    def read_all(self):
        (name,) = self.evaluations()
        base = os.path.join(self.store, "evaluations", name)
        return name, dict((n, read_bytes(os.path.join(base, n))) for n in os.listdir(base))

    def test_a_second_evaluation_is_identical_and_writes_nothing(self):
        self.audit()
        self.evaluate()
        first = self.read_all()
        out, _err = self.evaluate()
        self.assertIn("already committed, identical", out)
        self.assertEqual(self.read_all(), first)

    def test_regeneration_is_byte_identical(self):
        self.audit()
        self.evaluate()
        name, first = self.read_all()
        shutil.rmtree(os.path.join(self.store, "evaluations", name))
        self.evaluate()
        self.assertEqual(self.read_all(), (name, first))

    def test_different_content_under_the_same_identity_is_never_overwritten(self):
        self.audit()
        self.evaluate()
        name, _first = self.read_all()
        path = os.path.join(self.store, "evaluations", name, "results.json")
        os.chmod(path, 0o600)
        with open(path, "ab") as fh:
            fh.write(b" ")
        self.evaluate(expect=exitcodes.USAGE_OR_ENGINE)

    def test_the_identity_is_derived_from_the_snapshot_key(self):
        self.audit()
        self.evaluate()
        manifest = self.artifacts()["manifest.json"]
        self.assertTrue(record.EVL_RE.match(manifest["evaluation_id"]))
        self.assertEqual(manifest["evaluation_id"],
                         record.evaluation_id(manifest["snapshot"]["created_at"], manifest["key"]))
        self.assertIsNone(manifest["baseline_revision"])


class RecordShape(Slice):
    """SNAP-012/013 as amended, D-121 section 5, STORE-020, SNAP-011."""

    def test_the_evaluation_holds_exactly_the_four_artifacts_marked_dev(self):
        self.audit()
        self.evaluate()
        arts = self.artifacts()
        self.assertEqual(sorted(arts), ["changes.json", "findings.json", "manifest.json",
                                        "results.json"])
        for name, obj in arts.items():
            self.assertEqual(obj["state_root"], "DEV", name)        # CLAUDE.md section 5
        self.assertEqual(arts["changes.json"]["changes"], [])
        self.assertFalse(arts["changes.json"]["comparison_performed"])
        m = arts["manifest.json"]
        for field in ("snapshot", "engine_version", "catalog", "sections", "schema_versions",
                      "baseline_revision", "profile", "artifacts", "result_counts"):
            self.assertIn(field, m)
        self.assertEqual(m["catalog"]["criteria"], {"ISE-ACCOUNT-001": 1, "ISE-ACCOUNT-002": 1,
                                                    "ISE-ACCOUNT-003": 1, "ISE-ACCOUNT-004": 1,
                                                    "ISE-SSH-001": 1, "ISE-ACCOUNT-005": 1,
                                                    "ISE-AUTH-001": 1, "ISE-SSH-002": 1})
        self.assertEqual(m["sections"]["sections/accounts.json"]["collector_id"],
                         "isedraf.accounts")

    def test_the_snapshot_and_ledger_are_untouched(self):
        self.audit()
        snap = self.snapshot_dir()
        before = sorted((p, read_bytes(os.path.join(dp, p)))
                        for dp, _d, fs in os.walk(snap) for p in fs)
        ledger = read_bytes(os.path.join(self.store, "ledger", "segment-000001.jsonl"))
        self.evaluate()
        after = sorted((p, read_bytes(os.path.join(dp, p)))
                       for dp, _d, fs in os.walk(snap) for p in fs)
        self.assertEqual(before, after)                       # SNAP-011
        self.assertEqual(read_bytes(os.path.join(self.store, "ledger", "segment-000001.jsonl")),
                         ledger)           # STORE-020: no ledger entry

    def test_permissions(self):
        self.audit()
        self.evaluate()
        (name,) = self.evaluations()
        base = os.path.join(self.store, "evaluations", name)
        self.assertEqual(os.stat(base).st_mode & 0o777, 0o700)
        for n in os.listdir(base):
            self.assertEqual(os.stat(os.path.join(base, n)).st_mode & 0o777, 0o600)


class Separation(Slice):
    """EVAL-001: audit collects, evaluate evaluates, explain explains, report renders."""

    def test_audit_does_not_evaluate(self):
        self.audit()
        self.assertEqual(self.evaluations(), [])

    def test_report_shows_an_evaluation_and_never_creates_one(self):
        self.audit()
        code, out, err = self.run_cli(["report", "--json"])
        self.assertIn(code, (exitcodes.OK, exitcodes.INCOMPLETE), err)
        self.assertEqual(json.loads(out)["native_results"]["status"], "NO_EVALUATION")
        self.assertEqual(self.evaluations(), [])
        self.evaluate()
        _code, out, _err = self.run_cli(["report", "--json"])
        native = json.loads(out)["native_results"]
        first = [r for r in native["results"] if r["criterion_id"] == ID][0]
        self.assertEqual((native["status"], first["result"]), ("EVALUATED", "PASS"))
        _code, md, _err = self.run_cli(["report"])
        self.assertIn("## Native criteria", md)
        self.assertIn("not a verdict on the host", md)

    def test_a_tampered_evaluation_is_not_shown_as_a_result(self):
        self.audit()
        self.evaluate()
        (name,) = self.evaluations()
        path = os.path.join(self.store, "evaluations", name, "results.json")
        os.chmod(path, 0o600)
        with open(path, "ab") as fh:
            fh.write(b" ")
        _code, out, _err = self.run_cli(["report", "--json"])
        self.assertEqual(json.loads(out)["native_results"]["status"], "DOES_NOT_VERIFY")

    def test_explain_needs_no_audit_and_no_store(self):
        code, out, _err = self.run_cli(["explain", ID])
        self.assertEqual(code, exitcodes.OK)
        self.assertIn("Limitations - what a result does not establish", out)
        self.assertIn("v0.4", out)
        self.assertFalse(os.path.exists(self.store))          # nothing created or read

    def test_explain_of_an_unknown_criterion_is_a_usage_error(self):
        self.assertEqual(self.run_cli(["explain", "ISE-ACCOUNT-999"])[0],
                         exitcodes.USAGE_OR_ENGINE)

    def test_root_is_refused_with_the_existing_code(self):
        with mock.patch.dict(os.environ, {"SUDO_USER": "someone"}):
            self.assertEqual(self.run_cli(["explain", ID])[0], exitcodes.PRIVILEGE_REFUSED)
            self.assertEqual(self.run_cli(["evaluate"])[0], exitcodes.PRIVILEGE_REFUSED)


class OneRecord(unittest.TestCase):
    """EVAL-002 / EVAL-009: one installed record, and the code reads what it declares."""

    def test_the_registry_is_installed_beside_the_code(self):
        self.assertEqual(os.path.relpath(catalog.REGISTRY, str(ROOT)),
                         os.path.join("lib", "isedraf", "catalog", "native_controls.json"))

    def test_every_admitted_criterion_has_an_evaluator_reading_its_pointers(self):
        registry, _raw = catalog.load()
        for c in registry["criteria"]:
            fn, pointers, _needs = criteria.EVALUATORS[c["criterion_id"]]
            self.assertTrue(criteria.pointers_match(c, pointers), c["criterion_id"])

    def test_explain_renders_every_required_field(self):
        registry, _raw = catalog.load()
        c = catalog.criterion(registry, ID)
        text = "\n".join(explain.lines(c))
        for value in (c["purpose"], c["rationale"], c["check_type"], c["default_severity"]):
            self.assertIn(value, text)
        for p in c["evidence_pointers"]:
            self.assertIn(p["pointer"], text)


if __name__ == "__main__":
    unittest.main()
