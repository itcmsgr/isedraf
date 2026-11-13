# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: `isedraf evaluate` - verify one committed snapshot, evaluate, commit one EVL.
# Implements: SNAP-011, SNAP-012, SNAP-013, STORE-020, D-121, D-125, EVAL-001,
#             EVAL-003, EVAL-004, EVAL-005, EVAL-006, BASE-008, CMP-030, DELTA-010
#
# D-127 (v0.4): when a baseline is in force, it is verified first (BASE-008; a failure is
# baseline.revision.IntegrityFailure, exit 5, nothing written) and changes.json then holds
# the comparison. With no baseline at all, changes.json is byte-for-byte what v0.3 wrote.
#
# The order is the snapshot's (CLAUDE.md section 4): private temporary directory ->
# write -> fsync -> atomic rename, under the whole-run lock the caller holds. There is no
# ledger append: an evaluation is derived and regenerable (STORE-020).
#
# Every input is verified before use and read exactly once: the ledger chain, the
# snapshot (verify.verify_snapshot), the binding of the snapshot's manifest hash to its
# ledger record, and the digest of every section file against the manifest that binds it.
# Any failure refuses (EvaluationRefused) and nothing is written (EVAL-003). Nothing here
# reads the host or starts a collector (EVAL-001).
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="<state root>/evaluations and <state root>/tmp"
# meta:binaries=""
# =============================================================================
"""EVAL-001..006: evaluate committed evidence and commit one evaluation."""
import json
import os
import shutil

from .. import canonical, catalog, ledger, snapshot, stateroot, verify
from ..baseline import revision as baseline_revision
from . import criteria, record

RESULTS = ("PASS", "FAIL", "NOT_APPLICABLE", "MANUAL_REVIEW", "NOT_EVALUATED")


class EvaluationRefused(Exception):
    """The evidence or the catalog cannot be trusted; nothing was written (exit 64)."""


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def _select(root, snapshot_id):
    """(snapshot_id, ledgered manifest_hash) of the requested or latest committed run."""
    problems = verify.verify_ledger(root)
    if problems:
        raise EvaluationRefused("the ledger does not verify: " + "; ".join(problems))
    records = ledger.snapshot_records(root)
    if not records:
        raise EvaluationRefused("there is no committed run to evaluate; run `isedraf audit`")
    if snapshot_id is None:
        chosen = records[-1]
    else:
        matches = [r for r in records if r.get("snapshot_id") == snapshot_id]
        if not matches:
            raise EvaluationRefused("%s is not a committed (ledgered) snapshot" % snapshot_id)
        chosen = matches[-1]
    return chosen["snapshot_id"], chosen.get("manifest_hash")


def _verified_snapshot(root, snapshot_id, ledgered_hash):
    """(manifest_core, manifest_hash, {artifact: bytes}) of one verified snapshot."""
    base = os.path.join(root, "snapshots", snapshot_id)
    if not os.path.isdir(base):
        raise EvaluationRefused("%s is in the ledger but its directory is missing" % snapshot_id)
    problems = verify.verify_snapshot(base)
    if problems:
        raise EvaluationRefused("the snapshot does not verify: " + "; ".join(problems))
    raw_manifest = _read(os.path.join(base, "manifest.json"))
    envelope = json.loads(raw_manifest.decode("utf-8"))
    if envelope.get("manifest_hash") != ledgered_hash:
        raise EvaluationRefused("%s: the manifest hash is not the one its ledger record binds"
                                % snapshot_id)
    core = envelope["manifest_core"]
    data = {"manifest.json": raw_manifest}
    for path, bound in sorted(core.get("auxiliary_artifacts", {}).items()):
        if not path.startswith("sections/"):
            continue
        raw = _read(os.path.join(base, path))
        if snapshot.auxiliary_digest(raw) != bound:          # read once, checked as read
            raise EvaluationRefused("%s: %s does not match its binding" % (snapshot_id, path))
        data[path] = raw
    return core, envelope["manifest_hash"], data


def verified_run(root, snapshot_id):
    """(core, manifest_hash, data) of one ledgered snapshot that verifies. EvaluationRefused."""
    sid, ledgered_hash = _select(root, snapshot_id)
    return _verified_snapshot(root, sid, ledgered_hash)


def _section_methods(core, data):
    """SNAP-013: collector and parser version per section, as the snapshot recorded them."""
    out = {}
    for path in sorted(p for p in data if p.startswith("sections/")):
        try:
            section = json.loads(data[path].decode("utf-8"))
            method = section["method"]
            out[path] = {"schema_version": section["schema_version"],
                         "collector_id": method["collector_id"],
                         "collector_version": method["collector_version"],
                         "parser_version": method["parser_version"],
                         "digest": core["auxiliary_artifacts"][path]}
        except (ValueError, KeyError, TypeError):
            raise EvaluationRefused("%s does not carry the section envelope this engine "
                                    "knows" % path)
    return out


def build(root, state_root_class, engine_version, snapshot_id=None,
          registry_path=catalog.REGISTRY):
    """Every artifact of one evaluation, as canonical bytes. Writes nothing."""
    snapshot_id, ledgered_hash = _select(root, snapshot_id)
    core, manifest_hash, data = _verified_snapshot(root, snapshot_id, ledgered_hash)
    if core.get("state_root") != state_root_class:
        raise EvaluationRefused("%s belongs to the %s class, not this %s store"
                                % (snapshot_id, core.get("state_root"), state_root_class))
    try:
        registry, raw_registry = catalog.load(registry_path)
    except catalog.CatalogError as exc:
        raise EvaluationRefused(str(exc))
    catalog_digest = catalog.digest(raw_registry)
    # BASE-008: the baseline in force, verified before anything is compared or written.
    in_force, info = baseline_revision.verify(
        root, state_root_class, lambda sid: verified_run(root, sid))
    # The same derivation the report and the system route use (record.baseline_key); the
    # revision just verified carries exactly these values (BASE-011).
    key_revision, key_profile = record.baseline_key(
        ledger.baseline_records(root)[-1] if in_force is not None else None)
    the_key = record.key(snapshot_id, manifest_hash, engine_version, catalog_digest,
                         key_revision, key_profile)
    evl_id = record.evaluation_id(core["created_at"], the_key)
    digests = dict((p, core["auxiliary_artifacts"][p]) for p in data if p != "manifest.json")
    digests["manifest.json"] = manifest_hash
    methods = _section_methods(core, data)

    results, findings = [], []
    for c in sorted(registry["criteria"], key=lambda x: x["criterion_id"]):
        entry = criteria.EVALUATORS.get(c["criterion_id"])
        if entry is None:
            raise EvaluationRefused("%s is admitted but this engine has no evaluator for it"
                                    % c["criterion_id"])
        evaluate_one, pointers, needs = entry
        if not criteria.pointers_match(c, pointers):
            raise EvaluationRefused("%s: the record's evidence_pointers are not the facts "
                                    "its evaluator reads" % c["criterion_id"])
        missing = [n for n in needs if n not in data]
        if missing:
            raise EvaluationRefused("%s is not an audit run: it has no %s"
                                    % (snapshot_id, ", ".join(missing)))
        try:
            section = json.loads(data[needs[0]].decode("utf-8"))
            result, code, reason, observed, evidence = evaluate_one(section, c, digests)
        except (ValueError, criteria.MalformedEvidence) as exc:
            raise EvaluationRefused("%s: malformed evidence: %s" % (c["criterion_id"], exc))
        results.append({
            "criterion_id": c["criterion_id"], "criterion_version": c["version"],
            "result": result, "reason_code": code, "reason": reason,
            "scope": (c["dimensions"].get(criteria.SCOPE_DIMENSION.get(c["criterion_id"], "declared"))
                      if isinstance(c["dimensions"], dict) else None),
            "limitations": c["limitations"], "observations": observed, "evidence": evidence,
            "lifecycle": "EXPERIMENTAL",
        })
        # D-121 section 5, exactly: FAIL -> a security finding at default_severity;
        # MANUAL_REVIEW -> a review finding without one; nothing else gives a finding.
        if result == "FAIL":
            findings.append({"finding_id": "%s/%s" % (evl_id, c["criterion_id"]),
                             "type": "SECURITY", "criterion_id": c["criterion_id"],
                             "criterion_version": c["version"],
                             "severity": c["default_severity"], "reason_code": code,
                             "reason": reason, "evidence": evidence})
        elif result == "MANUAL_REVIEW":
            findings.append({"finding_id": "%s/%s" % (evl_id, c["criterion_id"]),
                             "type": "REVIEW", "criterion_id": c["criterion_id"],
                             "criterion_version": c["version"], "severity": None,
                             "reason_code": code, "reason": reason, "evidence": evidence})

    common = {"schema_version": record.SCHEMA_VERSION, "evaluation_id": evl_id,
              "snapshot_id": snapshot_id, "state_root": state_root_class}
    artifacts = {
        "results.json": dict(common, results=results),
        "findings.json": dict(common, findings=findings),
        "changes.json": _changes(common, in_force, info, core, data),
    }
    raw = dict((n, canonical.canonical_bytes(o)) for n, o in artifacts.items())
    counts = dict((r, sum(1 for x in results if x["result"] == r)) for r in RESULTS)
    manifest = dict(common, **{
        "key": the_key,
        "snapshot": {"snapshot_id": snapshot_id, "manifest_hash": manifest_hash,
                     "created_at": core["created_at"], "state_root": core.get("state_root"),
                     "run_mode": core.get("run_mode"), "schema_version": core.get("schema_version")},
        "baseline_revision": key_revision, "profile": key_profile,
        "engine_version": engine_version,
        "catalog": {"path": "lib/isedraf/catalog/native_controls.json",
                    "catalog_version": registry.get("catalog_version"), "digest": catalog_digest,
                    "criteria": dict((c["criterion_id"], c["version"]) for c in registry["criteria"])},
        "sections": methods,
        "schema_versions": {"evaluation": record.SCHEMA_VERSION,
                            "snapshot_manifest": core.get("schema_version")},
        "result_counts": counts,
        "finding_counts": {"SECURITY": sum(1 for f in findings if f["type"] == "SECURITY"),
                           "REVIEW": sum(1 for f in findings if f["type"] == "REVIEW")},
        "artifacts": dict((n, record.digest(b)) for n, b in raw.items()),
    })
    raw["manifest.json"] = canonical.canonical_bytes(manifest)
    return evl_id, raw, results


def _changes(common, in_force, info, core, data):
    """EVAL-005 as amended by D-127. No baseline: exactly the v0.3 record. A change is
    never manufactured: rows come only from the comparison of two verified snapshots."""
    if in_force is None:
        out = dict(common, comparison_performed=False,
                   reason="NO_BASELINE: baseline and delta are v0.4 (D-120)",
                   baseline_revision=None, changes=[])
        if info and info.get("unledgered_revision"):
            # Interrupted before its ledger record: reported, never used (D-127).
            out["unledgered_revision"] = info["unledgered_revision"]
        return out
    return dict(common, **baseline_revision.compare(in_force, info["approved"], core, data))


def commit(root, evl_id, raw):
    """(path, created). Identical existing evaluation -> nothing written (EVAL-006)."""
    final = os.path.join(root, "evaluations", evl_id)
    if os.path.lexists(final):
        if not os.path.isdir(final) or os.path.islink(final):
            raise EvaluationRefused("%s exists and is not an evaluation directory" % final)
        on_disk = sorted(os.listdir(final))
        if on_disk != sorted(raw) or any(_read(os.path.join(final, n)) != b
                                         for n, b in raw.items()):
            raise EvaluationRefused("%s already exists with different content; it is never "
                                    "overwritten" % evl_id)
        return final, False
    previous = os.umask(0o077)
    staging = os.path.join(root, "tmp", evl_id)
    try:
        os.makedirs(os.path.join(root, "evaluations"), mode=0o700, exist_ok=True)
        os.makedirs(staging, mode=0o700)
        for name, data in sorted(raw.items()):
            stateroot.write_file(os.path.join(staging, name), data)
        stateroot.fsync_dir(staging)
        os.rename(staging, final)
        stateroot.fsync_dir(os.path.join(root, "evaluations"))
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        os.umask(previous)
    return final, True
