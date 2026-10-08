#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Hold the frozen Evidence Limits Manifest schema to its fixtures and to the code.
# Implements: D-122, D-115, D-121
#
# Two things can drift, and this gate refuses both:
#   1. the schema's vocabulary block and lib/isedraf/coverage.py / status.py - two lists
#      that can disagree are how a second representation appears;
#   2. the rules and the fixtures - every valid fixture passes every ELIM rule, and every
#      invalid fixture fails the rule its name carries, so a rule cannot quietly stop firing.
#
# Development tooling only: standard library plus the engine's own pure modules.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================

"""Evidence Limits Manifest schema 2: vocabulary agreement and fixture conformance."""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                                            universal_newlines=True).strip())
sys.path.insert(0, str(ROOT / "lib"))

from isedraf import canonical, coverage, status   # noqa: E402

SPEC = ROOT / "docs" / "architecture" / "EVIDENCE_LIMITS_SCHEMA.md"
FIXTURES = ROOT / "tests" / "fixtures" / "evidence_limits" / "v2"
TOKEN = re.compile(r"^[A-Z][A-Z0-9_]*$")
REASON = re.compile(r"^[A-Z][A-Z0-9_]*: .+")

SOURCE_KEYS = {"domain", "source", "collector", "acquisition_mode", "operation_id",
               "operation", "status", "access_outcome", "reason", "source_universe",
               "universe_reasons", "note", "privilege_limited", "required_access",
               "affects_completeness", "absence_claim_allowed"}
COLLECTOR_KEYS = {"collector_id", "collector_version", "parser_version"}
MANIFEST_KEYS = {"schema_version", "requested_sections", "unreported_sections",
                 "acquisition_modes", "requested_sources", "complete_sources",
                 "partial_sources", "privilege_limited_sources",
                 "other_unavailable_sources", "required_access", "sources", "limitations",
                 "coverage_digest"}


def vocabulary():
    text = SPEC.read_text(encoding="utf-8")
    match = re.search(r"```json evidence-limits-vocabulary\n(.*?)\n```", text, re.S)
    if not match:
        sys.exit("FAIL  %s carries no evidence-limits-vocabulary block" % SPEC)
    return json.loads(match.group(1))


def agreement(vocab):
    """The schema's vocabularies ARE the code's: compared, never maintained twice."""
    code = {
        "status": list(status.STATUSES),
        "operation": list(coverage.OPERATIONS),
        "access_outcome": list(coverage.OUTCOMES),
        "required_access": list(coverage.ACCESS_REQUIREMENTS),
        "acquisition_mode": list(coverage.MODES),
        "source_universe": [coverage.UNIVERSE_COMPLETE, coverage.UNIVERSE_INCOMPLETE,
                            coverage.UNIVERSE_NOT_APPLICABLE],
    }
    problems = []
    for key, values in sorted(code.items()):
        if vocab.get(key) != values:
            problems.append("vocabulary %r: schema %s, code %s" % (key, vocab.get(key), values))
    if vocab.get("schema_version") != 2:
        problems.append("vocabulary block is not schema 2")
    return problems


def _strings(value, path=""):
    if isinstance(value, dict):
        for k, v in value.items():
            for item in _strings(v, path + "/" + k):
                yield item
    elif isinstance(value, list):
        for i, v in enumerate(value):
            for item in _strings(v, "%s[%d]" % (path, i)):
                yield item
    elif isinstance(value, str):
        yield path, value


def digest(manifest):
    frame = {"schema_version": manifest["schema_version"],
             "requested_sections": manifest["requested_sections"],
             "unreported_sections": manifest["unreported_sections"],
             "sources": [{k: s[k] for k in ("domain", "source", "operation",
                                            "acquisition_mode", "status", "access_outcome",
                                            "source_universe", "universe_reasons")}
                         for s in manifest["sources"]]}
    return canonical.rendered(canonical.hash_frame(
        "ISEDRAF:EVIDENCE-COVERAGE:V2", canonical.canonical_bytes(frame)))


def validate(raw, vocab):
    """Return [(rule, message)]; empty means the manifest conforms to schema 2."""
    errors = []

    def bad(rule, message):
        errors.append((rule, message))

    try:
        m = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return [("ELIM-013", "not JSON: %s" % exc)]
    if raw != canonical.canonical_bytes(m):
        bad("ELIM-013", "bytes are not the canonical serialization")
    if not isinstance(m, dict) or set(m) != MANIFEST_KEYS:
        return errors + [("ELIM-011", "manifest keys %s" % sorted(m) if isinstance(m, dict)
                          else "manifest is not an object")]
    for path, value in _strings(m):
        if value in vocab["forbidden_values"] and not path.endswith("/source_universe"):
            bad("ELIM-002", "evaluation or severity value %r at %s" % (value, path))
    if m["schema_version"] != 2:
        bad("ELIM-011", "schema_version %r" % m["schema_version"])

    sources = m["sources"]
    seen = set()
    for i, s in enumerate(sources):
        where = "sources[%d]" % i
        if not isinstance(s, dict) or set(s) != SOURCE_KEYS:
            bad("ELIM-005", "%s keys %s" % (where, sorted(s) if isinstance(s, dict) else s))
            continue
        for key in ("domain", "source"):
            if not isinstance(s[key], str) or not s[key]:
                bad("ELIM-005", "%s %s is not a non-empty string" % (where, key))
        c = s["collector"]
        if (not isinstance(c, dict) or set(c) != COLLECTOR_KEYS
                or not all(isinstance(v, str) and v for v in c.values())):
            bad("ELIM-006", "%s collector is not structured method identity" % where)
        for key, vocab_key in (("acquisition_mode", "acquisition_mode"),
                               ("operation", "operation"), ("status", "status"),
                               ("access_outcome", "access_outcome"),
                               ("source_universe", "source_universe"),
                               ("required_access", "required_access")):
            if s[key] not in vocab[vocab_key]:
                rule = "ELIM-008" if key == "acquisition_mode" else "ELIM-005"
                bad(rule, "%s %s %r is not in the schema vocabulary" % (where, key, s[key]))
        if s["operation_id"] is not None:
            bad("ELIM-008", "%s operation_id must be null in schema 2" % where)
        reasons = s["universe_reasons"]
        if (not isinstance(reasons, list) or reasons != sorted(set(reasons))
                or not all(isinstance(r, str) and TOKEN.match(r) for r in reasons)):
            bad("ELIM-007", "%s universe_reasons is not a sorted unique token list" % where)
        elif (s["source_universe"] == coverage.UNIVERSE_INCOMPLETE) != bool(reasons):
            bad("ELIM-007", "%s source_universe %s with universe_reasons %s"
                % (where, s["source_universe"], reasons))
        if s["status"] == status.COLLECTED:
            if s["reason"] is not None:
                bad("ELIM-009", "%s COLLECTED carries a reason" % where)
        elif not (isinstance(s["reason"], str) and REASON.match(s["reason"])):
            bad("ELIM-009", "%s reason %r does not follow CODE: text" % (where, s["reason"]))
        if s["note"] is not None and not isinstance(s["note"], str):
            bad("ELIM-005", "%s note is neither null nor a string" % where)
        if s["operation"] in coverage.OPERATIONS and s["access_outcome"] in coverage.OUTCOMES:
            expected = {
                "privilege_limited": coverage.privilege_limited(s["access_outcome"]),
                "required_access": coverage.required_access(s["operation"],
                                                            s["access_outcome"]),
                "affects_completeness": (s["status"] != status.COLLECTED
                                         or s["source_universe"]
                                         == coverage.UNIVERSE_INCOMPLETE),
                "absence_claim_allowed": coverage.absence_claim_allowed(s["source_universe"]),
            }
            for key, value in sorted(expected.items()):
                if s[key] != value:
                    bad("ELIM-010", "%s %s is %r, derivation gives %r"
                        % (where, key, s[key], value))
        pair = (s["domain"], s["source"])
        if pair in seen:
            bad("ELIM-011", "%s duplicates %s" % (where, pair))
        seen.add(pair)

    valid = [s for s in sources if isinstance(s, dict) and set(s) == SOURCE_KEYS]
    if [(s["domain"], s["source"]) for s in valid] != sorted((s["domain"], s["source"])
                                                             for s in valid):
        bad("ELIM-011", "sources are not sorted by (domain, source)")

    requested = m["requested_sections"]
    if requested != sorted(set(requested)):
        bad("ELIM-011", "requested_sections is not a sorted unique list")
    unreported = m["unreported_sections"]
    names = []
    for item in unreported:
        if not isinstance(item, dict) or set(item) != {"section", "reason"}:
            bad("ELIM-011", "unreported_sections item %r" % (item,))
            continue
        names.append(item["section"])
        if not (isinstance(item["reason"], str) and REASON.match(item["reason"])):
            bad("ELIM-011", "unreported section %s has no CODE: text reason" % item["section"])
    if names != sorted(set(names)):
        bad("ELIM-011", "unreported_sections is not sorted and unique by section")
    reported = set(s["domain"] for s in valid)
    for name in requested:
        if (name in reported) == (name in names):
            bad("ELIM-003", "requested section %s is %s" % (
                name, "both reported and unreported" if name in reported
                else "neither reported nor recorded as unreported"))
    for name in sorted(reported - set(requested)):
        bad("ELIM-011", "source domain %s is not a requested section" % name)
    for name in sorted(set(names) - set(requested)):
        bad("ELIM-011", "unreported section %s was not requested" % name)

    affects = [s for s in valid if s["affects_completeness"]]
    derived = {
        "acquisition_modes": sorted(set(s["acquisition_mode"] for s in valid)),
        "requested_sources": len(sources),
        "complete_sources": len([s for s in valid if not s["affects_completeness"]]),
        "partial_sources": len([s for s in valid if s["status"] == status.PARTIAL]),
        "privilege_limited_sources": len([s for s in valid if s["privilege_limited"]]),
        "other_unavailable_sources": len([s for s in affects if not s["privilege_limited"]
                                          and s["status"] != status.PARTIAL]),
        "required_access": sorted(set(s["required_access"] for s in valid
                                      if s["required_access"] != coverage.ACCESS_NONE)),
        "limitations": affects,
    }
    for key, value in sorted(derived.items()):
        if m[key] != value:
            bad("ELIM-012", "%s does not equal its derivation" % key)
    if not errors and m["coverage_digest"] != digest(m):
        bad("ELIM-014", "coverage_digest does not match the ELIM-014 frame")
    return errors


def main():
    vocab = vocabulary()
    problems = agreement(vocab)
    for p in problems:
        print("  FAIL  %s" % p)
    valid = sorted((FIXTURES / "valid").glob("*.json"))
    invalid = sorted((FIXTURES / "invalid").glob("*.json"))
    if not valid or not invalid:
        problems.append("fixtures missing")
        print("  FAIL  valid and invalid fixtures are both required under %s" % FIXTURES)
    for path in valid:
        errors = validate(path.read_bytes(), vocab)
        for rule, message in errors:
            problems.append(path.name)
            print("  FAIL  %s should conform: %s %s" % (path.name, rule, message))
    for path in invalid:
        rule = path.name[:8]
        errors = validate(path.read_bytes(), vocab)
        if rule not in [r for r, _ in errors]:
            problems.append(path.name)
            print("  FAIL  %s should violate %s; got %s" % (path.name, rule,
                                                           [r for r, _ in errors] or "none"))
    if problems:
        print("=== evidence limits schema gate FAILED ===")
        return 1
    print("  OK    evidence limits schema 2: vocabularies agree with coverage.py and status.py; "
          "%d valid fixtures conform, %d invalid fixtures each fail their named rule"
          % (len(valid), len(invalid)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
