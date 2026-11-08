# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The one installed native control registry, read and checked.
# Implements: D-111, D-125, EVAL-002, EVAL-003
#
# EVAL-002: lib/isedraf/catalog/native_controls.json is the only record of a criterion.
# The evaluator, `isedraf explain`, the report and the generated pages read it through
# this module, and nothing else holds a copy. It is located beside this file, never
# through a path an operator supplies.
#
# EVAL-003: a record that fails the catalog contract stops the work that needed it. The
# checks here are the runtime half of check_native_catalog.py: the fields the contract
# requires, the namespace, the result and severity vocabularies. They are repeated so an
# installed engine refuses a damaged registry rather than evaluating with it.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""EVAL-002: the native control registry, as installed."""
import hashlib
import json
import os
import re

REGISTRY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native_controls.json")


class CatalogError(ValueError):
    """The registry cannot be read, or a record fails the catalog contract."""


def digest(data):
    """The digest an evaluation records for the registry bytes it used (EVAL-005)."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def load(path=REGISTRY):
    """(registry, raw bytes). Every admitted criterion is checked before it is returned."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        registry = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise CatalogError("the native control registry cannot be read: %s" % exc)
    if not isinstance(registry, dict) or not isinstance(registry.get("criteria"), list):
        raise CatalogError("the native control registry has no criteria list")
    check(registry)
    return registry, raw


def check(registry):
    """Raise CatalogError unless every criterion holds to the contract."""
    try:
        pattern = re.compile(registry["namespace_pattern"])
        required = set(registry["required_criterion_fields"])
        results = set(registry["result_states"])
        severities = set(registry["severity_levels"])
        families = set(registry["families"])
        check_types = registry["check_types"]
    except (KeyError, TypeError, re.error) as exc:
        raise CatalogError("the native control registry is incomplete: %s" % exc)
    seen = set()
    for c in registry["criteria"]:
        cid = c.get("criterion_id") if isinstance(c, dict) else None
        if not isinstance(cid, str) or not pattern.match(cid):
            raise CatalogError("criterion %r does not match the namespace" % (cid,))
        if cid in seen:
            raise CatalogError("%s is defined more than once" % cid)
        seen.add(cid)
        family = cid.rsplit("-", 1)[0]
        missing = sorted(required - set(c))
        if family not in families or missing:
            raise CatalogError("%s fails the catalog contract (family %s, missing %s)"
                               % (cid, family, ", ".join(missing) or "none"))
        if c["check_type"] not in check_types.get(family, []):
            raise CatalogError("%s names an undeclared check type" % cid)
        if c["default_severity"] not in severities:
            raise CatalogError("%s has an unknown default_severity" % cid)
        if not isinstance(c["version"], int) or isinstance(c["version"], bool) or c["version"] < 1:
            raise CatalogError("%s has no integer version" % cid)
        semantics = c["evaluation_semantics"]
        produced = [r.get("result") for r in semantics.get("rules", [])] if isinstance(
            semantics, dict) else []
        if not produced or not set(produced) <= results:
            raise CatalogError("%s names a result outside the frozen vocabulary" % cid)


def criterion(registry, criterion_id):
    """The record of one admitted criterion, or None."""
    for c in registry["criteria"]:
        if c["criterion_id"] == criterion_id:
            return c
    return None
