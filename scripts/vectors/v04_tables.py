#!/usr/bin/env python3
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Write the classification tables the v0.4 vectors are computed over.
# Implements: NORM-039, SCOPE-045, SCOPE-047
#
# The tables ARE specification data (SCOPE-045): which field is STATE is decided in the
# domain models, so this one step reads them from lib/. Everything else about the vectors -
# projection, canonical bytes, hashing - is computed by v04_reference.py without lib/.
# tests/test_baseline_vectors.py fails when production tables differ from this copy, so a
# reclassification cannot change the vectors' meaning silently (SCOPE-047).
#
# meta:type="generator"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="test-vectors/v04/v1/tables.json"
# meta:binaries=""
# =============================================================================
"""usage: v04_tables.py   (writes test-vectors/v04/v1/tables.json)"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from isedraf.accounts import model as accounts_model          # noqa: E402
from isedraf.loginpolicy import model as loginpolicy_model    # noqa: E402
from isedraf.ssh import model as ssh_model                    # noqa: E402


def tables():
    return {"accounts": dict(accounts_model.CLASSIFICATION),
            "loginpolicy": dict(loginpolicy_model.CLASSIFICATION),
            "ssh": dict(ssh_model.CLASSIFICATION)}


def main():
    out = ROOT / "test-vectors" / "v04" / "v1" / "tables.json"
    out.write_text(json.dumps(tables(), indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
