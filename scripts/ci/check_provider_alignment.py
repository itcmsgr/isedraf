# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The public tree must not claim what the private registry has not authorized.
# Implements: D-84, D-90, GOV-001
#
# PRIVATE-ONLY, BY DESIGN. It reads the provider licensing registry, which lives outside
# this repository and does not exist on a CI runner. It is therefore never required by
# public CI, and it SKIPS cleanly when the registry is absent rather than failing on it.
#
# What it exists to catch is a drift nobody notices: the registry says a provider is
# CONTACT_REQUIRED while a README sentence written months earlier says the provider is
# supported. Neither file is wrong on its own; together they are a false public claim.
#
# It never quotes the registry. A failure reports the provider name, the public file and
# line, and the authorization state - and nothing else, because the registry holds
# commercial research and correspondence that must not reach a log.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,python3"
# =============================================================================

"""usage: check_provider_alignment.py"""
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True).strip())
POLICY = json.loads((ROOT / "scripts" / "ci" / "public_licensing_policy.json").read_text())
# Located by environment, never by a path published in this repository. The first
# version of the policy file recorded an absolute path under the owner's home directory
# and the privacy gate refused it, correctly: a public file does not get to describe a
# private filesystem.
_registry = os.environ.get("ISEDRAF_PROVIDER_REGISTRY", "")
REGISTRY = pathlib.Path(_registry) if _registry else None

print("--- provider alignment (PRIVATE, D-84) ---")

if REGISTRY is None or not REGISTRY.is_dir():
    print("  SKIP  ISEDRAF_PROVIDER_REGISTRY is unset or does not exist here.")
    print("        This check runs on the engineering workstation only and is NOT part of")
    print("        public CI. Not a pass: nothing was compared.")
    sys.exit(0)

try:
    import yaml
except ImportError:
    print("  SKIP  PyYAML is unavailable; the registry cannot be read here. Not a pass.")
    sys.exit(0)

AUTHORIZED = {"BUNDLED_OPEN", "OPEN_REFERENCE", "APPROVED_AS_OPEN_REFERENCE"}
states = {}
for status in sorted((REGISTRY / "providers").glob("*/STATUS.yaml")):
    try:
        d = yaml.safe_load(status.read_text())
    except Exception:
        continue
    states[status.parent.name] = str(d.get("decision", {}).get("status", "UNKNOWN"))

if not states:
    print("  SKIP  the registry contains no provider records. Not a pass.")
    sys.exit(0)

CLAIM = re.compile(POLICY["claim_context"]["positive"], re.I)
NEG = re.compile(POLICY["claim_context"]["negation"], re.I)
RESTRICTED = [(v, k) for k, v in POLICY["restricted_providers"].items()
              if not k.startswith("$")]
ALLOWED_CTX = set(POLICY["allowed_context_paths"]["paths"])

files = [p for p in subprocess.check_output(
    ["git", "ls-files"], cwd=str(ROOT), text=True).split()
    if p not in ALLOWED_CTX and p.endswith((".md", ".json", ".py", ".sh", ".in", ".yml"))]

fail = 0
for rel in files:
    try:
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    for n, line in enumerate(text.splitlines(), 1):
        if not CLAIM.search(line) or NEG.search(line):
            continue
        for pattern, label in RESTRICTED:
            if re.search(pattern, line):
                # Report the authorization state only. Never the registry's contents.
                state = "NOT_IN_REGISTRY"
                for key, st in states.items():
                    if key.split("_")[0].lower() in label.lower().replace("/", ""):
                        state = st
                        break
                if state not in AUTHORIZED:
                    print("  FAIL  %s:%d claims %s · registry authorization: %s"
                          % (rel, n, label, state))
                    fail += 1
                break

if fail:
    print("=== provider alignment FAILED ===")
    print("  The public tree claims a provider the registry has not authorized.")
    sys.exit(1)
print("  OK    %d provider records vs %d public files: no unauthorized claim"
      % (len(states), len(files)))
