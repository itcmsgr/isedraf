# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The PAM stack as declared, with the two distinctions that carry meaning.
# Implements: SCOPE-022, SCOPE-045
#
# Module presence is evidence. Nothing here concludes that login is secure, that lockout
# is configured, that password policy is effective, that MFA is enabled, or that
# authentication would succeed. Deciding any of those needs the stack evaluated against a
# real attempt, which is not something a configuration file can tell you.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Rule kinds, control vocabulary and edge semantics for the declared PAM stack."""

from ..status import COLLECTED, ERROR, NOT_TESTED, PARTIAL    # noqa: F401
from ..shared import result

RULE = "RULE"
EDGE = "EDGE"
UNSUPPORTED = "UNSUPPORTED"

TYPES = ("auth", "account", "password", "session")

# Simple controls, plus the two that reference another service.
SIMPLE_CONTROLS = ("required", "requisite", "sufficient", "optional")
INCLUDE = "include"
SUBSTACK = "substack"
BRACKETED = "BRACKETED"

# --- why include and substack are not one edge -------------------------------------------
# `include` splices the target's rules into the CURRENT stack, so a `done` or `die` taken
# inside the target ends the whole stack. `substack` evaluates the target as a
# self-contained sub-stack, so a jump inside it cannot escape past the substack boundary
# and the containing stack continues.
#
# The difference decides whether a failure deep inside a shared service aborts
# authentication or is contained. Recording both as "references another service" would
# throw that away, and no later criterion could recover it.
EDGE_SEMANTICS = {
    INCLUDE: "target rules are spliced into the current stack; a jump inside the target "
             "can terminate the containing stack",
    SUBSTACK: "target is evaluated as a self-contained sub-stack; a jump inside it "
              "cannot escape past the substack boundary",
}

# Named actions a bracketed control may take. Numeric values are jumps and stay numeric.
ACTIONS = ("ignore", "bad", "die", "ok", "done", "reset")

CLASSIFICATION = {
    "kind": result.STATE,
    "service": result.STATE, "type": result.STATE, "silent_if_missing": result.STATE,
    "control": result.STATE, "control_actions": result.STATE,
    "module": result.STATE, "arguments": result.STATE,
    "edge": result.STATE, "target_service": result.STATE,
    "raw_digest": result.STATE,
    "source_path": result.PROVENANCE, "source_line": result.PROVENANCE,
    "ordinal": result.PROVENANCE, "reason": result.PROVENANCE,
    "depth": result.PROVENANCE,
}

LIMITATION = (
    "Declared PAM configuration only. No stack outcome is computed: whether "
    "authentication would succeed depends on the modules' runtime behaviour, the "
    "account being authenticated and the order in which jumps resolve, none of which a "
    "configuration file states. Module presence is evidence that a module is configured, "
    "not that it is effective.")

NOT_COLLECTED = ("pam module runtime behaviour", "/etc/pam.conf legacy single-file form",
                 "authentication outcome")
