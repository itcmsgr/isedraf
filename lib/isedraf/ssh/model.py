# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Declared sshd configuration, with scope kept structural.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045
#
# DECLARED ONLY. Not sshd -T. Resolved and active state are a separate acquisition
# source that will later meet S3, and presenting a declared value as a running one is the
# kind of confident error an operator acts on.
#
# The structural rule this model exists to enforce:
#
#     PasswordAuthentication no
#
#     Match User backup
#         PasswordAuthentication yes
#
# Those are two different facts. Flattened into two values of one keyword they become
# "PasswordAuthentication is both yes and no", which is not a statement about any host.
# Every declaration therefore carries its enclosing scope.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Record kinds, scope and state dimension for declared sshd configuration."""

from ..status import COLLECTED, ERROR, NOT_TESTED, PARTIAL    # noqa: F401
from ..inventory.model import ACTIVE, DECLARED, RESOLVED      # noqa: F401
from ..shared import result

DIRECTIVE = "DIRECTIVE"
MATCH = "MATCH"
UNSUPPORTED = "UNSUPPORTED"
# AUTH-031: one line of `sshd -T`, the global effective configuration (Full Audit only).
RESOLVED_SETTING = "RESOLVED_SETTING"

GLOBAL = "GLOBAL"
MATCH_SCOPE = "MATCH"

# Match criteria keywords, lower-cased. `all` and `canonical` take no argument.
CRITERIA = ("user", "group", "host", "localaddress", "localport", "rdomain",
            "address", "all", "canonical", "final")
CRITERIA_WITHOUT_VALUE = ("all", "canonical", "final")

# sshd takes the FIRST value for most keywords. Recorded, never applied here - the
# opposite convention to the last-wins families in login-policy, which is exactly why a
# shared parser must not decide it.
DUPLICATE_POLICY = "FIRST_WINS"

# Only `*.conf` is read from a drop-in directory by convention; the glob in the Include
# directive is what actually selects, so the domain does not add a second filter.

CLASSIFICATION = {
    "kind": result.STATE,
    "keyword": result.STATE, "keyword_raw": result.STATE, "value": result.STATE,
    "scope": result.STATE, "match_index": result.STATE,
    "match_criteria": result.STATE, "criteria": result.STATE,
    "raw_digest": result.STATE,
    # AUTH-031, IQ-064: the position of a setting among the lines with the same keyword.
    # The order of a repeated directive is meaning (overlapping listen addresses bind
    # first-come), so it is state; the position in the whole output is not.
    "occurrence": result.STATE,
    "source_path": result.PROVENANCE, "source_line": result.PROVENANCE,
    "ordinal": result.PROVENANCE, "reason": result.PROVENANCE,
}

LIMITATION = (
    "Declared sshd configuration only, from sshd_config and the files it includes. "
    "sshd -T is not run, so no resolved or active value is claimed; a directive that "
    "sshd would reject, override or ignore is still recorded here as declared. "
    "Duplicate handling is recorded, not applied.")

NOT_COLLECTED = ("sshd -T", "sshd -T -C", "running sshd process state",
                 "authorized_keys")

# Full Audit (AUTH-031): sshd -T runs once, fixed, through the supervisor. What it gives is
# the GLOBAL effective configuration: Match blocks are applied only with a connection
# context (-C), which this operation never has.
RESOLVED_SCOPE = "GLOBAL_EFFECTIVE_SSHD_CONFIGURATION"
SUPERVISED_SCOPE = "DECLARED_SSHD_CONFIGURATION + %s" % RESOLVED_SCOPE
SUPERVISED_DIMENSION = "%s + %s" % (DECLARED, RESOLVED)
SUPERVISED_LIMITATION = (
    "Declared sshd configuration from sshd_config and the files it includes, and the global "
    "effective configuration from sshd -T. The global effective configuration is what sshd "
    "computes when no connection is known: it does not resolve Match blocks, so it is not "
    "the effective configuration of any particular connection, and Match-dependent values "
    "are NOT_TESTED. The Match blocks themselves are recorded as declared context. sshd -T "
    "re-reads the configuration on disk; what a running sshd loaded is not observed.")
SUPERVISED_NOT_COLLECTED = ("sshd -T -C", "running sshd process state", "authorized_keys")
CONNECTION_CONTEXT_REASON = (
    "NO_CONNECTION_CONTEXT: sshd -T ran without -C, so Match blocks were not applied; "
    "Match-dependent values are not resolved and no absence of Match restrictions is "
    "claimed (SCOPE-020, AUTH-031).")
