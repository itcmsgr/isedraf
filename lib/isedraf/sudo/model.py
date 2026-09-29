# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The vocabulary of declared sudo policy, and the line it does not cross.
# Implements: SCOPE-022, SCOPE-045, IDENT-013
#
# THIS LANE COLLECTS DECLARED POLICY. IT DOES NOT ANSWER "CAN ALICE BECOME ROOT".
#
# That question needs alias resolution, group membership from a source this lane does not
# read, host matching, command matching including wildcards, and the precedence rule that
# the LAST matching specification wins. Every one of those is an interpretation, and
# several of them need evidence from other domains. A collector that answered it would be
# guessing with an authoritative voice - the same failure as calling queue_rotational a
# solid-state disk, with consequences an operator would act on.
#
# So nothing here is named privileged, admin, sudoer, effective or root_equivalent, and
# NOPASSWD is a tag on a command rather than a finding.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Record kinds, principal kinds and tags for declared sudo policy."""

from ..status import COLLECTED, ERROR, NOT_TESTED, PARTIAL    # noqa: F401
from ..shared.result import DERIVED, OBSERVATION, PROVENANCE, STATE

# --- record kinds -------------------------------------------------------------------------
DEFAULTS = "DEFAULTS"
ALIAS = "ALIAS"
SPEC = "SPEC"
UNSUPPORTED = "UNSUPPORTED"

# --- how a principal was written ----------------------------------------------------------
# The sigil is SYNTAX and is stripped; the kind records what it meant. Keeping "%wheel" as
# a single opaque string would force every later consumer to re-parse it, and one of them
# would eventually get it wrong.
USER = "USER"
GROUP = "GROUP"          # %group
GROUP_ID = "GROUP_ID"    # %#gid
USER_ID = "USER_ID"      # #uid
NETGROUP = "NETGROUP"    # +netgroup
NONUNIX_GROUP = "NONUNIX_GROUP"   # %:nonunix
ALL = "ALL"
ALIAS_REFERENCE = "ALIAS_REFERENCE"

# --- Defaults scope -----------------------------------------------------------------------
SCOPE_GLOBAL = "GLOBAL"
SCOPE_USER = "USER"        # Defaults:user
SCOPE_RUNAS = "RUNAS"      # Defaults>runas
SCOPE_HOST = "HOST"        # Defaults@host
SCOPE_COMMAND = "COMMAND"  # Defaults!command

SCOPE_SIGILS = {":": SCOPE_USER, ">": SCOPE_RUNAS, "@": SCOPE_HOST, "!": SCOPE_COMMAND}

# --- alias types ---------------------------------------------------------------------------
ALIAS_TYPES = {"User_Alias": "USER", "Runas_Alias": "RUNAS",
               "Host_Alias": "HOST", "Cmnd_Alias": "CMND"}

# --- command tags ---------------------------------------------------------------------------
# Order-sensitive in the source: a tag applies from where it appears onward, so attaching
# one to the wrong command misreports which command needs a password.
TAGS = ("NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV",
        "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT",
        "FOLLOW", "NOFOLLOW", "MAIL", "NOMAIL", "INTERCEPT", "NOINTERCEPT")

# --- what sudoers itself ignores inside an includedir ----------------------------------------
# sudo skips any filename containing '.' or ending in '~'. This is DOMAIN semantics, and it
# is stated here rather than left to the generic enumerator: S5 reports the directory
# entries it observed, and this rule decides which of them sudoers actually considers.
# Without it ISEDRAF would report policy from a .bak file that the host never applies.
def includedir_eligible(name):
    return "." not in name and not name.endswith("~")


# --- SCOPE-045 -------------------------------------------------------------------------------
CLASSIFICATION = {
    "kind": STATE,
    "scope_type": STATE, "scope": STATE, "options": STATE,
    "alias_type": STATE, "name": STATE, "members": STATE,
    "principals": STATE, "host": STATE, "runas_users": STATE,
    "runas_groups": STATE, "commands": STATE,
    "raw_digest": STATE,
    "source_path": PROVENANCE, "source_line": PROVENANCE, "ordinal": PROVENANCE,
    "reason": PROVENANCE, "continued": PROVENANCE,
}
del DERIVED, OBSERVATION

LIMITATION = (
    "Declared local sudo policy only. Alias references are recorded, not resolved; "
    "group membership is not consulted; host and command matching are not performed; "
    "and the last-match precedence rule is not applied. This is what the policy files "
    "say, not what sudo would decide.")

NOT_COLLECTED = ("sudo -l", "cvtsudoers", "LDAP/SSSD sudoers")
