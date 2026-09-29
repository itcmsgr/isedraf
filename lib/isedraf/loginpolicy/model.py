# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Four login-policy source families, four grammars, and the line between them.
# Implements: SCOPE-022, SCOPE-045
#
# These files are routinely described as "the Linux password policy". They are not one
# thing. login.defs is whitespace-delimited, pwquality and faillock use `=`, and
# limits.conf is four positional fields with no key at all. A single profile applied
# across them produces confident nonsense with a grammar digest attached: parse
# `minlen = 12` with a whitespace profile and the value becomes "= 12".
#
# So the domain selects the profile per family. S1 can record WHICH grammar parsed a
# declaration - that is what its identity digest is for - but only the domain knows which
# one is right.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Family vocabulary and the S1 profiles that parse each one."""

from ..status import COLLECTED, ERROR, NOT_TESTED, PARTIAL    # noqa: F401
from ..shared import keyvalue, result

LOGIN_DEFS = "LOGIN_DEFS"
PWQUALITY = "PWQUALITY"
FAILLOCK = "FAILLOCK"
LIMITS = "LIMITS"

FAMILIES = (LOGIN_DEFS, PWQUALITY, FAILLOCK, LIMITS)


class LoginDefs(keyvalue.Profile):
    """`KEY value`, whitespace-delimited, case-sensitive keys.

    Not `=`. A pwquality profile applied here would take `UMASK 022` and find no
    delimiter at all, reporting every line as malformed.
    """

    name = "login.defs"
    whitespace_delimited = True
    comment_markers = ("#",)
    inline_comments = False
    case_insensitive_keys = False
    duplicate_policy = keyvalue.LAST_WINS
    empty_value_policy = keyvalue.EMPTY_IS_VALUE


class PwQuality(keyvalue.Profile):
    """`key = value`. libpwquality reads the last assignment."""

    name = "pwquality.conf"
    delimiters = ("=",)
    comment_markers = ("#",)
    inline_comments = False
    case_insensitive_keys = False
    duplicate_policy = keyvalue.LAST_WINS
    empty_value_policy = keyvalue.EMPTY_IS_VALUE


class Faillock(keyvalue.Profile):
    """`key = value`, and bare keys that act as booleans.

    A bare `silent` has no delimiter, so S1 records it as malformed. That is the honest
    answer from a key/value grammar, and the domain reclassifies it rather than teaching
    S1 a special case that only one consumer wants.
    """

    name = "faillock.conf"
    delimiters = ("=",)
    comment_markers = ("#",)
    inline_comments = False
    duplicate_policy = keyvalue.LAST_WINS
    empty_value_policy = keyvalue.EMPTY_IS_VALUE


PROFILES = {LOGIN_DEFS: LoginDefs(), PWQUALITY: PwQuality(), FAILLOCK: Faillock()}

# --- limits.conf is NOT key/value --------------------------------------------------------
# `<domain> <type> <item> <value>`, for example `* hard nofile 65535`. There is no key and
# no delimiter, and inventing one would produce key/value-shaped evidence that every later
# consumer has to re-parse. A domain parser owns it, for the same reason sudoers has one.
LIMIT_TYPES = ("hard", "soft", "-")

# --- fragment directories ------------------------------------------------------------------
# Both families read only `*.conf` from their .d directory. The enumerator reports what it
# saw; this decides what counts, exactly as the sudoers filename rule does.
def fragment_eligible(name):
    return name.endswith(".conf")


CLASSIFICATION = {
    "family": result.PROVENANCE,
    "key": result.STATE, "key_raw": result.STATE, "value": result.STATE,
    "raw_digest": result.STATE,
    "domain": result.STATE, "domain_negated": result.STATE,
    "limit_type": result.STATE, "item": result.STATE,
    "retention": result.PROVENANCE, "grammar_digest": result.PROVENANCE,
    "source_path": result.PROVENANCE, "source_line": result.PROVENANCE,
    "ordinal": result.PROVENANCE, "section": result.PROVENANCE,
    "continued": result.PROVENANCE, "empty": result.DERIVED,
    "malformed": result.DERIVED, "anomalies": result.DERIVED,
    "duplicate_of": result.DERIVED,
}

LIMITATION = (
    "Declared values from four independent source families. No cross-source effective "
    "policy is computed: login.defs PASS_MAX_DAYS and a per-account /etc/shadow max-age "
    "are evidence at different layers, and reconciling them requires PAM, account state "
    "and distribution behaviour that this lane does not observe.")
