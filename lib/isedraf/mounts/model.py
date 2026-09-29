# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The vocabulary of declared and active mount evidence, and its three identities.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045
#
# THIS IS NOT "THE MOUNTS ON THIS HOST". The active side is what one mount namespace could
# see. Measured, not assumed: /proc/1/ns/mnt is unreadable unprivileged, so the collector
# cannot prove it shares pid 1's namespace.
#
# THREE IDENTITIES, NOT INTERCHANGEABLE
#
#   declared record identity   fstab source file + ordinal
#   active record identity     source space + kernel mount_id
#   cross-source candidate     normalized target path
#
# The third is a CORRESPONDENCE KEY. On a stock installation /proc/sys/fs/binfmt_misc
# appears twice in mountinfo, so a target names a place and not a thing. The declared side
# is no better: one UUID= can be declared for two targets, told apart only by an option
# inside the options field.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Declared fstab records, active mountinfo records, and what may be compared."""

from ..shared import compare
from ..status import COLLECTED, ERROR, NOT_TESTED, PARTIAL      # noqa: F401

STATE = "STATE"
OBSERVATION = "OBSERVATION"
DERIVED = "DERIVED"
PROVENANCE = "PROVENANCE"

DECLARED = "DECLARED"
ACTIVE = "ACTIVE"
# RESOLVED is deliberately absent: it would need an authoritative UUID/LABEL -> device
# source with its own acquisition and coverage, and Batch 3 defines none.

DECLARED_SCOPE = "FSTAB_DECLARATIONS"
# Ruling D: this universe and nothing wider. An absent /etc/fstab establishes that THIS
# source contributes zero declarations - not that there are no systemd units or generator
# output.

# The active side's EVIDENCE UNIVERSE: the set of mounts the active source can describe
# at all - those visible in the mount namespace the collection was made in. It answers
# "what could have been seen", and it is the same answer whether that evidence was read
# from a live /proc or from a fixture.
ACTIVE_SCOPE = "ACTIVE_MOUNTS_CURRENT_COLLECTION_NAMESPACE"

# --- ruling E: which space the active evidence came from ---------------------------------
# The SOURCE SPACE is a different question: where the bytes came from. A fixture root and
# the live kernel file can describe the same universe and are not the same provenance.
# These two are recorded as two fields and are never used as aliases for one another:
#   EVIDENCE UNIVERSE  !=  SOURCE SPACE / ACQUISITION CONTEXT
SOURCE_LIVE_NAMESPACE = "LIVE_CURRENT_COLLECTION_NAMESPACE"
SOURCE_FIXTURE_OFFLINE = "FIXTURE_OR_OFFLINE_EVIDENCE"
# A mountinfo under a corpus root describes whatever produced it. Calling that "the
# current namespace" would attribute a fixture's contents to the process reading it.
ACTIVE_SOURCE_SPACES = (SOURCE_LIVE_NAMESPACE, SOURCE_FIXTURE_OFFLINE)

FSTAB_FIELDS = ("source_spec", "target", "fstype", "options_raw", "dump", "pass")

SOURCE_TAG_UUID = "UUID"
SOURCE_TAG_LABEL = "LABEL"
SOURCE_TAG_PARTUUID = "PARTUUID"
SOURCE_TAG_PARTLABEL = "PARTLABEL"
SOURCE_TAG_ID = "ID"
SOURCE_TAG_PATH = "PATH"
SOURCE_TAG_NONE = "PATH_OR_OTHER"
SOURCE_TAGS = (SOURCE_TAG_UUID, SOURCE_TAG_LABEL, SOURCE_TAG_PARTUUID,
               SOURCE_TAG_PARTLABEL, SOURCE_TAG_ID, SOURCE_TAG_PATH, SOURCE_TAG_NONE)

PARSE_OK = "OK"
PARSE_FIELD_COUNT = "FIELD_COUNT"
PARSE_MALFORMED_NUMERIC = "MALFORMED_NUMERIC"
PARSE_MALFORMED_RECORD = "MALFORMED_RECORD"
PARSE_UNDECODABLE = "UNDECODABLE_LINE"
PARSE_STATUSES = (PARSE_OK, PARSE_FIELD_COUNT, PARSE_MALFORMED_NUMERIC,
                  PARSE_MALFORMED_RECORD, PARSE_UNDECODABLE)

OPTIONAL_SHARED = "shared"
OPTIONAL_MASTER = "master"
OPTIONAL_PROPAGATE_FROM = "propagate_from"
OPTIONAL_UNBINDABLE = "unbindable"
KNOWN_OPTIONAL = (OPTIONAL_SHARED, OPTIONAL_MASTER, OPTIONAL_PROPAGATE_FROM,
                  OPTIONAL_UNBINDABLE)

LIMITATION = (
    "Declared /etc/fstab entries and active mounts from one mount namespace. The "
    "collector cannot prove it shares the initial mount namespace, so mounts outside the "
    "observed one are not seen and their absence is not claimed. Source specifications "
    "written as UUID=, LABEL=, PARTUUID= or PARTLABEL= are recorded as written and are "
    "NOT resolved to devices. Mount options are a required dimension of equivalence whose "
    "semantics this batch cannot authoritatively normalize, so most pairs are not "
    "decidable. Nothing here decides that a mount failed, is unexpected, or is "
    "misconfigured."
)

NOT_COLLECTED = (
    "UUID/LABEL to device resolution",
    "mount option semantic normalization",
    "mount namespaces other than the one observed",
    "systemd .mount unit state",
    "whether a declared entry was attempted at boot",
)

PROHIBITED_CLAIMS = ("MOUNT_FAILED", "UNEXPECTED_MOUNT", "INSECURE", "MISCONFIGURED",
                     "SECURE", "HOST_ACTIVE_MOUNTS", "ALL_MOUNTS")


# =============================================================================
# The S3 adapter
# =============================================================================
DIMENSION_SOURCE = "source_identity"
DIMENSION_FSTYPE = "filesystem_type"
DIMENSION_OPTIONS = "mount_option_semantics"

UNRESOLVED_SOURCE_SPEC = "UNRESOLVED_SOURCE_SPEC"
UNRESOLVED_OPTION_SEMANTICS = "UNRESOLVED_OPTION_SEMANTICS"
SUBTREE_NOT_RESOLVABLE = "SUBTREE_NOT_RESOLVABLE"


def normalize_target(path):
    """The cross-source CANDIDATE key. Lexical only, never realpath."""
    if not path or path == "/":
        return path
    return path.rstrip("/") or "/"


class MountComparator(compare.Comparator):
    """Correspondence by target; equivalence only where the evidence establishes it."""

    name = "mounts.declared_vs_active"
    version = 1
    order_sensitive = False
    # fstab line order is provenance and matters to boot sequencing, which R1.5 does not
    # model. Reordering two unrelated declarations does not change what is declared.

    #: FROZEN. Every dimension that must be authoritatively equivalent for EQUIVALENT.
    #: Mount-option semantics stay here: an earlier draft removed them so MATCHED would be
    #: reachable, which optimises the result distribution rather than the evidence and
    #: would let `ro,nodev` declared against `rw` active read as MATCHED.
    REQUIRED_DIMENSIONS = (DIMENSION_SOURCE, DIMENSION_FSTYPE, DIMENSION_OPTIONS)

    #: Facts with no counterpart on the other side. Recorded, never compared.
    DECLARED_ONLY_FACTS = ("dump", "pass")
    ACTIVE_ONLY_FACTS = ("mount_id", "parent_mount_id", "root", "major_minor",
                         "optional_fields")

    SEMANTIC_FIELDS = compare.Comparator.SEMANTIC_FIELDS + (
        "REQUIRED_DIMENSIONS", "DECLARED_ONLY_FACTS", "ACTIVE_ONLY_FACTS")

    def identity(self, record):
        target = (record.get("target") if record.get("kind") == "FSTAB_ENTRY"
                  else record.get("mount_point"))
        return normalize_target(target)

    def compare_pair(self, declared, active):
        """Three-valued aggregation over the required dimensions.

        A PROVEN contradiction outranks a limit: answering UNKNOWN where a dimension is
        known to differ would hide a real observation.
        """
        verdicts = self.dimensions(declared, active)
        if compare.DIFFERENT in verdicts.values():
            return compare.DIFFERENT
        if compare.UNKNOWN in verdicts.values():
            return compare.UNKNOWN
        return compare.EQUIVALENT

    def dimensions(self, declared, active):
        """Each required dimension's own verdict, so an UNKNOWN can name its cause."""
        return {
            DIMENSION_SOURCE: self._source(declared, active),
            DIMENSION_FSTYPE: self._fstype(declared, active),
            DIMENSION_OPTIONS: self._options(declared, active),
        }

    def unresolved_reasons(self, declared, active):
        reasons = []
        verdicts = self.dimensions(declared, active)
        if verdicts[DIMENSION_SOURCE] == compare.UNKNOWN:
            reasons.append(UNRESOLVED_SOURCE_SPEC)
        if verdicts[DIMENSION_OPTIONS] == compare.UNKNOWN:
            reasons.append(UNRESOLVED_OPTION_SEMANTICS)
        if active.get("root") not in (None, "/"):
            reasons.append(SUBTREE_NOT_RESOLVABLE)
        return reasons

    def _source(self, declared, active):
        """UUID=/LABEL= against a kernel device path cannot be compared, not `differs`."""
        tag = declared.get("source_spec_tag")
        if tag != SOURCE_TAG_NONE:
            return compare.UNKNOWN
        if active.get("root") not in (None, "/"):
            # A bind or subvolume view: the active source names the backing device while
            # the declaration names a subtree of it, and no stated transformation maps
            # one onto the other.
            return compare.UNKNOWN
        spec, source = declared.get("source_spec"), active.get("mount_source")
        if spec is None or source is None:
            return compare.UNKNOWN
        return compare.EQUIVALENT if spec == source else compare.DIFFERENT

    def _fstype(self, declared, active):
        declared_type, active_type = declared.get("fstype"), active.get("fstype")
        if not declared_type or not active_type:
            return compare.UNKNOWN
        if declared_type == active_type:
            return compare.EQUIVALENT
        if active_type == "autofs":
            # systemd mounts autofs on a target and the real filesystem arrives later.
            # Calling that a contradiction would report a difference on a host doing
            # exactly what it was configured to do.
            return compare.UNKNOWN
        return compare.DIFFERENT

    def _options(self, declared, active):
        """Almost always UNKNOWN, and that is the honest answer.

        The kernel ADDS options never declared, REWRITES others (`subvol=root` becomes
        `subvol=/root`), and never reports declaration-only options such as `noauto` and
        `nofail`. `defaults` expands to a filesystem-dependent set that never appears
        literally. No normalization is claimed, because none can be stated that preserves
        Linux semantics for every filesystem - and a normalization wrong for one
        filesystem is worse than none.

        The one decidable case needs no semantics at all: identical text on both sides.
        """
        declared_options = declared.get("options") or []
        active_options = active.get("super_options") or []
        if declared_options and declared_options == active_options:
            return compare.EQUIVALENT
        return compare.UNKNOWN
