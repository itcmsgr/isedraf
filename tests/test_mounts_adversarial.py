# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Attack the mounts declared-vs-active lane from its contract, before the code.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, GOV-001, GOV-002
#
# RED, PASS R1. Written against docs/development/MOUNTS_DECLARED_VS_ACTIVE_CONTRACT.md
# (rulings C-F applied) while lib/isedraf/mounts/ did not exist in this worktree, so every
# expectation here comes from that contract, from the frozen shared contracts
# (lib/isedraf/shared/compare.py, lib/isedraf/coverage.py, lib/isedraf/hostpath.py) and
# from fstab(5)/proc(5) grammar - never from what an implementation happens to do.
#
# The four attacks this suite exists for:
#
#   RULING C   an options-subset rule manufactures MATCHED out of a dimension nothing
#              can judge. Its mirror manufactures MODIFIED out of the same absence:
#              `noauto` is declared and never appears in the kernel's option set, so a
#              subset rule reports a confident mismatch about a normal host.
#
#   RULING D   source status and universe completeness are two questions. An absent
#              fstab contributes zero declarations and bounds its universe COMPLETELY,
#              so ACTIVE_ONLY becomes assertable; a REFUSED one bounds nothing, and an
#              ACTIVE_ONLY drawn from it would be an accusation manufactured from a gap
#              in our own reading.
#
#   RULING E   a non-root collection root must never fall through to the live /proc.
#              The fixture then describes the machine running the tool, and the evidence
#              says it is the machine under test.
#
#   RULING F   authorizedkeys._inside("/", ...) returned False, so at the ONLY root
#              production uses the lane read nothing while 191 tests passed. No fixture
#              root can be "/", so path-sensitive logic is exercised at a fixture root
#              AND at "/" here.
#
# Names versus semantics. The contract fixes the module set (acquire, model, sources),
# the fstab record FIELD names (section 2), the frozen scope VALUES (section 1) and every
# relationship value S3 defines - and it does not fix the name of a single function. So
# entry points are discovered by the shape of what they return and asserted by
# vocabulary, exactly as the authorized_keys pass did with PARSER_ENTRY_POINTS. A rename
# must not turn this suite green or red; a changed meaning must.
#
# Host contact: /proc/self/mountinfo, /proc/self/ns/mnt and /etc/fstab are READ at the
# production root, because ruling F exists precisely because nobody did. Nothing is
# mounted, unmounted, written or modified, and no assertion depends on this machine's
# disk layout - the production-root assertions are structural (path, scope, non-emptiness).
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""Independent adversarial attack on the mounts declared-versus-active lane."""

# =============================================================================
# CONTRACT QUESTIONS
#
# Raised rather than resolved. Each is written the CONTRACT's way in the tests below;
# where the contract is silent the weaker reading is asserted, and the question is here.
#
# CQ-1  RULING D versus coverage.absence_claim_allowed(). Ruling D: an absent
#       /etc/fstab is source status NOT_TESTED / NOT_FOUND, universe COMPLETE, and
#       absence claims PERMITTED. The central derivation is
#       `status == COLLECTED and universe in (COMPLETE, NOT_APPLICABLE)`, so the
#       coverage entry for that same file necessarily reports
#       absence_claim_allowed = False. The only way to satisfy both is for the
#       declared EVIDENCE to be COLLECTED (zero records, complete universe) while the
#       coverage ENTRY is NOT_TESTED - two statements about one source in one
#       artifact. These tests assert the observable half (ACTIVE_ONLY becomes
#       assertable) and take no position on which field a later criterion should read.
#       Owner question: is the central rule to be amended, or is the per-source
#       coverage entry simply not the authority for this class of absence?
#
# CQ-2  Section 7 does not enumerate the adapter's REQUIRED DIMENSIONS. "Every
#       dimension the adapter requires" is the hinge of the whole tri-state rule.
#       These tests assume {target, fstype, source_spec, options}, each authoritative
#       only on literal equality. Under that reading MATCHED is reachable (everything
#       written identically) and an options SUPERSET is EQUIVALENCE_UNKNOWN, which is
#       what ruling C's rejection is for. Under the other available reading - options
#       are not a required dimension at all - a superset silently becomes MATCHED and
#       ruling C has no observable consequence. The contract should say which.
#
# CQ-3  A provenance key collision between two frozen conventions.
#       `compare.compare()` writes provenance["coverage"] = COMPLETE | PARTIAL.
#       Every R1.5-P producer in the repository writes provenance["coverage"] =
#       [per-source acquisition entries]. Mounts is the first module that is BOTH, and
#       a dict.update() of one over the other destroys the axis the contract reports
#       beside coverage. Measured here on a deliberately honest stub, which lost the
#       comparison axis without any test outside this file noticing.
#
# CQ-4  fstab(5) treats an omitted dump/pass field as 0. Section 2 says the fields are
#       preserved verbatim and resolved NOT AT ALL. These tests take the contract's
#       side: a 4-field line reports dump and pass as undeclared rather than as "0",
#       so "the operator wrote 0" and "the operator wrote nothing" stay distinct.
#
# CQ-5  Section 2's retention rule ("a malformed line is retained, never skipped") is
#       written for the DECLARED side. Dropping a mountinfo line denies that an active
#       mount exists, which is the worse direction, but the contract does not say so.
#       The test here asserts only the weaker property - nothing vanishes without a
#       trace - and the contract should state the stronger one if it means it.
#
# CQ-6  An undecodable byte in an fstab target. NORM-035 keeps lone surrogates out of
#       canonical JSON, and this contract does not say how such a target is
#       represented. The test accepts either a lossless surrogate form or a hex
#       identity, and rejects only U+FFFD, which silently merges two different paths.
# =============================================================================
import ast
import inspect
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf import coverage as coverage_module                  # noqa: E402
from isedraf import hostpath, textbytes                          # noqa: E402
from isedraf.shared import compare, result                       # noqa: E402
from isedraf.mounts import acquire, model, sources               # noqa: E402


# =============================================================================
# Fixture evidence.
#
# Synthetic throughout. No device UUID, label or partition of the developing host is
# reproduced; the structure of each finding is preserved and the values are invented.
# =============================================================================

UUID_A = "UUID=00000000-0000-4000-8000-000000000001"
UUID_B = "UUID=00000000-0000-4000-8000-000000000002"
LABEL_A = "LABEL=fixture-label"
PARTUUID_A = "PARTUUID=00000000-0000-4000-8000-00000000000a"
PARTLABEL_A = "PARTLABEL=fixture-partlabel"

# --- declared (fstab) --------------------------------------------------------------------
# Six positional fields: source_spec target fstype options_raw dump pass.
DECL_EQ = "/dev/sda1 /data ext4 rw 0 2\n"
DECL_UUID = "%s /data ext4 rw 0 2\n" % UUID_A
DECL_SUPERSET = "/dev/sda1 /data ext4 rw,noatime 0 2\n"
DECL_NOAUTO = "/dev/sda1 /data ext4 noauto,nofail 0 2\n"
DECL_DEFAULTS = "/dev/sda1 /data ext4 defaults 0 2\n"
DECL_XFS = "/dev/sda1 /data xfs rw 0 2\n"
DECL_OTHER_TARGET = "/dev/sda1 /srv ext4 rw 0 2\n"

# --- active (mountinfo) ------------------------------------------------------------------
#   mount_id parent_id major:minor root mount_point options [optional] - fstype
ACT_EQ = "21 20 8:1 / /data rw - ext4 /dev/sda1 rw\n"
ACT_OTHER_SOURCE = "21 20 8:9 / /data rw - ext4 /dev/sdb9 rw\n"
ACT_XFS = "21 20 8:1 / /data rw - xfs /dev/sda1 rw\n"
ACT_SUPERSET = "21 20 8:1 / /data rw,noatime - ext4 /dev/sda1 rw,noatime,seclabel\n"
ACT_TMP = "31 20 0:31 / /tmp rw,nosuid shared:4 - tmpfs tmpfs rw,inode64\n"

ACT_NO_OPTIONAL = "22 20 8:2 / /srv rw,noatime - ext4 /dev/sda2 rw\n"
ACT_MANY_OPTIONAL = (
    "23 20 8:3 / /opt rw shared:2 master:3 propagate_from:4 unbindable"
    " - ext4 /dev/sda3 rw\n")
ACT_UNKNOWN_OPTIONAL = "24 20 8:4 / /home rw frobnicate:9 - ext4 /dev/sda4 rw\n"
ACT_DASH_SOURCE = "25 20 0:33 / /ephemeral rw shared:5 - tmpfs - rw,size=100k\n"
ACT_BIND = "28 20 8:1 /srv/shared /export rw,relatime shared:9 - ext4 /dev/sda1 rw\n"
ACT_ESCAPED = "29 20 8:5 / /mnt/my\\040dir rw shared:11 - ext4 /dev/sda5 rw\n"

# The measured stacked case, structurally: one target, two active records, two fstypes.
ACT_STACK_AUTOFS = (
    "26 20 0:34 / /proc/sys/fs/binfmt_misc rw shared:15 - autofs fixture-1 rw,fd=40\n")
ACT_STACK_REAL = (
    "27 26 0:54 / /proc/sys/fs/binfmt_misc rw shared:177 - binfmt_misc binfmt_misc rw\n")

FSTAB_PATH = "etc/fstab"
MOUNTINFO_PATH = "proc/self/mountinfo"
NS_PATH = "proc/self/ns/mnt"

LIVE_MOUNTINFO = "/proc/self/mountinfo"
LIVE_FSTAB = "/etc/fstab"


# =============================================================================
# Shape-tolerant, vocabulary-strict plumbing.
#
# The lane may lay its evidence out as it likes. It may not choose its own vocabulary,
# its own field names where the contract prints them, or its own answers.
# =============================================================================

_MISS = object()


def _default(obj):
    as_dict = getattr(obj, "as_dict", None)
    if callable(as_dict):
        return as_dict()
    return str(obj)


def dumped(obj):
    return json.dumps(obj, default=_default, sort_keys=True)


def structure(obj):
    """The evidence as plain JSON types, whatever objects it was built from."""
    return json.loads(dumped(obj))


def walk(obj):
    """Every dict anywhere inside a serialised evidence object."""
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            for found in walk(value):
                yield found
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            for found in walk(value):
                yield found


def dicts(obj):
    return list(walk(structure(obj)))


def _attempt(function, *args):
    try:
        return function(*args)
    except Exception:                      # noqa: BLE001 - discovery probe, not a test
        return _MISS


def _module_callables(module):
    name = getattr(module, "__name__", "")
    out = []
    for attr in sorted(dir(module)):
        if attr.startswith("_"):
            continue
        value = getattr(module, attr)
        if callable(value) and getattr(value, "__module__", name) == name:
            out.append((attr, value))
    return out


def _record_list(out):
    """Records, whether they arrived bare, in a tuple, or inside an Evidence."""
    if isinstance(out, list):
        return out
    if isinstance(out, tuple):
        for element in out:
            if isinstance(element, list):
                return element
        return None
    records = getattr(out, "records", None)
    if isinstance(records, list):
        return records
    return None


_DISCOVERED = {}

FSTAB_FIELDS = ("source_spec", "target", "fstype", "options_raw",
                "dump", "pass", "source_line", "ordinal", "parse_status")
FSTAB_REQUIRED = ("source_spec", "target", "fstype", "options_raw")

MOUNT_POINT_KEYS = ("mount_point", "target", "mountpoint", "path", "mount_target")
MOUNT_ID_KEYS = ("mount_id", "mountid", "kernel_mount_id", "id")
PARENT_ID_KEYS = ("parent_id", "parentid", "parent_mount_id", "parent")
MOUNT_ROOT_KEYS = ("root", "mount_root", "subtree", "source_root")
FSTYPE_KEYS = ("fstype", "filesystem_type", "fs_type", "type")
MOUNT_SOURCE_KEYS = ("mount_source", "source", "source_spec", "device", "spec")
DEVICE_KEYS = ("major_minor", "device_number", "devno", "major:minor", "st_dev",
               "device_id")
OPTION_KEYS = ("options", "options_raw", "vfs_options", "mount_options",
               "super_options", "fs_options")


def _field(record, keys, what):
    for key in keys:
        if key in record:
            return record[key]
    raise AssertionError(
        "no %s field in the record %r; tried %r. The contract names this concept and a "
        "record that does not carry it cannot support the comparison it is for."
        % (what, sorted(record), list(keys)))


def _has_field(record, keys):
    return any(key in record for key in keys)


def _discover(kind, sample, predicate, description):
    """Find the entry point by the SHAPE of what it returns, never by its name."""
    if kind in _DISCOVERED:
        return _DISCOVERED[kind]
    tried = []
    for attr, function in _module_callables(sources):
        tried.append(attr)
        for extra in ((os.path.join("/fixture", FSTAB_PATH), 0),
                      (os.path.join("/fixture", FSTAB_PATH),), ()):
            out = _attempt(function, sample, *extra)
            if out is _MISS:
                continue
            records = _record_list(out)
            if not records or not all(isinstance(r, dict) for r in records):
                continue
            if predicate(records):
                _DISCOVERED[kind] = (function, len(extra))
                return _DISCOVERED[kind]
    raise AssertionError(
        "isedraf.mounts.sources exposes no %s. The contract makes sources.py the pure "
        "text->records layer for both sides. Public callables tried: %r"
        % (description, sorted(set(tried))))


def _fstab_predicate(records):
    return all(field in records[0] for field in FSTAB_REQUIRED)


def _mountinfo_predicate(records):
    first = records[0]
    return (_has_field(first, MOUNT_ID_KEYS) and _has_field(first, MOUNT_POINT_KEYS)
            and not _has_field(first, ("options_raw",)))


def fstab_parser():
    return _discover("fstab", DECL_EQ, _fstab_predicate,
                     "pure fstab text->records entry point")


def mountinfo_parser():
    return _discover("mountinfo", ACT_EQ, _mountinfo_predicate,
                     "pure mountinfo text->records entry point")


def _parse_with(discovered, text, source):
    function, extra = discovered
    args = (text, source, 0)[:1 + extra]
    out = function(*args)
    records = _record_list(out)
    if records is None:
        raise AssertionError("%r returned %r, which carries no record list"
                             % (function, out))
    return records


def fstab_parse(text, source="/fixture/etc/fstab"):
    return _parse_with(fstab_parser(), text, source)


def mountinfo_parse(text, source="/fixture/proc/self/mountinfo"):
    return _parse_with(mountinfo_parser(), text, source)


def comparator():
    """The lane's S3 adapter, found by type rather than by name."""
    if "comparator" in _DISCOVERED:
        return _DISCOVERED["comparator"]
    found = comparator_classes()
    if not found:
        raise AssertionError(
            "the lane defines no compare.Comparator subclass. S3 is the frozen "
            "declared-vs-active engine and the contract's section 7 states the rule "
            "this lane's adapter must implement.")
    instance = found[0]()
    _DISCOVERED["comparator"] = instance
    return instance


def comparator_classes():
    seen, found = set(), []
    for module in (model, acquire, sources):
        for _, value in _module_callables(module):
            if (isinstance(value, type) and issubclass(value, compare.Comparator)
                    and value is not compare.Comparator and value not in seen):
                seen.add(value)
                found.append(value)
    return found


COLLECT_NAMES = ("collect", "collect_mounts", "acquire", "collect_all", "run")


def collector():
    for name in COLLECT_NAMES:
        function = getattr(acquire, name, None)
        if callable(function):
            return function
    raise AssertionError(
        "isedraf.mounts.acquire exposes no collection entry point; every other lane in "
        "the repository spells it collect(root='/'). Tried %r" % (COLLECT_NAMES,))


def collect(root):
    return collector()(root)


def rooting_function(token):
    """A pure root -> evidence-source-path function, if the lane has one.

    Accepted loosely (it must merely answer with a path naming the source) and asserted
    strictly by the tests, so a function returning the WRONG path is a failure rather
    than an undiscovered function.
    """
    key = "rooting:" + token
    if key in _DISCOVERED:
        return _DISCOVERED[key]
    for module in (acquire, model, sources):
        for _, function in _module_callables(module):
            if isinstance(function, type):
                continue
            out = _attempt(function, "/fixture")
            value = out if isinstance(out, str) else _path_like(out)
            if isinstance(value, str) and token in value and value.startswith("/fixture"):
                _DISCOVERED[key] = (function, module)
                return _DISCOVERED[key]
    return None


def _path_like(out):
    if isinstance(out, dict):
        for key in ("path", "source", "source_path", "file"):
            if isinstance(out.get(key), str):
                return out[key]
    if isinstance(out, (list, tuple)):
        for element in out:
            if isinstance(element, str):
                return element
    return None


def rooted_path(token, root):
    found = rooting_function(token)
    function = found[0]
    out = function(root)
    value = out if isinstance(out, str) else _path_like(out)
    if not isinstance(value, str):
        raise AssertionError("%r(%r) answered %r, which is not a path" %
                             (function, root, out))
    return value


# --- reading a collected result ------------------------------------------------

def comparison_items(obj):
    """Every S3 relationship item, wherever the lane hung the comparison."""
    return [d for d in dicts(obj) if "relationship" in d and "identity" in d]


def relationships(obj, identity=None):
    return [item["relationship"] for item in comparison_items(obj)
            if identity is None or item["identity"] == identity]


def comparison_provenance(obj):
    for entry in dicts(obj):
        if "declared_status" in entry and "active_status" in entry:
            return entry
    raise AssertionError(
        "no S3 comparison provenance in the evidence: nothing carries declared_status "
        "and active_status. compare.compare() emits both, so either the lane never ran "
        "the frozen comparator or it dropped the axes the contract reports beside "
        "coverage.")


S3_COVERAGE_VALUES = (compare.COMPLETE, compare.PARTIAL, compare.NOT_COMPARABLE,
                      compare.NOT_APPLICABLE)


def s3_coverage(obj):
    """The comparison's own coverage axis, wherever the lane hung it.

    It is looked up rather than read from a fixed key because of a collision this suite
    measured: compare.compare() writes provenance["coverage"] = COMPLETE|PARTIAL, and
    every R1.5-P producer in the repository writes provenance["coverage"] = [per-source
    entries]. Mounts is the first module that is BOTH, and a single provenance dict
    carrying both conventions loses one of them silently - the acquisition list wins,
    because it is merged last, and the axis the contract reports beside it disappears.
    """
    provenance = comparison_provenance(obj)
    found = [value for key, value in provenance.items()
             if "coverage" in key and isinstance(value, str)
             and value in S3_COVERAGE_VALUES]
    if not found:
        raise AssertionError(
            "the S3 comparison coverage axis is not readable in the evidence. "
            "compare.compare() emits it as provenance['coverage'], and the R1.5-P "
            "acquisition list uses the same key in every other lane; keys were %r"
            % (sorted(provenance),))
    return found[0]


def declared_records(obj):
    return [d for d in dicts(obj) if "source_spec" in d and "options_raw" in d]


def active_records(obj):
    return [d for d in dicts(obj)
            if _has_field(d, MOUNT_ID_KEYS) and _has_field(d, MOUNT_POINT_KEYS)
            and "options_raw" not in d]


def coverage_entries(obj):
    return [d for d in dicts(obj) if "access_outcome" in d]


def coverage_for(obj, fragment):
    return [entry for entry in coverage_entries(obj)
            if fragment in str(entry.get("source", ""))]


def source_paths(obj):
    """Every path the evidence names as a SOURCE, in a field rather than in prose.

    Separated from absolute_paths on purpose. A lane may name /proc/self/mountinfo in a
    sentence that explains what it did NOT read; naming it as the source it read is the
    fallthrough ruling E forbids, and only the second is a defect.
    """
    out = []
    for entry in dicts(obj):
        for key in ("source", "source_path", "path", "file", "active_source",
                    "declared_source"):
            value = entry.get(key)
            if isinstance(value, str) and value.startswith("/"):
                out.append(os.path.normpath(value))
    return out


def absolute_paths(obj):
    found = []
    for candidate in re.findall(r"/[A-Za-z0-9_./:*%-]+", dumped(obj)):
        found.append(os.path.normpath(candidate))
    return found


def side(status, records, reason=None):
    if status != result.COLLECTED and reason is None:
        reason = "incomplete for test purposes"
    return result.Evidence(status, records=records, reason=reason)


def compare_sides(declared_text, active_text,
                  declared_status=result.COLLECTED, active_status=result.COLLECTED,
                  declared_universe_complete=True, active_universe_complete=True):
    """One comparison, through the LANE's adapter and the FROZEN engine.

    PORTED: when IQ-020 made the universes mandatory, this helper was given a constant
    False for both, which is the cheapest way to make the call legal and the most
    expensive way to be wrong - with neither universe complete, EVERY relationship
    degrades to COUNTERPART_UNKNOWN and every test in this file asserting a positive
    relationship passes or fails for the wrong reason. The fixtures here are fully
    parsed text, so their universes ARE complete; a test that wants an incomplete one
    now says which side, separately from that side's status.
    """
    return compare.compare(side(declared_status, fstab_parse(declared_text)),
                           side(active_status, mountinfo_parse(active_text)),
                           comparator(),
        declared_universe_complete=declared_universe_complete,
        active_universe_complete=active_universe_complete)


def active_side_provenance(root_kind):
    """The active side's provenance at a fixture root, or at the production root.

    Section 13: the rooting rules are tested at BOTH, because "/" is where the root and
    the separator degenerate and where every path helper stops being exercised.
    """
    if root_kind == "production":
        return acquire.collect_active("/").provenance
    directory = tempfile.mkdtemp()
    try:
        os.makedirs(os.path.join(directory, "proc", "self"))
        with open(os.path.join(directory, "proc", "self", "mountinfo"), "w") as handle:
            handle.write(ACT_EQ)
        return acquire.collect_active(directory).provenance
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def sole(items, what):
    if len(items) != 1:
        raise AssertionError("expected exactly one %s, got %d: %r"
                             % (what, len(items), items))
    return items[0]


# --- AST helpers ----------------------------------------------------------------

def tree_of(module):
    path = os.path.abspath(inspect.getsourcefile(module))
    with open(path, "r") as handle:
        return ast.parse(handle.read(), filename=path)


def identifiers(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    return names


def imported(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base = ("." * (node.level or 0)) + (node.module or "")
            names.add(base)
            for alias in node.names:
                names.add(base + "." + alias.name)
    return names


def string_constants(tree):
    """Every string literal that is CODE, not prose.

    Docstrings and bare string expressions are excluded: a module that writes down the
    rule it obeys is not breaking it, and an assertion that punished the sentence would
    push the explanation out of the file.
    """
    prose = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            prose.add(id(node.value))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and id(node) not in prose:
            out.append(node.value)
    return out


def lane_modules():
    return (acquire, model, sources)


# =============================================================================
# A fixture host, and the production host.
# =============================================================================

class Fixture(unittest.TestCase):
    """A private collection root in a temporary directory. Nothing is mounted."""

    def setUp(self):
        self.enclosure = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.enclosure, True)
        self.root = os.path.join(self.enclosure, "root")
        self.outside = os.path.join(self.enclosure, "outside")
        os.makedirs(os.path.join(self.root, "etc"))
        os.makedirs(os.path.join(self.root, "proc", "self"))
        os.makedirs(self.outside)

    def write(self, relative, content, mode=None):
        path = os.path.join(self.root, relative)
        directory = os.path.dirname(path)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        handle = open(path, "wb" if isinstance(content, bytes) else "w")
        try:
            handle.write(content)
        finally:
            handle.close()
        if mode is not None:
            os.chmod(path, mode)
        return path

    def host(self, fstab=DECL_EQ, mountinfo=ACT_EQ, fstab_mode=None):
        if fstab is not None:
            self.write(FSTAB_PATH, fstab, fstab_mode)
        if mountinfo is not None:
            self.write(MOUNTINFO_PATH, mountinfo)
        return collect(self.root)


def live_mountinfo_readable():
    return os.access(LIVE_MOUNTINFO, os.R_OK)


def running_as_root():
    return os.geteuid() == 0


# =============================================================================
# 1. The surface the contract declares
# =============================================================================

class ContractSurface(unittest.TestCase):
    """The lane is three modules, and each must answer for its half of the contract."""

    def test_the_lane_is_exactly_the_three_declared_modules(self):
        for module, name in ((acquire, "acquire"), (model, "model"),
                             (sources, "sources")):
            self.assertEqual(module.__name__, "isedraf.mounts." + name)

    def test_sources_parses_fstab_text(self):
        self.assertTrue(fstab_parse(DECL_EQ))

    def test_sources_parses_mountinfo_text(self):
        self.assertTrue(mountinfo_parse(ACT_EQ))

    def test_the_two_parsers_are_not_the_same_function(self):
        # fstab has six positional fields and mountinfo has a variable-length optional
        # section terminated by '-'. One function that claims to do both has guessed a
        # grammar for at least one of them.
        self.assertIsNot(fstab_parser()[0], mountinfo_parser()[0])

    def test_the_lane_supplies_exactly_one_s3_adapter(self):
        found = comparator_classes()
        self.assertEqual(len(found), 1,
                         "expected one compare.Comparator subclass in the lane, found "
                         "%r" % ([c.__name__ for c in found],))

    def test_the_adapter_speaks_the_tri_state_contract(self):
        self.assertEqual(comparator().equivalence_contract, "TRI_STATE_V1")

    def test_acquire_exposes_a_collection_entry_point(self):
        self.assertTrue(callable(collector()))

    def test_a_pure_rooting_function_answers_for_the_active_source(self):
        self.assertIsNotNone(
            rooting_function("mountinfo"),
            "no pure collection-root -> active-source-path function was found. Ruling F "
            "requires path-sensitive logic to be exercisable at collection_root='/' "
            "WITHOUT reading arbitrary live-host state, and a path that can only be "
            "reached by performing the collection cannot be tested that way.")

    def test_a_pure_rooting_function_answers_for_the_declared_source(self):
        self.assertIsNotNone(rooting_function("fstab"),
                             "no pure collection-root -> /etc/fstab path function")


# =============================================================================
# 2. Vocabulary. The contract prints VALUES; the lane must hold those values.
# =============================================================================

class Vocabulary(unittest.TestCase):
    """A lane that invents FIXTURE_SCOPE has changed the product's evidence vocabulary.

    Asserted over the VALUES rather than the constant names: the authorized_keys pass
    lost 22 tests to the assumption that a value printed in a contract is also the name
    of the constant holding it, and the rule it was reaching for is about the value.
    """

    SCOPES = ("LIVE_CURRENT_COLLECTION_NAMESPACE", "FIXTURE_OR_OFFLINE_EVIDENCE",
              "ACTIVE_MOUNTS_CURRENT_COLLECTION_NAMESPACE")

    def values(self):
        out = set()
        for module in lane_modules():
            for name in dir(module):
                if name.startswith("_"):
                    continue
                value = getattr(module, name)
                if isinstance(value, str):
                    out.add(value)
                elif isinstance(value, (tuple, list, frozenset, set)):
                    out.update(v for v in value if isinstance(v, str))
                elif isinstance(value, dict):
                    out.update(v for v in value.values() if isinstance(v, str))
                    out.update(k for k in value if isinstance(k, str))
        return out

    def test_the_frozen_scope_values_are_defined(self):
        missing = [scope for scope in self.SCOPES if scope not in self.values()]
        self.assertEqual(missing, [],
                         "the contract freezes these scope values and the lane defines "
                         "no constant holding %r" % (missing,))

    def test_the_universe_and_the_source_space_are_two_fields(self):
        """The owner's naming ruling, which nothing else in this file measured.

        Defining the constant is not using it. The lane originally set the active
        side's `scope` to the SOURCE SPACE, so one field answered two questions - what
        the evidence could describe, and where the bytes came from - and the reverted
        aliasing passed 174 tests because the constant still existed in model.py.

            EVIDENCE UNIVERSE  !=  SOURCE SPACE / ACQUISITION CONTEXT
        """
        for root_kind in ("fixture", "production"):
            provenance = active_side_provenance(root_kind)
            self.assertEqual(provenance["scope"],
                             "ACTIVE_MOUNTS_CURRENT_COLLECTION_NAMESPACE",
                             "at the %s root the active scope is %r; the universe is "
                             "the same question whichever source answered it"
                             % (root_kind, provenance["scope"]))
            self.assertIn(provenance["source_space"], self.SCOPES[:2])
            self.assertNotEqual(provenance["scope"], provenance["source_space"],
                                "one value is carrying both concepts")

    def test_the_source_space_still_distinguishes_the_two_roots(self):
        # The ruling separates the axes; it does not make the source space constant.
        self.assertNotEqual(active_side_provenance("fixture")["source_space"],
                            active_side_provenance("production")["source_space"],
                            "a fixture collection and a live one report the same "
                            "acquisition context, so the axis is now inert")

    def test_the_two_source_space_scopes_are_distinct(self):
        self.assertNotEqual(self.SCOPES[0], self.SCOPES[1])
        self.assertTrue({self.SCOPES[0], self.SCOPES[1]} <= self.values())

    def test_the_lane_does_not_define_temporal_vocabulary(self):
        # Section 12: ADDED / REMOVED describe change over time. This compares two
        # sources at one instant.
        for word in ("ADDED", "REMOVED"):
            self.assertNotIn(word, self.values(),
                             "the lane defines the temporal value %r" % word)

    def test_the_lane_never_names_proc_mounts_as_a_source(self):
        # Section 1, fallback policy: none. /proc/mounts loses the mount ID, the parent
        # ID and the root field, and a comparison whose identity silently degraded is
        # worse than one that says it could not run.
        for module in lane_modules():
            for text in string_constants(tree_of(module)):
                self.assertNotIn("proc/mounts", text,
                                 "%s names /proc/mounts, and the contract's fallback "
                                 "policy is none" % module.__name__)

    def test_the_lane_names_no_external_resolution_tool(self):
        # Ruling C and section 2: no UUID/LABEL resolution source is defined by this
        # batch, and findmnt is a development oracle, never a production dependency.
        forbidden = ("findmnt", "lsblk", "blkid", "by-uuid", "by-label", "by-partuuid",
                     "udevadm", "/dev/disk")
        for module in lane_modules():
            for text in string_constants(tree_of(module)):
                lowered = text.lower()
                for token in forbidden:
                    self.assertNotIn(token, lowered,
                                     "%s names %r; resolving a UUID or a label needs an "
                                     "authoritative source this batch does not define"
                                     % (module.__name__, token))


# =============================================================================
# 3. The fstab grammar - against the pure parser alone
# =============================================================================

class FstabGrammar(unittest.TestCase):
    """Six positional fields, preserved verbatim, resolved not at all."""

    def one(self, text):
        return sole(fstab_parse(text), "fstab record from %r" % text)

    def test_a_normal_line_is_one_record(self):
        record = self.one(DECL_EQ)
        self.assertEqual(record["source_spec"], "/dev/sda1")
        self.assertEqual(record["target"], "/data")
        self.assertEqual(record["fstype"], "ext4")
        self.assertEqual(record["options_raw"], "rw")

    def test_every_contract_field_is_present(self):
        record = self.one(DECL_EQ)
        missing = [f for f in FSTAB_FIELDS if f not in record]
        self.assertEqual(missing, [],
                         "section 2 prints the preserved field set verbatim; %r is "
                         "absent" % (missing,))

    def test_the_dump_and_pass_fields_are_kept_as_written(self):
        record = self.one(DECL_EQ)
        self.assertEqual(str(record["dump"]), "0")
        self.assertEqual(str(record["pass"]), "2")

    def test_an_empty_file_produces_no_records(self):
        self.assertEqual(fstab_parse(""), [])

    def test_a_file_of_only_comments_produces_no_records(self):
        text = "# /etc/fstab\n#\n#   <spec> <target>\n\n   \n"
        self.assertEqual(fstab_parse(text), [])

    def test_a_comment_after_a_declaration_is_not_a_record(self):
        records = fstab_parse(DECL_EQ + "# trailing note\n")
        self.assertEqual(len(records), 1)

    def test_four_fields_parse_and_invent_no_dump_or_pass(self):
        # fstab(5) lets dump and pass be omitted. Section 2 says the fields are
        # preserved verbatim and resolved NOT AT ALL, so writing "0" where the operator
        # wrote nothing manufactures a declaration. See CONTRACT QUESTIONS 1.
        record = self.one("/dev/sda1 /data ext4 rw\n")
        self.assertEqual(record["target"], "/data")
        self.assertEqual(record["options_raw"], "rw")
        # PORTED for section 11c: fstab(5) DEFINES an omitted field 5 or 6 as 0, so
        # the effective value is not an invention. The oracle stands and is stronger:
        # the record must also say the field was never written, or a reader cannot
        # tell a declared 0 from an omitted one. Deleting either flag fails this.
        for field in ("dump", "pass"):
            self.assertEqual(str(record[field]), "0")
            self.assertIs(record[field + "_declared"], False,
                          "field %r was not declared and the record does not say so"
                          % field)

    def test_five_fields_parse_and_invent_no_pass(self):
        record = self.one("/dev/sda1 /data ext4 rw 0\n")
        self.assertEqual(str(record["dump"]), "0")
        self.assertIs(record["dump_declared"], True)
        self.assertEqual(str(record["pass"]), "0")   # section 11c, as above
        self.assertIs(record["pass_declared"], False,
                      "an omitted pass is indistinguishable from a declared 0")

    def test_seven_fields_are_retained_and_not_silently_absorbed(self):
        record = self.one("/dev/sda1 /data ext4 rw 0 2 surplus\n")
        self.assertEqual(record["target"], "/data",
                         "the surplus field must not shift the field mapping")
        self.assertNotEqual(record["parse_status"], self.one(DECL_EQ)["parse_status"],
                            "a seventh field is not fstab(5) grammar and the record's "
                            "parse_status must say so rather than matching a clean line")

    def test_a_single_field_line_is_retained_not_dropped(self):
        # Section 2: a dropped line is a declaration the operator wrote and the tool
        # denies exists.
        record = self.one("garbage\n")
        self.assertNotEqual(record["parse_status"], self.one(DECL_EQ)["parse_status"])

    def test_a_malformed_line_does_not_suppress_the_good_ones(self):
        records = fstab_parse("garbage\n" + DECL_EQ)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["target"], "/data")

    def test_line_numbers_are_the_files_own(self):
        records = fstab_parse("# header\n\n" + DECL_EQ)
        self.assertEqual(records[0]["source_line"], 3)

    def test_the_source_path_travels_with_the_record(self):
        record = sole(fstab_parse(DECL_EQ, "/fixture/etc/fstab"), "record")
        self.assertIn("/fixture/etc/fstab", dumped(record))

    def test_escaped_whitespace_does_not_split_a_field(self):
        record = self.one("/dev/sda5 /mnt/my\\040dir ext4 rw 0 2\n")
        self.assertEqual(record["fstype"], "ext4",
                         "\\040 was treated as a field separator")
        self.assertIn("my", record["target"])

    def test_an_escaped_backslash_is_not_an_escape_of_the_next_character(self):
        record = self.one("/dev/sda5 /mnt/back\\\\slash ext4 rw 0 2\n")
        self.assertEqual(record["fstype"], "ext4")
        self.assertEqual(str(record["dump"]), "0")

    def test_an_escaped_tab_does_not_split_a_field(self):
        record = self.one("/dev/sda5 /mnt/a\\011b ext4 rw 0 2\n")
        self.assertEqual(record["fstype"], "ext4")

    def test_tabs_between_fields_are_separators(self):
        record = self.one("/dev/sda1\t/data\text4\trw\t0\t2\n")
        self.assertEqual(record["target"], "/data")
        self.assertEqual(record["fstype"], "ext4")

    def test_a_uuid_source_is_kept_as_written(self):
        record = self.one(DECL_UUID)
        self.assertEqual(record["source_spec"], UUID_A)
        self.assertNotIn("/dev/", dumped(record),
                         "a device path appears in a record whose declaration named a "
                         "UUID; resolving it needs an authoritative source this batch "
                         "does not define")

    def test_a_label_source_is_kept_as_written(self):
        self.assertEqual(self.one("%s /data ext4 rw 0 2\n" % LABEL_A)["source_spec"],
                         LABEL_A)

    def test_a_partuuid_source_is_kept_as_written(self):
        self.assertEqual(self.one("%s /data ext4 rw 0 2\n" % PARTUUID_A)["source_spec"],
                         PARTUUID_A)

    def test_a_partlabel_source_is_kept_as_written(self):
        self.assertEqual(
            self.one("%s /data ext4 rw 0 2\n" % PARTLABEL_A)["source_spec"], PARTLABEL_A)

    def test_a_network_source_is_kept_as_written(self):
        record = self.one("server.invalid:/export /net nfs rw 0 0\n")
        self.assertEqual(record["source_spec"], "server.invalid:/export")

    def test_a_bind_declaration_keeps_its_option_text(self):
        record = self.one("/srv/shared /export none bind 0 0\n")
        self.assertEqual(record["options_raw"], "bind")
        self.assertEqual(record["fstype"], "none")

    def test_noauto_and_nofail_are_kept_and_not_interpreted(self):
        record = self.one(DECL_NOAUTO)
        self.assertEqual(record["options_raw"], "noauto,nofail")
        for word in ("boot", "expected", "should", "will_mount"):
            self.assertNotIn(word, dumped(record).lower(),
                             "the record interprets a declaration-only option")

    def test_duplicate_targets_are_both_retained(self):
        records = fstab_parse(DECL_EQ + "%s /data ext4 ro 0 2\n" % UUID_B)
        self.assertEqual(len(records), 2)
        self.assertEqual([r["target"] for r in records], ["/data", "/data"])

    def test_duplicate_sources_are_both_retained(self):
        records = fstab_parse(DECL_EQ + DECL_OTHER_TARGET)
        self.assertEqual(len(records), 2)
        self.assertEqual([r["target"] for r in records], ["/data", "/srv"])

    def test_the_same_source_on_two_targets_keeps_two_identities(self):
        # Section 3, measured: the development host declares one UUID for two targets,
        # distinguished only by subvol= INSIDE the options field. Source is not identity.
        text = ("%s /a btrfs subvol=root 0 0\n%s /b btrfs subvol=home 0 0\n"
                % (UUID_A, UUID_A))
        records = fstab_parse(text)
        self.assertEqual(len(records), 2)
        self.assertNotEqual(records[0]["source_line"], records[1]["source_line"])
        self.assertNotEqual(records[0]["target"], records[1]["target"])

    def test_undecodable_bytes_survive_without_a_replacement_character(self):
        text = "/dev/sda1 /mnt/b\udcffad ext4 rw 0 2\n"
        record = self.one(text)
        self.assertNotIn("�", dumped(record),
                         "an undecodable byte became U+FFFD, which is a different path")
        # PORTED: this assumed target is always text. Section 11b of the contract
        # rules otherwise - undecodable means target is null and the exact bytes are
        # retained in the hex-identity field. The oracle is unchanged: lossless in
        # text, or byte-identified. It is not weakened, because the hex must still
        # decode to the original bytes.
        self.assertTrue(
            textbytes.has_surrogates(record["target"] or "")
            or record.get("target_bytes_hex") in dumped(record),
            "the undecodable target is neither lossless nor hex-identified")
        # R2/M12: a mutation that keeps the surrogates in `target` loses no bytes, so
        # the assertion above accepts it - and it labels the field UTF8 and drops the
        # hex. Section 11b prescribes ONE shape, and an encoding label that says UTF8
        # for a byte sequence which is not valid UTF-8 is a false statement about the
        # evidence whether or not the bytes survive. Pinned here.
        self.assertEqual(record["target_encoding"], textbytes.UNDECODABLE,
                         "an undecodable target is labelled %r"
                         % record["target_encoding"])
        self.assertTrue(record.get("target_bytes_hex"),
                        "an undecodable target carries no hex identity")
        if record["target"] is None:
            self.assertEqual(
                bytearray.fromhex(record["target_bytes_hex"]),
                bytearray(b"/mnt/b\xffad"),
                "the retained bytes are not the bytes that were on the line")

    def test_parsing_is_deterministic(self):
        text = DECL_EQ + DECL_UUID + "garbage\n"
        self.assertEqual(dumped(fstab_parse(text)), dumped(fstab_parse(text)))

    def test_crlf_does_not_leak_a_carriage_return_into_a_field(self):
        record = self.one("/dev/sda1 /data ext4 rw 0 2\r\n")
        self.assertNotIn("\r", dumped(record))


# =============================================================================
# 4. The mountinfo grammar - against the pure parser alone
# =============================================================================

class MountinfoGrammar(unittest.TestCase):
    """The optional-field section is variable-length and terminated by '-'."""

    def one(self, text):
        return sole(mountinfo_parse(text), "mountinfo record from %r" % text)

    def point(self, record):
        return _field(record, MOUNT_POINT_KEYS, "mount point")

    def fstype(self, record):
        return _field(record, FSTYPE_KEYS, "filesystem type")

    def source(self, record):
        return _field(record, MOUNT_SOURCE_KEYS, "mount source")

    def test_a_normal_entry_carries_the_kernels_own_identity(self):
        record = self.one(ACT_EQ)
        self.assertEqual(str(_field(record, MOUNT_ID_KEYS, "mount id")), "21")
        self.assertEqual(str(_field(record, PARENT_ID_KEYS, "parent id")), "20")

    def test_a_normal_entry_keeps_the_major_minor_device(self):
        self.assertIn("8:1", str(_field(self.one(ACT_EQ), DEVICE_KEYS, "major:minor")))

    def test_a_normal_entry_keeps_the_root_field(self):
        # Section 1: without the root field a subvolume or bind mount is
        # indistinguishable from a whole-filesystem mount.
        self.assertEqual(_field(self.one(ACT_EQ), MOUNT_ROOT_KEYS, "mount root"), "/")

    def test_a_normal_entry_keeps_point_type_and_source(self):
        record = self.one(ACT_EQ)
        self.assertEqual(self.point(record), "/data")
        self.assertEqual(self.fstype(record), "ext4")
        self.assertEqual(self.source(record), "/dev/sda1")

    def test_zero_optional_fields_parse(self):
        record = self.one(ACT_NO_OPTIONAL)
        self.assertEqual(self.point(record), "/srv")
        self.assertEqual(self.fstype(record), "ext4")
        self.assertEqual(self.source(record), "/dev/sda2")

    def test_several_optional_fields_parse(self):
        record = self.one(ACT_MANY_OPTIONAL)
        self.assertEqual(self.point(record), "/opt")
        self.assertEqual(self.fstype(record), "ext4",
                         "a fixed field index cannot survive four optional fields")
        self.assertEqual(self.source(record), "/dev/sda3")

    def test_an_unknown_optional_field_does_not_destroy_the_record(self):
        # The optional section is open-ended by design; a tag this build has never seen
        # is not a reason to deny that the mount exists.
        record = self.one(ACT_UNKNOWN_OPTIONAL)
        self.assertEqual(self.point(record), "/home")
        self.assertEqual(self.fstype(record), "ext4")

    def test_an_unknown_optional_field_is_retained_as_evidence(self):
        self.assertIn("frobnicate", dumped(self.one(ACT_UNKNOWN_OPTIONAL)))

    def test_a_mount_source_of_a_single_dash_is_not_a_separator(self):
        # The separator is the field that is exactly '-' BEFORE the fstype. A split on
        # " - " finds the wrong one here and mangles every field after it.
        record = self.one(ACT_DASH_SOURCE)
        self.assertEqual(self.point(record), "/ephemeral")
        self.assertEqual(self.fstype(record), "tmpfs")
        self.assertEqual(self.source(record), "-")

    def test_a_bind_or_subvolume_root_is_kept(self):
        record = self.one(ACT_BIND)
        self.assertEqual(_field(record, MOUNT_ROOT_KEYS, "mount root"), "/srv/shared")
        self.assertEqual(self.point(record), "/export")

    def test_an_escaped_mount_point_does_not_split_a_field(self):
        record = self.one(ACT_ESCAPED)
        self.assertEqual(self.fstype(record), "ext4")
        self.assertIn("my", str(self.point(record)))

    def test_a_stacked_target_yields_two_records(self):
        records = mountinfo_parse(ACT_STACK_AUTOFS + ACT_STACK_REAL)
        self.assertEqual(len(records), 2)
        self.assertEqual(len({str(_field(r, MOUNT_ID_KEYS, "mount id"))
                              for r in records}), 2)
        self.assertEqual({self.fstype(r) for r in records}, {"autofs", "binfmt_misc"})

    def test_mountinfo_order_is_preserved(self):
        records = mountinfo_parse(ACT_EQ + ACT_TMP)
        self.assertEqual([self.point(r) for r in records], ["/data", "/tmp"])

    def test_a_malformed_line_is_not_silently_dropped(self):
        # Dropping a mountinfo line denies that an active mount exists. Either the
        # record is retained with a parse status or the loss is recorded; nothing
        # vanishes.
        text = "30 20 8:6\n" + ACT_EQ
        records = mountinfo_parse(text)
        blob = dumped(records)
        self.assertTrue(len(records) == 2 or "30" in blob,
                        "the malformed line left no trace: %r" % blob)
        self.assertTrue(any(self.point(r) == "/data" for r in records
                            if _has_field(r, MOUNT_POINT_KEYS)))

    def test_a_truncated_final_line_is_not_completed_by_guessing(self):
        records = mountinfo_parse(ACT_EQ + "32 20 8:7 / /var rw - ext4")
        self.assertTrue(any(_has_field(r, MOUNT_POINT_KEYS)
                            and self.point(r) == "/data" for r in records),
                        "the complete line before the truncated one was lost")
        for record in records:
            if not _has_field(record, MOUNT_POINT_KEYS):
                continue
            if str(self.point(record)) != "/var":
                continue
            if _has_field(record, MOUNT_SOURCE_KEYS):
                self.assertNotEqual(self.source(record), "ext4",
                                    "the fstype was promoted into the mount source to "
                                    "fill a field the kernel line does not carry")

    def test_parsing_is_deterministic(self):
        text = ACT_EQ + ACT_MANY_OPTIONAL + ACT_DASH_SOURCE
        self.assertEqual(dumped(mountinfo_parse(text)), dumped(mountinfo_parse(text)))

    def test_an_empty_mountinfo_produces_no_records(self):
        self.assertEqual(mountinfo_parse(""), [])


# =============================================================================
# 5. Ruling E and ruling F - where the active evidence comes from
# =============================================================================

class Rooting(Fixture):
    """The source space is frozen, and the fixture root never reaches the live /proc."""

    TOKEN_TARGET = "/mnt/fixture-only-target"
    FIXTURE_MOUNTINFO = (
        "51 50 9:1 / %s rw - ext4 /dev/fixture1 rw\n"
        "52 50 9:2 / /mnt/fixture-second rw - ext4 /dev/fixture2 rw\n" % TOKEN_TARGET)

    def test_the_active_source_under_a_fixture_root_is_beneath_it(self):
        self.assertEqual(rooted_path("mountinfo", "/fixture"),
                         os.path.join("/fixture", MOUNTINFO_PATH))

    def test_the_active_source_at_the_production_root_has_no_doubled_separator(self):
        # Ruling F, the authorizedkeys defect in its pure form: the root and the
        # separator degenerate at "/" and the resulting path names nothing.
        self.assertEqual(rooted_path("mountinfo", "/"), LIVE_MOUNTINFO)

    def test_the_declared_source_at_the_production_root_is_etc_fstab(self):
        self.assertEqual(rooted_path("fstab", "/"), LIVE_FSTAB)

    def test_the_declared_source_under_a_fixture_root_is_beneath_it(self):
        self.assertEqual(rooted_path("fstab", "/fixture"),
                         os.path.join("/fixture", FSTAB_PATH))

    def test_a_fixture_root_reads_the_fixtures_mounts_and_only_those(self):
        evidence = self.host(fstab="", mountinfo=self.FIXTURE_MOUNTINFO)
        records = active_records(evidence)
        self.assertEqual(len(records), 2,
                         "the fixture declares two active mounts; %d were collected, so "
                         "evidence from somewhere else entered the lane"
                         % len(records))
        self.assertIn(self.TOKEN_TARGET, dumped(evidence))

    def test_a_fixture_root_without_proc_falls_back_to_nothing(self):
        # Ruling E: never a fallback to the live /proc. A fixture that describes a host
        # with no /proc must not describe THIS machine's mounts instead.
        evidence = self.host(fstab=DECL_EQ, mountinfo=None)
        self.assertEqual(active_records(evidence), [],
                         "an absent fixture /proc produced active mount records")

    def test_a_fixture_root_never_names_the_live_mountinfo_as_its_source(self):
        evidence = self.host(fstab=DECL_EQ, mountinfo=None)
        self.assertNotIn(LIVE_MOUNTINFO, source_paths(evidence),
                         "a collection rooted at %r names the live %s as an evidence "
                         "source" % (self.root, LIVE_MOUNTINFO))

    def test_the_fixture_active_source_path_is_inside_the_collection_root(self):
        evidence = self.host(mountinfo=self.FIXTURE_MOUNTINFO)
        named = [p for p in source_paths(evidence) if p.endswith(MOUNTINFO_PATH)]
        self.assertTrue(named, "the evidence never names the active source it read")
        for path in named:
            self.assertTrue(hostpath.contains(self.root, path),
                            "%r is outside the collection root %r" % (path, self.root))

    def test_fixture_evidence_is_not_labelled_the_current_namespace(self):
        # Section 1: a synthetic mountinfo under a corpus root describes whatever
        # produced it, not the namespace of the process executing ISEDRAF.
        evidence = self.host(mountinfo=self.FIXTURE_MOUNTINFO)
        blob = dumped(evidence)
        self.assertIn("FIXTURE_OR_OFFLINE_EVIDENCE", blob,
                      "a non-root collection root must carry the fixture scope")
        self.assertNotIn("LIVE_CURRENT_COLLECTION_NAMESPACE", blob,
                         "fixture evidence is labelled as the live namespace of this "
                         "process")

    def test_an_incomplete_active_side_is_not_reported_as_the_whole_namespace(self):
        evidence = self.host(fstab=DECL_EQ, mountinfo=None)
        self.assertNotEqual(comparison_provenance(evidence)["active_status"],
                            result.COLLECTED)


class ProductionRoot(unittest.TestCase):
    """Ruling F. The root production uses, exercised, because nobody did last time.

    Reads are read-only and the assertions are structural: this machine's disk layout is
    never asserted, and no fixture can stand in for "/" because no fixture root can BE
    "/".
    """

    def setUp(self):
        self.evidence = collect("/")

    def test_the_production_root_collects_active_mounts(self):
        if not live_mountinfo_readable():
            self.assertNotEqual(comparison_provenance(self.evidence)["active_status"],
                                result.COLLECTED)
            return
        self.assertTrue(
            active_records(self.evidence),
            "collect('/') produced no active mount records on a running Linux host. "
            "This is the authorized_keys defect exactly: at the only root production "
            "uses, the lane read nothing.")

    def test_the_production_root_names_the_live_mountinfo_exactly(self):
        named = [p for p in source_paths(self.evidence)
                 if p.endswith("self/mountinfo")]
        self.assertTrue(named, "collect('/') never names /proc/self/mountinfo")
        for path in named:
            self.assertEqual(path, LIVE_MOUNTINFO,
                             "a doubled root produced %r" % path)

    def test_the_production_root_names_etc_fstab_exactly(self):
        named = [p for p in source_paths(self.evidence) if p.endswith("/fstab")]
        self.assertTrue(named, "collect('/') never names the declared source")
        for path in named:
            self.assertEqual(path, LIVE_FSTAB, "a doubled root produced %r" % path)

    def test_the_production_root_carries_the_live_namespace_scope(self):
        blob = dumped(self.evidence)
        self.assertIn("LIVE_CURRENT_COLLECTION_NAMESPACE", blob)
        self.assertNotIn("FIXTURE_OR_OFFLINE_EVIDENCE", blob)

    def test_the_active_evidence_is_scoped_to_the_collection_namespace(self):
        self.assertIn("ACTIVE_MOUNTS_CURRENT_COLLECTION_NAMESPACE",
                      dumped(self.evidence),
                      "the active side must be labelled as the collector's current "
                      "namespace, never as the host's mounts")

    def test_the_production_root_does_not_claim_to_see_every_host_mount(self):
        blob = dumped(self.evidence).lower()
        for phrase in ("host active mounts", "all mounts on the host",
                       "every mount on the host", "all host mounts"):
            self.assertNotIn(phrase, blob, phrase)

    def test_the_namespace_identity_it_observed_is_recorded(self):
        if not os.path.exists("/proc/self/ns/mnt"):
            self.skipTest("this kernel exposes no mount-namespace identity")
        blob = dumped(self.evidence)
        self.assertTrue("mnt:[" in blob or "ns/mnt" in blob,
                        "section 1 requires the evidence to carry the namespace "
                        "identity it observed")


# =============================================================================
# 6. Ruling D - source status and universe completeness are separate questions
# =============================================================================

class FstabUniverse(Fixture):
    """Absent, refused, partial. Three rows, three different absence permissions."""

    ACTIVE_UNDECLARED = ACT_TMP

    def test_an_absent_fstab_is_not_an_error(self):
        evidence = self.host(fstab=None, mountinfo=ACT_EQ)
        entry = sole(coverage_for(evidence, "fstab"), "fstab coverage entry")
        self.assertEqual(entry["access_outcome"], coverage_module.NOT_FOUND)
        self.assertEqual(entry["status"], result.NOT_TESTED)

    def test_an_absent_fstab_contributes_no_declarations(self):
        evidence = self.host(fstab=None, mountinfo=ACT_EQ)
        self.assertEqual(declared_records(evidence), [])
        # A lane that collected nothing at all also declares nothing. The active side
        # must be present, or this asserts silence rather than an absent fstab.
        self.assertTrue(active_records(evidence),
                        "the whole collection is empty, so the absent fstab is not "
                        "what this test measured")

    def test_an_absent_fstab_bounds_its_universe_completely(self):
        # Ruling D, the table row itself: an absent file fully establishes that THIS
        # SOURCE contributes zero declarations, so the universe it bounds is completely
        # known even though the source status is NOT_TESTED.
        evidence = self.host(fstab=None, mountinfo=ACT_EQ)
        entry = sole(coverage_for(evidence, "fstab"), "fstab coverage entry")
        self.assertEqual(entry["source_universe"], coverage_module.UNIVERSE_COMPLETE,
                         "an absent /etc/fstab was recorded as an incomplete universe, "
                         "which forbids the ACTIVE_ONLY that ruling D permits")

    def test_an_absent_fstab_needs_no_additional_access(self):
        evidence = self.host(fstab=None, mountinfo=ACT_EQ)
        entry = sole(coverage_for(evidence, "fstab"), "fstab coverage entry")
        self.assertFalse(entry["privilege_limited"])
        self.assertEqual(entry["required_access"], coverage_module.ACCESS_NONE)

    def test_an_absent_fstab_leaves_the_declared_universe_complete(self):
        # Ruling D. An absent file fully establishes that THIS SOURCE contributes zero
        # declarations, so the universe it bounds is completely known - and the
        # observable consequence is the only one that matters: ACTIVE_ONLY becomes
        # assertable.
        evidence = self.host(fstab=None, mountinfo=self.ACTIVE_UNDECLARED)
        # PORTED for IQ-020. This asserted declared_status == COLLECTED, which is the
        # conflation the owner ruled out: an absent file has source status NOT_TESTED
        # and a COMPLETE universe, and demanding COLLECTED here would force the two
        # axes back into one field. The property the test is about is the universe.
        provenance = comparison_provenance(evidence)
        self.assertTrue(provenance["declared_universe_complete"],
                        "the declared universe is not complete, so no active mount "
                        "can ever be shown to be undeclared")
        self.assertNotEqual(provenance["declared_status"], result.COLLECTED,
                            "an fstab that was never read is reported as collected; "
                            "a complete universe is not a successful read")
        self.assertEqual(relationships(evidence, "/tmp"), [compare.ACTIVE_ONLY])

    def test_an_absent_fstab_is_not_reported_as_a_wider_universe(self):
        # The universe is FSTAB DECLARATIONS and nothing wider: it does not establish
        # that there are no systemd mount units, no generator output and no transient
        # mounts.
        evidence = self.host(fstab=None, mountinfo=self.ACTIVE_UNDECLARED)
        blob = dumped(evidence)
        self.assertRegex(blob.upper(), r"FSTAB",
                         "the declared universe must name fstab, so a reader knows what "
                         "'only' means")
        lowered = blob.lower()
        self.assertTrue(
            any(word in lowered for word in ("unit", "generator", "transient")),
            "nothing in the evidence records that mount units, generator output and "
            "transient mounts are outside this universe, so ACTIVE_ONLY reads as "
            "'nothing declares this anywhere'")

    def test_a_refused_fstab_forbids_the_same_absence_claim(self):
        if running_as_root():
            self.skipTest("mode 0 does not refuse uid 0; this case needs a non-root "
                          "collection identity")
        evidence = self.host(fstab=DECL_OTHER_TARGET, mountinfo=self.ACTIVE_UNDECLARED,
                             fstab_mode=0)
        self.assertNotIn(compare.ACTIVE_ONLY, relationships(evidence),
                         "an unreadable declared source cannot prove any active mount "
                         "is undeclared")
        self.assertEqual(relationships(evidence, "/tmp"),
                         [compare.COUNTERPART_UNKNOWN])

    def test_a_refused_fstab_is_a_privilege_limitation(self):
        if running_as_root():
            self.skipTest("mode 0 does not refuse uid 0")
        evidence = self.host(fstab=DECL_EQ, mountinfo=ACT_EQ, fstab_mode=0)
        entry = sole(coverage_for(evidence, "fstab"), "fstab coverage entry")
        self.assertEqual(entry["access_outcome"], coverage_module.PERMISSION_DENIED)
        self.assertEqual(entry["required_access"], coverage_module.ACCESS_FILE_READ)
        self.assertTrue(entry["privilege_limited"])
        self.assertEqual(entry["source_universe"], coverage_module.UNIVERSE_INCOMPLETE)

    def test_a_refused_fstab_is_not_reported_as_absent(self):
        if running_as_root():
            self.skipTest("mode 0 does not refuse uid 0")
        evidence = self.host(fstab=DECL_EQ, mountinfo=ACT_EQ, fstab_mode=0)
        entry = sole(coverage_for(evidence, "fstab"), "fstab coverage entry")
        self.assertNotEqual(entry["access_outcome"], coverage_module.NOT_FOUND)
        self.assertEqual(declared_records(evidence), [])

    def test_a_partial_fstab_keeps_the_lines_that_parsed(self):
        evidence = self.host(fstab="garbage\n" + DECL_EQ, mountinfo=ACT_EQ)
        self.assertEqual(len(declared_records(evidence)), 2)

    def test_a_partial_fstab_makes_the_declared_side_incomplete(self):
        evidence = self.host(fstab="garbage\n" + DECL_OTHER_TARGET,
                             mountinfo=self.ACTIVE_UNDECLARED)
        self.assertEqual(comparison_provenance(evidence)["declared_status"],
                         result.PARTIAL)

    def test_a_partial_fstab_forbids_the_absence_claim(self):
        evidence = self.host(fstab="garbage\n" + DECL_OTHER_TARGET,
                             mountinfo=self.ACTIVE_UNDECLARED)
        self.assertEqual(relationships(evidence, "/tmp"),
                         [compare.COUNTERPART_UNKNOWN])
        self.assertNotIn(compare.ACTIVE_ONLY, relationships(evidence))

    def test_a_partial_fstab_marks_its_universe_incomplete(self):
        evidence = self.host(fstab="garbage\n" + DECL_EQ, mountinfo=ACT_EQ)
        entry = sole(coverage_for(evidence, "fstab"), "fstab coverage entry")
        self.assertEqual(entry["source_universe"], coverage_module.UNIVERSE_INCOMPLETE)

    def test_an_empty_fstab_is_a_complete_universe_with_no_declarations(self):
        evidence = self.host(fstab="", mountinfo=self.ACTIVE_UNDECLARED)
        self.assertEqual(declared_records(evidence), [])
        self.assertEqual(relationships(evidence, "/tmp"), [compare.ACTIVE_ONLY])

    def test_a_comment_only_fstab_is_a_complete_universe(self):
        evidence = self.host(fstab="# nothing declared here\n",
                             mountinfo=self.ACTIVE_UNDECLARED)
        self.assertEqual(relationships(evidence, "/tmp"), [compare.ACTIVE_ONLY])

    def test_no_second_declared_source_is_invented(self):
        # Section 2: /etc/fstab only. Linux has no fstab.d.
        evidence = self.host(fstab=DECL_EQ, mountinfo=ACT_EQ)
        self.assertNotIn("fstab.d", dumped(evidence))


# =============================================================================
# 7. S3, through the lane's own adapter
# =============================================================================

class Adapter(unittest.TestCase):
    """Identity, ordering and the tri-state verdict, as the contract states them."""

    def test_the_candidate_key_is_the_normalized_target(self):
        declared = sole(fstab_parse(DECL_EQ), "declared record")
        active = sole(mountinfo_parse(ACT_EQ), "active record")
        self.assertEqual(comparator().identity(declared),
                         comparator().identity(active))

    def test_a_trailing_slash_is_lexically_normalized(self):
        declared = sole(fstab_parse("/dev/sda1 /data/ ext4 rw 0 2\n"), "declared")
        active = sole(mountinfo_parse(ACT_EQ), "active")
        self.assertEqual(comparator().identity(declared),
                         comparator().identity(active))

    def test_the_root_target_keeps_its_slash(self):
        declared = sole(fstab_parse("/dev/sda1 / ext4 rw 0 1\n"), "declared")
        active = sole(mountinfo_parse("21 20 8:1 / / rw - ext4 /dev/sda1 rw\n"),
                      "active")
        self.assertEqual(comparator().identity(declared),
                         comparator().identity(active))
        self.assertIn("/", str(comparator().identity(declared)))

    def test_different_targets_are_different_identities(self):
        declared = sole(fstab_parse(DECL_OTHER_TARGET), "declared")
        active = sole(mountinfo_parse(ACT_EQ), "active")
        self.assertNotEqual(comparator().identity(declared),
                            comparator().identity(active))

    def test_a_sibling_prefix_is_not_the_same_target(self):
        declared = sole(fstab_parse("/dev/sda1 /data-evil ext4 rw 0 2\n"), "declared")
        active = sole(mountinfo_parse(ACT_EQ), "active")
        self.assertNotEqual(comparator().identity(declared),
                            comparator().identity(active))

    def test_mounts_are_not_order_sensitive(self):
        # Section 9: reordering two unrelated fstab lines does not change the declared
        # configuration.
        self.assertFalse(comparator().order_sensitive)

    def test_the_pairing_contract_is_declared_in_the_digest(self):
        identity = comparator().semantic_identity()
        self.assertIn("pairing_contract", identity["semantics"])
        self.assertIn("equivalence_contract", identity["semantics"])


class Verdicts(unittest.TestCase):
    """The tri-state rule of section 7, and ruling C on both of its sides."""

    def only(self, declared_text, active_text):
        evidence = compare_sides(declared_text, active_text)
        return sole([i["relationship"] for i in evidence.records], "relationship")

    def test_every_dimension_literally_equal_is_equivalent(self):
        # MATCHED is reachable IN PRINCIPLE, and this is the case that makes it so:
        # same target, same fstype, the same literal device path on both sides, and an
        # option text that is character-identical. Nothing here needs a resolution
        # source, an option-semantics engine or a normalizer.
        self.assertEqual(self.only(DECL_EQ, ACT_EQ), compare.MATCHED)

    def test_a_contradicting_device_path_is_different(self):
        self.assertEqual(self.only(DECL_EQ, ACT_OTHER_SOURCE), compare.MODIFIED)

    def test_a_contradicting_fstype_is_different(self):
        self.assertEqual(self.only(DECL_XFS, ACT_EQ), compare.MODIFIED)

    def test_a_uuid_against_a_device_path_is_undecidable(self):
        # The ordinary-host row. It is the CORRECT outcome, not a shortfall.
        self.assertEqual(self.only(DECL_UUID, ACT_EQ), compare.EQUIVALENCE_UNKNOWN)

    def test_a_label_against_a_device_path_is_undecidable(self):
        self.assertEqual(self.only("%s /data ext4 rw 0 2\n" % LABEL_A, ACT_EQ),
                         compare.EQUIVALENCE_UNKNOWN)

    def test_declared_options_inside_the_active_set_are_not_equivalence(self):
        # RULING C. `declared options subset of active option strings -> EQUIVALENT` is
        # rejected. Here the declared set is a strict subset of the active one and
        # every other dimension is identical, so a subset rule - or a lane that simply
        # declines to look at options at all - answers MATCHED.
        self.assertEqual(self.only(DECL_SUPERSET, ACT_SUPERSET),
                         compare.EQUIVALENCE_UNKNOWN)

    def test_a_declaration_only_option_is_not_a_mismatch(self):
        # The mirror of ruling C, and the one that hurts on a normal host: noauto and
        # nofail never appear in the kernel's option set, so a subset rule reports a
        # confident MODIFIED about a host where nothing is wrong.
        self.assertEqual(self.only(DECL_NOAUTO, ACT_EQ), compare.EQUIVALENCE_UNKNOWN)

    def test_defaults_is_not_expanded(self):
        # `defaults` expands to a filesystem-dependent set and never appears literally.
        self.assertEqual(self.only(DECL_DEFAULTS, ACT_EQ), compare.EQUIVALENCE_UNKNOWN)

    def test_an_undecidable_pair_is_not_a_missing_counterpart(self):
        evidence = compare_sides(DECL_UUID, ACT_EQ)
        self.assertNotIn(compare.COUNTERPART_UNKNOWN,
                         [i["relationship"] for i in evidence.records])

    def test_an_undecidable_pair_explains_which_uncertainty_it_is(self):
        evidence = compare_sides(DECL_UUID, ACT_EQ)
        reason = sole(evidence.records, "item")["reason"]
        self.assertIn("equivalen", reason.lower())

    def test_the_adapter_returns_only_the_three_contract_verdicts(self):
        declared = sole(fstab_parse(DECL_UUID), "declared")
        active = sole(mountinfo_parse(ACT_EQ), "active")
        self.assertIn(comparator().compare_pair(declared, active),
                      compare.EQUIVALENCE)

    def test_the_adapter_never_returns_a_bool(self):
        declared = sole(fstab_parse(DECL_EQ), "declared")
        active = sole(mountinfo_parse(ACT_EQ), "active")
        self.assertNotIsInstance(comparator().compare_pair(declared, active), bool)

    def test_dump_and_pass_are_not_compared(self):
        # Section 7: fstab-only fields with no active counterpart. Changing one must not
        # change the verdict.
        self.assertEqual(self.only("/dev/sda1 /data ext4 rw 1 1\n", ACT_EQ),
                         self.only(DECL_EQ, ACT_EQ))


class Multiplicity(unittest.TestCase):
    """No deterministic pairing exists under multiplicity, so none is invented."""

    def test_two_by_two_is_ambiguous_for_every_record(self):
        evidence = compare_sides(DECL_EQ + DECL_UUID, ACT_EQ + ACT_XFS)
        self.assertEqual([i["relationship"] for i in evidence.records],
                         [compare.AMBIGUOUS] * 4)

    def test_two_by_one_is_ambiguous_and_never_matched(self):
        evidence = compare_sides(DECL_EQ + DECL_UUID, ACT_EQ)
        relationship_set = {i["relationship"] for i in evidence.records}
        self.assertEqual(relationship_set, {compare.AMBIGUOUS})
        self.assertEqual(len(evidence.records), 3, "a record was consumed by pairing")

    def test_one_by_two_is_ambiguous(self):
        evidence = compare_sides(DECL_EQ, ACT_STACK_AUTOFS.replace(
            "/proc/sys/fs/binfmt_misc", "/data") + ACT_EQ)
        self.assertEqual({i["relationship"] for i in evidence.records},
                         {compare.AMBIGUOUS})

    def test_reordering_the_declared_side_changes_nothing(self):
        first = compare_sides(DECL_EQ + DECL_UUID, ACT_EQ)
        second = compare_sides(DECL_UUID + DECL_EQ, ACT_EQ)
        self.assertEqual(sorted(i["relationship"] for i in first.records),
                         sorted(i["relationship"] for i in second.records))

    def test_reordering_the_active_side_changes_nothing(self):
        first = compare_sides(DECL_EQ, ACT_EQ + ACT_XFS)
        second = compare_sides(DECL_EQ, ACT_XFS + ACT_EQ)
        self.assertEqual(sorted(i["relationship"] for i in first.records),
                         sorted(i["relationship"] for i in second.records))

    def test_ambiguity_does_not_degrade_acquisition_coverage(self):
        # The three frozen axes: two files acquired perfectly whose records cannot be
        # paired are COMPLETE acquisition evidence about an ambiguous situation.
        evidence = compare_sides(DECL_EQ + DECL_UUID, ACT_EQ + ACT_XFS)
        # PORTED for CQ-3: S3's scalar is comparison_input_coverage; "coverage" is the
        # R1.5-P list. That collision is what this suite exists to catch.
        self.assertEqual(evidence.provenance["comparison_input_coverage"],
                         compare.COMPLETE)
        self.assertEqual(evidence.provenance["pairing"], compare.AMBIGUOUS_PAIRING)

    def test_undecidability_does_not_degrade_acquisition_coverage(self):
        evidence = compare_sides(DECL_UUID, ACT_EQ)
        # PORTED for CQ-3: S3's scalar is comparison_input_coverage; "coverage" is the
        # R1.5-P list. That collision is what this suite exists to catch.
        self.assertEqual(evidence.provenance["comparison_input_coverage"],
                         compare.COMPLETE)
        self.assertEqual(evidence.provenance["comparability"],
                         compare.PARTIALLY_COMPARABLE)

    def test_an_incomplete_counterpart_is_counterpart_unknown(self):
        # Both axes named, because post-IQ-020 they are two facts: the read was
        # partial AND the universe it bounds is therefore not complete.
        evidence = compare_sides(DECL_EQ, ACT_TMP, active_status=result.PARTIAL,
                                 active_universe_complete=False)
        self.assertEqual(relationships(evidence, "/data"),
                         [compare.COUNTERPART_UNKNOWN])
        # ... and the status alone must not produce it, or the axes are still one.
        complete = compare_sides(DECL_EQ, ACT_TMP, active_status=result.PARTIAL)
        self.assertEqual(relationships(complete, "/data"),
                         [compare.DECLARED_ONLY])

    def test_a_complete_declared_side_still_proves_active_only(self):
        evidence = compare_sides(DECL_EQ, ACT_EQ + ACT_TMP)
        self.assertEqual(relationships(evidence, "/tmp"), [compare.ACTIVE_ONLY])

    def test_the_stacked_target_is_ambiguous_against_one_declaration(self):
        declared = "/dev/sda1 /proc/sys/fs/binfmt_misc autofs rw 0 0\n"
        evidence = compare_sides(declared, ACT_STACK_AUTOFS + ACT_STACK_REAL)
        self.assertEqual({i["relationship"] for i in evidence.records},
                         {compare.AMBIGUOUS})
        self.assertEqual(len(evidence.records), 3)


class MultiplicityThroughTheLane(Fixture):
    """Every record reaches the comparison; none is collapsed on the way."""

    def test_three_declarations_for_one_target_all_survive(self):
        text = (DECL_EQ + "%s /data ext4 ro 0 2\n" % UUID_A
                + "%s /data ext4 rw 0 2\n" % UUID_B)
        evidence = self.host(fstab=text, mountinfo=ACT_EQ)
        self.assertEqual(len(declared_records(evidence)), 3,
                         "a declaration disappeared between the parser and the "
                         "evidence; a dict keyed by target decides by insertion order "
                         "which one survived")

    def test_two_stacked_active_mounts_both_survive(self):
        evidence = self.host(fstab="", mountinfo=ACT_STACK_AUTOFS + ACT_STACK_REAL)
        self.assertEqual(len(active_records(evidence)), 2)

    def test_the_topmost_stacked_mount_is_not_privileged(self):
        evidence = self.host(fstab="", mountinfo=ACT_STACK_AUTOFS + ACT_STACK_REAL)
        blob = dumped(evidence)
        for fstype in ("autofs", "binfmt_misc"):
            self.assertIn(fstype, blob)

    def test_two_declarations_and_one_mount_are_ambiguous_through_the_lane(self):
        """The IQ-019 defect, attacked where a LANE could reintroduce it.

        S3 refuses to pair under multiplicity. A lane that pairs the records itself -
        before the comparator, after it, or instead of it - gets MATCHED back for a
        relationship decided by the order two unrelated sources happened to enumerate
        their lines in, and MATCHED is the most reassuring output this engine has.
        """
        evidence = self.host(fstab=DECL_EQ + DECL_UUID, mountinfo=ACT_EQ)
        found = relationships(evidence)
        self.assertEqual(set(found), {compare.AMBIGUOUS},
                         "the lane produced %r for two declarations against one active "
                         "mount" % (sorted(set(found)),))
        self.assertEqual(len(found), 3, "a record was consumed by pairing")

    def test_reordering_the_fstab_does_not_change_the_lanes_answer(self):
        first = self.host(fstab=DECL_EQ + DECL_UUID, mountinfo=ACT_EQ)
        self.write(FSTAB_PATH, DECL_UUID + DECL_EQ)
        second = collect(self.root)
        self.assertTrue(relationships(first), "no relationships to reorder")
        self.assertEqual(sorted(relationships(first)), sorted(relationships(second)))

    def test_the_comparison_items_are_the_frozen_engines_own(self):
        evidence = self.host(fstab=DECL_EQ, mountinfo=ACT_EQ)
        items = comparison_items(evidence)
        self.assertTrue(items)
        for item in items:
            self.assertIn(item["relationship"], compare.RELATIONSHIPS)
            self.assertIn("absence_assertable", item)

    def test_the_lane_does_not_index_records_by_target(self):
        """An AST attack on the shape that silently discards duplicates.

        `index[record["target"]] = record` is first-wins or last-wins depending on
        nothing but iteration order, and section 6 forbids both. A subscript assignment
        whose VALUE is a fresh list or set is a grouping container and is allowed,
        because that shape keeps every record.
        """
        offenders = []
        for module in lane_modules():
            tree = tree_of(module)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if not isinstance(target, ast.Subscript):
                        continue
                    if isinstance(target.slice, ast.Constant):
                        # record["mount_point"] = ... is a FIELD of one record, not an
                        # index OF records. Only a computed key can collapse a set.
                        continue
                    slice_text = ast.dump(target.slice)
                    if not any(word in slice_text
                               for word in ("target", "mount_point", "identity", "key")):
                        continue
                    value = node.value
                    if isinstance(value, (ast.List, ast.Set, ast.Dict)):
                        continue
                    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) \
                            and value.func.id in ("list", "set", "dict"):
                        continue
                    offenders.append("%s:%d" % (module.__name__, node.lineno))
        self.assertEqual(offenders, [],
                         "a record is stored under its target as a single value at %r; "
                         "duplicate targets are measured reality on a stock "
                         "installation" % (offenders,))


class EscapedTarget(Fixture):
    """Both sources use the SAME escaping, so a lane must not decode one side only.

    fstab(5) and proc(5) both write a space inside a path as an octal escape. Decoding
    the declared side while leaving the active side as the kernel wrote it - or the
    reverse - turns one mount into two records that no longer share a candidate key,
    and the report then says a declared mount is not active AND that an active mount is
    undeclared. Both halves are false, and each is an accusation section 12 forbids.
    """

    DECLARED = "/dev/sda5 /mnt/my\\040dir ext4 rw 0 2\n"

    def test_an_escaped_target_pairs_with_the_kernels_escaped_form(self):
        evidence = self.host(fstab=self.DECLARED, mountinfo=ACT_ESCAPED)
        items = comparison_items(evidence)
        self.assertEqual(
            len(items), 1,
            "one mount point written identically on both sides produced %d comparison "
            "items, so one side was decoded and the other was not: %r"
            % (len(items), [i["identity"] for i in items]))

    def test_an_escaped_target_is_not_reported_as_two_one_sided_records(self):
        found = relationships(self.host(fstab=self.DECLARED, mountinfo=ACT_ESCAPED))
        for relationship in (compare.DECLARED_ONLY, compare.ACTIVE_ONLY):
            self.assertNotIn(relationship, found)

    def test_an_escaped_backslash_target_pairs_too(self):
        evidence = self.host(
            fstab="/dev/sda5 /mnt/back\\134slash ext4 rw 0 2\n",
            mountinfo="33 20 8:5 / /mnt/back\\134slash rw - ext4 /dev/sda5 rw\n")
        self.assertEqual(len(comparison_items(evidence)), 1)


# =============================================================================
# 8. R1.5-P - the acquisition boundary, in fields
# =============================================================================

class Coverage(Fixture):
    """Structured coverage on every acquisition path, and five separate questions."""

    def entries(self, **host):
        """Every coverage entry, and never an empty list unnoticed.

        Measured against a fully inert lane: the "every entry carries X" tests all
        passed, because an empty universe satisfies every universal quantifier. The
        guard is here rather than in each caller so a test added later inherits it.
        """
        found = coverage_entries(self.host(**host))
        self.assertTrue(found,
                        "the collection produced no coverage entries at all, so every "
                        "assertion over them below is vacuously true")
        return found

    def test_the_declared_source_has_a_coverage_entry(self):
        self.assertTrue(coverage_for(self.host(), "fstab"))

    def test_the_active_source_has_a_coverage_entry(self):
        self.assertTrue(coverage_for(self.host(), "mountinfo"))

    def test_every_coverage_entry_carries_the_frozen_axes(self):
        for entry in self.entries():
            for field in ("access_outcome", "required_access", "source_universe",
                          "status", "privilege_limited", "absence_claim_allowed",
                          "affects_completeness", "operation"):
                self.assertIn(field, entry,
                              "coverage entry %r lacks %r" % (entry.get("source"),
                                                              field))

    def test_the_outcomes_are_the_central_vocabulary(self):
        for entry in self.entries():
            self.assertIn(entry["access_outcome"], coverage_module.OUTCOMES)
            self.assertIn(entry["required_access"], coverage_module.ACCESS_REQUIREMENTS)
            self.assertIn(entry["operation"], coverage_module.OPERATIONS)

    def test_the_derived_fields_agree_with_the_central_derivation(self):
        # coverage.py is the single authority. A lane that authored its own copy is a
        # second truth waiting to contradict the first.
        for entry in self.entries():
            self.assertEqual(
                entry["required_access"],
                coverage_module.required_access(entry["operation"],
                                                entry["access_outcome"]))
            self.assertEqual(entry["privilege_limited"],
                             coverage_module.privilege_limited(entry["access_outcome"]))
            self.assertEqual(
                entry["absence_claim_allowed"],
                # PORTED for CQ-1: the owner ruled that absence derives from the
                # UNIVERSE alone. Passing status here was the two-question signature
                # the ruling removed. The oracle - lane field equals central
                # derivation - is unchanged.
                coverage_module.absence_claim_allowed(entry["source_universe"]))

    def test_an_absent_proc_is_not_a_privilege_problem(self):
        entries = coverage_for(self.host(fstab=DECL_EQ, mountinfo=None), "mountinfo")
        self.assertTrue(entries, "an unavailable active source left no structured trace")
        for entry in entries:
            self.assertFalse(entry["privilege_limited"],
                             "an absent /proc was reported as a privilege limitation; "
                             "'root does not mean complete' has a mirror, and this is it")
            self.assertEqual(entry["required_access"], coverage_module.ACCESS_NONE)

    def test_an_unavailable_active_source_is_not_prose_only(self):
        evidence = self.host(fstab=DECL_EQ, mountinfo=None)
        entry = sole(coverage_for(evidence, "mountinfo"), "mountinfo coverage entry")
        self.assertNotEqual(entry["status"], result.COLLECTED)
        self.assertTrue(entry["affects_completeness"])

    def test_the_acquisition_mode_is_the_only_producible_one(self):
        blob = dumped(self.host())
        for forbidden in ("ELEVATED", "PRIVILEGED", "ROOT_MODE"):
            self.assertNotIn(forbidden, blob)
        if "acquisition_mode" in blob:
            for entry in dicts(self.host()):
                if "acquisition_mode" in entry:
                    self.assertIn(entry["acquisition_mode"], coverage_module.MODES)

    def test_a_complete_fixture_read_is_not_a_privilege_limitation(self):
        for entry in self.entries(fstab=DECL_EQ, mountinfo=ACT_EQ):
            self.assertFalse(entry["privilege_limited"],
                             "%r was read successfully and is still reported as "
                             "privilege limited" % entry.get("source"))

    def test_the_namespace_boundary_is_not_a_privilege_limitation(self):
        """Section 1 and section 11, and the sentence this lane must never write.

        The collector cannot read /proc/1/ns/mnt unprivileged, so it cannot prove it
        shares pid 1's namespace. That is an OBSERVATION BOUNDARY recorded as coverage
        context. It is NOT a claim that additional authority would reveal every mount on
        the host - no privilege makes a process see another namespace's mounts - and a
        lane that files it under required_access sends an operator to grant access that
        changes nothing.
        """
        evidence = self.host(fstab=DECL_EQ, mountinfo=ACT_EQ)
        for entry in coverage_entries(evidence):
            if "ns/mnt" in str(entry.get("source", "")) or "namespace" in str(
                    entry.get("source", "")).lower():
                self.assertEqual(entry["required_access"], coverage_module.ACCESS_NONE)
                self.assertFalse(entry["privilege_limited"])
        # PORTED. The regex below cannot read a negation, and the sentence the lane is
        # REQUIRED to write - the one denying that privilege would help - is itself a
        # privilege word near "namespace". Left as written, this oracle forbade stating
        # the very invariant it protects. The exemption is exactly one sentence, quoted
        # in full, and the test first proves that sentence is present: delete the denial
        # and this fails, reword it and this fails, and every OTHER pairing of privilege
        # with namespace anywhere in the evidence still fails.
        DENIAL = ("an evidence boundary, not a privilege limitation: no acquisition "
                  "method here establishes that additional authority would reveal "
                  "other namespaces.")
        blob = dumped(evidence).lower()
        self.assertIn(DENIAL, blob,
                      "the evidence does not state that the namespace boundary is not "
                      "a privilege limitation, so an operator reading it has no reason "
                      "to believe access would not widen it")
        blob = blob.replace(DENIAL, " ")
        for pattern in (r"(root|privileg\w*|authority)[^.\"]{0,60}namespace",
                        r"namespace[^.\"]{0,60}(root|privileg\w*|additional authority)"):
            self.assertIsNone(
                re.search(pattern, blob),
                "the evidence connects the namespace boundary to privilege: %r"
                % (re.search(pattern, blob).group(0)
                   if re.search(pattern, blob) else ""))

    def test_an_unknown_optional_field_is_not_an_acquisition_gap(self):
        # The optional section of a mountinfo line is open-ended by design. A tag this
        # build has never seen is not a hole in what was read, and reporting it as one
        # would forbid every absence claim on a host that mounted something new.
        evidence = self.host(fstab="", mountinfo=ACT_UNKNOWN_OPTIONAL)
        self.assertEqual(comparison_provenance(evidence)["active_status"],
                         result.COLLECTED)
        entry = sole(coverage_for(evidence, "mountinfo"), "mountinfo coverage entry")
        self.assertEqual(entry["source_universe"], coverage_module.UNIVERSE_COMPLETE)

    def test_the_five_questions_stay_separate(self):
        # access outcome / access requirement / acquisition mode / evidence
        # completeness / namespace scope. A single collapsed field cannot answer them.
        entry = sole(coverage_for(self.host(), "mountinfo"), "mountinfo entry")
        self.assertNotEqual(entry["access_outcome"], entry["required_access"])
        self.assertIn(entry["source_universe"],
                      (coverage_module.UNIVERSE_COMPLETE,
                       coverage_module.UNIVERSE_INCOMPLETE,
                       coverage_module.UNIVERSE_NOT_APPLICABLE))
        self.assertNotIn(entry["source_universe"], coverage_module.OUTCOMES)

    def test_the_comparison_axis_and_the_acquisition_list_both_survive(self):
        """Two frozen conventions, one provenance key.

        compare.compare() writes provenance['coverage'] = COMPLETE|PARTIAL. Every
        R1.5-P producer writes provenance['coverage'] = [source entries]. Both are
        required of this lane, and a dict.update() of one over the other destroys the
        axis a reader needs in order to tell "we could not obtain the evidence" from
        "we obtained it and could not judge it".
        """
        evidence = self.host()
        self.assertIn(s3_coverage(evidence), S3_COVERAGE_VALUES)
        self.assertTrue(coverage_entries(evidence))
        provenance = comparison_provenance(evidence)
        self.assertIn("comparability", provenance)
        self.assertIn("pairing", provenance)

    def test_the_namespace_boundary_does_not_make_the_read_incomplete(self):
        # Section 1: completeness is COMPLETE over the STATED universe.
        entry = sole(coverage_for(self.host(), "mountinfo"), "mountinfo entry")
        self.assertEqual(entry["status"], result.COLLECTED)
        self.assertEqual(entry["source_universe"], coverage_module.UNIVERSE_COMPLETE)


# =============================================================================
# 9. Root containment. The bait lives in a SIBLING of the collection root.
# =============================================================================

class RootContainment(Fixture):
    """Hermetic: the attack is observable without this machine being involved.

    The live /etc/fstab is never read to prove any of it - a containment test that
    consulted the real host would itself be the defect it is looking for.
    """

    BAIT_TARGET = "/mnt/bait-outside-the-collection-root"
    BAIT_FSTAB = "/dev/baitdisk %s ext4 rw 0 0\n" % BAIT_TARGET
    BAIT_MOUNTINFO = ("99 1 7:7 / %s rw - ext4 /dev/baitdisk rw\n" % BAIT_TARGET)

    def bait(self, name, text):
        path = os.path.join(self.outside, name)
        with open(path, "w") as handle:
            handle.write(text)
        return path

    def assert_no_bait(self, evidence, what):
        blob = dumped(evidence)
        for marker in (self.BAIT_TARGET, "/dev/baitdisk", "baitdisk"):
            self.assertNotIn(marker, blob,
                             "%s read outside the collection root (%r leaked)"
                             % (what, marker))

    def test_a_symlinked_fstab_pointing_outside_is_not_read(self):
        self.bait("fstab", self.BAIT_FSTAB)
        os.symlink(os.path.join(self.outside, "fstab"),
                   os.path.join(self.root, FSTAB_PATH))
        self.write(MOUNTINFO_PATH, ACT_EQ)
        self.assert_no_bait(collect(self.root), "a symlinked /etc/fstab")

    def test_a_symlinked_mountinfo_pointing_outside_is_not_read(self):
        self.bait("mountinfo", self.BAIT_MOUNTINFO)
        os.symlink(os.path.join(self.outside, "mountinfo"),
                   os.path.join(self.root, MOUNTINFO_PATH))
        self.write(FSTAB_PATH, DECL_EQ)
        self.assert_no_bait(collect(self.root), "a symlinked mountinfo")

    def test_a_symlinked_etc_pointing_outside_is_not_read(self):
        os.makedirs(os.path.join(self.outside, "etc"))
        self.bait(os.path.join("etc", "fstab"), self.BAIT_FSTAB)
        shutil.rmtree(os.path.join(self.root, "etc"))
        os.symlink(os.path.join(self.outside, "etc"), os.path.join(self.root, "etc"))
        self.write(MOUNTINFO_PATH, ACT_EQ)
        self.assert_no_bait(collect(self.root), "a symlinked /etc")

    def test_a_symlinked_fstab_is_not_reported_as_an_absent_one(self):
        # Ruling D's trap: a source that was refused or redirected out of the root is
        # NOT absent, so it may not licence an absence claim. FILE_OUTSIDE_COLLECTION_ROOT
        # is an observation, never an absence.
        self.bait("fstab", self.BAIT_FSTAB)
        os.symlink(os.path.join(self.outside, "fstab"),
                   os.path.join(self.root, FSTAB_PATH))
        self.write(MOUNTINFO_PATH, ACT_TMP)
        evidence = collect(self.root)
        self.assertNotIn(compare.ACTIVE_ONLY, relationships(evidence),
                         "a declared source that was redirected outside the collection "
                         "root was treated as a complete universe of zero declarations")

    def test_no_path_outside_the_root_appears_in_the_evidence(self):
        self.write(FSTAB_PATH, DECL_EQ)
        self.write(MOUNTINFO_PATH, ACT_EQ)
        evidence = collect(self.root)
        for path in absolute_paths(evidence):
            if path.startswith(self.enclosure):
                self.assertTrue(hostpath.contains(self.root, path),
                                "%r is outside the collection root" % path)

    def test_a_sibling_whose_name_extends_the_root_is_not_inside_it(self):
        sibling = self.root + "-evil"
        os.makedirs(os.path.join(sibling, "etc"))
        self.assertFalse(hostpath.contains(self.root, sibling))
        self.write(FSTAB_PATH, DECL_EQ)
        self.write(MOUNTINFO_PATH, ACT_EQ)
        with open(os.path.join(sibling, "etc", "fstab"), "w") as handle:
            handle.write(self.BAIT_FSTAB)
        self.assert_no_bait(collect(self.root), "a sibling root")

    def test_the_collection_root_itself_is_never_escaped_by_dotdot(self):
        self.write(FSTAB_PATH, "/dev/sda1 /data/../../outside ext4 rw 0 2\n")
        self.write(MOUNTINFO_PATH, ACT_EQ)
        evidence = collect(self.root)
        for path in absolute_paths(evidence):
            if path.startswith(self.enclosure):
                self.assertTrue(hostpath.contains(self.root, path), path)


# =============================================================================
# 10. What the lane never says
# =============================================================================

class NonClaims(Fixture):
    """Section 12. Two sources at one instant, and no verdict about either."""

    VERDICTS = ("PASS", "FAIL", "COMPLIANT", "NON_COMPLIANT", "VIOLATION", "SECURE",
                "INSECURE", "HARDENED", "WEAK", "RISK", "SEVERITY", "CRITICAL")

    def evidence(self):
        return self.host(fstab=DECL_NOAUTO + DECL_UUID, mountinfo=ACT_EQ + ACT_TMP)

    def payload(self):
        evidence = self.evidence()
        return dumped({"records": structure(evidence).get("records"),
                       "items": comparison_items(evidence),
                       "declared": declared_records(evidence),
                       "active": active_records(evidence)})

    def test_no_temporal_vocabulary_anywhere(self):
        blob = dumped(self.evidence())
        for word in ("ADDED", "REMOVED"):
            self.assertNotIn(word, blob,
                             "%r describes change over time; this compares two sources "
                             "at one instant" % word)

    def test_the_payload_carries_no_verdict_vocabulary(self):
        # Scanned WITHOUT upper-casing the payload first: every value in this project's
        # vocabulary is SCREAMING_SNAKE, and fstab's fifth and sixth fields are named
        # `dump` and `pass`. Upper-casing the payload turns the contract's own field
        # name into a verdict and the assertion then punishes a correct lane.
        blob = self.payload()
        for word in self.VERDICTS:
            self.assertNotIn(word, blob, word)

    def test_the_payload_does_not_say_a_mount_failed(self):
        blob = self.payload().lower()
        for word in ("failed", "failure", "unexpected", "misconfigur", "suspicious",
                     "insecure", "should be", "must be"):
            self.assertNotIn(word, blob, word)

    def test_declared_only_is_not_a_mount_failure(self):
        evidence = self.host(fstab=DECL_OTHER_TARGET, mountinfo=ACT_EQ)
        items = [i for i in comparison_items(evidence)
                 if i["relationship"] == compare.DECLARED_ONLY]
        self.assertTrue(items, "the fixture declares /srv with no active counterpart")
        for item in items:
            text = dumped(item).lower()
            for word in ("failed", "not mounted correctly", "should", "unexpected"):
                self.assertNotIn(word, text, word)

    def test_active_only_is_not_unexpected(self):
        evidence = self.host(fstab="", mountinfo=ACT_TMP)
        items = [i for i in comparison_items(evidence)
                 if i["relationship"] == compare.ACTIVE_ONLY]
        self.assertTrue(items)
        for item in items:
            self.assertNotIn("unexpected", dumped(item).lower())

    def test_noauto_plus_active_is_not_a_contradiction(self):
        # The measured case: a declaration saying "do not mount at boot" coexisting with
        # an active mount is normal operation.
        evidence = self.host(fstab=DECL_NOAUTO, mountinfo=ACT_EQ)
        blob = dumped(evidence).lower()
        for word in ("contradict", "inconsistent", "conflict", "violat"):
            self.assertNotIn(word, blob, word)

    def test_ambiguous_is_not_incomplete_acquisition(self):
        evidence = self.host(fstab=DECL_EQ + DECL_UUID, mountinfo=ACT_EQ + ACT_XFS)
        provenance = comparison_provenance(evidence)
        self.assertEqual(s3_coverage(evidence), compare.COMPLETE)
        self.assertEqual(provenance["declared_status"], result.COLLECTED)
        self.assertEqual(provenance["active_status"], result.COLLECTED)

    def test_the_lane_claims_no_organizational_compliance(self):
        blob = dumped(self.evidence()).lower()
        for word in (r"\bcis\b", r"\bpci\b", r"iso 27", r"\bnist\b", r"benchmark",
                     r"control\s+id"):
            self.assertIsNone(re.search(word, blob), word)

    def test_the_lane_does_not_claim_the_host_is_unchanged_by_collection(self):
        blob = dumped(self.evidence()).lower()
        for word in ("tamper-proof", "guaranteed", "host unchanged", "read-only "
                     "guaranteed"):
            self.assertNotIn(word, blob, word)


# =============================================================================
# 11. The pure layer
# =============================================================================

class PureLayer(unittest.TestCase):
    """sources.py is text in, records out; model.py is vocabulary. acquire.py reads."""

    FORBIDDEN_NAMES = ("open", "listdir", "scandir", "walk", "stat", "lstat", "fstat",
                       "environ", "getenv", "putenv", "getcwd", "chdir", "expanduser",
                       "expandvars", "realpath", "readlink", "Popen", "check_output",
                       "check_call", "popen", "system", "fdopen", "read_text",
                       "read_bytes", "iglob", "urlopen", "socket", "connect", "mkdtemp",
                       "remove", "unlink")

    FORBIDDEN_IMPORTS = ("os", "subprocess", "socket", "ssl", "urllib", "http", "glob",
                         "shutil", "pathlib", "tempfile", "pickle", "sqlite3", "asyncio",
                         "ctypes")

    def test_sources_performs_no_io(self):
        used = identifiers(tree_of(sources))
        for name in self.FORBIDDEN_NAMES:
            self.assertNotIn(name, used, "sources.py uses %s" % name)

    def test_sources_imports_nothing_that_can_touch_the_host(self):
        for entry in imported(tree_of(sources)):
            parts = [part for part in entry.replace(".", " ").split() if part]
            for name in self.FORBIDDEN_IMPORTS:
                self.assertNotIn(name, parts,
                                 "sources.py imports %r, which reaches the host" % entry)

    def test_sources_names_no_absolute_path(self):
        for text in string_constants(tree_of(sources)):
            self.assertFalse(text.startswith("/") and len(text) > 1,
                             "sources.py names an absolute path %r" % text)

    def test_model_is_vocabulary_with_no_io(self):
        used = identifiers(tree_of(model))
        for name in ("open", "listdir", "Popen", "environ", "expanduser", "realpath"):
            self.assertNotIn(name, used, "model.py uses %s" % name)

    def test_the_lane_runs_no_command(self):
        for module in lane_modules():
            used = identifiers(tree_of(module))
            for name in ("Popen", "system", "check_output", "run_command", "call"):
                self.assertNotIn(name, used,
                                 "%s runs a command; both sources of this lane are "
                                 "files" % module.__name__)

    def test_the_lane_opens_no_network(self):
        for module in lane_modules():
            for entry in imported(tree_of(module)):
                for name in ("socket", "ssl", "urllib", "http", "asyncio"):
                    self.assertNotIn(name, entry.split("."),
                                     "%s imports %r" % (module.__name__, entry))

    def test_the_parsers_do_not_depend_on_the_environment(self):
        # A pure parser that consulted the environment would produce a different answer
        # depending on where it ran, which is the whole reason the layer exists.
        text = DECL_EQ + DECL_UUID
        first = dumped(fstab_parse(text))
        os.environ["ISEDRAF_ADVERSARIAL_PROBE"] = "1"
        try:
            self.assertEqual(first, dumped(fstab_parse(text)))
        finally:
            del os.environ["ISEDRAF_ADVERSARIAL_PROBE"]


# =============================================================================
# 12. Determinism of the whole lane
# =============================================================================

class Determinism(Fixture):

    def test_two_identical_collections_agree(self):
        first = self.host(fstab=DECL_EQ + DECL_UUID, mountinfo=ACT_EQ + ACT_TMP)
        second = collect(self.root)
        # Two empty answers are also identical. Determinism is only worth asserting
        # over an answer that has content.
        self.assertTrue(relationships(first),
                        "the collection produced no relationships, so agreeing with "
                        "itself proves only that nothing happened twice")
        self.assertEqual(dumped(first), dumped(second))

    def test_the_comparator_digest_is_stable(self):
        self.assertEqual(comparator().semantic_identity()["comparator_digest"],
                         comparator().semantic_identity()["comparator_digest"])

    def test_the_comparator_digest_covers_the_pairing_contract(self):
        identity = comparator().semantic_identity()
        self.assertEqual(identity["semantics"]["pairing_contract"],
                         comparator().pairing_contract)


class EvidenceSelfContainment(Fixture):
    """REFERENCE-BEARING EVIDENCE must retain or integrity-bind its referent.

    The R1 defect was that collect() published the comparison and discarded the
    evidence, so every S3 item held a pointer - source_path, source_line, ordinal -
    into records the artifact did not contain. Counting records does not close that:
    a lane can retain records AND publish references that resolve to none of them.
    Measured, R2/M01c - stripping exactly the three reference keys from the retained
    records left all 176 tests passing.

        pointer without referent  !=  portable evidence
    """

    REFERENCE_KEYS = ("source_path", "source_line", "ordinal", "path", "key")

    def resolve(self, evidence):
        """(references checked, references that resolve to a retained record)."""
        pools = {side: list(evidence.provenance[side].get("records", []))
                 for side in ("declared", "active")}
        checked = resolved = 0
        for item in evidence.records:
            for side in ("declared", "active"):
                reference = item.get(side)
                if reference is None:
                    continue
                checked += 1
                self.assertNotEqual(
                    reference, {"present": True},
                    "a comparison item points at a record with no identifying key at "
                    "all, so nothing can ever resolve it")
                if any(all(record.get(key) == value
                           for key, value in reference.items())
                       for record in pools[side]):
                    resolved += 1
        return checked, resolved

    def test_every_comparison_reference_resolves_to_a_retained_record(self):
        evidence = self.host(fstab=DECL_EQ + DECL_UUID,
                             mountinfo=ACT_EQ + ACT_TMP)
        checked, resolved = self.resolve(evidence)
        self.assertTrue(checked,
                        "the comparison carries no references at all, so this proves "
                        "nothing about the ones it should carry")
        self.assertEqual(resolved, checked,
                         "%d of %d references in the artifact resolve to no retained "
                         "record; the evidence is not portable" % (checked - resolved,
                                                                   checked))

    def test_the_reference_keys_survive_into_the_retained_records(self):
        # The keys S3 points WITH must be the keys the records carry. Naming them
        # explicitly, because resolving by luck on one shared field is not resolving.
        evidence = self.host(fstab=DECL_EQ, mountinfo=ACT_EQ)
        for side in ("declared", "active"):
            records = evidence.provenance[side].get("records", [])
            self.assertTrue(records, "the %s side retained no records" % side)
            for record in records:
                present = [key for key in self.REFERENCE_KEYS if key in record]
                self.assertTrue(present,
                                "a retained %s record carries none of the keys a "
                                "reference is built from" % side)

    def test_the_production_root_artifact_is_also_self_contained(self):
        # Section 13: both roots. "/" is where the path helpers stop being exercised,
        # and it is the only root a real collection runs at.
        checked, resolved = self.resolve(collect("/"))
        self.assertEqual(resolved, checked)


class ActiveUniverseCompleteness(Fixture):
    """Section 11a, which nothing measured until R2/M08 walked through it."""

    MALFORMED = "30 20 8:6\n"
    UNDECLARED_ELSEWHERE = "/dev/sdb1 /srv ext4 defaults 0 2\n"

    def test_a_malformed_active_line_leaves_the_active_universe_incomplete(self):
        evidence = self.host(fstab=DECL_EQ, mountinfo=self.MALFORMED + ACT_EQ)
        self.assertFalse(
            comparison_provenance(evidence)["active_universe_complete"],
            "a mountinfo line that did not parse left the active universe COMPLETE, "
            "so absence against the active side is licensed while an active mount "
            "was not understood")

    def test_a_malformed_active_line_forbids_the_declared_only_claim(self):
        # The observable consequence, and the worse direction: section 11a exists
        # because dropping or discounting an active record manufactures DECLARED_ONLY.
        evidence = self.host(fstab=self.UNDECLARED_ELSEWHERE,
                             mountinfo=self.MALFORMED)
        self.assertEqual(relationships(evidence, "/srv"),
                         [compare.COUNTERPART_UNKNOWN],
                         "a declaration was called DECLARED_ONLY against an active "
                         "source with an unparsed line in it")

    def test_a_clean_active_source_still_completes_its_universe(self):
        # Without this, forcing the universe permanently incomplete would pass above.
        evidence = self.host(fstab=self.UNDECLARED_ELSEWHERE, mountinfo=ACT_EQ)
        self.assertTrue(comparison_provenance(evidence)["active_universe_complete"])
        self.assertEqual(relationships(evidence, "/srv"), [compare.DECLARED_ONLY])


if __name__ == "__main__":
    unittest.main()
