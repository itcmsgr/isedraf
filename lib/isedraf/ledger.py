# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The ledger — snapshot_committed and baseline_approved records, hash-chained.
# Implements: STORE-024, STORE-001, SNAP-014, SNAP-018, BASE-007, SCOPE-075
#
# The ledger carries identifiers and hashes. It never duplicates host state and never
# carries personal data.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="state-root only"
# meta:binaries=""
# =============================================================================

"""STORE-024's record and chaining rule; STORE-010 segments; STORE-016 recovery."""
import errno
import hashlib
import json
import os
import re

from . import canonical, stateroot

LEDGER_SCHEMA_VERSION = 1
EVENT_SNAPSHOT_COMMITTED = "snapshot_committed"
# D-127 (v0.4): the second event W1 admits (SCOPE-075, STORE-010's enum). Same chain, same
# record_hash rule (STORE-024); its own field set.
EVENT_BASELINE_APPROVED = "baseline_approved"
# STORE-016 (v0.5): the first record of the segment after a damaged one (recovery design 2.3).
EVENT_LEDGER_RECOVERED = "ledger_recovered"
GENESIS_PREVIOUS = "sha256:" + "0" * 64
_COMMON = ("ledger_schema_version", "sequence", "event", "event_id", "occurred_at",
           "previous_record_hash", "state_root")
FIELDS = {
    EVENT_SNAPSHOT_COMMITTED: frozenset(_COMMON + ("snapshot_id", "manifest_hash")),
    EVENT_BASELINE_APPROVED: frozenset(_COMMON + (
        "baseline_revision", "revision_hash", "artifact_digest", "snapshot_id",
        "manifest_hash")),
    EVENT_LEDGER_RECOVERED: frozenset(_COMMON + (
        "damaged_segment", "verified_length", "damaged_length", "torn_tail_hash")),
}


# --- segments and recovery (STORE-010, STORE-016; v0.5, D-129) ---------------------------
# The ledger is ledger/segment-NNNNNN.jsonl, numbered from 000001, chained across segments.
# A segment whose last write did not complete ends in bytes after its last newline: a torn
# tail. Recovery keeps that segment byte for byte, seals it, and opens the next segment with a
# ledger_recovered record (docs/development/V0_5_LEDGER_RECOVERY_DESIGN.md).
LEDGER_DIRECTORY = "ledger"
SEGMENT_RE = re.compile(r"^segment-([0-9]{6})\.jsonl$")
SEGMENT_BOUND = 64 * 1024 * 1024        # one segment's bytes, read bounded
SEGMENTS_BOUND = 10000                  # segments read by one reader
TAIL_BOUND = 1024 * 1024                # a torn tail is part of ONE record, never more
INTEGRITY_FAILURE = "LEDGER_INTEGRITY_FAILURE"
TORN_TAIL = "LEDGER_TORN_TAIL"


class IntegrityFailure(ValueError):
    """The ledger does not verify and is not a recoverable interruption; nothing is written."""


class WriteIncomplete(OSError):
    """A ledger write wrote fewer bytes than the record holds (STORE-016)."""


def segment_name(number):
    return "segment-%06d.jsonl" % number


def segment_path(root, number=1):
    return os.path.join(root, LEDGER_DIRECTORY, segment_name(number))


def segment_names(root):
    """The segment files present, in number order; links and non-files are never read."""
    directory = os.path.join(root, LEDGER_DIRECTORY)
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    found = sorted(n for n in names if SEGMENT_RE.match(n))
    if len(found) > SEGMENTS_BOUND:
        raise IntegrityFailure("%s: more than %d ledger segments" % (INTEGRITY_FAILURE,
                                                                  SEGMENTS_BOUND))
    return found


def read_segments(root):
    """{name: bytes} of every segment, bounded and no-follow."""
    out = {}
    for name in segment_names(root):
        fd = os.open(os.path.join(root, LEDGER_DIRECTORY, name),
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            data = os.read(fd, SEGMENT_BOUND + 1)
            while data and len(data) <= SEGMENT_BOUND:
                more = os.read(fd, SEGMENT_BOUND + 1 - len(data))
                if not more:
                    break
                data += more
        finally:
            os.close(fd)
        if len(data) > SEGMENT_BOUND:
            raise IntegrityFailure("%s: %s exceeds %d bytes" % (INTEGRITY_FAILURE, name,
                                                             SEGMENT_BOUND))
        out[name] = data
    return out


def _tail_hash(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def parse(segments):
    """(rows, torn, problems) from {segment name: bytes}. Pure.

    rows: every verified record, in chain order. torn: None, or the newest segment's torn tail
    ({"segment", "verified_length", "damaged_length", "tail"}) when everything before it
    verifies. problems: anything that is not a recoverable interruption of the last record.
    """
    rows, problems, torn = [], [], None
    names = sorted(segments)
    numbers = [int(SEGMENT_RE.match(n).group(1)) for n in names]
    if numbers and numbers != list(range(1, len(numbers) + 1)):
        problems.append("%s: the segments are not numbered 1..%d without a gap"
                        % (INTEGRITY_FAILURE, len(numbers)))
        return rows, None, problems
    previous, sequence = GENESIS_PREVIOUS, 0
    # A seal lives in the NEXT segment's first record; read those first. They are verified
    # (hash and chain) when the main pass reaches them; a forged one fails there.
    sealed = {}                              # damaged segment name -> its ledger_recovered core
    for position, name in enumerate(names[1:], start=1):
        first = segments[name].split(b"\n", 1)[0]
        try:
            core = json.loads(first.decode("utf-8"))["record_core"]
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            continue
        if isinstance(core, dict) and core.get("event") == EVENT_LEDGER_RECOVERED:
            sealed[names[position - 1]] = core
    seen_seals = set()
    for position, name in enumerate(names):
        data = segments[name]
        cut = data.rfind(b"\n") + 1
        body, tail = data[:cut], data[cut:]
        seal = sealed.get(name)
        newest = position == len(names) - 1
        if seal is not None:
            if (seal.get("verified_length") != cut or seal.get("damaged_length") != len(data)
                    or seal.get("torn_tail_hash") != _tail_hash(tail)):
                problems.append("%s: %s no longer matches its ledger_recovered record"
                                % (INTEGRITY_FAILURE, name))
                return rows, None, problems
        elif tail and not newest:
            problems.append("%s: %s ends in an incomplete record but is not the newest "
                            "segment and no recovery seals it" % (INTEGRITY_FAILURE, name))
            return rows, None, problems
        for number, line in enumerate(body.split(b"\n")[:-1], start=1):
            where = "%s record %d" % (name, number)
            try:
                row = json.loads(line.decode("utf-8"))
                core, record_hash = row["record_core"], row["record_hash"]
            except (ValueError, KeyError, TypeError, UnicodeDecodeError):
                problems.append("%s: %s is not a ledger record" % (INTEGRITY_FAILURE, where))
                return rows, None, problems
            if not isinstance(core, dict) or canonical.canonical_bytes(row) != line + b"\n":
                problems.append("%s: %s is not canonical" % (INTEGRITY_FAILURE, where))
                return rows, None, problems
            if _sealed(core)[2] != record_hash:
                problems.append("%s: %s: record_hash does not match its preimage"
                                % (INTEGRITY_FAILURE, where))
                return rows, None, problems
            if core.get("sequence") != sequence + 1 or core.get("previous_record_hash") != previous:
                problems.append("%s: %s breaks the chain (STORE-024)" % (INTEGRITY_FAILURE,
                                                                         where))
                return rows, None, problems
            if core.get("event") == EVENT_LEDGER_RECOVERED:
                damaged = core.get("damaged_segment")
                if (number != 1 or position == 0 or damaged != names[position - 1]
                        or damaged in seen_seals or sealed.get(damaged) != core):
                    problems.append("%s: %s is a ledger_recovered record out of place"
                                    % (INTEGRITY_FAILURE, where))
                    return rows, None, problems
                seen_seals.add(damaged)
            rows.append(row)
            previous, sequence = record_hash, core["sequence"]
        if seal is None and tail:            # the newest segment, everything before verified
            if len(tail) > TAIL_BOUND:
                problems.append("%s: %s ends in %d bytes after its last record, more than one "
                                "record" % (INTEGRITY_FAILURE, name, len(tail)))
                return rows, None, problems
            torn = {"segment": name, "verified_length": cut, "damaged_length": len(data),
                    "tail": tail}
    # A seal names the segment before it; re-check, now that every seal is known.
    for name, core in sealed.items():
        data = segments[name]
        cut = data.rfind(b"\n") + 1
        if (core.get("verified_length") != cut or core.get("damaged_length") != len(data)
                or core.get("torn_tail_hash") != _tail_hash(data[cut:]) or cut == len(data)):
            problems.append("%s: %s does not match its ledger_recovered record"
                            % (INTEGRITY_FAILURE, name))
            return rows, None, problems
    return rows, torn, problems


def read_records(root):
    """Every verified record, across segments, in chain order. A torn tail of the newest
    segment is not a record and is left for recovery; anything else raises IntegrityFailure."""
    rows, _torn, problems = parse(read_segments(root))
    if problems:
        raise IntegrityFailure("; ".join(problems))
    return rows


def torn_tail(root):
    """The newest segment's unrecovered torn tail, or None. Raises IntegrityFailure."""
    _rows, torn, problems = parse(read_segments(root))
    if problems:
        raise IntegrityFailure("; ".join(problems))
    return torn


def recover(root, state_root_class, occurred_at, event_id, before_rename=None):
    """STORE-016 under the caller's whole-run lock. Returns the ledger_recovered core, or None
    when nothing is torn. Raises IntegrityFailure (nothing written) or OSError (for example
    ENOSPC; the store is as before, and the next writer repeats the recovery).

    The damaged segment is never written: it is sealed by the next segment, whose first record
    is ledger_recovered. That record is written to tmp/, byte-count checked and fsynced, then
    renamed into ledger/: the new segment exists complete, or not at all.
    """
    segments = read_segments(root)
    rows, torn, problems = parse(segments)
    if problems:
        raise IntegrityFailure("; ".join(problems))
    if torn is None:
        return None
    sequence, previous = ((rows[-1]["record_core"]["sequence"], rows[-1]["record_hash"])
                          if rows else (0, GENESIS_PREVIOUS))
    core, _canonical, record_hash = _sealed({
        "ledger_schema_version": LEDGER_SCHEMA_VERSION,
        "sequence": sequence + 1,
        "event": EVENT_LEDGER_RECOVERED,
        "event_id": event_id,
        "occurred_at": occurred_at,
        "previous_record_hash": previous,
        "state_root": state_root_class,
        "damaged_segment": torn["segment"],
        "verified_length": torn["verified_length"],
        "damaged_length": torn["damaged_length"],
        "torn_tail_hash": _tail_hash(torn["tail"]),
    })
    row = canonical.canonical_bytes({"record_core": core, "record_hash": record_hash})
    name = segment_name(len(segments) + 1)
    final = os.path.join(root, LEDGER_DIRECTORY, name)
    if os.path.lexists(final):
        raise IntegrityFailure("%s: %s already exists" % (INTEGRITY_FAILURE, name))
    staging = os.path.join(root, "tmp", "ledger-recovery-" + name)
    previous_umask = os.umask(0o077)
    try:
        if os.path.lexists(staging) and not os.path.islink(staging):
            os.unlink(staging)              # an earlier, never-referenced attempt of this name
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600)
        try:
            _write_all_checked(fd, row)
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.umask(previous_umask)
    if before_rename is not None:
        before_rename()                     # tests: an interruption between the steps
    os.rename(staging, final)
    stateroot.fsync_dir(os.path.join(root, LEDGER_DIRECTORY))
    stateroot.fsync_dir(os.path.join(root, "tmp"))
    return core


def _write_all_checked(fd, data):
    """STORE-016: one bounded write whose byte count is verified."""
    written = os.write(fd, data)
    if written != len(data):
        raise WriteIncomplete(errno.EIO, "wrote %d of %d bytes" % (written, len(data)))


def snapshot_records(root):
    """record_core of every snapshot_committed record, in ledger order.

    A reader that wants "the latest run" takes the last of THESE, never the last record:
    since v0.4 the ledger also carries baseline_approved records.
    """
    return [r["record_core"] for r in read_records(root)
            if r["record_core"].get("event") == EVENT_SNAPSHOT_COMMITTED]


def baseline_records(root):
    """record_core of every baseline_approved record, in ledger order."""
    return [r["record_core"] for r in read_records(root)
            if r["record_core"].get("event") == EVENT_BASELINE_APPROVED]


def head(root):
    """(sequence, record_hash) of the last record, or (0, GENESIS_PREVIOUS)."""
    records = read_records(root)
    if not records:
        return 0, GENESIS_PREVIOUS
    last = records[-1]
    return last["record_core"]["sequence"], last["record_hash"]


def build_record(root, snapshot_id, manifest_hash, event_id, occurred_at,
                 state_root_class):
    """STORE-024: sequence strictly increments with no gaps; previous_record_hash links."""
    sequence, previous = head(root)
    core = {
        "ledger_schema_version": LEDGER_SCHEMA_VERSION,
        "sequence": sequence + 1,
        "event": EVENT_SNAPSHOT_COMMITTED,
        "event_id": event_id,
        "occurred_at": occurred_at,
        "previous_record_hash": previous,
        "snapshot_id": snapshot_id,
        "manifest_hash": manifest_hash,
        "state_root": state_root_class,
    }
    return _sealed(core)


def _sealed(core):
    core_canonical = canonical.canonical_bytes(core)
    record_hash = canonical.rendered(
        canonical.hash_frame(canonical.DOMAIN_LEDGER_RECORD, core_canonical))
    return core, core_canonical, record_hash


def build_baseline_record(root, revision_id, revision_hash, artifact_digest, snapshot_id,
                          manifest_hash, event_id, occurred_at, state_root_class):
    """D-127: the baseline_approved record. It binds the revision artifact's exact bytes
    (artifact_digest), so a field the revision hash does not cover is still bound."""
    sequence, previous = head(root)
    return _sealed({
        "ledger_schema_version": LEDGER_SCHEMA_VERSION,
        "sequence": sequence + 1,
        "event": EVENT_BASELINE_APPROVED,
        "event_id": event_id,
        "occurred_at": occurred_at,
        "previous_record_hash": previous,
        "baseline_revision": revision_id,
        "revision_hash": revision_hash,
        "artifact_digest": artifact_digest,
        "snapshot_id": snapshot_id,
        "manifest_hash": manifest_hash,
        "state_root": state_root_class,
    })


def append(root, core, record_hash):
    """SNAP-014: ledger append + fsync, last, under the run lock. One physical line, to the
    newest segment; one write whose byte count is verified (STORE-016). A torn tail must be
    recovered first: appending after it would bury it in the middle of the segment."""
    names = segment_names(root)
    path = os.path.join(root, LEDGER_DIRECTORY, names[-1]) if names else segment_path(root)
    if torn_tail(root) is not None:
        raise IntegrityFailure("%s: the newest ledger segment ends in an incomplete record; "
                               "it is recovered before any append" % TORN_TAIL)
    row = canonical.canonical_bytes({"record_core": core, "record_hash": record_hash})
    previous = os.umask(0o077)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600)
        try:
            _write_all_checked(fd, row)
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.umask(previous)
    stateroot.fsync_dir(os.path.dirname(path))
    return record_hash


def unledgered_snapshots(root):
    """SNAP-018: SDS-* directories the ledger does not reference.

    The crash window SNAP-014 creates is between the atomic rename and the ledger append.
    Exactly one such directory is that crash and is recoverable; more than one is store
    discontinuity, which is a different thing and SHALL NOT be reported as a benign crash.
    """
    snapshots = os.path.join(root, "snapshots")
    if not os.path.isdir(snapshots):
        return []
    known = set(r["snapshot_id"] for r in snapshot_records(root))
    return sorted(d for d in os.listdir(snapshots)
                  if d.startswith("SDS-") and d not in known)
