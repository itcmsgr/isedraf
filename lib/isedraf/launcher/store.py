# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Validate the SYSTEM_PRODUCTION store, open a staging, promote what the engine built.
# Implements: AUTH-021, AUTH-022, AUTH-023, AUTH-026, AUTH-027, SNAP-014, EXEC-020
#
# Declared by the package, validated here, repaired by no one (AUTH-027). The root must exist
# as a directory, not a link, root:root, mode 0700; anything else is STATE_ROOT_UNUSABLE (67)
# and nothing is changed. The entries below it are created exclusively and without following
# links when missing, and refused when present and non-conforming.
#
# The promotion route is the one the P5b measurement proved on the lab corpus: a root-owned
# staging directory, 0777 under the root-only tmp/, which the reduced engine fills as its
# own identity; a mechanical check of the staged tree (declared names only, no links, no
# hard links, engine-owned, bounded) and of its hashes; chmod 0700; one atomic rename into
# snapshots/; the ledger append last. No file changes owner (CAP_CHOWN is measured not
# required). Reading the engine-owned files needs CAP_DAC_READ_SEARCH and nothing more.
#
# Only ISEDRAF's own artifacts are read here, and only to recompute their hashes; host
# evidence is never parsed or interpreted (AUTH-021).
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="launcher (root inside the Full Audit unit)"
# meta:mutates="state-root only"
# meta:binaries=""
# =============================================================================
"""SYSTEM_PRODUCTION store: conformance, staging and mechanical promotion."""
import json
import os
import stat

from isedraf import ids, ledger, snapshot, stateroot, verify

ROOT = "/var/lib/isedraf"
# The owner of the store. Tests replace these module constants; no runtime path does.
OWNER_UID = 0
OWNER_GID = 0

DIRECTORIES = ("snapshots", "ledger", "tmp")
STAGING_MODE = 0o777          # under the root-only 0700 tmp/: reachable only from inside
BUNDLE_DIRECTORIES = ("coverage", "method", "sections", "state")
BUNDLE_FILES = ("manifest.json", "method/host_identity.json", "state/host_identity.json",
                "coverage/evidence_limits.json") + snapshot.SECTION_ARTIFACTS
FILE_BOUND = 16 * 1024 * 1024
MANIFEST_BOUND = 1024 * 1024


class Unusable(Exception):
    """AUTH-023: the state root or one of its entries cannot be used (exit 67)."""


class PromotionRefused(Exception):
    """AUTH-021: the staged tree is not exactly what the engine may produce."""


def _conforms(path, directory, mode, uid, gid):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    kind = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
    if not kind or stat.S_ISLNK(st.st_mode):
        raise Unusable("%s is not a %s (a link or another type); nothing was changed"
                       % (path, "directory" if directory else "regular file"))
    if (st.st_uid, st.st_gid) != (uid, gid) or stat.S_IMODE(st.st_mode) != mode:
        raise Unusable("%s is %d:%d %04o, not %d:%d %04o; nothing was changed"
                       % (path, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode),
                          uid, gid, mode))
    return st


def check_root(root=None):
    """AUTH-027: exists, a directory, not a link, owner:group root, mode 0700. Else 67."""
    root = root or ROOT
    if _conforms(root, True, 0o700, OWNER_UID, OWNER_GID) is None:
        raise Unusable("%s does not exist; it is declared by the package and never created "
                       "at runtime" % root)


def prepare(root=None):
    """Create the missing store entries exclusively, refuse non-conforming ones (AUTH-022)."""
    root = root or ROOT
    check_root(root)
    previous = os.umask(0o077)
    try:
        for name in DIRECTORIES:
            path = os.path.join(root, name)
            if _conforms(path, True, 0o700, OWNER_UID, OWNER_GID) is None:
                os.mkdir(path, 0o700)                   # exclusive; never follows a link
                _conforms(path, True, 0o700, OWNER_UID, OWNER_GID)
        lock = os.path.join(root, stateroot.LOCK_NAME)
        if _conforms(lock, False, 0o600, OWNER_UID, OWNER_GID) is None:
            os.close(os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o600))
            _conforms(lock, False, 0o600, OWNER_UID, OWNER_GID)
    finally:
        os.umask(previous)


def make_staging(root, run_id):
    """The run's staging directory: root-owned, 0777 under the root-only tmp/ (AUTH-027)."""
    if not ids.ID_RE.match(run_id or "") or not run_id.startswith("RUN-"):
        raise ValueError("not a run identifier: %r" % (run_id,))
    path = os.path.join(root, "tmp", run_id)
    os.mkdir(path, 0o700)                               # exclusive
    os.chmod(path, STAGING_MODE)
    return path


def _entry(path, directory, engine_uid):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise PromotionRefused("%s is a link" % path)
    if directory:
        if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700:
            raise PromotionRefused("%s is not a 0700 directory" % path)
    else:
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600:
            raise PromotionRefused("%s is not a 0600 regular file" % path)
        if st.st_nlink != 1:
            raise PromotionRefused("%s has %d links" % (path, st.st_nlink))
        if st.st_size > FILE_BOUND:
            raise PromotionRefused("%s exceeds %d bytes" % (path, FILE_BOUND))
    if st.st_uid != engine_uid:
        raise PromotionRefused("%s is owned by uid %d, not the engine" % (path, st.st_uid))


def check_staged(staging, engine_uid, run_id):
    """The mechanical check of AUTH-021. Returns the manifest envelope, or refuses."""
    st = os.lstat(staging)
    if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)
            or (st.st_uid, st.st_gid) != (OWNER_UID, OWNER_GID)
            or stat.S_IMODE(st.st_mode) != STAGING_MODE):
        raise PromotionRefused("%s is not the staging the launcher created" % staging)
    for name in sorted(os.listdir(staging)):
        if name in BUNDLE_DIRECTORIES:
            _entry(os.path.join(staging, name), True, engine_uid)
            for child in sorted(os.listdir(os.path.join(staging, name))):
                relative = name + "/" + child
                if relative not in BUNDLE_FILES:
                    raise PromotionRefused("undeclared staged file %s" % relative)
                _entry(os.path.join(staging, relative), False, engine_uid)
        elif name in BUNDLE_FILES:
            _entry(os.path.join(staging, name), False, engine_uid)
        else:
            raise PromotionRefused("undeclared staged entry %s" % name)
    with open(os.path.join(staging, "manifest.json"), "rb") as fh:
        raw = fh.read(MANIFEST_BOUND + 1)
    if len(raw) > MANIFEST_BOUND:
        raise PromotionRefused("the staged manifest exceeds its bound")
    problems = verify.verify_snapshot(staging)
    if problems:
        raise PromotionRefused("the staged snapshot does not verify: %s" % "; ".join(problems))
    envelope = json.loads(raw.decode("utf-8"))
    core = envelope["manifest_core"]
    if (core.get("state_root"), core.get("run_mode")) != (stateroot.SYSTEM_PRODUCTION,
                                                          stateroot.FULL_AUDIT):
        raise PromotionRefused("the staged snapshot is not SYSTEM_PRODUCTION / FULL_AUDIT")
    if core.get("run_id") != run_id:
        raise PromotionRefused("the staged snapshot belongs to run %r" % core.get("run_id"))
    sid = core.get("snapshot_id") or ""
    if not ids.ID_RE.match(sid) or not sid.startswith("SDS-"):
        raise PromotionRefused("the staged snapshot id %r is not an identifier" % sid)
    return envelope


def promote(root, staging, envelope):
    """chmod 0700, one atomic rename into snapshots/, then the ledger append (SNAP-014)."""
    core = envelope["manifest_core"]
    final = os.path.join(root, "snapshots", core["snapshot_id"])
    if os.path.lexists(final):
        raise PromotionRefused("snapshot %s already exists" % core["snapshot_id"])
    os.chmod(staging, 0o700)
    stateroot.fsync_dir(staging)
    os.rename(staging, final)
    stateroot.fsync_dir(os.path.join(root, "snapshots"))
    created_at = core["created_at"]
    record, _canonical, record_hash = ledger.build_record(
        root, core["snapshot_id"], envelope["manifest_hash"],
        ids.new_id("EVT", created_at), created_at, stateroot.SYSTEM_PRODUCTION)
    ledger.append(root, record, record_hash)
    return final
