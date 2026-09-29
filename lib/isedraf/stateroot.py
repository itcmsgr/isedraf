# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: State-root resolution, privilege refusal and the W1-A directory layout.
# Implements: STORE-001, STORE-025, PRIV-004, SCOPE-070, SCOPE-071, SNAP-014
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="state-root only"
# meta:binaries=""
# =============================================================================

"""Where evidence lives, and who is allowed to write it."""
import fcntl
import os
import stat

PRODUCTION_ROOT = "/var/lib/isedraf"        # STORE-001, the single normative statement
ENV_STATE_ROOT = "ISEDRAF_STATE_ROOT"
# STORE-026 (D-116): three artifact classes, never confusable. The literal is fixed
# by how the root was selected, never inferred from a path.
DEV = "DEV"                                 # PRIV-004's literal spelling, unchanged
USER_PRODUCTION = "USER_PRODUCTION"         # GA v0.1: the invoking user's own store
SYSTEM_PRODUCTION = "SYSTEM_PRODUCTION"     # /var/lib/isedraf; Full Audit, SCOPE-072
STATE_ROOT_CLASSES = (DEV, USER_PRODUCTION, SYSTEM_PRODUCTION)

# STORE-027: filesystems known to lack the local rename/flock/fsync semantics a commit
# relies on (remote, or FUSE, which is how most network filesystems reach the kernel),
# and the local ones known to have them. Anything else is not established - and refused.
UNSUITABLE_FILESYSTEMS = ("nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "afs", "ceph",
                          "glusterfs", "lustre", "davfs", "ncpfs", "fuse")
SUITABLE_FILESYSTEMS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs", "bcachefs",
                        "tmpfs", "overlay")

# STORE-025: W1-A creates ONLY these. baselines/, evaluations/, acceptances/, reports/,
# exports/ and host/anchor.key belong to later freeze sets and are not created.
W1A_DIRECTORIES = ("snapshots", "tmp", "ledger")
LOCK_NAME = ".lock"
LEDGER_SEGMENT = os.path.join("ledger", "segment-000001.jsonl")


class PrivilegeRefused(Exception):
    """SCOPE-071. Refusal is explicit and temporary, never a silent degradation."""


class StateRootError(Exception):
    """The state root cannot be used. Never silently relocated."""


def _under_sudo():
    return bool(os.environ.get("SUDO_USER"))


def resolve(environ=None, euid=None):
    """Returns (path, state_root_class).

    SCOPE-071: W1 refuses privileged execution outright. PRIV-004: the development
    override is honoured only when euid != 0 AND SUDO_USER is unset, and everything it
    produces is marked DEV so it can never be mistaken for production evidence.
    """
    environ = os.environ if environ is None else environ
    euid = os.geteuid() if euid is None else euid
    if euid == 0 or bool(environ.get("SUDO_USER")):
        raise PrivilegeRefused(
            "Privileged execution is not supported in ISEDRAF 0.1. Run ISEDRAF as your "
            "normal user. Evidence requiring elevated privilege is reported as NOT_TESTED.")
    override = environ.get(ENV_STATE_ROOT)
    if override:
        if not os.path.isabs(override):
            raise StateRootError("%s must be an absolute path" % ENV_STATE_ROOT)
        return override, DEV
    # IQ-010 is superseded by D-116 (STORE-026): W1 had no production mode, and
    # GA v0.1 has an unprivileged one - the invoking user's own store. The system store
    # stays with the Full Audit release (SCOPE-072) and is never selected here.
    return user_root(environ), USER_PRODUCTION


def user_root(environ):
    """STORE-026's USER_PRODUCTION root: $XDG_STATE_HOME/isedraf when XDG_STATE_HOME is
    absolute (a relative value is ignored), otherwise ~/.local/state/isedraf.

    The home directory comes from an absolute $HOME only; with none, the run is refused
    rather than guessed, and says how to proceed.
    """
    xdg = environ.get("XDG_STATE_HOME")
    if xdg and os.path.isabs(xdg):
        return os.path.join(xdg, "isedraf")
    home = environ.get("HOME")
    if home and os.path.isabs(home):
        return os.path.join(home, ".local", "state", "isedraf")
    raise StateRootError(
        "the user-mode evidence store cannot be located: neither XDG_STATE_HOME nor HOME "
        "is an absolute path (STORE-026). Set one of them, or use %s=<an absolute path "
        "you own> for a development run." % ENV_STATE_ROOT)


def check_user_root(root, euid):
    """STORE-026: an existing root must be a real directory owned by `euid`, mode 0700.

    Refused with a reason otherwise - never relocated, never repaired behind the
    operator's back. An absent root is fine: prepare() creates it with 0700.
    """
    try:
        info = os.lstat(root)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise StateRootError("the evidence store %s cannot be examined: %s" % (root, exc))
    if not stat.S_ISDIR(info.st_mode):
        raise StateRootError("the evidence store %s is not a directory (a symlink or file "
                             "is refused, STORE-026)" % root)
    if info.st_uid != euid:
        raise StateRootError("the evidence store %s is owned by uid %d, not the invoking "
                             "uid %d (STORE-026)" % (root, info.st_uid, euid))
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise StateRootError("the evidence store %s has mode %04o; it must be 0700 "
                             "(STORE-026). Fix its permissions; it is not changed for you."
                             % (root, stat.S_IMODE(info.st_mode)))


def _unescape(field):
    """mountinfo writes space, tab, newline and backslash as a backslash and 3 octal digits."""
    out, i = [], 0
    while i < len(field):
        code = field[i + 1:i + 4]
        if field[i] == "\\" and len(code) == 3 and code.isdigit():
            out.append(chr(int(code, 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def storage_suitability(path, mountinfo="/proc/self/mountinfo"):
    """(ok, reason) for committing evidence under `path` (STORE-027).

    The filesystem is the one mounted at the longest mount point containing `path`. A
    known-unsuitable type is refused by name; a type not known to be suitable, or mount
    information that cannot be read, is refused as not established. Fail closed.
    """
    try:
        with open(mountinfo, "rb") as fh:
            lines = fh.read(1 << 20).decode("utf-8", "replace").splitlines()
    except OSError as exc:
        return False, ("STORAGE_NOT_ESTABLISHED: mount information could not be read (%s), "
                       "so the filesystem of %s is not known" % (exc.strerror, path))
    target = os.path.normpath(path)
    best, fstype = "", None
    for line in lines:
        left, sep, right = line.partition(" - ")
        fields = left.split(" ")
        if not sep or len(fields) < 5 or not right:
            continue
        mount = _unescape(fields[4])
        inside = target == mount or target.startswith(mount.rstrip("/") + "/")
        if inside and len(mount) >= len(best):
            best, fstype = mount, right.split(" ")[0]
    if fstype is None:
        return False, "STORAGE_NOT_ESTABLISHED: no mount contains %s" % path
    family = fstype.split(".")[0]
    if fstype in UNSUITABLE_FILESYSTEMS or family in UNSUITABLE_FILESYSTEMS:
        return False, ("STORAGE_UNSUITABLE: %s is on a %s filesystem, which does not give "
                       "the local atomic rename, lock and sync a commit needs (STORE-027). "
                       "No evidence was committed; use a local directory via "
                       "XDG_STATE_HOME, or a %s development run." % (path, fstype, DEV))
    if fstype not in SUITABLE_FILESYSTEMS:
        return False, ("STORAGE_NOT_ESTABLISHED: %s is on a %s filesystem, whose commit "
                       "semantics are not established (STORE-027). No evidence was "
                       "committed." % (path, fstype))
    return True, None

def prepare(root):
    """Create the W1-A subset of STORE-001's layout. umask 077, directories 0700."""
    previous = os.umask(0o077)
    try:
        os.makedirs(root, mode=0o700, exist_ok=True)
        for name in W1A_DIRECTORIES:
            os.makedirs(os.path.join(root, name), mode=0o700, exist_ok=True)
    except OSError as exc:
        if root == PRODUCTION_ROOT:          # unreachable in W1; kept for Freeze Set 2
            # IQ-010. SCOPE-070 makes W1 unprivileged-only and SCOPE-071 refuses root,
            # but STORE-001's root is mode 0700 under /var/lib and only root can create
            # it. W1 therefore cannot bootstrap its own production store: packaging must
            # create it, and packaging does not exist yet. Say that, rather than leaving
            # an operator to read "permission denied" and guess.
            raise StateRootError(
                "the production evidence root %s does not exist or is not writable, and "
                "W1 runs unprivileged by design (SCOPE-070) so it cannot create it. "
                "Packaging creates it; packaging is not implemented yet. For development "
                "use %s=<an absolute path you own>. Underlying error: %s"
                % (root, ENV_STATE_ROOT, exc))
        raise StateRootError("state root %s is not writable: %s" % (root, exc))
    finally:
        os.umask(previous)
    return root


class RunLock(object):
    """SNAP-014: a whole-run exclusive flock. Not advisory politeness — the commit
    ordering below it is only safe while one run holds it."""

    def __init__(self, root):
        self._path = os.path.join(root, LOCK_NAME)
        self._fd = None

    def __enter__(self):
        self._fd = os.open(self._path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self._fd)
            self._fd = None
            raise StateRootError("another ISEDRAF run holds the lock")
        return self

    def __exit__(self, *exc):
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None
        return False


def write_file(path, data, mode=0o600):
    """Write and fsync one artifact. Files 0600, exclusive creation, no follow."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_dir(path):
    """A rename is only durable once the DIRECTORY is synced, not just the file."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
