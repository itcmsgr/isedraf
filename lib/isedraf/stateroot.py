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

PRODUCTION_ROOT = "/var/lib/isedraf"        # STORE-001, the single normative statement
ENV_STATE_ROOT = "ISEDRAF_STATE_ROOT"
DEV = "DEV"                                 # PRIV-004's literal spelling
PRODUCTION = "PRODUCTION"

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
            "prototype W1 does not yet support privileged execution")
    override = environ.get(ENV_STATE_ROOT)
    if override:
        if not os.path.isabs(override):
            raise StateRootError("%s must be an absolute path" % ENV_STATE_ROOT)
        return override, DEV
    # IQ-010 RESOLVED. This used to fall back to PRODUCTION_ROOT, which W1 has no way to
    # reach: STORE-001 puts it at mode 0700 under /var/lib, only root can create it, and
    # SCOPE-071 refuses root. That looked like a contradiction between frozen rules.
    #
    # It is not. SCOPE-070 already states that W1 "runs under ISEDRAF_STATE_ROOT", and
    # PRIV-005's Mode A - `sudo isedraf`, root supervisor, sandbox, state-root writability
    # preflight - is the only thing that ever owns the production root. Mode A is
    # DEFERRED_TO_FREEZE_SET_2 by SCOPE-072, so W1 HAS NO PRODUCTION MODE BY DESIGN.
    #
    # The defect was the implementation offering one. It now says so instead.
    raise StateRootError(
        "W1 is unprivileged only and runs under %s (SCOPE-070). The production evidence "
        "root %s belongs to PRIV-005's Mode A - privileged supervisor inside a sandbox - "
        "which is deferred to Freeze Set 2 (SCOPE-072), so this slice has no production "
        "mode to fall back to. Set %s to an absolute path you own; every artifact will "
        "carry the DEV marker (PRIV-004)." % (ENV_STATE_ROOT, PRODUCTION_ROOT,
                                              ENV_STATE_ROOT))


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
