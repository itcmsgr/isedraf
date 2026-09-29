# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Map a path the HOST declares onto the tree this collection was told to read.
# Implements: SCOPE-022, GOV-001
#
# Configuration files name absolute paths. `#include /etc/extra`, `Include /etc/ssh/*.conf`
# and an account home of `/home/alice` are all statements about the host's own filesystem.
# A collection given a root that is not "/" - a fixture, an unpacked image, a mounted
# volume - must read the corresponding object BENEATH that root. If it does not, it reads
# the machine running the tool and reports it as the machine under test.
#
# Two lanes reached this independently. sudo/acquire.py found it first, on contact with
# the adversarial lane; ssh/acquire.py implemented the same four lines and recorded itself
# as consumer #2 rather than extracting on the spot. authorized_keys is #3: an account
# home is a host-absolute path, and a declared AuthorizedKeysFile is either absolute or
# relative to that home. Three consumers with identical semantics is the threshold.
#
# This is not a path framework and must not become one. It knows nothing about sudo, SSH,
# accounts, authorized keys, symlinks, whether anything exists, or what any of it means
# for security. It is lexical string arithmetic over two inputs.
#
#   under(root, "/etc/extra")        root="/"    -> "/etc/extra"        identity
#                                    root="/fix" -> "/fix/etc/extra"
#
# `realpath` is deliberately absent. Resolving symlinks would make the identity of an
# object depend on the live filesystem, which is the fallthrough this module exists to
# prevent - and include_graph already decided the same thing for cycle detection.
#
# Pure: takes two strings, returns a string. No filesystem, no subprocess, no network.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Lexical mapping of host-declared paths into a collection root."""
import os

HOST_ROOT = "/"


def under(root, host_path):
    """The object `host_path` names, as it appears beneath `root`.

    `host_path` MUST be host-absolute. A relative path is anchored by something only its
    own domain knows - the including file's directory for sudoers and sshd_config, the
    account's home for AuthorizedKeysFile - and a shared helper that guessed an anchor
    would be guessing domain semantics. Callers branch on absoluteness themselves; that
    branch is grammar, and grammar stays in the domain.

    Normalisation happens in HOST space, before the join, and this ordering is the whole
    security content of the function. `..` above `/` is `/` on a Linux host, so
    `/etc/../../tmp/x` means `/tmp/x`. Joining first and normalising afterwards would turn
    that into `<root>/etc/../../tmp/x`, which resolves to `/tmp/x` on the LIVE host - a
    fixture run reading the machine executing it. Normalising first yields `/tmp/x` in host
    space and `<root>/tmp/x` under the root, which is what the host statement means.

    Because an absolute normalised path contains no `..` component at all, the result is
    always `root` or beneath it. Containment is a property of the construction, not a
    check bolted on after it.
    """
    if not host_path.startswith(HOST_ROOT):
        raise ValueError(
            "under() takes a host-absolute path; %r is relative and only its own "
            "domain knows what it is relative to" % (host_path,))
    normalized = os.path.normpath(HOST_ROOT + host_path.lstrip(HOST_ROOT))
    return os.path.normpath(os.path.join(root, normalized.lstrip(HOST_ROOT)))


def beneath(root, collection_path):
    """Re-apply the root to a path a domain built by joining onto a rooted path.

    The counterpart of `under` for the relative branch. A domain resolves a relative
    target against something already rooted - `dirname(parent)` for an include, the rooted
    home for an authorized-keys file - and the target may carry `..`. Those components
    escape exactly as the absolute ones did: under root `/fix`, a parent of
    `/fix/etc/sudoers` and a target of `../../tmp/x` produce `/fix/etc/../../tmp/x`, and
    that resolves to `/tmp/x` on the live host.

    The fix is to say what the host says: strip the root, and read the remainder as the
    host-absolute path it is. With root "/" this is `normpath`, which is precisely what
    the kernel would have done with the same string.
    """
    base = os.path.normpath(root)
    if base == HOST_ROOT:
        rest = collection_path
    elif collection_path == base:
        rest = HOST_ROOT
    elif collection_path.startswith(base + os.sep):
        rest = collection_path[len(base):]
    else:
        raise ValueError(
            "beneath() takes a path built from %r; %r was not, so stripping the root "
            "would invent a host path that was never declared" % (root, collection_path))
    return under(root, rest)


def contains(root, candidate):
    """Is `candidate` the same object as `root`, or inside it? Pure, lexical, by COMPONENT.

    Both must be absolute. This answers containment and nothing else: it does not resolve
    symlinks, touch the filesystem or decide WHICH containment the caller wants. A caller
    needing resolved-target containment calls realpath on both itself and passes the
    results here, which keeps the frozen distinction where it belongs:

        lexical containment != resolved-target containment != race-free acquisition

    IT IS NOT STRING-PREFIX ARITHMETIC, and that is the whole reason it exists. The
    previous implementations wrote `candidate.startswith(root + os.sep)`, which has two
    defects that pull in opposite directions:

        root "/"          ->  "//"  -> nothing matched, so at the PRODUCTION root the
                                       collector refused every path and read nothing
        root "/fixture"   ->  "/fixture/" is fine, but a naive `startswith(root)` without
                                       the separator accepts "/fixture-evil", a sibling
                                       whose name merely extends the root's

    Comparing components cannot express either bug.
    """
    if not root.startswith(HOST_ROOT) or not candidate.startswith(HOST_ROOT):
        raise ValueError(
            "contains() takes absolute paths; got root=%r candidate=%r" % (root, candidate))
    root_parts = _components(root)
    candidate_parts = _components(candidate)
    return candidate_parts[:len(root_parts)] == root_parts


def _components(path):
    """The path's components, normalised. '/' is the empty sequence."""
    return [part for part in os.path.normpath(path).split(os.sep) if part]
