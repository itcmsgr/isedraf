# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Ask the machine's own glibc what it makes of synthetic account files.
# Implements: GOV-002, IDENT-041
#
# TEST ORACLE ONLY (owner ruling N1/N2, 2026-09-26). Never imported by, shipped with or
# called from ISEDRAF. It runs inside `unshare -rm`, an unprivileged private user and
# mount namespace: each case's synthetic /etc/nsswitch.conf ("files" only), /etc/passwd,
# /etc/group and /etc/shadow are bind-mounted over the real ones inside that namespace
# and nothing on the host is read or changed. glibc is asked through its own interfaces -
# getpwent/getgrent/getspent enumeration and getpwnam/getgrnam/getspnam lookups - so the
# answers are glibc's behaviour, not a reimplementation of it. No glibc code is copied.
#
# Input (stdin): JSON list of cases {"id", "passwd", "group", "shadow", "nsswitch", "names"},
# file contents hex-encoded (exact bytes), "names" the lookup keys as hex.
# Output (stdout): JSON list of {"id", "passwd", "group", "shadow", "lookups"}.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private mount namespace and a private temporary directory"
# meta:binaries="python3,mount,umount"
# =============================================================================
"""glibc oracle driver: run inside `unshare -rm`."""
import ctypes
import grp
import json
import os
import pwd
import subprocess
import sys
import tempfile

LIBC = ctypes.CDLL("libc.so.6", use_errno=True)


class Spwd(ctypes.Structure):
    _fields_ = [("sp_namp", ctypes.c_char_p), ("sp_pwdp", ctypes.c_char_p),
                ("sp_lstchg", ctypes.c_long), ("sp_min", ctypes.c_long),
                ("sp_max", ctypes.c_long), ("sp_warn", ctypes.c_long),
                ("sp_inact", ctypes.c_long), ("sp_expire", ctypes.c_long),
                ("sp_flag", ctypes.c_ulong)]


LIBC.getspent.restype = ctypes.POINTER(Spwd)
LIBC.getspnam.restype = ctypes.POINTER(Spwd)
LIBC.getspnam.argtypes = [ctypes.c_char_p]


def _hex(b):
    return None if b is None else b.hex()


def _sp(p):
    s = p.contents
    return {"name": _hex(s.sp_namp), "password": _hex(s.sp_pwdp),
            "ageing": [s.sp_lstchg, s.sp_min, s.sp_max, s.sp_warn, s.sp_inact,
                       s.sp_expire]}


def _enc(s):
    """Exact bytes as hex; None stays None (glibc gives NULL fields for bare "+" lines)."""
    return None if s is None else s.encode("utf-8", "surrogateescape").hex()


def _pw(p):
    enc = _enc
    return {"name": enc(p.pw_name), "uid": p.pw_uid, "gid": p.pw_gid,
            "gecos": enc(p.pw_gecos), "home": enc(p.pw_dir), "shell": enc(p.pw_shell)}


def _gr(g):
    enc = _enc
    return {"name": enc(g.gr_name), "gid": g.gr_gid, "members": [enc(m) for m in g.gr_mem]}


def query(names):
    out = {"passwd": [_pw(p) for p in pwd.getpwall()],
           "group": [_gr(g) for g in grp.getgrall()],
           "shadow": [], "lookups": {}}
    LIBC.setspent()
    while True:
        p = LIBC.getspent()
        if not p:
            break
        out["shadow"].append(_sp(p))
    LIBC.endspent()
    for name_hex in names:
        raw = bytes.fromhex(name_hex)
        text = raw.decode("utf-8", "surrogateescape")
        entry = {}
        try:
            entry["passwd"] = _pw(pwd.getpwnam(text))
        except (KeyError, ValueError):
            entry["passwd"] = None
        # initgroups/getgrouplist: the path that decides a user's supplementary groups.
        # It does not skip "#" lines in /etc/group, unlike getgrent (final re-check R3-1).
        entry["grouplist"] = None
        if entry["passwd"] is not None and "\x00" not in text:
            try:
                entry["grouplist"] = sorted(os.getgrouplist(text, entry["passwd"]["gid"]))
            except (OSError, ValueError, TypeError):
                entry["grouplist"] = None
        try:
            entry["group"] = _gr(grp.getgrnam(text))
        except (KeyError, ValueError):
            entry["group"] = None
        p = LIBC.getspnam(raw) if b"\x00" not in raw else None
        entry["shadow"] = _sp(p) if p else None
        out["lookups"][name_hex] = entry
    return out


def _isolated(case):
    """Ask glibc in a fresh child process, so no glibc state survives into the next case.

    glibc keeps NSS backend streams open inside a process: under `*_compat: files` the
    included "map" is the local file itself, and a batch read the PREVIOUS case's file
    through a stream still open after its mount was lazily detached, so a real mismatch
    passed (red team pass 8, N1, found when a case failed alone and passed in the batch).
    The child exits before the parent unmounts, which also closes every stream it held.
    """
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:                                   # child: query, report, exit
        os.close(read_end)
        try:
            answer = query(case.get("names", []))
            answer["id"] = case["id"]
            payload = json.dumps(answer).encode()
        except Exception as exc:                   # reported, never swallowed
            payload = json.dumps({"id": case["id"], "error": repr(exc)}).encode()
        with os.fdopen(write_end, "wb") as out:
            out.write(payload)
        os._exit(0)
    os.close(write_end)
    with os.fdopen(read_end, "rb") as src:
        payload = src.read()
    _, status = os.waitpid(pid, 0)
    answer = json.loads(payload.decode())
    if status != 0 or "error" in answer:
        raise RuntimeError("oracle child failed for %s: %r" % (case["id"], answer))
    return answer


def main():
    cases = json.load(sys.stdin)
    work = tempfile.mkdtemp()
    results = []
    for case in cases:
        mounted = []
        # Each case carries its NSS configuration (owner ruling IQ-036); cases recorded
        # before the ruling ran under "files" for every database.
        nss = os.path.join(work, "nsswitch.conf")
        with open(nss, "wb") as fh:
            fh.write(bytes.fromhex(case["nsswitch"]) if "nsswitch" in case
                     else b"passwd: files\ngroup: files\nshadow: files\n")
        subprocess.check_call(["mount", "--bind", nss, "/etc/nsswitch.conf"])
        mounted.append("/etc/nsswitch.conf")
        for db in ("passwd", "group", "shadow"):
            path = os.path.join(work, db)
            with open(path, "wb") as fh:
                fh.write(bytes.fromhex(case[db]))
            subprocess.check_call(["mount", "--bind", path, "/etc/" + db])
            mounted.append("/etc/" + db)
        try:
            results.append(_isolated(case))
        finally:
            for target in reversed(mounted):
                subprocess.check_call(["umount", target])
    json.dump(results, sys.stdout)


if __name__ == "__main__":
    main()
