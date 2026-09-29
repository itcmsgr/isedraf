# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Differential testing of the account parser against glibc, as an executable rule.
# Implements: GOV-002, IDENT-041, IDENT-060, SCOPE-022
#
# Owner ruling N1/N2 (2026-09-26): stop closing libc corner cases one at a time. Every
# generated case is parsed by ISEDRAF and answered by glibc (tests/glibc_oracle_driver.py,
# run in an unprivileged private namespace), and the pair must satisfy:
#
#   glibc accepts + resolves X,  ISEDRAF resolves X                  PASS
#   glibc accepts + resolves X,  ISEDRAF explicitly PARTIAL/untrusted PASS (conservative)
#   glibc rejects,               ISEDRAF rejects / PARTIAL           PASS
#   glibc rejects,               ISEDRAF reports it PRESENT          FAIL
#   glibc resolves X,            ISEDRAF confidently resolves Y      FAIL
#
# "Confident" means evidence ISEDRAF presents as trustworthy: an account or group record
# with no per-record anomaly, a shadow relation of PRESENT or ABSENT_FROM_COLLECTED_SOURCE,
# and a source status of COLLECTED (which asserts the record list is complete).
#
# glibc is a TEST oracle: nothing here is imported by ISEDRAF. Cases and glibc's recorded
# answers are committed as a corpus, so the replay gate (test_glibc_differential.py) needs
# no namespace; `sweep` regenerates answers and records every mismatch as a new case.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3,unshare"
# =============================================================================
"""Differential account-parser testing against glibc."""
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))

from isedraf.accounts import acquire, model, sources            # noqa: E402
from isedraf.nss import acquire as nss_acquire                   # noqa: E402
from isedraf import canonical                                    # noqa: E402

CORPUS = os.path.join(HERE, "fixtures", "glibc_differential", "corpus.json")
ROOT_PASSWD = b"root:x:0:0:root:/root:/bin/sh\n"
ROOT_GROUP = b"root:x:0:\n"
ROOT_SHADOW = b"root:*:19000:0:99999:7:::\n"
# Owner ruling IQ-036: a case carries the NSS configuration that gives its lines meaning,
# and both sides read the same bytes. Cases recorded before the ruling ran under FILES.
FILES_NSSWITCH = b"passwd: files\ngroup: files\nshadow: files\n"
COMPAT_NSSWITCH = b"passwd: compat\ngroup: compat\nshadow: compat\n"


def nsswitch_of(case):
    return bytes.fromhex(case["nsswitch"]) if "nsswitch" in case else FILES_NSSWITCH


# --- ISEDRAF side ---------------------------------------------------------------------------
def isedraf(case):
    base = tempfile.mkdtemp()
    try:
        os.mkdir(os.path.join(base, "etc"))
        for db in ("passwd", "group", "shadow"):
            with open(os.path.join(base, "etc", db), "wb") as fh:
                fh.write(bytes.fromhex(case[db]))
        with open(os.path.join(base, "etc", "nsswitch.conf"), "wb") as fh:
            fh.write(nsswitch_of(case))
        # The same path production uses: NSS evidence -> explicit context -> collect.
        nss = nss_acquire.collect(base)
        return acquire.collect(base, nss_context=acquire.compat_context(nss),
                               effectiveness=acquire.file_effectiveness(nss))
    finally:
        shutil.rmtree(base)


def _member_bytes(member):
    if member.startswith("hex:"):
        return bytes.fromhex(member[4:])
    return member.encode("utf-8", "surrogateescape")


def _text_bytes(value):
    """A record field's exact bytes; "hex:<bytes>" is the form for non-UTF-8 text."""
    return b"" if value is None else _member_bytes(value)


# --- comparison -----------------------------------------------------------------------------
def file_passes(case, database):
    """How many times glibc enumerates /etc/<database> under the case's nsswitch.conf.

    `files` and `compat` both read the local file, so "passwd: files compat" lists every
    local entry twice (measured). Undeclared databases use glibc's default, one pass here.
    Modelling this is the NSS-aware comparison IQ-036 asks for, not a relaxation: the
    expected enumeration is exact.
    """
    for line in nsswitch_of(case).decode("utf-8", "replace").split("\n"):
        key, sep, rest = line.partition(":")
        if sep and key.strip() == database:
            words = [w for w in rest.replace("[", " [").split() if not w.startswith("[")]
            return max(1, sum(1 for w in words if w in ("files", "compat")))
    return 1


def plain_nsswitch(case):
    """Every line `db: service...` with known services, no brackets, no duplicate db."""
    from isedraf.nss import model as nss_model
    seen = set()
    for line in nsswitch_of(case).decode("utf-8", "replace").split("\n"):
        if not line.strip():
            continue
        key, sep, rest = line.partition(":")
        words = rest.split()
        if (not sep or key.strip() in seen or "[" in rest or not words
                or any(nss_model.classify(w) == nss_model.UNKNOWN for w in words)):
            return False
        seen.add(key.strip())
    return True


def declared_services(case, database):
    """The service words of the case's (single) line for `database`, or None."""
    found = []
    for line in nsswitch_of(case).decode("utf-8", "replace").split("\n"):
        key, sep, rest = line.partition(":")
        if sep and key.strip() == database:
            found.append([w for w in rest.replace("[", " [").replace("]", "] ").split()
                          if not (w.startswith("[") or w.endswith("]"))])
    return found[0] if len(found) == 1 else None


def compare(case, oracle, result=None):
    """A list of rule violations; empty means the pair satisfies the owner's table."""
    if result is None:
        try:
            result = isedraf(case)
        except Exception as exc:          # a crash is a failure to report, not to hide
            return ["CRASH collect(): %s" % type(exc).__name__]
    r = result
    failures = []
    try:
        canonical.canonical_bytes(r)
    except Exception as exc:
        failures.append("NOT_SERIALIZABLE evidence: %s" % type(exc).__name__)
    status = r["sources"]

    # Owner ruling IQ-037: two dimensions, compared separately.
    #   A. file collection fidelity - what the file holds (the checks below);
    #   B. effective resolution - whether glibc consults the file at all.
    # glibc's answers speak about the file only where ISEDRAF says the file is ACTIVE.
    # INACTIVE must mean glibc resolves nothing from it; NOT_ASSERTED claims neither.
    eff = r["nss_file_effectiveness"]
    active = lambda rel, key="files_effective": eff[rel][key] == model.FILES_ACTIVE
    for rel, db in (("etc/passwd", "passwd"), ("etc/group", "group")):
        # Guard against hiding behind NOT_ASSERTED: on a plain configuration (every line
        # a known service list, no brackets, no duplicates) a files/compat database must
        # be ACTIVE. An unsupported configuration answered NOT_ASSERTED is a PASS.
        declared = declared_services(case, db)
        if plain_nsswitch(case) and declared and set(declared) <= {"files", "compat"} \
                and eff[rel]["files_effective"] != model.FILES_ACTIVE:
            failures.append("UNDERCLAIM %s: nsswitch declares %r but ISEDRAF says %s"
                            % (db, declared, eff[rel]["files_effective"]))
    if eff["etc/passwd"]["files_effective"] == model.FILES_INACTIVE and oracle["passwd"]:
        failures.append("FALSE_INACTIVE passwd: glibc lists %d entries" % len(oracle["passwd"]))
    if eff["etc/group"]["files_effective"] == model.FILES_INACTIVE and oracle["group"]:
        failures.append("FALSE_INACTIVE group: glibc lists %d entries" % len(oracle["group"]))

    # Python's pwd/grp report (uid_t)-1 as -1; it is the unsigned value 4294967295.
    u32 = lambda v: v & 0xFFFFFFFF
    hx = lambda v: b"" if v is None else bytes.fromhex(v)
    g_passwd = [(hx(p["name"]), u32(p["uid"]), u32(p["gid"]), hx(p["gecos"]),
                 hx(p["home"]), hx(p["shell"]))
                for p in oracle["passwd"]]
    confident = [(bytes.fromhex(a["name_bytes_hex"] or ""), a["uid"], a["primary_gid"],
                  _text_bytes(a["gecos"]), _text_bytes(a["home"]), _text_bytes(a["shell"]))
                 for a in r["local_accounts"] if not a["passwd_anomalies"]]
    for acct in (confident if active("etc/passwd") else []):
        if acct not in g_passwd:
            failures.append("FALSE_PRESENT passwd %r: glibc has no such entry" % (acct,))
    if (active("etc/passwd") and status["etc/passwd"]["status"] == model.COLLECTED
            and confident * file_passes(case, "passwd") != g_passwd):
        failures.append("FALSE_COMPLETE passwd: COLLECTED %r but glibc lists %r"
                        % (confident, g_passwd))

    g_group = [(hx(g["name"]), u32(g["gid"]),
                [hx(m) for m in g["members"]]) for g in oracle["group"]]
    confident_g = [(bytes.fromhex(g["name_bytes_hex"] or ""), g["gid"],
                    [_member_bytes(m) for m in g["explicit_members"]])
                   for g in r["local_groups"] if not g["group_anomalies"]]
    for grp_ in (confident_g if active("etc/group") else []):
        if grp_ not in g_group:
            failures.append("FALSE_PRESENT group %r: glibc has no such entry" % (grp_,))
    if (active("etc/group") and status["etc/group"]["status"] == model.COLLECTED
            and confident_g * file_passes(case, "group") != g_group):
        failures.append("FALSE_COMPLETE group: COLLECTED %r but glibc lists %r"
                        % (confident_g, g_group))

    # initgroups/getgrouplist decides supplementary groups, and it does not skip "#" lines
    # in /etc/group (final re-check R3-1). Where the group source claims completeness, the
    # memberships ISEDRAF can derive for a confident account must equal glibc's.
    # Every confident membership must be one initgroups grants (pass 8, N3): an
    # overclaim is checked even when the group source is PARTIAL.
    if active("etc/group", "initgroups_files_effective") and active("etc/passwd"):
        for a in r["local_accounts"]:
            key = a["name_bytes_hex"] or ""
            looked = oracle["lookups"].get(key)
            if a["passwd_anomalies"] or not looked or looked.get("grouplist") is None:
                continue
            granted = set(v & 0xFFFFFFFF for v in looked["grouplist"])
            name = bytes.fromhex(key)
            for g in r["local_groups"]:
                if (not g["group_anomalies"] and g["gid"] not in granted
                        and name in [_member_bytes(m) for m in g["explicit_members"]]):
                    failures.append("FALSE_PRESENT membership %r in gid %r: getgrouplist "
                                    "does not grant it" % (key, g["gid"]))
    group_complete = (status["etc/group"]["status"] == model.COLLECTED
                      and active("etc/group", "initgroups_files_effective")
                      and active("etc/passwd"))
    for a in r["local_accounts"]:
        if a["passwd_anomalies"] or not group_complete:
            continue
        key = a["name_bytes_hex"] or ""
        looked = oracle["lookups"].get(key)
        if not looked or looked.get("grouplist") is None:
            continue
        name = bytes.fromhex(key)
        # The base gid is the one glibc was handed (getpwnam's, the first record for the
        # name), so this compares group membership only; passwd itself is compared above.
        base = looked["passwd"]["gid"] & 0xFFFFFFFF
        mine = sorted(set([base] + [
            g["gid"] for g in r["local_groups"] if not g["group_anomalies"]
            and name in [_member_bytes(m) for m in g["explicit_members"]]]))
        theirs = sorted(set(v & 0xFFFFFFFF for v in looked["grouplist"]))
        if mine != theirs:
            failures.append("FALSE_COMPLETE initgroups for %r: group source COLLECTED gives "
                            "%r, glibc getgrouplist gives %r" % (key, mine, theirs))

    # Keyed lookups (red team pass 7, F2/F6): a confident record is one glibc resolves BY
    # NAME, not only one enumeration lists. Under compat an EXCLUDE before a local line
    # leaves it enumerated but unresolvable by name.
    first_seen = set()
    for a in r["local_accounts"]:
        key = a["name_bytes_hex"] or ""
        if a["passwd_anomalies"] or key in first_seen or not active("etc/passwd"):
            continue
        first_seen.add(key)
        looked = oracle["lookups"].get(key)
        if looked is not None and looked["passwd"] is None:
            failures.append("FALSE_PRESENT keyed passwd %r: glibc getpwnam finds nothing" % key)
        elif looked is not None:
            # The value too (pass 8, N2): glibc resolves the FIRST line it accepts, which
            # may be one ISEDRAF rejected; a confident later record must not stand in.
            p = looked["passwd"]
            mine = (a["uid"], a["primary_gid"])
            theirs = (p["uid"] & 0xFFFFFFFF, p["gid"] & 0xFFFFFFFF)
            if mine != theirs:
                failures.append("WRONG_LOOKUP passwd %r: ISEDRAF %r, getpwnam %r"
                                % (key, mine, theirs))
    first_seen = set()
    for g in r["local_groups"]:
        key = g["name_bytes_hex"] or ""
        if g["group_anomalies"] or key in first_seen or not active("etc/group"):
            continue
        first_seen.add(key)
        looked = oracle["lookups"].get(key)
        if looked is not None and looked.get("group") is None:
            failures.append("FALSE_PRESENT keyed group %r: glibc getgrnam finds nothing" % key)
        elif looked is not None and (looked["group"]["gid"] & 0xFFFFFFFF) != g["gid"]:
            failures.append("WRONG_LOOKUP group %r: ISEDRAF gid %r, getgrnam %r"
                            % (key, g["gid"], looked["group"]["gid"] & 0xFFFFFFFF))

    for a in r["local_accounts"]:
        # Empty names are compared too (final re-check R3-2).
        if a["passwd_anomalies"] or not (active("etc/shadow") and active("etc/passwd")):
            continue
        looked = oracle["lookups"].get(a["name_bytes_hex"] or "")
        if looked is None:
            continue
        g_sp = looked["shadow"]
        rel = a["shadow_record"]
        if rel == model.RECORD_PRESENT:
            if g_sp is None:
                failures.append("FALSE_PRESENT shadow for %r: glibc getspnam finds nothing"
                                % (a["name_bytes_hex"] or ""))
                continue
            s = a["shadow"]
            expect_pw = sources._password_state(
                bytes.fromhex(g_sp["password"]).decode("utf-8", "surrogateescape"))
            if s["password_state"] != expect_pw:
                failures.append("WRONG_JOIN shadow for %r: password state %r, glibc's "
                                "record gives %r" % (a["name_bytes_hex"],
                                                     s["password_state"], expect_pw))
            fields = ("last_change_days", "min_days", "max_days", "warn_days",
                      "inactive_days", "expire_days")
            mine = [-1 if s[f] is None else s[f] for f in fields]
            if mine != g_sp["ageing"]:
                failures.append("WRONG_JOIN shadow ageing for %r: %r, glibc %r"
                                % (a["name_bytes_hex"], mine, g_sp["ageing"]))
        elif rel == model.RECORD_ABSENT_FROM_COLLECTED_SOURCE and g_sp is not None:
            failures.append("FALSE_ABSENT shadow for %r: glibc getspnam finds a record"
                            % (a["name_bytes_hex"] or ""))
    return failures


# --- generation -----------------------------------------------------------------------------
PREFIXES = [b"", b" ", b"\t", b"\v", b"\f", b"\r", b"\xc2\xa0", b"\xe2\x80\xa8", b"\x1c"]
NAMES = [b"alice", b"bob", b"a b", b"+alice", b"-alice", b"+", b"al\xffce", b"#x", b"",
         b"root", b"alice$6$s$h"]
IDS = [b"0", b"1000", b"+0", b" 0", b"-0", b"-1", b"00", b"4294967295", b"4294967296",
       b"abc", b"", b" 1", b"1 ", b"1e3", b"0" * 40 + b"7"]
TRAILERS = [b"", b"\r", b" ", b":extra", b"\x00junk"]
AGEING = [b"", b"0", b"19000", b"-1", b"-0", b"-5", b"+3", b" 3", b"3 ", b"5x",
          b"2147483647", b"2147483648", b"4294967295"]
PASSWORDS = [b"*", b"!", b"x", b"", b"!$6$s$h", b"$6$s$h", b"$y$j$abc"]
MEMBERS = [b"", b"alice", b" alice", b"alice ", b"alice,bob", b", bob", b"alice,,bob",
           b"\talice,\vbob", b"al\xffce"]


def _case(cid, passwd=b"", group=b"", shadow=b"", nsswitch=FILES_NSSWITCH):
    return {"id": cid, "passwd": (ROOT_PASSWD + passwd).hex(),
            "group": (ROOT_GROUP + group).hex(), "shadow": (ROOT_SHADOW + shadow).hex(),
            "nsswitch": nsswitch.hex()}


def generate(seed=20260926, random_count=400):
    """Deterministic: one-factor variation of every dimension, then seeded combinations."""
    cases = []
    base_pw = [b"alice", b"x", b"1000", b"1000", b"A", b"/home/a", b"/bin/sh"]
    for i, prefix in enumerate(PREFIXES):
        for eol in (b"\n", b""):
            line = prefix + b":".join(base_pw) + eol
            cases.append(_case("pw-prefix-%d-%s" % (i, "eol" if eol else "noeol"), line))
    for i, name in enumerate(NAMES):
        cases.append(_case("pw-name-%d" % i, name + b":x:1000:1000::/h:/bin/sh\n"))
        # The same name in shadow: glibc's lookups refuse "+"/"-" names in files mode
        # while enumeration lists them (found by the seeded sweep, made deterministic).
        cases.append(_case("sh-name-%d" % i, name + b":x:1000:1000::/h:/bin/sh\n",
                           shadow=name + b":$6$s$h:19000:0:99999:7:::\n"))
    for i, uid in enumerate(IDS):
        cases.append(_case("pw-uid-%d" % i, b"alice:x:" + uid + b":1000::/h:/bin/sh\n"))
        cases.append(_case("pw-gid-%d" % i, b"alice:x:1000:" + uid + b"::/h:/bin/sh\n"))
        cases.append(_case("gr-gid-%d" % i, group=b"wheel:x:" + uid + b":alice\n"))
    for i, t in enumerate(TRAILERS):
        cases.append(_case("pw-trailer-%d" % i, b"alice:x:1000:1000::/h:/bin/sh" + t + b"\n"))
        cases.append(_case("sh-trailer-%d" % i,
                           b"alice:x:1000:1000::/h:/bin/sh\n",
                           shadow=b"alice:*:19000:0:99999:7:::" + t + b"\n"))
    for i, m in enumerate(MEMBERS):
        cases.append(_case("gr-members-%d" % i, b"alice:x:1000:1000::/h:/bin/sh\n"
                           b"bob:x:1001:1001::/h:/bin/sh\n", group=b"wheel:x:10:" + m + b"\n"))
    # Group-side lines (final re-check): comments that initgroups still reads, blank and
    # Unicode prefixes, no final newline, bare compat lines, and empty names everywhere.
    two_users = b"alice:x:1000:1000::/h:/bin/sh\nbob:x:1001:1001::/h:/bin/sh\n"
    for i, prefix in enumerate(PREFIXES):
        for j, body in enumerate((b"wheel:x:10:alice", b"#wheel:x:10:alice",
                                  b"# wheel:x:0:alice", b"#")):
            for eol in (b"\n", b""):
                cases.append(_case("gr-line-%d-%d-%s" % (i, j, "eol" if eol else "noeol"),
                                   two_users, group=prefix + body + eol))
    for i, bare in enumerate((b"+", b"-", b"+:", b"+::::::", b"-::::::")):
        cases.append(_case("bare-%d" % i, bare + b"\n", group=bare + b"\n",
                           shadow=bare + b"\n"))
    cases.append(_case("empty-name", b":x:0:0::/h:/bin/sh\n",
                       shadow=b":$6$s$h:19000:0:99999:7:::\n"))
    # IQ-036: the same compat-shaped lines under each NSS mode. glibc is asked with the
    # case's own nsswitch.conf; "compat" has no NIS behind it here, so glibc can only show
    # what the local lines contribute, which is exactly what ISEDRAF claims locally.
    modes = (("cp", COMPAT_NSSWITCH),
             ("mix", b"passwd: compat\ngroup: files\nshadow: files\n"),
             ("amb", b"passwd: files compat\ngroup: files\nshadow: files\n"),
             ("undecl", b"hosts: files\n"))
    for tag, nss in modes:
        for i, name in enumerate(NAMES):
            cases.append(_case("%s-name-%d" % (tag, i), name + b":x:1000:1000::/h:/bin/sh\n",
                               shadow=name + b":!:19000::::::\n", nsswitch=nss))
        for i, bare in enumerate((b"+", b"-", b"+:", b"+::::::", b"-::::::", b"+@ng::::::")):
            cases.append(_case("%s-bare-%d" % (tag, i),
                               bare + b"\nalice:x:1000:1000::/h:/bin/sh\n",
                               group=bare + b"\n", shadow=bare + b"\n", nsswitch=nss))
        cases.append(_case("%s-exclude-before-local" % tag,
                           b"-alice::::::\nalice:x:1000:1000::/h:/bin/sh\n", nsswitch=nss))
    # Red team pass 7: the NSS topology around compat, and compat lines around local ones.
    alice = b"alice:x:1000:1000::/h:/bin/sh\n"
    nss_variants = [
        b"passwd: compat\ngroup: compat\ninitgroups: files\nshadow: compat\n",
        b"passwd: compat\ngroup: compat\ninitgroups: files [SUCCESS=continue]\nshadow: compat\n",
        b"passwd: compat\ngroup: compat\ninitgroups: sss files\nshadow: compat\n",
        b"passwd: compat\ngroup: compat\ninitgroups: compat\nshadow: compat\n",
        b"passwd: files\npasswd: compat\ngroup: compat\nshadow: compat\n",
        b"passwd: compat\npasswd: files\ngroup: files\nshadow: files\n",
        b"passwd: compat [NOTFOUND=return][UNAVAIL=return]\ngroup: compat\nshadow: compat\n",
        b"passwd: compat [NOTFOUND=return]\ngroup: compat [NOTFOUND=return]\nshadow: compat\n",
        b"passwd: sss compat\ngroup: sss compat\nshadow: compat\n",
        # Owner ruling IQ-037: databases NSS may not read from the file at all.
        b"passwd: Compat\ngroup: compat\nshadow: compat\n",
        b"passwd: sss\ngroup: sss\nshadow: sss\n",
        b"passwd: ldap\ngroup: files\nshadow: files\n",
        b"passwd: sss files\ngroup: sss files\nshadow: files\n",
        b"passwd: extrausers files\ngroup: files\nshadow: files\n",
        b"passwd: files\ngroup: files\ninitgroups: sss\nshadow: files\n",
        b"passwd: files\ngroup: sss\ninitgroups: files\nshadow: files\n",
        # Red team pass 8: *_compat naming a file-reading service (N1), and the mirror of
        # F1 (N3).
        b"passwd: compat\npasswd_compat: files\ngroup: compat\ngroup_compat: files\n"
        b"shadow: compat\nshadow_compat: files\n",
        b"passwd: compat\npasswd_compat: sss\ngroup: compat\ngroup_compat: sss\n"
        b"shadow: compat\n",
        b"passwd: files\ngroup: files\ninitgroups: compat\nshadow: files\n",
    ]
    layouts = [
        ("grp-inc", alice, b"+wheel:x:0:alice\n", b""),
        ("grp-all", alice, b"+:::alice\n", b""),
        ("grp-exc", alice, b"-wheel:x:0:alice\n", b""),
        ("pw-exc-local", b"-alice\n" + alice, b"", b""),
        ("pw-exc6-local", b"-alice::::::\n" + alice, b"", b""),
        ("pw-exc-other", b"-bob\n" + alice, b"", b""),
        ("pw-excng-local", b"-@ng::::::\n" + alice, b"", b""),
        ("pw-incng-local", b"+@ng::::::\n" + alice, b"", b""),
        ("pw-inc-local", b"+\n" + alice, b"", b""),
        ("pw-local-inc", alice + b"+::::::\n", b"", b""),
        ("sh-exc-local", alice, b"", b"-alice\nalice:$6$s$h:1:2:3:4:::\n"),
        ("sh-inc-local", alice, b"", b"+alice\nalice:$6$s$h:1:2:3:4:::\n"),
        ("sh-all-local", alice, b"", b"+\nalice:$6$s$h:1:2:3:4:::\n"),
        ("gr-exc-local", alice, b"-wheel\nwheel:x:10:alice\n", b""),
        ("gr-inc-local", alice, b"+\nwheel:x:10:alice\n", b""),
        ("pw-odd-home", b"+alice:x::::/home/j\xf6rg:/bin/sh\n" + alice, b"", b""),
        ("pw-odd-gecos", b"+alice:x:::J\xf6rg::\n", b"", b""),
        ("gr-odd-member", alice, b"+wheel:x::j\xf6rg\n", b""),
        # Red team pass 8.
        ("pw-local-all", alice + b"+::::::\n", b"wheel:x:10:alice\n+:::\n",
         b"alice:!:1:2:3:4:::\n+::::::::\n"),
        ("gr-inc-member", alice, b"+\nwheel:x:10:alice\n", b""),
        ("pw-malformed-first", b"alice:x:0:0::/r:/bin/sh:extra\n" + alice, b"", b""),
        ("pw-short-first", b"alice:x:0:0::/r\n" + alice, b"", b""),
        ("gr-malformed-first", alice, b"wheel:x:0:alice:extra\nwheel:x:10:bob\n", b""),
        ("pw-odd-gecos-rec", b"zed:x:1:1:G\xf6:/h:/bin/sh\n", b"", b""),
        ("pw-odd-home-rec", b"zed:x:1:1::/h\xff:/bin/sh\n", b"", b""),
        ("pw-odd-shell-rec", b"zed:x:1:1::/h:/bin/\xff\n", b"", b""),
    ]
    for n, nss in enumerate([COMPAT_NSSWITCH] + nss_variants):
        for tag, pw, gr, sh in layouts:
            cases.append(_case("p7-%d-%s" % (n, tag), pw, group=gr, shadow=sh, nsswitch=nss))
    for f in range(7):
        for j, v in enumerate(AGEING):
            fields = [b"19000", b"0", b"99999", b"7", b"", b"", b""]
            fields[f] = v
            cases.append(_case("sh-age-%d-%d" % (f, j), b"alice:x:1000:1000::/h:/bin/sh\n",
                               shadow=b"alice:*:" + b":".join(fields) + b"\n"))
    for i, (bad, good) in enumerate(itertools.product(AGEING, PASSWORDS)):
        # A candidate line then a valid duplicate: the join must follow glibc's first
        # ACCEPTED record, whatever ISEDRAF thinks of the first one.
        first = b"alice:$6$FIRST$h:19000:0:" + bad + b":7:::\n"
        second = b"alice:" + good + b":19000:0:99999:7:::\n"
        cases.append(_case("sh-dup-%d" % i, b"alice:x:1000:1000::/h:/bin/sh\n",
                           shadow=first + second))
    rnd = random.Random(seed)
    for i in range(random_count):
        name = rnd.choice(NAMES)
        line = (rnd.choice(PREFIXES) + name + b":" + rnd.choice(PASSWORDS) + b":" +
                rnd.choice(IDS) + b":" + rnd.choice(IDS) + b"::/h:/bin/sh" +
                rnd.choice(TRAILERS) + rnd.choice([b"\n", b""]))
        sh = (rnd.choice(PREFIXES) + name + b":" + rnd.choice(PASSWORDS) + b":" +
              b":".join(rnd.choice(AGEING) for _ in range(6)) + b":" +
              rnd.choice([b"", b"0", b"\r", b" "]) + rnd.choice([b"\n", b""]))
        gr = rnd.choice(PREFIXES) + b"wheel:x:" + rnd.choice(IDS) + b":" + rnd.choice(MEMBERS)
        cases.append(_case("rnd-%d-%d" % (seed, i), line + b"\n", group=gr + b"\n",
                           shadow=sh + b"\n"))
    return cases


def _with_names(case):
    try:
        r = isedraf(case)
    except Exception:
        case = dict(case)
        case["names"] = []
        return case
    names = sorted(set(a["name_bytes_hex"] or "" for a in r["local_accounts"]) |
                   set(g["name_bytes_hex"] or "" for g in r["local_groups"]))
    case = dict(case)
    case["names"] = names
    return case


def ask_glibc(cases):
    """Run the oracle driver in an unprivileged private namespace. Test-time only."""
    driver = os.path.join(HERE, "glibc_oracle_driver.py")
    env = dict(os.environ, LC_ALL="C", LANG="C")        # pinned, not inherited (R3)
    out = subprocess.run(["unshare", "-rm", sys.executable, "-B", driver],
                         input=json.dumps(cases).encode(), stdout=subprocess.PIPE,
                         check=True, env=env).stdout
    return {r["id"]: r for r in json.loads(out.decode())}


def sweep(seed=20260926, random_count=400, write_corpus=False):
    cases = [_with_names(c) for c in generate(seed, random_count)]
    answers = ask_glibc(cases)
    failing = []
    for case in cases:
        problems = compare(case, answers[case["id"]])
        if problems:
            failing.append((case["id"], problems))
    if write_corpus:
        os.makedirs(os.path.dirname(CORPUS), exist_ok=True)
        with open(CORPUS, "w") as fh:
            json.dump([{"case": c, "glibc": answers[c["id"]]} for c in cases], fh,
                      sort_keys=True, separators=(",", ":"))
            fh.write("\n")
    return cases, failing


if __name__ == "__main__":
    write = "--write-corpus" in sys.argv

    def option(flag, default):
        return int(sys.argv[sys.argv.index(flag) + 1]) if flag in sys.argv else default
    # The big sweep: --seed N --random COUNT. The recorded corpus uses the defaults.
    cases, failing = sweep(seed=option("--seed", 20260926),
                           random_count=option("--random", 400), write_corpus=write)
    for cid, problems in failing:
        print("FAIL %s" % cid)
        for p in problems:
            print("     %s" % p[:300])
    print("differential sweep: %d cases, %d failing" % (len(cases), len(failing)))
    sys.exit(1 if failing else 0)
