# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The NSS topology lane contract, asserted before the collector existed.
# Implements: IDENT-040, IDENT-041, CMP-020, SCOPE-022, SCOPE-045
#
# Written from docs/development/NSS_HOSTNAME_LANE_CONTRACT.md and nsswitch.conf(5) before
# lib/isedraf/nss/ was written. Every NSS line here is synthetic. No test reads the live
# /etc/nsswitch.conf except the production-root cases, which assert structure only.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3"
# =============================================================================

"""The NSS topology evidence contract."""
import ast
import hashlib
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "lib")
sys.path.insert(0, LIB)

from isedraf import canonical                                   # noqa: E402
from isedraf.accounts import acquire as accounts                # noqa: E402
from isedraf.accounts import model as account_model             # noqa: E402
from isedraf.nss import acquire, model, sources                 # noqa: E402

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n")
GROUP = "root:x:0:\nalice:x:1000:\n"
SHADOW = "root:*:19000:0:99999:7:::\nalice:!:19500:0:99999:7:::\n"


def tree(**files):
    """A hermetic fixture root. Only what is written here exists."""
    base = tempfile.mkdtemp()
    os.mkdir(os.path.join(base, "etc"))
    for name, text in files.items():
        with open(os.path.join(base, "etc", name), "w") as fh:
            fh.write(text)
    return base


def parse(text):
    return sources.parse_nsswitch(text)


def line_of(text, database="passwd"):
    return [r for r in parse(text).records if r["database"] == database][0]


def services(text, database="passwd"):
    return [e["service"] for e in line_of(text, database)["entries"]]


class OrderAndActions(unittest.TestCase):
    """Order and action clauses are resolver semantics, never set membership."""

    def test_files(self):
        self.assertEqual(services("passwd: files\n"), ["files"])

    def test_order_is_kept(self):
        self.assertEqual(services("passwd: files sss\n"), ["files", "sss"])
        self.assertEqual(services("passwd: sss files\n"), ["sss", "files"])

    def test_opposite_orders_are_not_equal(self):
        self.assertNotEqual(line_of("passwd: files sss\n")["entries"],
                            line_of("passwd: sss files\n")["entries"])

    def test_an_action_attaches_to_the_service_before_it(self):
        entries = line_of("passwd: files [NOTFOUND=return] sss\n")["entries"]
        self.assertEqual([e["service"] for e in entries], ["files", "sss"])
        self.assertEqual(entries[0]["actions"],
                         [{"negated": False, "status": "notfound", "action": "return"}])
        self.assertEqual(entries[1]["actions"], [])

    def test_an_action_clause_changes_equality(self):
        self.assertNotEqual(line_of("passwd: files sss\n")["entries"],
                            line_of("passwd: files [NOTFOUND=return] sss\n")["entries"])

    def test_negation_is_kept(self):
        a = line_of("hosts: dns [!UNAVAIL=return] files\n", "hosts")["entries"][0]["actions"]
        self.assertEqual(a, [{"negated": True, "status": "unavail", "action": "return"}])
        self.assertNotEqual(
            line_of("passwd: files [!NOTFOUND=return] sss\n")["entries"],
            line_of("passwd: files [NOTFOUND=return] sss\n")["entries"])

    def test_two_pairs_in_one_bracket_keep_their_order(self):
        a = line_of("passwd: files [NOTFOUND=return SUCCESS=continue] sss\n")
        self.assertEqual([(x["status"], x["action"]) for x in a["entries"][0]["actions"]],
                         [("notfound", "return"), ("success", "continue")])

    def test_keywords_are_case_insensitive_and_lowered(self):
        a = line_of("passwd: files [NotFound=Return] sss\n")["entries"][0]["actions"]
        self.assertEqual(a, [{"negated": False, "status": "notfound", "action": "return"}])

    def test_service_names_are_kept_verbatim(self):
        self.assertEqual(services("passwd: Files\n"), ["Files"])

    def test_merge_is_a_known_action(self):
        r = line_of("group: files [SUCCESS=merge] sss\n", "group")
        self.assertEqual(r["semantics"], model.KNOWN)


class SyntaxNormalization(unittest.TestCase):

    def test_comments_tabs_and_blank_lines(self):
        p = parse("# header\n\npasswd:\tfiles\t sss   # trailing\n")
        self.assertEqual(len(p.records), 1)
        self.assertEqual(services("passwd:\tfiles\t sss   # trailing\n"), ["files", "sss"])
        self.assertEqual(p.anomalies, [])

    def test_raw_line_is_retained_without_the_comment(self):
        r = line_of("passwd: files sss # c\n")
        self.assertEqual(r["raw"], "passwd: files sss")
        self.assertEqual(r["line"], 1)


class UnsupportedIsPreservedNotNormalized(unittest.TestCase):

    def test_unknown_status_is_unsupported_and_retained(self):
        r = line_of("passwd: files [MAYBE=return] sss\n")
        self.assertEqual(r["semantics"], model.UNSUPPORTED)
        self.assertEqual(r["raw"], "passwd: files [MAYBE=return] sss")
        self.assertTrue(parse("passwd: files [MAYBE=return] sss\n").anomalies)

    def test_unknown_action_is_unsupported(self):
        self.assertEqual(line_of("passwd: files [NOTFOUND=explode]\n")["semantics"],
                         model.UNSUPPORTED)

    def test_a_bracket_before_any_service_is_unsupported(self):
        self.assertEqual(line_of("passwd: [NOTFOUND=return] files\n")["semantics"],
                         model.UNSUPPORTED)

    def test_an_unclosed_bracket_is_unsupported(self):
        self.assertEqual(line_of("passwd: files [NOTFOUND=return sss\n")["semantics"],
                         model.UNSUPPORTED)

    def test_a_line_with_no_colon_is_retained_as_unsupported(self):
        # Corrected by red-team F3: glibc honours "passwd files", so it is a database line
        # this lane cannot fully interpret, not a line to drop.
        r = line_of("passwd files\n")
        self.assertEqual(r["semantics"], model.UNSUPPORTED)
        self.assertTrue(parse("passwd files\n").anomalies)


class Classification(unittest.TestCase):
    """The closed vocabulary. UNKNOWN is never assumed local."""

    CASES = {"files": model.LOCAL_FILES, "compat": model.COMPAT,
             "systemd": model.LOCAL_NON_FILES, "myhostname": model.LOCAL_NON_FILES,
             "sss": model.REMOTE_DIRECTORY, "ldap": model.REMOTE_DIRECTORY,
             "winbind": model.REMOTE_DIRECTORY, "nis": model.REMOTE_DIRECTORY,
             "dns": model.RESOLVER, "resolve": model.RESOLVER,
             "mdns4_minimal": model.RESOLVER, "altfiles": model.UNKNOWN,
             "Files": model.UNKNOWN}

    def test_every_documented_service(self):
        for service, cls in self.CASES.items():
            self.assertEqual(model.classify(service), cls, service)

    def test_the_entry_carries_its_class(self):
        self.assertEqual(line_of("passwd: files sss\n")["entries"][1]["class"],
                         model.REMOTE_DIRECTORY)


class Collection(unittest.TestCase):
    """SCOPE-022 per source, with the absent and duplicate cases the contract names."""

    def collect(self, **files):
        root = tree(**files)
        self.addCleanup(shutil.rmtree, root)
        return acquire.collect(root)

    def test_a_plain_file_is_collected(self):
        r = self.collect(**{"nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\n"})
        self.assertEqual(r["status"], model.COLLECTED, r["reason"])

    def test_an_absent_file_is_not_tested_and_asserts_no_default(self):
        r = self.collect()
        self.assertEqual(r["status"], model.NOT_TESTED)
        self.assertIn("SOURCE_ABSENT", r["reason"])
        self.assertEqual(r["undeclared_identity_databases"],
                         {"passwd": model.DEFAULT_NOT_ASSERTED,
                          "group": model.DEFAULT_NOT_ASSERTED,
                          "shadow": model.DEFAULT_NOT_ASSERTED})

    def test_an_absent_database_line_is_default_not_asserted(self):
        r = self.collect(**{"nsswitch.conf": "passwd: files\n"})
        self.assertEqual(r["undeclared_identity_databases"],
                         {"group": model.DEFAULT_NOT_ASSERTED,
                          "shadow": model.DEFAULT_NOT_ASSERTED})
        self.assertNotIn("group", [x["database"] for x in r["identity_nss_topology"]])

    def test_a_duplicated_database_keeps_both_and_is_partial(self):
        r = self.collect(**{"nsswitch.conf": "passwd: files\npasswd: sss\n"})
        self.assertEqual(r["status"], model.PARTIAL)
        self.assertEqual([x["database"] for x in r["records"]], ["passwd", "passwd"])

    def test_unsupported_semantics_are_partial(self):
        r = self.collect(**{"nsswitch.conf": "passwd: files [MAYBE=return] sss\n"})
        self.assertEqual(r["status"], model.PARTIAL)

    def test_a_database_glibc_does_not_know_is_retained(self):
        r = self.collect(**{"nsswitch.conf": "passwd: files\nsudoers: files\n"})
        self.assertIn("sudoers", [x["database"] for x in r["records"]])
        self.assertEqual(r["status"], model.COLLECTED, r["reason"])

    def test_iq037_an_unknown_identity_service_is_partial_and_retained(self):
        # Owner ruling IQ-037: an unknown or unsupported service token leaves the effective
        # resolver semantics unknown, so the topology is PARTIAL, never quietly complete.
        for text in ("passwd: Compat\n", "passwd: extrausers files\n", "group: altfiles\n"):
            r = self.collect(**{"nsswitch.conf": text})
            self.assertEqual(r["status"], model.PARTIAL, text)
            self.assertIn(model.ANOMALY_UNKNOWN_SERVICE,
                          [a["anomaly"] for a in r["anomalies"]], text)
        # A database outside identity is not held to it.
        r = self.collect(**{"nsswitch.conf": "passwd: files\nhosts: files frobnicate\n"})
        self.assertEqual(r["status"], model.COLLECTED, r["reason"])

    def test_unreadable_is_never_collected(self):
        root = tree(**{"nsswitch.conf": "passwd: files\n"})
        self.addCleanup(shutil.rmtree, root)
        os.chmod(os.path.join(root, "etc", "nsswitch.conf"), 0)
        if os.geteuid() == 0:
            self.skipTest("root ignores the permission bits this test depends on")
        self.assertNotEqual(acquire.collect(root)["status"], model.COLLECTED)


class RemoteProviderDetection(unittest.TestCase):
    """IDENT-040: detected, never enumerated."""

    def collect(self, conf):
        root = tree(**{"nsswitch.conf": conf, "passwd": PASSWD, "group": GROUP,
                       "shadow": SHADOW})
        self.addCleanup(shutil.rmtree, root)
        return root, acquire.collect(root)

    def test_a_remote_provider_is_detected(self):
        _, r = self.collect("passwd: files sss\ngroup: files sss\nshadow: files\n")
        found = {(x["database"], x["service"], x["class"])
                 for x in r["non_files_identity_sources"]}
        self.assertEqual(found, {("passwd", "sss", model.REMOTE_DIRECTORY),
                                 ("group", "sss", model.REMOTE_DIRECTORY)})

    def test_files_only_detects_nothing(self):
        _, r = self.collect("passwd: files\ngroup: files\nshadow: files\n")
        self.assertEqual(r["non_files_identity_sources"], [])

    def test_compat_is_reported_as_non_files(self):
        _, r = self.collect("passwd: compat\n")
        self.assertEqual(r["non_files_identity_sources"],
                         [{"database": "passwd", "service": "compat", "class": model.COMPAT}])

    def test_a_remote_provider_adds_zero_accounts(self):
        root, _ = self.collect("passwd: files sss\ngroup: files sss\nshadow: files\n")
        self.assertEqual([a["name"] for a in accounts.collect(root)["local_accounts"]],
                         ["root", "alice"])

    def test_the_topology_is_never_state(self):
        for field, cls in model.CLASSIFICATION.items():
            self.assertNotEqual(cls, model.STATE, field)


def state_projection(result):
    """Every STATE field of the account and group records, dotted ones included.

    Red team pass 4 (L6): the earlier projection dropped every dotted key, so shadow.* and
    group.* STATE never took part in the central proof.
    """
    cls = account_model.CLASSIFICATION
    accounts = []
    for a in result["local_accounts"]:
        item = {k: a.get(k) for k, v in cls.items() if v == account_model.STATE and "." not in k}
        shadow = a.get("shadow") or {}
        item.update({k: shadow.get(k.split(".", 1)[1]) for k, v in cls.items()
                     if v == account_model.STATE and k.startswith("shadow.")
                     and "." not in k.split(".", 1)[1]})
        item["shadow.password_state"] = shadow.get("password_state")
        accounts.append(item)
    groups = [{k: g.get(k.split(".", 1)[1]) for k, v in cls.items()
               if v == account_model.STATE and k.startswith("group.")}
              for g in result["local_groups"]]
    return canonical.canonical_bytes({"accounts": accounts, "groups": groups})


class StateInvarianceVersusSourceIdentity(unittest.TestCase):
    """The central lane proof. Same /etc/passwd, NSS files -> files sss.

    NOW (this lane): account STATE bytes and their digest unchanged, NSS topology digest
    changed, remote provider detected, zero remote accounts. LATER (W1-C, not here): one
    collection-scope or method change, no account drift.
    """

    def both(self, first, second):
        out = []
        for conf in (first, second):
            root = tree(**{"nsswitch.conf": conf, "passwd": PASSWD, "group": GROUP,
                           "shadow": SHADOW})
            self.addCleanup(shutil.rmtree, root)
            out.append((accounts.collect(root), acquire.collect(root)))
        return out

    def test_files_to_files_sss(self):
        (a1, n1), (a2, n2) = self.both("passwd: files\ngroup: files\nshadow: files\n",
                                       "passwd: files sss\ngroup: files sss\nshadow: files\n")
        self.assertEqual(state_projection(a1), state_projection(a2))
        self.assertEqual(hashlib.sha256(state_projection(a1)).hexdigest(),
                         hashlib.sha256(state_projection(a2)).hexdigest())
        self.assertNotEqual(n1["identity_nss_topology_digest"],
                            n2["identity_nss_topology_digest"])
        self.assertEqual(n1["non_files_identity_sources"], [])
        self.assertTrue(n2["non_files_identity_sources"])
        self.assertEqual(len(a1["local_accounts"]), len(a2["local_accounts"]))

    def test_order_alone_moves_the_digest(self):
        (_, n1), (_, n2) = self.both("passwd: files sss\n", "passwd: sss files\n")
        self.assertNotEqual(n1["identity_nss_topology_digest"],
                            n2["identity_nss_topology_digest"])

    def test_an_action_alone_moves_the_digest(self):
        (_, n1), (_, n2) = self.both("passwd: files sss\n",
                                     "passwd: files [NOTFOUND=return] sss\n")
        self.assertNotEqual(n1["identity_nss_topology_digest"],
                            n2["identity_nss_topology_digest"])

    def test_formatting_alone_does_not_move_the_digest(self):
        (_, n1), (_, n2) = self.both("passwd: files sss\n",
                                     "# c\npasswd:\tfiles   sss  # trailing\n")
        self.assertEqual(n1["identity_nss_topology_digest"],
                         n2["identity_nss_topology_digest"])

    def test_a_non_identity_database_does_not_move_the_identity_digest(self):
        (_, n1), (_, n2) = self.both("passwd: files\nhosts: files dns\n",
                                     "passwd: files\nhosts: files mdns4_minimal dns\n")
        self.assertEqual(n1["identity_nss_topology_digest"],
                         n2["identity_nss_topology_digest"])


class NoLookup(unittest.TestCase):
    """No resolver, NSS or directory call is reachable from the lane's modules.

    pwd, grp and spwd go through NSS, so importing them IS the enumeration IDENT-040
    forbids. socket's gethostbyname and friends are the resolver.
    """

    FORBIDDEN = {"socket", "pwd", "grp", "spwd", "subprocess", "ctypes", "importlib"}

    def test_the_lane_and_the_account_source_import_nothing_that_looks_up(self):
        for package in ("nss", "hostname", "accounts"):
            directory = os.path.join(LIB, "isedraf", package)
            for name in sorted(os.listdir(directory)):
                if not name.endswith(".py"):
                    continue
                with open(os.path.join(directory, name)) as fh:
                    tree_ = ast.parse(fh.read())
                for node in ast.walk(tree_):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [a.name.split(".")[0] for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                        names = [node.module.split(".")[0]]
                    for n in names:
                        self.assertNotIn(n, self.FORBIDDEN, "%s/%s" % (package, name))


class RedTeamRegressions(unittest.TestCase):
    """Findings of the independent adversarial pass, each written before its fix.

    Where nsswitch.conf(5) is silent, the red team asked the machine's own glibc with
    `getent` inside an unprivileged private namespace, against synthetic files, using only
    `files` and a nonexistent service. Those observations are the authority cited below.
    """

    def digest(self, conf):
        root = tree(**{"nsswitch.conf": conf})
        self.addCleanup(shutil.rmtree, root)
        return acquire.collect(root)

    def test_f1_form_feed_cr_and_vt_are_whitespace_not_line_breaks(self):
        # glibc splits lines on \n only.
        for sep in ("\f", "\r", "\v"):
            self.assertEqual(services("passwd: files%ssss\n" % sep), ["files", "sss"], sep)
            r = self.digest("passwd: files%ssss\n" % sep)
            self.assertNotEqual(r["identity_nss_topology_digest"],
                                self.digest("passwd: files\n")["identity_nss_topology_digest"])

    def test_f2_a_second_bracket_is_unsupported_and_moves_the_digest(self):
        # glibc stops at a second consecutive bracket; one bracket with two pairs does not.
        two = "passwd: bogus [NOTFOUND=continue] [UNAVAIL=continue] files\n"
        one = "passwd: bogus [NOTFOUND=continue UNAVAIL=continue] files\n"
        self.assertEqual(line_of(two)["semantics"], model.UNSUPPORTED)
        self.assertEqual(line_of(one)["semantics"], model.KNOWN)
        self.assertNotEqual(self.digest(two)["identity_nss_topology_digest"],
                            self.digest(one)["identity_nss_topology_digest"])

    def test_f3_a_line_without_a_colon_is_retained_and_moves_the_digest(self):
        # glibc honours "passwd files"; it is neither dropped nor an absent database.
        r = self.digest("passwd files\n")
        self.assertEqual([x["database"] for x in r["records"]], ["passwd"])
        self.assertEqual(r["records"][0]["semantics"], model.UNSUPPORTED)
        self.assertNotIn("passwd", r["undeclared_identity_databases"])
        self.assertNotEqual(r["identity_nss_topology_digest"],
                            self.digest("passwd sss ldap\n")["identity_nss_topology_digest"])

    def test_f4_compat_pseudo_databases_and_netgroup_are_identity_scope(self):
        # nsswitch.conf(5): passwd_compat, group_compat, shadow_compat name the source
        # compat reads; netgroup resolves +@netgroup directives.
        base = self.digest("passwd: compat\n")["identity_nss_topology_digest"]
        for extra in ("passwd_compat: ldap", "group_compat: sss", "shadow_compat: winbind",
                      "netgroup: ldap"):
            r = self.digest("passwd: compat\n%s\n" % extra)
            self.assertNotEqual(r["identity_nss_topology_digest"], base, extra)
            self.assertIn(extra.split(":")[1].strip(),
                          [x["service"] for x in r["non_files_identity_sources"]], extra)

    def test_f8_an_undecodable_byte_never_crashes_and_is_serializable(self):
        for data in (b"passwd: files sss\xff\n", b"hosts: files dns\xff\npasswd: files\n"):
            root = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, root)
            os.mkdir(os.path.join(root, "etc"))
            with open(os.path.join(root, "etc", "nsswitch.conf"), "wb") as fh:
                fh.write(data)
            r = acquire.collect(root)
            self.assertTrue(canonical.canonical_bytes({k: v for k, v in r.items()
                                                       if k != "coverage"}))
            self.assertEqual(r["status"], model.PARTIAL)

    def test_f9_a_symlink_never_escapes_a_fixture_root(self):
        root = tempfile.mkdtemp()
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        self.addCleanup(shutil.rmtree, outside)
        os.mkdir(os.path.join(root, "etc"))
        with open(os.path.join(outside, "nsswitch.conf"), "w") as fh:
            fh.write("passwd: files sss\n")
        os.symlink(os.path.join(outside, "nsswitch.conf"),
                   os.path.join(root, "etc", "nsswitch.conf"))
        r = acquire.collect(root)
        self.assertEqual(r["status"], model.NOT_TESTED)
        self.assertIn("SOURCE_OUTSIDE_COLLECTION_ROOT", r["reason"])
        self.assertEqual(r["records"], [])

    def test_f11_spaced_brackets_are_accepted(self):
        # glibc treats [ NOTFOUND = return ] exactly as [NOTFOUND=return].
        a = line_of("passwd: files [ NOTFOUND = return ] sss\n")
        self.assertEqual(a["semantics"], model.KNOWN)
        self.assertEqual(a["entries"], line_of("passwd: files [NOTFOUND=return] sss\n")["entries"])

    def test_f11_a_blank_after_negation_is_unsupported(self):
        # Corrected by red-team pass 2 (#3): glibc 2.43 REJECTS "[! NOTFOUND=return]"
        # (lookup fails) while accepting "[ !NOTFOUND=return]" and "[!NOTFOUND =return]".
        self.assertEqual(line_of("passwd: files [! NOTFOUND=return] sss\n")["semantics"],
                         model.UNSUPPORTED)
        self.assertEqual(line_of("passwd: files [ !NOTFOUND=return] sss\n")["semantics"],
                         model.KNOWN)

    def test_low_reordering_distinct_databases_does_not_move_the_digest(self):
        # Order between databases is not resolver semantics; order within one is.
        self.assertEqual(
            self.digest("passwd: files\ngroup: files sss\n")["identity_nss_topology_digest"],
            self.digest("group: files sss\npasswd: files\n")["identity_nss_topology_digest"])


class RedTeamPass2(unittest.TestCase):
    """Pass-2 findings on this lane, each written before its fix. glibc 2.43 as oracle."""

    def collect(self, conf):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.mkdir(os.path.join(root, "etc"))
        with open(os.path.join(root, "etc", "nsswitch.conf"), "wb") as fh:
            fh.write(conf if isinstance(conf, bytes) else conf.encode())
        return acquire.collect(root)

    def digest(self, conf):
        return self.collect(conf)["identity_nss_topology_digest"]

    def test_p2_2_an_invalid_bracket_on_any_line_moves_the_identity_digest(self):
        # glibc: one invalid bracket on a known database line fails the whole file, and
        # passwd lookups with it.
        self.assertNotEqual(self.digest("passwd: files\n"),
                            self.digest("hosts: files [NOTFOUND=bogus] dns\npasswd: files\n"))

    def test_p2_3_a_blank_after_negation_moves_the_digest(self):
        self.assertNotEqual(self.digest("passwd: sss [!NOTFOUND=return] files\n"),
                            self.digest("passwd: sss [! NOTFOUND=return] files\n"))

    def test_p2_3_only_ascii_blanks_are_blanks_in_a_bracket(self):
        for body in ("\x1cUNAVAIL=continue", "UNAVAIL\xa0=continue"):
            r = line_of("passwd: files [%s] sss\n" % body)
            self.assertEqual(r["semantics"], model.UNSUPPORTED, repr(body))

    def test_p2_4_a_line_whose_colon_comes_later_is_kept_and_its_services_seen(self):
        r = self.collect("passwd: files\npasswd sss x:y\n")
        self.assertIn("sss", [x["service"] for x in r["non_files_identity_sources"]])
        self.assertEqual([x["database"] for x in r["records"]], ["passwd", "passwd"])
        self.assertNotEqual(r["identity_nss_topology_digest"], self.digest("passwd: files\n"))

    def test_p2_4_an_unclosed_bracket_does_not_hide_the_services_after_it(self):
        r = self.collect("passwd: files [NOTFOUND=return sss\n")
        self.assertIn("sss", [x["service"] for x in r["non_files_identity_sources"]])

    def test_p2_12_a_control_character_is_not_a_separator(self):
        # glibc ignores "passwd\x1csss": the database name is not passwd.
        r = self.collect("passwd\x1csss\n")
        self.assertEqual(r["non_files_identity_sources"], [])

    def test_p2_12_nul_ends_the_line_for_glibc(self):
        r = self.collect(b"passwd: files\x00 sss\n")
        self.assertEqual(r["status"], model.PARTIAL)
        rec = r["records"][0]
        self.assertEqual(rec["semantics"], model.UNSUPPORTED)

    def test_p2_13_a_fifo_is_refused_not_read(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.mkdir(os.path.join(root, "etc"))
        os.mkfifo(os.path.join(root, "etc", "nsswitch.conf"))
        r = acquire.collect(root)
        self.assertNotEqual(r["status"], model.COLLECTED)
        self.assertIn("not a regular file", r["reason"])


class RedTeamPass3(unittest.TestCase):
    """Pass-3 findings on this lane, each written before its fix. glibc 2.43 as oracle."""

    def collect(self, conf):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.mkdir(os.path.join(root, "etc"))
        with open(os.path.join(root, "etc", "nsswitch.conf"), "w") as fh:
            fh.write(conf)
        return acquire.collect(root)

    def test_p3_f3_an_action_glued_to_the_next_negation_is_unsupported(self):
        # glibc reads the action up to blank, "=" or "]", so "return!UNAVAIL" is invalid.
        a = self.collect("passwd: files [NOTFOUND=return!UNAVAIL=return] nosuch\n")
        b = self.collect("passwd: files [NOTFOUND=return !UNAVAIL=return] nosuch\n")
        self.assertEqual(a["status"], model.PARTIAL)
        self.assertNotEqual(a["identity_nss_topology_digest"], b["identity_nss_topology_digest"])

    def test_p3_f4_colons_after_the_database_name_are_skipped(self):
        # glibc: "passwd::files", "passwd: :files" and "passwd :: files" all mean files.
        base = self.collect("passwd: files\n")["identity_nss_topology_digest"]
        for conf in ("passwd::files\n", "passwd: :files\n", "passwd :: files\n"):
            r = self.collect(conf)
            self.assertEqual(r["identity_nss_topology_digest"], base, conf)
            self.assertEqual(r["non_files_identity_sources"], [], conf)
        r = self.collect("passwd::sss\n")
        self.assertEqual(r["non_files_identity_sources"][0]["class"], model.REMOTE_DIRECTORY)

    def test_p3_f5_many_unclosed_brackets_never_raise(self):
        r = self.collect("passwd: files " + "[" * 5000 + "\n")
        self.assertEqual(r["status"], model.PARTIAL)

    def test_p3_f7_compat_without_its_pseudo_database_is_default_not_asserted(self):
        # nsswitch.conf(5): "By default, the source is nis" - recorded, never assumed.
        r = self.collect("passwd: compat\ngroup: compat\nshadow: compat\n")
        for db in ("passwd_compat", "group_compat", "shadow_compat"):
            self.assertEqual(r["undeclared_identity_databases"].get(db),
                             model.DEFAULT_NOT_ASSERTED, db)


class ProductionRoot(unittest.TestCase):
    """Ruling F: the production root, structurally. Nothing is asserted about this host."""

    def test_collect_at_root_reads_the_real_path(self):
        r = acquire.collect("/")
        self.assertEqual(r["source"], "/etc/nsswitch.conf")
        self.assertIn(r["status"], (model.COLLECTED, model.PARTIAL, model.NOT_TESTED,
                                    model.ERROR))


if __name__ == "__main__":
    unittest.main(verbosity=0)
