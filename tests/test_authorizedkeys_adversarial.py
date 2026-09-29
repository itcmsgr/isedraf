# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Attack the authorized_keys evidence lane from its contract, before the code.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, IDENT-041, GOV-002
#
# RED, PASS R1. Written against docs/development/AUTHORIZED_KEYS_LANE_CONTRACT.md while
# lib/isedraf/authorizedkeys/ did not exist, so every expectation here comes from the
# contract and from sshd_config(5)/authorized_keys(5) semantics rather than from whatever
# an implementation happens to do. A test written after the code tends to agree with it.
#
# The central attack is the one the contract itself names: a lane that reads
# ~/.ssh/authorized_keys because that is where keys usually live has manufactured a
# declaration the host never made, and every record it then emits reads as authoritative.
# The second attack is the completeness lie - one file read perfectly does not mean the
# set of sources was observed.
#
# Assertions read structured fields wherever a field exists. Where the envelope is
# scanned it is for a leak or a verdict, and the payload (records + anomalies) is scanned
# separately from the provenance prose: three separate occasions have now proved that a
# limitation sentence naming the concept it denies will defeat a whole-envelope
# substring assertion.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="a private temporary directory"
# meta:binaries="python3,ssh-keygen"
# =============================================================================

"""Independent adversarial attack on the authorized_keys source-evidence lane."""
import ast
import base64
import hashlib
import inspect
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf import textbytes                                    # noqa: E402
from isedraf.shared import result                                # noqa: E402
from isedraf.accounts import acquire as accounts_acquire         # noqa: E402
from isedraf.ssh import acquire as ssh_acquire                   # noqa: E402
from isedraf.authorizedkeys import acquire, model, sources       # noqa: E402


# =============================================================================
# Fixture key material, built here rather than copied from anywhere.
#
# An SSH public key blob is a sequence of length-prefixed strings whose FIRST element is
# the key type the blob itself claims. Building the blobs by hand is what makes the
# "declared type disagrees with the encoded type" attack possible at all.
# =============================================================================

def blob(*parts):
    """A base64 SSH key blob from length-prefixed byte strings."""
    raw = b"".join(struct.pack(">I", len(part)) + part for part in parts)
    return base64.b64encode(raw).decode("ascii")


ED_A = blob(b"ssh-ed25519", b"A" * 32)
ED_B = blob(b"ssh-ed25519", b"B" * 32)
RSA_A = blob(b"ssh-rsa", b"\x01\x00\x01", b"\x00" + b"\xab" * 255)
ECDSA_A = blob(b"ecdsa-sha2-nistp256", b"nistp256", b"\x04" + b"\xcd" * 64)
UNKNOWN_TYPE = blob(b"ssh-frobnicate2031", b"Z" * 32)

# Decodes as base64, is not a key blob: no sane length prefix, no type string.
NOT_A_BLOB = base64.b64encode(b"this is not a key blob at all").decode("ascii")
# Does not decode as base64 at all.
BAD_B64 = "AAAA!!!!not-base64-@@@@"

VALID = "ssh-ed25519 %s" % ED_A
BAIT_KEY = "ssh-ed25519 %s baitkeyshouldneverbecollected\n" % blob(
    b"ssh-ed25519", b"\xba\x17" * 16)


# =============================================================================
# Shape-tolerant, vocabulary-strict accessors.
#
# The contract names the FIELDS and the VALUES but not where in the envelope each one
# hangs. Walking the serialised evidence for a field name is therefore deliberate: it
# lets the implementation choose its own layout while leaving it no room to choose its
# own vocabulary, and an assertion that walked one hard-coded path would pass on a lane
# that had simply moved the leak somewhere else.
# =============================================================================

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


def dumped(obj):
    return json.dumps(obj, default=str, sort_keys=True)


def payload(ev):
    """Records and anomalies only - never the provenance prose.

    The limitation sentence a lane is REQUIRED to carry names the very claims it
    refuses to make. Scanning it for those words punishes honesty, which is how the
    login-policy lane's prose assertion certified a defect.
    """
    return dumped({"records": ev.records, "anomalies": ev.anomalies})


def envelope(ev):
    return dumped(ev.as_dict())


def candidates(ev):
    """Every candidate in the evidence, across all accounts."""
    return [d for d in walk(ev.as_dict()) if "resolution" in d]


def records_for_alice(ev):
    """Key records belonging to alice, by her lossless byte identity."""
    return [r for r in ev.as_dict()["records"]
            if ALICE_HEX in dumped(r.get("account_ref", {}))]


def candidates_of(entry):
    """One account's candidates.

    R1 used `candidates(ev)` for counts that MEAN "this account's candidates", and the
    fixtures carry two accounts, so `assertEqual(len(...), 2)` was measuring four. The
    contract makes the candidate set a per-account fact and R1's own
    test_the_universe_is_decided_per_account_not_per_host says so; this is that rule
    applied to the accessor it was missing from.
    """
    return [d for d in walk(entry) if "resolution" in d]


def key_records(ev):
    return [d for d in walk(ev.as_dict())
            if "parse_status" in d or "key_fingerprint" in d]


def universes(ev):
    return [d for d in walk(ev.as_dict()) if "source_universe" in d]


def universe_state(entry):
    value = entry["source_universe"]
    if isinstance(value, dict):
        return value.get("state", value.get("source_universe"))
    return value


def universe_reasons(entry):
    value = entry["source_universe"]
    if isinstance(value, dict) and "reasons" in value:
        return value["reasons"]
    for key in ("universe_reasons", "source_universe_reasons", "reasons",
                "incomplete_reasons"):
        if key in entry:
            return entry[key]
    return []


def leak_markers(line):
    """Every string that would betray this key if it entered the evidence.

    Computed HERE, from the key material, rather than by asking the lane's own parser
    for a fingerprint: a containment assertion that depends on the implementation
    producing a fingerprint stops detecting anything the moment the implementation
    returns None. The three forms cover a lane that stored the base64 body, a hex
    digest, or OpenSSH's own unpadded-base64 SHA256 form.
    """
    body = line.split()[1]
    raw = base64.b64decode(body + "=" * (-len(body) % 4))
    digest = hashlib.sha256(raw).digest()
    markers = [body, hashlib.sha256(raw).hexdigest(),
               base64.b64encode(digest).decode("ascii").rstrip("=")]
    for word in line.split()[2:]:
        markers.append(word)
    return markers


def assert_no_leak(case, ev, line, what):
    """No trace of `line`'s key anywhere in the serialised evidence."""
    blob_text = envelope(ev)
    for marker in leak_markers(line):
        case.assertNotIn(marker, blob_text, "%s leaked %r" % (what, marker))


def option_names(record):
    return [option["name"] for option in record["options"]]


def option(record, name):
    for entry in record["options"]:
        if entry["name"] == name:
            return entry
    raise AssertionError("option %r absent; names were %r"
                         % (name, option_names(record)))


PARSER_ENTRY_POINTS = ("parse", "parse_text", "parse_authorized_keys",
                       "parse_lines", "records")


def parse(text):
    """The pure text -> records entry point of sources.py, however it is named.

    The contract fixes the module's CONTRACT ("PURE parser; text in, records out") and
    the record shape, but not the function name, so this tolerates the name and nothing
    else. If it returns (records, anomalies) the records are taken.
    """
    for name in PARSER_ENTRY_POINTS:
        function = getattr(sources, name, None)
        if callable(function):
            out = function(text)
            if isinstance(out, tuple) and len(out) == 2:
                out = out[0]
            return list(out)
    raise AssertionError(
        "sources.py exposes no pure text->records entry point; the contract requires "
        "one: 'lib/isedraf/authorizedkeys/sources.py   PURE parser; text in, records "
        "out'. Tried %r" % (PARSER_ENTRY_POINTS,))


def one(text):
    records = parse(text)
    if len(records) != 1:
        raise AssertionError("expected exactly one record from %r, got %d"
                             % (text, len(records)))
    return records[0]


ALICE_HEX = textbytes.hex_of("alice")
DEFAULT_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
                  "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n")
DEFAULT_GROUP = "root:x:0:\nalice:x:1000:\n"
# A fabricated shadow file in a private temporary directory. The live /etc/shadow is
# never read by anything here; without this fixture the account evidence is PARTIAL and
# every completeness assertion below would be testing the wrong thing.
DEFAULT_SHADOW = "root:*:19000:0:99999:7:::\nalice:*:19000:0:99999:7:::\n"


class Lane(unittest.TestCase):
    """A private fixture host, and the two evidence inputs collected from it."""

    PASSWD = DEFAULT_PASSWD
    GROUP = DEFAULT_GROUP
    SHADOW = DEFAULT_SHADOW

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base, True)
        os.makedirs(os.path.join(self.base, "etc", "ssh"))

    def write(self, relative, content, mode=None):
        path = os.path.join(self.base, relative)
        directory = os.path.dirname(path)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        if isinstance(content, bytes):
            handle = open(path, "wb")
        else:
            handle = open(path, "w")
        try:
            handle.write(content)
        finally:
            handle.close()
        if mode is not None:
            os.chmod(path, mode)
        return path

    def accounts(self, passwd=None, group=None, shadow=None):
        self.write("etc/passwd", self.PASSWD if passwd is None else passwd)
        self.write("etc/group", self.GROUP if group is None else group)
        if (self.SHADOW if shadow is None else shadow) is not None:
            self.write("etc/shadow", self.SHADOW if shadow is None else shadow)
        return accounts_acquire.collect(self.base)

    def ssh(self, config):
        if config is not None:
            self.write("etc/ssh/sshd_config", config)
        return ssh_acquire.collect(self.base)

    def collect(self, config="", passwd=None, group=None, shadow=None,
                account_evidence=None, ssh_evidence=None):
        accounts = (self.accounts(passwd, group, shadow)
                    if account_evidence is None else account_evidence)
        ssh = self.ssh(config) if ssh_evidence is None else ssh_evidence
        return acquire.collect(self.base, accounts, ssh)

    def alice(self, ev):
        """Alice's source-universe entry, found by her lossless byte identity."""
        found = [u for u in universes(ev) if ALICE_HEX in dumped(u)]
        self.assertTrue(found, "no source_universe entry carries alice's identity; "
                               "the contract makes the universe a per-account fact "
                               "('every observed declaration was expanded for this "
                               "account')")
        return found[0]


# =============================================================================
# 1. The vocabulary the contract declares
# =============================================================================

class Vocabulary(unittest.TestCase):
    """Every name the contract prints must exist in model.py, spelled that way.

    A lane that invents `NO_DECL` or `MATCH_UNRESOLVED` has changed the evidence
    vocabulary of the product by accident, and the contract is then describing
    something that does not exist.
    """

    # R1 wrote this list from the contract as the contract was then printed:
    #
    #     "DECLARED_CANDIDATE_SOURCE", "OBSERVED_FILE", "UNRESOLVED_SOURCE_UNIVERSE",
    #     "UNRESOLVED_MATCH_SCOPED", "NO_DECLARATION_OBSERVED", "DECLARED_NONE",
    #     "UNEXPANDED_TOKEN", "HOME_NOT_AVAILABLE", "NO_MATCH", "COMPLETE",
    #     "INCOMPLETE", "MALFORMED_BASE64", "UNKNOWN_KEY_TYPE"
    #
    # Every one of those was a VALUE, and the contract never said what the constants
    # holding them were called - so R1 assumed the value was the name and the two sides
    # disagreed on 22 tests. The RULE this class encodes is right and unchanged: a name
    # the contract prints must exist in model.py, spelled that way. What changed is that
    # the contract now prints constant names, which is what it should have printed.
    NAMES = ("DECLARED_CANDIDATE_SOURCE", "OBSERVED_FILE", "SOURCE_SCOPE",
             "UNRESOLVED_MATCH_SCOPED", "UNCONDITIONAL", "PATH_DERIVED",
             "EFFECTIVE_NOT_EVALUATED", "NO_DECLARATION_OBSERVED", "DECLARED_NONE",
             "UNEXPANDED_TOKEN", "HOME_NOT_AVAILABLE", "GLOB_NO_MATCH",
             "UNIVERSE_COMPLETE", "UNIVERSE_INCOMPLETE", "PARSE_OK",
             "PARSE_MALFORMED_BASE64", "PARSE_KEY_TYPE_MISMATCH",
             "PARSE_NOT_A_KEY_BLOB", "PARSE_OPTIONS_ONLY",
             "FILE_OUTSIDE_COLLECTION_ROOT")

    def test_every_contract_name_is_defined(self):
        missing = [name for name in self.NAMES if not hasattr(model, name)]
        self.assertEqual(missing, [], "model.py does not define %r" % (missing,))

    def test_the_names_are_distinct_strings(self):
        values = [getattr(model, name) for name in self.NAMES
                  if hasattr(model, name)]
        for value in values:
            self.assertIsInstance(value, str)
        self.assertEqual(len(set(values)), len(values),
                         "two contract concepts share one value")

    def test_the_source_scope_is_the_accounts_lanes_own_constant(self):
        # The account_ref's `source` is LOCAL_ACCOUNT_FILES because that is what the
        # accounts lane calls itself. A second spelling here would be a second claim
        # about what the evidence describes.
        self.assertEqual(model.SOURCE_SCOPE, "LOCAL_ACCOUNT_FILES")


# =============================================================================
# 2. Grammar - the pure parser
# =============================================================================

class Grammar(unittest.TestCase):
    """authorized_keys(5) line grammar, against sources.py alone."""

    def test_a_valid_key_is_one_record(self):
        record = one(VALID + "\n")
        self.assertEqual(record["parse_status"], model.PARSE_OK)
        self.assertEqual(record["key_type"], "ssh-ed25519")
        self.assertTrue(record["key_fingerprint"])
        self.assertTrue(record["key_digest_algorithm"])

    def test_the_key_type_is_kept_as_written(self):
        for written, body in (("ssh-rsa", RSA_A),
                              ("ecdsa-sha2-nistp256", ECDSA_A),
                              ("ssh-ed25519", ED_A)):
            record = one("%s %s\n" % (written, body))
            self.assertEqual(record["key_type"], written)

    def test_malformed_base64_is_recorded_not_dropped(self):
        record = one("ssh-ed25519 %s\n" % BAD_B64)
        self.assertEqual(record["parse_status"], model.PARSE_MALFORMED_BASE64)
        self.assertIsNone(record["key_fingerprint"])

    def test_material_that_decodes_but_is_not_a_key_blob_is_not_OK(self):
        # The dangerous outcome is a fingerprint computed over arbitrary bytes and
        # reported as a key. Decoding successfully is not the same as being a key.
        record = one("ssh-ed25519 %s\n" % NOT_A_BLOB)
        self.assertNotEqual(record["parse_status"], model.PARSE_OK)
        self.assertIsNone(record["key_fingerprint"])

    def test_an_unrecognised_algorithm_is_recorded_verbatim_not_rejected(self):
        """R1 expected KEY_TYPE_MISMATCH here. The lane deliberately says OK.

        R1's blob NAMES ssh-frobnicate2031 inside itself, so the text and the wire
        format agree and the entry is internally consistent - it is simply an algorithm
        this code has never heard of. Reporting that as a defect would require a list of
        known key types, which is the list this parser refuses to maintain precisely
        because it would mislabel every algorithm invented after it was written.

        The evidence R1 was protecting is preserved and asserted: the type is recorded
        verbatim, the blob is confirmed to agree, and a fingerprint is produced. What is
        NOT claimed is that the algorithm is known to anyone.
        """
        record = one("ssh-frobnicate2031 %s\n" % UNKNOWN_TYPE)
        self.assertEqual(record["key_type"], "ssh-frobnicate2031")
        self.assertEqual(record["blob_type"], "ssh-frobnicate2031")
        self.assertEqual(record["blob_type_agreement"], model.BLOB_TYPE_MATCHES)
        self.assertEqual(record["parse_status"], model.PARSE_OK)
        self.assertTrue(record["key_fingerprint"].startswith("SHA256:"))

    def test_a_type_the_blob_contradicts_is_not_OK(self):
        # The state R1 was reaching for, on the input that actually shows it.
        record = one("ssh-rsa %s\n" % ED_A)
        self.assertEqual(record["parse_status"], model.PARSE_KEY_TYPE_MISMATCH)
        self.assertEqual(record["key_type"], "ssh-rsa")
        self.assertEqual(record["blob_type"], "ssh-ed25519")

    def test_declared_type_disagreeing_with_the_encoded_type_is_not_OK(self):
        # `ssh-rsa <ed25519 blob>` - sshd would reject it. A parser that trusts the
        # first word reports an RSA key that does not exist on the host.
        record = one("ssh-rsa %s\n" % ED_A)
        self.assertNotEqual(record["parse_status"], model.PARSE_OK)
        self.assertEqual(record["key_type"], "ssh-rsa")

    def test_multiple_keys_keep_their_own_positions(self):
        records = parse("%s\n%s\n" % (VALID, "ssh-ed25519 " + ED_B))
        self.assertEqual(len(records), 2)
        self.assertEqual([r["source_line"] for r in records], [1, 2])
        self.assertEqual([r["ordinal"] for r in records], sorted(
            r["ordinal"] for r in records))
        self.assertEqual(len(set(r["ordinal"] for r in records)), 2)

    def test_an_exact_duplicate_key_is_marked_not_collapsed(self):
        records = parse("%s\n%s\n" % (VALID, VALID))
        self.assertEqual(len(records), 2)
        self.assertIsNone(records[0]["duplicate_of"])
        self.assertEqual(records[1]["duplicate_of"], records[0]["ordinal"])

    def test_the_same_key_with_different_options_keeps_both_option_sets(self):
        # De-duplicating on the key alone would discard an option set, and the option
        # set is the part a later criterion reads.
        records = parse("no-pty %s\n%s\n" % (VALID, VALID))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["key_fingerprint"],
                         records[1]["key_fingerprint"])
        self.assertEqual(option_names(records[0]), ["no-pty"])
        self.assertEqual(option_names(records[1]), [])
        # The KEY is identical, so the later line is still a duplicate of the earlier.
        self.assertEqual(records[1]["duplicate_of"], records[0]["ordinal"])

    def test_options_precede_the_key_type_and_do_not_become_it(self):
        record = one('no-pty,no-agent-forwarding %s\n' % VALID)
        self.assertEqual(record["key_type"], "ssh-ed25519")
        self.assertEqual(record["parse_status"], model.PARSE_OK)
        self.assertEqual(option_names(record), ["no-pty", "no-agent-forwarding"])

    def test_a_quoted_option_value_is_one_option(self):
        record = one('command="/usr/bin/true" %s\n' % VALID)
        self.assertEqual(option_names(record), ["command"])

    def test_a_comma_inside_a_quoted_option_value_does_not_split_the_list(self):
        # The classic authorized_keys parser break. A naive split(",") yields four
        # options here, three of them fabricated, and the key type is lost.
        record = one('from="10.0.0.1,10.0.0.2",no-pty %s\n' % VALID)
        self.assertEqual(option_names(record), ["from", "no-pty"])
        self.assertEqual(record["key_type"], "ssh-ed25519")
        self.assertEqual(record["parse_status"], model.PARSE_OK)

    def test_an_escaped_quote_inside_a_quoted_value_does_not_end_the_value(self):
        record = one('command="echo \\"hi\\",x",no-pty %s\n' % VALID)
        self.assertEqual(option_names(record), ["command", "no-pty"])
        self.assertEqual(record["key_type"], "ssh-ed25519")

    def test_an_unterminated_quote_is_malformed_not_silently_truncated(self):
        record = one('command="unterminated %s\n' % VALID)
        self.assertNotEqual(record["parse_status"], model.PARSE_OK)

    def test_blank_and_comment_lines_are_not_records(self):
        records = parse("\n   \n# a comment\n\t# indented comment\n%s\n" % VALID)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["source_line"], 5)

    def test_a_line_with_only_options_invents_no_key(self):
        record = one("no-pty,restrict\n")
        self.assertNotEqual(record["parse_status"], model.PARSE_OK)
        self.assertIsNone(record["key_fingerprint"])
        self.assertIsNone(record["key_type"])

    def test_trailing_whitespace_does_not_change_the_key(self):
        plain = one(VALID + "\n")
        padded = one(VALID + "   \t  \n")
        self.assertEqual(padded["parse_status"], model.PARSE_OK)
        self.assertEqual(padded["key_fingerprint"], plain["key_fingerprint"])
        self.assertEqual(padded["key_type"], "ssh-ed25519")

    def test_crlf_line_endings_do_not_leak_a_carriage_return(self):
        record = one(VALID + "\r\n")
        self.assertEqual(record["key_type"], "ssh-ed25519")
        self.assertEqual(record["parse_status"], model.PARSE_OK)
        self.assertEqual(record["key_fingerprint"], one(VALID + "\n")["key_fingerprint"])
        self.assertNotIn("\r", dumped(record))

    def test_a_very_long_line_is_bounded_and_not_copied_into_evidence(self):
        records = parse("ssh-ed25519 " + ("A" * 200000) + "\n")
        self.assertIsInstance(records, list)
        self.assertLess(len(dumped(records)), 50000,
                        "a 200 KB line was copied into the records")

    def test_comment_text_is_not_a_second_key_field(self):
        record = one("%s this is a trailing comment with spaces\n" % VALID)
        self.assertEqual(record["parse_status"], model.PARSE_OK)
        self.assertEqual(record["key_type"], "ssh-ed25519")


# =============================================================================
# 3. Privacy - the material around the key
# =============================================================================

EMAIL = "carol.danvers@example-corp.invalid"
HOSTNAME = "jump01.prod.internal.invalid"
COMMAND = "/usr/local/bin/backup --to nas01.internal.invalid --key SECRETARG"
NETWORK = "NEVER-RETAIN-THIS-ORIGIN,*.dmz.internal.invalid"
ENVIRONMENT = "DEPLOY_TOKEN=SECRETENVVALUE"


class Privacy(unittest.TestCase):
    """Public keys are not secret; the material around them frequently is."""

    def test_a_comment_is_not_retained_by_default(self):
        record = one("%s %s from %s\n" % (VALID, EMAIL, HOSTNAME))
        self.assertEqual(record["comment_retention"], result.NOT_RETAINED)
        blob_text = dumped(record)
        self.assertNotIn(EMAIL, blob_text)
        self.assertNotIn("example-corp", blob_text)
        self.assertNotIn(HOSTNAME, blob_text)

    def test_a_command_option_keeps_its_name_and_not_its_value(self):
        record = one('command="%s" %s\n' % (COMMAND, VALID))
        self.assertIn("command", option_names(record))
        self.assertNotEqual(option(record, "command")["value_retention"],
                            result.RETAIN_VALUE)
        blob_text = dumped(record)
        self.assertNotIn("SECRETARG", blob_text)
        self.assertNotIn("nas01", blob_text)

    def test_a_from_option_does_not_publish_network_topology(self):
        record = one('from="%s" %s\n' % (NETWORK, VALID))
        self.assertIn("from", option_names(record))
        self.assertNotEqual(option(record, "from")["value_retention"],
                            result.RETAIN_VALUE)
        self.assertNotIn("NEVER-RETAIN-THIS-ORIGIN", dumped(record))
        self.assertNotIn("dmz.internal", dumped(record))

    def test_an_environment_option_does_not_publish_its_content(self):
        record = one('environment="%s" %s\n' % (ENVIRONMENT, VALID))
        self.assertIn("environment", option_names(record))
        self.assertNotIn("SECRETENVVALUE", dumped(record))

    def test_behavioural_option_names_are_retained(self):
        # These carry no operator data and are exactly what a later criterion reads.
        record = one("restrict,no-pty,cert-authority,no-port-forwarding %s\n" % VALID)
        for name in ("restrict", "no-pty", "cert-authority", "no-port-forwarding"):
            self.assertIn(name, option_names(record))

    def test_every_option_declares_its_retention(self):
        record = one('command="x",no-pty,from="NEVER-RETAIN-THIS-ORIGIN" %s\n' % VALID)
        for entry in record["options"]:
            self.assertIn("value_retention", entry)
            self.assertIn(entry["value_retention"], result.RETENTION)

    def test_a_comment_does_not_survive_through_the_whole_lane(self):
        # The parser may be clean and the acquisition layer may still serialise the raw
        # line somewhere in provenance. This is the assertion that catches that.
        host = _HostWithKeys(EMAIL_KEYS)
        self.addCleanup(host.close)
        ev = host.collect()
        self.assertNotIn(EMAIL, envelope(ev))
        self.assertNotIn(HOSTNAME, envelope(ev))
        self.assertNotIn("SECRETARG", envelope(ev))


EMAIL_KEYS = ('command="%s" %s %s\n' % (COMMAND, VALID, EMAIL))


class _HostWithKeys(object):
    """A minimal fixture host carrying one declared, readable authorized_keys file."""

    def __init__(self, keys_text):
        self.base = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.base, "etc", "ssh"))
        self._write("etc/passwd", DEFAULT_PASSWD)
        self._write("etc/group", DEFAULT_GROUP)
        self._write("etc/shadow", DEFAULT_SHADOW)
        self._write("etc/ssh/sshd_config", "AuthorizedKeysFile .ssh/authorized_keys\n")
        self._write("home/alice/.ssh/authorized_keys", keys_text)

    def _write(self, relative, text):
        path = os.path.join(self.base, relative)
        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        with open(path, "w") as handle:
            handle.write(text)

    def collect(self):
        return acquire.collect(self.base,
                               accounts_acquire.collect(self.base),
                               ssh_acquire.collect(self.base))

    def close(self):
        shutil.rmtree(self.base, True)


# =============================================================================
# 4. No declaration observed - the single most important behaviour in the lane
# =============================================================================

class NoDeclarationObserved(Lane):
    """`~/.ssh/authorized_keys` is a compiled-in default of a build, not evidence.

    Inventing it from absence manufactures a declaration the host never made. Every
    record that follows then reads as authoritative, and an operator who has moved
    AuthorizedKeysFile elsewhere is told about a file sshd may never consult.
    """

    def setUp(self):
        Lane.setUp(self)
        # A real, readable, conventionally-located file, with a real key in it.
        self.write("home/alice/.ssh/authorized_keys", BAIT_KEY)

    def assert_bait_unread(self, ev, what):
        blob_text = envelope(ev)
        for marker in leak_markers(BAIT_KEY):
            self.assertNotIn(marker, blob_text,
                             "%s: the lane read ~/.ssh/authorized_keys without a "
                             "declaration (%r leaked)" % (what, marker))

    def test_no_declaration_produces_no_candidate(self):
        ev = self.collect("PermitRootLogin no\n")
        self.assertEqual(candidates(ev), [],
                         "a candidate was invented from an absent declaration")

    def test_no_declaration_produces_no_key_records(self):
        ev = self.collect("PermitRootLogin no\n")
        self.assertEqual(key_records(ev), [])

    def test_the_conventional_file_is_never_read(self):
        self.assert_bait_unread(self.collect("PermitRootLogin no\n"),
                                "an unrelated directive")

    def test_no_conventional_path_appears_anywhere_in_the_evidence(self):
        ev = self.collect("PermitRootLogin no\n")
        for found in re.findall(r"[A-Za-z0-9_./%-]*authorized_keys[A-Za-z0-9_./%-]*",
                                envelope(ev)):
            self.assertNotIn("/.ssh/", found,
                             "%r looks like a manufactured default path" % found)

    def test_the_universe_is_incomplete_with_the_declared_reason(self):
        ev = self.collect("PermitRootLogin no\n")
        entry = self.alice(ev)
        self.assertEqual(universe_state(entry), model.UNIVERSE_INCOMPLETE)
        self.assertIn(model.NO_DECLARATION_OBSERVED,
                      dumped(universe_reasons(entry)))

    def test_an_sshd_config_that_does_not_exist_is_the_same_case(self):
        # NOT_TESTED ssh evidence is not weaker than an empty one: it is evidence that
        # nothing was observed, which is precisely NO_DECLARATION_OBSERVED.
        accounts = self.accounts()
        ssh = ssh_acquire.collect(self.base)
        self.assertEqual(ssh.status, result.NOT_TESTED)
        ev = acquire.collect(self.base, accounts, ssh)
        self.assertEqual(key_records(ev), [])
        self.assert_bait_unread(ev, "an absent sshd_config")
        self.assertNotEqual(ev.status, result.COLLECTED)

    def test_a_declaration_for_a_different_keyword_is_not_a_declaration(self):
        # AuthorizedPrincipalsFile is a different directive naming a different file.
        ev = self.collect("AuthorizedPrincipalsFile .ssh/principals\n")
        self.assertEqual(key_records(ev), [])
        self.assert_bait_unread(ev, "AuthorizedPrincipalsFile")


# =============================================================================
# 5. Declarations, expansion and the source universe
# =============================================================================

class Declarations(Lane):

    KEYS = "ssh-ed25519 %s declaredkeymarker\n" % ED_A

    def test_a_relative_value_is_anchored_to_the_rooted_home(self):
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        observed = [c for c in candidates(ev)
                    if c.get("observation") == model.FILE_READ]
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0]["source_path"].startswith(self.base))
        self.assertEqual(len(key_records(ev)), 1)

    def test_an_absolute_value_is_mapped_under_the_collection_root(self):
        self.write("etc/ssh/keys/alice", self.KEYS)
        ev = self.collect("AuthorizedKeysFile /etc/ssh/keys/%u\n")
        observed = [c for c in candidates(ev)
                    if c.get("observation") == model.FILE_READ]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["source_path"],
                         os.path.join(self.base, "etc/ssh/keys/alice"))

    def test_declared_none_is_not_a_path_and_is_not_an_absence(self):
        self.write("home/alice/.ssh/authorized_keys", BAIT_KEY)
        ev = self.collect("AuthorizedKeysFile none\n")
        resolutions = [c["resolution"] for c in candidates(ev)]
        self.assertIn(model.DECLARED_NONE, resolutions)
        self.assertNotIn(model.FILE_READ,
                         [c.get("observation") for c in candidates(ev)])
        self.assertEqual(key_records(ev), [])
        assert_no_leak(self, ev, BAIT_KEY, "the bait file")
        # `none` is a declaration; it is not NO_DECLARATION_OBSERVED.
        self.assertNotIn(model.NO_DECLARATION_OBSERVED, dumped(candidates(ev)))

    def test_a_match_scoped_declaration_is_unresolved_and_keeps_its_criteria(self):
        self.write("etc/ssh/keys/alice", self.KEYS)
        ev = self.collect("Match User alice\n"
                          "    AuthorizedKeysFile /etc/ssh/keys/%u\n")
        scoped = [c for c in candidates_of(self.alice(ev))
                  if c["applicability"] == model.UNRESOLVED_MATCH_SCOPED]
        self.assertEqual(len(scoped), 1, "the Match-scoped declaration was flattened")
        self.assertEqual(scoped[0]["scope"], "MATCH")
        criteria = scoped[0]["match_criteria"]
        self.assertEqual(criteria[0]["keyword"], "user")
        self.assertEqual(criteria[0]["values"], ["alice"])

    def test_a_match_scoped_declaration_makes_the_universe_incomplete(self):
        ev = self.collect("Match User alice\n"
                          "    AuthorizedKeysFile /etc/ssh/keys/%u\n")
        self.assertEqual(universe_state(self.alice(ev)), model.UNIVERSE_INCOMPLETE)

    def test_a_match_scoped_file_is_recorded_but_never_as_an_effective_source(self):
        """IQ-014. R1 and the implementation disagree, and the owner decides.

        R1 wrote this as `assert_no_leak(...)` plus `assertEqual(key_records(ev), [])`:
        a Match-scoped file should not be OPENED at all, because sshd may never consult
        it. That reading is coherent and quieter.

        The implementation reads it and labels it, on the owner's instruction to "retain
        observed candidate files but mark the source universe incomplete" - keys that
        exist on disk are evidence, and the accompanying rule, that an unresolved
        declaration "must not be presented as an effective source path", is met by the
        label rather than by silence.

        Until the owner rules, this asserts the property BOTH readings require and which
        is the actual risk: nothing from a Match-scoped candidate may appear unlabelled
        or as an effective source. If the ruling goes R1's way, the two lines above go
        back in unchanged.
        """
        self.write("etc/ssh/keys/alice", BAIT_KEY)
        ev = self.collect("Match User alice\n"
                          "    AuthorizedKeysFile /etc/ssh/keys/%u\n")
        for record in key_records(ev):
            self.assertEqual(record["declaration_scope"], "MATCH")
            self.assertEqual(record["declaration_applicability"],
                             model.UNRESOLVED_MATCH_SCOPED)
            self.assertTrue(record["declaration_match_criteria"],
                            "a Match-scoped key lost the criteria that condition it")
        for candidate in candidates(ev):
            self.assertNotEqual(candidate["applicability"], model.UNCONDITIONAL)
            self.assertEqual(candidate["applies_to_account"], "UNDETERMINED")
        self.assertEqual(universe_state(self.alice(ev)), model.UNIVERSE_INCOMPLETE)
        self.assertIn(model.MATCH_SCOPED_DECLARATION,
                      dumped(universe_reasons(self.alice(ev))))

    def test_a_global_and_a_match_declaration_stay_distinguishable(self):
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        self.write("etc/ssh/keys/alice", BAIT_KEY)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n"
                          "Match User alice\n"
                          "    AuthorizedKeysFile /etc/ssh/keys/%u\n")
        scopes = sorted(str(c.get("scope")) for c in candidates_of(self.alice(ev)))
        self.assertEqual(scopes, ["GLOBAL", "MATCH"])
        self.assertEqual(universe_state(self.alice(ev)), model.UNIVERSE_INCOMPLETE)

    def test_two_declarations_in_global_scope_are_both_candidates(self):
        # sshd applies the FIRST; the lane records both, because "why is my later edit
        # not taking effect" is the question an operator actually asks.
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        self.write("home/alice/.ssh/other", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n"
                          "AuthorizedKeysFile .ssh/other\n")
        paths = sorted(os.path.basename(str(c.get("source_path")))
                       for c in candidates_of(self.alice(ev)))
        self.assertEqual(paths, ["authorized_keys", "other"])

    def test_one_declaration_naming_two_files_yields_two_candidates(self):
        # sshd_config(5): AuthorizedKeysFile accepts several arguments. A lane that
        # treats the value as one path silently loses the second source.
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        self.write("home/alice/.ssh/authorized_keys2", self.KEYS)
        ev = self.collect(
            "AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n")
        self.assertEqual(len(candidates_of(self.alice(ev))), 2,
                         "a multi-valued AuthorizedKeysFile was read as one path")

    def test_an_unknown_token_leaves_the_candidate_unexpanded(self):
        ev = self.collect("AuthorizedKeysFile /etc/ssh/keys/%q\n")
        resolutions = [c["resolution"] for c in candidates(ev)]
        self.assertIn(model.UNEXPANDED_TOKEN, resolutions)
        self.assertNotIn(model.FILE_READ,
                         [c.get("observation") for c in candidates(ev)])
        self.assertEqual(universe_state(self.alice(ev)), model.UNIVERSE_INCOMPLETE)

    def test_an_unknown_token_is_not_dropped_to_make_a_readable_path(self):
        # Deleting %q yields /etc/ssh/keys/, and stripping the whole component yields
        # /etc/ssh/keys. Both are paths the host never declared.
        self.write("etc/ssh/keys", BAIT_KEY)
        ev = self.collect("AuthorizedKeysFile /etc/ssh/keys/%q\n")
        assert_no_leak(self, ev, BAIT_KEY, "the bait file")
        self.assertEqual(key_records(ev), [])

    def test_double_percent_is_a_literal_percent(self):
        self.write("etc/ssh/keys/100%done", self.KEYS)
        ev = self.collect("AuthorizedKeysFile /etc/ssh/keys/100%%done\n")
        observed = [c for c in candidates_of(self.alice(ev))
                    if c.get("observation") == model.FILE_READ]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["source_path"],
                         os.path.join(self.base, "etc/ssh/keys/100%done"))

    def test_percent_h_is_the_accounts_home(self):
        self.write("home/alice/keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile %h/keys\n")
        observed = [c for c in candidates(ev)
                    if c.get("observation") == model.FILE_READ]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["source_path"],
                         os.path.join(self.base, "home/alice/keys"))

    def test_percent_u_is_the_account_name(self):
        self.write("etc/ssh/keys/alice", self.KEYS)
        ev = self.collect("AuthorizedKeysFile /etc/ssh/keys/%u\n")
        self.assertEqual(len([c for c in candidates(ev)
                              if c.get("observation") == model.FILE_READ]), 1)

    def test_percent_U_is_the_uid_and_is_case_sensitive(self):
        # %U and %u differ only in case. A case-insensitive expansion reads the wrong
        # file and reports it as the declared source.
        self.write("etc/ssh/keys/1000", self.KEYS)
        self.write("etc/ssh/keys/alice", BAIT_KEY)
        ev = self.collect("AuthorizedKeysFile /etc/ssh/keys/%U\n")
        observed = [c for c in candidates(ev)
                    if c.get("observation") == model.FILE_READ]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["source_path"],
                         os.path.join(self.base, "etc/ssh/keys/1000"))
        assert_no_leak(self, ev, BAIT_KEY, "the bait file")

    def test_a_glob_matching_nothing_is_NO_MATCH(self):
        os.makedirs(os.path.join(self.base, "etc/ssh/keys"))
        ev = self.collect("AuthorizedKeysFile /etc/ssh/keys/*.pub\n")
        self.assertIn(model.GLOB_NO_MATCH,
                      [c.get("observation") for c in candidates(ev)])
        self.assertEqual(key_records(ev), [])

    def test_a_glob_matching_several_files_reads_all_of_them(self):
        self.write("etc/ssh/keys/10-a.pub", "ssh-ed25519 %s\n" % ED_A)
        self.write("etc/ssh/keys/20-b.pub", "ssh-ed25519 %s\n" % ED_B)
        ev = self.collect("AuthorizedKeysFile /etc/ssh/keys/*.pub\n")
        observed = [c for c in candidates_of(self.alice(ev))
                    if c.get("observation") == model.FILE_READ]
        self.assertEqual(len(observed), 1, "the glob candidate did not report a read")
        self.assertEqual(len(observed[0]["observed_files"]), 2)
        self.assertEqual(len(records_for_alice(ev)), 2)

    def test_a_glob_expansion_is_ordered_deterministically(self):
        self.write("etc/ssh/keys/20-b.pub", "ssh-ed25519 %s\n" % ED_B)
        self.write("etc/ssh/keys/10-a.pub", "ssh-ed25519 %s\n" % ED_A)
        first = self.collect("AuthorizedKeysFile /etc/ssh/keys/*.pub\n")
        second = self.collect("AuthorizedKeysFile /etc/ssh/keys/*.pub\n")
        def order(ev):
            got = candidates_of(self.alice(ev))
            return [m["path"] for c in got for m in c.get("observed_files", [])]
        self.assertEqual(order(first), order(second))
        self.assertEqual([os.path.basename(p) for p in order(first)],
                         ["10-a.pub", "20-b.pub"])


class HomeEvidence(Lane):

    NO_HOME = ("root:x:0:0:root:/root:/bin/bash\n"
               "alice:x:1000:1000:Alice::/bin/bash\n")

    def test_an_account_with_no_home_field_cannot_expand_a_relative_value(self):
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n",
                          passwd=self.NO_HOME)
        self.assertIn(model.HOME_NOT_AVAILABLE,
                      [c["resolution"] for c in candidates(ev)])
        self.assertEqual(universe_state(self.alice(ev)), model.UNIVERSE_INCOMPLETE)

    def test_a_missing_home_is_not_replaced_by_the_running_users_home(self):
        # os.path.expanduser("~") is the live host's home of whoever runs the tool.
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n",
                          passwd=self.NO_HOME)
        live = os.path.expanduser("~")
        if live and live != "/":
            self.assertNotIn(live, envelope(ev))
        self.assertEqual(key_records(ev), [])

    def test_a_home_that_does_not_exist_on_disk_yields_no_observation(self):
        passwd = ("root:x:0:0:root:/root:/bin/bash\n"
                  "alice:x:1000:1000:Alice:/home/absent:/bin/bash\n")
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n", passwd=passwd)
        self.assertNotIn(model.OBSERVED_FILE,
                         [c["resolution"] for c in candidates(ev)])
        self.assertEqual(key_records(ev), [])

    def test_an_undecodable_home_is_used_exactly_not_repaired(self):
        """The contract said HOME_NOT_AVAILABLE here. The contract was wrong.

        A non-UTF-8 home is a perfectly valid BYTE path on Linux, and textbytes plus
        surrogateescape exist in this project so such paths survive losslessly rather
        than being discarded. Refusing to expand one is not caution: it hands an attacker
        an evasion, because giving an account a non-UTF-8 home would make its authorized
        keys invisible to the tool while remaining entirely usable to sshd.

        What R1 was protecting is the part that matters and is still asserted: the path
        is not GUESSED, and no replacement character reaches the evidence.
        """
        passwd = (b"root:x:0:0:root:/root:/bin/bash\n"
                  b"alice:x:1000:1000:Alice:/home/jos\xe9:/bin/bash\n")
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n", passwd=passwd)
        got = candidates_of(self.alice(ev))
        self.assertEqual([c["resolution"] for c in got],
                         [model.PATH_DERIVED])
        self.assertTrue(os.fsencode(got[0]["path"]).endswith(
            b"/home/jos\xe9/.ssh/authorized_keys"),
            "the undecodable home was not carried through byte-exact")
        self.assertNotIn("�", envelope(ev),
                         "an undecodable home became a replacement character")

    def test_an_undecodable_account_name_still_has_a_lossless_identity(self):
        passwd = (b"root:x:0:0:root:/root:/bin/bash\n"
                  b"jos\xe9:x:1001:1001:Jose:/home/jose:/bin/bash\n")
        self.write("home/jose/.ssh/authorized_keys", "ssh-ed25519 %s\n" % ED_A)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n", passwd=passwd)
        refs = [d for d in walk(ev.as_dict()) if "name_bytes_hex" in d]
        self.assertTrue(refs, "no account_ref carries name_bytes_hex")
        jose = [r for r in refs if r["name_bytes_hex"] == textbytes.hex_of("jos\udce9")]
        self.assertTrue(jose, "the undecodable account lost its identity entirely")
        self.assertIsNone(jose[0]["name"],
                          "an undecodable name must be null, never a guess")
        self.assertNotIn("�", envelope(ev))

    def test_an_undecodable_account_name_is_not_expanded_into_percent_u(self):
        passwd = (b"root:x:0:0:root:/root:/bin/bash\n"
                  b"jos\xe9:x:1001:1001:Jose:/home/jose:/bin/bash\n")
        self.write("etc/ssh/keys/jose", BAIT_KEY)
        ev = self.collect("AuthorizedKeysFile /etc/ssh/keys/%u\n", passwd=passwd)
        self.assertNotIn("�", envelope(ev))
        # Whatever the lane does, it must not read a DIFFERENT account's file.
        assert_no_leak(self, ev, BAIT_KEY, "the bait file")


class UpstreamEvidence(Lane):

    def test_both_evidence_arguments_are_required(self):
        # A default that collected them itself would hide the dependency and make a
        # second acquisition path easy to add by accident.
        self.assertRaises(TypeError, acquire.collect, self.base)

    def test_partial_account_evidence_is_not_reported_as_complete(self):
        # No /etc/shadow under the root: the accounts lane reports PARTIAL, and an
        # account it could not fully describe may be an account whose keys were missed.
        self.write("etc/passwd", self.PASSWD)
        self.write("etc/group", self.GROUP)
        accounts = accounts_acquire.collect(self.base)
        self.assertEqual(accounts["collection_status"], result.PARTIAL)
        self.write("home/alice/.ssh/authorized_keys", "ssh-ed25519 %s\n" % ED_A)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n",
                          account_evidence=accounts)
        self.assertNotEqual(ev.status, result.COLLECTED,
                            "PARTIAL account evidence produced COLLECTED key evidence")
        self.assertTrue(ev.reason)

    def test_partial_ssh_evidence_is_not_reported_as_complete(self):
        ssh = result.Evidence(result.PARTIAL, records=[],
                              reason="MISSING_TARGET: an Include was not read.")
        ev = self.collect(ssh_evidence=ssh)
        self.assertNotEqual(ev.status, result.COLLECTED)

    def test_partial_ssh_evidence_does_not_become_a_complete_universe(self):
        # An Include that was not read may have carried an AuthorizedKeysFile. The set
        # of declarations is therefore not known to be complete.
        ssh = result.Evidence(result.PARTIAL, records=[],
                              reason="MISSING_TARGET: an Include was not read.")
        ev = self.collect(ssh_evidence=ssh)
        self.assertEqual(universe_state(self.alice(ev)), model.UNIVERSE_INCOMPLETE)

    def test_errored_ssh_evidence_invents_nothing(self):
        self.write("home/alice/.ssh/authorized_keys", BAIT_KEY)
        ssh = result.Evidence(result.ERROR, records=[],
                              reason="SOURCE_UNREADABLE: sshd_config could not be read.")
        ev = self.collect(ssh_evidence=ssh)
        self.assertEqual(key_records(ev), [])
        assert_no_leak(self, ev, BAIT_KEY, "the bait file")
        self.assertNotEqual(ev.status, result.COLLECTED)

    def test_the_upstream_status_is_recorded_not_merely_absorbed(self):
        ssh = result.Evidence(result.PARTIAL, records=[],
                              reason="MISSING_TARGET: an Include was not read.")
        ev = self.collect(ssh_evidence=ssh)
        self.assertIn("MISSING_TARGET", envelope(ev),
                      "the upstream reason vanished; a reader cannot see why the "
                      "declaration set is not known to be complete")


# =============================================================================
# 6. The completeness invariant
# =============================================================================

class SourceUniverse(Lane):
    """A file observed successfully does not make the universe complete."""

    KEYS = "ssh-ed25519 %s\n" % ED_A

    def test_one_perfect_read_beside_one_unresolvable_declaration(self):
        # THE invariant. Reading .ssh/authorized_keys proves that file's content; the
        # %q declaration proves the set of sources is not known.
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n"
                          "AuthorizedKeysFile /etc/ssh/keys/%q\n")
        got = candidates_of(self.alice(ev))
        self.assertIn(model.FILE_READ, [c.get("observation") for c in got])
        self.assertIn(model.UNEXPANDED_TOKEN, [c["resolution"] for c in got])
        self.assertEqual(len(records_for_alice(ev)), 1)
        self.assertEqual(universe_state(self.alice(ev)), model.UNIVERSE_INCOMPLETE)

    def test_an_incomplete_universe_says_why(self):
        ev = self.collect("AuthorizedKeysFile /etc/ssh/keys/%q\n")
        self.assertTrue(universe_reasons(self.alice(ev)),
                        "INCOMPLETE with no reason tells the reader nothing")

    def test_a_complete_universe_is_still_reachable(self):
        # The control. A lane that answered INCOMPLETE unconditionally would pass every
        # negative assertion in this class and be worthless.
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertEqual(universe_state(self.alice(ev)), model.UNIVERSE_COMPLETE)

    def test_the_universe_is_decided_per_account_not_per_host(self):
        passwd = ("root:x:0:0:root:/root:/bin/bash\n"
                  "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
                  "nohome:x:1001:1001:No home::/bin/bash\n")
        group = "root:x:0:\nalice:x:1000:\nnohome:x:1001:\n"
        shadow = ("root:*:19000:0:99999:7:::\nalice:*:19000:0:99999:7:::\n"
                  "nohome:*:19000:0:99999:7:::\n")
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n",
                          passwd=passwd, group=group, shadow=shadow)
        self.assertEqual(universe_state(self.alice(ev)), model.UNIVERSE_COMPLETE)
        nohome = [u for u in universes(ev)
                  if textbytes.hex_of("nohome") in dumped(u)]
        self.assertTrue(nohome)
        self.assertEqual(universe_state(nohome[0]), model.UNIVERSE_INCOMPLETE)

    def test_an_observed_file_is_a_candidate_that_was_read(self):
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        observed = [c for c in candidates(ev)
                    if c.get("observation") == model.FILE_READ]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["kind"], model.DECLARED_CANDIDATE_SOURCE)

    def test_every_key_record_carries_its_position_and_its_account_reference(self):
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        for record in key_records(ev):
            self.assertIn("source_path", record)
            self.assertIn("source_line", record)
            self.assertIn("ordinal", record)
            reference = record["account_ref"]
            self.assertEqual(reference["source"], "LOCAL_ACCOUNT_FILES")
            self.assertEqual(reference["nss_source"], "files")
            self.assertEqual(reference["name_bytes_hex"], ALICE_HEX)
            self.assertEqual(reference["uid"], 1000)
            self.assertIn("passwd_line", reference)

    def test_the_account_reference_is_a_reference_not_a_copy(self):
        # A copy of the account record would duplicate STATE the accounts lane owns,
        # and gecos - which carries personal data - would travel with it.
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        for record in key_records(ev):
            for field in ("shell", "gecos", "primary_gid", "shadow",
                          "password_state", "home"):
                self.assertNotIn(field, record["account_ref"], field)

    def test_the_openssh_version_travels_with_the_evidence(self):
        # "Record the OpenSSH version with the evidence; a token table is version
        # specific." A token table with no version attached cannot be audited later.
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertIn("openssh_version", ev.provenance)

    def test_the_lane_declares_what_it_does_not_claim(self):
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertIn("limitation", ev.provenance)
        self.assertTrue(ev.provenance["limitation"])


# =============================================================================
# 7. Acquisition - the file layer
# =============================================================================

class Acquisition(Lane):

    KEYS = "ssh-ed25519 %s\n" % ED_A

    def test_a_declared_file_that_is_absent_is_a_normal_host(self):
        # Most accounts have no authorized_keys. If this is not COLLECTED the status is
        # worthless, because nearly every host will be PARTIAL.
        os.makedirs(os.path.join(self.base, "home/alice"))
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual(key_records(ev), [])
        self.assertNotIn(model.OBSERVED_FILE,
                         [c["resolution"] for c in candidates(ev)])

    def test_an_absent_named_file_is_not_the_same_as_a_glob_with_no_match(self):
        os.makedirs(os.path.join(self.base, "home/alice/.ssh"))
        named = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        globbed = self.collect("AuthorizedKeysFile .ssh/*.keys\n")
        self.assertNotEqual([c.get("observation") for c in candidates(named)],
                            [c.get("observation") for c in candidates(globbed)])
        self.assertIn(model.GLOB_NO_MATCH,
                      [c.get("observation") for c in candidates(globbed)])
        self.assertIn(model.FILE_ABSENT,
                      [c.get("observation") for c in candidates(named)])

    def test_an_unreadable_file_is_reported_and_not_reported_as_empty(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores these permission bits")
        path = self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        os.chmod(path, 0)
        # LIFO: this runs BEFORE the rmtree registered in setUp, so it restores the
        # mode on a path that still exists.
        self.addCleanup(os.chmod, path, 0o600)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertNotEqual(ev.status, result.COLLECTED)
        self.assertEqual(key_records(ev), [])
        self.assertEqual(universe_state(self.alice(ev)), model.UNIVERSE_INCOMPLETE)

    def test_a_declared_path_that_is_a_directory_is_not_read_as_a_file(self):
        os.makedirs(os.path.join(self.base, "home/alice/.ssh/authorized_keys"))
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertEqual(key_records(ev), [])
        self.assertNotIn(model.OBSERVED_FILE,
                         [c["resolution"] for c in candidates(ev)])

    def test_a_symlink_to_a_file_inside_the_root_is_read(self):
        self.write("home/alice/.ssh/real_keys", self.KEYS)
        os.symlink(os.path.join(self.base, "home/alice/.ssh/real_keys"),
                   os.path.join(self.base, "home/alice/.ssh/authorized_keys"))
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertEqual(len(key_records(ev)), 1)
        for record in key_records(ev):
            self.assertTrue(record["source_path"].startswith(self.base))

    def test_a_dangling_symlink_is_not_an_observation(self):
        os.makedirs(os.path.join(self.base, "home/alice/.ssh"))
        os.symlink(os.path.join(self.base, "home/alice/.ssh/gone"),
                   os.path.join(self.base, "home/alice/.ssh/authorized_keys"))
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertEqual(key_records(ev), [])

    def test_undecodable_bytes_in_the_key_file_never_become_a_replacement_char(self):
        content = (b"ssh-ed25519 " + ED_A.encode("ascii") + b" jos\xe9\n" +
                   b"ssh-ed25519 " + ED_B.encode("ascii") + b"\n")
        self.write("home/alice/.ssh/authorized_keys", content)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertNotIn("�", envelope(ev))
        # The undecodable byte is in a COMMENT, which is not retained anyway - so the
        # second key must still be collected normally.
        self.assertEqual(len(key_records(ev)), 2)

    def test_a_key_file_of_pure_binary_does_not_produce_key_claims(self):
        self.write("home/alice/.ssh/authorized_keys", bytes(bytearray(range(256))))
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertNotIn("�", envelope(ev))
        for record in key_records(ev):
            self.assertNotEqual(record["parse_status"], model.PARSE_OK)

    def test_file_metadata_is_observed_for_every_candidate_that_was_read(self):
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        files = ev.provenance.get("files")
        self.assertTrue(files, "no file metadata was recorded")
        for entry in files:
            for field in ("requested_path", "uid", "gid", "mode", "file_type"):
                self.assertIn(field, entry)

    def test_the_lane_is_deterministic_across_two_identical_collections(self):
        self.write("home/alice/.ssh/authorized_keys",
                   "ssh-ed25519 %s\nssh-ed25519 %s\n" % (ED_A, ED_B))
        first = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        second = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assertEqual(dumped(first.records), dumped(second.records))


# =============================================================================
# 8. Root containment
# =============================================================================

class RootEscape(unittest.TestCase):
    """Nothing outside the collection root may enter the evidence.

    Hermetic by construction: the bait lives in a SIBLING of the collection root, inside
    this test's own temporary directory. The attack is observable without the machine
    running the test being involved at all - a test that proved this by reading the live
    /etc or the live home directory would itself be the defect.
    """

    TOKEN = "baitkeyoutsidetheroot"
    BAIT = "ssh-ed25519 %s %s\n" % (blob(b"ssh-ed25519", b"\xba\x17" * 16), TOKEN)

    def setUp(self):
        self.enclosure = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.enclosure, True)
        self.root = os.path.join(self.enclosure, "root")
        self.outside = os.path.join(self.enclosure, "outside")
        os.makedirs(os.path.join(self.root, "etc", "ssh"))
        os.makedirs(self.outside)
        self.write_outside("bait", self.BAIT)
        self.write_outside("authorized_keys", self.BAIT)

    def write_outside(self, name, text):
        with open(os.path.join(self.outside, name), "w") as handle:
            handle.write(text)

    def write(self, relative, text):
        path = os.path.join(self.root, relative)
        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        with open(path, "w") as handle:
            handle.write(text)
        return path

    def collect(self, config, passwd=DEFAULT_PASSWD):
        self.write("etc/passwd", passwd)
        self.write("etc/group", DEFAULT_GROUP)
        self.write("etc/shadow", DEFAULT_SHADOW)
        self.write("etc/ssh/sshd_config", config)
        return acquire.collect(self.root,
                               accounts_acquire.collect(self.root),
                               ssh_acquire.collect(self.root))

    def absolute_paths(self, ev):
        """Every absolute path anywhere in the evidence, normalised.

        Collecting them from the serialised object rather than from one known key is
        deliberate: an escape that surfaced only in a reason string would still be an
        escape, and it is the kind a targeted assertion walks straight past.
        """
        found = []
        for candidate in re.findall(r"/[A-Za-z0-9_./*%-]+", envelope(ev)):
            found.append(os.path.normpath(candidate))
        return found

    def assert_contained(self, ev, what):
        for path in self.absolute_paths(ev):
            if path.startswith(self.enclosure) or path.startswith("/tmp"):
                self.assertTrue(
                    path == self.root or path.startswith(self.root + os.sep),
                    "%s produced %r, outside the collection root" % (what, path))

    def assert_bait_unread(self, ev, what):
        blob_text = envelope(ev)
        for marker in leak_markers(self.BAIT):
            self.assertNotIn(marker, blob_text,
                             "%s read outside the collection root (%r leaked)"
                             % (what, marker))

    def test_a_declaration_climbing_above_the_root_stays_inside_it(self):
        what = "an absolute AuthorizedKeysFile with .."
        ev = self.collect("AuthorizedKeysFile /etc/ssh/../../../outside/bait\n")
        self.assert_contained(ev, what)
        self.assert_bait_unread(ev, what)

    def test_a_relative_declaration_climbing_above_the_root_stays_inside_it(self):
        what = "a home-relative AuthorizedKeysFile with .."
        ev = self.collect("AuthorizedKeysFile ../../../../outside/bait\n")
        self.assert_contained(ev, what)
        self.assert_bait_unread(ev, what)

    def test_a_glob_climbing_above_the_root_enumerates_nothing_outside(self):
        what = "a glob with .."
        ev = self.collect("AuthorizedKeysFile /etc/ssh/../../../outside/*\n")
        self.assert_contained(ev, what)
        self.assert_bait_unread(ev, what)

    def test_a_home_containing_dotdot_cannot_reach_outside(self):
        what = "a home with .."
        passwd = ("root:x:0:0:root:/root:/bin/bash\n"
                  "alice:x:1000:1000:Alice:/home/../../outside:/bin/bash\n")
        ev = self.collect("AuthorizedKeysFile %h/authorized_keys\n", passwd=passwd)
        self.assert_contained(ev, what)
        self.assert_bait_unread(ev, what)

    def test_a_home_containing_dotdot_with_a_relative_declaration(self):
        what = "a home with .. and a relative declaration"
        passwd = ("root:x:0:0:root:/root:/bin/bash\n"
                  "alice:x:1000:1000:Alice:/home/../../outside:/bin/bash\n")
        ev = self.collect("AuthorizedKeysFile authorized_keys\n", passwd=passwd)
        self.assert_contained(ev, what)
        self.assert_bait_unread(ev, what)

    def test_a_symlink_pointing_outside_the_root_is_not_followed_out(self):
        what = "a symlink out of the root"
        os.makedirs(os.path.join(self.root, "home", "alice", ".ssh"))
        os.symlink(os.path.join(self.outside, "authorized_keys"),
                   os.path.join(self.root, "home/alice/.ssh/authorized_keys"))
        ev = self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")
        self.assert_bait_unread(ev, what)

    def test_a_home_that_is_a_symlink_out_of_the_root_is_not_followed(self):
        what = "a home that is a symlink out of the root"
        os.makedirs(os.path.join(self.root, "home"))
        os.symlink(self.outside, os.path.join(self.root, "home", "alice"))
        # Lexically the candidate path is inside the root. The escape
        # is the kernel's, at open() time, which is why lexical containment alone is
        # not the whole answer.
        ev = self.collect("AuthorizedKeysFile authorized_keys\n")
        self.assert_bait_unread(ev, what)

    def test_the_host_meaning_of_a_path_is_still_honoured(self):
        # Clamping everything to the root would pass every test above and be wrong.
        # `/etc/ssh/../keys/alice` names `/etc/keys/alice` on a host, so under a root it
        # names that path beneath the root - and the file there must still be read.
        self.write("etc/keys/alice", "ssh-ed25519 %s insidemarker\n" % ED_A)
        ev = self.collect("AuthorizedKeysFile /etc/ssh/../keys/%u\n")
        observed = [c for c in candidates(ev)
                    if c.get("observation") == model.FILE_READ]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["source_path"],
                         os.path.join(self.root, "etc/keys/alice"))


# =============================================================================
# 9. No verdicts, no second acquisition path, no impurity
# =============================================================================

VERDICT_WORDS = ("TRUSTED", "SECURE", "INSECURE", "WEAK", "EXPOSED",
                 "GRANTS_LOGIN", "CAN_LOGIN")
# EFFECTIVE_SOURCE left this list deliberately when IQ-014 gave the lane an
# effectiveness AXIS that exists in order to say NOT_EVALUATED. It is covered by
# test_every_effectiveness_field_denies_rather_than_asserts, which checks the VALUE
# rather than the spelling and is the stronger rule.

PERSON_FIELDS = ("owner", "person", "belongs_to", "holder", "human", "employee",
                 "identity_of", "key_owner", "principal_name")


class NoVerdicts(Lane):
    """R1.5 records source facts. Trust, exposure and effectiveness are later layers."""

    KEYS = ('restrict,command="/bin/true",from="10.0.0.0/8" ssh-ed25519 %s alice\n'
            % ED_A)

    def evidence(self):
        self.write("home/alice/.ssh/authorized_keys", self.KEYS)
        return self.collect("AuthorizedKeysFile .ssh/authorized_keys\n")

    def test_the_payload_carries_no_verdict_vocabulary(self):
        blob_text = payload(self.evidence()).upper()
        for word in VERDICT_WORDS:
            self.assertNotIn(word, blob_text, word)

    def test_the_payload_carries_no_finding_vocabulary(self):
        blob_text = payload(self.evidence()).lower()
        for word in ("finding", "risk", "severity", "recommend", "compliant",
                     "hardened", "dangerous", "safe_", "vulnerab"):
            self.assertNotIn(word, blob_text, word)

    def test_no_field_name_claims_effectiveness_anywhere_in_the_envelope(self):
        # These tokens have no honest place even in limitation prose, which says what is
        # NOT claimed in sentences rather than in SCREAMING_SNAKE field names.
        blob_text = envelope(self.evidence())
        for token in ("GRANTS_LOGIN", "CAN_LOGIN", "effective_sources",
                      "will_be_used", "sshd_will_use"):
            self.assertNotIn(token, blob_text, token)

    def test_every_effectiveness_field_denies_rather_than_asserts(self):
        """The IQ-014 axis must be readable without becoming sayable.

        R1 banned the token EFFECTIVE_SOURCE outright, and that was right while the lane
        had no effectiveness axis at all. The owner ruling requires one - an explicit
        `effective_source_universe: NOT_EVALUATED` - so the ban would now forbid the lane
        from SAYING it does not know, which is the opposite of the intent. This is the
        same trap R1 flagged in Q11 for limitation prose, one layer deeper.

        The rule that survives is semantic, and is stronger than the lexical one: a field
        whose name mentions effectiveness may exist, and its value may ONLY be a denial.
        A path, a boolean, a count or an account name there would be the claim.
        """
        denials = frozenset([model.EFFECTIVE_NOT_EVALUATED,
                             model.EFFECTIVE_REASON_MATCH_UNRESOLVED,
                             model.EFFECTIVE_REASON_NOT_IN_SCOPE])
        seen = 0
        for entry in walk(self.evidence().as_dict()):
            for key, value in entry.items():
                if "effective" not in key.lower():
                    continue
                seen += 1
                values = value if isinstance(value, list) else [value]
                for item in values:
                    self.assertIn(item, denials,
                                  "%s carries %r, which asserts effectiveness rather "
                                  "than denying it" % (key, item))
        self.assertTrue(seen, "the effectiveness axis vanished; IQ-014 requires it to "
                              "be present and to say NOT_EVALUATED")
        # Per RECORD, not merely somewhere in the envelope. A falsification injection
        # that deleted the record-level field passed while the plan-level one survived,
        # which means "the axis exists" was being proved by the wrong object: a key
        # travels further than the plan it came from, and must carry its own denial.
        evidence = self.evidence()
        self.assertTrue(key_records(evidence), "no key record to check")
        for record in key_records(evidence):
            self.assertEqual(record.get("effective_source"),
                             model.EFFECTIVE_NOT_EVALUATED,
                             "a key record left the lane without the denial attached")

    def test_no_field_claims_a_key_belongs_to_a_person(self):
        ev = self.evidence()
        for record in key_records(ev) + candidates(ev):
            for field in PERSON_FIELDS:
                self.assertNotIn(field, record, field)

    def test_options_are_recorded_without_being_interpreted(self):
        records = key_records(self.evidence())
        self.assertEqual(len(records), 1, "the declared key was not collected at all")
        record = records[0]
        self.assertIn("restrict", option_names(record))
        blob_text = dumped(record).lower()
        for word in ("restricted", "confined", "limited_to", "forced_command"):
            self.assertNotIn(word, blob_text, word)

    def test_the_lane_does_not_claim_these_are_the_files_sshd_will_use(self):
        ev = self.evidence()
        for entry in candidates(ev):
            self.assertEqual(entry["kind"], model.DECLARED_CANDIDATE_SOURCE)
            self.assertNotIn("effective", dumped(entry).lower())


def lane_modules():
    """Every .py file of the lane, by path."""
    directory = os.path.dirname(os.path.abspath(inspect.getsourcefile(model)))
    return sorted(os.path.join(directory, name)
                  for name in os.listdir(directory) if name.endswith(".py"))


def tree_of(path):
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

    Docstrings and bare string expressions are excluded on purpose. A module that says
    "the lane MUST NOT read /etc/passwd again" in its own header is stating the rule,
    not breaking it, and an assertion that punished it would push the explanation out
    of the file - which is how the prohibition gets forgotten.
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


class NoSecondAccountPath(unittest.TestCase):
    """There is one account model and one acquisition path for it.

    A lane that reads /etc/passwd again, or calls pwd.getpwnam, has created a second
    source of account truth that can disagree with the first - and the disagreement
    would surface as a key attributed to the wrong account.
    """

    def test_the_lane_does_not_name_the_passwd_file(self):
        for path in lane_modules():
            for text in string_constants(tree_of(path)):
                self.assertNotIn("/etc/passwd", text, path)
                self.assertNotIn("etc/passwd", text, path)

    def test_the_lane_mentions_passwd_only_as_the_reference_field(self):
        # `passwd_line` is part of the account_ref the contract prints, so it is the one
        # permitted occurrence. Anything else - a literal, an attribute, a helper named
        # `read_passwd` - is a second derivation of account truth.
        pattern = re.compile(r"passwd(?!_line\b)", re.IGNORECASE)
        for path in lane_modules():
            tree = tree_of(path)
            for text in string_constants(tree) + sorted(identifiers(tree)):
                found = pattern.findall(text)
                self.assertEqual(found, [],
                                 "%s re-derives passwd via %r" % (path, text))

    def test_the_lane_does_not_import_the_account_acquisition_path(self):
        # isedraf.accounts.model is vocabulary and is fine. acquire and sources ARE the
        # acquisition path, and importing either creates a second one.
        for path in lane_modules():
            for name in imported(tree_of(path)):
                parts = name.replace(".", " ").split()
                if "accounts" not in parts:
                    continue
                for leaf in ("acquire", "sources"):
                    self.assertNotIn(leaf, parts,
                                     "%s imports the account acquisition path via %r"
                                     % (path, name))

    def test_the_lane_does_not_import_a_relative_accounts_acquirer(self):
        # `from ..accounts import acquire` shows up as ".." plus "..acquire".
        for path in lane_modules():
            names = imported(tree_of(path))
            for name in names:
                self.assertFalse(name.endswith("accounts.acquire")
                                 or name.endswith("accounts.sources"),
                                 "%s imports %r" % (path, name))

    def test_the_lane_does_not_use_the_pwd_module(self):
        for path in lane_modules():
            tree = tree_of(path)
            self.assertNotIn("pwd", imported(tree), path)
            for name in ("getpwnam", "getpwuid", "getpwall", "getgrnam", "getgrgid"):
                self.assertNotIn(name, identifiers(tree), "%s uses %s" % (path, name))

    def test_the_lane_does_not_resolve_a_home_from_the_running_user(self):
        # expanduser reads $HOME - the home of whoever runs ISEDRAF, on the LIVE host.
        for path in lane_modules():
            tree = tree_of(path)
            for name in ("expanduser", "expandvars", "getlogin", "getuid", "geteuid"):
                self.assertNotIn(name, identifiers(tree), "%s uses %s" % (path, name))

    def test_the_lane_does_not_re_parse_sshd_config(self):
        """The rule is "no second parser", not "never say the word".

        R1 forbade the token `sshd_config` in any string constant, and the lane's own
        reason text cites `sshd_config(5)` as the authority for its token table - which
        is the opposite of re-parsing, and is exactly the provenance a reader needs. The
        fourth time in this project that a prose mention has tripped a text assertion;
        the answer each time has been to make the assertion precise rather than to make
        the code less explained. What must not appear is a PATH to the file.
        """
        for path in lane_modules():
            for text in string_constants(tree_of(path)):
                self.assertNotIn("etc/ssh/sshd_config", text, path)
                self.assertFalse(text.rstrip("/").endswith("/sshd_config"), path)
            self.assertNotIn("isedraf.ssh.sources", " ".join(imported(tree_of(path))))


class PureParser(unittest.TestCase):
    """sources.py is text in, records out. Nothing else."""

    FORBIDDEN_NAMES = ("open", "listdir", "scandir", "walk", "stat", "lstat", "fstat",
                       "environ", "getenv", "putenv", "getcwd", "chdir", "expanduser",
                       "expandvars", "realpath", "abspath", "readlink", "Popen",
                       "check_output", "check_call", "popen", "system", "fdopen",
                       "read_text", "read_bytes", "iglob", "urlopen", "socket",
                       "connect", "mkdtemp", "remove", "unlink")

    FORBIDDEN_IMPORTS = ("os", "subprocess", "socket", "ssl", "urllib", "http",
                         "glob", "shutil", "pathlib", "tempfile", "pickle",
                         "sqlite3", "asyncio", "ctypes")

    def setUp(self):
        self.path = os.path.abspath(inspect.getsourcefile(sources))
        self.tree = tree_of(self.path)

    def test_sources_performs_no_io(self):
        used = identifiers(self.tree)
        for name in self.FORBIDDEN_NAMES:
            self.assertNotIn(name, used, "sources.py uses %s" % name)

    def test_sources_imports_nothing_that_can_touch_the_host(self):
        for entry in imported(self.tree):
            parts = [part for part in entry.replace(".", " ").split() if part]
            for name in self.FORBIDDEN_IMPORTS:
                self.assertNotIn(name, parts,
                                 "sources.py imports %r, which reaches the host"
                                 % entry)

    def test_sources_names_no_absolute_path(self):
        # A pure parser has no filesystem to name.
        for text in string_constants(self.tree):
            self.assertFalse(text.startswith("/") and len(text) > 1,
                             "sources.py names an absolute path %r" % text)

    def test_model_is_vocabulary_with_no_io(self):
        # The contract makes acquire.py "the only module that touches the host".
        model_tree = tree_of(os.path.abspath(inspect.getsourcefile(model)))
        for name in ("open", "listdir", "Popen", "stat", "environ", "expanduser"):
            self.assertNotIn(name, identifiers(model_tree),
                             "model.py uses %s" % name)

    def test_parsing_the_same_text_twice_gives_the_same_records(self):
        text = ("# comment\n%s alice@example.invalid\n"
                'command="x",no-pty ssh-ed25519 %s\n' % (VALID, ED_B))
        self.assertEqual(dumped(parse(text)), dumped(parse(text)))


# =============================================================================
# 10. Fingerprints
# =============================================================================

def have_ssh_keygen():
    return shutil.which("ssh-keygen") is not None


class Fingerprints(unittest.TestCase):

    def test_the_same_key_gives_the_same_fingerprint_twice(self):
        self.assertEqual(one(VALID + "\n")["key_fingerprint"],
                         one(VALID + "\n")["key_fingerprint"])

    def test_two_different_keys_give_different_fingerprints(self):
        self.assertNotEqual(one("ssh-ed25519 %s\n" % ED_A)["key_fingerprint"],
                            one("ssh-ed25519 %s\n" % ED_B)["key_fingerprint"])

    def test_the_fingerprint_is_over_the_blob_not_the_line(self):
        # A digest of the whole line would change when a comment or an option changed,
        # and the same key on two hosts would then look like two keys.
        plain = one("ssh-ed25519 %s\n" % ED_A)["key_fingerprint"]
        dressed = one('no-pty,command="x" ssh-ed25519 %s someone@example.invalid\n'
                      % ED_A)["key_fingerprint"]
        self.assertEqual(plain, dressed)

    def test_the_digest_algorithm_is_declared(self):
        record = one(VALID + "\n")
        self.assertTrue(record["key_digest_algorithm"])
        self.assertEqual(one(VALID + "\n")["key_digest_algorithm"],
                         record["key_digest_algorithm"])

    def test_a_key_that_did_not_parse_has_no_fingerprint(self):
        for text in ("ssh-ed25519 %s\n" % BAD_B64,
                     "ssh-ed25519 %s\n" % NOT_A_BLOB,
                     "no-pty\n"):
            self.assertIsNone(one(text)["key_fingerprint"], text)

    @unittest.skipUnless(have_ssh_keygen(), "ssh-keygen is not installed")
    def test_the_fingerprint_agrees_with_ssh_keygen(self):
        """ORACLE_LEVEL_1: an external, independent implementation of the answer.

        OpenSSH's SHA256 fingerprint is the SHA-256 of the decoded key blob. Comparing
        against ssh-keygen -lf rather than against a second call of our own parser is
        the difference between testing correctness and testing self-consistency.

        The key is generated into a private temporary directory. No real key is read.
        """
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        private = os.path.join(directory, "k")
        environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        subprocess.check_call(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
             "oracle@example.invalid", "-f", private],
            shell=False, env=environment, timeout=60,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        with open(private + ".pub", "r") as handle:
            public_line = handle.read()

        listed = subprocess.check_output(
            ["ssh-keygen", "-l", "-E", "sha256", "-f", private + ".pub"],
            shell=False, env=environment, timeout=60,
            stdin=subprocess.DEVNULL).decode("ascii")
        oracle = [word for word in listed.split() if word.startswith("SHA256:")]
        self.assertTrue(oracle, "ssh-keygen -lf produced no SHA256 fingerprint: %r"
                        % listed)
        base64_form = oracle[0].split(":", 1)[1]
        raw = base64.b64decode(base64_form + "=" * (-len(base64_form) % 4))
        hex_form = "".join("%02x" % byte for byte in bytearray(raw))

        record = one(public_line)
        self.assertEqual(record["parse_status"], model.PARSE_OK)
        self.assertEqual(record["key_type"], "ssh-ed25519")
        printed = str(record["key_fingerprint"])
        self.assertTrue(
            base64_form in printed or hex_form in printed.lower(),
            "lane fingerprint %r matches neither ssh-keygen's %r nor its hex form %r"
            % (printed, oracle[0], hex_form))

    @unittest.skipUnless(have_ssh_keygen(), "ssh-keygen is not installed")
    def test_ssh_keygen_agrees_about_a_hand_built_blob(self):
        """The oracle applied to the fixture material the rest of the suite uses.

        If ssh-keygen and the lane disagree about ED_A, every other assertion in this
        file that leans on ED_A is resting on a blob OpenSSH would not accept.
        """
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "hand.pub")
        with open(path, "w") as handle:
            handle.write("ssh-ed25519 %s hand@example.invalid\n" % ED_A)
        environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        listed = subprocess.check_output(
            ["ssh-keygen", "-l", "-E", "sha256", "-f", path],
            shell=False, env=environment, timeout=60,
            stdin=subprocess.DEVNULL).decode("ascii")
        base64_form = [w for w in listed.split() if w.startswith("SHA256:")][0]
        base64_form = base64_form.split(":", 1)[1]
        # Independently: OpenSSH hashes the decoded blob itself.
        expected = base64.b64encode(
            hashlib.sha256(base64.b64decode(ED_A)).digest()).decode("ascii").rstrip("=")
        self.assertEqual(base64_form, expected)
        printed = str(one("ssh-ed25519 %s\n" % ED_A)["key_fingerprint"])
        hex_form = hashlib.sha256(base64.b64decode(ED_A)).hexdigest()
        self.assertTrue(base64_form in printed or hex_form in printed.lower(),
                        "lane fingerprint %r does not agree with ssh-keygen"
                        % printed)


if __name__ == "__main__":
    unittest.main(verbosity=0)
