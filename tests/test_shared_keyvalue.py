# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: S1 key/value framework — grammar comes from the profile, meaning does not.
# Implements: SCOPE-022, SCOPE-045, GOV-002
#
# The profiles here are TEST grammars. No real format's profile appears: coupling the
# framework to its first consumer is the failure the shared-primitive rule prevents.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================

"""S1 — key/value parsing framework."""
import ast
import inspect
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from isedraf.shared import keyvalue, result                # noqa: E402


class Equals(keyvalue.Profile):
    name = "equals"


class Spaced(keyvalue.Profile):
    name = "spaced"
    whitespace_delimited = True


class Rich(keyvalue.Profile):
    name = "rich"
    inline_comments = True
    allow_continuation = True
    case_insensitive_keys = True
    strip_quotes = True
    section_pattern = r"^\[([^\]]+)\]$"


class Preservation(unittest.TestCase):
    """The parser preserves declarations. It does not decide effective configuration."""

    def test_duplicates_are_both_kept_in_order(self):
        ev = keyvalue.parse("Key=a\nKey=b\nKey=c\n", Equals())
        self.assertEqual([r["value"] for r in ev.records], ["a", "b", "c"])
        self.assertEqual([r["source_line"] for r in ev.records], [1, 2, 3])

    def test_duplicate_is_marked_but_not_resolved(self):
        ev = keyvalue.parse("Key=a\nKey=b\n", Equals())
        self.assertEqual(ev.records[1]["duplicate_of"], 1)
        self.assertIn(keyvalue.DUPLICATE_KEY, ev.records[1]["anomalies"])
        # No effective value is computed anywhere in the result.
        self.assertNotIn("effective", json.dumps(ev.as_dict()))

    def test_duplicate_policy_is_recorded_not_applied(self):
        class LastWins(Equals):
            duplicate_policy = keyvalue.LAST_WINS

        ev = keyvalue.parse("Key=a\nKey=b\n", LastWins())
        self.assertEqual(ev.provenance["grammar"]["duplicate_policy"],
                         keyvalue.LAST_WINS)
        self.assertEqual(len(ev.records), 2)

    def test_empty_value_policy_is_recorded_not_applied(self):
        class Unset(Equals):
            empty_value_policy = keyvalue.EMPTY_IS_UNSET

        ev = keyvalue.parse("Key=\n", Unset())
        self.assertEqual(ev.records[0]["value"], "")
        self.assertTrue(ev.records[0]["empty"])
        self.assertEqual(ev.provenance["grammar"]["empty_value_policy"],
                         keyvalue.EMPTY_IS_UNSET)

    def test_declarations_are_not_sorted(self):
        ev = keyvalue.parse("Zeta=1\nAlpha=2\n", Equals())
        self.assertEqual([r["key"] for r in ev.records], ["Zeta", "Alpha"])

    def test_unknown_key_is_evidence_not_an_error(self):
        # A format gains options over time. A collector that errored on an option it had
        # not heard of would fail on every host newer than itself.
        ev = keyvalue.parse("SomeOptionInventedLastTuesday=1\n", Equals())
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual(ev.records[0]["key"], "SomeOptionInventedLastTuesday")


class Grammar(unittest.TestCase):
    """Every syntactic behaviour comes from the profile."""

    def test_whitespace_delimited(self):
        ev = keyvalue.parse("Key   some value here\n", Spaced())
        self.assertEqual(ev.records[0]["key"], "Key")
        self.assertEqual(ev.records[0]["value"], "some value here")

    def test_equals_delimited_keeps_later_equals_in_the_value(self):
        ev = keyvalue.parse("Key=a=b=c\n", Equals())
        self.assertEqual(ev.records[0]["value"], "a=b=c")

    def test_inline_comments_only_when_the_profile_allows_them(self):
        text = "Key=value # trailing\n"
        self.assertEqual(keyvalue.parse(text, Equals()).records[0]["value"],
                         "value # trailing")
        self.assertEqual(keyvalue.parse(text, Rich()).records[0]["value"], "value")

    def test_full_line_comments_and_blanks_are_skipped_everywhere(self):
        ev = keyvalue.parse("# c\n\n   \nKey=v\n", Equals())
        self.assertEqual(len(ev.records), 1)
        self.assertEqual(ev.status, result.COLLECTED)

    def test_quotes_stripped_only_when_the_profile_says_so(self):
        text = 'Key="quoted"\n'
        self.assertEqual(keyvalue.parse(text, Equals()).records[0]["value"], '"quoted"')
        self.assertEqual(keyvalue.parse(text, Rich()).records[0]["value"], "quoted")

    def test_case_insensitivity_normalizes_key_but_keeps_the_raw_form(self):
        ev = keyvalue.parse("KeyName=v\n", Rich())
        self.assertEqual(ev.records[0]["key"], "keyname")
        self.assertEqual(ev.records[0]["key_raw"], "KeyName")

    def test_case_sensitive_profile_does_not_merge_two_keys(self):
        ev = keyvalue.parse("Key=a\nkey=b\n", Equals())
        self.assertNotIn("duplicate_of", ev.records[1])

    def test_continuation_joins_only_when_allowed(self):
        text = "Key=one \\\ntwo\n"
        rich = keyvalue.parse(text, Rich())
        self.assertEqual(rich.records[0]["value"], "one two")
        self.assertTrue(rich.records[0]["continued"])
        plain = keyvalue.parse(text, Equals())
        self.assertEqual(plain.records[0]["value"], "one \\")

    def test_unterminated_continuation_is_recorded(self):
        ev = keyvalue.parse("Key=one \\\n", Rich())
        self.assertTrue(any("unterminated" in a["detail"] for a in ev.anomalies))

    def test_sections_scope_duplicate_detection(self):
        ev = keyvalue.parse("[a]\nKey=1\n[b]\nKey=2\n", Rich())
        self.assertEqual([r["section"] for r in ev.records], ["a", "b"])
        self.assertNotIn("duplicate_of", ev.records[1])

    def test_unusual_whitespace_is_tolerated(self):
        ev = keyvalue.parse("\tKey   =   value  \n", Equals())
        self.assertEqual(ev.records[0]["key"], "Key")
        self.assertEqual(ev.records[0]["value"], "value")


class Malformed(unittest.TestCase):

    def test_line_without_delimiter_is_retained_and_counted(self):
        ev = keyvalue.parse("Key=v\nnonsense\n", Equals())
        self.assertEqual(ev.status, result.PARTIAL)
        self.assertEqual(len(ev.records), 2)
        self.assertTrue(ev.records[1]["malformed"])
        self.assertIn(keyvalue.NO_DELIMITER, ev.records[1]["anomalies"])

    def test_every_line_malformed_is_error(self):
        ev = keyvalue.parse("nonsense\nmore nonsense\n", Equals())
        self.assertEqual(ev.status, result.ERROR)
        self.assertIn("UNPARSEABLE", ev.reason)

    def test_empty_source_is_collected(self):
        ev = keyvalue.parse("", Equals())
        self.assertEqual(ev.status, result.COLLECTED)
        self.assertEqual(ev.records, [])

    def test_undecodable_line_is_flagged_not_silently_accepted(self):
        text = b"Key=jos\xe9\n".decode("utf-8", "surrogateescape")
        ev = keyvalue.parse(text, Equals())
        self.assertIn(keyvalue.UNDECODABLE_LINE, ev.records[0]["anomalies"])


class Privacy(unittest.TestCase):
    """The retention policy runs before a value ever reaches a record."""

    class Secretive(keyvalue.Profile):
        name = "secretive"

        def retention(self, key):
            if key == "Password":
                return result.REDACT_VALUE
            if key == "Token":
                return result.DIGEST_VALUE
            if key == "Nothing":
                return result.NOT_RETAINED
            return result.RETAIN_VALUE

    def test_redacted_value_never_appears(self):
        ev = keyvalue.parse("Password=hunter2FIXTUREONLY\nUser=alice\n", self.Secretive())
        blob = json.dumps(ev.records)
        self.assertNotIn("FIXTUREONLY", blob)
        self.assertIsNone(ev.records[0]["value"])
        self.assertEqual(ev.records[0]["retention"], result.REDACT_VALUE)
        self.assertEqual(ev.records[1]["value"], "alice")

    def test_digest_retains_comparability_without_the_value(self):
        ev = keyvalue.parse("Token=abcFIXTUREONLY\n", self.Secretive())
        self.assertTrue(ev.records[0]["value"].startswith("sha256:"))
        self.assertNotIn("FIXTUREONLY", json.dumps(ev.records))

    def test_not_retained_stores_nothing_at_all(self):
        ev = keyvalue.parse("Nothing=xFIXTUREONLY\n", self.Secretive())
        self.assertIsNone(ev.records[0]["value"])
        self.assertEqual(ev.records[0]["retention"], result.NOT_RETAINED)

    def test_retention_is_recorded_so_empty_and_withheld_are_distinguishable(self):
        ev = keyvalue.parse("Password=\nUser=\n", self.Secretive())
        self.assertEqual(ev.records[0]["retention"], result.REDACT_VALUE)
        self.assertEqual(ev.records[1]["retention"], result.RETAIN_VALUE)
        self.assertEqual(ev.records[1]["value"], "")

    def test_there_is_no_raw_escape_hatch(self):
        # No record may carry the unprocessed value under any other name.
        ev = keyvalue.parse("Password=hunter2FIXTUREONLY\n", self.Secretive())
        for record in ev.records:
            for key, value in record.items():
                if isinstance(value, str):
                    self.assertNotIn("FIXTUREONLY", value, key)


class NoDomainPolicy(unittest.TestCase):
    """S1 is a shared primitive: no domain, no verdicts, no I/O."""

    def _executable_strings(self, module):
        tree = ast.parse(inspect.getsource(module))
        docs = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc is not None:
                    docs.add(doc)
        return [n.value for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and n.value not in docs]

    def test_no_domain_name_is_acted_on(self):
        for value in self._executable_strings(keyvalue):
            for forbidden in ("PermitRootLogin", "sudoers", "sshd", "pam_", "journald"):
                self.assertNotIn(forbidden.lower(), value.lower(), value)

    def test_parser_performs_no_io(self):
        # It takes text. It cannot read a file, run a command or reach a network, so a
        # fixture test cannot be affected by the machine running it.
        src = inspect.getsource(keyvalue)
        tree = ast.parse(src)
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        for forbidden in ("open", "socket", "urlopen", "Popen", "system", "read_file"):
            self.assertNotIn(forbidden, names + attrs, forbidden)

    def test_only_shared_modules_are_imported(self):
        tree = ast.parse(inspect.getsource(keyvalue))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertIn(node.module or "", ("", "result"), node.module)


class GrammarIdentity(unittest.TestCase):
    """A grammar change must not be mistakable for a host change."""

    def test_same_name_different_grammar_yields_a_different_digest(self):
        class V1(keyvalue.Profile):
            name = "same"

        class V2(keyvalue.Profile):
            name = "same"
            inline_comments = True

        a = keyvalue.parse("K=v # c\n", V1())
        b = keyvalue.parse("K=v # c\n", V2())
        # The same bytes produce different values...
        self.assertNotEqual(a.records[0]["value"], b.records[0]["value"])
        # ...so the provenance must be able to say why.
        self.assertNotEqual(a.provenance["grammar_digest"],
                            b.provenance["grammar_digest"])

    def test_digest_is_stable_across_calls(self):
        class P(keyvalue.Profile):
            name = "stable"

        self.assertEqual(keyvalue.parse("K=v\n", P()).provenance["grammar_digest"],
                         keyvalue.parse("K=other\n", P()).provenance["grammar_digest"])

    def test_digest_is_derived_not_hand_maintained(self):
        # Editing the grammar changes the digest whether or not anyone bumped `version`.
        class P(keyvalue.Profile):
            name = "derived"

        before = keyvalue.parse("K=v\n", P()).provenance["grammar_digest"]

        class Q(keyvalue.Profile):
            name = "derived"
            version = 1            # deliberately NOT bumped
            strip_quotes = True

        after = keyvalue.parse("K=v\n", Q()).provenance["grammar_digest"]
        self.assertNotEqual(before, after)

    def test_explicit_version_also_changes_identity(self):
        class P(keyvalue.Profile):
            name = "versioned"

        class P2(keyvalue.Profile):
            name = "versioned"
            version = 2

        self.assertNotEqual(keyvalue.parse("K=v\n", P()).provenance["grammar_digest"],
                            keyvalue.parse("K=v\n", P2()).provenance["grammar_digest"])

    def test_provenance_answers_how_these_records_were_interpreted(self):
        class P(keyvalue.Profile):
            name = "full"
            duplicate_policy = keyvalue.LAST_WINS
            empty_value_policy = keyvalue.EMPTY_IS_UNSET

        prov = keyvalue.parse("K=v\n", P()).provenance
        for field in ("profile", "version", "grammar_digest", "grammar",
                      "declaration_count", "malformed_count"):
            self.assertIn(field, prov)
        self.assertEqual(prov["grammar"]["duplicate_policy"], keyvalue.LAST_WINS)
        self.assertEqual(prov["grammar"]["empty_value_policy"], keyvalue.EMPTY_IS_UNSET)

    def test_records_carry_retention_and_position(self):
        ev = keyvalue.parse("K=v\n", Equals())
        record = ev.records[0]
        for field in ("source_path", "source_line", "ordinal", "retention"):
            self.assertIn(field, record)


if __name__ == "__main__":
    unittest.main(verbosity=0)
