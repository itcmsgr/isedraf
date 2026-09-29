# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Measure the public documentation layer against DOC-PUBLIC-UX-001.
# Implements: D-87, D-88, DOC-PUBLIC-UX-001
#
# The owner requirement (docs/development/PUBLIC_DOCS_UX.md) is about comprehension, which
# no script can measure. What a script CAN measure are proxies that reliably go wrong when
# comprehension does: internal identifiers driving the narrative, walls of text, a README
# that has grown into a second specification, the same paragraph copied between documents,
# and promotional framing. Each proxy is named as a proxy; none is a verdict on the prose.
#
# The rule lists are REUSED, not reinvented. Identifier shapes come from
# scripts/ci/check_requirement_refs.py, framing terms from scripts/docs/doclint.py and
# scripts/ci/check_docs_truth.py. They are read with `ast` (never executed), so a rename
# there fails this gate closed instead of silently emptying a rule.
#
# Modes: `report` prints NOTE lines and exits 0; `enforce` exits 1 on any finding. With no
# mode argument the registry field `enforce` decides, so moving to enforcement is a
# one-line reviewed change to scripts/ci/public_layer.json.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git"
# =============================================================================

"""usage: public_ux.py [report|enforce] [--self-test]"""
import ast
import json
import pathlib
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
)
REGISTRY_REL = "scripts/ci/public_layer.json"
REQUIREMENT = "DOC-PUBLIC-UX-001"


class RuleSourceError(Exception):
    """A reused rule list could not be read. Always fatal: an empty rule is a silent pass."""


# --- reused rule sources (read, never executed) ------------------------------------------
def _assignment(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return node.value
    raise RuleSourceError("%s: no top-level assignment %s" % (path.name, name))


def _literal(path, name):
    try:
        return ast.literal_eval(_assignment(path, name))
    except ValueError:
        raise RuleSourceError("%s: %s is not a literal" % (path.name, name))


_FLAG = {"I": re.I, "IGNORECASE": re.I, "M": re.M, "MULTILINE": re.M,
         "S": re.S, "DOTALL": re.S, "X": re.X, "VERBOSE": re.X}


def _pattern(path, name):
    """Rebuild `NAME = re.compile("<literal>", flags)` without executing the module."""
    node = _assignment(path, name)
    if not (isinstance(node, ast.Call) and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)):
        raise RuleSourceError("%s: %s is not re.compile(<literal>)" % (path.name, name))
    flags = 0
    for extra in list(node.args[1:]) + [k.value for k in node.keywords]:
        for sub in ast.walk(extra):
            if isinstance(sub, ast.Attribute) and sub.attr in _FLAG:
                flags |= _FLAG[sub.attr]
    return re.compile(node.args[0].value, flags)


class Rules:
    def __init__(self, root):
        refs = root / "scripts" / "ci" / "check_requirement_refs.py"
        lint = root / "scripts" / "docs" / "doclint.py"
        truth = root / "scripts" / "ci" / "check_docs_truth.py"
        # Identifier shapes, exactly as the reference-integrity gate defines them.
        self.id_res = [_pattern(refs, "REF_RE"), _pattern(refs, "DREF_RE"),
                       _pattern(refs, "AMEND_RE")]
        self.not_ids = set(_literal(refs, "NOT_IDS"))
        # The refs gate skips these prefixes because they are not REQUIREMENTS; for a
        # public reader most of them are still internal (implementation questions,
        # governance gaps), so they are matched here explicitly.
        self.skip_prefixes = tuple(_literal(refs, "NOT_ID_PREFIXES"))
        self.id_res.append(re.compile(
            r"(?<![A-Za-z0-9-])((?:%s)\d+)\b"
            % "|".join(re.escape(p) for p in self.skip_prefixes)))
        # Single-letter finding and question identifiers (Q-15, Z-20, C-06, T-27).
        self.id_res.append(re.compile(r"(?<![A-Za-z0-9-])([A-Z]-\d{2})\b"))
        # Framing: the doclint claim lists and the docs-truth framing list.
        self.forbidden = list(_literal(lint, "FORBIDDEN"))
        self.overclaim = _pattern(lint, "OVERCLAIM_RE")
        self.competitive = _pattern(lint, "COMPETITIVE")
        self.neg_near = _pattern(lint, "NEG_NEAR")
        self.mention = _pattern(lint, "MENTION_RE")
        self.framing = [(re.compile(p, re.I), why) for p, why in _literal(truth, "FRAMING")]
        reg = json.loads((root / "scripts" / "ci" / "docs_truth_registry.json")
                         .read_text(encoding="utf-8"))
        self.projects = [n.lower() for n in reg["external_projects"]["names"]]
        if not (self.forbidden and self.framing and self.projects and self.not_ids):
            raise RuleSourceError("a reused rule list is empty")

    def is_claim(self, text, start, end):
        """Same test doclint applies: a mention or a negation is not a claim."""
        lead = text[max(0, start - 120):start]
        tail = text[end:end + 60]
        if self.mention.search(text[max(0, start - 2):start]) or self.mention.search(tail[:2]):
            return False
        return not (self.neg_near.search(lead) or self.neg_near.search(tail))


# Internal-process vocabulary (owner text: "decision IDs, freeze sets, amendment history,
# implementation questions, CI gates, lane names or development chronology").
VOCAB_RE = re.compile(
    r"\b(freeze[ -]sets?|freeze[ -]manifests?|amendments?|lanes?|falsif\w*|gates?"
    r"|implementation questions?|decisions? register|register)\b", re.I)
IQ_WORD_RE = re.compile(r"\bIQ\b")
REFS_HEADING_RE = re.compile(
    r"\b(references?|normative references|further reading|see also|read next)\b", re.I)

# --- markdown model ----------------------------------------------------------------------
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE_OPEN_RE = re.compile(r"^\s*(```|~~~)")
LIST_ITEM_RE = re.compile(r"^\s*([-*+]|\d+[.)])\s+")
LINK_TARGET_RE = re.compile(r"\]\(([^)\s]*)[^)]*\)")
URL_RE = re.compile(r"https?://\S+")
WORD_RE = re.compile(r"\S+")


def classify(text):
    """One (lineno, kind, text) per line; kind is fence/html/heading/table/blank/text."""
    out, fence, html = [], None, False
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if fence:
            out.append((n, "fence", line))
            if s.startswith(fence):
                fence = None
            continue
        if html:
            out.append((n, "html", line))
            html = "-->" not in s
            continue
        m = FENCE_OPEN_RE.match(line)
        if m:
            fence = m.group(1)
            out.append((n, "fence", line))
        elif s.startswith("<!--"):
            out.append((n, "html", line))
            html = "-->" not in s
        elif HEADING_RE.match(s):
            out.append((n, "heading", line))
        elif s.startswith("|"):
            out.append((n, "table", line))
        elif not s:
            out.append((n, "blank", line))
        else:
            out.append((n, "text", line))
    return out


def paragraphs(lines):
    """(first line number, joined text) for every prose paragraph and list item."""
    out, cur = [], None
    for n, kind, line in lines:
        if kind != "text":
            if cur:
                out.append(cur)
            cur = None
            continue
        if cur is None or LIST_ITEM_RE.match(line):
            if cur:
                out.append(cur)
            cur = [n, line.strip()]
        else:
            cur[1] += " " + line.strip()
    if cur:
        out.append(cur)
    return [tuple(p) for p in out]


def words(text):
    return len(WORD_RE.findall(text))


def references_start(lines):
    """Line number where the final references section begins, or None.

    Only the LAST top-level (H1/H2) section counts: a "References" heading followed by
    more narrative is not the end of the document, and identifiers under it still drive
    that narrative.
    """
    last = None
    for n, kind, line in lines:
        if kind == "heading":
            m = HEADING_RE.match(line.strip())
            if len(m.group(1)) <= 2:
                last = (n, m.group(2))
    if last and REFS_HEADING_RE.search(last[1]):
        return last[0]
    return None


def normalize_paragraph(text):
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^a-z0-9]+", " ", text.lower())
    return " ".join(text.split())


# --- analysis ----------------------------------------------------------------------------
def load_registry(root):
    reg = json.loads((root / REGISTRY_REL).read_text(encoding="utf-8"))
    if not isinstance(reg.get("enforce"), bool):
        raise RuleSourceError("%s: `enforce` must be true or false" % REGISTRY_REL)
    docs = reg.get("documents")
    if not docs or not all(isinstance(d, str) for d in docs):
        raise RuleSourceError("%s: `documents` must be a non-empty list of paths" % REGISTRY_REL)
    for d in docs:
        if d.startswith("/") or ".." in d.split("/"):
            raise RuleSourceError("%s: unsafe document path %r" % (REGISTRY_REL, d))
    for k in ("paragraph_words", "section_words", "readme_lines", "duplicate_paragraph_words"):
        if not isinstance(reg.get("limits", {}).get(k), int):
            raise RuleSourceError("%s: limits.%s must be an integer" % (REGISTRY_REL, k))
    return reg


def analyse(root, reg, rules):
    findings = []   # (rule, path, line, message)
    lim = reg["limits"]
    product = tuple(reg.get("product_id_prefixes", {}).get("prefixes", []))
    present = {}
    for rel in reg["documents"]:
        p = root / rel
        if not p.is_file():
            findings.append(("missing", rel, 0, "NOT YET WRITTEN - listed in %s" % REGISTRY_REL))
            continue
        present[rel] = p.read_text(encoding="utf-8")

    seen_paragraphs = {}
    for rel, text in present.items():
        lines = classify(text)
        refs_at = references_start(lines)

        # (a) internal identifiers and process vocabulary before the references section.
        for n, kind, line in lines:
            if kind not in ("text", "heading", "table"):
                continue
            if refs_at is not None and n >= refs_at:
                break
            scan = URL_RE.sub(" ", LINK_TARGET_RE.sub("]", line))
            ids = []
            for rx in rules.id_res:
                for m in rx.finditer(scan):
                    i = m.group(1) if m.re.groups else m.group(0)
                    if i in rules.not_ids or i.startswith(product) or i in ids:
                        continue
                    ids.append(i)
            if ids:
                findings.append(("a", rel, n, "internal identifier(s) %s drive the narrative; "
                                 "move them to a final References section" % ", ".join(ids)))
            terms = sorted({m.group(0).lower() for m in VOCAB_RE.finditer(scan)}
                           | {m.group(0) for m in IQ_WORD_RE.finditer(scan)})
            if terms:
                findings.append(("a", rel, n, "internal-process vocabulary %s; a reader "
                                 "should not need it to understand the product"
                                 % ", ".join(repr(t) for t in terms)))

        # (b) paragraph and section length, outside code blocks and tables.
        for n, para in paragraphs(lines):
            w = words(para)
            if w > lim["paragraph_words"]:
                findings.append(("b", rel, n, "paragraph of %d words (cap %d)"
                                 % (w, lim["paragraph_words"])))
            if w >= lim["duplicate_paragraph_words"]:
                seen_paragraphs.setdefault(normalize_paragraph(para), []).append((rel, n))
        start, count = 1, 0
        for n, kind, line in lines + [(10 ** 9, "heading", "# end")]:
            if kind == "heading":
                if count > lim["section_words"]:
                    findings.append(("b", rel, start, "section of %d words (cap %d)"
                                     % (count, lim["section_words"])))
                start, count = n, 0
            elif kind == "text":
                count += words(line)

        # (e) promotional framing, with the rule lists the doc lint already enforces.
        blank = "\n".join(line if kind in ("text", "heading", "table") else ""
                          for _, kind, line in lines)
        src = blank.splitlines()
        for term in rules.forbidden:
            for m in re.finditer(re.escape(term), blank, re.I):
                if rules.is_claim(blank, m.start(), m.end()):
                    findings.append(("e", rel, blank.count("\n", 0, m.start()) + 1,
                                     "forbidden claim %r" % term))
        for rx, label in ((rules.overclaim, "unscoped overclaim"),
                          (rules.competitive, "competitive framing")):
            for m in rx.finditer(blank):
                if rules.is_claim(blank, m.start(), m.end()):
                    findings.append(("e", rel, blank.count("\n", 0, m.start()) + 1,
                                     "%s %r" % (label, m.group(0))))
        for rx, why in rules.framing:
            for m in rx.finditer(blank):
                n = blank.count("\n", 0, m.start()) + 1
                line = src[n - 1].lower() if n - 1 < len(src) else ""
                if "doclint:allow-framing" in line:
                    continue
                named = [p for p in rules.projects if p in line]
                if named:
                    findings.append(("e", rel, n, "%r %s %s"
                                     % (m.group(0), why, "/".join(named))))

    # (c) README: length and the reader test.
    readme = reg["documents"][0]
    if readme in present:
        text = present[readme]
        lines = classify(text)
        total = len(text.splitlines())
        if total > lim["readme_lines"]:
            findings.append(("c", readme, total, "README is %d lines (cap %d, "
                             "DOCUMENTATION_POLICY: front door <= ~150 lines)"
                             % (total, lim["readme_lines"])))
        base = posixpath.dirname(readme)
        targets = set()
        for m in LINK_TARGET_RE.finditer(text):
            t = m.group(1).split("#", 1)[0]
            if t and not t.startswith(("http://", "https://", "mailto:")):
                targets.add(posixpath.normpath(posixpath.join(base, t)))
        for rel in reg["documents"][1:]:
            if rel in present and rel not in targets:
                findings.append(("c", readme, 0, "does not link to public-layer document %s"
                                 % rel))
        heads = [line.strip().lower() for _, kind, line in lines if kind == "heading"]
        for question, keys in reg.get("readme_sections", {}).items():
            if question.startswith("$"):
                continue
            if not any(k.lower() in h for h in heads for k in keys):
                findings.append(("c", readme, 0, "reader test: no section answers %r "
                                 "(heading keywords: %s)" % (question, ", ".join(keys))))

    # (d) the same paragraph in two public documents.
    for key, where in seen_paragraphs.items():
        files = sorted({r for r, _ in where})
        if len(files) > 1:
            first = min(where)
            others = ", ".join("%s:%d" % w for w in sorted(where) if w[0] != first[0])
            findings.append(("d", first[0], first[1], "paragraph of %d words repeated in %s; "
                             "consolidate and link" % (len(key.split()), others)))
    return sorted(findings, key=lambda f: (f[1], f[2], f[0], f[3]))


RULE_NAMES = {"a": "internal terms", "b": "length", "c": "README", "d": "duplicate",
              "e": "framing", "missing": "not yet written"}


def render(findings, mode, reg):
    """(exit code, output lines). Kept pure so the self-test can drive both modes."""
    tag = "FAIL" if mode == "enforce" else "NOTE"
    out = []
    for rule, rel, n, msg in findings:
        where = "%s:%d" % (rel, n) if n else rel
        out.append("  %s  %s: [%s] %s" % (tag, where, rule, msg))
    counts = {}
    for f in findings:
        counts[f[0]] = counts.get(f[0], 0) + 1
    breakdown = ", ".join("%s %d" % (RULE_NAMES[k], counts[k]) for k in sorted(counts))
    tail = " (%s)" % breakdown if breakdown else ""
    if mode == "report":
        out.append("  NOTE  %s is REPORT-ONLY until milestone %s; %d findings%s"
                   % (REQUIREMENT, reg.get("milestone", "DOC-PUBLIC-01"), len(findings), tail))
        return 0, out
    if findings:
        out.insert(0, "=== public documentation UX (%s) FAILED ===" % REQUIREMENT)
        out.append("  FAIL  %d findings%s" % (len(findings), tail))
        return 1, out
    out.append("  OK    %s: %d public-layer documents, 0 findings"
               % (REQUIREMENT, len(reg["documents"])))
    return 0, out


# --- self-test ---------------------------------------------------------------------------
GOOD_README = """# Example

## What it is

Example records what the host exposes locally and keeps the source of every fact.

## What it does not do

It does not change the host.

## Install

Build from source.

## First run

Run the example command.

```
%s
```

## Where next

Read [Getting started](docs/GETTING_STARTED.md).

## References

Normative detail: GOV-001, D-87, IQ-011, the freeze manifest and the amendment record.
"""

GOOD_GUIDE = """# Getting started

Start here. Each step says what you will see.

| Step | Meaning |
|---|---|
| %s | a table cell is not a paragraph |
"""

LONG = " ".join(["word"] * 130)
DUP = ("This paragraph explains one idea to an operator in enough words that copying it "
       "between two public documents would count as duplication, which the owner asked us "
       "to consolidate into one place and link to from everywhere else instead of copying "
       "it again.")


def _write_tree(root, readme, guide, docs):
    (root / "scripts" / "ci").mkdir(parents=True)
    (root / "docs").mkdir()
    reg = json.loads((ROOT / REGISTRY_REL).read_text(encoding="utf-8"))
    reg["documents"] = docs
    (root / REGISTRY_REL).write_text(json.dumps(reg), encoding="utf-8")
    (root / "README.md").write_text(readme, encoding="utf-8")
    if guide is not None:
        (root / "docs" / "GETTING_STARTED.md").write_text(guide, encoding="utf-8")


def self_test():
    rules = Rules(ROOT)
    claim = rules.forbidden[0]
    code = " ".join(["codeword"] * 200)       # a long code block is never a paragraph
    good_readme = GOOD_README % code
    good_guide = GOOD_GUIDE % " ".join(["cell"] * 200)
    docs = ["README.md", "docs/GETTING_STARTED.md"]
    cases = [
        # name, readme, guide, documents, expected rule (None = must be clean)
        ("clean public layer", good_readme, good_guide, docs, None),
        ("identifier in narrative", good_readme.replace(
            "Build from source.", "Build from source, see GOV-001."), good_guide, docs, "a"),
        ("amendment identifier in narrative", good_readme.replace(  # refs:test-fixture
            "Build from source.", "Build from source (A-014)."), good_guide, docs, "a"),  # refs:test-fixture
        ("finding identifier in narrative", good_readme.replace(
            "Build from source.", "Build from source (C-06)."), good_guide, docs, "a"),
        ("process vocabulary in narrative", good_readme.replace(
            "Build from source.", "Build from source once the freeze manifest passes."),
         good_guide, docs, "a"),
        ("references section is not final", good_readme + "\n## Afterword\n\nMore.\n",
         good_guide, docs, "a"),
        ("long paragraph", good_readme.replace("It does not change the host.", LONG),
         good_guide, docs, "b"),
        ("long section", good_readme.replace("It does not change the host.",
                                             "\n\n".join([" ".join(["w"] * 90)] * 5)),
         good_guide, docs, "b"),
        ("README over the line cap", good_readme + "\n" * 200, good_guide, docs, "c"),
        ("README does not link a public document", good_readme.replace(
            "Read [Getting started](docs/GETTING_STARTED.md).", "Read the guide."),
         good_guide, docs, "c"),
        ("README misses a reader-test section", good_readme.replace("## Install", "## Setup"),
         good_guide, docs, "c"),
        ("duplicate paragraph", good_readme.replace("It does not change the host.", DUP),
         good_guide + "\n" + DUP + "\n", docs, "d"),
        ("promotional claim", good_readme, good_guide.replace(
            "Start here.", "Example is %s." % claim), docs, "e"),
        ("public document not yet written", good_readme, None, docs, "missing"),
    ]
    bad = []
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="public-ux-selftest-"))
    try:
        for i, (name, readme, guide, dl, expect) in enumerate(cases):
            root = tmp / str(i)
            _write_tree(root, readme, guide, dl)
            reg = load_registry(root)
            found = analyse(root, reg, rules)
            rc_report, out_report = render(found, "report", reg)
            rc_enforce, _ = render(found, "enforce", reg)
            fired = {f[0] for f in found}
            if rc_report != 0 or "REPORT-ONLY" not in out_report[-1]:
                bad.append("%s: report mode must exit 0 and say REPORT-ONLY" % name)
            if expect is None:
                if found or rc_enforce != 0:
                    bad.append("%s: expected no findings, got %s" % (
                        name, "; ".join("[%s] %s:%d %s" % (f[0], f[1], f[2], f[3])
                                        for f in found)))
            else:
                if expect not in fired:
                    bad.append("%s: rule [%s] did not fire (fired: %s)"
                               % (name, expect, ", ".join(sorted(fired)) or "none"))
                if rc_enforce != 1:
                    bad.append("%s: enforce mode must exit 1 on a finding" % name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        print("=== public documentation UX self-test FAILED ===")
        for b in bad:
            print("  FAIL  " + b)
        return 1
    print("  OK    public documentation UX self-test: %d rule cases fired, 1 clean document "
          "set passed, report and enforce modes both exercised" % (len(cases) - 1))
    return 0


def main(argv):
    args = argv[1:]
    unknown = [a for a in args if a not in ("report", "enforce", "--self-test")]
    if unknown:
        print(__doc__, file=sys.stderr)
        return 64
    try:
        if "--self-test" in args:
            return self_test()
        reg = load_registry(ROOT)
        modes = [a for a in args if a in ("report", "enforce")]
        mode = modes[-1] if modes else ("enforce" if reg["enforce"] else "report")
        rc, out = render(analyse(ROOT, reg, Rules(ROOT)), mode, reg)
    except (RuleSourceError, OSError, ValueError, KeyError) as e:
        print("  FAIL  public documentation UX: cannot load its rules: %s" % e, file=sys.stderr)
        return 2
    print("\n".join(out))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
