# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Stop a real operator identifier reaching the publication surface.
# Implements: GOV-001, GOV-002, D-90
#
# WHY THIS EXISTS. A pre-publication audit found an SSH key fingerprint, private-key
# paths and a verbatim ssh_config stanza inside docs/ — the publication surface — after
# two rounds of grepping had already declared the tree clean. The answer to a missed leak
# is not to look harder next time; it is a gate.
#
# TWO SCOPES, because they answer different questions:
#   release     what a user RECEIVES or READS (scripts/ci/release_surface.txt). BLOCKING.
#   repository  the whole tracked tree. ADVISORY, and it reports rather than fails.
# A synthetic address in a unit test is not equivalent to publishing an operator's.
#
# OUTPUT IS REDACTED BY DEFAULT. This gate runs in CI, and in a public repository a CI log
# is public. A privacy gate that prints what it found defeats itself. `--show` reveals the
# matches and is for local use only.
#
# IPs are classified with the stdlib `ipaddress` module rather than by regex alone, so
# documentation ranges, loopback and the disposable lab network are recognised as what
# they are instead of being pattern-matched into a panic.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git"
# =============================================================================

"""Classify every candidate identifier. Nothing is excluded without a category."""
import argparse
import fnmatch
import ipaddress
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
ALLOWLIST = json.loads((ROOT / "scripts" / "ci" / "privacy_allowlist.json").read_text())
SURFACE = [l.strip() for l in (ROOT / "scripts" / "ci" / "release_surface.txt")
           .read_text().splitlines() if l.strip() and not l.startswith("#")]
# `!path` marks a tracked file that the export REMOVES, so it is not a publication
# surface however many globs match it. Without this the gate inspected the decisions
# register for private information - which is what that document is for.
NOT_PUBLISHED = {p[1:] for p in SURFACE if p.startswith("!")}
SURFACE = [p for p in SURFACE if not p.startswith("!")]

# --- categories. Every finding gets exactly one; there is no implicit default -----------
REAL_OPERATOR_IDENTIFIER = "REAL_OPERATOR_IDENTIFIER"   # blocks
UNCLASSIFIED = "UNCLASSIFIED"                           # blocks: unknown is not safe
LAB_DISPOSABLE = "LAB_DISPOSABLE"
SYNTHETIC = "SYNTHETIC"
APPROVED_PUBLIC = "APPROVED_PUBLIC"
BLOCKING = (REAL_OPERATOR_IDENTIFIER, UNCLASSIFIED)

KINDS = [
    ("SSH_KEY_FINGERPRINT", re.compile(r"SHA256:[A-Za-z0-9+/]{42,44}={0,2}")),
    ("SSH_PRIVATE_KEY_PATH", re.compile(r"[~/][\w./-]*/id_(?:ed25519|rsa|ecdsa|dsa)\w*")),
    ("SSH_CONFIG_DIRECTIVE",
     re.compile(r"^\s*(?:IdentityFile|ProxyJump|ControlPath|HostName|IdentitiesOnly)\s+\S",
                re.M)),
    ("PRIVATE_KEY_MATERIAL", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("TOKEN", re.compile(r"\b(?:ghp_|github_pat_|gho_|AKIA|xox[baprs]-)[A-Za-z0-9_]{8,}")),
    ("PERSONAL_PATH", re.compile(r"/home/(?!<)[a-z_][a-z0-9_-]{1,31}/")),
    ("MAC_ADDRESS", re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")),
    ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("DOMAIN", re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
                          r"(?:gr|com|net|org|io|dev|test|invalid|local)\b")),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
]

SKIP_SUFFIXES = (".png", ".jpg", ".gif", ".ico", ".pdf", ".gz", ".zip", ".deb", ".rpm",
                 ".bin", ".sha256")


def redact(text):
    """Enough to find the line, never enough to republish the value."""
    if len(text) <= 6:
        return text[0] + "…" if text else "…"
    return "%s…%s" % (text[:3], text[-2:])


def classify_ip(value):
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None                       # not an address: a version string, a digest
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return SYNTHETIC
    for net, _why in ALLOWLIST["synthetic_ranges"].items():
        if addr in ipaddress.ip_network(net):
            return SYNTHETIC
    for net, _why in ALLOWLIST["lab_disposable_ranges"].items():
        if addr in ipaddress.ip_network(net):
            return LAB_DISPOSABLE
    if value in ALLOWLIST["approved_public_hosts"]:
        return APPROVED_PUBLIC
    if addr.is_private or addr.is_link_local:
        # A private address that is not a documentation range and not the lab network is
        # somebody's actual infrastructure.
        return REAL_OPERATOR_IDENTIFIER
    return UNCLASSIFIED


def classify(kind, value):
    if kind in ("SSH_KEY_FINGERPRINT", "SSH_PRIVATE_KEY_PATH", "SSH_CONFIG_DIRECTIVE",
                "PRIVATE_KEY_MATERIAL", "TOKEN", "PERSONAL_PATH"):
        return REAL_OPERATOR_IDENTIFIER
    if kind == "IPV4":
        return classify_ip(value)
    if kind == "MAC_ADDRESS":
        # 52:54:00 is QEMU's locally-administered prefix: a generated VM address.
        return LAB_DISPOSABLE if value.lower().startswith("52:54:00") \
            else REAL_OPERATOR_IDENTIFIER
    if kind in ("DOMAIN", "EMAIL"):
        low = value.lower()
        for approved in ALLOWLIST["approved_public_identifiers"]:
            if low == approved or low.endswith("." + approved) or low.endswith(
                    "@" + approved):
                return APPROVED_PUBLIC
        for literal in ALLOWLIST["synthetic_literals"]:
            if literal.lower() in low:
                return SYNTHETIC
        if low.endswith((".test", ".invalid", ".local", ".example")):
            return SYNTHETIC
        return REAL_OPERATOR_IDENTIFIER if low.endswith((".gr", ".com", ".net")) \
            else UNCLASSIFIED
    return UNCLASSIFIED


def on_surface(rel):
    return any(fnmatch.fnmatch(rel, pattern) or
               fnmatch.fnmatch(rel, pattern.replace("**", "*"))
               for pattern in SURFACE)


def scan(paths):
    findings = []
    for rel in paths:
        path = ROOT / rel
        if path.suffix in SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for kind, pattern in KINDS:
            for m in pattern.finditer(text):
                value = m.group(0).strip()
                category = classify(kind, value)
                if category is None:
                    continue
                line = text[:m.start()].count("\n") + 1
                # A planted fixture is exempt only on its own line, and only when it says
                # so. The falsifiability harness exists to contain prohibited values; a
                # file-level exemption would hide a real leak that landed beside one.
                start = text.rfind("\n", 0, m.start()) + 1
                end = text.find("\n", m.start())
                if "privacy:planted-fixture" in text[start:end if end != -1 else len(text)]:
                    continue
                findings.append({"path": rel, "line": line, "kind": kind,
                                 "category": category, "value": value,
                                 "surface": on_surface(rel)})
    return findings


LEGITIMATE = [
    # Ordinary, truthful supply-chain prose. The gate MUST stay silent on every line.
    # A gate that flags these is one maintainers learn to skip, and noise is a defect.
    "CodeQL analyses both the Python and the GitHub Actions workflows.",
    "OpenSSF Scorecard runs against this repository; no score is published.",
    "GitGuardian is one of several secret-scanning services available.",
    "The public repository requires seven status checks before a merge.",
    "Workflow tokens default to read-only; Actions cannot approve pull requests.",
    "Every third-party GitHub Action is pinned to a full commit SHA.",
    "A ruleset blocks force-push and deletion on the public repository's main branch.",
    "Repository access for this project is reviewed before any integration is added.",
    "Settings are documented in the operator guide.",
    "Branch protection on the public repository was observed to refuse a force-push.",
]


# Structured-config cases. YAML carries exactly what the prose scan exists to prevent,
# while the prose classifier would fire on every legitimate `permissions:` block. These
# assert the structured scan catches the first pair and stays silent on the second.
YAML_MUST_FAIL = [
    "  repo: itcmsgr/isedraf-dev",
    "  app_id: 46505",
    "  path: PROVIDERS_LICENSE/providers/CIS/STATUS.yaml",
]
YAML_MUST_PASS = [
    "permissions:",
    "  contents: read",
    "  security-events: write",
    "name: CodeQL",
    "  - uses: github/codeql-action/analyze@1c5b675653bb5c22dbe9b12b556ec555138e09fd",
    "concurrency:",
    "  group: governance-${{ github.ref }}",
]


def self_test():
    """Prove PUBLIC-OPS-001 stays silent on legitimate prose (noise-floor control)."""
    import re as _re
    subject = _re.compile(
        r"\b(private (?:engineering )?repos(?:itory|itories)|isedraf-dev)\b", _re.I)
    pairs = [
        _re.compile(r"\b(access|permission|authoriz|integrat|readable|observ)", _re.I),
        _re.compile(r"\b(force[- ]push|deletion of|unprotected|cannot be (?:made )?"
                    r"required|without a pull request|branch protection)", _re.I),
    ]
    app = _re.compile(
        r"\bapp[ _]?id\b.{0,40}\b\d{4,}\b|\b\d{4,}\b.{0,40}\bapp[ _]?id\b"
        r"|\bcontents:\s*read\b|\bissues:\s*write\b|\bpull_requests:\s*write\b", _re.I)
    remediation = _re.compile(
        r"Settings\s*(?:\u2192|->)\s*Applications|Installed GitHub Apps|"
        r"Only select repositories", _re.I)
    noisy = []
    for line in LEGITIMATE:
        if app.search(line) or remediation.search(line):
            noisy.append(line)
        elif subject.search(line) and any(p.search(line) for p in pairs):
            noisy.append(line)
    if noisy:
        print("=== PUBLIC-OPS-001 NOISE FLOOR FAILED ===", file=sys.stderr)
        print("  The rule fired on legitimate prose. A gate that cries wolf is one",
              file=sys.stderr)
        print("  maintainers learn to skip; false-positive noise is a defect.",
              file=sys.stderr)
        for line in noisy:
            print("    FALSE_POSITIVE  %r" % line, file=sys.stderr)
        return 1
    # structured scan, both directions
    ids = [k for k in ALLOWLIST.get("forbidden_operational_identifiers", {})
           if not k.startswith("$")]
    missed = [l for l in YAML_MUST_FAIL if not any(i in l for i in ids)]
    noisy_yaml = [l for l in YAML_MUST_PASS if any(i in l for i in ids)]
    if missed or noisy_yaml:
        print("=== PUBLIC-OPS-001 STRUCTURED SCAN FAILED ===", file=sys.stderr)
        for l in missed:
            print("    NOT_CAUGHT      %r" % l, file=sys.stderr)
        for l in noisy_yaml:
            print("    FALSE_POSITIVE  %r" % l, file=sys.stderr)
        return 1

    print("  OK    PUBLIC-OPS-001 noise floor: %d legitimate lines, 0 false positives"
          % len(LEGITIMATE))
    print("  OK    PUBLIC-OPS-001 structured: %d YAML disclosures caught, %d legitimate "
          "YAML lines silent" % (len(YAML_MUST_FAIL), len(YAML_MUST_PASS)))
    return 0


def main():
    parser = argparse.ArgumentParser(description="ISEDRAF privacy / disclosure gate")
    parser.add_argument("--scope", choices=("release", "repository"), default="release")
    parser.add_argument("--self-test", action="store_true",
                        help="prove PUBLIC-OPS-001 stays silent on legitimate prose")
    parser.add_argument("--show", action="store_true",
                        help="print raw matches — LOCAL USE ONLY, never in CI")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    tracked = subprocess.check_output(["git", "ls-files"], cwd=str(ROOT), text=True).split()
    tracked = [p for p in tracked if not p.startswith("planning/")]
    paths = [p for p in tracked if on_surface(p) and p not in NOT_PUBLISHED] \
        if args.scope == "release" else tracked

    # The surface list is an assertion about what ships, and an assertion drifts. The
    # source tarball is `git archive HEAD` - every tracked file - so the moment a source
    # tarball became a published artifact, the publication surface became the whole
    # tracked tree. `scripts/**`, `tests/**` and `git-hooks/**` were reaching users
    # inside that tarball while the BLOCKING scope did not cover them; only the advisory
    # scope did. A hand-maintained list cannot notice that, so it is checked here.
    # --- PUBLIC-OPS-001: operational disclosure -------------------------------------
    #
    # Public release surfaces SHALL NOT disclose unresolved private engineering security
    # findings or private operational trust-boundary details unless explicitly approved.
    #
    # This is a PRIVACY problem, not a claims problem, so it lives here beside private
    # paths and infrastructure identifiers rather than in check-public-claims.
    #
    # It matches COMBINATIONS, never bare words. "GitGuardian", "GitHub", "CodeQL" and
    # "Scorecard" all have legitimate public uses - the supply-chain section of the README
    # names several on purpose. Banning a vendor name outright would produce findings on
    # every legitimate mention, and a gate that cries wolf is one people learn to skip.
    # What is forbidden is a private-repository weakness, an integration scope, an App
    # identifier with its permissions, or remediation steps for something still open.
    if args.scope == "release":
        PRIVATE_SUBJECT = re.compile(
            r"\b(private (?:engineering )?repos(?:itory|itories)|isedraf-dev)\b", re.I)
        OPS_PAIR = [
            (re.compile(r"\b(access|permission|authoriz|integrat|readable|observ)", re.I),
             "private-repository access or integration scope"),
            (re.compile(r"\b(force[- ]push|deletion of|unprotected|cannot be (?:made )?"
                        r"required|without a pull request|branch protection)", re.I),
             "private-repository protection weakness"),
        ]
        APP_DETAIL = re.compile(
            r"\bapp[ _]?id\b.{0,40}\b\d{4,}\b|\b\d{4,}\b.{0,40}\bapp[ _]?id\b"
            r"|\bcontents:\s*read\b|\bissues:\s*write\b|\bpull_requests:\s*write\b",
            re.I)
        REMEDIATION = re.compile(
            r"Settings\s*(?:→|->)\s*Applications|Installed GitHub Apps|"
            r"Only select repositories", re.I)
        ALLOW = "<!-- privacy:allow-ops-disclosure -->"

        # --- structured scan: EXACT identifiers, every file type ---------------------
        # Runs against .yml/.yaml too. YAML can carry exactly what the prose scan is for
        #     env: {PRIVATE_REPO: itcmsgr/isedraf-dev}
        #     external_service: {app_id: 46505}
        # while the prose classifier would fire on every legitimate
        #     permissions: {contents: read, security-events: write}
        # Literal identifiers have no false positives, so they can be scanned everywhere
        # and the prose patterns stay confined to documents.
        # Files that contain these strings because they IMPLEMENT or DECLARE the rules.
        # One set, used by both scans — the structured scan and the prose scan had
        # separate exemption lists for one commit, which is the same two-lists defect
        # that let the release surface drift.
        GATE_SELF = {
            "scripts/ci/check_privacy.py", "scripts/ci/privacy_allowlist.json",
            "scripts/ci/check_licensing.py", "scripts/ci/falsifiable.sh",
            "scripts/ci/release_surface.txt", "scripts/ci/public_licensing_policy.json",
        }
        FORBIDDEN_IDS = {k: v for k, v in
                         ALLOWLIST.get("forbidden_operational_identifiers", {}).items()
                         if not k.startswith("$")}
        ops = []
        for rel in paths:
            if rel in GATE_SELF:
                continue
            try:
                body = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            for n, line in enumerate(body.splitlines(), 1):
                if ALLOW in line:
                    continue
                for ident, why in FORBIDDEN_IDS.items():
                    if ident in line:
                        ops.append((rel, n, "forbidden operational identifier %r — %s"
                                    % (ident, why)))
                        break

        # --- prose scan: combinations, documents only --------------------------------
        for rel in paths:
            if not rel.endswith((".md", ".json", ".txt")):
                continue
            if rel in GATE_SELF:
                continue
            try:
                body = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for n, line in enumerate(body.splitlines(), 1):
                if ALLOW in line:
                    continue
                if APP_DETAIL.search(line):
                    ops.append((rel, n, "external App identifier or permission detail"))
                    continue
                if REMEDIATION.search(line):
                    ops.append((rel, n, "remediation instructions for an integration"))
                    continue
                if PRIVATE_SUBJECT.search(line):
                    for pat, why in OPS_PAIR:
                        if pat.search(line):
                            ops.append((rel, n, why))
                            break
        if ops:
            print("=== privacy gate FAILED (PUBLIC-OPS-001) ===", file=sys.stderr)
            print("  Public release surfaces must not disclose private operational",
                  file=sys.stderr)
            print("  security detail. Record it in the private governance record, or",
                  file=sys.stderr)
            print("  mark the line %s if the disclosure is approved."
                  % ALLOW, file=sys.stderr)
            for rel, n, why in ops[:20]:
                print("    OPS_DISCLOSURE  %s:%d  %s" % (rel, n, why), file=sys.stderr)
            return 1
        print("  OK    PUBLIC-OPS-001: no private operational disclosure on the "
              "publication surface")

    # An excluded path means "must not appear in release artifacts", NOT "the scanner may
    # ignore it". Read the other way, the exclusion list becomes a hole with a label on
    # it: a file could be excluded from scanning and still copied into a package by some
    # other build path. Verified against what was actually built.
    if args.scope == "release":
        export = ROOT / "dist" / "export"
        if export.is_dir():
            leaked = [rel for rel in sorted(NOT_PUBLISHED) if (export / rel).exists()]
            for rel in leaked:
                print("  FAIL  %s is excluded from the release surface yet present in "
                      "the export. Exclusion means absent from release artifacts, not "
                      "merely unscanned." % rel, file=sys.stderr)
            if leaked:
                return 1
            print("  OK    %d excluded path(s) verified absent from the built export"
                  % len(NOT_PUBLISHED))

    if args.scope == "release":
        uncovered = sorted(set(tracked) - set(paths) - NOT_PUBLISHED)
        if uncovered:
            print("=== privacy gate FAILED (release scope) ===", file=sys.stderr)
            print("  The source tarball ships every tracked file, so every tracked file",
                  file=sys.stderr)
            print("  is on the publication surface. These are not covered by",
                  file=sys.stderr)
            print("  scripts/ci/release_surface.txt:", file=sys.stderr)
            for rel in uncovered[:40]:
                print("    UNCOVERED  %s" % rel, file=sys.stderr)
            if len(uncovered) > 40:
                print("    ... and %d more" % (len(uncovered) - 40), file=sys.stderr)
            return 1
    findings = scan(paths)

    counts = {}
    for f in findings:
        counts[f["category"]] = counts.get(f["category"], 0) + 1

    blocking = [f for f in findings if f["category"] in BLOCKING
                and (args.scope == "repository" or f["surface"])]
    if blocking:
        print("=== privacy gate FAILED (%s scope) ===" % args.scope, file=sys.stderr)
        for f in sorted(blocking, key=lambda x: (x["path"], x["line"])):
            shown = f["value"] if args.show else redact(f["value"])
            print("  FAIL  %s:%d %s %s %s"
                  % (f["path"], f["line"], f["category"], f["kind"], shown),
                  file=sys.stderr)
        print("  Values are redacted: a CI log in a public repository is public.",
              file=sys.stderr)
        print("  Run locally with --show to see them.", file=sys.stderr)
        print("  Fix by removing the value, or classify it in "
              "scripts/ci/privacy_allowlist.json WITH a justification.", file=sys.stderr)
        if args.scope == "repository":
            return 1
        return 1
    summary = ", ".join("%s %d" % (k, v) for k, v in sorted(counts.items())) or "nothing"
    print("  OK    privacy gate (%s): %d files, %s" % (args.scope, len(paths), summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
