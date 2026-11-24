# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The compact header, the audit summary and readable refusals for human output.
# Implements: D-129, SCOPE-077, OUT-001
#
# v0.5 register items P1 (one ASCII header), P2 (what a run did, coverage counts, a reason per
# area not collected, where it is, the next commands, what exit 2 means) and P3 (a refusal
# says what failed, whether anything was written and the next command). Pure: it renders
# values it is given - the committed run's own identifiers, times and statuses - and reads
# nothing: no host data, no store, no clock. Never used for --json output.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Human-readable header, audit summary and refusal text (v0.5 P1, P2, P3)."""
import re

from isedraf import ENGINE_VERSION
from isedraf.status import COLLECTED, ERROR, NOT_TESTED, PARTIAL

STATUSES = (COLLECTED, PARTIAL, NOT_TESTED, ERROR)

# Where the evidence lives, in operator words, per state-root class (D-117, D-124).
STORE_WORDS = {
    "USER_PRODUCTION": ("Standard Audit", "your personal evidence store",
                        "private to you: a 0700 directory only your account can read"),
    "DEV": ("development run", "a development (DEV) store",
            "marked DEV: never production evidence"),
    "SYSTEM_PRODUCTION": ("Full Audit", "the system evidence store",
                          "root-only: a 0700 directory owned by root"),
}

# The sections a registered Full Audit fixed operation reads (AUTH-019, AUTH-024; the
# operation registry is lib/isedraf/supervisor/contracts.py). Only these get the Full Audit
# hint: for any other area, root would not read more through ISEDRAF, and saying so would
# turn "run it as root" into advice it is not.
FULL_AUDIT_READS = {
    "accounts": "/etc/shadow",
    "sudo": "the sudo policy files",
    "ssh": "the SSH server configuration and the output of sshd -T",
}
FULL_AUDIT_PLATFORMS = "Debian 12, Ubuntu 24.04, Rocky Linux 9, AlmaLinux 9"
WIDTH = 79


# A word, or a backticked code span with whatever is attached to it, kept whole by wrap().
TOKEN = re.compile(r"\S*`[^`]*`\S*|\S+")
# The terminal rule (owner, 2026-11-20): human text fits TERMINAL columns. A longer line is
# allowed only when it holds one value that may not be split, alone: an identifier, a path, a
# digest, a JSON pointer or a code span (see within_terminal).
TERMINAL = 80
WHOLE_VALUE = re.compile(r"^\s*(sha256:[0-9a-f]{64}|(SDS|EVL|RUN|EVT|BL|RPT)-\S+|[/~][^\s]*"
                         r"|[A-Za-z0-9_.-]+/[^\s]*|`[^`]*`[.,;:)]?)\s*$")


def within_terminal(line):
    """True when a line of human terminal text keeps the terminal rule."""
    return len(line) <= TERMINAL or bool(WHOLE_VALUE.match(line))


def wrap(first, text, indent):
    """`first` then `text` word-wrapped to WIDTH; continuation lines indented by `indent`.
    A word is never split, and a `code span` is one word: identifiers, paths, digests, JSON
    pointers and commands stay whole (owner rule 2026-11-20)."""
    lines, current = [], first
    for word in TOKEN.findall(text):
        if len(current) + 1 + len(word) > WIDTH and current.strip():
            lines.append(current.rstrip())
            current = " " * indent + word
        else:
            current = current + ("" if current.endswith(" ") or not current else " ") + word
    lines.append(current.rstrip())
    return lines


def header(command, store_class=None, snapshot_id=None, collected_at=None):
    """P1: product, version and command; for evidence output also the mode, the snapshot and
    its collection time, all taken from the committed evidence."""
    lines = ["ISEDRAF %s | %s" % (ENGINE_VERSION, command)]
    if store_class in STORE_WORDS:
        mode, where, _why = STORE_WORDS[store_class]
        lines.append("%s, %s" % (mode, where))
    if snapshot_id:
        lines.append("snapshot %s%s" % (snapshot_id,
                                        ", collected %s" % collected_at if collected_at else ""))
    rule = "-" * max(len(l) for l in lines)
    return "\n".join([rule] + lines + [rule]) + "\n"


def _reason_words(reason):
    """`TOKEN: plain words` -> `plain words (TOKEN)`: the words first, the token kept for
    diagnosis and automation."""
    if not isinstance(reason, str) or not reason:
        return "no reason was recorded"
    token, sep, words = reason.partition(": ")
    if sep and token.replace("_", "").isalnum() and token.upper() == token:
        return "%s (%s)" % (words.rstrip("."), token)
    return reason


def counts(sections, names):
    found = dict((s, 0) for s in STATUSES)
    for name in names:
        status = (sections.get(name) or {}).get("collection_status", ERROR)
        found[status if status in found else ERROR] += 1
    return found


def audit_summary(sections, names, run_status, store_class, root, identity_collected,
                  snapshot_id, committed=True):
    """P2: what happened, coverage counts, one reason per area not collected with what would
    change it, where the run is, the next commands, and what exit 2 means."""
    complete = identity_collected and run_status == COLLECTED
    found = counts(sections, names)
    mode, where, why = STORE_WORDS.get(store_class, ("run", "the evidence store", ""))
    state = ("complete" if complete else "incomplete (some areas could not be fully read)")
    # The Full Audit engine reports before the launcher has checked and committed the staged
    # run; the launcher prints the commit itself.
    out = wrap("", "Committed: one run, %s." % state if committed else
               "Collected: one run, %s. The launcher checks and commits it next." % state, 0)
    out.append("Coverage of %d areas: %s." % (len(names), ", ".join(
        "%d %s" % (found[s], s) for s in STATUSES)))
    missing = [n for n in names
               if (sections.get(n) or {}).get("collection_status") != COLLECTED]
    if missing:
        out.append("Not fully collected:")
        hinted = False
        width = max(len(n) for n in missing)
        for name in missing:
            section = sections.get(name) or {}
            lead = "  %-*s  %-10s " % (width, name, section.get("collection_status"))
            text = _reason_words(section.get("reason"))
            if name in FULL_AUDIT_READS and store_class != "SYSTEM_PRODUCTION":
                text = "%s. Full Audit (sudo isedraf audit) reads %s." % (
                    text.rstrip(". "), FULL_AUDIT_READS[name])
                hinted = True
            out.extend(wrap(lead, text, len(lead)))
        if hinted:
            out.extend(wrap("", "Full Audit runs on %s, with systemd." % FULL_AUDIT_PLATFORMS,
                            0))
    out.extend(wrap("", "%s %s: %s" % ("Stored in" if committed else "To be stored in", where,
                                       root), 2))
    if why:
        out.append("  (%s)" % why)
    sudo = "sudo " if store_class == "SYSTEM_PRODUCTION" else ""
    out.extend(["Next:",
                "  %sisedraf evaluate     evaluate this run against the native criteria" % sudo,
                "  %sisedraf report       show the report of this run" % sudo])
    if not complete:
        out.extend(wrap("", "Exit 2 means the run was committed with incomplete areas. %s"
                        "It is not a security verdict." % ("" if store_class == "SYSTEM_PRODUCTION"
                                                         else "Without root that is expected. "),
                        0))
    return "\n".join(out) + "\n"


def refusal(what, written, next_command=None):
    """P3: what failed, whether anything was written, and the exact next command."""
    lines = wrap("isedraf: ", what.rstrip(), 2) + wrap("  ", written, 2)
    if next_command:
        lines.append("  next: %s" % next_command)
    return "\n".join(lines) + "\n"


# R4 (owner decision 2026-11-16): the safe export of a Full Audit report, shown by help, the
# system-store listing and the root refusal. Private (umask 077), never overwriting (noclobber),
# created by the operator's own shell, not by ISEDRAF as root.
EXPORT_COMMAND = "(umask 077; set -o noclobber; sudo isedraf report > ~/isedraf-report.md)"


# --- isedraf list (v0.5 R1) ----------------------------------------------------------------
LIST_NEWEST = 10
# Without --all, each kind shows its newest LIST_NEWEST entries and says how many more exist.


def _newest(items, show_all):
    if show_all or len(items) <= LIST_NEWEST:
        return items, 0
    return items[-LIST_NEWEST:], len(items) - LIST_NEWEST


def listing_text(found, store_class, root, show_all=False):
    """R1: what one store holds, newest last, from committed metadata only."""
    mode, where, why = STORE_WORDS.get(store_class, ("store", "the evidence store", ""))
    out = wrap("Store: ", "%s, %s" % (where, root), 2)
    if why:
        out.append("  (%s)" % why)
    approved = set(b["snapshot_id"] for b in found["baselines"])
    runs, more = _newest(found["runs"], show_all)
    out.extend(["", "Runs (%d committed; collection time, UTC):" % len(found["runs"])])
    if more:
        out.append("  ... %d older; isedraf list --all shows every one" % more)
    for r in runs:
        # The class is shown only where it differs from the store's; identifiers stay whole.
        out.append("  %s  %s%s%s" % (
            r["snapshot_id"], r["collected_at"],
            "" if r["state_root"] == store_class else "  %s" % r["state_root"],
            "  [baseline]" if r["snapshot_id"] in approved else ""))
    if not found["runs"]:
        out.append("  none yet; start with: %sisedraf audit"
                   % ("sudo " if store_class == "SYSTEM_PRODUCTION" else ""))
    if found["unledgered"]:
        out.extend(wrap("  ", "%d snapshot director%s not in the ledger: not committed, not "
                        "listed (SNAP-018)" % (found["unledgered"], "y is"
                                               if found["unledgered"] == 1 else "ies are"), 2))
    evaluations, more = _newest(found["evaluations"], show_all)
    out.extend(["", "Evaluations (%d):" % len(found["evaluations"])])
    if more:
        out.append("  ... %d older; isedraf list --all shows every one" % more)
    for e in evaluations:
        if e.get("identity_only"):
            # The system store's listing opens no evaluation artifact (AUTH-035).
            out.append("  %s" % e["evaluation_id"])
            continue
        if e.get("problem"):
            out.append("  %s  %s" % (e["evaluation_id"], e["problem"]))
            continue
        counts = ", ".join("%d %s" % (n, r) for r, n in sorted(e["result_counts"].items())
                           if n) or "no results"
        out.append("  %s" % e["evaluation_id"])                # two IDs never share a line
        out.extend(wrap("    of %s: " % e["snapshot_id"], counts, 6))
    if not found["evaluations"]:
        out.append("  none yet; after a run: %sisedraf evaluate"
                   % ("sudo " if store_class == "SYSTEM_PRODUCTION" else ""))
    elif any(e.get("identity_only") for e in found["evaluations"]):
        out.extend(wrap("  ", "(identities only; sudo isedraf report shows the latest run with "
                        "its evaluation)", 3))
    out.extend(["", "Baseline:"])
    if found["baselines"]:
        b = found["baselines"][-1]
        out.append("  %s  for %s" % (b["revision"], b["snapshot_id"]))
        out.append("    approved %s" % b["approved_at"])
    else:
        out.append("  none approved")
    if store_class == "SYSTEM_PRODUCTION":
        # Under root nothing is saved (no root-chosen output path); export instead (R4).
        out.extend(["", "Saved reports: none; the system store keeps no reports. Export one "
                    "privately:", "  " + EXPORT_COMMAND])
        return "\n".join(out) + "\n"
    reports, more = _newest(found["reports"], show_all)
    out.extend(["", "Saved reports (%d):" % len(found["reports"])])
    if more:
        out.append("  ... %d older; isedraf list --all shows every one" % more)
    for r in reports:
        line = "  %s  (%d bytes)" % (r["path"], r["size"])
        out += ([line] if len(line) <= TERMINAL               # a long path stands alone
                else ["  %s" % r["path"], "    (%d bytes)" % r["size"]])
    if not found["reports"]:
        out.append("  none saved; isedraf report --save writes one and prints its path")
    return "\n".join(out) + "\n"


# --- baseline approval, shown before anything is written (v0.5 P5) ---------------------------
ACCEPTED_NOT_SECURE = ("Approval records accepted state; it does not establish that the host is "
                       "secure.")


def approval_text(obj, collected_at, store_class):
    """P5: what is about to be approved, before any write: the run and its collection time, the
    store, the profile, every required section with its status, and what approval means."""
    mode, where, _why = STORE_WORDS.get(store_class, ("store", "the evidence store", ""))
    out = ["Approving as the baseline: %s" % obj["snapshot_id"],
           "  collected: %s" % (collected_at or "unknown"),
           "  store: %s (%s)" % (where, store_class),
           "  profile: %s" % obj["profile"]["object"]["profile_id"]]
    sections = obj.get("sections") or {}
    out.extend(wrap("  required sections: ", ", ".join(
        "%s %s" % (n, (sections.get(n) or {}).get("collection_status", "MISSING"))
        for n in obj["required_sections"]), 4))
    out.extend(wrap("", ACCEPTED_NOT_SECURE, 0))
    return "\n".join(out) + "\n"


# --- refusals in operator language (v0.5 H8) -------------------------------------------------
# Plain words first; the stable reason token stays, unchanged, for diagnosis and automation,
# with its detail and requirement IDs after it. The next command is the default where the
# refusal itself does not name one. Human text only: wrap() never splits a word, so tokens,
# identifiers and paths stay whole.
PLAIN = {
    "BASELINE_CLASS_NOT_ADMITTED": (
        "this is your personal evidence store, and a baseline is not approved here; "
        "production baselines come from Full Audit",
        "sudo isedraf audit, then sudo isedraf baseline approve"),
    "INCOMPLETE_FOR_BASELINE": (
        "this run is incomplete: a baseline needs every required section collected",
        "a complete audit, then approve again"),
    "NOT_COMPARABLE_FOR_BASELINE": (
        "the state of a required section cannot be recorded, so it could never be compared",
        None),
    "BASELINE_ALREADY_APPROVED": (
        "a baseline is already approved for this store, and this version does not replace it",
        "evaluate compares later runs with it"),
    "UNLEDGERED_REVISION_PRESENT": (
        "an earlier approval stopped before it was recorded; it is kept and never reused",
        None),
    "FULL_AUDIT_UNSUPPORTED": (
        "Full Audit cannot run on this host",
        "isedraf audit, as your normal user"),
    "ENGINE_IDENTITY_MISSING": (
        "the isedraf account that the package declares does not exist",
        "reinstall the isedraf package"),
    "ENGINE_UNSAFE_INSTALL": (
        "the installed ISEDRAF files are not protected as Full Audit requires",
        "reinstall the isedraf package (/usr/lib/isedraf must be root-owned and closed to "
        "others)"),
}


def explained(token, detail, written, next_command=None):
    """H8: plain words, then the reason token with its detail, what was written, what next."""
    plain, default_next = PLAIN.get(token, (None, None))
    lines = wrap("isedraf: ", (plain + ".") if plain else token, 2)
    parts = [p.strip() for p in str(detail).split("\n") if p.strip()] or [""]
    lines += wrap("  reason: ", "%s: %s" % (token, parts[0]), 10)
    for part in parts[1:]:                  # one line per blocking item, kept apart
        lines += wrap("    - ", part, 6)
    lines += wrap("  ", written, 2)
    nxt = next_command or default_next
    if nxt:
        lines += wrap("  next: ", nxt, 8)
    return "\n".join(lines) + "\n"


def recovered_notice(segment):
    """STORE-016: the notice a recovering run prints, wrapped like every other human line."""
    return "\n".join(wrap("isedraf: ", "LEDGER_RECOVERED: %s ended in an incomplete record; its "
                          "bytes are kept unchanged and a new segment continues the ledger "
                          "(STORE-016)." % segment, 2)) + "\n"
