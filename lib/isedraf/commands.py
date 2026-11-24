# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The one definition of every isedraf command form: the parser, the help, the command
#          reference and the bash completion are all derived from this table.
# Implements: D-129, SCOPE-077, OUT-001, AUTH-019
#
# Pure data and pure rendering: no I/O, no host reads, no evidence. Only implemented command
# forms are listed; a gate (scripts/ci/check_commands.py) holds the table equal to the parser,
# to lib/isedraf/exitcodes.json and to the forms the root route admits (launcher/outer.py).
# Help text describes; it never becomes state.
#
# `answer` is the one implementation of the help forms (HELP_FORMS, `help COMMAND`) and the
# version. The user route (cli.main) and the root route (launcher/outer.main, AUTH-019 as
# amended for v0.5) both call it before anything else, so they print the same text.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""The command table (D-129, register item H6) and the help rendered from it."""
from isedraf import ENGINE_VERSION

PROG = "isedraf"
# C-01: the canonical short identity (scripts/ci/project_status.json "short"); the public
# claims gate holds this literal equal to it.
DESCRIPTION = "Linux host evidence and assurance tool"

# The order help lists the groups in. Developer commands come last (register item H4).
GROUPS = ("Getting started", "Collect evidence", "Evaluate and understand",
          "Approve a reference", "View results", "Developer")

# What a command does, in plain words (register item H5).
EFFECTS = {
    "COLLECTS": "collects evidence from this host and commits it as one run",
    "EVALUATES": "evaluates committed evidence and writes an evaluation; collects nothing",
    "APPROVES": "approves committed evidence as the baseline, explicitly; collects nothing",
    "RENDERS": "shows committed evidence; collects nothing and writes nothing unless asked to save",
    "SHOWS_HOST": "reads this host now and prints what it found; commits nothing",
    "READS_DEFINITIONS": "reads the installed definitions only; no evidence, no store",
    "LISTS": "lists what the evidence store holds from its committed metadata; collects, "
             "approves and writes nothing",
}

# Completion kinds of an option value or an argument. SNAPSHOT is never completed: completion
# never reads an evidence store (register item C1).
COMPLETE_NONE = "none"
COMPLETE_FILE = "file"
COMPLETE_DIR = "dir"
COMPLETE_CRITERION = "criterion"
COMPLETE_SNAPSHOT = "snapshot"
# The name of a command (`isedraf help COMMAND`), from this table.
COMPLETE_COMMAND = "command"

# Exit codes in plain words. The authority is lib/isedraf/exitcodes.json (OUT-001); this is
# help text, and the gate checks every code used here is listed there for the same command.
EXIT_MEANINGS = {
    0: "completed; every area was collected",
    2: "completed, but some area is incomplete (expected without root; not a security verdict)",
    5: "the baseline in force does not verify; nothing was written",
    64: "usage error or engine error; nothing was committed",
    65: "approval refused, with the reason named; nothing was written",
    66: "another ISEDRAF run holds the lock; nothing was collected or written",
    67: "the evidence store cannot be used; nothing was collected",
    68: "too little free space for the run; nothing was committed or deleted",
    70: "refused under root or sudo; nothing was collected",
    129: "interrupted (SIGHUP) before the commit",
    130: "interrupted (SIGINT) before the commit",
    143: "interrupted (SIGTERM) before the commit",
    255: "the Full Audit unit ended abnormally; no claim about what was committed",
}

START_LINES = (
    "Start here, as your normal user:",
    "  isedraf audit        collect evidence into your personal store",
    "  isedraf evaluate     evaluate it against the native criteria",
    "  isedraf report       show the report",
    "Full Audit, with root authority, into the system store:",
    "  sudo isedraf audit   then sudo isedraf evaluate, sudo isedraf report",
    "Approving a baseline is an explicit decision, never an automatic next step:",
    "  sudo isedraf baseline approve",
)


def _option(flag, help_text, metavar=None, complete=COMPLETE_NONE):
    return {"flag": flag, "help": help_text, "metavar": metavar, "complete": complete}


def _argument(name, help_text, complete=COMPLETE_NONE, required=True, metavar=None):
    return {"name": name, "help": help_text, "complete": complete, "required": required,
            "metavar": metavar or name.upper()}


COMMANDS = (
    {
        # Register items H1, H3, H4 (D-129; AUTH-019 as amended for v0.5). Answered by
        # `answer`, before any other parsing, on the user route and the root route alike.
        "path": ("help",),
        "group": "Getting started",
        "summary": "show the start page, every command (--all) or one command",
        "effect": "READS_DEFINITIONS",
        "privilege": "anyone. Under sudo or root, `sudo isedraf`, `sudo isedraf help`, "
                     "`sudo isedraf --help` and `sudo isedraf --version` are answered before "
                     "anything else is checked: no evidence is read, no store is opened, "
                     "nothing is collected and no unit is started",
        "writes": "nothing",
        "options": (_option("--all", "every command, grouped"),),
        "arguments": (_argument("topic", "a command, for example audit or baseline approve",
                                COMPLETE_COMMAND, required=False, metavar="COMMAND"),),
        "examples": ("isedraf", "isedraf help --all", "isedraf help audit",
                     "isedraf --version", "sudo isedraf help"),
        "exits": {"isedraf": (0,), "isedraf --help": (0,), "isedraf --version": (0,),
                  "isedraf help": (0, 64),
                  "sudo isedraf": (0,), "sudo isedraf --help": (0,),
                  "sudo isedraf --version": (0,), "sudo isedraf help": (0, 64)},
        "exit_notes": {0: "the help was shown",
                       64: "the command named is unknown; the valid commands are listed"},
        "sudo_forms": (),
        "root_help": True,
        "missing": None,
    },
    {
        "path": ("audit",),
        "group": "Collect evidence",
        "summary": "collect evidence from this host and commit it as one run",
        "effect": "COLLECTS",
        "privilege": "your normal user: what an unprivileged user may read, the rest recorded "
                     "as NOT_TESTED. `sudo isedraf audit` is Full Audit: root authority, "
                     "the root-only system store",
        "writes": "one committed run (snapshot and ledger record) in the evidence store",
        "options": (_option("--root", "filesystem root to collect from (testing)", "DIR",
                            COMPLETE_DIR),),
        "arguments": (),
        "examples": ("isedraf audit", "sudo isedraf audit"),
        "exits": {"isedraf audit": (0, 2, 64, 66, 67, 68, 70),
                  "sudo isedraf audit": (0, 2, 64, 66, 67, 68, 70, 129, 130, 143, 255)},
        "sudo_forms": (("audit",),),
        "missing": None,
    },
    {
        "path": ("evaluate",),
        "group": "Evaluate and understand",
        "summary": "evaluate the latest committed run against the native criteria",
        "effect": "EVALUATES",
        "privilege": "your normal user, on your store. `sudo isedraf evaluate` evaluates the "
                     "system store's latest Full Audit run",
        "writes": "one evaluation (evaluations/EVL-...); with a baseline in force, the "
                  "comparison with it",
        "options": (_option("--snapshot", "a committed snapshot ID (default: the latest "
                                          "committed run)", "SDS-ID", COMPLETE_SNAPSHOT),),
        "arguments": (),
        "examples": ("isedraf evaluate", "sudo isedraf evaluate"),
        "exits": {"isedraf evaluate": (0, 5, 64, 66, 67, 70),
                  "sudo isedraf evaluate": (0, 5, 64, 66, 67, 70, 129, 130, 143, 255)},
        "exit_notes": {0: "the evaluation was written; it does not mean every criterion passed"},
        "sudo_forms": (("evaluate",),),
        "missing": None,
    },
    {
        "path": ("explain",),
        "group": "Evaluate and understand",
        "summary": "explain one native criterion",
        "effect": "READS_DEFINITIONS",
        "privilege": "your normal user",
        "writes": "nothing",
        "options": (),
        "arguments": (_argument("criterion_id", "a criterion ID, for example ISE-ACCOUNT-001",
                                COMPLETE_CRITERION),),
        "examples": ("isedraf explain ISE-ACCOUNT-001",),
        "exits": {"isedraf explain": (0, 64, 70)},
        "exit_notes": {0: "the criterion was explained"},
        "sudo_forms": (),
        "missing": "Name the criterion to explain.",
    },
    {
        "path": ("baseline", "approve"),
        "group": "Approve a reference",
        "summary": "approve committed evidence as the baseline, explicitly",
        "effect": "APPROVES",
        "privilege": "two separate contexts, and nothing moves between them. In the system "
                     "store, `sudo isedraf baseline approve` approves that store's latest Full "
                     "Audit run (made by `sudo isedraf audit`) and takes no snapshot argument. "
                     "In a development (DEV) store, `isedraf baseline approve SDS-ID` approves "
                     "the named run. Your personal store holds no baseline, and approving "
                     "under sudo never turns a personal-store run into production evidence",
        "writes": "baselines/BL-000001.json and its ledger record; on refusal, nothing",
        "options": (),
        "arguments": (_argument("snapshot_id", "the SDS-... run to approve (DEV store only)",
                                COMPLETE_SNAPSHOT),),
        "examples": ("sudo isedraf baseline approve",
                     "isedraf baseline approve SDS-20261113T101500Z-41a4d71af5303e60"),
        "exits": {"isedraf baseline approve": (0, 5, 64, 65, 66, 67, 70),
                  "sudo isedraf baseline approve": (0, 5, 64, 65, 66, 67, 70, 129, 130, 143,
                                                    255)},
        "exit_notes": {0: "the baseline was approved"},
        "sudo_forms": (("baseline", "approve"),),
        "missing": "name the run to approve, or use the system store's own route. A "
                   "baseline is approved in one of two separate contexts. Development (DEV) "
                   "store: `isedraf baseline approve SDS-ID`, where `isedraf audit` printed "
                   "the ID of each run it committed there. System store: `sudo isedraf "
                   "baseline approve` approves the latest Full Audit run already in that "
                   "store (made by `sudo isedraf audit`) and takes no argument. Your "
                   "personal store holds no baseline; sudo does not turn a personal-store "
                   "run into production evidence.",
    },
    {
        "path": ("list",),
        "group": "View results",
        "summary": "list committed runs, evaluations, the baseline and saved reports",
        "effect": "LISTS",
        "privilege": "your normal user, on your store. `sudo isedraf list` lists the system "
                     "store read-only: runs, the baseline and evaluation identities, from its "
                     "metadata; it opens no evidence and writes nothing",
        "writes": "nothing",
        "options": (_option("--all", "every entry, not only the newest of each kind"),),
        "arguments": (),
        "examples": ("isedraf list", "isedraf list --all", "sudo isedraf list"),
        "exits": {"isedraf list": (0, 64, 67, 70),
                  "sudo isedraf list": (0, 64, 66, 67, 70, 129, 130, 143, 255)},
        "exit_notes": {0: "the store was listed (an empty or absent store too)"},
        "sudo_forms": (("list",), ("list", "--all")),
        "missing": None,
    },
    {
        "path": ("report",),
        "group": "View results",
        "summary": "show the report of the latest committed run",
        "effect": "RENDERS",
        "privilege": "your normal user, on your store. `sudo isedraf report` (also --json, "
                     "--html) shows the system store's latest Full Audit run; it cannot save. "
                     "Export it privately as your user: (umask 077; set -o noclobber; sudo "
                     "isedraf report > ~/isedraf-report.md)",
        "writes": "nothing; with --save, one file under <evidence store>/reports/",
        "options": (_option("--json", "the machine-readable report model"),
                    _option("--html", "a static HTML report"),
                    _option("--profile", "an optional assessment profile file (JSON); "
                                         "personal details belong in a file, not on the "
                                         "command line", "FILE", COMPLETE_FILE),
                    _option("--save", "write the report under <evidence store>/reports/ and "
                                      "print its path")),
        "arguments": (),
        "examples": ("isedraf report", "isedraf report --html --save", "sudo isedraf report"),
        "exits": {"isedraf report": (0, 2, 64, 70),
                  "sudo isedraf report": (0, 2, 64, 66, 67, 70, 129, 130, 143, 255)},
        "exit_notes": {0: "the report was shown; every area of the run was collected"},
        "sudo_forms": (("report",), ("report", "--json"), ("report", "--html")),
        "missing": None,
    },
    {
        "path": ("identity",),
        "group": "Developer",
        "summary": "collect the host identity only and commit it as a run",
        "effect": "COLLECTS",
        "privilege": "your normal user",
        "writes": "one committed run in the evidence store",
        "options": (_option("--source", "identity source path (testing)", "FILE",
                            COMPLETE_FILE),),
        "arguments": (),
        "examples": ("isedraf identity",),
        "exits": {"isedraf identity": (0, 2, 64, 66, 67, 68, 70)},
        "sudo_forms": (),
        "missing": None,
    },
    {
        "path": ("inventory",),
        "group": "Developer",
        "summary": "read the host inventory now and print it",
        "effect": "SHOWS_HOST",
        "privilege": "your normal user",
        "writes": "nothing",
        "options": (_option("--json", "the normalized inventory object"),
                    _option("--root", "filesystem root to read (testing)", "DIR",
                            COMPLETE_DIR)),
        "arguments": (),
        "examples": ("isedraf inventory", "isedraf inventory --json"),
        "exits": {"isedraf inventory": (0, 2, 64)},
        "sudo_forms": (),
        "missing": None,
    },
)


def name(record):
    return " ".join(record["path"])


def find(path):
    """The record for a command path, or None."""
    for record in COMMANDS:
        if record["path"] == tuple(path):
            return record
    return None


def overview():
    """`isedraf --help` (register item H4): the start lines, then every command by group."""
    lines = ["usage: isedraf <command> [options]", "",
             "%s." % DESCRIPTION, ""]
    lines.extend(START_LINES)
    width = max(len(name(r)) for r in COMMANDS)
    for group in GROUPS:
        members = [r for r in COMMANDS if r["group"] == group]
        if not members:
            continue
        lines.extend(["", "%s:" % group])
        for r in members:
            lines.extend(_wrap("  %-*s  " % (width, name(r)), r["summary"], width + 4))
    lines.extend(["", "Options:",
                  "  --help     this list (also `isedraf help --all`); `isedraf help COMMAND` "
                  "or",
                  "             `isedraf COMMAND --help` for one command",
                  "  --version  the installed version",
                  "", "Documentation: /usr/share/doc/isedraf/"])
    return "\n".join(lines) + "\n"


WIDTH = 79


def _wrap(label, text, indent):
    """Word-wrap `label + text` to WIDTH, continuation lines indented by `indent`."""
    lines, current = [], label
    for word in text.split():
        if len(current) + 1 + len(word) > WIDTH and current.strip() and current != label:
            lines.append(current)
            current = " " * indent + word
        else:
            current = current + ("" if current == label else " ") + word
    lines.append(current)
    return lines


def _usage(record):
    parts = [PROG] + list(record["path"])
    for o in record["options"]:
        parts.append("[%s%s]" % (o["flag"], " " + o["metavar"] if o["metavar"] else ""))
    for a in record["arguments"]:
        parts.append(a["metavar"] if a["required"] else "[%s]" % a["metavar"])
    lines = ["usage: %s" % " ".join(parts)]
    for form in record["sudo_forms"]:
        lines.append("       sudo %s %s" % (PROG, " ".join(form)))
    if record.get("root_help"):
        lines.append("       %s | %s --help | %s --version" % (PROG, PROG, PROG))
        lines.append("       sudo %s" % " ".join(parts))
    return lines


def _exit_rows(record):
    notes = record.get("exit_notes", {})
    rows = []
    for key in sorted(record["exits"], key=lambda k: (k.startswith("sudo"), k)):
        rows.append("  %s:" % key)
        for code in record["exits"][key]:
            rows.extend(_wrap("    %-3d  " % code, notes.get(code, EXIT_MEANINGS[code]), 9))
    return rows


def command_help(record):
    """`isedraf <command> --help` (register item H5)."""
    lines = _usage(record) + ["", "%s." % record["summary"].capitalize(), ""]
    lines.extend(_wrap("What it does:   ", EFFECTS[record["effect"]], 16))
    lines.extend(_wrap("Who runs it:    ", record["privilege"], 16))
    lines.extend(_wrap("What it writes: ", record["writes"], 16))
    if record["arguments"]:
        lines.extend(["", "Arguments:"])
        for a in record["arguments"]:
            lines.extend(_wrap("  %-14s " % a["metavar"], a["help"], 17))
    lines.extend(["", "Options:", "  %-14s %s" % ("--help", "this help")])
    for o in record["options"]:
        flag = o["flag"] + (" " + o["metavar"] if o["metavar"] else "")
        lines.extend(_wrap("  %-14s " % flag, o["help"], 17))
    lines.extend(["", "Exit codes:"])
    lines.extend(_exit_rows(record))
    lines.extend(["", "Examples:"])
    lines.extend("  %s" % e for e in record["examples"])
    return "\n".join(lines) + "\n"


def missing_help(record, extra=()):
    """A missing required argument (register item H7): what to do, and complete examples."""
    lines = _wrap("isedraf %s: " % name(record), record["missing"], 2)
    for line in extra:
        lines.extend(_wrap("", line, 2))
    lines.append("Examples:")
    lines.extend("  %s" % e for e in record["examples"])
    lines.append("More: isedraf %s --help" % name(record))
    return "\n".join(lines) + "\n"


# --- The help forms and the version (register items H1, H3, H4; Q1-Q3 decided 2026-11-14) ---
# The accepted forms, explicitly. Besides these, `help COMMAND` is accepted for every command
# path and command group in the table (help_forms). Anything else starting with `help` is a
# usage error (64) naming the valid commands. A gate holds the user route and the root route
# to this list (scripts/ci/check_commands.py).
HELP_FORMS = (
    ((), "start"),
    (("help",), "start"),
    (("help", "--all"), "all"),
    (("help", "--help"), "self"),
    (("help", "-h"), "self"),
    (("--help",), "all"),
    (("-h",), "all"),
    (("--version",), "version"),
)


def version_text():
    return "%s %s\n" % (PROG, ENGINE_VERSION)


def start_page():
    """`isedraf` and `isedraf help` (register item H3)."""
    lines = [
        "%s %s - %s." % (PROG, ENGINE_VERSION, DESCRIPTION),
        "",
        "ISEDRAF collects evidence about this Linux host, commits it as one run,",
        "evaluates it against its native criteria and reports on it.",
        "",
        "Standard Audit, as your normal user, into your personal store:",
        "  isedraf audit        collect evidence; root-only facts are NOT_TESTED",
        "  isedraf evaluate     evaluate the latest run against the native criteria",
        "  isedraf report       show the report of the latest run",
        "",
        "Full Audit, with root authority, into the system store:",
        "  sudo isedraf audit   then sudo isedraf evaluate and sudo isedraf report",
        "",
        "Approving a baseline is an explicit decision, never an automatic next step:",
        "  sudo isedraf baseline approve   (the system store's latest Full Audit run)",
        "",
        "More:",
        "  isedraf help --all       every command, grouped",
        "  isedraf help COMMAND     one command: what it does, writes and returns",
        "  Documentation: /usr/share/doc/isedraf/docs/",
    ]
    return "\n".join(lines) + "\n"


def _help_paths():
    """Every command path and every command group, in table order."""
    paths = []
    for record in COMMANDS:
        for depth in range(1, len(record["path"]) + 1):
            if record["path"][:depth] not in paths:
                paths.append(record["path"][:depth])
    return paths


def help_forms():
    """Every accepted help form: HELP_FORMS, then `help COMMAND` for each path and group."""
    return [form for form, _kind in HELP_FORMS] + [("help",) + p for p in _help_paths()]


def unknown_help(words):
    """`isedraf help <unknown>` (Q2): name it, list the valid commands; exit 64."""
    lines = ["%s help: unknown command '%s'." % (PROG, " ".join(words))]
    lines.extend(_wrap("Commands: ", ", ".join(name(r) for r in COMMANDS), 10))
    lines.append("More: %s help --all" % PROG)
    return "\n".join(lines) + "\n"


def answer(argv):
    """The help forms and the version: (exit code, stdout text, stderr text), or None when
    argv is not a help form and does not start with `help`. Pure: no I/O, no evidence."""
    argv = tuple(argv)
    for form, kind in HELP_FORMS:
        if argv == form:
            text = {"start": start_page, "all": overview, "version": version_text,
                    "self": lambda: command_help(find(("help",)))}[kind]()
            return 0, text, ""
    if argv[:1] != ("help",):
        return None
    words = argv[1:]
    if words in _help_paths():
        members = [r for r in COMMANDS if r["path"][:len(words)] == words]
        return 0, "\n".join(command_help(r) for r in members), ""
    return 64, "", unknown_help(words)
