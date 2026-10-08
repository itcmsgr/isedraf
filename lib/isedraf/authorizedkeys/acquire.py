# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Turn declared AuthorizedKeysFile values into observed candidate sources.
# Implements: SCOPE-020, SCOPE-021, SCOPE-022, SCOPE-045, IDENT-041, GOV-001
#
# The bridge lane. It consumes two canonical evidence objects and produces a third; it
# acquires NOTHING that either of them already acquired.
#
#   account evidence  ->  identity and home            (never re-reads the passwd file)
#   ssh evidence      ->  AuthorizedKeysFile values    (never re-reads sshd_config)
#
# Consumer #3 of isedraf.hostpath, which is why that primitive was extracted before this
# module was written rather than after a third private copy of it appeared here.
#
# The trap this module is shaped around: an authorized_keys file is easy to find and the
# answer it gives is easy to over-state. Reading one file successfully says what is in
# that file. It does not say that sshd would consult it, that it is the only such file,
# or that a compiled-in default names it. Every one of those would need evidence this
# collection does not have, so the source universe carries its own completeness and says
# why when it is not complete.
#
# meta:type="collector"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================

"""Candidate authorized-key sources, observed and reported with their limits."""
import os

from .. import coverage, hostio, hostpath, textbytes
from ..shared import bounded, filemeta, result
from . import model, sources

KEYWORD = "authorizedkeysfile"
GLOB_CHARACTERS = ("*", "?", "[")
TOKENS = ("%", "h", "u", "U")           # documented in sshd_config(5), TOKENS


class KeyDirectory(bounded.Universe):
    """One level, files only. A glob names files beside each other, not a tree."""

    name = "authorized_keys_glob"
    max_depth = 1
    include_files = True
    include_directories = False


def collect(root, account_evidence, ssh_evidence, option_policy=None):
    """Observe the candidate authorized-key sources for every local account.

    Both evidence objects are REQUIRED. A default that collected them here would create
    the second account acquisition path this lane exists to avoid.
    """
    declarations = _declarations(ssh_evidence)
    accounts = (account_evidence or {}).get("local_accounts") or []

    inherited = _inherited_limits(account_evidence, ssh_evidence)
    plans, records, files = [], [], []
    for account in accounts:
        plan = _plan(root, account, declarations, inherited)
        for candidate in plan["candidates"]:
            _observe(candidate, plan["account_ref"], records, files, option_policy, root)
        _finish(plan)
        plans.append(plan)

    status, reason = _status(plans, declarations, accounts, inherited)
    return result.Evidence(
        status, records=records, reason=reason, source=root,
        provenance={
            "scope": model.SCOPE,
            "limitation": model.LIMITATION,
            "not_collected": list(model.NOT_COLLECTED),
            "declarations": declarations,
            "source_plans": plans,
            "files": files,
            "coverage": _coverage(plans),
            "inherited_limits": inherited,
            # The contract asked for the OpenSSH version to travel with the evidence and
            # did not say where it comes from. It is not in the SSH lane's provenance,
            # this lane may not run `sshd -V`, and package evidence is out of prototype
            # scope - so the honest answer is null WITH the reason, not a guess and not
            # silence. Raised as IQ-015; the token table below is version-sensitive and
            # a reader deserves to know the version was not established.
            "openssh_version": None,
            "openssh_version_reason": (
                "NOT_COLLECTED: no evidence source in this collection reports the "
                "OpenSSH build. The AuthorizedKeysFile token table used here is "
                "sshd_config(5)'s and is version-sensitive."),
        })


# --- inputs -------------------------------------------------------------------------------

def _declarations(ssh_evidence):
    """Every AuthorizedKeysFile value the SSH lane observed, with its scope intact.

    Scope, match_index and match_criteria travel with the value. Dropping them here and
    keeping only the path is how a conditional declaration becomes an unconditional one.
    """
    out = []
    for record in getattr(ssh_evidence, "records", None) or []:
        if record.get("keyword") != KEYWORD:
            continue
        out.append({
            "value": record.get("value"),
            "scope": record.get("scope"),
            "match_index": record.get("match_index"),
            "match_criteria": record.get("match_criteria"),
            "source_path": record.get("source_path"),
            "source_line": record.get("source_line"),
            "ordinal": record.get("ordinal"),
        })
    return out


def _inherited_limits(account_evidence, ssh_evidence):
    """An input that was itself incomplete cannot produce a complete output.

    Both directions matter. Incomplete account evidence means accounts may be missing, so
    the set of accounts whose sources were considered is not known to be all of them.
    Incomplete SSH evidence means declarations may be missing, so the set of candidates is
    not known to be all of them either.
    """
    limits = []
    account_status = (account_evidence or {}).get("collection_status")
    if account_status and account_status != model.COLLECTED:
        limits.append({"input": model.SOURCE_SCOPE, "status": account_status,
                       "reason": model.ACCOUNT_EVIDENCE_INCOMPLETE,
                       "upstream_reason": (account_evidence or {}).get("reason")})
    ssh_status = getattr(ssh_evidence, "status", None)
    if ssh_status and ssh_status != model.COLLECTED:
        limits.append({"input": "DECLARED_SSHD_CONFIGURATION", "status": ssh_status,
                       "reason": model.SSH_EVIDENCE_INCOMPLETE,
                       # The upstream's OWN words, carried verbatim. "the declaration set
                       # may be incomplete" is useless next to "an Include was not read";
                       # a reader needs to know which Include.
                       "upstream_reason": getattr(ssh_evidence, "reason", None)})
    return limits


def _account_ref(account):
    """A REFERENCE into the account evidence, not a second interpretation of it.

    `name_bytes_hex` is the field that is always present and always lossless. An account
    whose name did not decode still has an identity; what it does not have is a `name`.
    """
    return {
        "source": "LOCAL_ACCOUNT_FILES",
        "name": None if account.get("name_encoding") != textbytes.UTF8
                else account.get("name"),
        "name_bytes_hex": account.get("name_bytes_hex"),
        "uid": account.get("uid"),
        "nss_source": account.get("nss_source"),
        "passwd_line": account.get("passwd_line"),
    }


# --- planning -----------------------------------------------------------------------------

def _plan(root, account, declarations, inherited):
    plan = {
        "account_ref": _account_ref(account),
        "candidates": [],
        # The DECLARED CANDIDATE universe: is the set of candidate sources known to be
        # all of them? Never the effective universe; see below.
        "source_universe": model.UNIVERSE_COMPLETE,
        "universe_reasons": [],
        # The EFFECTIVE universe: which of them sshd would consult. R1.5 does not
        # evaluate it, on any host, ever - so it is a constant with a reason rather than
        # a value that happens to be unknown today.
        "effective_source_universe": model.EFFECTIVE_NOT_EVALUATED,
        "effective_source_reasons": [model.EFFECTIVE_REASON_NOT_IN_SCOPE],
    }
    for limit in inherited:
        plan["universe_reasons"].append(limit["reason"])

    if not declarations:
        # THE trap. OpenSSH's compiled-in default is a property of a build this lane has
        # no evidence of, so nothing is produced from the absence of a declaration.
        plan["universe_reasons"].append(model.NO_DECLARATION_OBSERVED)
        return plan

    home = _home(root, account)
    for declaration in declarations:
        plan["candidates"].extend(_candidates(root, home, account, declaration))
    return plan


def _home(root, account):
    """The account's home, in BOTH spaces, because the two are used for different jobs.

    `%h` is expanded in HOST space: sshd substitutes the home the host declares, and the
    result is then subject to the same absolute-path rule as any other value. Substituting
    the already-rooted path would send it through the root a second time and produce
    <root><root>/home/... - a path that exists nowhere.

    The rooted form is what a RELATIVE value is resolved against, since that resolution
    happens in the tree being read.
    """
    host = account.get("home")
    if host and host.startswith("hex:"):
        # A home that is not UTF-8 is carried as "hex:<bytes>" (red team pass 8, N4); the
        # path is those exact bytes, so keys under /home/jörg in Latin-1 are still found.
        host = bytes.fromhex(host[4:]).decode("utf-8", "surrogateescape")
    if not host or not host.startswith("/"):
        return {"host": None, "rooted": None}
    return {"host": host, "rooted": hostpath.under(root, host)}


def _candidates(root, home, account, declaration):
    value = declaration.get("value")
    base = {
        "kind": model.DECLARED_CANDIDATE_SOURCE,
        "declaration": declaration,
        # Denormalised onto the candidate as well as kept in `declaration`. A consumer
        # deciding whether a candidate is conditional must not have to know the shape of
        # the SSH lane's record to find out, and the adversarial pass reached for it here
        # first - which is where a renderer will reach for it too.
        "scope": declaration.get("scope"),
        "match_index": declaration.get("match_index"),
        "match_criteria": declaration.get("match_criteria"),
        # IQ-014: the applicability axis, separate from whether the path could be built
        # and from whether the file was read. A Match-scoped candidate that was read
        # perfectly is PATH_DERIVED + UNRESOLVED_MATCH_SCOPED + FILE_READ, and no single
        # field can say that.
        "applicability": (model.UNRESOLVED_MATCH_SCOPED
                          if declaration.get("scope") == "MATCH"
                          else model.UNCONDITIONAL),
        "applies_to_account": "UNDETERMINED",
        # Never "yes". Whether sshd reaches this declaration for this account depends on
        # connection context, and a Match block's criteria are recorded, not evaluated.
    }
    if value is None or not value.strip():
        return [dict(base, resolution=model.UNEXPANDED_TOKEN, pattern=None,
                     path=None, observation=None)]

    if value.strip().lower() == "none":
        return [dict(base, resolution=model.DECLARED_NONE, pattern=value.strip(),
                     path=None, observation=None)]

    out = []
    for pattern in value.split():
        out.append(_candidate(root, home, account, base, pattern))
    return out


def _candidate(root, home, account, base, pattern):
    expanded, unexpanded = _expand(pattern, account, home)
    candidate = dict(base, pattern=pattern, path=None, observation=None)
    if expanded is None and unexpanded is None:
        candidate["resolution"] = model.HOME_NOT_AVAILABLE
        return candidate
    if unexpanded:
        candidate["resolution"] = model.UNEXPANDED_TOKEN
        candidate["unexpanded_token"] = unexpanded
        return candidate

    if expanded.startswith("/"):
        candidate["path"] = hostpath.under(root, expanded)
    elif home["rooted"] is None:
        candidate["resolution"] = model.HOME_NOT_AVAILABLE
        return candidate
    else:
        candidate["path"] = hostpath.beneath(
            root, os.path.join(home["rooted"], expanded))

    candidate["resolution"] = model.PATH_DERIVED
    return candidate


def _expand(pattern, account, home):
    """Expand %%, %h, %u and %U. Any other token stops the candidate.

    The table is sshd_config(5)'s, read on the host rather than recalled. A token this
    lane does not know is not expanded to nothing and not left literal: the candidate
    becomes unresolved, because a path built around a guess is a path that was invented.
    """
    out, index, unexpanded = [], 0, None
    while index < len(pattern):
        character = pattern[index]
        if character != "%":
            out.append(character)
            index += 1
            continue
        if index + 1 >= len(pattern):
            unexpanded = "%"
            break
        token = pattern[index + 1]
        if token == "%":
            out.append("%")
        elif token == "h":
            if home["host"] is None:
                return None, None      # handled by the caller as HOME_NOT_AVAILABLE
            out.append(home["host"])
        elif token == "u":
            out.append(account.get("name") or "")
        elif token == "U":
            out.append(str(account.get("uid")))
        else:
            unexpanded = "%" + token
            break
        index += 2
    if unexpanded:
        return None, unexpanded
    return "".join(out), None


# --- observation --------------------------------------------------------------------------

def _observe(candidate, account_ref, records, files, option_policy, root):
    path = candidate.get("path")
    if not path:
        return
    if any(character in candidate["pattern"] for character in GLOB_CHARACTERS):
        _observe_glob(candidate, account_ref, records, files, option_policy, root)
        return
    _observe_file(candidate, path, account_ref, records, files, option_policy, root=root)


def _observe_glob(candidate, account_ref, records, files, option_policy, root):
    directory = os.path.dirname(candidate["path"])
    if not _inside(root, directory):
        candidate["observation"] = model.FILE_OUTSIDE_COLLECTION_ROOT
        return
    listing = bounded.enumerate_paths(directory, KeyDirectory())
    matched = []
    for entry in listing.records:
        if entry["name"] is not None and _fnmatch(entry["name"],
                                                  os.path.basename(candidate["pattern"])):
            matched.append(entry["path"])
    candidate["glob_matches"] = matched
    candidate["glob_enumeration"] = listing.status
    if listing.status != model.COLLECTED:
        candidate["observation"] = model.GLOB_NO_MATCH
        candidate["observation_reason"] = model.GLOB_NOT_ENUMERABLE
        return
    if not matched:
        # A pattern that matched nothing. The administrator wrote it; nothing was there.
        candidate["observation"] = model.GLOB_NO_MATCH
        return
    members = candidate.setdefault("observed_files", [])
    for path in matched:
        _observe_file(candidate, path, account_ref, records, files, option_policy,
                      collect_into=members, root=root)
    # The candidate's own observation summarises its members, so a consumer asking "was
    # this source read?" gets an answer without having to know the candidate expanded.
    outcomes = [m.get("observation") for m in members]
    candidate["observation"] = (model.FILE_READ if model.FILE_READ in outcomes
                                else outcomes[0] if outcomes else model.GLOB_NO_MATCH)
    candidate["source_path"] = matched[0] if matched else None


def _fnmatch(name, pattern):
    """Shell-style matching on the FILENAME only, lexically.

    fnmatch is not used: it consults os.path.normcase and, on some platforms, folds case.
    A filename on a Linux host is bytes and matching it must not depend on where the tool
    happens to be running.
    """
    return _glob_match(name, pattern)


def _glob_match(name, pattern):
    if not pattern:
        return not name
    if pattern[0] == "*":
        if _glob_match(name, pattern[1:]):
            return True
        return bool(name) and _glob_match(name[1:], pattern)
    if not name:
        return False
    if pattern[0] == "?":
        return _glob_match(name[1:], pattern[1:])
    if pattern[0] == "[":
        close = pattern.find("]", 1)
        if close < 0:
            return name[0] == "[" and _glob_match(name[1:], pattern[1:])
        members = pattern[1:close]
        negated = members.startswith("!")
        if negated:
            members = members[1:]
        if (name[0] in members) != negated:
            return _glob_match(name[1:], pattern[close + 1:])
        return False
    return name[0] == pattern[0] and _glob_match(name[1:], pattern[1:])


def _inside(root, path):
    """Does `path` still name an object inside `root` AFTER symlinks are resolved?

    hostpath guarantees the path is lexically inside the root. That is not the same
    guarantee, and the adversarial pass found the gap: give an account a home that IS a
    symlink pointing out of the collection root, and the rooted path it produces
    is lexically contained while open() reads the collector's own machine. No amount of
    string arithmetic can see that - only resolution can.

    realpath appears here and nowhere else, and it is used as a CHECK, never as identity.
    The path recorded in the evidence stays the lexical one, because that is what the
    host declared; what resolution decides is whether we are entitled to read it.

    This is a check, not a guarantee: resolve-then-open is racy against an adversary who
    can rewrite the tree between the two calls. ISEDRAF observes rather than defends, and
    the threat this closes is a fixture tree reading the machine that runs the tool. With
    root "/" every path is inside and nothing changes.
    """
    # The caller owns the resolution; hostpath.contains owns the containment. Keeping
    # them apart is what preserves the frozen distinction between lexical containment and
    # resolved-target containment - the helper must not decide which one is being asked.
    return hostpath.contains(os.path.realpath(root), os.path.realpath(path))


def _observe_file(candidate, path, account_ref, records, files, option_policy,
                  collect_into=None, root=None):
    if root is not None and not _inside(root, path):
        target_set(collect_into if collect_into is not None else candidate,
                   "observation", model.FILE_OUTSIDE_COLLECTION_ROOT, path)
        return
    examined = filemeta.observe(path)
    meta = examined.records[0]
    files.append(meta)
    target = collect_into if collect_into is not None else candidate

    if not meta.get("exists"):
        # IQ-044: filemeta sets exists=False for EVERY failed lstat. Only ENOENT is
        # absence; a denial (usually an untraversable home) or another error means the
        # path was not observed, so it must never become FILE_ABSENT. Fail closed: any
        # reason other than SOURCE_ABSENT is unobserved.
        if (examined.reason or "").startswith("SOURCE_ABSENT:"):
            target_set(target, "observation", model.FILE_ABSENT, path)
        else:
            target_set(target, "observation", model.FILE_UNREADABLE, path)
            target_set(target, "observation_detail",
                       hostio.PERMISSION_DENIED if examined.status == result.NOT_TESTED
                       else hostio.IO_ERROR, None)
        return
    if meta.get("file_type") == "SYMLINK":
        # filemeta lstat()s, so a symlink is reported as a symlink - correctly, since the
        # link itself is the object the path names. But an authorized_keys file that is a
        # symlink to a file elsewhere in the tree is an ordinary administrative
        # arrangement, and refusing to read it would report a configured source as
        # unreadable. _inside() has already established that the TARGET is in the tree,
        # so following it here reads the collection and not the collector.
        target_set(target, "symlink", True, None)
        if not os.path.isfile(path):
            target_set(target, "observation", model.FILE_NOT_REGULAR, path)
            return
    elif meta.get("file_type") != "REGULAR":
        target_set(target, "observation", model.FILE_NOT_REGULAR, path)
        return

    outcome = hostio.read_file_lossless(path)
    if not outcome.ok:
        target_set(target, "observation", model.FILE_UNREADABLE, path)
        target_set(target, "observation_detail", outcome.detail, None)
        return

    target_set(target, "observation", model.FILE_READ, path)
    parsed, malformed = sources.parse(outcome.value, path, len(records), option_policy)
    target_set(target, "malformed_lines", malformed, None)
    for record in parsed:
        record["account_ref"] = account_ref
        record["candidate_resolution"] = candidate["resolution"]
        record["effective_source"] = model.EFFECTIVE_NOT_EVALUATED
        record["declaration_scope"] = candidate["declaration"].get("scope")
        record["declaration_applicability"] = candidate["applicability"]
        record["declaration_match_index"] = candidate["declaration"].get("match_index")
        record["declaration_match_criteria"] = candidate["declaration"].get(
            "match_criteria")
        records.append(record)


class _Member(dict):
    """One file's observation, whether it is the candidate itself or a glob member.

    The first version appended one dict PER FIELD to the glob's list, so a file that was
    read produced {"path": ..., "observation": ...} and {"malformed_lines": 0} as two
    unrelated entries. That is not a record; it is a pile. One object per observed file,
    and the candidate itself is observed through the same shape.
    """


def target_set(target, key, value, path):
    if isinstance(target, list):
        for member in target:
            if path is not None and member.get("path") == path:
                member[key] = value
                return
            if path is None and target:
                target[-1][key] = value
                return
        target.append(_Member({"path": path, key: value}))
        return
    target[key] = value
    if path:
        target.setdefault("source_path", path)


# --- completeness ---------------------------------------------------------------------------

def _finish(plan):
    """Decide whether this account's candidate set is known to be all of them.

    A file read perfectly does not settle it. The question is not "did a read succeed"
    but "is there a declaration whose consequences this collection could not follow".
    """
    for candidate in plan["candidates"]:
        resolution = candidate.get("resolution")
        if candidate.get("applicability") == model.UNRESOLVED_MATCH_SCOPED:
            # An unresolved Match leaves the CANDIDATE universe incomplete - another
            # declaration may apply that this collection cannot see - and it is also a
            # reason the EFFECTIVE universe is unknown. Two axes, recorded on both.
            plan["universe_reasons"].append(model.MATCH_SCOPED_DECLARATION)
            plan["effective_source_reasons"].append(
                model.EFFECTIVE_REASON_MATCH_UNRESOLVED)
        if resolution == model.UNEXPANDED_TOKEN:
            plan["universe_reasons"].append(model.TOKEN_NOT_EXPANDED)
        elif resolution == model.HOME_NOT_AVAILABLE:
            plan["universe_reasons"].append(model.HOME_UNKNOWN)
        if candidate.get("observation_reason") == model.GLOB_NOT_ENUMERABLE:
            plan["universe_reasons"].append(model.GLOB_NOT_ENUMERABLE)
        if candidate.get("observation") in (model.FILE_UNREADABLE,
                                            model.FILE_OUTSIDE_COLLECTION_ROOT):
            plan["universe_reasons"].append(model.CANDIDATE_NOT_OBSERVED)

    def unique(reasons):
        ordered, seen = [], set()
        for reason in reasons:
            if reason not in seen:
                seen.add(reason)
                ordered.append(reason)
        return ordered

    ordered = unique(plan["universe_reasons"])
    plan["universe_reasons"] = ordered
    plan["effective_source_reasons"] = unique(plan["effective_source_reasons"])
    plan["source_universe"] = (model.UNIVERSE_COMPLETE if not ordered
                               else model.UNIVERSE_INCOMPLETE)


def _status(plans, declarations, accounts, inherited=()):
    if not accounts:
        return model.NOT_TESTED, "NO_LOCAL_ACCOUNTS: the account evidence lists none."
    if not declarations:
        # IQ-046 (5): "carries no AuthorizedKeysFile" may only be said of a configuration
        # that was read. An absent sshd_config is nothing to observe and keeps
        # NO_DECLARATION_OBSERVED; a refused or incomplete one is the real cause.
        unseen = [limit for limit in inherited
                  if limit["reason"] == model.SSH_EVIDENCE_INCOMPLETE
                  and not (limit.get("upstream_reason") or "").startswith("SOURCE_ABSENT:")]
        if unseen:
            return (model.NOT_TESTED,
                    "SSH_EVIDENCE_INCOMPLETE: no AuthorizedKeysFile declaration was "
                    "observed because the declared sshd configuration was not fully "
                    "observed (%s)." % (unseen[0].get("upstream_reason")
                                        or unseen[0]["status"]))
        return (model.NOT_TESTED,
                "NO_DECLARATION_OBSERVED: the declared sshd configuration carries no "
                "AuthorizedKeysFile, and a compiled-in default is not evidence this "
                "collection holds.")
    incomplete = [p for p in plans if p["source_universe"] != model.UNIVERSE_COMPLETE]
    if incomplete:
        reasons = []
        for plan in incomplete:
            for reason in plan["universe_reasons"]:
                if reason not in reasons:
                    reasons.append(reason)
        return (model.PARTIAL,
                "UNRESOLVED_SOURCE_UNIVERSE for %d of %d account(s): %s"
                % (len(incomplete), len(plans), ", ".join(reasons)))
    return model.COLLECTED, None


def _coverage(plans):
    """R1.5-P acquisition context, one entry per observed candidate.

    The source universe is this lane's own, and it is the reason the lane matters to
    R1.5-P: a candidate file read perfectly under an unresolved Match leaves the universe
    INCOMPLETE, so the central rule refuses an absence claim over it even though the read
    succeeded. Completeness is not the same question as success.
    """
    out = []
    for plan in plans:
        universe = (coverage.UNIVERSE_COMPLETE
                    if plan["source_universe"] == model.UNIVERSE_COMPLETE
                    else coverage.UNIVERSE_INCOMPLETE)
        for candidate in plan["candidates"]:
            path = candidate.get("source_path") or candidate.get("path")
            if not path:
                continue
            observed = candidate.get("observation")
            outcome = (coverage.READ_OK if observed == model.FILE_READ
                       else coverage.NOT_FOUND if observed in (model.FILE_ABSENT,
                                                               model.GLOB_NO_MATCH)
                       else coverage.PERMISSION_DENIED
                       if candidate.get("observation_detail") == hostio.PERMISSION_DENIED
                       else coverage.IO_ERROR if observed == model.FILE_UNREADABLE
                       else coverage.NOT_SUPPORTED)
            out.append(coverage.source(
                "authorizedkeys", path,
                result.COLLECTED if observed == model.FILE_READ else result.NOT_TESTED,
                outcome, coverage.OP_FILE_READ, universe=universe,
                note=candidate.get("applicability")))
    return out
