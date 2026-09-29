<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Sudo lane interface contract

Status: IMPLEMENTED
Implements: SCOPE-022, SCOPE-045, IDENT-013

Declared by the coordinator BEFORE either worker started, so the adversarial lane could
attack a specification rather than an implementation. That ordering is what made pass 1
independent, and pass 1 is what found the fixture-root include defect.

isedraf.sudo.acquire.collect(root="/") -> shared.result.Evidence

Evidence.status      SCOPE-022, via the include graph and per-file parse outcomes
Evidence.records     policy records, IN SOURCE ORDER across the whole include graph
Evidence.provenance  {"files": [...], "include_events": [...], "grammar": {...}}

Every record carries: kind, source_path, source_line, ordinal

kind = DEFAULTS
    scope_type   GLOBAL | USER | RUNAS | HOST | COMMAND
    scope        the qualifier text, or null for GLOBAL
    options      [{name, value, operator, negated}]   operator in = += -= or null

kind = ALIAS
    alias_type   USER | RUNAS | HOST | CMND
    name
    members      [{value, negated}]

kind = SPEC
    principals      [{value, kind: USER|GROUP|ALIAS|NETGROUP|ALL, negated}]
    host            {value, negated}
    runas_users     [{value, negated}] or null
    runas_groups    [{value, negated}] or null
    commands        [{command, negated, tags: [...]}]

kind = UNSUPPORTED
    raw_digest   sha256 of the line; the line itself is NOT retained
    reason

NOT in scope: effective privilege, "can X become root", any verdict.
