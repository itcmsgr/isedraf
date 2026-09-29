<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Auditor guide

This page is for someone reviewing ISEDRAF evidence they did not produce. It explains what
to look at first, how to check a single fact by hand without trusting ISEDRAF, and what
the evidence cannot tell you.

## What you are given

Usually two things: a report (HTML, Markdown or JSON), and a copy of the operator's
evidence store, or at least the run directory the report names. The report is a rendering;
the files in the run are the evidence. When they disagree, the files win, and the
disagreement is itself worth recording.

Everything in a run is plain JSON. You need no ISEDRAF installation to read or check it;
Python's standard library is enough.

## Five things to read first

1. **Privilege level.** ISEDRAF 0.1 always reports UNPRIVILEGED. Anything that needs root
   was not observed.
2. **Overall evidence status.** COLLECTED, PARTIAL or ERROR. PARTIAL is normal for an
   unprivileged run.
3. **Evidence class.** USER_PRODUCTION is a normal run. DEV is a development run and is not
   production evidence.
4. **Verification line.** The report states whether the digests, bindings and ledger chain
   held when it was rendered.
5. **Each area's status and reason.** A reason tells you exactly what was not read and why,
   for example `SOURCE_UNREADABLE: /etc/sudoers could not be read.`

The [Evidence model](EVIDENCE_MODEL.md) explains the statuses; the
[Report guide](REPORT_GUIDE.md) walks through the report layout.

## Checking one observation by hand

Each report section ends with an evidence reference: the file inside the run and its
digest. The steps below check that reference, the run that contains it, and the ledger
entry that commits the run, using only Python. The values are from a small test host.

The report said, for local accounts:

```text
evidence: sections/accounts.json · sha256:b78bea64006d0219e1abc0c87a3fa6c9d3023cb4668c0c72ee5450d8d879f8c3
```

ISEDRAF digests are SHA-256 over a fixed label, the content length as 8 bytes, and the
content. The label keeps a file digest from ever being mistaken for any other kind of
digest. That is why a plain `sha256sum` gives a different value.

**Step 1. Recompute the file's digest.** Run this in the run directory
(`snapshots/SDS-…/` in the store):

```sh
python3 - sections/accounts.json <<'PY'
import hashlib, sys
data = open(sys.argv[1], "rb").read()
label = b"ISEDRAF:AUXILIARY-ARTIFACT:V1"
print("sha256:" + hashlib.sha256(label + len(data).to_bytes(8, "big") + data).hexdigest())
PY
```

It must print the digest the report showed.

**Step 2. Check that the run lists that digest.**

```sh
python3 -c 'import json; print(json.load(open("manifest.json"))["manifest_core"]["auxiliary_artifacts"]["sections/accounts.json"])'
```

**Step 3. Recompute the manifest's own digest.** The manifest holds only identifiers and
digests, so sorted, compact JSON reproduces ISEDRAF's canonical form exactly.

```sh
python3 - <<'PY'
import hashlib, json
m = json.load(open("manifest.json"))
core = (json.dumps(m["manifest_core"], sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False) + "\n").encode("utf-8")
label = b"ISEDRAF:SNAPSHOT-MANIFEST:V1"
print("sha256:" + hashlib.sha256(label + len(core).to_bytes(8, "big") + core).hexdigest())
print(m["manifest_hash"])
PY
```

The two lines must be equal.

**Step 4. Check the ledger.** Every record must hash correctly and point at the record
before it; the record for this run must carry the manifest digest from step 3.

```sh
python3 - ../../ledger/segment-000001.jsonl <<'PY'
import hashlib, json, sys
previous = "sha256:" + "0" * 64
for line in open(sys.argv[1]):
    r = json.loads(line)
    core = (json.dumps(r["record_core"], sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False) + "\n").encode("utf-8")
    label = b"ISEDRAF:LEDGER-RECORD:V1"
    ok = ("sha256:" + hashlib.sha256(label + len(core).to_bytes(8, "big") + core).hexdigest()
          == r["record_hash"] and r["record_core"]["previous_record_hash"] == previous)
    print(r["record_core"]["sequence"], r["record_core"]["snapshot_id"],
          r["record_core"]["manifest_hash"], "ok" if ok else "MISMATCH")
    previous = r["record_hash"]
PY
```

**Step 5. Read the fact itself.** The report said "Accounts with uid 0: 1". Count it in
the evidence:

```sh
python3 -c 'import json; e=json.load(open("sections/accounts.json"))["evidence"]; print(sum(1 for a in e["local_accounts"] if a["uid"] == 0))'
```

If you have access to the host, compare with the source file, for example
`awk -F: '$3 == 0' /etc/passwd`. A difference may simply mean the host changed after the run.

## What the evidence does not tell you

These limits hold for every run. They are not caveats to skip.

- **An accepted baseline is not a secure host.** When baselines arrive, accepting one will
  record a decision, not a security judgement. ISEDRAF 0.1 has no baselines at all.
- **No observed change does not mean uncompromised.** ISEDRAF reads what userspace and the
  kernel expose. Someone with root can alter those sources, the logs, the evidence store
  and ISEDRAF itself.
- **NOT_TESTED is not PASS.** It means the fact was not observed. Nothing may be inferred
  from it in either direction.
- **Host evidence is not organizational compliance.** A run describes one host at one
  moment. It says nothing about policies, people or processes, and no framework mapping
  exists in this repository.
- **A missing local product is not a missing control.** If no firewall, antivirus or EDR
  product is seen on the host, the control may still exist outside it.
- **This is not remote attestation.** Verification shows that the files match what the
  ledger recorded. It does not show that the host reported the truth, and nothing in a run
  is signed.

[Security and limitations](SECURITY_AND_LIMITATIONS.md) lists everything outside the
scope of ISEDRAF 0.1.

## Questions worth asking the operator

- Was this run made on the host it names, as a normal user, without `ISEDRAF_STATE_ROOT`?
- Are there later runs, and why was this one chosen?
- Who else can read or write the evidence store, and who has root on the host?
- Which areas were NOT_TESTED, and is there other evidence for them?

## References

Normative sources, for readers who need them: hash framing and canonical form
(NORM-035, NORM-039); section binding outside the host-state hash (D-115); commit order and
the ledger (SNAP-014, D-50); collection versus evaluation (EVID-001, D-13); the
limitations above (CMP-001, CMP-002, EVID-040). The frozen design is under
[docs/architecture](architecture/).
