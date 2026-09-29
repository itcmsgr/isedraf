<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Critical call trees

Status: IMPLEMENTED

Bounded trees rooted in security-critical entry points. One whole-project call graph would
be unreadable on the day it was produced; these answer specific questions. **`[io]`** marks
a side-effecting leaf.

## isedraf identity

```
cli.cmd_identity
└── stateroot.resolve                       [io] env + state root
└── identity.collect
    └── identity.read_source                [io] /etc/machine-id, bounded to 4096
    └── identity.parse                      pure
    └── Identity.__init__ -> canonical.hash_frame
└── snapshot.commit                         [io] temp dir -> fsync -> atomic rename
    └── ledger.append                       [io] append + fsync
└── verify.verify_store                     [io] re-reads what was just written
```

## isedraf inventory

```
cli.cmd_inventory
└── inventory.collect
    ├── collectors.collect_host             [io] /proc, /etc/hosts
    ├── collectors.collect_platform         [io] /etc/os-release, uname
    ├── collectors.collect_machine          [io] /sys/class/dmi, systemd-detect-virt
    ├── collectors.collect_compute|memory   [io] /proc
    ├── collectors.collect_storage          [io] /sys/block, /proc/self/mounts
    ├── collectors.collect_network|dns      [io] ip, /etc/resolv.conf
    └── collectors.collect_time             [io] timedatectl, chronyc
        every leaf returns model.subdomain(status, data, reason)
```

## isedraf report

```
cli.cmd_report
└── inventory.collect                       [io]  the CLI collects
└── report.build
    ├── report.model.identity_evidence      [io]  READS the committed state root
    │   └── verify.verify_store                   re-verifies, never re-collects
    ├── report.artifact.build                     pure, digests the inventory
    └── report.model._collection_summary          pure
└── report.render.to_json | to_markdown           pure
```

The renderer performs no acquisition. `report.model` reads the evidence store; the
architecture gate forbids it importing `hostio`, the collectors or any acquire module.

## account source acquisition

```
accounts.acquire.collect
├── acquire.acquire(passwd|group|shadow)
│   └── hostio.read_file_lossless           [io]  surrogateescape, lossless
│   └── sources.parse_*                     pure  text in, records out
├── _shadow_relation                        pure  PRESENT / ABSENT_FROM_COLLECTED / UNKNOWN
└── orphan detection                        pure  gated on counterpart completeness
```

## shared primitives

```
S1  keyvalue.parse(text, profile)           pure — no I/O at all
S2  include_graph.resolve(root, adapter)
    └── hostio.read_file_lossless           [io]  injectable; tests pass a fake reader
S3  compare.compare(declared, active, cmp)  pure — no I/O at all
S4  filemeta.observe(path, digest)          [io]  lstat, then O_NOFOLLOW open for digest
S5  bounded.enumerate_paths(root, universe) [io]  listdir + lstat, never follows a link
```
