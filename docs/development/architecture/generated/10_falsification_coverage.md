<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Falsification coverage by subsystem

Status: IMPLEMENTED

GENERATED from `scripts/ci/falsifiable.sh`. A large total is not coverage if most of it attacks one subsystem.

| Subsystem | Injections |
|---|---|
| W1-A / canonical | 16 |
| inventory / storage D-114 | 5 |
| accounts W1-D | 22 |
| S1 key/value | 4 |
| S2 include graph | 5 |
| S3 comparison | 22 |
| S4 file metadata | 4 |
| S5 enumeration | 5 |
| architecture | 7 |
| privacy / disclosure | 27 |
| licensing / framework | 21 |
| packaging / release | 9 |
| governance / gates | 8 |
| docs truth | 7 |
| other / cross-cutting | 209 |
| **total** | **371** |
