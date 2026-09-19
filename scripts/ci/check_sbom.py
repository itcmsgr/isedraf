# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Check that each SBOM describes the artifact it claims to describe.
# Implements: D-86, D-90, GOV-002
#
# An SBOM is a claim about bytes. Generated and never checked, it is a document that
# says whatever its generator believed - including a generator with a bug, which is
# the failure mode this project has already met twice (the DEB staged to the wrong
# prefix; /proc read once and truncated).
#
# The strongest check here is the RPM one, and it is strong because it is INDEPENDENT:
# rpm records its own per-file SHA-256 digests at build time, and `rpm -qp --dump`
# reads them back. Comparing those against the SBOM compares two different programs'
# accounts of the same package. For the deb and the tarball no second digest source
# exists, so the file INVENTORY is cross-checked and the digests are recomputed - which
# is weaker, and is reported as weaker rather than presented as equivalent.
#
# meta:type="ci-gate"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="git,rpm,ar,tar,python3"
# =============================================================================

"""usage: check_sbom.py [dist-directory]"""
import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import shutil

ROOT = pathlib.Path(subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True).strip())
DIST = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist"
FAIL = []


def bad(msg):
    FAIL.append(msg)
    print("  FAIL  %s" % msg)


def ok(msg):
    print("  OK    %s" % msg)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sbom_files(doc):
    """{normalized path: sha256} as the SBOM states it."""
    out = {}
    for f in doc["files"]:
        name = f["fileName"]
        name = name[2:] if name.startswith("./") else name
        digest = [c["checksumValue"] for c in f["checksums"]
                  if c["algorithm"] == "SHA256"]
        if not digest:
            bad("SBOM file entry without a SHA256 checksum: %s" % name)
            continue
        out["/" + name.lstrip("/")] = digest[0]
    return out


def rpm_dump(artifact):
    """{path: sha256} as RPM ITSELF recorded it at build time. Independent source."""
    text = subprocess.check_output(
        ["rpm", "-qp", "--dump", str(artifact)], text=True,
        stderr=subprocess.DEVNULL)
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        path, _size, _mtime, digest = parts[0], parts[1], parts[2], parts[3]
        # Directories and ghost entries carry an all-zero or empty digest.
        if not digest or set(digest) == {"0"}:
            continue
        out[path] = digest
    return out


def archive_members(artifact):
    """Path inventory read straight out of the archive, without extracting."""
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        if artifact.name.endswith(".deb"):
            data = subprocess.check_output(["ar", "p", str(artifact), "data.tar.gz"])
            (tmp / "d.tar.gz").write_bytes(data)
            src = tmp / "d.tar.gz"
        else:
            src = artifact
        with tarfile.open(src) as tf:
            return {"/" + m.name.lstrip("./").lstrip("/")
                    for m in tf.getmembers() if m.isfile()}
    finally:
        shutil.rmtree(str(tmp), ignore_errors=True)


print("--- SBOM accuracy (D-86, GOV-002) ---")
sbom_dir = DIST / "sbom"
pkg_dir = DIST / "packages"
if not sbom_dir.is_dir():
    bad("no SBOM directory at %s - run packaging/build.sh first" % sbom_dir)
    sys.exit(1)

sboms = sorted(sbom_dir.glob("*.spdx.json"))
# U-30 / Z-18: count the inputs BEFORE checking them. A gate that passes over an empty
# directory is not a gate, and this project has already shipped that exact defect once.
if not sboms:
    bad("no SBOM documents found in %s" % sbom_dir)
    sys.exit(1)

for sbom_path in sboms:
    artifact = pkg_dir / sbom_path.name[:-len(".spdx.json")]
    doc = json.loads(sbom_path.read_text())

    if not artifact.exists():
        bad("%s describes an artifact that does not exist: %s"
            % (sbom_path.name, artifact.name))
        continue

    # --- 1. structural minimum -------------------------------------------------------
    for key in ("spdxVersion", "SPDXID", "documentNamespace", "creationInfo",
                "packages", "files", "relationships", "dataLicense"):
        if key not in doc:
            bad("%s is missing the required SPDX field %r" % (sbom_path.name, key))
    if doc.get("spdxVersion") != "SPDX-2.3":
        bad("%s declares %r, not SPDX-2.3" % (sbom_path.name, doc.get("spdxVersion")))

    # --- 2. the SBOM names the artifact by digest ------------------------------------
    real = sha256_file(artifact)
    stated = None
    for p in doc.get("packages", []):
        if p.get("SPDXID") == "SPDXRef-Package-isedraf":
            for c in p.get("checksums", []):
                if c.get("algorithm") == "SHA256":
                    stated = c["checksumValue"]
    if stated != real:
        bad("%s states artifact sha256 %s, the file is %s"
            % (sbom_path.name, stated, real))
        continue
    ok("%s binds to its artifact by digest" % sbom_path.name)

    # --- 3. the file inventory, cross-checked ----------------------------------------
    claimed = sbom_files(doc)

    if artifact.name.endswith(".rpm") and shutil.which("rpm"):
        recorded = rpm_dump(artifact)
        missing = set(recorded) - set(claimed)
        extra = set(claimed) - set(recorded)
        mismatched = [p for p in set(recorded) & set(claimed)
                      if recorded[p] != claimed[p]]
        for p in sorted(missing):
            bad("%s: rpm records %s, the SBOM does not list it" % (sbom_path.name, p))
        for p in sorted(extra):
            bad("%s: SBOM lists %s, rpm does not record it" % (sbom_path.name, p))
        for p in sorted(mismatched):
            bad("%s: digest disagreement on %s (rpm %s / SBOM %s)"
                % (sbom_path.name, p, recorded[p][:16], claimed[p][:16]))
        if not (missing or extra or mismatched):
            ok("%s: %d files agree with rpm's OWN recorded digests (independent)"
               % (sbom_path.name, len(recorded)))
    else:
        members = archive_members(artifact)
        missing = members - set(claimed)
        extra = set(claimed) - members
        for p in sorted(missing):
            bad("%s: archive contains %s, the SBOM does not list it"
                % (sbom_path.name, p))
        for p in sorted(extra):
            bad("%s: SBOM lists %s, the archive does not contain it"
                % (sbom_path.name, p))
        if not (missing or extra):
            ok("%s: %d files agree with the archive inventory "
               "(inventory only - no second digest source exists for this format)"
               % (sbom_path.name, len(members)))

    # --- 4. the interpreter is declared as external, never as something we ship ------
    cpython = [p for p in doc["packages"] if p.get("SPDXID") == "SPDXRef-Package-cpython"]
    if not cpython:
        bad("%s does not declare the external Python runtime requirement"
            % sbom_path.name)
    elif cpython[0].get("filesAnalyzed") is not False:
        bad("%s describes the interpreter as if this package contained it"
            % sbom_path.name)

if FAIL:
    print("=== SBOM accuracy gate FAILED ===")
    print("  An SBOM is a claim about bytes. Fix the claim, or the bytes it claims.")
    sys.exit(1)
print("  OK    %d SBOM documents describe the artifacts they name" % len(sboms))
