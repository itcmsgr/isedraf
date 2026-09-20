# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: An SPDX 2.3 JSON SBOM describing the FINAL built artifact.
# Implements: D-84, EXEC-016, GOV-001
#
# NO EXTERNAL SBOM TOOL. Adding a third-party generator to describe a zero-dependency
# package would introduce a supply-chain dependency in order to document the absence of
# supply-chain dependencies — and it would be a tool this project then has to pin, review
# and trust. The standard library can list files and hash them.
#
# It describes the ARTIFACT, not the source checkout. A clean source tree is not a correct
# package: the DEB once staged to the wrong prefix, built fine, and did nothing. An SBOM
# generated from source would have described a package that was never shipped.
#
# meta:type="tool"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="writes the SBOM file it is asked for"
# meta:binaries="git,ar,tar,rpm2cpio,cpio"
# =============================================================================

"""usage: generate_sbom.py <artifact> <output.spdx.json>"""
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

SPDX_VERSION = "SPDX-2.3"
LICENSE = "MPL-2.0"
SUPPLIER = "Organization: ITCMS"
NAMESPACE = "https://github.com/itcmsgr/isedraf/spdx"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def unpack(artifact, dest):
    """Extract the payload a user actually receives. Returns (kind, root)."""
    name = artifact.name
    if name.endswith(".deb"):
        data = subprocess.check_output(["ar", "p", str(artifact), "data.tar.gz"])
        tarball = dest / "data.tar.gz"
        tarball.write_bytes(data)
        with tarfile.open(tarball) as tf:
            tf.extractall(dest / "payload")
        return "deb", dest / "payload"
    if name.endswith(".rpm"):
        root = dest / "payload"
        root.mkdir()
        cpio = subprocess.Popen(["rpm2cpio", str(artifact)], stdout=subprocess.PIPE)
        subprocess.check_call(["cpio", "-idmu", "--quiet"], stdin=cpio.stdout, cwd=str(root))
        cpio.wait()
        return "rpm", root
    if name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(artifact) as tf:
            tf.extractall(dest / "payload")
        return "tarball", dest / "payload"
    raise SystemExit("unsupported artifact type: %s" % name)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    artifact = pathlib.Path(sys.argv[1]).resolve()
    output = pathlib.Path(sys.argv[2])
    version = (pathlib.Path(
        subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
    ) / "VERSION").read_text().strip()
    artifact_digest = sha256_file(artifact)

    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        kind, root = unpack(artifact, tmp)
        files = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            files.append({
                "SPDXID": "SPDXRef-File-%d" % (len(files) + 1),
                "fileName": "./" + rel,
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha256_file(path)}],
                "licenseConcluded": LICENSE,
                "copyrightText": "Copyright (c) 2026 Antonios Voulvoulis / ITCMS",
            })
    finally:
        shutil.rmtree(str(tmp), ignore_errors=True)

    # The runtime requirement, stated as what it is. Python itself is NOT vendored, NOT
    # installed and NOT bundled: the package uses the interpreter the host already has.
    packages = [
        {
            "SPDXID": "SPDXRef-Package-isedraf",
            "name": "isedraf",
            "versionInfo": version,
            "supplier": SUPPLIER,
            "downloadLocation": "https://github.com/itcmsgr/isedraf",
            "filesAnalyzed": True,
            "licenseConcluded": LICENSE,
            "licenseDeclared": LICENSE,
            "copyrightText": "Copyright (c) 2026 Antonios Voulvoulis / ITCMS",
            "checksums": [{"algorithm": "SHA256", "checksumValue": artifact_digest}],
            "primaryPackagePurpose": "APPLICATION",
            "comment": ("Python standard library only. No compiled component, no "
                        "third-party runtime module, no vendored interpreter."),
        },
        {
            "SPDXID": "SPDXRef-Package-cpython",
            "name": "python3",
            "versionInfo": ">=3.6",
            "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "APPLICATION",
            "comment": ("An EXTERNAL runtime prerequisite satisfied by the operating "
                        "system. ISEDRAF never installs, bundles, pins or downgrades an "
                        "interpreter; it uses the vendor one already present."),
        },
    ]

    document = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "isedraf-%s-%s" % (version, artifact.name),
        "documentNamespace": "%s/%s-%s" % (NAMESPACE, artifact.name, artifact_digest[:16]),
        "creationInfo": {
            "created": datetime.datetime.now(
                datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Organization: ITCMS", "Tool: isedraf-sbom-1"],
            "comment": ("Generated from the FINAL %s artifact, not from a source "
                        "checkout, because a clean source tree is not a correct package."
                        % kind),
        },
        "packages": packages,
        "files": files,
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
             "relatedSpdxElement": "SPDXRef-Package-isedraf"},
            {"spdxElementId": "SPDXRef-Package-isedraf",
             "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-Package-cpython"},
        ] + [{"spdxElementId": "SPDXRef-Package-isedraf",
              "relationshipType": "CONTAINS",
              "relatedSpdxElement": f["SPDXID"]} for f in files],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print("  SBOM %s  %d files, artifact sha256:%s"
          % (output.name, len(files), artifact_digest[:16]))


if __name__ == "__main__":
    sys.exit(main())
