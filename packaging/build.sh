#!/usr/bin/env bash
# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Bridge (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: Build the release artifacts — tarball, .deb, .rpm and SHA256SUMS.build.
# Implements: EXEC-016, D-12, D-84
#
# ARCHITECTURE-INDEPENDENT BY CONSTRUCTION. The payload is Python standard library with
# no compiled component, so the DEB is `Architecture: all` and the RPM is `noarch`: one
# artifact installs on x86_64 and aarch64 alike. Nothing here cross-compiles because
# there is nothing to compile.
#
# The .deb is assembled with `ar` and `tar` rather than dpkg-deb, so the build needs no
# Debian tooling and runs on any host - which is the same reason the product itself has
# no runtime dependencies.
#
# meta:type="tool"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="dist/ only"
# meta:binaries="git,tar,gzip,ar,sha256sum,rpmbuild"
# =============================================================================
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT" || exit 2

VERSION="$(tr -d '[:space:]' < VERSION)"
# Debian orders `~` BEFORE the release, so 0.1.0~alpha1 < 0.1.0. RPM needs the same
# ordering expressed differently: version 0.1.0 with release 0.alpha1.
DEB_VERSION="${VERSION/-/\~}"
RPM_VERSION="${VERSION%%-*}"
RPM_RELEASE="0.${VERSION#*-}"
[ "$RPM_RELEASE" = "0.$VERSION" ] && RPM_RELEASE="1"
DIST="$ROOT/dist"
STAGE="$DIST/stage"
MAINTAINER="Antonios Voulvoulis / ITCMS <contact@itcms.gr>"
DESCRIPTION="Linux host assurance, approved baseline, state delta and evidence engine"

say() { echo "  $*"; }
die() { echo "  FAIL  $*" >&2; exit 1; }

rm -rf "$DIST"; mkdir -p "$DIST/packages"

# ---- 1. the payload, assembled once and shared by every artifact ----------------------
say "staging payload for $VERSION"
install -d -m 0755 "$STAGE/usr/bin" "$STAGE/usr/lib/isedraf" \
                   "$STAGE/usr/share/doc/isedraf"
install -m 0755 bin/isedraf "$STAGE/usr/bin/isedraf"
# git ls-files, so an untracked scratch file can never be shipped by accident.
for f in $(git ls-files 'lib/isedraf/*.py' 'lib/isedraf/**/*.py'); do
    # $STAGE/usr/lib/isedraf/... - an earlier version stripped "lib/" and installed to
    # /usr/isedraf, where the launcher does not look. The package built, installed, and
    # then did nothing.
    install -D -m 0644 "$f" "$STAGE/usr/$f" || die "staging $f"
done
find "$STAGE/usr/lib/isedraf" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null
find "$STAGE" -name '*.pyc' -delete 2>/dev/null
install -m 0644 LICENSE "$STAGE/usr/share/doc/isedraf/LICENSE" 2>/dev/null || true
install -m 0644 README.md "$STAGE/usr/share/doc/isedraf/README.md"
install -m 0644 docs/reference/PLATFORM_COMPATIBILITY.md \
    "$STAGE/usr/share/doc/isedraf/PLATFORM_COMPATIBILITY.md"
install -m 0644 docs/operator/STORAGE_AND_OUTPUTS.md \
    "$STAGE/usr/share/doc/isedraf/STORAGE_AND_OUTPUTS.md"

# D-17/D-86: bytecode is never shipped.
find "$STAGE" -name '*.pyc' -o -name '__pycache__' | grep -q . \
    && die "bytecode found in the staged payload (D-86)"
# The launcher resolves <prefix>/lib/isedraf from its own location. If the payload is
# not exactly there, the package installs cleanly and the command does nothing.
[ -f "$STAGE/usr/lib/isedraf/cli.py" ] || die "payload layout wrong: expected usr/lib/isedraf/cli.py"
[ -x "$STAGE/usr/bin/isedraf" ] || die "launcher missing or not executable"
say "payload: $(find "$STAGE" -type f | wc -l) files, layout verified"

# ---- 2. source tarball -----------------------------------------------------------------
TARBALL="$DIST/packages/isedraf-$VERSION.tar.gz"
git archive --format=tar --prefix="isedraf-$VERSION/" HEAD \
    | gzip -n9 > "$TARBALL" || die "git archive failed"
say "tarball: $(basename "$TARBALL")"

# ---- 3. DEB, assembled with ar and tar -------------------------------------------------
DEBROOT="$DIST/debroot"
rm -rf "$DEBROOT"; mkdir -p "$DEBROOT/DEBIAN"
cp -a "$STAGE/." "$DEBROOT/"
# Installed-Size, computed from the FILE SIZES rather than from `du`. `du -sk` reports
# DISK usage, which depends on the filesystem: the same payload measured 224 on btrfs
# and 260 on the runner's ext4, so the deb carried a property of the build machine's
# filesystem and could never reproduce across machines. Debian policy asks for an
# estimate in KiB; summing ceil(bytes/1024) per file is an estimate that depends only
# on the payload.
INSTALLED_KB=$(find "$DEBROOT/usr" -type f -printf '%s\n' \
    | awk '{ total += int(($1 + 1023) / 1024) } END { print total + 0 }')
sed -e "s|@VERSION@|$DEB_VERSION|g" -e "s|@MAINTAINER@|$MAINTAINER|g" \
    -e "s|@INSTALLED_SIZE@|$INSTALLED_KB|g" -e "s|@DESCRIPTION@|$DESCRIPTION|g" \
    packaging/deb/control.in > "$DEBROOT/DEBIAN/control" || die "deb control"

# Sorted, in the C locale. `find` returns directory order, which is a property of the
# FILESYSTEM: the same payload produced the same 24 lines in a different sequence on
# btrfs and on ext4, so the control archive - and therefore the .deb - differed across
# machines while the payload was byte-identical.
#
# This is NORM-037 in the packaging rather than in the engine: a set-like field entered
# an artifact unordered. The engine has had a gate and an injection for that since W1-A;
# the package build did not.
( cd "$DEBROOT" && find usr -type f -print0 | LC_ALL=C sort -z \
    | xargs -0 sha256sum > DEBIAN/sha256sums ) || die "deb sha256sums"

DEB="$DIST/packages/isedraf_${DEB_VERSION}_all.deb"
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
echo "2.0" > "$TMPD/debian-binary"
# --sort=name and a fixed mtime: the same input must produce the same bytes, which is the
# same property the evidence engine is built around.
TARFLAGS="--sort=name --owner=root:0 --group=root:0 --mtime=@0 --format=gnu"
# shellcheck disable=SC2086
tar $TARFLAGS -czf "$TMPD/control.tar.gz" -C "$DEBROOT/DEBIAN" . || die "control.tar.gz"
# shellcheck disable=SC2086
tar $TARFLAGS -czf "$TMPD/data.tar.gz" -C "$DEBROOT" usr || die "data.tar.gz"
# `ar rcD` — DETERMINISTIC mode. Plain `ar rc` writes the current time, the builder's
# numeric uid and the builder's gid into every member header, so two builds of an
# identical tree produced different bytes, and the artifact carried the build account's
# UID to every person who downloaded it. Both were true of every package built so far.
( cd "$TMPD" && ar rcD "$DEB" debian-binary control.tar.gz data.tar.gz ) || die "ar"
say "deb: $(basename "$DEB")"

# ---- 4. RPM ------------------------------------------------------------------------------
# SOURCE_DATE_EPOCH is taken from the commit being built, not from the clock, so rpm's
# BUILDTIME and every packaged mtime are a property of the SOURCE rather than of the
# moment someone happened to run this. Without it the same tree produced a different
# .rpm every time, which makes "rebuild it yourself and compare" impossible.
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct 2>/dev/null || echo 0)"
export SOURCE_DATE_EPOCH
if command -v rpmbuild >/dev/null 2>&1; then
    RPMTOP="$DIST/rpmbuild"
    mkdir -p "$RPMTOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    cp "$TARBALL" "$RPMTOP/SOURCES/"
    sed -e "s|@VERSION@|$RPM_VERSION|g" -e "s|@RELEASE@|$RPM_RELEASE|g" \
        -e "s|@FULLVERSION@|$VERSION|g" -e "s|@DESCRIPTION@|$DESCRIPTION|g" \
        packaging/rpm/isedraf.spec.in > "$RPMTOP/SPECS/isedraf.spec" || die "rpm spec"
    rpmbuild --define "_topdir $RPMTOP" --define "_sourcedir $RPMTOP/SOURCES" \
             --define "_buildhost isedraf-build" \
             --define "use_source_date_epoch_as_buildtime 1" \
             --define "clamp_mtime_to_source_date_epoch 1" \
             -bb "$RPMTOP/SPECS/isedraf.spec" >"$DIST/rpmbuild.log" 2>&1 \
        || { tail -20 "$DIST/rpmbuild.log" >&2; die "rpmbuild failed"; }
    found="$(find "$RPMTOP/RPMS" -name '*.rpm' | head -1)"
    [ -n "$found" ] || die "rpmbuild produced no package"
    cp "$found" "$DIST/packages/isedraf-$RPM_VERSION-$RPM_RELEASE.noarch.rpm"
    say "rpm: isedraf-$RPM_VERSION-$RPM_RELEASE.noarch.rpm"
else
    say "SKIP rpm: rpmbuild is not installed on this builder"
fi

# ---- 5. stable aliases, so a user never has to find a version number --------------------
# GitHub serves /releases/latest/download/<name> only for an EXACT asset name, so each
# artifact is published twice: once versioned and immutable for the record, once under a
# fixed name so one documented URL keeps working across every release.
( cd "$DIST/packages"
  for f in isedraf_*_all.deb;        do [ -e "$f" ] && cp "$f" "isedraf-latest_all.deb"; done
  for f in isedraf-*.noarch.rpm;     do [ -e "$f" ] && cp "$f" "isedraf-latest.noarch.rpm"; done
  for f in isedraf-*.tar.gz;         do case "$f" in *latest*) continue;; esac
                                       [ -e "$f" ] && cp "$f" "isedraf-latest.tar.gz"; done
) 2>/dev/null

# ---- 6. SHA256SUMS.build — the local ground truth -----------------------------------------
# Named .build deliberately. The release workflow downloads the published assets back and
# regenerates SHA256SUMS from what a USER actually receives, then compares the two. A
# checksum computed only over what we uploaded cannot detect a corrupted upload.
( cd "$DIST/packages" && sha256sum ./* | sed 's| \./| |' > "$DIST/SHA256SUMS.build" )
# ---- 7. SBOM per artifact, from the FINAL package ------------------------------------------
# Generated here rather than only in the release workflow, so it is exercised on every
# local build instead of first running on the day it matters. Standard library only: a
# third-party SBOM generator would add a supply-chain dependency in order to document the
# absence of supply-chain dependencies.
# The `latest` aliases are byte-identical copies of the versioned artifacts and are skipped;
# an SBOM for each would be the same document twice under two names.
mkdir -p "$DIST/sbom"
for a in "$DIST"/packages/*; do
    case "$(basename "$a")" in *latest*|SHA256SUMS*) continue;; esac
    case "$a" in *.deb|*.rpm|*.tar.gz) ;; *) continue;; esac
    python3 "$ROOT/scripts/ci/generate_sbom.py" "$a" "$DIST/sbom/$(basename "$a").spdx.json" \
        || die "SBOM generation failed for $(basename "$a")"
done

say "artifacts:"
sed 's/^/    /' "$DIST/SHA256SUMS.build"
echo "  build complete: $DIST"
