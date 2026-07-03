#!/usr/bin/env bash
# Build a fully static sgdisk (gptfdisk) from the Debian-packaged source inside
# a Debian (glibc) container. A glibc fully-static binary is self-contained (no
# PT_INTERP, no dlopen) and runs in the no-libc SquashFS rootfs.
#
# Why glibc, not Alpine/musl: gptfdisk links against libuuid and libpopt; the
# popt static archive is present in Debian but absent from Alpine's popt-static
# in the version we use. Matching the e2fsprogs approach keeps one builder image.
#
# Source strategy: apt-get source (Debian 12 ships gdisk 1.0.9); this avoids
# external git connectivity to SourceForge. Set GPTFDISK_VERSION in versions.env
# to the expected upstream version for the static-check assertion.
#
# Output: build/out/sgdisk-<arch>. Requires Docker on the build host.
# Refs #115
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=/dev/null
source "$root/build/ci/versions.env"

arch="${1:-amd64}"
out="$root/build/out"
mkdir -p "$out"

case "$arch" in
  amd64) platform=linux/amd64 ;;
  arm64) platform=linux/arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

# The build runs entirely inside the pinned Debian image; only the resulting
# static binary is copied back out to the mounted /out. versions.env vars are
# shell-local (not exported), so pass them explicitly with -e.
docker run --rm --platform "$platform" \
  -e GPTFDISK_VERSION="$GPTFDISK_VERSION" \
  -e ARCH="$arch" \
  -v "$out:/out" "$DEBIAN_BUILDER" sh -eu -c '
    export DEBIAN_FRONTEND=noninteractive
    # Enable deb-src so apt-get source works (not enabled in the base image).
    echo "deb-src http://deb.debian.org/debian bookworm main" \
      >> /etc/apt/sources.list
    apt-get update >/dev/null
    # build-dep pulls in the static libs (libpopt-dev, libuuid-dev, libedit-dev).
    apt-get install -y --no-install-recommends \
      build-essential dpkg-dev ca-certificates \
      libpopt-dev libuuid1 uuid-dev libedit-dev >/dev/null
    apt-get source gdisk >/dev/null 2>&1

    # The source directory is named gdisk-<version>; find it regardless of
    # the exact Debian revision suffix.
    srcdir="$(find /root -maxdepth 1 -type d -name "gdisk-*" 2>/dev/null | head -1)"
    if [ -z "$srcdir" ]; then
      # apt-get source may drop files in the working directory instead.
      srcdir="$(find . -maxdepth 1 -type d -name "gdisk-*" | head -1)"
    fi
    [ -n "$srcdir" ] || { echo "gptfdisk: could not find source directory" >&2; exit 1; }
    cd "$srcdir"

    # Build static binary; suppress harmless warnings from the upstream Makefile.
    make -j"$(nproc)" sgdisk \
      CXXFLAGS="-O2" \
      LDFLAGS="-static -s" \
      LIBS="-lpopt -luuid -lm" >/dev/null

    cp sgdisk "/out/sgdisk-${ARCH}"
    # Fail closed unless genuinely static: a static ELF has no PT_INTERP.
    if readelf -l "/out/sgdisk-${ARCH}" | grep -q "INTERP"; then
      echo "gptfdisk: sgdisk is dynamically linked (has PT_INTERP)" >&2
      exit 1
    fi
    "/out/sgdisk-${ARCH}" --version
  '
echo "gptfdisk: wrote $out/sgdisk-$arch"
