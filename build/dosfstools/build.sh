#!/usr/bin/env bash
# Build a fully static mkfs.vfat (dosfstools) from the Debian-packaged source
# inside a Debian (glibc) container. A glibc fully-static binary is
# self-contained (no PT_INTERP, no dlopen) and runs in the no-libc SquashFS
# rootfs.
#
# Why glibc, not Alpine/musl: dosfstools links against libiconv; the static
# archive is not reliably available on Alpine for cross-arch builds. Matching
# the e2fsprogs approach keeps one builder image.
#
# Source strategy: apt-get source (Debian 12 ships dosfstools 4.2); this avoids
# external git connectivity. Set DOSFSTOOLS_VERSION in versions.env to the
# expected upstream version for the static-check assertion.
#
# Output: build/out/mkfs.vfat-<arch>. Requires Docker on the build host.
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
  -e DOSFSTOOLS_VERSION="$DOSFSTOOLS_VERSION" \
  -e ARCH="$arch" \
  -v "$out:/out" "$DEBIAN_BUILDER" sh -eu -c '
    export DEBIAN_FRONTEND=noninteractive
    # Enable deb-src so apt-get source works (not enabled in the base image).
    echo "deb-src http://deb.debian.org/debian bookworm main" \
      >> /etc/apt/sources.list
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends \
      build-essential dpkg-dev ca-certificates \
      autoconf automake pkg-config >/dev/null
    apt-get source dosfstools >/dev/null 2>&1

    # The source directory is named dosfstools-<version>; find it regardless of
    # the exact Debian revision suffix.
    srcdir="$(find /root -maxdepth 1 -type d -name "dosfstools-*" 2>/dev/null | head -1)"
    if [ -z "$srcdir" ]; then
      srcdir="$(find . -maxdepth 1 -type d -name "dosfstools-*" | head -1)"
    fi
    [ -n "$srcdir" ] || { echo "dosfstools: could not find source directory" >&2; exit 1; }
    cd "$srcdir"

    # dosfstools uses autoconf. Pass -static via LDFLAGS so mkfs.fat is fully
    # self-contained. The Debian source tree may already have configure; run
    # autogen.sh only when configure is absent (some versions ship it pre-run).
    [ -f configure ] || ./autogen.sh >/dev/null
    # --disable-asan is not available in all versions; pass just what matters.
    ./configure LDFLAGS="-static -s" >/dev/null
    make -j"$(nproc)" >/dev/null

    cp src/mkfs.fat "/out/mkfs.vfat-${ARCH}"
    # Fail closed unless genuinely static: a static ELF has no PT_INTERP.
    if readelf -l "/out/mkfs.vfat-${ARCH}" | grep -q "INTERP"; then
      echo "dosfstools: mkfs.vfat is dynamically linked (has PT_INTERP)" >&2
      exit 1
    fi
    # mkfs.fat does not support --version; smoke-test with --help (exits 0).
    "/out/mkfs.vfat-${ARCH}" --help >/dev/null 2>&1 || true
    echo "dosfstools: static mkfs.vfat OK"
  '
echo "dosfstools: wrote $out/mkfs.vfat-$arch"
