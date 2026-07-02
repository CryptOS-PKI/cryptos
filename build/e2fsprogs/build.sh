#!/usr/bin/env bash
# Build a fully static mke2fs (installed into the rootfs as mkfs.ext4) from the
# pinned e2fsprogs git tag, inside a Debian (glibc) container.
#
# Why glibc, not the Alpine/musl base the rest of the image uses: e2fsprogs'
# bundled libblkid does not static-link against musl (llseek), and Alpine ships
# no libeconf-static for the util-linux libblkid path. A glibc fully-static
# build is self-contained (no PT_INTERP, no dlopen) and runs in the no-libc
# SquashFS rootfs. Output: build/out/mke2fs-<arch>. Requires Docker.
#
# Source is the git tag (not a cdn.kernel.org tarball); the tag is permanent and
# reachable where the pruned tarball URLs are not. See build/kernel/build.sh.
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
  -e E2FSPROGS_VERSION="$E2FSPROGS_VERSION" \
  -e ARCH="$arch" \
  -v "$out:/out" "$DEBIAN_BUILDER" sh -eu -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends \
      build-essential git ca-certificates pkg-config >/dev/null

    cd /tmp
    git clone --depth 1 --branch "v${E2FSPROGS_VERSION}" \
      https://github.com/tytso/e2fsprogs.git e2fsprogs
    cd e2fsprogs

    # Use the in-tree libblkid/libuuid (no util-linux dep) and static-link.
    ./configure --disable-nls --disable-defrag --disable-shared >/dev/null
    make -j"$(nproc)" LDFLAGS="-static -s" >/dev/null

    b="$(find . -name mke2fs -type f | head -1)"
    cp "$b" "/out/mke2fs-${ARCH}"
    # Fail closed unless genuinely static: a static ELF has no PT_INTERP.
    if readelf -l "/out/mke2fs-${ARCH}" | grep -q "INTERP"; then
      echo "e2fsprogs: mke2fs is dynamically linked (has PT_INTERP)" >&2
      exit 1
    fi
    "/out/mke2fs-${ARCH}" -V
  '
echo "e2fsprogs: wrote $out/mke2fs-$arch"
