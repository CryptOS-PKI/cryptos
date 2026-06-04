#!/usr/bin/env bash
# DRAFT — not yet executed. Validate on a Linux build host before relying on it.
#
# Fetch a pinned Linux kernel, verify its checksum, merge the CryptOS
# config fragment onto a minimal defconfig, and build a reproducible
# bzImage. Output: build/out/vmlinuz-<arch>.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=/dev/null
source "$root/build/ci/versions.env"

arch="${1:-amd64}"
out="$root/build/out"
work="$root/build/.work/kernel"
mkdir -p "$out" "$work"

if [ "$KERNEL_SHA256" = "REPLACE_WITH_VERIFIED_SHA256" ]; then
  echo "kernel: set KERNEL_SHA256 in build/ci/versions.env first" >&2
  exit 1
fi

# Reproducibility: pin the build timestamp to the repo's HEAD commit.
SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct)"
export SOURCE_DATE_EPOCH KBUILD_BUILD_TIMESTAMP="@$SOURCE_DATE_EPOCH"
export KBUILD_BUILD_USER=cryptos KBUILD_BUILD_HOST=cryptos

tarball="linux-${KERNEL_VERSION}.tar.xz"
src="$work/linux-${KERNEL_VERSION}"
if [ ! -d "$src" ]; then
  curl -fsSL -o "$work/$tarball" \
    "https://cdn.kernel.org/pub/linux/kernel/v6.x/$tarball"
  echo "${KERNEL_SHA256}  $work/$tarball" | sha256sum -c -
  tar -C "$work" -xf "$work/$tarball"
fi

case "$arch" in
  amd64) karch=x86_64 ;;
  arm64) karch=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

make -C "$src" ARCH="$karch" tinyconfig
"$src/scripts/kconfig/merge_config.sh" -m -O "$src" \
  "$src/.config" "$root/build/kernel/cryptos.config"
make -C "$src" ARCH="$karch" olddefconfig

# Fail closed if a required hardening option got dropped during merge.
grep -q '^CONFIG_MODULES=n' "$src/.config" || { echo "CONFIG_MODULES must be n" >&2; exit 1; }

make -C "$src" ARCH="$karch" -j"$(nproc)"
cp "$src/arch/$karch/boot/bzImage" "$out/vmlinuz-$arch"
echo "kernel: wrote $out/vmlinuz-$arch"
