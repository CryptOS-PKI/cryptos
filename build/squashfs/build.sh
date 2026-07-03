#!/usr/bin/env bash
# DRAFT — not yet executed. Validate on a Linux build host before relying on it.
#
# Assemble the read-only root filesystem tree and pack it as a SquashFS.
# The tree holds the Go PID 1 (/init), cryptosctl, a static cryptsetup,
# and the baked-in machine config slot. Output: build/out/rootfs-<arch>.squashfs.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=/dev/null
source "$root/build/ci/versions.env"

arch="${1:-amd64}"
out="$root/build/out"
tree="$root/build/.work/rootfs-$arch"
mkdir -p "$out"
rm -rf "$tree"

# Minimal FHS skeleton for a no-shell, no-login image.
mkdir -p "$tree"/{proc,sys,dev,run,tmp,sbin,etc/cryptos,var/lib/cryptos}

# Statically linked binaries (CGO_ENABLED=0). The init binary becomes /init.
GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
  -o "$tree/init" "$root/cmd/init"
GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
  -o "$tree/sbin/cryptosctl" "$root/cmd/cryptosctl"

# A static cryptsetup is required by internal/storage/luks. By default use
# the from-source musl-static build (build/cryptsetup/build.sh); override
# with CRYPTSETUP_STATIC to bake in a different binary.
CRYPTSETUP_STATIC="${CRYPTSETUP_STATIC:-$out/cryptsetup-$arch}"
[ -f "$CRYPTSETUP_STATIC" ] || {
  echo "missing static cryptsetup ($CRYPTSETUP_STATIC); run 'task cryptsetup:build' first" >&2
  exit 1
}
install -m 0755 "$CRYPTSETUP_STATIC" "$tree/sbin/cryptsetup"

# A static mkfs.ext4 is required by internal/init to format the unlocked state
# volume on first boot. mke2fs makes ext4 when invoked as mkfs.ext4 (it keys off
# argv[0]). By default use the from-source glibc-static build
# (build/e2fsprogs/build.sh); override with MKFS_EXT4_STATIC.
MKFS_EXT4_STATIC="${MKFS_EXT4_STATIC:-$out/mke2fs-$arch}"
[ -f "$MKFS_EXT4_STATIC" ] || {
  echo "missing static mke2fs ($MKFS_EXT4_STATIC); run 'task e2fsprogs:build' first" >&2
  exit 1
}
install -m 0755 "$MKFS_EXT4_STATIC" "$tree/sbin/mkfs.ext4"

# A static sgdisk is required by internal/install to lay out the GPT on the
# target disk. By default use the from-source glibc-static build
# (build/gptfdisk/build.sh); override with SGDISK_STATIC.
SGDISK_STATIC="${SGDISK_STATIC:-$out/sgdisk-$arch}"
[ -f "$SGDISK_STATIC" ] || {
  echo "missing static sgdisk ($SGDISK_STATIC); run 'task sgdisk:build' first" >&2
  exit 1
}
install -m 0755 "$SGDISK_STATIC" "$tree/sbin/sgdisk"

# A static mkfs.vfat is required by internal/install to format the EFI System
# Partition. By default use the from-source glibc-static build
# (build/dosfstools/build.sh); override with MKFS_VFAT_STATIC.
MKFS_VFAT_STATIC="${MKFS_VFAT_STATIC:-$out/mkfs.vfat-$arch}"
[ -f "$MKFS_VFAT_STATIC" ] || {
  echo "missing static mkfs.vfat ($MKFS_VFAT_STATIC); run 'task mkfsvfat:build' first" >&2
  exit 1
}
install -m 0755 "$MKFS_VFAT_STATIC" "$tree/sbin/mkfs.vfat"

# The machine config is baked in (resolved delivery model). MACHINE_CONFIG
# points at the per-node machine.yaml; CI generates one inline.
: "${MACHINE_CONFIG:?set MACHINE_CONFIG to the machine.yaml to bake in}"
install -m 0400 "$MACHINE_CONFIG" "$tree/etc/cryptos/machine.yaml"

# Reproducible squashfs: pinned mkfs time, no xattrs noise, xz compression.
SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct)"
mksquashfs "$tree" "$out/rootfs-$arch.squashfs" \
  -comp xz -noappend -all-root -no-progress \
  -mkfs-time "$SOURCE_DATE_EPOCH" -all-time "$SOURCE_DATE_EPOCH"
echo "rootfs: wrote $out/rootfs-$arch.squashfs"
