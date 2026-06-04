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

# A static cryptsetup is required by internal/storage/luks. Provide it via
# CRYPTSETUP_STATIC (path to a prebuilt static binary for $arch) until a
# from-source build is wired here.
: "${CRYPTSETUP_STATIC:?set CRYPTSETUP_STATIC to a static cryptsetup binary for $arch}"
install -m 0755 "$CRYPTSETUP_STATIC" "$tree/sbin/cryptsetup"

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
