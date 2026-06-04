#!/usr/bin/env bash
# DRAFT — not yet executed. Validate on a Linux build host before relying on it.
#
# Assemble an unsigned Unified Kernel Image (kernel + initrd + cmdline)
# with ukify (systemd-stub). Output: build/out/cryptos-<arch>.uki.unsigned.
#
# Rootfs delivery is selected by ROOTFS_MODE:
#   squashfs  (default) — the spec target: a tiny shim initramfs (the
#               cryptos-switchroot /init plus the SquashFS image) that
#               loop-mounts the read-only SquashFS and switch_roots into it.
#   initramfs           — pack the rootfs tree directly as the initrd and run
#               the real init from it (initramfs-as-root). A fallback for
#               bring-up; the running root is then writable tmpfs, not the
#               immutable SquashFS.
# Boot validation of either path is done in QEMU on a real host.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=/dev/null
source "$root/build/ci/versions.env"

arch="${1:-amd64}"
profile="${2:-prod}"   # prod | qemu-dev
out="$root/build/out"
tree="$root/build/.work/rootfs-$arch"
[ -d "$tree" ] || { echo "run rootfs build first (missing $tree)" >&2; exit 1; }

# Kernel command line per profile. prod: lockdown, no console. qemu-dev:
# adds a serial console for the test harness. Each profile is measured into
# its own PCR-11 profile and they are not interchangeable.
case "$profile" in
  prod)     cmdline="quiet lockdown=confidentiality" ;;
  qemu-dev) cmdline="console=ttyS0 lockdown=confidentiality" ;;
  *) echo "unknown profile: $profile" >&2; exit 1 ;;
esac

SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct)"
export SOURCE_DATE_EPOCH

mode="${ROOTFS_MODE:-squashfs}"
initrd="$root/build/.work/initrd-$arch.cpio.gz"

case "$mode" in
  squashfs)
    sqfs="$out/rootfs-$arch.squashfs"
    [ -f "$sqfs" ] || { echo "run rootfs build first (missing $sqfs)" >&2; exit 1; }
    # Shim initramfs = the switch-root /init + the SquashFS image. The shim
    # loop-mounts the SquashFS read-only and pivots into it.
    shim="$root/build/.work/shim-$arch"
    rm -rf "$shim"; mkdir -p "$shim"
    GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o "$shim/init" "$root/cmd/cryptos-switchroot"
    cp "$sqfs" "$shim/rootfs.squashfs"
    ( cd "$shim" && find . -print0 | sort -z \
        | cpio --null --create --format=newc --owner=0:0 2>/dev/null \
        | gzip -n ) > "$initrd"
    ;;
  initramfs)
    # Pack the rootfs tree directly; the real init runs from it.
    ( cd "$tree" && find . -print0 | sort -z \
        | cpio --null --create --format=newc --owner=0:0 2>/dev/null \
        | gzip -n ) > "$initrd"
    ;;
  *) echo "unknown ROOTFS_MODE: $mode (want squashfs|initramfs)" >&2; exit 1 ;;
esac

ukify build \
  --linux="$out/vmlinuz-$arch" \
  --initrd="$initrd" \
  --cmdline="$cmdline" \
  --os-release="@$root/build/uki/os-release" \
  --output="$out/cryptos-$arch.uki.unsigned"
echo "uki: wrote $out/cryptos-$arch.uki.unsigned (profile=$profile, rootfs=$mode)"
