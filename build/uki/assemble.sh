#!/usr/bin/env bash
# DRAFT — not yet executed. Validate on a Linux build host before relying on it.
#
# Assemble an unsigned Unified Kernel Image (kernel + initrd + cmdline)
# with ukify (systemd-stub). Output: build/out/cryptos-<arch>.uki.unsigned.
#
# OPEN DECISION (finalize on Linux): the rootfs delivery. This draft packs
# the rootfs tree as a cpio initramfs and uses it as the initrd
# (initramfs-as-root) — the simplest first-bootable path. The spec target
# is the read-only SquashFS root (built by build/squashfs/build.sh); wiring
# it as root needs a small switch-root shim initramfs, layered on once the
# initramfs-as-root path boots. See build/README.md.
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

# Build a reproducible cpio initramfs from the rootfs tree.
initrd="$root/build/.work/initrd-$arch.cpio.gz"
( cd "$tree" && find . -print0 | sort -z \
    | cpio --null --create --format=newc --owner=0:0 2>/dev/null \
    | gzip -n ) > "$initrd"

ukify build \
  --linux="$out/vmlinuz-$arch" \
  --initrd="$initrd" \
  --cmdline="$cmdline" \
  --os-release="@$root/build/uki/os-release" \
  --output="$out/cryptos-$arch.uki.unsigned"
echo "uki: wrote $out/cryptos-$arch.uki.unsigned (profile=$profile)"
