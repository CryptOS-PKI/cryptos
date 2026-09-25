#!/usr/bin/env bash
# Wrap a UKI into a UEFI-only bootable ISO. The ISO carries a FAT EFI
# System Partition image whose EFI/BOOT/BOOTX64.EFI is the UKI; xorriso records
# it as an El Torito EFI boot image (no legacy BIOS entry). Output:
# build/out/cryptos-<arch>-<platform>[-nodeid][-unsigned].iso. Requires xorriso,
# mtools, dosfstools.
#
# Input UKI:
#   default     the signed build/out/cryptos-<arch>.uki (task image)
#   UNSIGNED=1  the unsigned build/out/cryptos-<arch>.uki.unsigned
#               (task image:unsigned); the ISO name gains -unsigned
#   UKI=<path>  any UKI; treated as unsigned (and suffixed -unsigned) when the
#               path ends in .unsigned or UNSIGNED=1 is also set
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

arch="${1:-amd64}"
platform="${PLATFORM:-vmware}"
# STATEKEY suffixes nodeid variants so the TPM-less image is unmistakable.
statekey="${STATEKEY:-tpm}"
suffix=""
[ "$statekey" = "nodeid" ] && suffix="-nodeid"
out="$root/build/out"
case "${UNSIGNED:-}" in
  1|true|yes) unsigned=1 ;;
  ''|0|false|no) unsigned=0 ;;
  *) echo "iso: UNSIGNED=$UNSIGNED (want 1 or unset)" >&2; exit 1 ;;
esac
if [ -n "${UKI:-}" ]; then
  uki="$UKI"
  case "$uki" in *.unsigned) unsigned=1 ;; esac
  [ -f "$uki" ] || { echo "iso: missing UKI ($uki)" >&2; exit 1; }
elif [ "$unsigned" = 1 ]; then
  uki="$out/cryptos-$arch.uki.unsigned"
  [ -f "$uki" ] || { echo "iso: missing unsigned UKI ($uki); run 'task image:unsigned' first" >&2; exit 1; }
else
  uki="$out/cryptos-$arch.uki"
  [ -f "$uki" ] || { echo "iso: missing signed UKI ($uki); run 'task image' first" >&2; exit 1; }
fi
# An unsigned image is named as such so it is never mistaken for a signed one.
[ "$unsigned" = 1 ] && suffix="$suffix-unsigned"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 1. FAT ESP image sized to the UKI + slack, with EFI/BOOT/BOOTX64.EFI = UKI.
esp="$work/esp.img"
uki_kib=$(( ( $(stat -c%s "$uki") / 1024 ) + 2048 ))   # UKI size + 2 MiB slack
truncate -s "${uki_kib}K" "$esp"
mkfs.vfat -n CRYPTOS "$esp" >/dev/null
mmd -i "$esp" ::EFI ::EFI/BOOT
mcopy -i "$esp" "$uki" ::EFI/BOOT/BOOTX64.EFI

# 2. ISO with the ESP as an El Torito EFI boot image (UEFI only).
#    A plain copy of the UKI is also placed at the ISO root so that
#    LocateBootUKI can find it when the system is booted from this CD/ISO
#    (no GPT EFI partition exists on a CD; the UKI at /cryptos.uki is the
#    iso9660-fallback path used by internal/init/bootmedia_linux.go).
isodir="$work/iso"
mkdir -p "$isodir"
cp "$esp" "$isodir/efiboot.img"
cp "$uki" "$isodir/cryptos.uki"
iso="$out/cryptos-$arch-$platform$suffix.iso"
xorriso -as mkisofs \
  -V "CRYPTOS_${platform}" \
  -e efiboot.img -no-emul-boot \
  -isohybrid-gpt-basdat \
  -o "$iso" "$isodir" >/dev/null 2>&1
echo "iso: wrote $iso"
