#!/usr/bin/env bash
# Wrap the signed UKI into a UEFI-only bootable ISO. The ISO carries a FAT EFI
# System Partition image whose EFI/BOOT/BOOTX64.EFI is the UKI; xorriso records
# it as an El Torito EFI boot image (no legacy BIOS entry). Output:
# build/out/cryptos-<arch>-<platform>[-nodeid].iso. Requires xorriso, mtools,
# dosfstools.
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
uki="$out/cryptos-$arch.uki"
[ -f "$uki" ] || { echo "iso: missing signed UKI ($uki); run 'task image' first" >&2; exit 1; }

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
#    A plain copy of the signed UKI is also placed at the ISO root so that
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
