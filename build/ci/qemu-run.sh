#!/usr/bin/env bash
# DRAFT — not yet executed. Validate on a Linux host before relying on it.
#
# Boot the debug UKI interactively in QEMU with a software TPM (swtpm) and
# OVMF firmware, forwarding the management port to the host. Intended for
# hands-on dev; the automated acceptance flow is the integration harness
# (a separate task / issue).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
arch="${1:-amd64}"
out="$root/build/out"
uki="$out/cryptos-$arch.uki.unsigned"   # debug image is unsigned
[ -f "$uki" ] || { echo "missing $uki (run: task image:debug)" >&2; exit 1; }

: "${OVMF_CODE:?set OVMF_CODE to the OVMF firmware code file}"
: "${OVMF_VARS:?set OVMF_VARS to a writable OVMF vars file (Secure Boot keys pre-enrolled)}"

# Software TPM 2.0.
tpmstate="$(mktemp -d)"
swtpm socket --tpm2 --tpmstate dir="$tpmstate" \
  --ctrl type=unixio,path="$tpmstate/swtpm-sock" &
swtpm_pid=$!
trap 'kill "$swtpm_pid" 2>/dev/null; rm -rf "$tpmstate"' EXIT

# State disk: a GPT image with a single partition named "cryptos-state" (what
# the bare-metal installer would lay down; that path is deferred). init resolves
# it by that GPT name via sysfs and LUKS-formats it on first boot. Attached as
# virtio-blk below so the guest sees it as /dev/vda with partition /dev/vda1.
statedisk="$tpmstate/state.img"
truncate -s 2G "$statedisk"
sgdisk --new=1:0:0 --change-name=1:cryptos-state --typecode=1:8300 "$statedisk" >/dev/null

# A UKI is a PE/EFI executable, not a bzImage — QEMU's -kernel uses the Linux
# boot protocol, so OVMF rejects a UKI passed that way ("Bad kernel image: Load
# error"). Present it the way firmware expects: on an EFI System Partition at the
# removable-media fallback path EFI/BOOT/BOOTX64.EFI, which OVMF auto-launches.
# QEMU's VVFAT (fat:rw:<dir>) serves the directory as a FAT ESP.
esp="$tpmstate/esp"
mkdir -p "$esp/EFI/BOOT"
cp "$uki" "$esp/EFI/BOOT/BOOTX64.EFI"

qemu-system-x86_64 \
  -machine q35,accel=kvm:tcg -m 2048 -nographic \
  -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,unit=1,file="$OVMF_VARS" \
  -chardev socket,id=chrtpm,path="$tpmstate/swtpm-sock" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  -drive format=raw,file="fat:rw:$esp" \
  -drive if=none,id=state,format=raw,file="$statedisk" \
  -device virtio-blk-pci,drive=state \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:4443-:443 \
  -device virtio-net-pci,netdev=n0
