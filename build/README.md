# Image build pipeline

> **Status: DRAFT.** These recipes are written but **not yet executed** —
> they need a Linux build host (kernel toolchain, `mksquashfs`, `ukify`,
> `sbsign`, `cpio`). Treat the shell scripts as reviewed skeletons, not
> validated builds. The version pins (`ci/versions.env`) and the kernel
> config (`kernel/cryptos.config`) are the reviewable, load-bearing parts.

## Pipeline

```
versions.env ──> kernel/build.sh    ─> out/vmlinuz-<arch>
                 cryptsetup/build.sh ─> out/cryptsetup-<arch>      (static, musl)
                 squashfs/build.sh   ─> out/rootfs-<arch>.squashfs  (+ rootfs tree)
                 uki/assemble.sh     ─> out/cryptos-<arch>.uki.unsigned
                 uki/sign.sh         ─> out/cryptos-<arch>.uki      (Secure Boot signed)
```

Driven by the `Taskfile.yml` targets:

| Task | Does |
|---|---|
| `task kernel:build` | fetch + checksum + build the pinned hardened kernel |
| `task cryptsetup:build` | build the static `cryptsetup` from source (Docker + Alpine/musl) |
| `task rootfs:build` | assemble the rootfs tree (init, cryptosctl, cryptsetup, baked config) + pack SquashFS |
| `task uki:assemble` | build the unsigned UKI (kernel + initrd + cmdline) |
| `task uki:sign` | Secure Boot-sign the UKI |
| `task image` | the full prod chain end to end |
| `task image:debug` | a debug UKI (qemu-dev cmdline + serial console); never published |
| `task qemu:run` | boot the debug image in QEMU + swtpm interactively |

## Inputs the scripts expect

- `KERNEL_SHA256` filled + verified in `ci/versions.env`.
- `CRYPTSETUP_STATIC` — optional override; defaults to the from-source
  static `cryptsetup` produced by `task cryptsetup:build` (Docker required).
- `MACHINE_CONFIG` — the per-node `machine.yaml` baked into the rootfs.
- `SB_KEY` / `SB_CERT` — the Secure Boot signing key + cert (ephemeral in
  CI smoke tests; hardware-token key for tagged releases).

## Rootfs delivery

`uki/assemble.sh` defaults to `ROOTFS_MODE=squashfs` (the spec target): a tiny
shim initramfs — the `cryptos-switchroot` `/init` plus the SquashFS image —
loop-mounts the read-only SquashFS and `switch_root`s into it, so the real
PID 1 runs from an immutable, RAM-resident root. `ROOTFS_MODE=initramfs` is a
bring-up fallback that runs init directly from a writable cpio tree. The pivot
sequence is unit-tested; the boot itself is validated in QEMU on a real host.

## Open decisions to finalize during Linux validation

1. **arm64.** Scripts parameterize `arch`, but only amd64 is exercised first.

## Not covered here (separate issues)

- Bare-metal disk installer — GPT layout (ESP + `cryptos-state`) + UKI
  install to the ESP (`OpenStateVolume` only formats/unlocks an existing
  partition). Tracked separately.
- Secure Boot key **enrollment** into firmware for bare metal (this
  pipeline only *signs*). Tracked separately.
- The QEMU + swtpm integration harness (the Phase 1 acceptance gate).
