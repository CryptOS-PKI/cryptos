# Image build pipeline

> **Status: DRAFT.** These recipes are written but **not yet executed** —
> they need a Linux build host (kernel toolchain, `mksquashfs`, `ukify`,
> `sbsign`, `cpio`). Treat the shell scripts as reviewed skeletons, not
> validated builds. The version pins (`ci/versions.env`) and the kernel
> config (`kernel/cryptos.config`) are the reviewable, load-bearing parts.

## Pipeline

```
versions.env ──> kernel/build.sh    ─> out/vmlinuz-<arch>
                 squashfs/build.sh   ─> out/rootfs-<arch>.squashfs  (+ rootfs tree)
                 uki/assemble.sh     ─> out/cryptos-<arch>.uki.unsigned
                 uki/sign.sh         ─> out/cryptos-<arch>.uki      (Secure Boot signed)
```

Driven by the `Taskfile.yml` targets:

| Task | Does |
|---|---|
| `task kernel:build` | fetch + checksum + build the pinned hardened kernel |
| `task rootfs:build` | assemble the rootfs tree (init, cryptosctl, cryptsetup, baked config) + pack SquashFS |
| `task uki:assemble` | build the unsigned UKI (kernel + initrd + cmdline) |
| `task uki:sign` | Secure Boot-sign the UKI |
| `task image` | the full prod chain end to end |
| `task image:debug` | a debug UKI (qemu-dev cmdline + serial console); never published |
| `task qemu:run` | boot the debug image in QEMU + swtpm interactively |

## Inputs the scripts expect

- `KERNEL_SHA256` filled + verified in `ci/versions.env`.
- `CRYPTSETUP_STATIC` — path to a static `cryptsetup` for the target arch.
- `MACHINE_CONFIG` — the per-node `machine.yaml` baked into the rootfs.
- `SB_KEY` / `SB_CERT` — the Secure Boot signing key + cert (ephemeral in
  CI smoke tests; hardware-token key for tagged releases).

## Open decisions to finalize during Linux validation

1. **Rootfs delivery.** The spec target is a read-only **SquashFS** root
   (`squashfs/build.sh` produces it). The draft `uki/assemble.sh` instead
   packs the rootfs tree as a **cpio initramfs** and runs init from there
   (initramfs-as-root) — the simplest first-bootable path. Wiring the
   SquashFS as the real root needs a small switch-root shim initramfs;
   layer it on once the initramfs-as-root path boots.
2. **From-source `cryptsetup`.** Currently injected via `CRYPTSETUP_STATIC`;
   a pinned from-source static build should replace that.
3. **arm64.** Scripts parameterize `arch`, but only amd64 is exercised first.

## Not covered here (separate issues)

- Bare-metal disk installer — GPT layout (ESP + `cryptos-state`) + UKI
  install to the ESP (`OpenStateVolume` only formats/unlocks an existing
  partition). Tracked separately.
- Secure Boot key **enrollment** into firmware for bare metal (this
  pipeline only *signs*). Tracked separately.
- The QEMU + swtpm integration harness (the Phase 1 acceptance gate).
