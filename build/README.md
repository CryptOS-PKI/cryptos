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

## Toolchain

The build host needs the kernel build deps (`build-essential`, `bc`, `flex`,
`bison`, `libelf-dev`, `libssl-dev`, `xz-utils`), `squashfs-tools`
(`mksquashfs`), `cpio`, `sbsigntool` (`sbsign`), Docker (for the static
`cryptsetup`), and the UKI tooling: `systemd-ukify` + `systemd-boot-efi` (the
EFI stub). See `.github/workflows/ci-image.yml` for the exact apt list.

> **`ukify` needs the Python `pefile` module.** `systemd-ukify` does not depend
> on it, so `uki:assemble` fails with `ModuleNotFoundError: No module named
> 'pefile'` unless `pefile` is installed. On CI/system Python install the
> `python3-pefile` package. Note: `ukify` runs under `#!/usr/bin/env python3`,
> so on a host where a version manager (e.g. pyenv) shadows the system
> interpreter, `python3-pefile` (system) is invisible to it — install into the
> interpreter `ukify` actually resolves, e.g. `python3 -m pip install pefile`.

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
