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

- `KERNEL_VERSION` in `ci/versions.env` — the kernel is shallow-cloned from the
  matching stable git tag `v${KERNEL_VERSION}` (no tarball checksum to maintain;
  the git tag is the source of truth).
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

## Image factory (platform ISOs)

`task iso PLATFORM=<platform>` builds a UEFI-bootable ISO for a target platform.
A platform is an additive kernel-config fragment in `build/kernel/profiles/`
(e.g. `vmware.config` = NVMe/AHCI/PVSCSI + e1000e/vmxnet3), merged onto the base
`cryptos.config` during `kernel:build`. The base is unchanged, so builds with no
`PLATFORM` behave as before.

    task iso PLATFORM=vmware        # -> build/out/cryptos-amd64-vmware.iso

Boot it in a UEFI VM (Secure Boot off for the dev/ephemeral-key image). Adding a
platform = adding a `profiles/<name>.config` fragment (keep `CONFIG_MODULES=n`;
every driver is built in). A hosted image-factory service is a future step.

## Machine config: baked seed vs. state-partition source

At runtime the node reads its machine config from the encrypted state partition
(`/var/lib/cryptos/config/machine.yaml`). The baked `/etc/cryptos/machine.yaml`
(written into the rootfs during `task rootfs:build`) is an **interim first-boot
seed only**: on first boot, if no config is present on the state partition, init
copies the baked file there and uses it. On every subsequent boot the
state-partition copy is the sole source of truth.

The baked seed is a build-time convenience. In the install sub-spec (Sub-spec 3)
the bare-metal installer will write the operator's config directly to the state
partition and **delete the baked seed** so it is never used again. Until that
sub-spec lands, the seed file must be kept up to date in `build/.work/ci/` and
regenerated any time the `machine.yaml` schema changes.

## Not covered here (separate issues)

- Bare-metal disk installer — GPT layout (ESP + `cryptos-state`) + UKI
  install to the ESP (`OpenStateVolume` only formats/unlocks an existing
  partition). Tracked separately.
- Secure Boot key **enrollment** into firmware for bare metal (this
  pipeline only *signs*). Tracked separately.
- The QEMU + swtpm integration harness (the Phase 1 acceptance gate).
