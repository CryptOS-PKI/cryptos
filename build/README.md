# Image build pipeline

> **Status: DRAFT.** These recipes are written but **not yet executed** —
> they need a Linux build host (kernel toolchain, `mksquashfs`, `ukify`,
> `sbsign`, `cpio`). Treat the shell scripts as reviewed skeletons, not
> validated builds. The version pins (`ci/versions.env`) and the kernel
> config (`kernel/cryptos.config`) are the reviewable, load-bearing parts.

## Pipeline

```
versions.env ──> kernel/build.sh      ─> out/vmlinuz-<arch>
                 cryptsetup/build.sh   ─> out/cryptsetup-<arch>      (static, musl)
                 e2fsprogs/build.sh    ─> out/mke2fs-<arch>           (static, glibc)
                 gptfdisk/build.sh     ─> out/sgdisk-<arch>           (static, glibc)
                 dosfstools/build.sh   ─> out/mkfs.vfat-<arch>        (static, glibc)
                 squashfs/build.sh     ─> out/rootfs-<arch>.squashfs  (+ rootfs tree)
                 uki/assemble.sh       ─> out/cryptos-<arch>.uki.unsigned
                 uki/sign.sh           ─> out/cryptos-<arch>.uki      (Secure Boot signed)
```

Driven by the `Taskfile.yml` targets:

| Task | Does |
|---|---|
| `task kernel:build` | fetch + checksum + build the pinned hardened kernel |
| `task cryptsetup:build` | build the static `cryptsetup` from source (Docker + Alpine/musl) |
| `task e2fsprogs:build` | build the static `mke2fs`/`mkfs.ext4` from source (Docker + Debian/glibc) |
| `task sgdisk:build` | build the static `sgdisk` (gptfdisk) from source (Docker + Debian/glibc) |
| `task mkfsvfat:build` | build the static `mkfs.vfat` (dosfstools) from source (Docker + Debian/glibc) |
| `task rootfs:build` | assemble the rootfs tree (init, cryptosctl, static tools) + pack SquashFS |
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
- `MKFS_EXT4_STATIC` — optional override; defaults to the from-source
  static `mke2fs` produced by `task e2fsprogs:build` (Docker required).
- `SGDISK_STATIC` — optional override; defaults to the from-source
  static `sgdisk` produced by `task sgdisk:build` (Docker required).
- `MKFS_VFAT_STATIC` — optional override; defaults to the from-source
  static `mkfs.vfat` produced by `task mkfsvfat:build` (Docker required).
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

## Machine config delivery

The image is **config-free**: the rootfs carries no `machine.yaml`. Machine
config reaches a node exclusively via the install path:

1. The operator boots the node from the CryptOS UKI into maintenance mode (no
   state partition → init serves the maintenance API).
2. `cryptosctl config apply -f machine.yaml` sends the config to the maintenance
   node, which partitions the target disk, writes the UKI to the ESP, and stages
   the config at `EFI/cryptos/machine.yaml` on that ESP before rebooting.
3. On the first boot of the installed system, init reads the staged config,
   persists it to the encrypted state partition, and deletes the stage file.
4. On every subsequent boot the state-partition copy is the sole source of truth.

## Maintenance install: operator workflow

When a bare-metal node boots the CryptOS UKI for the first time it has no
state partition, so init enters maintenance mode and listens on a temporary
gRPC endpoint (default port 443) with a self-signed server certificate and
no client authentication. The operator sends the machine config from a
workstation on the same network:

```sh
cryptosctl \
  --insecure \
  --endpoint <maintenance-node-ip>:443 \
  --server-name localhost \
  config apply -f machine.yaml
```

`machine.yaml` must include an `install.disk` field naming the target block
device (for example `/dev/sda` or `/dev/nvme0n1`). The maintenance node reads
that field from the `ApplyConfig` RPC, partitions the disk, writes the UKI to
the ESP, copies the config to the state partition, and reboots into the
installed system. A successful apply prints:

```
applied: generation=1 requires_reboot=true digest=<sha256>
```

The `--insecure` flag disables server-certificate verification and sends no
client identity. It must only be used against a maintenance endpoint; running
it against an established node's mTLS port would succeed only if the server
also accepts unauthenticated clients, which it does not.

Security note: the maintenance API accepts unauthenticated clients by design
(the Talos maintenance model). In this mode `config apply` erases the target
disk and installs a config the caller supplies, then reboots into that
configuration. Anyone who can reach the maintenance node on port 443 before the
operator can therefore take over the node. Only expose a maintenance node on a
trusted, isolated provisioning network, and complete the install before moving
it onto a general network.

## Not covered here (separate issues)

- Secure Boot key **enrollment** into firmware for bare metal (this
  pipeline only *signs*). Tracked separately.
- The QEMU + swtpm integration harness (the Phase 1 acceptance gate).
