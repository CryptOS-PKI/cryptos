# Self-hosted GitHub Actions runner on a Raspberry Pi

This guide stands up a self-hosted Actions runner on a home Raspberry Pi
so the **image build** (`task image` — kernel, SquashFS rootfs, UKI,
signing) runs on real arm64 Linux. The fast Go checks (`task ci`) stay on
GitHub-hosted runners; the QEMU + swtpm integration boot is run by hand on
a real host, not in CI.

> **Read the Security section first.** These repos are public, and a
> self-hosted runner that runs untrusted code is a path onto your home
> network. The workflow here is deliberately scoped to avoid that, but the
> repo setting matters too.

## 0. Security (do this, not optional)

A self-hosted runner executes whatever a triggered workflow tells it to,
on your hardware, on your network. For a **public** repo the danger is
fork pull requests running attacker-controlled code.

Mitigations, in order of importance:

1. **`ci-image.yml` never runs on `pull_request`.** It triggers only on push
   to `main`, tags, and manual `workflow_dispatch` — all of which require
   write access to the repo. Fork PRs can't trigger it. Keep it that way.
2. **Repo setting:** Settings → Actions → General →
   - "Fork pull request workflows from outside collaborators" → **Require
     approval for all external contributors** (or stricter).
   - Consider restricting which actions can run (allow `actions/*` +
     pinned third parties).
3. **Isolate the Pi:** put it on a guest VLAN with no access to the rest
   of your LAN; run the runner as a **non-root** user; ideally use an
   **ephemeral** runner (`--ephemeral`, re-registers per job) or run jobs
   in a throwaway container/VM.
4. **Scope the runner** to this one repo (or an org runner group limited
   to it), not the whole org.

If any of that is more than you want to maintain, make the repo private
for the image-build runner, or run the build on an ubuntu-hosted runner
with cross-compilation instead.

## 1. Hardware + OS

- **Raspberry Pi 4 or 5, 8 GB RAM recommended** (4 GB works but the kernel
  build will swap). Kernel compiles are CPU/RAM-heavy.
- **Boot from SSD over USB3**, not an SD card — the kernel build is very
  I/O heavy and SD cards are slow and wear out.
- **64-bit OS:** Raspberry Pi OS (64-bit) or Ubuntu Server 24.04 arm64.
  The runner and the build are arm64-native.

## 2. Build dependencies

On Debian/Ubuntu arm64:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential bc bison flex libssl-dev libelf-dev \
  squashfs-tools cpio xz-utils curl git jq \
  sbsigntool systemd-ukify cryptsetup-bin
# systemd-ukify provides `ukify`; on older releases ukify ships inside the
# `systemd` package instead. Verify: `ukify --version`.
```

Go, `go-task`, and `golangci-lint` are installed by the workflow itself
(via `actions/setup-go` + `go install`), so they don't need to be
preinstalled — but having Go on the box is handy for local runs.

`cryptsetup-bin` gives a dynamically linked cryptsetup; the image needs a
**static** one (`CRYPTSETUP_STATIC`). For a first pass you can point at the
dynamic binary to get the build moving, then swap in a static build.

## 3. Register the runner

In the repo: **Settings → Actions → Runners → New self-hosted runner →
Linux / ARM64**. GitHub shows exact download + token commands; they look
like:

```bash
mkdir -p ~/actions-runner && cd ~/actions-runner
curl -o runner.tar.gz -L https://github.com/actions/runner/releases/download/vX.Y.Z/actions-runner-linux-arm64-X.Y.Z.tar.gz
tar xzf runner.tar.gz
./config.sh --url https://github.com/CryptOS-PKI/cryptos \
  --token <REGISTRATION_TOKEN> \
  --labels self-hosted,linux,ARM64,cryptos-image \
  --name pi-builder --unattended
```

The labels matter: `ci-image.yml` targets `[self-hosted, linux, ARM64]`.

Run it as a service so it survives reboots:

```bash
sudo ./svc.sh install
sudo ./svc.sh start
sudo ./svc.sh status
```

(For an ephemeral runner instead, add `--ephemeral` to `config.sh` and
re-register per job from a wrapper — more secure, more setup.)

## 4. First build inputs

`ci-image.yml` (and `task image`) need a few inputs the recipes don't ship:

- **`build/ci/versions.env` → `KERNEL_SHA256`** — set to the verified
  SHA-256 of the pinned `linux-<KERNEL_VERSION>.tar.xz` from kernel.org.
  The build refuses to run with the placeholder.
- **`CRYPTSETUP_STATIC`** — path to a static `cryptsetup` for arm64.
- **`MACHINE_CONFIG`** — the `machine.yaml` to bake into the rootfs (CI
  generates a throwaway one with an ephemeral bootstrap admin cert).
- **`SB_KEY` / `SB_CERT`** — Secure Boot signing key + cert. CI generates
  an **ephemeral** key per run; the production hardware-token key is only
  used in tagged-release runs with manual approval.

Until `KERNEL_SHA256` is filled, `ci-image.yml` will fail fast at the kernel
step — that's expected; it's the first thing to resolve on the Pi.

## 5. Expectations

- A from-scratch kernel build on a Pi 4/5 is **tens of minutes**. The
  workflow caches the kernel source + `.config`-driven objects
  (`actions/cache`) so only the first run pays full price.
- arm64 is native here. Producing the **amd64** UKI from a Pi needs a
  cross toolchain (`gcc-x86-64-linux-gnu`, `ARCH=x86_64
  CROSS_COMPILE=...`) or binfmt/QEMU-user; start with arm64-native and add
  amd64 cross-build later.

## 6. Try it

1. Register the runner (steps 1-3) and confirm it shows **Idle** in
   Settings → Actions → Runners.
2. Fill `KERNEL_SHA256` and push to `main` (or run `ci-image.yml` via the
   **Run workflow** button — `workflow_dispatch`).
3. Watch the job in the Actions tab; iterate on the build recipes (they're
   drafts — this is exactly how we shake them out on real Linux).
4. For the QEMU boot, on your real host run `task image:debug` then
   `task qemu:run` (see `build/README.md`); that part stays off CI.
