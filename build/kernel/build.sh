#!/usr/bin/env bash
# DRAFT — not yet executed. Validate on a Linux build host before relying on it.
#
# Fetch a pinned Linux kernel from the canonical stable git tag, merge the
# CryptOS config fragment onto the tiny base config, and build a reproducible
# bzImage. Output: build/out/vmlinuz-<arch>.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=/dev/null
source "$root/build/ci/versions.env"

arch="${1:-amd64}"
out="$root/build/out"
work="$root/build/.work/kernel"
mkdir -p "$out" "$work"

# Reproducibility: pin the build timestamp to the repo's HEAD commit.
SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct)"
export SOURCE_DATE_EPOCH KBUILD_BUILD_TIMESTAMP="@$SOURCE_DATE_EPOCH"
export KBUILD_BUILD_USER=cryptos KBUILD_BUILD_HOST=cryptos

# Source the kernel from the canonical stable git tag rather than a
# cdn.kernel.org tarball: superseded point releases are pruned from the CDN (so
# a pinned tarball URL 404s once a newer point release lands), but the git tag
# is permanent. Shallow-clone exactly the pinned tag. Integrity is anchored to
# the tag; commit-level pinning is a future hardening.
src="$work/linux-${KERNEL_VERSION}"
if [ ! -d "$src" ]; then
  git clone --depth 1 --branch "v${KERNEL_VERSION}" \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git "$src"
fi

case "$arch" in
  amd64) karch=x86_64 ;;
  arm64) karch=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

make -C "$src" ARCH="$karch" tinyconfig
"$src/scripts/kconfig/merge_config.sh" -m -O "$src" \
  "$src/.config" "$root/build/kernel/cryptos.config"
make -C "$src" ARCH="$karch" olddefconfig

# Fail closed if a required hardening option got dropped during merge.
# olddefconfig writes a disabled bool as "# CONFIG_X is not set", not "=n".
grep -q '^# CONFIG_MODULES is not set' "$src/.config" || { echo "CONFIG_MODULES must be disabled" >&2; exit 1; }

# Fail closed if any requested `=y` option was silently dropped during the merge
# (an unmet dependency in the tiny base makes olddefconfig discard it, which is
# how a non-bootable / de-hardened image can ship unnoticed). Every `CONFIG_x=y`
# in cryptos.config must survive into the final .config.
dropped=""
while IFS= read -r opt; do
  key="${opt%%=*}"
  grep -q "^${key}=y" "$src/.config" || dropped="$dropped $key"
done < <(grep -E '^CONFIG_[A-Z0-9_]+=y' "$root/build/kernel/cryptos.config")
if [ -n "$dropped" ]; then
  echo "kernel: requested options dropped from .config (unmet deps in the base?):$dropped" >&2
  exit 1
fi

make -C "$src" ARCH="$karch" -j"$(nproc)"
cp "$src/arch/$karch/boot/bzImage" "$out/vmlinuz-$arch"
echo "kernel: wrote $out/vmlinuz-$arch"
