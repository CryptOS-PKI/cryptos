#!/usr/bin/env bash
# Build the image the full-image suite boots (test/image/run.sh): the same
# kernel, static tools and rootfs as `task image:debug`, unsigned and with no
# upgrade anchor, except that /init is built with Go coverage instrumentation
# (-cover and the e2ecover tag, cmd/init/coverflush_e2ecover_linux.go). The
# kernel command line is the qemu-dev profile, so the boot log and the console
# are on the serial line the suite reads and types into.
#
# For the upgrade step it also stamps a per-build upgrade anchor (a throwaway
# RSA key made here and discarded, like ci-image.yml's smoke build) and builds
# a second image with a different version string, both with detached
# signatures, so a node booted from the first can be upgraded to the second.
#
# This build is for the suite only. Release and CI images never set -cover or
# the e2ecover tag. Output in build/out: cryptos-amd64-e2e.uki and
# cryptos-amd64-e2e-next.uki, each with a .sig.
#
# Linux only. Needs the image toolchain (build/README.md) and docker for the
# static tools, which are reused when build/out already holds them.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
arch=amd64
out="$root/build/out"
uki="$out/cryptos-$arch-e2e.uki"

log() { printf '[e2e:image build] %s\n' "$*" >&2; }

[ "$(uname -s)" = "Linux" ] || { log "SKIP: the image builds on a Linux host; this is $(uname -s)"; exit 0; }

cd "$root"
started=$SECONDS

log "kernel (reuses build/.work/kernel when it is there)"
PLATFORM='' bash build/kernel/build.sh "$arch"

for tool in cryptsetup:cryptsetup e2fsprogs:mke2fs gptfdisk:sgdisk dosfstools:mkfs.vfat; do
  dir="${tool%%:*}" bin="${tool##*:}"
  if [ -x "$out/$bin-$arch" ]; then
    log "reusing $out/$bin-$arch"
  else
    log "building $bin"
    bash "build/$dir/build.sh" "$arch"
  fi
done

anchor="$root/build/.work/e2e-anchor"
rm -rf "$anchor"
mkdir -p "$anchor"
trap 'rm -rf "$anchor"' EXIT
log "throwaway upgrade anchor"
go run ./cmd/cryptos-sbkey --out-dir "$anchor" --cn "CryptOS full-image suite (throwaway)" --days 2 >/dev/null

version="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
build_one() {
  local name="$1" ver="$2"
  log "rootfs $ver with a coverage-instrumented init"
  CRYPTOS_VERSION="$ver" SB_CERT="$anchor/sb.crt" STATEKEY=tpm \
    GOFLAGS="-cover -covermode=atomic -coverpkg=github.com/CryptOS-PKI/cryptos-node/... -tags=e2ecover" \
    bash build/squashfs/build.sh "$arch"
  log "UKI $name (qemu-dev command line)"
  CRYPTOS_VERSION="$ver" bash build/uki/assemble.sh "$arch" qemu-dev
  cp "$out/cryptos-$arch.uki.unsigned" "$out/$name"
  openssl dgst -sha256 -sign "$anchor/sb.key" -out "$out/$name.sig" "$out/$name"
}
build_one "cryptos-$arch-e2e.uki" "$version"
build_one "cryptos-$arch-e2e-next.uki" "$version-next"
log "wrote $uki and its successor in $((SECONDS - started))s"
