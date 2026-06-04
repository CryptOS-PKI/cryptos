#!/usr/bin/env bash
# DRAFT — not yet executed. Validate on a Linux build host before relying on it.
#
# Secure Boot-sign the assembled UKI with sbsign. Output:
# build/out/cryptos-<arch>.uki.
#
# Two trust anchors, never crossed:
#   - CI smoke tests use a per-run ephemeral key (generated, used, discarded).
#   - Tagged releases use a hardware-token key in a manual-approval workflow.
# This script just takes whatever key/cert it is handed via SB_KEY/SB_CERT;
# the workflow decides which anchor that is.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

arch="${1:-amd64}"
out="$root/build/out"
in="$out/cryptos-$arch.uki.unsigned"
[ -f "$in" ] || { echo "missing $in (run uki assemble first)" >&2; exit 1; }

: "${SB_KEY:?set SB_KEY to the Secure Boot signing key (PEM or PKCS#11 URI)}"
: "${SB_CERT:?set SB_CERT to the Secure Boot signing certificate (PEM)}"

sbsign --key "$SB_KEY" --cert "$SB_CERT" \
  --output "$out/cryptos-$arch.uki" "$in"
sbverify --cert "$SB_CERT" "$out/cryptos-$arch.uki"
echo "uki: signed $out/cryptos-$arch.uki"
