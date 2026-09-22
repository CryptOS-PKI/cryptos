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

# Detached release signature, for in-place upgrades over the API (#208).
#
# This does not duplicate the Authenticode signature above and does not replace
# it: the firmware remains the only authority on whether an image may boot. It
# answers an earlier question that the firmware is in no position to answer --
# may these bytes be written to a running node's ESP at all. Without it an
# authorized StageImage call could park an unbootable image, the firmware would
# refuse it, and recovering the node would take a site visit.
#
# The node cannot check Authenticode itself: sbverify is a build-host tool and
# is not in the rootfs, and a hand-rolled PE signature parser in a CA's trusted
# path is a poor trade against PKCS#1 v1.5 over a SHA-256 digest.
#
# Signed over the *signed* UKI, because those are the bytes that get written.
# Same key and certificate as above, so there is one release anchor; the node
# verifies against the copy of SB_CERT stamped into it at build time
# (internal/release, see build/squashfs/build.sh).
sig="$out/cryptos-$arch.uki.sig"
case "$SB_KEY" in
  pkcs11:*) sign_key_args=(-engine pkcs11 -keyform engine -sign "$SB_KEY") ;;
  *)        sign_key_args=(-sign "$SB_KEY") ;;
esac
openssl dgst -sha256 "${sign_key_args[@]}" -out "$sig" "$out/cryptos-$arch.uki"

# Verify with the certificate rather than the key, so a mismatched SB_KEY and
# SB_CERT fail here on the build host instead of on a node mid-upgrade.
openssl x509 -in "$SB_CERT" -pubkey -noout > "$out/.release-pub-$arch.pem"
openssl dgst -sha256 -verify "$out/.release-pub-$arch.pem" \
  -signature "$sig" "$out/cryptos-$arch.uki"
rm -f "$out/.release-pub-$arch.pem"
echo "uki: release signature $sig"
