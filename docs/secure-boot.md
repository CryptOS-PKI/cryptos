# Secure Boot: build and sign with your own key

CryptOS does not ship a signing key, and it does not ask you to trust one. You
generate your own Secure Boot key, build the image with it, and enroll its
certificate on the machines you run. The same certificate becomes the node's
upgrade anchor, so the key that makes an image bootable is also the only key
that can replace it later.

> **Public release assets are unsigned, or a build recipe only.** Nothing the
> project publishes is signed by, carries, or trusts a key the project
> generated. A prebuilt image is for evaluation with Secure Boot off; it has no
> upgrade anchor, so a node installed from it cannot be upgraded in place. To
> run CryptOS for real, build it with your own key as described below.

## What the key is used for

`build/uki/sign.sh` takes the key and certificate you hand it through
`SB_KEY` / `SB_CERT` and uses them three ways. They have to be the same key
and certificate for all three:

| Use | Done by | Checked by |
|---|---|---|
| Authenticode signature on the UKI | `sbsign` in `build/uki/sign.sh` | the machine's firmware, against Secure Boot `db` |
| Detached signature, `cryptos-<arch>.uki.sig` | `openssl dgst -sha256 -sign` in `build/uki/sign.sh` | the running node, at `cryptosctl image stage` |
| Upgrade anchor stamped into `/init` | `build/squashfs/build.sh`, when `SB_CERT` is set | the node, when it verifies the next image's `.sig` |

The anchor is compiled into the init binary as
`internal/release.CertificateDER`. It is never read from configuration or
disk, so an administrator cannot swap it at runtime. See
[`image-upgrade.md`](image-upgrade.md) for the upgrade path it protects.

## 1. Generate your signing key and certificate

Do this on the machine that will hold the key, ideally an offline or
dedicated build host. Either of the two methods below produces the same three
files:

| File | Encoding | Consumed by |
|---|---|---|
| `sb.key` | RSA private key, PEM | `SB_KEY` (`sbsign --key`, `openssl dgst -sign`) |
| `sb.crt` | certificate, PEM | `SB_CERT` (`sbsign --cert`, `sbverify`, the stamped anchor) |
| `sb.der` | certificate, raw DER | firmware `db` enrollment |

### With openssl

```bash
umask 077
mkdir -p ~/cryptos-sb && cd ~/cryptos-sb

openssl req -new -x509 -newkey rsa:2048 -sha256 -noenc -days 3650 \
  -subj "/O=Example Org/CN=Example Org Secure Boot Signing 2026" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" \
  -addext "extendedKeyUsage=codeSigning" \
  -keyout sb.key -out sb.crt

openssl x509 -in sb.crt -outform DER -out sb.der
```

`-noenc` needs OpenSSL 3.0 or later; on 1.1.1 use `-nodes`. The key is written
unencrypted because `sbsign` and `sign.sh` read it non-interactively; protect it
with file permissions and storage instead (see "Key custody" below).

The extensions match what `cryptos-sbkey` writes: a self-signed certificate
with the code-signing extended key usage.

### With `cryptos-sbkey`

The repository's own generator does the same thing without openssl:

```bash
task build                     # produces bin/cryptos-sbkey
bin/cryptos-sbkey --out-dir ~/cryptos-sb --cn "Example Org Secure Boot Signing 2026"
```

Flags: `--out-dir`, `--cn`, `--days` (0, the default, means about 10 years),
`--bits` (`2048`, the default, or `4096`) and `--force` to overwrite existing
files. `sb.key` is written as PKCS#8 PEM with mode 0600.

### Key size

Use **RSA**. The anchor check refuses any other key type
(`internal/release`), and the detached signature is PKCS#1 v1.5 over SHA-256.

- **RSA-2048** is the UEFI-mandated baseline and loads on every firmware.
  Choose it unless you have a reason not to.
- **RSA-4096** works only on firmware that accepts RSA-4096 certificates in
  `db`. Swap `rsa:2048` for `rsa:4096` (or pass `--bits 4096`), and confirm
  the target firmware boots a test image before you depend on it. Firmware
  that rejects the key refuses to boot the image.

ECDSA is not an option here, even though CryptOS uses ECDSA for its CA keys:
support for ECDSA in `db` is inconsistent across firmware vendors, and the
anchor check expects RSA. This key signs boot images and nothing else.

### Validity

Give the certificate a long life: 10 years (`-days 3650`, or the
`cryptos-sbkey` default) is the recommended value. Expiry is not what limits
the key:

- The node does not enforce the anchor's validity dates. An expired anchor
  would otherwise block the one upgrade that could replace it.
- Most firmware, including EDK II/OVMF, has no trusted clock and does not
  enforce the dates on `db` certificates or image signatures either.

Changing the key is the expensive part (a fleet-wide `db` update and, without
the old key, a re-provision), so pick a lifetime that outlasts the nodes. Do
not copy the one-day validity the CI workflow uses; that key is thrown away
at the end of the run.

## 2. Decide: Secure Boot on or off

The detached signature and the stamped anchor work the same either way. What
changes is whether the firmware also checks the image at every boot.

| | Secure Boot **on**, your cert in `db` | Secure Boot **off** |
|---|---|---|
| Firmware refuses a tampered or foreign image at boot | yes | no |
| Upgrades must be signed by your key | yes | yes (stamped anchor) |
| Setup needed per machine | enroll `sb.der` in `db` | none |

Decide **before installing a node**. With the default `STATEKEY=tpm`, the state
partition key is sealed to PCR 7, which measures the Secure Boot state and the
`db` contents. Turning Secure Boot on or off, or changing `db`, after the node
is installed means the state key no longer unseals. The `STATEKEY=nodeid`
variant does not use the TPM and is not affected.

## 3. Enroll the certificate (Secure Boot on)

Skip this section if you run with Secure Boot off.

UEFI keeps three authority levels: **PK** (owns the platform and signs KEK
updates), **KEK** (signs `db`/`dbx` updates) and **db** (certificates the
firmware loads images from). `dbx` is the revocation list. You only need to
**add your certificate to db**; the existing PK, KEK and vendor `db` entries can
stay.

### VMware vSphere / ESXi

A VM with EFI firmware and Secure Boot enabled starts with the Microsoft
certificates in `db`, which do not cover your image. To add yours:

1. Power the VM off. Under **VM Options > Advanced > Configuration
   Parameters**, add `uefi.allowAuthBypass` = `TRUE`. This lets the VM's
   firmware setup accept a `db` entry that is not signed by a KEK.
2. Put `sb.der` on a volume the firmware can read, for example a small
   FAT-formatted virtual disk attached to the VM.
3. Power on into firmware setup (**VM Options > Boot Options > Force EFI setup**
   for the next boot), then go to **Secure Boot Configuration > DB Options >
   Enroll Signature**, pick `sb.der`, save and exit. Menu names differ slightly
   between ESXi releases.
4. Power off, remove `uefi.allowAuthBypass` and the key disk, and confirm
   **Secure Boot** is still enabled under **VM Options > Boot Options**.

Do this before the first boot of the CryptOS installer image, for the reason
given in step 2 above.

### Bare metal: firmware setup UI

1. Copy `sb.der` to a FAT32 USB stick.
2. Reboot into firmware setup, then Security > Secure Boot.
3. Put Secure Boot in **Setup Mode** or **Custom Mode** (vendor wording
   varies).
4. Choose **Enroll key / Add to db / Append signature** and select `sb.der`.
5. Save, return Secure Boot to **User Mode** / **Enabled**, reboot.

Most enterprise firmware accepts a raw DER (`.der` / `.cer`) file here.

### Bare metal: `sbctl` from a Linux live environment

CryptOS has no shell, so run this from a live Linux USB on the target, with the
firmware in Setup Mode:

```bash
sbctl status                                  # confirm Setup Mode
sbctl import-keys --db-cert ./sb.der          # add your cert to db
sbctl enroll-keys --append                    # --append keeps the existing keys
```

Drop `--append` only if you mean to replace the platform keys entirely.

### Scripted or air-gapped: `efitools`

If you own PK and KEK, build a signed `db` update:

```bash
cert-to-efi-sig-list -g "$(uuidgen)" sb.der sb.esl
sign-efi-sig-list -k KEK.key -c KEK.crt db sb.esl sb.auth
# Apply sb.auth through the firmware's "update db" path or efi-updatevar.
```

## 4. Build the image with your key

The image build runs on a Linux host; see [`build/README.md`](../build/README.md)
for the toolchain. Pass the key and certificate as environment variables, with
absolute paths:

```bash
export SB_KEY="$HOME/cryptos-sb/sb.key"
export SB_CERT="$HOME/cryptos-sb/sb.crt"

task image PLATFORM=vmware STATEKEY=nodeid
```

`task image` builds the kernel, the static tools and the rootfs, assembles the
UKI and signs it. To also wrap it in a bootable ISO, run `task iso` instead; it
runs `task image` first:

```bash
task iso PLATFORM=vmware STATEKEY=nodeid
```

Drop `STATEKEY=nodeid` (or set `STATEKEY=tpm`) for the TPM-backed image; see
[`build/README.md`](../build/README.md#statekey-the-tpm-less-nodeid-variant)
for when `nodeid` is appropriate.

**Keep `SB_CERT` set for the whole run.** The certificate is read twice, at
different steps:

- `rootfs:build` stamps it into `/init` as the upgrade anchor, if it is set.
- `uki:sign` signs the finished UKI with `SB_KEY` / `SB_CERT`, and fails if
  either is missing.

Running the steps separately with `SB_CERT` unset during `rootfs:build` gives
you a correctly signed image with **no** anchor: it boots, but a node installed
from it serves the image upgrade RPCs as `Unimplemented` and can only be
replaced by a reinstall. Exporting both variables once, as above, avoids that.

Outputs in `build/out/`:

| File | What it is |
|---|---|
| `cryptos-amd64.uki.unsigned` | the assembled UKI before signing |
| `cryptos-amd64.uki` | the signed UKI (anchor inside, Authenticode signature on it) |
| `cryptos-amd64.uki.sig` | the detached signature `image stage` checks |
| `cryptos-amd64-vmware-nodeid.iso` | the installer ISO (`task iso` only; `-nodeid` is omitted for `STATEKEY=tpm`) |

## 5. Verify the build

`sign.sh` already runs both checks below and fails the build if either fails.
Run them yourself before you ship an image to a node.

The Authenticode signature is from your certificate:

```bash
sbverify --cert "$SB_CERT" build/out/cryptos-amd64.uki
sbverify --list build/out/cryptos-amd64.uki     # shows the signer subject
```

The detached signature verifies against the certificate (not just the key):

```bash
openssl dgst -sha256 \
  -verify <(openssl x509 -in "$SB_CERT" -pubkey -noout) \
  -signature build/out/cryptos-amd64.uki.sig \
  build/out/cryptos-amd64.uki
```

The anchor was stamped. The rootfs tree stays under `build/.work/` after the
build, and the anchor is the certificate's DER in base64:

```bash
grep -q -a -F "$(openssl x509 -in "$SB_CERT" -outform DER | base64 -w0)" \
  build/.work/rootfs-amd64/init && echo "anchor stamped"
```

No output means the build carries no anchor.

On the target, with Secure Boot on, the machine should boot the image. If the
firmware refuses it, your certificate is not in `db`, or the image was signed
with a different key.

## 6. Upgrade with the same key

A node accepts a new image only if its `.sig` verifies against the anchor the
**running** image carries. Build every later version with the same `SB_KEY`
and `SB_CERT`, then stage and activate it as described in
[`image-upgrade.md`](image-upgrade.md):

```bash
cryptosctl --endpoint pki-root.example.org:443 image stage \
  --image build/out/cryptos-amd64.uki
```

The signature is read from `<image>.sig` unless `--signature` names another
file. An image signed by any other key is refused before anything is written
to the ESP.

## Key custody

The key is the only thing that can produce an image your nodes will accept.

- **Losing the key means re-provisioning to change anchors.** A node checks the
  next image against the anchor compiled into the image it is running, and
  nothing on the node can replace that anchor. Without the key you cannot sign
  an image it will stage, so the only way onto a new key is a reinstall, which
  reformats the state partition and destroys the CA key.
- **A leaked key lets anyone with admin access to a node install an image of
  their choosing**, and, with Secure Boot on, boot it on any machine that
  trusts your certificate. Treat it like a CA key.
- Keep it offline when you are not building: an encrypted backup in at least
  two places, and the working copy on a build host you control, readable only
  by the account that runs the build.
- Never commit it, never put it in CI secrets for a public repository, and do
  not reuse it for anything else.

## Rotation

CryptOS has no remote `db` update path. Moving to a new key means enrolling the
new certificate in every machine's firmware, then building the next image with
the new key and certificate so the new certificate becomes its anchor. The
running node still checks that image against the **old** anchor, so its
detached signature has to come from the old key. The build scripts do not do
this; replace the `.sig` by hand after the build:

```bash
openssl dgst -sha256 -sign /path/to/old/sb.key \
  -out build/out/cryptos-amd64.uki.sig build/out/cryptos-amd64.uki
```

Plan it as a physically attended, fleet-wide operation. On a `STATEKEY=tpm` node the `db` change alters PCR 7,
which the state key is sealed to, so on those nodes a rotation is a
re-provision today. If the old key was ever exposed, add its certificate to
`dbx`.
