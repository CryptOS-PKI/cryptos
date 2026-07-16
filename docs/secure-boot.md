# Secure Boot key enrollment (bare metal)

CryptOS ships a UKI that is Secure Boot–signed. For a machine's firmware to
actually load it, the firmware has to trust the certificate the UKI was signed
with. In QEMU + OVMF (the integration path) the keys are pre-loaded into the
OVMF variable store, so this is automatic. On real hardware you have to enroll
the signing certificate into platform firmware yourself — this document covers
how.

> Scope: bare metal only. The QEMU path needs none of this.

## Two trust anchors, never crossed

| | Where the key lives | Lifetime | Used for |
|---|---|---|---|
| **Ephemeral** | Generated in the CI job, used, discarded | One workflow run | Smoke-test images; never enrolled in a real machine |
| **Release** | Hardware token (or an HSM-backed signer), behind manual approval | ~10 years | Images you actually boot on hardware |

The build never mixes them: `build/uki/sign.sh` signs with whatever
`SB_KEY` / `SB_CERT` it is handed, and the workflow decides which anchor that
is. Only the release certificate is ever enrolled into a machine's firmware.

## Generating the signing material

`cryptos-sbkey` produces an RSA key and a self-signed certificate. By
default the key is RSA-2048:

```bash
task build               # produces bin/cryptos-sbkey
bin/cryptos-sbkey --out-dir ./sbkeys --cn "CryptOS Secure Boot (release)"
```

It writes three files:

| File | Encoding | Consumed by |
|---|---|---|
| `sb.key` | RSA private key, PKCS#8 PEM (mode 0600) | `sbsign --key` |
| `sb.crt` | certificate, PEM | `sbsign --cert`, `sbverify` |
| `sb.der` | certificate, raw DER | firmware **db** enrollment |

Then sign the UKI:

```bash
SB_KEY=./sbkeys/sb.key SB_CERT=./sbkeys/sb.crt task uki:sign
```

### Why RSA-2048 and not ECDSA

CryptOS defaults to ECDSA everywhere else, but the UEFI specification mandates
RSA-2048 PKCS#1 v1.5 support for image authentication, while ECDSA in `db` is
implemented inconsistently across firmware vendors. Secure Boot is the one
place we pick RSA for interoperability. The key never touches the PKI cert
path — it signs a boot image, nothing else.

### Choosing a larger key: `--bits 4096`

`--bits` accepts `2048` (the default) or `4096`; any other value is rejected.
If you know the target firmware supports RSA-4096 in `db` — this is a
long-lived (~10-year) certificate, so a larger key can be worth it — opt in
explicitly:

```bash
bin/cryptos-sbkey --out-dir ./sbkeys --cn "CryptOS Secure Boot (release)" --bits 4096
```

`cryptos-sbkey` prints a warning to stderr whenever `--bits` is not 2048:

```
cryptos-sbkey: warning: RSA-4096 Secure Boot keys load only on firmware that supports RSA-4096 in db; RSA-2048 is the UEFI-mandated baseline. If the target firmware rejects this key, the signed image will not boot.
```

Not every firmware implementation accepts RSA-4096 in `db`; if the target
firmware does not, the signed image will fail Secure Boot verification and
will not boot. Confirm firmware support before enrolling a 4096-bit
certificate on hardware you cannot easily re-flash, and prefer the 2048
default unless you have a specific reason to size up.

## The UEFI key hierarchy

Secure Boot has three variable stores, in a chain of authority:

- **PK** (Platform Key) — one key; owns the platform. Signs updates to KEK.
- **KEK** (Key Exchange Keys) — sign updates to db/dbx.
- **db** (signature database) — the certificates the firmware will load images
  signed by. **This is where the CryptOS signing cert goes.**
- **dbx** — the revocation list (signatures the firmware refuses).

You do **not** need to replace PK/KEK. The common, lowest-friction path is to
keep the firmware's existing Setup/Owner keys and just **add the CryptOS cert
to db**. Replacing the whole hierarchy with your own PK/KEK/db is supported by
the same tools if your security policy requires sole ownership of the platform.

## Enrolling `sb.der` into db

Pick whichever matches the machine.

### Option A — firmware setup UI (no extra tooling)

1. Copy `sb.der` to a FAT32 USB stick.
2. Reboot into firmware setup → Security → Secure Boot.
3. Put Secure Boot in **Setup Mode** / **Custom Mode** (vendor wording varies).
4. Choose **Enroll key / Add to db / Append signature** and select `sb.der`
   from the stick.
5. Save, return Secure Boot to **User Mode** / **Enabled**, reboot.

Most enterprise firmware accepts a raw DER (`.der` / `.cer`) here directly.

### Option B — `sbctl` (running Linux on the target)

`sbctl` manages a key set and enrollment from the OS:

```bash
sbctl status                                  # check Setup Mode
sbctl import-keys --db-cert ./sbkeys/sb.der   # add our cert to db
sbctl enroll-keys --append                    # --append keeps firmware/MS keys
```

`--append` adds the CryptOS cert alongside the existing db rather than
replacing it. Drop `--append` only if you intend to own the platform keys.

### Option C — `efitools` (scripted / air-gapped)

`efitools` builds the signed EFI signature-list update that firmware in Setup
Mode will accept:

```bash
# Wrap the DER cert in an EFI signature list, then sign it for db with KEK.
cert-to-efi-sig-list -g "$(uuidgen)" sb.der sb.esl
sign-efi-sig-list -k KEK.key -c KEK.crt db sb.esl sb.auth
# Apply sb.auth via the firmware's "update db" path or efi-updatevar.
```

Use this when you control PK/KEK and need a reproducible, signable artifact
(e.g. an air-gapped Root build host).

## Verifying

After enrollment, with Secure Boot enabled:

- `sbverify --cert ./sbkeys/sb.crt build/out/cryptos-amd64.uki` confirms the
  image carries a signature from this cert (run on the build host).
- The machine boots the UKI with Secure Boot **on**. If the firmware rejects
  it, the cert is not in db (or the image was signed with a different key).
- `sbctl status` / the firmware UI lists the CryptOS certificate in db.

## Rotation

Rotating the release key means re-enrolling the new cert in **every** machine's
firmware — there is no remote db update path in CryptOS. Hence the long default
validity. Plan rotation as a fleet-wide, physically-attended operation, and add
the retired cert to **dbx** if it was ever exposed.
