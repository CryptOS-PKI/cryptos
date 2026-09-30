# Upgrading a CryptOS node in place

A CryptOS node can take a new OS image without being re-provisioned. This
matters because re-provisioning reformats the state partition and destroys the
CA key with it: on an established node that means re-issuing every certificate
it ever signed and redistributing the trust anchor.

The disk layout is what makes the separation possible. The root filesystem is
an immutable SquashFS carried inside a Unified Kernel Image on the EFI System
Partition; identity -- CA key, etcd, issued history -- lives on a separate LUKS
partition. **An upgrade writes the ESP and reboots. The state partition is
never opened.** On a TPM node staging also adds a sealed copy of the state key
to the partition's LUKS header, so the new image can unlock it; see
"TPM-backed nodes" below.

## What you need

- The signed image, `cryptos-amd64.uki`, and its detached signature,
  `cryptos-amd64.uki.sig`, built with **your own** Secure Boot key.
  `build/uki/sign.sh` writes both, side by side. See
  [`secure-boot.md`](secure-boot.md) for generating the key and building with
  it.
- A node that was installed from an image built with that same key, so it
  carries the matching upgrade anchor.
- An admin credential for the node (the bootstrap admin client certificate).
- A maintenance window for step 3, and only step 3.

The node accepts an image only if its detached signature verifies against the
anchor certificate compiled into the image it is running, which is the
`SB_CERT` that image was built with. An image signed by any other key is
refused, including a CI build signed with that workflow's per-run ephemeral
key.

The public release assets carry no anchor. A node installed from one serves
the upgrade RPCs as `Unimplemented`, and moving it onto your own key is a
reinstall.

## The procedure

> [!WARNING]
> **This has not been exercised on production hardware yet.** The verification,
> slot management, RPC and CLI paths are covered by tests; the actual
> `mount`/reboot sequence on a real ESP is not something a test can cover.
> The same goes for the TPM reseal: it is tested against a TPM simulator and
> a model of the stub's measurement, not yet across a real reboot on a vTPM.
> Do the first run on a node you can reach physically.

> [!NOTE]
> `cryptosctl` runs on Linux and macOS today. A Windows build is coming.

The commands below use the default trust file, `~/.cryptos/trust.crt`. An
upgraded node already has its CA, so its management certificate is CA-signed:
put your root certificate in that file, and use an endpoint the certificate
names (the node's IP or a `pki.est.hostnames` entry), or add `--server-name`
with the IP. See [`management-trust.md`](management-trust.md). Activating an
image reboots the node, and the reboot gives the management certificate a new
key; a trust file holding the root keeps working, a pinned certificate does
not.

### 1. See where the node is

```sh
cryptosctl --endpoint pki-root.example:443 image status
```

> [!TIP]
> Expected output, for a node with nothing staged:
>
> ```text
> Running version:  v1.4.0
> Running image:    9f2c...
> Next boot image:  9f2c...
> Previous image:   (none retained)
> Reboot pending:   no
> ```
>
> `Running image` and `Next boot image` being equal means nothing is staged.

### 2. Stage the new image

> [!CAUTION]
> **A TPM node running an image from before the reseal cannot be upgraded
> in place.** Staging runs on the old image, and an old image does not reseal
> the key, so the new image would boot unable to unlock the state partition.
> Reinstall such a node instead. See "TPM-backed nodes" below.

```sh
cryptosctl --endpoint pki-root.example:443 image stage \
  --image build/out/cryptos-amd64.uki
```

The signature is read from `<image>.sig` unless `--signature` says otherwise.

This is the long step -- the image is a few hundred megabytes -- and it is
**not** disruptive. The node keeps serving throughout. It verifies the
signature before anything reaches the ESP, so a bad upload costs you the
transfer and nothing else.

Afterwards `image status` shows the two digests disagreeing and a reboot
pending. The node is still running the old image.

### 3. Activate, in the window

> [!WARNING]
> This reboots the node through the same orderly shutdown as
> `cryptosctl reboot`: every certificate operation that depends on it is
> unavailable until it comes back.

> [!WARNING]
> **An image that does not boot at all is not recoverable over the network.**
> The retained image is bootable, but selecting it means reaching the node,
> which is the thing that is down. Test a new image on a non-production node
> first.

```sh
cryptosctl --endpoint pki-root.example:443 image activate \
  --confirm "Example Root CA G1"
```

`--confirm` must be the node's CA common name, the same echo the reset verbs
require.

The node reads its CA common name when the call arrives, so a CA certificate
installed earlier in the same boot (a subordinate's `submit-subordinate-cert`,
or the ceremony) is accepted without a reboot first. A node that has no CA
certificate yet refuses with `FailedPrecondition` ("node has no CA identity
yet"); a wrong common name is refused with `PermissionDenied`.

> [!IMPORTANT]
> Confirm afterwards. The node came back with a new management certificate. A
> trust file holding your root still verifies it; if you pinned the certificate
> itself, the pin no longer matches and the next call fails with
> `x509: certificate signed by unknown authority`. Switch to the root, as
> described in [`management-trust.md`](management-trust.md):

```sh
cryptosctl --endpoint pki-root.example:443 image status
```

> [!TIP]
> `Running version` should be the new one, the two digests should agree again,
> and `Previous image` should now name the image you upgraded from.

### 4. If it went badly

```sh
cryptosctl --endpoint pki-root.example:443 image rollback
cryptosctl --endpoint pki-root.example:443 image activate \
  --confirm "Example Root CA G1"
```

A pinned management certificate goes stale after that reboot too. The previous
image is retained on the ESP and stays bootable, so a failed upgrade is
recoverable over the network. If the new image will not boot at all
-- rather than booting badly -- rollback is not reachable and the node needs
console access; see "Limits" below.

## Two signatures, and why

The firmware is the only authority on whether an image may boot. It verifies
the UKI's Authenticode signature against the Secure Boot db certificate
enrolled on that machine, and nothing in this procedure can weaken that. With
Secure Boot off the firmware checks nothing, and the detached signature below
is the only check an image passes.

The detached `.sig` answers a different and earlier question: **may these bytes
be written to a running node's ESP at all.** Without it, an admin-authorized
`image stage` could park an unbootable image, the firmware would refuse it at
the next boot, and recovering the node would take a site visit. It is the same
key and the same certificate as the Secure Boot signature, so an image is
attributable exactly when it is bootable.

The node cannot check Authenticode itself: `sbverify` is a build-host tool and
is not in the rootfs, and a PE signature parser in a CA's trusted path is a
poor trade against PKCS#1 v1.5 over a SHA-256 digest.

## Limits worth knowing before you start

- **An upgrade is not a re-key.** It replaces the OS. The CA key, the issued
  inventory, the node's identity and its configuration all survive untouched.
  Changing the CA key algorithm is still a re-provision.
- **Staging never reboots, and activating always does.** They are separate
  calls so the upload and the outage can happen at different times.
- **Activating with nothing staged is refused.** Rebooting a CA to boot the
  image it is already running is an outage with nothing to show for it.
- **A build without an anchor serves none of this.** An image built without
  `SB_CERT` set during `rootfs:build` (a development build, or a public
  release asset) has no anchor compiled in, and the image upgrade RPCs return
  `Unimplemented` ("image upgrade is not available on this server"). Such a
  node is upgraded by reinstalling it.
- **The anchor cannot change without the key.** The next image is checked
  against the anchor of the running one. Lose the key and the only way to a
  new anchor is a re-provision. See the key custody section of
  [`secure-boot.md`](secure-boot.md).
- **Only one previous image is retained.** Two upgrades in a row leave you able
  to roll back one.

## State-key mode

An upgrade never changes how the state partition is unlocked. The node reads
its state-key mode from the partition's LUKS2 header on every boot, so the mode
chosen at install (from `state_key.mode`, or the installing image's `STATEKEY`
default) carries over to any image, whatever `STATEKEY` the new image was built
with. A `nodeid` node upgraded to a `STATEKEY=tpm` image stays `nodeid`, and
the reverse.

## TPM-backed nodes

On a `tpm`-mode node the state-partition key is sealed to PCR 7 (Secure
Boot policy) and PCR 11. PCR 11 is where systemd-stub measures the UKI, so
every new image changes it, and a key sealed only to the running image would
not unseal after the upgrade.

`image stage` handles this before it writes the ESP. The node:

1. Predicts the PCR 11 value of the image it is running, from the image bytes
   on the ESP, and compares it with the value the TPM holds right now. If the
   two differ, the node cannot trust its prediction for any other image, and
   the stage is refused with `FailedPrecondition`. Nothing is written.
2. Predicts PCR 11 for the incoming image, and for the image that will be
   retained for rollback.
3. Seals a copy of the state key for each of those images, and for the running
   one, each to its own predicted PCR 11 and the current PCR 7. Each copy is a
   separate token in the LUKS header; the keyslot and the key do not change.
4. Removes every older copy, so the images that can unlock the state partition
   are exactly the running image and the images the ESP can boot.

On the next boot the node tries each copy until the one sealed for the booted
image opens the volume. A rollback works for the same reason: the retained
image has its own copy.

`image rollback` narrows the set again. It copies the retained image over the
active one, so afterwards the ESP boots only that image, and the image rolled
back from is gone from the ESP. Once the ESP write is done, the node:

1. Checks its PCR 11 prediction for the running image against the TPM, as a
   stage does.
2. Seals a fresh copy of the state key for the rollback target.
3. Removes every other copy, including the one for the image it is running
   (unless that is the rollback target).

The new copy goes in before any old one comes out, so the rollback target
never loses the copy it boots with. After two stages without a reboot the
running image is no longer on the ESP, so there is nothing to check the
prediction against: the node then keeps the copy the target was given when it
was staged, seals nothing new, and removes the rest. If the target has no copy
of its own, the header is left alone. If any of this fails, the rollback still
stands: the header keeps its old copies, the target's among them, and the
next `image stage` prunes the rest. The node log records the failure
(`image rollback: warn: state key prune failed`).

Things to know:

- **The image has to be one the node can predict.** Prediction follows the
  systemd-stub measurement of a single-profile UKI built by
  `build/uki/assemble.sh`. An image with sections it does not recognise, or a
  multi-profile UKI, is refused rather than guessed at.
- **PCR 7 must not change across the upgrade.** The new copy is sealed to the
  current PCR 7, which holds for an image signed with the same Secure Boot key
  (the only kind the node accepts). Changing Secure Boot state or the enrolled
  keys in the firmware still breaks the unseal, upgrade or not.
- **Staging twice without a reboot is fine**, but a third stage in a row is
  refused, because by then the image the node is running is no longer on the
  ESP to check the prediction against. Reboot into the staged image first; a
  rollback does not bring the running image back to the ESP.
- **Rolling forward after a rollback means staging again.** The rollback
  removes the newer image from the ESP and its copy of the key from the
  header, so the only way back to it is `image stage`.
- **A refused stage says why.** The `FailedPrecondition` message states once
  that the state key cannot be resealed, followed by the specific cause, for
  example an unknown UKI section or a PCR 11 mismatch.
