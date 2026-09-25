# Upgrading a CryptOS node in place

A CryptOS node can take a new OS image without being re-provisioned. This
matters because re-provisioning reformats the state partition and destroys the
CA key with it: on an established node that means re-issuing every certificate
it ever signed and redistributing the trust anchor.

The disk layout is what makes the separation possible. The root filesystem is
an immutable SquashFS carried inside a Unified Kernel Image on the EFI System
Partition; identity -- CA key, etcd, issued history -- lives on a separate LUKS
partition. **An upgrade writes the ESP and reboots. The state partition is
never opened.**

## What you need

- The signed image, `cryptos-amd64.uki`, and its detached release signature,
  `cryptos-amd64.uki.sig`. `build/uki/sign.sh` writes both, side by side.
- An admin credential for the node (the bootstrap admin client certificate).
- A maintenance window for step 3, and only step 3.

The node accepts an image only if it is signed by the release key the running
image was built against. A CI build, signed with that workflow's per-run
ephemeral key, is refused -- which is the point.

## The procedure

The commands below use the default trust file, `~/.cryptos/trust.crt`. It has
to hold the node's current self-signed management certificate, and the
endpoint has to be the IP that certificate names. A DNS name like the one shown
also needs `--server-name` with that IP. See
[`management-trust.md`](management-trust.md). Activating an image reboots the
node, and the reboot replaces that certificate.

### 1. See where the node is

```sh
cryptosctl --endpoint pki-root.example:443 image status
```

```
Running version:  v1.4.0
Running image:    9f2c...
Next boot image:  9f2c...
Previous image:   (none retained)
Reboot pending:   no
```

`Running image` and `Next boot image` being equal means nothing is staged.

### 2. Stage the new image

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

```sh
cryptosctl --endpoint pki-root.example:443 image activate \
  --confirm "Example Root CA G1"
```

`--confirm` must be the node's CA common name, the same echo the reset verbs
require. This reboots the node through the same orderly shutdown as
`cryptosctl reboot`: every certificate operation that depends on it is
unavailable until it comes back.

Confirm afterwards. The node came back with a new management certificate, so
the pin you used before the reboot no longer matches. Fetch the current one
first, as described in [`management-trust.md`](management-trust.md), or the
next call fails with `x509: certificate signed by unknown authority`:

```sh
cryptosctl --endpoint pki-root.example:443 image status
```

`Running version` should be the new one, the two digests should agree again,
and `Previous image` should now name the image you upgraded from.

### 4. If it went badly

```sh
cryptosctl --endpoint pki-root.example:443 image rollback
cryptosctl --endpoint pki-root.example:443 image activate \
  --confirm "Example Root CA G1"
```

Fetch the management certificate again after that reboot too. The previous
image is retained on the ESP and stays bootable, so a failed upgrade is
recoverable over the network. If the new image will not boot at all
-- rather than booting badly -- rollback is not reachable and the node needs
console access; see "Limits" below.

## Two signatures, and why

The firmware is the only authority on whether an image may boot. It verifies
the UKI's Authenticode signature against the Secure Boot db certificate
enrolled on that machine, and nothing in this procedure can weaken that.

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
- **A development build serves none of this.** Without a release certificate
  compiled in, the image upgrade RPCs return `Unimplemented`. Development
  builds are upgraded by reinstalling them.
- **Only one previous image is retained.** Two upgrades in a row leave you able
  to roll back one.
- **An image that does not boot at all is not recoverable over the network.**
  The retained image is bootable, but selecting it means reaching the node,
  which is the thing that is down. Test a new image on a non-production node
  first.
- **This has not been exercised on production hardware yet.** The verification,
  slot management, RPC and CLI paths are covered by tests; the actual
  `mount`/reboot sequence on a real ESP is not something a test can cover.
  Do the first run on a node you can reach physically.
