# SCEP enrolment (RFC 8894)

SCEP is the enrolment protocol network equipment speaks. Cisco IOS and IOS-XE
trustpoints, and most switch, router, firewall and VPN platforms, cannot run
an ACME client, so SCEP is their only automated way to get a certificate and
to renew it.

> Scope: `GetCACaps`, `GetCACert`, and `PKIOperation` with `PKCSReq`,
> `RenewalReq`, `CertPoll` (`GetCertInitial`), `GetCert` and `GetCRL`.
> `GetNextCACert` is not offered.

## How a device is authorized

| | Authorized by | Names it may request |
|---|---|---|
| Initial enrolment (`PKCSReq`) | A one-time challenge an admin mints for that device | Inside `allowed_identifier_suffixes`, and inside the challenge's bound names when it has any |
| Renewal (`RenewalReq`) | The certificate the device holds, issued by this CA, current and not revoked | Exactly the names on that certificate |

There is no static shared challenge. One secret configured on every device
would let anyone who lifts it from one device enrol as any other, so each
initial enrolment needs its own challenge:

- only its SHA-256 is stored, and it is never logged or read back;
- it is consumed by the first request that presents it, whether that request
  is issued, refused or queued;
- it expires (one hour by default, seven days at most);
- it names the profile the certificate is issued from;
- it can be bound to the names the device may ask for.

A `PKCSReq` signed by a current certificate from this CA is treated as a
renewal, with the same rules as `RenewalReq`. That is how renewal worked
before RFC 8894, and how `sscep` and Cisco IOS auto-enrol rollover still send
it.

## Switching it on

SCEP is off unless the `pki.scep` block is present, and a Root refuses it.

```yaml
pki:
  profiles:
    - name: cisco-device
      key_alg: ECDSA-P384
      validity_days: 365
      key_usage: [digital_signature, key_encipherment]
      ext_key_usage: [client_auth, server_auth]
  scep:
    http_port: 0              # 0 shares the CRL/OCSP port (80 by default)
    profiles:
      - profile: cisco-device
        min_rsa_key_bits: 2048   # Cisco trustpoints cannot hold a larger key
        require_approval: false
    allowed_identifier_suffixes: [example.com]
    ra:
      validity_days: 365
      rotation_overlap_days: 30
```

> [!WARNING]
> Switching SCEP on or off, or changing any `pki.scep` field, takes effect at
> the next boot. `cryptosctl config apply` stores the change and answers
> `requires_reboot: true`; the listener only starts at boot. Plan the change
> for a maintenance window and reboot the node (`cryptosctl reboot`).

`pki.scep` travels in the machine config, so `config apply`, the maintenance
install and the Fleet Manager all carry it. `cryptosctl config apply` sends
the whole config, so a YAML file without the block switches SCEP off. An API
client that leaves `pki.scep` out of the message entirely keeps the stored
block; it switches SCEP off with `enabled: false`.

`cryptosctl status -o json` reports SCEP under `protocols`: `configured` is
the stored config, `running` is this boot, and `reboot_pending` is set when
they differ.

### Profiles and key sizes

Each entry in `profiles` names a non-CA profile in `pki.profiles`. Its
`min_rsa_key_bits` is the smallest RSA key it certifies over SCEP:

- `0` means 3072, the node-wide floor;
- `2048` is the lowest allowed, for devices that cannot do better;
- stronger RSA keys and ECDSA P-384 keys are always accepted.

The floor applies to SCEP only. The node's own CA, RA and listener keys stay
RSA 3072 or larger, or ECDSA P-384, and every other issuance path keeps the
node-wide floor.

> [!CAUTION]
> A device's key must be RSA. The reply is encrypted to the key that signed
> the request, and SCEP key transport is RSA. A request signed with an ECDSA
> key is refused with `badAlg`.

### Transport, paths and the RA

SCEP is plain HTTP, as the RFC intends: the CMS envelope carries
confidentiality and integrity. It answers on `/cgi-bin/pkiclient.exe` (the
path Cisco appends) and `/scep`. With `http_port: 0` it shares the CRL/OCSP
listener when that one runs (`revocation_base_url` set), so
`http://<node>/cgi-bin/pkiclient.exe` works as written; otherwise it binds its
own listener on that port. A non-zero `http_port` always gets its own
listener.

Requests are encrypted to, and replies signed by, an RA certificate the node
mints from its own CA: RSA 3072, key usage `digitalSignature` and
`keyEncipherment`. The CA key only ever signs certificates. `GetCACert`
returns the CA certificate and the RA certificate
(`application/x-x509-ca-ra-cert`), so the device's trustpoint needs RA mode.

The RA is valid for `validity_days` (365 at most) and is stored on the
encrypted state partition. `rotation_overlap_days` before it expires, the node
mints its successor. From then on `GetCACert` offers the new RA, and requests
encrypted to either RA still decrypt, so a device that cached the old one
keeps enrolling. The expired RA is dropped. The RA key is a software key on the
state partition even on a TPM node.

`GetCACaps` advertises `AES`, `POSTPKIOperation`, `Renewal`, `SHA-256` and
`SHA-512`. DES, 3DES, MD5 and SHA-1 are refused.

## Minting a challenge

```sh
cryptosctl scep challenge mint --profile cisco-device --ttl 30m --name switch01.example.com
```

The challenge is printed once. The node cannot show it again, so a lost
challenge is revoked and a new one minted. `--name` (repeatable) binds the
challenge: the request may then carry only those names. `--profile` can be
left out when only one SCEP profile is configured.

```sh
cryptosctl scep challenge list
cryptosctl scep challenge revoke --id <id>
```

`list` shows the challenges that are still usable, never the challenge itself.

## Holding enrolments for approval

With `require_approval: true` on a profile, every initial enrolment from it is
answered `PENDING` and waits. The device polls (`CertPoll`) until an admin
decides:

```sh
cryptosctl scep enrollments list
cryptosctl scep enrollments approve --id <id>
cryptosctl scep enrollments reject --id <id> --reason "not one of ours"
```

Approval checks the request again against the config in force; one that no
longer passes stays queued to be rejected. Renewals are never queued.

## Retries and polling

Every transaction is recorded. A retransmitted request, or a `CertPoll`, gets
the certificate already issued for its transaction, never a second one, and a
transaction ID reused with a different key is refused. A request that fails is
not recorded, so the device can try again with a fresh challenge.

## Every decision is audited

Each issuance, refusal and queued request is written to the audit log with
the transaction ID, the profile, the serial and the ID of the challenge that
was consumed. Minting, revoking, approving and rejecting are audited as the
admin RPCs they are. A challenge never appears in the log.

## Limits worth knowing before you deploy

- **DNS names only.** Every DNS name in the request, and the subject common
  name, must fall inside `allowed_identifier_suffixes`. IP, email and URI
  subject alternative names are refused rather than dropped.
- **Wildcards are refused.** A challenge establishes nothing about a label
  space.
- **`GetCert` and `GetCRL`** need a request signed by a current certificate
  from this CA.
- **The RA key is a software key** on the encrypted state partition, not a
  TPM key.
- **The clock gate applies.** While a configured time source has not synced
  this boot, issuance is refused, the same as for ACME and EST, and the device
  gets a `badRequest` failure. See [`time-sync.md`](time-sync.md).

For the Cisco IOS and IOS-XE steps, see the docs site page "Enrol devices with
SCEP".
