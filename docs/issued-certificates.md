# Issued certificates

Every certificate a node issues is recorded in its issued set, keyed by its
serial. `cryptosctl` reads that set, fetches a certificate back from it, and
revokes from it. All three verbs need the bootstrap admin client certificate
over mTLS, the same as every other `ca` verb.

> [!NOTE]
> `cryptosctl` runs on Linux and macOS today. A Windows build is coming.

## List what a node issued

```sh
cryptosctl --endpoint pki-issuing.example:443 ca list-issued
```

This prints the serial, subject, profile and notAfter of each certificate.
`-o json` or `-o yaml` gives the full inventory entries.

## Fetch one certificate and its chain

```sh
cryptosctl --endpoint pki-issuing.example:443 ca get-issued --serial 4f1a09c2 > leaf-chain.pem
```

stdout gets the certificate as PEM, followed by the node's chain from the
issuing CA up to the root, so the output can go straight to a file. stderr gets
the status:

> [!TIP]
> The status line on stderr, here for a revoked certificate:
>
> ```text
> status: revoked (revoked at 2026-03-04T05:06:07Z)
> ```

The status is `valid`, `revoked` or `expired`. A revoked certificate is still
returned, and its revocation time is included. If a certificate is both
revoked and expired, it reports `revoked`.

`-o json` or `-o yaml` prints the `GetIssuedCertificate` response instead:
`certificate_der`, `chain_der` (base64, issuer first), `status`, and
`revoked_at` (RFC 3339, empty unless revoked).

The serial is hex, as `list-issued` prints it. Upper case, leading zeros, a
`0x` prefix and colon-separated bytes (the `openssl x509 -serial` and browser
spellings) are accepted.

Errors:

- **`NotFound`:** the serial is not in this node's issued set. It was issued
  by a different CA, or mistyped.
- **`FailedPrecondition`:** the certificate was issued before nodes kept the
  issued certificate itself. Only its inventory entry exists, so `list-issued`
  still shows it and `revoke` still works, but it cannot be fetched.
- **`InvalidArgument`:** the serial is not hex.

## Revoke

> [!CAUTION]
> Revocation cannot be undone. The node has no way to take a serial back off
> the revoked list, and revoking it again returns the original record,
> reason code included. Check the serial with `ca get-issued` first.

```sh
cryptosctl --endpoint pki-issuing.example:443 ca revoke --serial 4f1a09c2 --reason 1
cryptosctl --endpoint pki-issuing.example:443 ca revocations
```

`--reason` is an RFC 5280 CRL reason code. The node records the revocation
and rebuilds its CRL. OCSP answers from the same store.

`--serial` accepts the same spellings as `get-issued`: upper or lower case,
leading zeros, a `0x` prefix and colon-separated bytes, so a serial copied
from `openssl x509 -serial` works as it is. The node normalises it to the
stored form (lower case, no leading zeros) before the lookup.

Errors:

- **`NotFound`:** no certificate this node issued has that serial. The
  message shows the normalised serial the node looked up, for example
  `serial "4f1a09c2" not found among the certificates this node issued`.
- **`InvalidArgument`:** the serial is not hex.
