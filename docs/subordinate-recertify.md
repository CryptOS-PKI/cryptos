# Re-certifying an intermediate without re-keying

An intermediate or issuing CA can get a fresh certificate from its parent for
the key it already holds. The usual reason is that the parent's
`pki.revocation_base_url` was set after the intermediate enrolled, so the
intermediate's certificate has no CRL distribution point, OCSP pointer or
caIssuers pointer. Re-keying (`ca rotate-key` / `ca submit-rotation`) would add
them too, but it replaces the key, and every certificate the intermediate
already issued then chains through a key the node no longer holds.

Re-certification keeps the key, the subject and the subject key identifier
(SKI). The parent derives the SKI from the key, so it cannot change. Leaf
certificates issued before the swap name the same issuer and carry the same
authority key identifier, so they verify through the new intermediate
certificate as well as the old one.

## What the node checks

`ca get-renewal-csr` returns a PKCS#10 request signed by the node's current CA
key. Its subject is copied byte for byte from the current CA certificate, not
rebuilt from the machine config. The node stages nothing, so fetching a CSR and
never submitting it is harmless.

`ca submit-renewed-cert` accepts the chain only if all of these hold. Otherwise
it rejects the chain and changes nothing:

- the chain verifies to the pinned parent anchor (`pki.parent`) and is valid now;
- the new certificate's public key is byte-identical to the current CA key;
- the new certificate's subject is byte-identical to the current one, and its
  SKI is unchanged;
- it is a CA certificate (basicConstraints `CA:TRUE`, `keyCertSign`), and its
  pathLenConstraint is not wider than the current one.

On success, one guarded transaction replaces the CA certificate and the served
chain. The previous certificate is kept in the node's identity history. The
signer, CRL, OCSP, `/ca.cer` and EST paths read the CA certificate from the
store on every use, so **no reboot is needed on the intermediate**.
Submitting the current certificate again is a no-op.

The previous certificate is not revoked and stays valid until it expires.

A root is self-signed and has no parent, so on a root both RPCs return
`Unimplemented`.

## The procedure

The commands below abbreviate the global connection flags (`--endpoint`,
`--identity`, `--identity-key`, `--trust`) as `...`. Both RPCs need the bootstrap admin credential of the intermediate. See
[`management-trust.md`](management-trust.md) for pinning a node's management
certificate.

**1. Configure the parent's revocation base URL.** Add
`pki.revocation_base_url` to the parent's machine config and apply it:

```sh
cryptosctl --endpoint <root>:443 ... config apply -f root.yaml
```

This field is not hot-reloaded. The apply reports that a reboot is required,
and the parent starts its `/crl`, `/ocsp` and `/ca.cer` listener and its
revocation preflight only at boot. Reboot the parent. Until the preflight
passes, `sign-subordinate` refuses with `FailedPrecondition`: the base URL host
must resolve, and `<base>/crl`, `<base>/ocsp` and `<base>/ca.cer` must answer.
The parent logs `revocation preflight: ok` once it passes, and re-checks every
30 seconds. Set
`allow_unverified_revocation_url` only if you accept pointers that may never
resolve. They are permanent in every certificate signed while it is set.

**2. Fetch the renewal CSR from the intermediate.**

```sh
cryptosctl --endpoint <intermediate>:443 ... identity show -o pem > sub-old-chain.pem
cryptosctl --endpoint <intermediate>:443 ... ca get-renewal-csr > sub-renewal.csr
```

Keep `sub-old-chain.pem` for the checks in step 5.

**3. Sign it on the parent** with the same CA profile the intermediate was
enrolled under:

```sh
cryptosctl --endpoint <root>:443 ... ca sign-subordinate \
  --csr sub-renewal.csr --profile <sub-ca-profile> > sub-renewed-chain.pem
```

The parent needs no special mode for this. `sign-subordinate` has no
already-issued or duplicate guard: every signature gets a fresh random serial
and is recorded in the parent's issued inventory. The profile decides validity
and extensions, and the pathLenConstraint is clamped to the parent's budget as
usual. A profile whose path length is wider than the intermediate's current
certificate is rejected at submit.

**4. Submit the chain back to the intermediate.**

```sh
cryptosctl --endpoint <intermediate>:443 ... ca submit-renewed-cert --chain sub-renewed-chain.pem
```

The command prints the node's new identity. From now on the node serves the
renewed chain and signs under it. No reboot is needed.

**5. Verify with openssl** (1.1.1 or later, for `-ext`). Each command reads the
first certificate in the file, which is the intermediate.

```sh
# same key: the two digests must match
openssl x509 -in sub-old-chain.pem -noout -pubkey | openssl sha256
openssl x509 -in sub-renewed-chain.pem -noout -pubkey | openssl sha256

# same subject and SKI, and a new serial
openssl x509 -in sub-old-chain.pem -noout -subject -serial -ext subjectKeyIdentifier
openssl x509 -in sub-renewed-chain.pem -noout -subject -serial -ext subjectKeyIdentifier

# the new certificate carries the pointers
openssl x509 -in sub-renewed-chain.pem -noout -ext crlDistributionPoints,authorityInfoAccess,basicConstraints

# the chain verifies to the root, and a leaf issued before the swap verifies through the new certificate
openssl verify -CAfile root.pem -untrusted sub-renewed-chain.pem sub-renewed-chain.pem
openssl verify -CAfile root.pem -untrusted sub-renewed-chain.pem existing-leaf.pem
```

Expect `<base>/crl` under the CRL distribution points, and `OCSP - URI:<base>/ocsp`
and `CA Issuers - URI:<base>/ca.cer` under Authority Information Access.

## After the swap

Anything that holds a copy of the intermediate certificate keeps the old one
until you replace it: TLS servers that send the intermediate in their chain,
intermediate stores pushed by policy, trust bundles. Both certificates verify,
so this is not urgent, but only the new one carries the revocation pointers.
Replace those copies with the new certificate from `sub-renewed-chain.pem`.

Nothing on the intermediate needs a restart. `/ca.cer`, EST `/cacerts`, and
the chains returned by `issue-leaf` and `sign-subordinate` carry the new
certificate straight away. The CRL is signed under it. The EST listener
re-mints its TLS certificate under it on the next handshake. The delegated OCSP
responder certificate is not re-minted, and does not need to be: it names the
same issuer and carries the same authority key identifier, so it validates
against the new certificate.
