# Subordinating VMware VMCA under a CryptOS CA

vCenter's built-in CA (VMCA) can run as a subordinate issuing CA under a CryptOS
root, so everything it issues for vSphere and ESXi chains to your root instead of
a self-signed VMCA root. VMCA keeps issuing; only its own certificate changes.

The same shape applies to Microsoft AD CS, which also generates its own key and
offers no algorithm choice.

## The one requirement that decides everything: RSA end to end

vSphere **does not accept ECDSA signatures**. From *Certificate Requirements for
Different Solution Paths* (vSphere 8.0, unchanged in 9.0):

> vSphere deploys only RSA certificates for server authentication and does not
> support generating ECDSA certificates.

A certificate's signature algorithm is a property of its **issuer's** key, not
its own. So it is not enough that VMCA's request is RSA — the CryptOS CA signing
it must hold an RSA key, and so must every CA above it. An RSA intermediate
under an ECDSA root does not work: the intermediate's own certificate carries an
`ecdsa-with-SHA384` signature and appears in the chain vCenter verifies.

**This fails silently at signing time.** CryptOS will happily certify an RSA
subject key from an ECDSA CA and hand you a certificate; vCenter refuses it at
import, after `certificate-manager` has started. `TestVMCASubordination_UnderAnECDSACARejected`
exists to pin that behaviour so it is not rediscovered the hard way.

An ECDSA-rooted fleet therefore needs a **separate RSA hierarchy** for this, not
a re-key of the existing one.

## What the CA must be configured with

The signing node needs an RSA CA key, a revocation base URL, and a CA profile:

```yaml
pki:
  root_key_alg: RSA-3072          # or RSA-4096. RSA-2048 is rejected: the CA
                                  # will not certify a subject key below 3072.
  revocation_base_url: http://pki-inter.example
  profiles:
    - name: platform-sub-ca
      key_alg: RSA-3072           # required by validation; governs keys this
                                  # node generates, not the ones it certifies,
                                  # so VMCA's own key is fine
      validity_days: 1825
      basic_constraints:
        is_ca: true
        path_len: 0               # VMCA may not create sub-CAs of its own
      key_usage: [digital_signature, cert_sign, crl_sign]
      # ext_key_usage: leave unset (or [server_auth] only)
      # sans: leave unset (or at most one dns entry)
```

`cert_sign` and `crl_sign` are both required — vCenter states CRL signing must be
enabled. The accepted `key_usage` names are `digital_signature`, `cert_sign`,
`crl_sign`, `key_encipherment` and `key_agreement`; any other name fails config
validation. Extended key usage must be empty or `server_auth` only.

The subject of the issued certificate comes from VMCA's CSR, but every extension
comes from the profile, including subject alternative names: whatever is in the
profile's `sans` block is stamped onto the VMCA certificate, and SANs in the CSR
are ignored. vCenter rejects a VMCA signing certificate with more than one DNS
name, so leave `sans` unset, or give it at most one `dns` entry and nothing else.

`path_len: 0` is the requested value. If the signing CA is itself
pathLen-constrained, the node clamps the requested value to the budget its own
certificate leaves, so it can only get tighter.

**Set `revocation_base_url` before signing.** It is what stamps revocation
pointers onto issued certificates: a CRL distribution point at `<base>/crl` and
an AIA OCSP pointer at `<base>/ocsp`. With it empty, the VMCA certificate is
issued with neither extension and nothing can check whether it has been revoked;
a certificate already issued cannot gain them later without being re-signed. When
it is set, signing fails closed if the node's revocation preflight is not passing
(the URL does not resolve, or `/crl` and `/ocsp` are unreachable), unless
`allow_unverified_revocation_url: true` is set.

RSA CA keys are supported on the software key path (`state_key.mode` of `nodeid`
or `kms`). A TPM-resident RSA CA key is not supported; see #197.

## The procedure

**1. Generate the request on vCenter.** Put VMCA into intermediate CA mode and
have it emit its CSR. Copy the CSR off the appliance, then check its key size
before going further:

```sh
openssl req -in vmca.csr -noout -text | grep Public-Key
```

The node refuses any RSA subject key below 3072 bits, so anything smaller than
`(3072 bit)` is rejected at signing. Do not assume the key size; the tooling on
the appliance can produce a smaller key depending on how it is invoked.

**2. Sign it with the CryptOS CA.** From an operator workstation with an admin
credential for the signing node, first pin the node's **current** management
certificate. It is self-signed and regenerated on every boot, so your root does
not verify it and a pin taken before the node's last reboot no longer works.
Fetch it after the node is up, using the node's management IP:

```sh
openssl s_client -connect 192.0.2.10:443 -servername 192.0.2.10 </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > node-trust.pem
```

Then sign:

```sh
cryptosctl ca sign-subordinate \
  --endpoint 192.0.2.10:443 \
  --identity admin.crt --identity-key admin.key \
  --trust node-trust.pem \
  --csr vmca.csr \
  --profile platform-sub-ca > vmca-chain.pem
```

`sign-subordinate` is a subcommand of `ca`. `--endpoint`, `--identity`,
`--identity-key` and `--trust` are the global connection flags: the node's
`host:port`, the admin client certificate and its key, and the node's pinned
management certificate. `--trust root.pem` does **not** work and fails with
`x509: certificate signed by unknown authority`. Address the node by IP: its
management certificate names the IP and `localhost` and no DNS names. If you
connect through a DNS name, add `--server-name` with the IP. There is no
`--node` flag. `--csr` (PEM or DER) and `--profile` are both required. The
profile must be a CA profile (`is_ca: true`) defined on the signing node.

If the call fails with `certificate signed by unknown authority`, the node has
rebooted since you fetched `node-trust.pem`. Fetch it again. The node shows no
fingerprint to compare the fetch against, so the pin is trust on first use.
What makes that safe here is step 3: a certificate that verifies against your
root came from your CA, whoever answered the connection. See
[`management-trust.md`](management-trust.md) for the details.

The output is leaf-first: the new VMCA certificate followed by the certificate of
the CA that signed it. **The root is not included.** When the signing node is an
intermediate, the output is VMCA plus that intermediate and nothing above it.
`certificate-manager` needs the full chain, so append the rest of the chain up to
and including the root yourself:

```sh
cat vmca-chain.pem root.pem > vmca-fullchain.pem
```

Under a deeper hierarchy, append each missing CA certificate in order, leaf to
root, before the root.

**3. Verify before importing.** Importing is the disruptive step, so check the
result first:

```sh
# the VMCA certificate (the first one in the file)
openssl x509 -in vmca-fullchain.pem -noout -text | grep -E 'Signature Algorithm|CA:|Key Usage|CRL Distribution|OCSP' -A1
# the signature algorithm of every certificate in the chain
openssl crl2pkcs7 -nocrl -certfile vmca-fullchain.pem | openssl pkcs7 -print_certs -text -noout | grep 'Signature Algorithm'
# the chain verifies to your root
openssl verify -CAfile root.pem -untrusted vmca-chain.pem vmca-chain.pem
```

Expect a `sha256WithRSAEncryption` or `sha384WithRSAEncryption` signature,
`CA:TRUE, pathlen:0`, both `Certificate Sign` and `CRL Sign`, and the CRL
distribution point and OCSP URL under your `revocation_base_url`. An
`ecdsa-with-SHA384` signature on any certificate in the chain means the hierarchy
is not RSA end to end and vCenter will refuse the import.

**4. Import into vCenter** with `certificate-manager`, option 2 ("Replace VMCA
Root certificate with Custom Signing Certificate"), giving it the full chain from
step 2 (`vmca-fullchain.pem`). vCenter restarts its services and reissues every
certificate it had issued.

## Limits worth knowing before you start

- **vCenter does not allow sub-CAs of VMCA.** `path_len: 0` matches that.
- **Not more than one DNS name**, and no wildcards, in the VMCA certificate.
  SANs come from the profile, not the CSR, so this is controlled by the
  profile's `sans` block.
- **Key size 2048 to 8192 bits.** CryptOS enforces its own floor of 3072 on any
  subject key it certifies, so the usable range here is 3072 to 8192.
- **Name constraints are not yet supported** by the profile surface. Limiting
  what a subordinated platform CA may issue is tracked separately.

## What is covered by tests

`internal/node/vmca_subordination_test.go` drives the real `SignSubordinate`
path with a request shaped like VMCA's and asserts every published requirement
above: the whole returned chain is RSA SHA-2 signed, the certificate is v3 with
`CA:TRUE`, carries certificate and CRL signing, has no extended key usage beyond
`serverAuth`, has at most one DNS name, has a key inside vCenter's size range,
and verifies as a chain.

So "will vCenter accept what we issue" is answered by CI rather than during a
maintenance window. What CI cannot answer is whether your hierarchy is RSA — that
is a property of the CA you sign with.
