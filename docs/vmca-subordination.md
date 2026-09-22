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

The signing node needs an RSA CA key and a CA profile:

```yaml
pki:
  root_key_alg: RSA-3072          # or RSA-4096. RSA-2048 is rejected: the CA
                                  # will not certify a subject key below 3072.
  profiles:
    - name: platform-sub-ca
      key_alg: RSA-3072           # governs keys this node generates, not the
                                  # ones it certifies, so VMCA's own key is fine
      validity_days: 1825
      basic_constraints:
        is_ca: true
        path_len: 0               # VMCA may not create sub-CAs of its own
      key_usage: [digital_signature, cert_sign, crl_sign]
```

`cert_sign` and `crl_sign` are both required — vCenter states CRL signing must be
enabled. Extended key usage must be empty or `server_auth` only.

RSA CA keys are supported on the software key path (`state_key.mode` of `nodeid`
or `kms`). A TPM-resident RSA CA key is not supported; see #197.

## The procedure

**1. Generate the request on vCenter.** Put VMCA into intermediate CA mode and
have it emit its CSR. It produces RSA-3072 with a single common name and no
SANs. Copy the CSR off the appliance.

**2. Sign it with the CryptOS CA.** From an operator workstation with an admin
credential for the signing node:

```sh
cryptosctl --node pki-inter.example:443 sign-subordinate \
  --csr vmca.csr \
  --profile platform-sub-ca > vmca-chain.pem
```

The output is the leaf-first chain: the new VMCA certificate followed by the
issuing CA and the root. `certificate-manager` wants the chain, not just the
leaf.

**3. Verify before importing.** Importing is the disruptive step, so check the
result first:

```sh
openssl x509 -in vmca-chain.pem -noout -text | grep -E 'Signature Algorithm|CA:|Key Usage' -A1
openssl verify -CAfile root.pem -untrusted intermediate.pem vmca-chain.pem
```

Expect a `sha256WithRSAEncryption` or `sha384WithRSAEncryption` signature,
`CA:TRUE`, and both `Certificate Sign` and `CRL Sign`. An `ecdsa-with-SHA384`
signature here means the hierarchy is not RSA end to end and vCenter will refuse
the import.

**4. Import into vCenter** with `certificate-manager`, option 2 ("Replace VMCA
Root certificate with Custom Signing Certificate"). vCenter restarts its
services and reissues every certificate it had issued.

## Limits worth knowing before you start

- **vCenter does not allow sub-CAs of VMCA.** `path_len: 0` matches that.
- **Not more than one DNS name**, and no wildcards, in the VMCA certificate.
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
