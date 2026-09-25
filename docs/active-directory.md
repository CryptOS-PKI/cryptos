# Certificates for Active Directory domain controllers

A CryptOS issuing (or intermediate) CA can issue the two certificates a domain
controller needs without AD CS: an LDAPS server certificate, and a KDC
certificate for strict KDC validation, PKINIT and smart-card logon. This guide
covers the profiles for both, the per-DC profile pattern, generating the request
on Server Core with `certreq`, and installing the result with `certreq -accept`.

The examples use the forest `ad.example.org` (Kerberos realm `AD.EXAMPLE.ORG`),
a domain controller `dc01.ad.example.org`, and an issuing node reachable at
`pki.example.org` for revocation and at `192.0.2.10:443` for management.

## What the CA must be configured with

The profile decides every extension. The CSR contributes only the subject and
the public key; SANs or EKUs requested in the CSR are ignored. So the names on a
domain controller's certificate are whatever its profile lists.

Set `revocation_base_url` on the issuing node. Windows checks revocation on both
certificates, and a DC certificate whose CRL cannot be fetched fails
validation. With the base URL set, every certificate carries a CRL distribution
point at `<base>/crl`, an AIA OCSP pointer at `<base>/ocsp`, and an AIA
caIssuers pointer at `<base>/ca.cer`, from which a client that trusts only the
root can fetch the issuing CA's certificate. Use an `http://` URL. Windows
fetches CRLs and AIA over plain HTTP, and HTTPS would make revocation checking
depend on another certificate.

```yaml
pki:
  revocation_base_url: http://pki.example.org
  profiles:
    # ... the profiles below
```

The node certifies RSA keys of 3072 bits or more and ECDSA P-384 keys. Windows
defaults to RSA 2048, so the INF files below ask for RSA 3072 explicitly.

## LDAPS certificate

AD DS uses a certificate from the computer's personal store for LDAPS (port
636) when it has the Server Authentication EKU and the DC's fully qualified
name in its subject alternative names.

```yaml
    - name: ldaps-dc01
      key_alg: RSA-3072          # required by validation; governs keys this
                                 # node generates, not the DC's key
      validity_days: 365
      key_usage: [digital_signature, key_encipherment]
      ext_key_usage: [server_auth]
      sans:
        dns: [dc01.ad.example.org, ad.example.org]
```

`ad.example.org` is optional. It lets clients that connect to the domain name
rather than a specific DC (`ldaps://ad.example.org`) validate the name.

## KDC certificate

For PKINIT and smart-card logon, and for clients that enforce strict KDC
validation, the KDC presents a certificate with the KDC Authentication EKU
(`1.3.6.1.5.2.3.5`). With strict KDC validation the SANs must also include the
domain's DNS name. Windows' own Kerberos Authentication template adds Client
Authentication, Server Authentication and Smart Card Logon
(`1.3.6.1.4.1.311.20.2.2`); the profile does the same. The `krb5_principal` SAN
carries the KDC's principal, `krbtgt/<REALM>@<REALM>`, as an `id-pkinit-san`
otherName (RFC 4556). Windows clients do not need it; MIT Kerberos and other
PKINIT clients do.

```yaml
    - name: kdc-dc01
      key_alg: RSA-3072
      validity_days: 365
      key_usage: [digital_signature, key_encipherment]
      ext_key_usage:
        - server_auth
        - client_auth
        - 1.3.6.1.4.1.311.20.2.2   # Smart Card Logon
        - 1.3.6.1.5.2.3.5          # KDC Authentication
      sans:
        dns: [dc01.ad.example.org, ad.example.org]
        krb5_principal: ["krbtgt/AD.EXAMPLE.ORG@AD.EXAMPLE.ORG"]
```

`ext_key_usage` takes the names `server_auth` and `client_auth` or any dotted
OID. OIDs are checked strictly: decimal arcs, no leading zeros, a first arc of
0, 1 or 2. Listing the same usage twice, by name or by OID, fails validation.

The `sans` block also accepts `upn`, a list of Microsoft user principal names
stamped as otherName `1.3.6.1.4.1.311.20.2.3`. User smart-card logon
certificates carry one. A DC certificate does not need it.

A Kerberos principal is `name[/instance]@REALM`. Components and realm are
printable ASCII without `/`, `@` or `\`; escapes are not accepted.
`krbtgt/<instance>` gets the NT-SRV-INST name type, anything else
NT-PRINCIPAL.

One certificate can do both jobs: the KDC profile already has Server
Authentication and the DC's name, so AD DS will also use it for LDAPS. Keeping
two profiles lets you rotate or revoke them independently.

## One profile per domain controller

The SANs come from the profile, and every DC has its own name, so each DC gets
its own pair of profiles: `ldaps-dc01` and `kdc-dc01`, `ldaps-dc02` and
`kdc-dc02`, and so on. They differ only in `name` and the first `dns` entry.
The domain name and the `krbtgt` principal are the same on every DC.

Profiles live in the machine config under `pki.profiles`. Add them with
`cryptosctl config apply`; the signer reads the live config, so new profiles are
usable without a reboot.

## Generating the request on Server Core

`certreq` and `certutil` are both on Server Core. Write the INF with Notepad or
PowerShell. The key is created in the computer's store (`MachineKeySet`) and is
not exportable.

`dc01-ldaps.inf`:

```ini
[Version]
Signature = "$Windows NT$"

[NewRequest]
Subject = "CN=dc01.ad.example.org"
KeyAlgorithm = RSA
KeyLength = 3072
KeySpec = 1
KeyUsage = 0xA0
MachineKeySet = TRUE
Exportable = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
HashAlgorithm = SHA256
SMIME = FALSE
```

`KeyUsage = 0xA0` is digital signature plus key encipherment, and `KeySpec = 1`
is a key-exchange key, which LDAPS needs. For the KDC certificate use the same
file with a different name (`dc01-kdc.inf`). Leave out `[Extensions]` and
`[EnhancedKeyUsageExtension]`: the node ignores what the CSR asks for.

```powershell
certreq -new dc01-ldaps.inf dc01-ldaps.req
certreq -new dc01-kdc.inf dc01-kdc.req
```

`certreq -new` keeps the new key as a pending request in the computer's store.
The certificate must be accepted on the same DC.

## Issuing

Copy the `.req` files to the workstation that runs `cryptosctl` and issue each
under its profile:

```sh
cryptosctl ca issue-leaf \
  --endpoint 192.0.2.10:443 \
  --identity admin.crt --identity-key admin.key \
  --trust node-trust.pem \
  --csr dc01-ldaps.req --profile ldaps-dc01 > dc01-ldaps.cer

cryptosctl ca issue-leaf \
  --endpoint 192.0.2.10:443 \
  --identity admin.crt --identity-key admin.key \
  --trust node-trust.pem \
  --csr dc01-kdc.req --profile kdc-dc01 > dc01-kdc.cer
```

The output is the certificate alone, PEM-encoded, which `certreq` accepts. See
[`management-trust.md`](management-trust.md) for `--trust`.

Check the extensions before installing:

```sh
openssl x509 -in dc01-kdc.cer -noout -ext subjectAltName,extendedKeyUsage,authorityInfoAccess
```

Expect `Signing KDC Response` and `Microsoft Smartcard Login` among the EKUs,
`othername: 1.3.6.1.5.2.2:<unsupported>` next to the DNS names, and the
`CA Issuers` URI under your `revocation_base_url`.

## Trusting the chain

The DC and the clients must trust the root, and Windows must be able to find
the issuing CA certificate: publish it, or let clients fetch it from the AIA
caIssuers URI. From an account with Enterprise Admins rights:

```powershell
certutil -dspublish -f root.cer RootCA
certutil -dspublish -f issuing.cer SubCA
# for smart-card logon and PKINIT, the CA that issues the KDC and user
# certificates must also be in NTAuth:
certutil -dspublish -f issuing.cer NTAuthCA
```

Domain members pick these up at the next Group Policy refresh
(`gpupdate /force`, or `certutil -pulse`).

## Installing with certreq -accept

Copy the `.cer` files back to the DC and accept them into the computer's store,
which pairs each one with its pending key:

```powershell
certreq -accept -machine dc01-ldaps.cer
certreq -accept -machine dc01-kdc.cer
certutil -store My
certutil -verify -urlfetch dc01-kdc.cer
```

`certutil -verify -urlfetch` fetches the CRL, OCSP and AIA URLs and should end
with no errors. `certreq -accept` fails with a chain error if the root is not
yet trusted on the DC.

To have AD DS load the LDAPS certificate without a reboot, apply an LDIF that
sets `renewServerCertificate` on the rootDSE. `renew.ldf`:

```ldif
dn:
changetype: modify
add: renewServerCertificate
renewServerCertificate: 1
-
```

```powershell
ldifde -i -f renew.ldf
```

The KDC chooses its certificate when the service starts, so restart it to pick
up the new one:

```powershell
Restart-Service kdc
```

Check LDAPS from a Linux host:

```sh
openssl s_client -connect dc01.ad.example.org:636 -CAfile root.pem </dev/null
```

## Renewal

Repeat the request, issue and accept steps before the certificate expires. The
old certificate can stay in the store until it expires; revoke it with
`cryptosctl ca revoke` if it has to go sooner.
