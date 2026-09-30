# EST enrolment (RFC 7030)

EST is the enrolment protocol for clients that renew with the certificate they
already hold. That is the capability neither of the other two paths offers:
ACME proves control of a name but needs a challenge the client can answer, and
SCEP needs an admin to mint a one-time challenge for every initial enrolment.

Use EST where a fleet is provisioned once and then renews itself for years:
network gear, appliances, anything with a factory or first-boot identity.

> [!NOTE]
> Scope: `/cacerts`, `/simpleenroll`, `/simplereenroll` and `/csrattrs`.
> Server-side key generation and the deferred-enrolment 202 flow are not
> implemented.

## The two ways in, and what each one proves

| | Authenticated by | Names it may request |
|---|---|---|
| `simpleenroll` | An operator-provisioned HTTP Basic credential | Anything in `allowed_identifier_suffixes` |
| `simplereenroll` | A TLS client certificate this CA issued | Exactly the names already on that certificate |

The asymmetry is the point. `simplereenroll` is safe to leave open to the
fleet, because a certificate can only ever renew itself: the server refuses a
CSR that asks for any name the presented certificate does not already carry,
so holding one certificate never becomes a way to mint another. It also
refuses a certificate that is expired or revoked, which a TLS handshake alone
would happily accept.

`simpleenroll` has no equivalent. Nothing about a Basic credential proves the
client controls the name it is asking for, so whoever holds that credential
can obtain a certificate for any name the policy permits. That is why the
identifier allowlist is mandatory when credentials are configured, and why
turning it off needs `allow_any_identifier` spelled out.

A perfectly good deployment configures no credentials at all: enrol through
ACME, renew through EST.

## Configuring it

EST is off unless the `pki.est` block is present.

```yaml
pki:
  profiles:
    - name: leaf-server
      key_alg: ECDSA-P384
      validity_days: 90
      key_usage: [digital_signature]
      ext_key_usage: [server_auth, client_auth]
  est:
    hostnames: [est.example.org, 10.0.0.10]
    http_port: 8443
    profile: leaf-server
    realm: acme corp est
    allowed_identifier_suffixes: [example.org]
    enroll_credentials:
      - username: switch-fleet
        password_sha256: <64 hex characters>
```

> [!IMPORTANT]
> The profile needs `client_auth` in `ext_key_usage` if the certificates it
> issues are themselves going to re-enrol later: `simplereenroll` verifies the
> presented certificate for client authentication, and one issued without that
> usage cannot renew itself.

`hostnames` matters more here than elsewhere. Unlike the ACME listener, which
sits behind your TLS terminator, this one terminates TLS itself, because
`simplereenroll` needs the client certificate to reach the handler. The node
mints its own server certificate for those names, signed by its own CA and
renewed in place, so a client that trusts the CA also trusts the listener with
no extra anchor. A name missing from this list is a name clients cannot
verify.

The listener's own key follows the CA's key algorithm, because that key signs
the handshake: on an RSA CA it is an RSA-3072 key, so a client that rejects the
ECDSA family can complete the handshake and not merely verify the chain. That
key is generated when the listener starts rather than inside the handshake,
since an RSA key generation there would stall the first client to connect.

The listener requests but does not require a client certificate: `/cacerts`
exists for a client that holds nothing yet, so demanding one at the handshake
would lock out exactly the callers that endpoint is for. TLS 1.2 is the floor
rather than 1.3, because RFC 7030 predates 1.3 and the embedded clients EST
exists to serve commonly top out at 1.2.

### Provisioning a simpleenroll credential

> [!CAUTION]
> The config holds the SHA-256 of the password, not the password, so a running
> configuration never contains a live credential. That is only safe because the
> password has to be generated rather than chosen: a digest of a memorable word
> falls to a dictionary in seconds.

**Linux / macOS**

```bash
PASSWORD=$(head -c 24 /dev/urandom | basenc --base64url | tr -d '=')
printf '%s' "$PASSWORD" | sha256sum | cut -d' ' -f1
echo "password: $PASSWORD"
```

**Windows (PowerShell)**

```powershell
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$PASSWORD = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$sha = [System.Security.Cryptography.SHA256]::Create()
-join ($sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($PASSWORD)) | ForEach-Object { $_.ToString('x2') })
"password: $PASSWORD"
```

Put the digest in `password_sha256` and give the password to whoever runs the
client. Keep it out of the config.

## Fetching the CA

`/cacerts` is unauthenticated, which is correct: a client that does not yet
trust this CA has to be able to fetch it, and the certificates it returns are
public by definition. On first contact a client either trusts the response
explicitly out of band or already holds the CA from provisioning.

**Linux / macOS**

```bash
curl -s https://est.example.org:8443/.well-known/est/cacerts \
  | base64 -d \
  | openssl pkcs7 -inform DER -print_certs -noout
```

**Windows (PowerShell)**

```powershell
curl.exe -s https://est.example.org:8443/.well-known/est/cacerts -o cacerts.b64
openssl base64 -d -A -in cacerts.b64 -out cacerts.p7b
openssl pkcs7 -inform DER -in cacerts.p7b -print_certs -noout
```

## Enrolling

`simpleenroll`, with a provisioned credential:

**Linux / macOS**

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
  -keyout switch01.key -subj "/CN=switch01.example.org" \
  -addext "subjectAltName=DNS:switch01.example.org" -outform DER -out switch01.csr

curl -s --cacert ca.pem \
  -u "switch-fleet:$PASSWORD" \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  --data-binary "$(base64 -w0 switch01.csr)" \
  https://est.example.org:8443/.well-known/est/simpleenroll \
  | base64 -d | openssl pkcs7 -inform DER -print_certs -out switch01.pem
```

**Windows (PowerShell)**

```powershell
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes `
  -keyout switch01.key -subj "/CN=switch01.example.org" `
  -addext "subjectAltName=DNS:switch01.example.org" -outform DER -out switch01.csr

openssl base64 -A -in switch01.csr -out switch01.csr.b64
curl.exe -s --cacert ca.pem `
  -u "switch-fleet:$PASSWORD" `
  -H "Content-Type: application/pkcs10" `
  -H "Content-Transfer-Encoding: base64" `
  --data-binary "@switch01.csr.b64" `
  https://est.example.org:8443/.well-known/est/simpleenroll `
  -o switch01.b64
openssl base64 -d -A -in switch01.b64 -out switch01.p7b
openssl pkcs7 -inform DER -in switch01.p7b -print_certs -out switch01.pem
```

`simplereenroll`, authenticated by the certificate being replaced:

```sh
curl -s --cacert ca.pem \
  --cert switch01.pem --key switch01.key \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  --data-binary "$(base64 -w0 renewal.csr)" \
  https://est.example.org:8443/.well-known/est/simplereenroll \
  | base64 -d | openssl pkcs7 -inform DER -print_certs -out switch01-new.pem
```

The renewal CSR must carry the same names as `switch01.pem`. A CSR asking for
anything else is refused with 403 rather than quietly issued for a subset.

## Serving several CAs from one host

RFC 7030 allows an arbitrary label between `/.well-known/est` and the
operation. Set `label: issuing` and every path moves under
`/.well-known/est/issuing/`. The unlabelled paths then return 404, so a label
is routing rather than decoration.

## Switching it on, changing it and switching it off

EST runs on an intermediate or issuing node only. A Root serves no enrolment
protocol, so a config that sets `pki.est` on a Root is refused by
`config apply`, by the maintenance install and by `ceremony start --config`.

> [!CAUTION]
> Don't add `pki.est` to a Root's config. It is refused, and nothing is
> stored. Serve EST from an issuing node under that Root instead.

To switch EST on, add the `pki.est` block and run `config apply`. To
switch it off, remove the block and apply again. Over the API the block is
`Pki.est` with an explicit `enabled` flag: `enabled: false` switches it
off, and leaving the block out of an `ApplyConfig` keeps what the node has.

> [!WARNING]
> Every EST change, switching it on or off included, takes effect at the
> next reboot, not when you apply it. `config apply` stores the change and
> prints `requires_reboot=true`; the listener starts, stops or picks up the new
> settings only when the node boots again. Plan the reboot for a maintenance
> window, because the node stops issuing while it restarts, then use
> `cryptosctl reboot`.

`cryptosctl status` shows what is stored against what is running until then:

```text
Protocols:       ACME off, EST on (not running, reboot pending), SCEP off
Reboot:          pending (the stored config changes take effect at the next boot)
```

`password_sha256` is write-only. `cryptosctl config get` prints it blank, with its
`username`. Leave a blank value as it is and `config apply` keeps the one the
node stores for that `username`; set a value to replace it. A new `username`
needs its value, and an apply that leaves it blank is refused. Removing an
entry revokes it.

## Limits worth knowing before you deploy

- **Wildcards are refused.** Nothing in EST establishes control of a label
  space, and a wildcard obtained from a shared credential is a large grant
  from a small secret.
- **Non-DNS SANs are refused** rather than dropped, so a client is never
  handed back less than it asked for without being told.
- **`/csrattrs` returns 204.** This server imposes no attributes beyond what
  the profile stamps, and RFC 7030 section 4.5.2 says a server with nothing to
  say answers 204.
- **Issuance is synchronous.** There is no 202 Retry-After manual-approval
  flow; a request either yields a certificate or fails.
