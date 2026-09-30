# ACME enrolment (RFC 8555)

A node with ACME configured lets clients enrol and renew on their own, instead
of an operator moving every CSR by hand through `cryptosctl`. The usual clients
all work: certbot, lego and acme.sh on Linux; win-acme, Posh-ACME and Certify
The Web on Windows — with no AD CS anywhere in the chain.

> [!NOTE]
> Scope: `http-01` only. `dns-01` and wildcard names are not implemented, and a
> wildcard identifier is refused at order time rather than half-supported.

## What the node decides, and what the client decides

The client picks the names. Everything else comes from the certificate profile
you name in the config — key usage, extended key usage, validity, extra
extensions, and the CRL/OCSP pointers. An ACME order can never widen a profile;
it can only fill in the subject alternative names, and only names whose
challenge passed.

Every ACME-issued certificate is recorded in the same issued set as an
operator-ferried one, so it appears on the CRL, answers over OCSP, and can be
revoked either through `cryptosctl` or through ACME itself.

## Configuring it

ACME is off unless the `pki.acme` block is present. Add it to the machine
config alongside the profile it issues under:

```yaml
pki:
  revocation_base_url: https://ca.example.org
  profiles:
    - name: leaf-server
      key_alg: ECDSA-P384
      validity_days: 90
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
  acme:
    base_url: https://ca.example.org/acme
    http_port: 8555
    profile: leaf-server
    terms_of_service: https://example.org/ca-terms
    allowed_identifier_suffixes: [example.org]
    external_account_keys:
      - key_id: ops-team
        hmac_key_base64: <32+ bytes, base64url, no padding>
```

> [!IMPORTANT]
> `base_url` must be what clients dial, not what the node binds. Every URL the
> server hands out is built from it, and every request carries a signature over
> the URL it was sent to, so a `base_url` that does not match the front end
> breaks every request rather than degrading quietly.

`http_port` is the origin port behind your TLS terminator. It defaults to 8555
and is deliberately not 80: port 80 belongs to the CRL/OCSP listener, which has
to stay where the CDP pointers in already-issued certificates say it is.

### Generating an external account key

Accounts require an External Account Binding by default. An open ACME endpoint
on an internal CA is a broad grant, so the binding is what decides *who* may
enrol, while the `http-01` challenge decides *what* they may enrol for.

**Linux / macOS**

```bash
head -c 32 /dev/urandom | basenc --base64url | tr -d '='
```

**Windows (PowerShell)**

```powershell
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
```

Put the result in `hmac_key_base64` and hand the same value, with its `key_id`,
to whoever runs the client. Keys shorter than 32 bytes are rejected: nothing
rate-limits an offline guess against a captured binding.

To run without bindings — a closed lab, say — set
`allow_anonymous_accounts: true` explicitly. There is no way to end up
anonymous by leaving a field out.

### Restricting names

`allowed_identifier_suffixes` limits what the node will order for. A name must
equal an entry or be a subdomain of one, matched on a label boundary, so
`example.org` covers `web.example.org` but not `notexample.org`. Leave it out
to place no name restriction, in which case proof of control and the account
binding are the only gates.

## Enrolling with a client

`lego`, with an external account binding:

```sh
lego \
  --server https://ca.example.org/acme/directory \
  --email ops@example.org \
  --eab --kid ops-team --hmac "$EAB_HMAC" \
  --domains web.example.org \
  --http --http.port :80 \
  run
```

`certbot`:

```sh
certbot certonly --standalone \
  --server https://ca.example.org/acme/directory \
  --eab-kid ops-team --eab-hmac-key "$EAB_HMAC" \
  -d web.example.org
```

On Windows, `win-acme` and `Posh-ACME` take the same directory URL and the same
key ID and HMAC.

The challenge is fetched from `http://<name>:80/.well-known/acme-challenge/...`
as the node resolves the name. Port 80 is fixed by RFC 8555 and is not
configurable: control of a high port is not control of a name.

## Revoking

Either the account that ordered the certificate or the holder of the
certificate's own key may revoke it:

```sh
lego --server https://ca.example.org/acme/directory \
  --domains web.example.org revoke
```

Accepted reason codes are `unspecified` (0), `keyCompromise` (1),
`affiliationChanged` (3), `superseded` (4), `cessationOfOperation` (5) and
`privilegeWithdrawn` (9). `certificateHold` is refused: this CA has no hold
workflow, and accepting the request would imply one.

## Switching it on, changing it and switching it off

ACME runs on an intermediate or issuing node only. A Root serves no enrolment
protocol, so a config that switches `pki.acme` on at a Root is refused by
`config apply`, by the maintenance install and by `ceremony start --config`.

> [!CAUTION]
> Don't switch `pki.acme` on in a Root's config. It is refused, and nothing
> is stored. Serve ACME from an issuing node under that Root instead. A
> Root accepts a block with `enabled: false`, and never serves it.

To switch ACME on, add the `pki.acme` block and run `config apply`. To
switch it off and keep its settings, set `enabled: false` in the block and
apply again; to switch it back on, set `enabled: true` (or remove the line).
A block without `enabled` is on. Removing the block switches ACME off and
drops its settings.

```yaml
pki:
  acme:
    enabled: false
    # the rest of the block stays as it was
```

The node stores a switched-off block's settings and `config get` prints the
block with `enabled: false`, so flipping `enabled` alone is enough to switch
it back on. The Fleet Manager switches a protocol the same way. Nothing reads
a switched-off block at boot, so changing only its settings does not need a
reboot.

Over the API the block is `Pki.acme` with an explicit `enabled` flag.
`enabled: false` switches it off and keeps the settings sent with it, an
`enabled: false` block with no settings drops them, and leaving the block out
of an `ApplyConfig` keeps what the node has, on or off.

> [!WARNING]
> Every ACME change, switching it on or off included, takes effect at the
> next reboot, not when you apply it. `config apply` stores the change and
> prints `requires_reboot=true`; the listener starts, stops or picks up the new
> settings only when the node boots again. Plan the reboot for a maintenance
> window, because the node stops issuing while it restarts, then use
> `cryptosctl reboot`.

`cryptosctl status` shows what is stored against what is running until then:

```text
Protocols:       ACME on (not running, reboot pending), EST off, SCEP off
Reboot:          pending (the stored config changes take effect at the next boot)
```

`hmac_key_base64` is write-only, in a switched-off block too. `cryptosctl config get` prints it blank, with its
`key_id`. Leave a blank value as it is and `config apply` keeps the one the
node stores for that `key_id`; set a value to replace it. A new `key_id`
needs its value, and an apply that leaves it blank is refused. Removing an
entry revokes it.

## Limits worth knowing before you deploy

- **Key change is not implemented.** RFC 8555 section 7.3.5 is absent from the
  directory. A client that needs to roll its account key registers a new
  account.
- **Account and authorization deactivation are not implemented.**
- **Authorizations are never reused across orders.** Every order revalidates,
  which costs one fetch per name and means an authorization never outlives the
  order that justified it.
- **Validation runs inline on the challenge POST**, bounded by a ten-second
  timeout. The client's first poll already carries the answer.
