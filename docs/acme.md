# ACME enrolment (RFC 8555)

A node with ACME configured lets clients enrol and renew on their own, instead
of an operator moving every CSR by hand through `cryptosctl`. The usual clients
all work: certbot, lego and acme.sh on Linux; win-acme, Posh-ACME and Certify
The Web on Windows — with no AD CS anywhere in the chain.

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

`base_url` must be what clients dial, not what the node binds. Every URL the
server hands out is built from it, and every request carries a signature over
the URL it was sent to, so a `base_url` that does not match the front end
breaks every request rather than degrading quietly.

`http_port` is the origin port behind your TLS terminator. It defaults to 8555
and is deliberately not 80: port 80 belongs to the CRL/OCSP listener, which has
to stay where the CDP pointers in already-issued certificates say it is.

### Generating an external account key

Accounts require an External Account Binding by default. An open ACME endpoint
on an internal CA is a broad grant, so the binding is what decides *who* may
enrol, while the `http-01` challenge decides *what* they may enrol for.

```sh
head -c 32 /dev/urandom | basenc --base64url | tr -d '='
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
- **The `pki.acme` block is not yet carried in the proto machine config**, so
  it survives a staged YAML boot but not an `ApplyConfig` from a manager.
