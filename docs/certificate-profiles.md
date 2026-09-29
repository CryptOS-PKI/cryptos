# Certificate profiles

A certificate profile is a named template under `pki.profiles` in the machine
config. `cryptosctl ca issue-leaf`, `ca sign-subordinate`, ACME and EST all
issue from a profile, which sets everything about the certificate except its
subject and public key. Those two come from the CSR.

Profiles take effect as soon as they are applied. A change to profiles alone
does not require a reboot.

```yaml
pki:
  profiles:
    - name: platform-sub-ca
      key_alg: RSA-3072
      validity_days: 1825
      validity_policy: cap
      basic_constraints:
        is_ca: true
        path_len: 0
      key_usage: [digital_signature, cert_sign, crl_sign]
```

## Fields

| Field | Meaning |
|---|---|
| `name` | Required and unique. Callers select the profile by this name. |
| `key_alg` | Required: `ECDSA-P384`, `RSA-3072` or `RSA-4096`. Governs keys this node generates, not the subject keys it certifies. |
| `subject` | `common_name`, `organization`, `country`, `province`, `locality`. Used when the node builds a CSR; an issued certificate takes its subject from the CSR it signs. |
| `validity_days` | Required, greater than 0. The certificate's requested lifetime, counted from signing. It never runs past the issuing CA's own notAfter; see below. |
| `validity_policy` | `cap` (the default when omitted) or `reject`. What happens when `validity_days` would run past the issuing CA's notAfter; see below. |
| `basic_constraints` | `is_ca` marks a CA profile, which only `sign-subordinate` uses. `path_len` applies to CA profiles and is clamped to the budget the signing CA's own certificate leaves. |
| `key_usage` | Any of `digital_signature`, `key_encipherment`, `key_agreement`, `cert_sign`, `crl_sign`. |
| `ext_key_usage` | `server_auth`, `client_auth`, or dotted OIDs such as `1.3.6.1.5.2.3.5`. |
| `sans` | `dns`, `ip`, `email`, `uri`, `krb5_principal`, `upn`. These are stamped on every certificate the profile issues; SANs in the CSR are ignored. ACME and EST replace them with the names the client proved. |
| `extra_extensions` | Raw extensions (`oid`, `critical`, DER `value`) for anything not modelled above. |
| `allow_request_sans` | Leaf profiles only. Lets `issue-leaf --dns` replace the profile's SANs. See [`active-directory.md`](active-directory.md). |

## Validity and the issuing CA's notAfter

A certificate can't outlive the CA that signed it. Once the issuer expires,
chain validation fails, whatever the child's own notAfter says. So an
issuing node caps every certificate it signs at its own notAfter. This applies
on every path: `issue-leaf`, `sign-subordinate` (including re-certifying a
subordinate), ACME, EST, the delegated OCSP responder certificate and the EST
listener certificate. A self-signed root has no issuer and is never capped.

With `validity_policy: cap`, the default, the certificate is issued and ends at
the issuer's notAfter. `cryptosctl` prints a warning on stderr, and the
certificate on stdout is unchanged:

```
WARNING: requested validity ends 2046-09-22; capped to issuer notAfter 2041-09-21
```

The audit entry for the `IssueLeaf` or `SignSubordinateCSR` call records both
dates as `requested_not_after` and `effective_not_after`. ACME and EST issue the
capped certificate without a warning, because those protocols have no channel
for one. The client sees the shorter notAfter in the certificate itself.

With `validity_policy: reject`, the node refuses to issue instead. The call
fails with `FailedPrecondition` and a message naming both dates, before the CA
key is loaded:

```
node: profile "platform-sub-ca" has validity_policy reject: requested validity ends 2046-09-22, after issuer notAfter 2041-09-21
```

Use `reject` where a shortened certificate would cause trouble later. One
example is a platform CA whose renewal is planned around a fixed lifetime.

`cryptosctl config apply` also warns when a profile's `validity_days` already
runs past the node's CA certificate, for example:

```
WARNING: profile "platform-sub-ca": validity_days 7300 runs past this CA's notAfter 2041-09-21; its certificates will be capped to that date
```

This is a warning, not a validation error. The config is still applied,
because every profile eventually crosses the line as the CA's remaining
lifetime shrinks. A node that has no CA certificate yet gives no warning.
