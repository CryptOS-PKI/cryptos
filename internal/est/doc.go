// Package est implements the server side of EST (RFC 7030), the enrolment
// protocol for clients that renew with the certificate they already hold
// rather than with a shared secret they have to keep.
//
// It sits between the other two enrolment paths. ACME covers anything with a
// modern client and can prove control of a name; SCEP covers legacy gear that
// can do nothing else. EST covers the middle: simplereenroll authenticated by
// the current certificate is the capability neither of the others offers.
//
// Like internal/acme this is a wire-format adapter that holds no key.
// Issuance, the CA chain and the revocation check all arrive as closures, so
// the protocol runs in tests with no CA behind it, and in production issuance
// goes through node.CASigner, leaving ca.Profile as the single place
// extensions are decided.
//
// Dependencies are stdlib only. The one thing EST needs that the standard
// library does not provide is a CMS writer, and it needs exactly one shape of
// it: the degenerate certs-only SignedData in pkcs7.go, which is a fixed
// ASN.1 envelope with a certificate set and no signers.
//
// # Authentication, and what it does and does not prove
//
// EST has no challenge. Authentication is the whole of the authorization, and
// the two entry points authenticate very differently:
//
//   - simplereenroll authenticates with a TLS client certificate that must
//     chain to this CA and must not be revoked. The CSR may then request only
//     the names already on that certificate, so a renewal cannot become an
//     escalation.
//
//   - simpleenroll authenticates with an operator-provisioned HTTP Basic
//     credential over TLS. Nothing proves the client controls the name it
//     asks for -- unlike an ACME http-01 challenge -- so whoever holds the
//     credential can obtain a certificate for any name the policy permits.
//     That is why the identifier allowlist is mandatory for simpleenroll
//     unless an operator turns it off by name.
//
// Implemented: /cacerts, /simpleenroll, /simplereenroll and /csrattrs.
//
// Not implemented: server-side key generation (/serverkeygen), certificate
// attribute requests beyond an empty /csrattrs, and the deferred-enrolment
// 202 Retry-After flow. Issuance here is synchronous or it fails.
package est

/*
Apache License 2.0

Copyright 2026 Shane

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
