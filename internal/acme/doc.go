// Package acme implements the server side of ACME (RFC 8555) so clients can
// enrol against this node without an operator ferrying CSRs by hand.
//
// It is a wire-format adapter and nothing more. The package never loads a key,
// never builds a certificate template, and never decides an extension: it
// parses JWS, runs the order/authorization state machine, proves control of an
// identifier, and then hands a CSR to an injected issuance closure. That
// closure is node.CASigner.IssueLeaf in production, so ca.Profile remains the
// single place extensions are decided and every ACME-issued certificate lands
// in the revocation issued set exactly as an operator-ferried one does.
//
// Dependencies are stdlib only. internal/ca/doc.go allows a wire-format
// library for a protocol adapter, but JWS verification is the security
// boundary of the whole protocol -- a client's signature over a request is the
// only thing standing between an anonymous caller and an order -- so it is
// implemented here against a strict algorithm allowlist rather than delegated.
// See jws.go.
//
// Implemented: directory, new-nonce, new-account (with External Account
// Binding, RFC 8555 section 7.3.4), new-order, authorization, the http-01
// challenge, finalize, certificate download, and revoke-cert.
//
// Not implemented: key change (section 7.3.5), account and authorization
// deactivation, dns-01, and wildcard identifiers (http-01 cannot prove control
// of a wildcard, so they are refused at order time).
package acme

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
