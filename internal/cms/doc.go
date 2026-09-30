// Package cms is a hand-written subset of the Cryptographic Message Syntax
// (RFC 5652): exactly what SCEP (RFC 8894), EST (RFC 7030) and RFC 3161
// time-stamp tokens need, and nothing else.
//
// It covers:
//
//   - SignedData: parse and verify (content-type and message-digest
//     attribute checks, signers identified by issuer and serial number or
//     by subject key identifier); build with signed attributes; and the
//     degenerate form that carries only certificates and CRLs.
//   - EnvelopedData: parse, decrypt and build, with RSA PKCS#1 v1.5 key
//     transport and AES-128-CBC or AES-256-CBC content encryption.
//   - The content types id-data, id-signedData, id-envelopedData and
//     id-ct-TSTInfo.
//
// Algorithms are an allowlist: SHA-256, SHA-384 and SHA-512 digests; RSA
// PKCS#1 v1.5 and ECDSA signatures; RSA PKCS#1 v1.5 key transport; AES-CBC.
// SHA-1, MD5, DES and 3DES are refused with ErrUnsupportedAlgorithm.
//
// The package is standard library only (encoding/asn1 and crypto/...).
// Third-party CMS libraries sign and decrypt with keys they hold; here the
// caller passes a crypto.Signer or crypto.Decrypter, so a key can stay in
// the TPM and never reaches this code.
//
// Input may be BER, as streaming encoders produce: every parse first
// rewrites indefinite lengths and chunked OCTET STRINGs to DER. A DER input
// is left byte-for-byte unchanged, so signatures over it still verify.
//
// The package does not log. Its callers are protocol handlers that already
// log each request; errors here carry structure only, never content,
// plaintext or key material, so they are safe for those handlers to log.
//
// Verification proves who signed, not whether they are trusted: path
// validation, key usage, validity and revocation are the caller's policy.
package cms

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
