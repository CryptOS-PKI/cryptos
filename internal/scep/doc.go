// Package scep implements the server side of SCEP (RFC 8894), the enrolment
// protocol network equipment speaks: Cisco IOS and IOS-XE trustpoints, and
// most switch, router, firewall and VPN platforms that cannot run ACME.
//
// Implemented: GetCACaps, GetCACert (the CA and the RA certificate), and
// PKIOperation with PKCSReq, RenewalReq, CertPoll (GetCertInitial), GetCert
// and GetCRL. GetNextCACert is not offered. Content encryption is AES and
// signatures are SHA-256 or SHA-512 (SHA-384 is accepted too); DES, 3DES,
// MD5 and SHA-1 are refused by internal/cms.
//
// # Keys
//
// The CA key only signs certificates. Requests are encrypted to, and replies
// signed by, an RA certificate the node mints from its own CA: RSA 3072 with
// key usage digitalSignature and keyEncipherment, valid for a year, held on
// the encrypted state partition and rotated with an overlap during which the
// old and the new RA both decrypt (RAManager). The CMS work is internal/cms,
// which never holds a key: the RA key is passed in as a crypto.Signer and a
// crypto.Decrypter.
//
// # Authorization
//
// Initial enrolment (PKCSReq) is authorized by a one-time challenge an admin
// mints with MintScepChallenge. Only its SHA-256 is stored; it is single-use
// (consumed by the first request that presents it, whatever the outcome),
// expires, names the profile it issues from, and may be bound to the names it
// may request. Every name must also fall inside the configured allowlist,
// which is mandatory. Renewal (RenewalReq) is authorized by the certificate
// the device already holds: it must chain to this CA, be current and not be
// revoked, and the renewed certificate keeps its names and its profile. A
// PKCSReq signed by such a certificate is handled the same way: that is how
// renewal was done before RFC 8894 added RenewalReq, and how sscep and Cisco
// IOS rollover still do it. There is no static shared challenge.
//
// Each profile carries its own RSA key floor (2048 at the lowest, for Cisco
// trustpoints; 3072 by default), and may hold initial enrolments in a queue
// for an admin to approve or reject; the device is answered PENDING and polls.
//
// # Transactions
//
// Every transactionID is recorded with its outcome, so a retransmitted
// request or a CertPoll gets the same certificate rather than a second one,
// and a transactionID reused for a different key is refused. A request that
// fails is not recorded, so the device can try again with a fresh challenge.
//
// Issuance goes through the node's CA signer, so ca.Profile decides the
// extensions and every certificate is recorded for revocation before it is
// returned. Every decision is written to the audit log with the challenge id,
// never the challenge.
package scep

/*
Copyright The CryptOS Authors.

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
