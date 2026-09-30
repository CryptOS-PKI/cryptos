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

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	// Registered so crypto.Hash.New works for every digest the package
	// accepts.
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// Content types (RFC 5652 sections 4, 5 and 6; RFC 3161 section 2.4.2).
var (
	OIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// Attribute types (RFC 5652 section 11).
var (
	OIDAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// Digest algorithms (RFC 5754 section 2).
var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// Signature and key-transport algorithms (RFC 3370 section 3.2 and 4.2.1,
// RFC 5754 section 3, RFC 5758 section 3.2).
var (
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// Content-encryption algorithms (RFC 3565 section 4.1).
var (
	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// digestOIDs is the whole digest allowlist. SHA-1 and MD5 are absent on
// purpose: SCEP (RFC 8894) and RFC 3161 clients can both use SHA-256 or
// better, and a trust anchor has no reason to accept broken digests.
var digestOIDs = []struct {
	oid  asn1.ObjectIdentifier
	hash crypto.Hash
}{
	{oidSHA256, crypto.SHA256},
	{oidSHA384, crypto.SHA384},
	{oidSHA512, crypto.SHA512},
}

func hashForDigestOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	for _, d := range digestOIDs {
		if d.oid.Equal(oid) {
			return d.hash, nil
		}
	}
	return 0, fmt.Errorf("%w: digest %s", ErrUnsupportedAlgorithm, oid)
}

func digestOIDForHash(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	for _, d := range digestOIDs {
		if d.hash == h {
			return d.oid, nil
		}
	}
	return nil, fmt.Errorf("%w: digest %s", ErrUnsupportedAlgorithm, h)
}

// digestAlgorithm is the AlgorithmIdentifier for h. RFC 5754 section 2 says
// the parameters SHOULD be absent.
func digestAlgorithm(h crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	oid, err := digestOIDForHash(h)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}
	return pkix.AlgorithmIdentifier{Algorithm: oid}, nil
}

type signatureKind int

const (
	sigRSA signatureKind = iota + 1
	sigECDSA
)

// signatureScheme resolves a SignerInfo signatureAlgorithm. The bare
// rsaEncryption OID is what OpenSSL and most SCEP clients write (RFC 3370
// section 3.2 allows it); it carries no hash, so digestAlgorithm decides.
// The hash-specific OIDs must agree with digestAlgorithm, or the SignerInfo
// is inconsistent and refused.
func signatureScheme(oid asn1.ObjectIdentifier, digest crypto.Hash) (signatureKind, error) {
	pinned := []struct {
		oid  asn1.ObjectIdentifier
		kind signatureKind
		hash crypto.Hash
	}{
		{oidSHA256WithRSA, sigRSA, crypto.SHA256},
		{oidSHA384WithRSA, sigRSA, crypto.SHA384},
		{oidSHA512WithRSA, sigRSA, crypto.SHA512},
		{oidECDSAWithSHA256, sigECDSA, crypto.SHA256},
		{oidECDSAWithSHA384, sigECDSA, crypto.SHA384},
		{oidECDSAWithSHA512, sigECDSA, crypto.SHA512},
	}
	if oid.Equal(oidRSAEncryption) {
		return sigRSA, nil
	}
	for _, p := range pinned {
		if p.oid.Equal(oid) {
			if p.hash != digest {
				return 0, fmt.Errorf("%w: signature algorithm %s does not match digest %s", ErrUnsupportedAlgorithm, oid, digest)
			}
			return p.kind, nil
		}
	}
	return 0, fmt.Errorf("%w: signature %s", ErrUnsupportedAlgorithm, oid)
}

// signatureAlgorithm is the AlgorithmIdentifier this package writes. RSA
// takes the hash-specific OID with NULL parameters (RFC 5754 section 3.2);
// ECDSA takes ecdsa-with-SHAx with the parameters absent (RFC 5758 section
// 3.2).
func signatureAlgorithm(kind signatureKind, h crypto.Hash) pkix.AlgorithmIdentifier {
	switch kind {
	case sigRSA:
		oid := map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA256: oidSHA256WithRSA, crypto.SHA384: oidSHA384WithRSA, crypto.SHA512: oidSHA512WithRSA}[h]
		return pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue}
	default:
		oid := map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA256: oidECDSAWithSHA256, crypto.SHA384: oidECDSAWithSHA384, crypto.SHA512: oidECDSAWithSHA512}[h]
		return pkix.AlgorithmIdentifier{Algorithm: oid}
	}
}
