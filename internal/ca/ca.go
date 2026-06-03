package ca

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// RootParams collects everything the caller (the ceremony layer) needs
// to provide to mint a Phase 1 Root certificate. The Signer is the
// TPM-backed crypto.Signer holding the just-created Root key.
type RootParams struct {
	// Signer is the TPM-backed signer holding the Root key. Required.
	Signer crypto.Signer

	// Subject is the X.500 DN — placed in both Subject and Issuer for
	// a self-signed Root.
	Subject pkix.Name

	// NotBefore is when validity begins; typically time.Now() truncated
	// to the second by the caller.
	NotBefore time.Time

	// NotAfter is when validity ends; typically NotBefore + years.
	NotAfter time.Time

	// PathLenConstraint is encoded into basicConstraints. Per RFC 5280
	// §4.2.1.9: 0 means "this CA may issue end-entity certs only,"
	// higher values bound the depth of further sub-CAs.
	PathLenConstraint int
}

// SelfSignRoot builds an RFC 5280-strict self-signed Root certificate
// using params.Signer to sign. Returns the DER and PEM forms.
//
// Phase 1 contract — the produced cert MUST:
//   - Be version 3.
//   - Carry a positive ~159-bit serial (≤20 octets DER, RFC 5280 §4.1.2.2).
//   - Use ecdsa-with-SHA384 as both signatureAlgorithm and tbsCertificate.signature.
//   - Have Issuer == Subject.
//   - Carry basicConstraints (CRITICAL): cA=true, pathLenConstraint set per params.
//   - Carry keyUsage (CRITICAL): keyCertSign | cRLSign — and ONLY those two.
//   - Carry subjectKeyIdentifier = SHA-1(SPKI BIT STRING) (RFC 5280 §4.2.1.2 method 1).
//   - Carry authorityKeyIdentifier with keyIdentifier == subjectKeyIdentifier.
//   - NOT carry extendedKeyUsage (CABF: Roots SHOULD NOT have EKU).
//   - NOT carry subjectAltName (a Root has no DNS identity).
func SelfSignRoot(params RootParams) (der []byte, pemBytes []byte, err error) {
	if params.Signer == nil {
		return nil, nil, errors.New("ca: SelfSignRoot: Signer is required")
	}
	pub, ok := params.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("ca: SelfSignRoot: Signer.Public() must be *ecdsa.PublicKey, got %T", params.Signer.Public())
	}
	if pub.Curve != elliptic.P384() {
		return nil, nil, fmt.Errorf("ca: SelfSignRoot: Phase 1 requires P-384, got %s", pub.Curve.Params().Name)
	}
	if params.NotBefore.IsZero() || params.NotAfter.IsZero() || !params.NotAfter.After(params.NotBefore) {
		return nil, nil, errors.New("ca: SelfSignRoot: NotBefore and NotAfter must be set, with NotAfter > NotBefore")
	}
	if params.PathLenConstraint < 0 {
		return nil, nil, fmt.Errorf("ca: SelfSignRoot: PathLenConstraint must be >= 0, got %d", params.PathLenConstraint)
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, nil, err
	}

	ski, err := subjectKeyIdentifier(pub)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               params.Subject,
		Issuer:                params.Subject, // self-signed
		NotBefore:             params.NotBefore.UTC().Truncate(time.Second),
		NotAfter:              params.NotAfter.UTC().Truncate(time.Second),
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            params.PathLenConstraint,
		MaxPathLenZero:        params.PathLenConstraint == 0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// No extKeyUsage on a Root (CABF guidance).
		// No subjectAltName on a Root.
		SubjectKeyId:   ski,
		AuthorityKeyId: ski, // == SKI for a self-signed Root.
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, params.Signer)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: SelfSignRoot: CreateCertificate: %w", err)
	}
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	return derBytes, pem.EncodeToMemory(pemBlock), nil
}

// generateSerial returns a positive integer with ~159 random bits so
// that the DER encoding fits in ≤20 octets (RFC 5280 §4.1.2.2).
//
// 20 octets DER = max 159 bits unsigned. We sample 20 bytes from
// crypto/rand and force the top bit clear so the SET BIT INTEGER
// encoding doesn't add a leading 0x00.
func generateSerial() (*big.Int, error) {
	const serialBytes = 20
	buf := make([]byte, serialBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("ca: generateSerial: rand: %w", err)
	}
	buf[0] &= 0x7f // clear top bit -> positive, DER length ≤20 octets
	if buf[0] == 0 {
		// SetBytes would lose the leading zero; force at least 1 there
		// so the result has full 159 bits and a non-trivial leading byte.
		buf[0] = 1
	}
	return new(big.Int).SetBytes(buf), nil
}

// subjectKeyIdentifier returns SHA-1 of the BIT STRING value of the
// SubjectPublicKeyInfo encoding of pub (RFC 5280 §4.2.1.2 method 1).
//
// Computing this ourselves rather than letting the stdlib default
// in CreateCertificate handle it removes a source of drift across
// Go releases and matches what other CAs produce for the same key.
//
//nolint:gosec // RFC 5280 §4.2.1.2 method 1 specifies SHA-1; not used for security.
func subjectKeyIdentifier(pub *ecdsa.PublicKey) ([]byte, error) {
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ca: subjectKeyIdentifier: MarshalPKIXPublicKey: %w", err)
	}
	var info subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(spkiDER, &info); err != nil {
		return nil, fmt.Errorf("ca: subjectKeyIdentifier: unmarshal SPKI: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("ca: subjectKeyIdentifier: trailing bytes after SPKI")
	}
	sum := sha1.Sum(info.SubjectPublicKey.Bytes)
	return sum[:], nil
}

// subjectPublicKeyInfo mirrors the RFC 5280 §4.1.2.7 structure so we
// can extract the SubjectPublicKey BIT STRING value (the raw key
// octets) without the algorithm wrapper.
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}
