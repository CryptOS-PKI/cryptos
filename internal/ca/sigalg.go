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
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// MinRSAIssuerKeyBits is the smallest RSA issuer key this package will sign
// with. 2048 is the floor below which an RSA CA key is not defensible; larger
// sizes are preferred and get a stronger digest (see SignatureAlgorithmFor).
const MinRSAIssuerKeyBits = 2048

// RSASHA384MinBits is the issuer modulus size at or above which SHA-384 is
// paired with RSA instead of SHA-256. Both are SHA-2 and both are widely
// accepted; pairing the digest with the key size keeps the two at a comparable
// strength rather than capping a 3072-bit or 4096-bit key at SHA-256.
const RSASHA384MinBits = 3072

// SignatureAlgorithmFor returns the signature algorithm an issuer holding pub
// must use to sign, and reports an error when pub is not an acceptable issuer
// key.
//
// The signature on a certificate is produced by the ISSUER's key, so the
// algorithm is a property of that key and cannot be chosen independently of
// it. This matters beyond style: platform CAs exist that accept only SHA-2 RSA
// signatures and reject the whole ECDSA family, so they cannot verify a chain
// signed by an ECDSA issuer. Subordinating one of them requires an RSA issuer
// at every level of the chain it must walk, because an RSA subordinate under
// an ECDSA parent still carries an ECDSA signature on itself.
//
// ECDSA is accepted on P-384 only, paired with SHA-384 -- unchanged from when
// that was the only supported issuer key. RSA is accepted at
// MinRSAIssuerKeyBits or above.
func SignatureAlgorithmFor(pub crypto.PublicKey) (x509.SignatureAlgorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P384() {
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("issuer ECDSA key must be on P-384, got %s", k.Curve.Params().Name)
		}
		return x509.ECDSAWithSHA384, nil
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < MinRSAIssuerKeyBits {
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("issuer RSA key must be at least %d bits, got %d", MinRSAIssuerKeyBits, bits)
		}
		if bits >= RSASHA384MinBits {
			return x509.SHA384WithRSA, nil
		}
		return x509.SHA256WithRSA, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("issuer public key must be *ecdsa.PublicKey or *rsa.PublicKey, got %T", pub)
	}
}
