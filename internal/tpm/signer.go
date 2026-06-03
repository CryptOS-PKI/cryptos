package tpm

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
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// Public satisfies crypto.Signer. Returns the loaded key's ECDSA public
// key (with curve set to elliptic.P384 for AlgorithmECDSAP384).
func (k *Key) Public() crypto.PublicKey {
	if k == nil {
		return nil
	}
	return k.pub
}

// Sign satisfies crypto.Signer. The digest must be SHA-384 for an
// AlgorithmECDSAP384 key (48 bytes); shorter or longer inputs are
// rejected.
//
// The rand argument is required by the interface but unused — randomness
// for ECDSA signing is sourced from the TPM itself.
//
// Returns a DER-encoded SEQUENCE { r INTEGER, s INTEGER } suitable for
// embedding directly into an X.509 certificate signature field — i.e.
// the form crypto/x509.CreateCertificate stores.
func (k *Key) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if k == nil || k.tpm == nil {
		return nil, ErrClosed
	}
	if k.alg != AlgorithmECDSAP384 {
		return nil, fmt.Errorf("tpm: Sign: unsupported KeyAlgorithm %d", k.alg)
	}
	if len(digest) != 48 {
		return nil, fmt.Errorf("tpm: Sign: digest must be 48 bytes (SHA-384) for P-384, got %d", len(digest))
	}
	rwc, err := k.tpm.transport()
	if err != nil {
		return nil, err
	}

	resp, err := (tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: k.handle,
			Name:   k.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA384,
			}),
		},
		// Empty hash-check ticket; this key is not restricted so the TPM
		// accepts an externally-computed digest.
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm: Sign: TPM2_Sign: %w", err)
	}

	ecdsaSig, err := resp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("tpm: Sign: extract ECDSA signature: %w", err)
	}

	r := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)

	// DER-encode SEQUENCE { r INTEGER, s INTEGER } — the form
	// crypto/x509.CreateCertificate expects from a crypto.Signer.
	der, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("tpm: Sign: marshal signature: %w", err)
	}
	return der, nil
}

// ecdsaSignature is the ASN.1 SEQUENCE encoding of an ECDSA signature.
type ecdsaSignature struct {
	R, S *big.Int
}
