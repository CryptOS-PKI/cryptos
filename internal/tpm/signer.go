package tpm

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

import (
	"crypto"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// Public satisfies crypto.Signer. It returns *ecdsa.PublicKey (curve P-384)
// for an AlgorithmECDSAP384 key and *rsa.PublicKey for an RSA key.
func (k *Key) Public() crypto.PublicKey {
	if k == nil {
		return nil
	}
	return k.pub
}

// Sign satisfies crypto.Signer, delegating the private-key operation to
// TPM2_Sign.
//
// For an AlgorithmECDSAP384 key the digest must be SHA-384 (48 bytes) and opts
// is not consulted; the result is a DER-encoded SEQUENCE { r INTEGER,
// s INTEGER }, the form crypto/x509.CreateCertificate stores.
//
// For an RSA key opts is required: its hash (SHA-256, SHA-384 or SHA-512) must
// match the digest length, and *rsa.PSSOptions selects RSASSA-PSS where any
// other opts selects RSASSA-PKCS1-v1_5. The TPM applies the padding. The raw
// signature is returned, and only after it verifies against the public key, so
// a faulty signature is never released.
//
// The rand argument is required by the interface but unused: the TPM sources
// its own randomness.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k == nil || k.tpm == nil {
		return nil, ErrClosed
	}
	switch pub := k.pub.(type) {
	case *rsa.PublicKey:
		return k.signRSA(pub, digest, opts)
	default:
		if k.alg != AlgorithmECDSAP384 {
			return nil, fmt.Errorf("tpm: Sign: unsupported KeyAlgorithm %d", k.alg)
		}
		return k.signECDSA(digest)
	}
}

func (k *Key) signECDSA(digest []byte) ([]byte, error) {
	if len(digest) != 48 {
		return nil, fmt.Errorf("tpm: Sign: digest must be 48 bytes (SHA-384) for P-384, got %d", len(digest))
	}
	resp, err := k.tpmSign(digest, tpm2.TPMAlgECDSA, tpm2.TPMAlgSHA384)
	if err != nil {
		return nil, err
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

func (k *Key) signRSA(pub *rsa.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("tpm: Sign: an RSA key needs crypto.SignerOpts to name the hash and padding")
	}
	hash := opts.HashFunc()
	hashAlg, err := tpmHashAlg(hash)
	if err != nil {
		return nil, err
	}
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("tpm: Sign: digest is %d bytes, want %d for %v", len(digest), hash.Size(), hash)
	}

	pss, isPSS := opts.(*rsa.PSSOptions)
	scheme := tpm2.TPMAlgRSASSA
	if isPSS {
		scheme = tpm2.TPMAlgRSAPSS
	}
	resp, err := k.tpmSign(digest, scheme, hashAlg)
	if err != nil {
		return nil, err
	}

	var rsaSig *tpm2.TPMSSignatureRSA
	if isPSS {
		rsaSig, err = resp.Signature.Signature.RSAPSS()
	} else {
		rsaSig, err = resp.Signature.Signature.RSASSA()
	}
	if err != nil {
		return nil, fmt.Errorf("tpm: Sign: extract RSA signature: %w", err)
	}
	sig := rsaSig.Sig.Buffer

	// The TPM chooses its own PSS salt length, so a caller that pinned a
	// different one is refused here rather than handed a signature its own
	// verifier rejects. The same check keeps a faulty signature from ever
	// leaving the signer.
	if isPSS {
		err = rsa.VerifyPSS(pub, hash, digest, sig, pss)
	} else {
		err = rsa.VerifyPKCS1v15(pub, hash, digest, sig)
	}
	if err != nil {
		return nil, fmt.Errorf("tpm: Sign: TPM signature does not verify under the requested scheme: %w", err)
	}
	return sig, nil
}

// tpmSign runs TPM2_Sign over an externally computed digest.
func (k *Key) tpmSign(digest []byte, scheme, hashAlg tpm2.TPMAlgID) (*tpm2.SignResponse, error) {
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
			Scheme:  scheme,
			Details: tpm2.NewTPMUSigScheme(scheme, &tpm2.TPMSSchemeHash{HashAlg: hashAlg}),
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
	return resp, nil
}

// tpmHashAlg maps a SHA-2 crypto.Hash to its TPM algorithm ID. Anything else
// is refused: a CA signature over SHA-1 is not acceptable.
func tpmHashAlg(h crypto.Hash) (tpm2.TPMAlgID, error) {
	switch h {
	case crypto.SHA256:
		return tpm2.TPMAlgSHA256, nil
	case crypto.SHA384:
		return tpm2.TPMAlgSHA384, nil
	case crypto.SHA512:
		return tpm2.TPMAlgSHA512, nil
	default:
		return 0, fmt.Errorf("tpm: Sign: unsupported hash %v for an RSA key (want SHA-256, SHA-384 or SHA-512)", h)
	}
}

// ecdsaSignature is the ASN.1 SEQUENCE encoding of an ECDSA signature.
type ecdsaSignature struct {
	R, S *big.Int
}
