package init

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
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/CryptOS-PKI/cryptos/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// NewSoftRootBackend returns the software (nodeID/dev-mode) Root-key backend as
// a ceremony.RootKeyBackend. It is the same backend production selects in
// nodeID mode (see run.go newStateKeyBackends); exposing a constructor lets the
// hierarchy end-to-end test drive the real ceremony with a CGO-free key
// backend, without exporting the concrete type or duplicating its logic.
func NewSoftRootBackend() ceremony.RootKeyBackend { return softRootBackend{} }

// softRootBackend generates and holds the Root CA key in software (nodeID/dev
// mode). The key is persisted by the ceremony to the LUKS-encrypted state
// partition; it is NOT hardware-protected. Dev tier only.
type softRootBackend struct{}

func (softRootBackend) ProvisionSRK() error { return nil }

func (softRootBackend) CreateKey(alg tpm.KeyAlgorithm) (*tpm.CreatedKey, error) {
	var (
		priv    crypto.Signer
		privDER []byte
		err     error
	)
	switch bits, isRSA := tpm.RSAKeyBits(alg); {
	case isRSA:
		var k *rsa.PrivateKey
		if k, err = rsa.GenerateKey(rand.Reader, bits); err != nil {
			return nil, fmt.Errorf("softroot: generate key: %w", err)
		}
		// PKCS#8 rather than PKCS#1 so one encoding covers every algorithm
		// this backend may hold. ECDSA keys keep their existing SEC1
		// encoding so blobs already on disk stay readable.
		if privDER, err = x509.MarshalPKCS8PrivateKey(k); err != nil {
			return nil, fmt.Errorf("softroot: marshal private: %w", err)
		}
		priv = k
	case alg == tpm.AlgorithmECDSAP384:
		var k *ecdsa.PrivateKey
		if k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
			return nil, fmt.Errorf("softroot: generate key: %w", err)
		}
		if privDER, err = x509.MarshalECPrivateKey(k); err != nil {
			return nil, fmt.Errorf("softroot: marshal private: %w", err)
		}
		priv = k
	default:
		return nil, fmt.Errorf("softroot: CreateKey: unsupported algorithm %d", alg)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("softroot: marshal public: %w", err)
	}
	// No TPM creation attestation for a software key.
	return &tpm.CreatedKey{Private: privDER, Public: pubDER}, nil
}

// LoadKey parses a private key blob written by CreateKey. SEC1 is tried first
// so ECDSA keys persisted before RSA support was added keep loading unchanged;
// PKCS#8 covers the RSA keys.
func (softRootBackend) LoadKey(private, _ []byte) (ceremony.RootSigner, error) {
	if priv, err := x509.ParseECPrivateKey(private); err == nil {
		return softRootSigner{priv}, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("softroot: parse private: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("softroot: parse private: key of type %T cannot sign", parsed)
	}
	return softRootSigner{signer}, nil
}

// softRootSigner is a crypto.Signer with a no-op Close, satisfying
// ceremony.RootSigner.
type softRootSigner struct{ crypto.Signer }

func (softRootSigner) Close() error { return nil }

// Public and Sign are promoted from the embedded crypto.Signer.
var _ ceremony.RootSigner = softRootSigner{}
var _ io.Closer = softRootSigner{}
var _ crypto.Signer = softRootSigner{}
