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
	"crypto/x509"
	"fmt"
	"io"

	"github.com/CryptOS-PKI/cryptos/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// softRootBackend generates and holds the Root CA key in software (nodeID/dev
// mode). The key is persisted by the ceremony to the LUKS-encrypted state
// partition; it is NOT hardware-protected. Dev tier only.
type softRootBackend struct{}

func (softRootBackend) ProvisionSRK() error { return nil }

func (softRootBackend) CreateKey(alg tpm.KeyAlgorithm) (*tpm.CreatedKey, error) {
	if alg != tpm.AlgorithmECDSAP384 {
		return nil, fmt.Errorf("softroot: CreateKey: unsupported algorithm %d (Phase 1 requires ECDSA-P384)", alg)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("softroot: generate key: %w", err)
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("softroot: marshal private: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("softroot: marshal public: %w", err)
	}
	// No TPM creation attestation for a software key.
	return &tpm.CreatedKey{Private: privDER, Public: pubDER}, nil
}

func (softRootBackend) LoadKey(private, _ []byte) (ceremony.RootSigner, error) {
	priv, err := x509.ParseECPrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("softroot: parse private: %w", err)
	}
	return softRootSigner{priv}, nil
}

// softRootSigner is an *ecdsa.PrivateKey with a no-op Close, satisfying
// ceremony.RootSigner.
type softRootSigner struct{ *ecdsa.PrivateKey }

func (softRootSigner) Close() error { return nil }

// Public and Sign are promoted from the embedded *ecdsa.PrivateKey.
var _ ceremony.RootSigner = softRootSigner{}
var _ io.Closer = softRootSigner{}
var _ crypto.Signer = softRootSigner{}
