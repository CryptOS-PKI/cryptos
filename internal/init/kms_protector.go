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
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/kms"
)

// kmsProtector envelope-encrypts the state key: it generates a random DEK (the
// LUKS key), seals it with an external KMS, and persists only the sealed blob
// plus the endpoint in a LUKS2 token. Later boots recover the DEK by unsealing
// the token's blob against the token's endpoint — the machine config is not
// read pre-unlock. Production tier for hosts without a usable TPM.
type kmsProtector struct {
	endpoint string
	trustPEM []byte
	// newProvider builds the seal/unseal Provider; it defaults to
	// kms.NewHTTPProvider and is overridable in tests.
	newProvider func(endpoint string, trustPEM []byte) (kms.Provider, error)
}

// kmsToken is the JSON persisted in the LUKS2 header token. It carries the
// endpoint and trust bundle so later boots can rebuild the Provider without the
// machine config, plus the sealed DEK blob.
type kmsToken struct {
	Endpoint string `json:"endpoint"`
	TrustPEM string `json:"trust_pem"`
	Sealed   []byte `json:"sealed"`
}

// newKMSProtector builds a kmsProtector from the machine-config KMS settings.
// It is used on first boot to provision (Seal) the DEK; later boots recover
// from the token and do not depend on cfg.
func newKMSProtector(cfg *config.KmsStateKey) (*kmsProtector, error) {
	if cfg == nil {
		return nil, errors.New("kms protector: nil kms config")
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("kms protector: endpoint is required")
	}
	return &kmsProtector{
		endpoint:    cfg.Endpoint,
		trustPEM:    []byte(cfg.TrustPEM),
		newProvider: kms.NewHTTPProvider,
	}, nil
}

// kmsProtector satisfies the state-key protector interface.
var _ StateKeyProtector = (*kmsProtector)(nil)

func (p *kmsProtector) Name() string        { return "kms" }
func (p *kmsProtector) PersistsToken() bool { return true }

func (p *kmsProtector) provider(endpoint string, trustPEM []byte) (kms.Provider, error) {
	if p.newProvider != nil {
		return p.newProvider(endpoint, trustPEM)
	}
	return kms.NewHTTPProvider(endpoint, trustPEM)
}

// ProvisionKey generates a 32-byte DEK, seals it with the configured KMS, and
// returns the DEK plus a token JSON carrying the endpoint, trust bundle, and
// sealed blob. The DEK plaintext is never persisted.
func (p *kmsProtector) ProvisionKey(ctx context.Context) (key, token []byte, err error) {
	provider, err := p.provider(p.endpoint, p.trustPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("kms: build provider: %w", err)
	}
	key = make([]byte, stateKeyBytes)
	if _, err = rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("kms: generate key: %w", err)
	}
	sealed, err := provider.Seal(ctx, key)
	if err != nil {
		wipe(key)
		return nil, nil, fmt.Errorf("kms: seal: %w", err)
	}
	token, err = json.Marshal(kmsToken{
		Endpoint: p.endpoint,
		TrustPEM: string(p.trustPEM),
		Sealed:   sealed,
	})
	if err != nil {
		wipe(key)
		return nil, nil, fmt.Errorf("kms: marshal token: %w", err)
	}
	return key, token, nil
}

// RecoverKey rebuilds the Provider from the persisted token (NOT from config,
// since later boots have no config pre-unlock) and unseals the DEK.
func (p *kmsProtector) RecoverKey(ctx context.Context, tokenJSON []byte) ([]byte, error) {
	var tok kmsToken
	if err := json.Unmarshal(tokenJSON, &tok); err != nil {
		return nil, fmt.Errorf("kms: parse token: %w", err)
	}
	if tok.Endpoint == "" {
		return nil, errors.New("kms: token has no endpoint")
	}
	if len(tok.Sealed) == 0 {
		return nil, errors.New("kms: token has no sealed blob")
	}
	provider, err := p.provider(tok.Endpoint, []byte(tok.TrustPEM))
	if err != nil {
		return nil, fmt.Errorf("kms: build provider: %w", err)
	}
	key, err := provider.Unseal(ctx, tok.Sealed)
	if err != nil {
		return nil, fmt.Errorf("kms: unseal: %w", err)
	}
	return key, nil
}
