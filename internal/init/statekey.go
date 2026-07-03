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
	"fmt"

	"github.com/CryptOS-PKI/cryptos/internal/storage/luks"
)

// StateKeyProtector supplies the LUKS key for the encrypted state partition.
// tpmProtector seals it to the TPM; nodeIDProtector derives it from the node
// UUID. The interface keeps OpenStateVolume independent of the key source.
type StateKeyProtector interface {
	// Name reports the provider ("tpm" | "nodeid") for status and logging.
	Name() string
	// ProvisionKey returns the LUKS key to format with on first boot, plus an
	// optional token to persist alongside it (nil = none).
	ProvisionKey(ctx context.Context) (key, token []byte, err error)
	// RecoverKey returns the LUKS key to open with on later boots, given the
	// persisted token (nil if PersistsToken is false).
	RecoverKey(ctx context.Context, token []byte) (key []byte, err error)
	// PersistsToken reports whether this provider stores/reads a LUKS token.
	PersistsToken() bool
}

// tpmProtector seals the state key to the TPM under a PCR policy and stores the
// sealed blobs as a LUKS2 token.
type tpmProtector struct {
	tpm  Sealer
	pcrs []int
}

func newTPMProtector(s Sealer, pcrs []int) *tpmProtector {
	return &tpmProtector{tpm: s, pcrs: pcrs}
}

func (p *tpmProtector) Name() string        { return "tpm" }
func (p *tpmProtector) PersistsToken() bool { return true }

func (p *tpmProtector) ProvisionKey(_ context.Context) (key, token []byte, err error) {
	key = make([]byte, stateKeyBytes)
	if _, err = rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	if err = p.tpm.ProvisionSRK(); err != nil {
		wipe(key)
		return nil, nil, fmt.Errorf("provision SRK: %w", err)
	}
	priv, pub, err := p.tpm.SealToPCR(key, p.pcrs)
	if err != nil {
		wipe(key)
		return nil, nil, fmt.Errorf("seal: %w", err)
	}
	tok, err := luks.BuildTPM2Token(priv, pub, stateKeyslot, p.pcrs, nil)
	if err != nil {
		wipe(key)
		return nil, nil, fmt.Errorf("build token: %w", err)
	}
	token, err = json.Marshal(tok)
	if err != nil {
		wipe(key)
		return nil, nil, fmt.Errorf("marshal token: %w", err)
	}
	return key, token, nil
}

func (p *tpmProtector) RecoverKey(_ context.Context, tokenJSON []byte) ([]byte, error) {
	tok, err := luks.ParseTPM2Token(tokenJSON)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	priv, pub, err := tok.SealedBlobs()
	if err != nil {
		return nil, fmt.Errorf("token blobs: %w", err)
	}
	pcrs := tok.PCRs
	if len(pcrs) == 0 {
		pcrs = p.pcrs
	}
	key, err := p.tpm.UnsealWithPCR(priv, pub, pcrs)
	if err != nil {
		return nil, fmt.Errorf("unseal (PCR drift requires reinit): %w", err)
	}
	return key, nil
}
