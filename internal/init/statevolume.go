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

	"github.com/CryptOS-PKI/cryptos/internal/storage/luks"
)

// Sealer is the subset of *tpm.TPM the state-volume bring-up needs. It is
// an interface so the format-vs-unseal orchestration is unit-testable
// without a TPM device.
type Sealer interface {
	ProvisionSRK() error
	SealToPCR(data []byte, pcrs []int) (private, public []byte, err error)
	UnsealWithPCR(private, public []byte, pcrs []int) ([]byte, error)
}

// stateKeyBytes is the LUKS2 master-key length CryptOS generates on first
// boot (256-bit, from crypto/rand).
const stateKeyBytes = 32

// stateKeyslot is the LUKS keyslot luksFormat populates and that the TPM
// token references.
const stateKeyslot = 0

// StateVolumeConfig parameterizes OpenStateVolume.
type StateVolumeConfig struct {
	// TPM seals/unseals the volume key. Required.
	TPM Sealer
	// Device is the state-partition block device. Required.
	Device *luks.Device
	// MappedName is the dm-crypt name to expose (e.g. "cryptos-state").
	MappedName string
	// PCRs is the PCR set the key is sealed to (e.g. tpm.DefaultSealPCRs).
	PCRs []int
	// TokenID is the LUKS2 token id holding the sealed key.
	TokenID int
	// FirstBoot selects the format-and-seal path; otherwise unseal.
	FirstBoot bool
}

func (c StateVolumeConfig) validate() error {
	switch {
	case c.TPM == nil:
		return errors.New("TPM is required")
	case c.Device == nil:
		return errors.New("device is required")
	case c.MappedName == "":
		return errors.New("mapped name is required")
	case len(c.PCRs) == 0:
		return errors.New("PCRs is required")
	}
	return nil
}

// OpenStateVolume opens the encrypted state partition, returning the
// unlocked LUKS volume.
//
// On first boot it generates a fresh 256-bit key, formats the partition,
// seals the key to the TPM under the PCR policy, stores the sealed key as
// a LUKS2 token, and opens the volume. On every subsequent boot it reads
// the token, unseals the key with the TPM, and opens the volume. The
// plaintext key is wiped from memory before returning.
//
// It composes internal/tpm (SealToPCR/UnsealWithPCR) and
// internal/storage/luks (Format/ImportToken/ExportToken/Open) into the
// actual boot behavior.
func OpenStateVolume(ctx context.Context, cfg StateVolumeConfig) (*luks.Volume, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: %w", err)
	}
	if cfg.FirstBoot {
		return openFirstBoot(ctx, cfg)
	}
	return openUnseal(ctx, cfg)
}

func openFirstBoot(ctx context.Context, cfg StateVolumeConfig) (*luks.Volume, error) {
	key := make([]byte, stateKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: generate key: %w", err)
	}
	defer wipe(key)

	if err := cfg.Device.Format(ctx, key); err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: format: %w", err)
	}
	if err := cfg.TPM.ProvisionSRK(); err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: provision SRK: %w", err)
	}
	priv, pub, err := cfg.TPM.SealToPCR(key, cfg.PCRs)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: seal: %w", err)
	}
	token, err := luks.BuildTPM2Token(priv, pub, stateKeyslot, cfg.PCRs, nil)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: build token: %w", err)
	}
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: marshal token: %w", err)
	}
	if err := cfg.Device.ImportToken(ctx, cfg.TokenID, tokenJSON); err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: import token: %w", err)
	}
	vol, err := cfg.Device.Open(ctx, key, cfg.MappedName)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: open: %w", err)
	}
	return vol, nil
}

func openUnseal(ctx context.Context, cfg StateVolumeConfig) (*luks.Volume, error) {
	tokenJSON, err := cfg.Device.ExportToken(ctx, cfg.TokenID)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: export token: %w", err)
	}
	token, err := luks.ParseTPM2Token(tokenJSON)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: parse token: %w", err)
	}
	priv, pub, err := token.SealedBlobs()
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: token blobs: %w", err)
	}
	pcrs := token.PCRs
	if len(pcrs) == 0 {
		pcrs = cfg.PCRs
	}
	key, err := cfg.TPM.UnsealWithPCR(priv, pub, pcrs)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: unseal (PCR drift requires reinit): %w", err)
	}
	defer wipe(key)

	vol, err := cfg.Device.Open(ctx, key, cfg.MappedName)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: open: %w", err)
	}
	return vol, nil
}

// wipe zeroes a secret byte slice.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
