package init

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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"

	"github.com/CryptOS-PKI/cryptos-node/internal/storage/luks"
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
	// Protector supplies the LUKS key (TPM-sealed or nodeID-derived). Required.
	Protector StateKeyProtector
	// Device is the state-partition block device. Required.
	Device *luks.Device
	// MappedName is the dm-crypt name to expose (e.g. "cryptos-state").
	MappedName string
	// TokenID is the LUKS2 token id holding the sealed key (TPM mode only).
	TokenID int
	// FirstBoot selects the format path; otherwise recover-and-open.
	FirstBoot bool
}

func (c StateVolumeConfig) validate() error {
	switch {
	case c.Protector == nil:
		return errors.New("protector is required")
	case c.Device == nil:
		return errors.New("device is required")
	case c.MappedName == "":
		return errors.New("mapped name is required")
	}
	return nil
}

// OpenStateVolume opens the encrypted state partition, returning the
// unlocked LUKS volume.
//
// The LUKS key comes from the configured StateKeyProtector, not from this
// function directly. On first boot it asks the protector to provision a key
// (and an optional token to persist), formats the partition, imports the
// token when the protector persists one, and opens the volume. On every
// subsequent boot it reads the token (when the protector persists one), asks
// the protector to recover the key, and opens the volume. The plaintext key
// is wiped from memory before returning.
//
// It composes the protector with internal/storage/luks
// (Format/ImportToken/ExportToken/Open) into the actual boot behavior.
func OpenStateVolume(ctx context.Context, cfg StateVolumeConfig) (*luks.Volume, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: %w", err)
	}
	if cfg.FirstBoot {
		return openFirstBoot(ctx, cfg)
	}
	return openRecover(ctx, cfg)
}

func openFirstBoot(ctx context.Context, cfg StateVolumeConfig) (*luks.Volume, error) {
	key, token, err := cfg.Protector.ProvisionKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: provision key: %w", err)
	}
	defer wipe(key)

	if err := cfg.Device.Format(ctx, key); err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: format: %w", err)
	}
	if cfg.Protector.PersistsToken() && token != nil {
		if err := cfg.Device.ImportToken(ctx, cfg.TokenID, token); err != nil {
			return nil, fmt.Errorf("init: OpenStateVolume: import token: %w", err)
		}
	}
	vol, err := cfg.Device.Open(ctx, key, cfg.MappedName)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: open: %w", err)
	}
	return vol, nil
}

func openRecover(ctx context.Context, cfg StateVolumeConfig) (*luks.Volume, error) {
	key, err := recoverFromToken(ctx, cfg, cfg.TokenID)
	if err != nil {
		scanner, ok := cfg.Protector.(tokenScanner)
		if !ok {
			return nil, err
		}
		log.Printf("state volume: token %d did not open the volume (%v); trying the other %s tokens", cfg.TokenID, err, scanner.TokenType())
		key, err = recoverFromAnyToken(ctx, cfg, scanner.TokenType(), err)
		if err != nil {
			return nil, err
		}
	}
	defer wipe(key)

	vol, err := cfg.Device.Open(ctx, key, cfg.MappedName)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: open: %w", err)
	}
	return vol, nil
}

// tokenScanner is implemented by a protector whose key may sit in any of
// several header tokens of one type. After an in-place upgrade the TPM
// protector keeps one sealed copy per bootable image, and only the copy for
// the image that actually booted unseals, so the install-time token id is
// just the first one to try.
type tokenScanner interface {
	TokenType() string
}

func recoverFromToken(ctx context.Context, cfg StateVolumeConfig, tokenID int) ([]byte, error) {
	var token []byte
	if cfg.Protector.PersistsToken() {
		var err error
		token, err = cfg.Device.ExportToken(ctx, tokenID)
		if err != nil {
			return nil, fmt.Errorf("init: OpenStateVolume: export token: %w", err)
		}
	}
	key, err := cfg.Protector.RecoverKey(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("init: OpenStateVolume: recover key: %w", err)
	}
	return key, nil
}

// recoverFromAnyToken tries every other token of tokenType, in id order, and
// returns the first key recovered. first is the failure of the primary token,
// kept in the error so a node that cannot open its state says why.
func recoverFromAnyToken(ctx context.Context, cfg StateVolumeConfig, tokenType string, first error) ([]byte, error) {
	all, err := cfg.Device.Tokens(ctx)
	if err != nil {
		return nil, errors.Join(first, fmt.Errorf("init: OpenStateVolume: list tokens: %w", err))
	}
	ids := make([]int, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	errs := []error{first}
	for _, id := range ids {
		if id == cfg.TokenID || tokenTypeOf(all[id]) != tokenType {
			continue
		}
		key, err := cfg.Protector.RecoverKey(ctx, all[id])
		if err != nil {
			log.Printf("state volume: token %d did not unseal: %v", id, err)
			errs = append(errs, fmt.Errorf("token %d: %w", id, err))
			continue
		}
		log.Printf("state volume: opened with token %d", id)
		return key, nil
	}
	return nil, fmt.Errorf("init: OpenStateVolume: no %s token recovers the key: %w", tokenType, errors.Join(errs...))
}

// tokenTypeOf reads a token's "type" field, or "" when it has none.
func tokenTypeOf(tokenJSON []byte) string {
	var t struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(tokenJSON, &t) != nil {
		return ""
	}
	return t.Type
}

// wipe zeroes a secret byte slice.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
