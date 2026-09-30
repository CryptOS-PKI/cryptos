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

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/storage/luks"
)

// stateBackendFactory builds the state-key protector and Root-key backend for
// a state-key mode. newStateKeyBackends is the production factory.
type stateBackendFactory func(mode string, sk config.StateKey) (StateKeyProtector, ceremony.RootKeyBackend, func(), cryptosv1.TpmState, error)

// stateUnlocker opens (or, on first boot, formats) the encrypted state volume
// with the protector for the node's state-key mode.
type stateUnlocker struct {
	device *luks.Device
	stage  espStageAccessors
	// buildDefault is the image's build-time mode, used when first-boot config
	// selects none.
	buildDefault string
	newBackends  stateBackendFactory
}

// unlockedState is an open state volume and the backends it was opened with.
// The caller owns close.
type unlockedState struct {
	mode      string
	firstBoot bool
	vol       *luks.Volume
	protector StateKeyProtector
	root      ceremony.RootKeyBackend
	close     func()
	tpmState  cryptosv1.TpmState
}

func (u stateUnlocker) unlock(ctx context.Context) (*unlockedState, error) {
	firstBoot := !u.device.IsLUKS(ctx)
	mode, sk, err := u.stateKey(ctx, firstBoot)
	if err != nil {
		return nil, err
	}
	protector, root, closeFn, tpmState, err := u.newBackends(mode, sk)
	if err != nil {
		return nil, err
	}
	vol, err := OpenStateVolume(ctx, StateVolumeConfig{
		Protector: protector, Device: u.device, MappedName: StateMappedName,
		TokenID: StateTokenID, FirstBoot: firstBoot,
	})
	if err != nil {
		closeFn()
		return nil, err
	}
	return &unlockedState{
		mode: mode, firstBoot: firstBoot, vol: vol, protector: protector,
		root: root, close: closeFn, tpmState: tpmState,
	}, nil
}

// stateKey resolves the state-key selection before the volume is open. On
// first boot it comes from the ESP-staged config, else the build-time default.
// Every later boot reads it from the volume's LUKS2 header, which records how
// the volume was sealed; the config (inside the volume) is not readable yet,
// and the stage is gone.
func (u stateUnlocker) stateKey(ctx context.Context, firstBoot bool) (string, config.StateKey, error) {
	if firstBoot {
		sk := preUnlockStateKey(u.stage)
		if sk.Mode == "" {
			return u.buildDefault, sk, nil
		}
		return sk.Mode, sk, nil
	}
	tokens, err := u.device.Tokens(ctx)
	if err != nil {
		return "", config.StateKey{}, fmt.Errorf("init: read the state volume's tokens: %w", err)
	}
	sk, err := sealedStateKey(tokens)
	if err != nil {
		return "", config.StateKey{}, err
	}
	log.Printf("state key: the volume is sealed in %s mode", sk.Mode)
	return sk.Mode, sk, nil
}

// sealedStateKey derives the state-key selection a volume was sealed with from
// its LUKS2 token types: a TPM token (one per bootable image after an upgrade)
// means tpm, a KMS token means kms with the endpoint and trust it carries, and
// no protector token means nodeid, which persists none. Tokens of any other
// type are ignored.
func sealedStateKey(tokens map[int][]byte) (config.StateKey, error) {
	ids := make([]int, 0, len(tokens))
	for id := range tokens {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	var tpmTokens int
	var kmsTok *kmsToken
	for _, id := range ids {
		switch tokenTypeOf(tokens[id]) {
		case luks.TPM2TokenType:
			tpmTokens++
		case kmsTokenType:
			if kmsTok != nil {
				continue
			}
			var t kmsToken
			if err := json.Unmarshal(tokens[id], &t); err != nil {
				return config.StateKey{}, fmt.Errorf("init: state volume token %d: %w", id, err)
			}
			kmsTok = &t
		}
	}
	switch {
	case tpmTokens > 0 && kmsTok != nil:
		return config.StateKey{}, errors.New("init: the state volume has both TPM and KMS tokens; cannot tell how it was sealed")
	case tpmTokens > 0:
		return config.StateKey{Mode: config.StateKeyModeTPM}, nil
	case kmsTok != nil:
		return config.StateKey{Mode: config.StateKeyModeKMS, KMS: &config.KmsStateKey{
			Endpoint: kmsTok.Endpoint, TrustPEM: kmsTok.TrustPEM,
		}}, nil
	}
	return config.StateKey{Mode: config.StateKeyModeNodeID}, nil
}
