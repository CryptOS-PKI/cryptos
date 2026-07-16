package node

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
	"crypto/sha256"
	"errors"
	"fmt"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// IdentityProvider adapts a Store to the grpc.Identity interface.
type IdentityProvider struct {
	store *Store
}

// NewIdentityProvider returns an IdentityProvider over store.
func NewIdentityProvider(store *Store) *IdentityProvider {
	return &IdentityProvider{store: store}
}

// Get returns the node's Identity, or ErrNoIdentity before the ceremony
// has committed. The gRPC layer maps the error to FAILED_PRECONDITION.
func (p *IdentityProvider) Get(ctx context.Context) (*cryptosv1.Identity, error) {
	return p.store.Identity(ctx)
}

// StatusConfig configures a StatusProvider. Store and Role are required;
// the health functions are optional and default to OK when nil.
type StatusConfig struct {
	// Store reads phase + boot count.
	Store *Store
	// Role is the node's configured role.
	Role cryptosv1.NodeRole
	// SoftwareVersion is the running build's version string.
	SoftwareVersion string
	// TPMState reports live TPM health; nil defaults to TPM_STATE_OK.
	TPMState func() cryptosv1.TpmState
	// EtcdState reports live datastore health; nil defaults to ETCD_STATE_OK.
	EtcdState func() cryptosv1.EtcdState
}

// StatusProvider adapts a Store + live health probes to grpc.StatusProvider.
type StatusProvider struct {
	cfg StatusConfig
}

// NewStatusProvider returns a StatusProvider. Returns an error if Store
// is nil.
func NewStatusProvider(cfg StatusConfig) (*StatusProvider, error) {
	if cfg.Store == nil {
		return nil, errors.New("node: NewStatusProvider: Store is required")
	}
	return &StatusProvider{cfg: cfg}, nil
}

// Status builds the live NodeStatus.
func (p *StatusProvider) Status(ctx context.Context) (*cryptosv1.NodeStatus, error) {
	phase, err := p.cfg.Store.Phase(ctx)
	if err != nil {
		return nil, err
	}
	bootCount, err := p.cfg.Store.BootCount(ctx)
	if err != nil {
		return nil, err
	}
	tpmState := cryptosv1.TpmState_TPM_STATE_OK
	if p.cfg.TPMState != nil {
		tpmState = p.cfg.TPMState()
	}
	etcdState := cryptosv1.EtcdState_ETCD_STATE_OK
	if p.cfg.EtcdState != nil {
		etcdState = p.cfg.EtcdState()
	}
	return &cryptosv1.NodeStatus{
		Role:            p.cfg.Role,
		IdentityState:   phase.IdentityState(),
		TpmState:        tpmState,
		EtcdState:       etcdState,
		BootCount:       bootCount,
		SoftwareVersion: p.cfg.SoftwareVersion,
		// Thin M4: no Fleet Manager endpoint concept yet, so a node is not
		// enrolled. The real connected/disconnected signal arrives with the
		// future Fleet Manager enrollment spec.
		FleetManager: cryptosv1.FleetManagerState_FLEET_MANAGER_STATE_NOT_ENROLLED,
	}, nil
}

// ConfigStore adapts a config.FileStore to the grpc.ConfigStore interface.
type ConfigStore struct {
	fs *config.FileStore
}

// NewConfigStore returns a ConfigStore backed by fs.
func NewConfigStore(fs *config.FileStore) *ConfigStore {
	return &ConfigStore{fs: fs}
}

// Current returns the node's currently persisted machine config, parsed and
// converted to its proto representation. It returns an error if no config
// has been written yet: SetManagement (the only caller today) is a
// read-modify-write over an existing config and has nothing to merge into
// before the first ApplyConfig/install has persisted one.
func (c *ConfigStore) Current(ctx context.Context) (*cryptosv1.MachineConfig, error) {
	raw, _, ok, err := c.fs.Read()
	if err != nil {
		return nil, fmt.Errorf("node: Current: %w", err)
	}
	if !ok {
		return nil, errors.New("node: Current: no config persisted yet")
	}
	parsed, err := config.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("node: Current: parse: %w", err)
	}
	return parsed.ToProto(), nil
}

// Apply converts cfg to YAML, persists it via the FileStore, and returns
// the new generation, digest, and whether a reboot is required. In Phase 1
// every applicable field (network, PKI) takes effect only on reboot, so
// requires_reboot is always true.
func (c *ConfigStore) Apply(ctx context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	if cfg == nil {
		return nil, errors.New("node: Apply: nil config")
	}
	parsed, err := config.FromProto(cfg)
	if err != nil {
		return nil, fmt.Errorf("node: Apply: %w", err)
	}
	raw, err := parsed.Marshal()
	if err != nil {
		return nil, fmt.Errorf("node: Apply: marshal: %w", err)
	}
	gen, err := c.fs.Write(raw)
	if err != nil {
		return nil, fmt.Errorf("node: Apply: persist: %w", err)
	}
	digest := sha256.Sum256(raw)
	return &cryptosv1.ApplyConfigResponse{
		Generation:     gen,
		RequiresReboot: true,
		ConfigDigest:   digest[:],
	}, nil
}
